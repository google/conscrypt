/*
 * Copyright 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.conscrypt.util;

import org.conscrypt.Internal;

import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * Helpers for reading DER-encoded data (the binary format used by X.509 certificates).
 *
 * <p>Every DER item is laid out as {@code [Tag (1 byte)][Length (1-5 bytes)][Content]}:
 * <ul>
 *   <li>{@code readOctetString} / {@code readRelativeOidBytes} strip the header and return only
 *       the inner {@code [Content]} bytes.
 *   <li>{@code readSequenceElement} / {@code readOptionalElement} / {@code readElement}
 *       return the entire {@code [Tag][Length][Content]} slice intact (for copying or hashing raw
 *       fields).
 *   <li>{@code readSequence} / {@code readContent} step <i>into</i> a struct by advancing the
 *       outer buffer past the entire element and returning a zero-copy {@link ByteBuffer} slice
 *       bounded to the inner {@code [Content]} bytes.
 *   <li>{@code skipSequence} / {@code skipInteger} jump completely <i>over</i> an entire
 *       {@code [Tag][Length][Content]} item to reach the next field.
 * </ul>
 *
 * <p>This class only supports single-byte tags (tag numbers &lt; 31, rejecting multi-byte tag
 * marker {@code 0x1F}) and lengths up to 4 bytes, which covers all X.509, CT, and MTC structures.
 */
@Internal
public final class DerUtils {
    // Tag bytes identifying the data type of the [Content] that follows:
    private static final int TAG_INTEGER = 0x02; // Whole number (e.g. certificate serial number)
    private static final int TAG_OCTET_STRING = 0x04; // Raw byte[] blob
    private static final int TAG_OID =
            0x06; // ASN.1 OBJECT IDENTIFIER (e.g. "1.3.6.1.4.1.44363.47.3")
    private static final int TAG_RELATIVE_OID = 0x0D; // Base-128 relative OID (e.g. "32473.1")
    private static final int TAG_SEQUENCE = 0x30; // Struct / ordered group of nested DER fields
    private static final int TAG_SET = 0x31; // ASN.1 SET (e.g. RelativeDistinguishedName)

    // Context-specific constructed tag [0] EXPLICIT (0xA0), e.g. for optional X.509 TBSCertificate
    // version field.
    public static final int TAG_CONTEXT_EXPLICIT_0 = 0xA0;

    private DerUtils() {}

    /**
     * Reads a struct ({@code SEQUENCE}) and returns the full {@code [Tag][Length][Content]} bytes
     * intact, preserving the outer header so the field can be copied or hashed as-is.
     */
    public static byte[] readSequenceElement(ByteBuffer buf) throws SerializationException {
        return readElement(buf, TAG_SEQUENCE);
    }

    /**
     * Jumps completely over an entire struct ({@code [Tag][Length][Content]}) to land on the next
     * sibling field without allocating a byte array.
     */
    public static void skipSequence(ByteBuffer buf) throws SerializationException {
        skipElement(buf, TAG_SEQUENCE);
    }

    /**
     * Steps inside a struct ({@code SEQUENCE}) by verifying its tag, advancing {@code buf} past
     * the entire sequence, and returning a zero-copy {@link ByteBuffer} slice bounded to the
     * inner {@code [Content]} bytes.
     */
    public static ByteBuffer readSequence(ByteBuffer buf) throws SerializationException {
        return readContent(buf, TAG_SEQUENCE);
    }

    /**
     * Steps inside an ASN.1 {@code SET} (tag {@code 0x31}) by verifying its tag, advancing
     * {@code buf} past the entire set, and returning a zero-copy {@link ByteBuffer} slice
     * bounded to the inner {@code [Content]} bytes.
     */
    public static ByteBuffer readSet(ByteBuffer buf) throws SerializationException {
        return readContent(buf, TAG_SET);
    }

    /**
     * Jumps completely over an entire integer field ({@code [Tag][Length][Content]}) to land on
     * the next sibling field without allocating a byte array.
     */
    public static void skipInteger(ByteBuffer buf) throws SerializationException {
        skipElement(buf, TAG_INTEGER);
    }

    /**
     * Checks if an optional element with {@code expectedTag} is present at the current buffer
     * position. If so, reads and returns its full {@code [Tag][Length][Content]} bytes; if
     * absent, leaves the buffer untouched and returns {@code null}.
     */
    public static byte[] readOptionalElement(ByteBuffer buf, int expectedTag)
            throws SerializationException {
        if (!buf.hasRemaining()) {
            return null;
        }
        if (Byte.toUnsignedInt(buf.get(buf.position())) == expectedTag) {
            return readElement(buf, expectedTag);
        }
        return null;
    }

    /**
     * Verifies that the next item has {@code expectedTag} and returns its complete
     * {@code [Tag][Length][Content]} bytes.
     */
    public static byte[] readElement(ByteBuffer buf, int expectedTag)
            throws SerializationException {
        int tagPosition = buf.position();
        int valueLen;
        try {
            int tag = readTag(buf);
            if (tag != expectedTag) {
                throw new SerializationException("Wrong DER tag, expected " + expectedTag + ", got "
                                                 + tag);
            }
            valueLen = readLength(buf);
        } catch (SerializationException e) {
            buf.position(tagPosition);
            throw e;
        }
        int headerLen = buf.position() - tagPosition;

        byte[] tlv = new byte[headerLen + valueLen];
        // Rewind to tagPosition so buf.get(tlv) copies the entire [Tag][Length][Content] slice.
        buf.position(tagPosition);
        buf.get(tlv);
        return tlv;
    }

    /**
     * Verifies that the next item has {@code expectedTag} and advances the buffer past the entire
     * {@code [Tag][Length][Content]} item.
     */
    public static void skipElement(ByteBuffer buf, int expectedTag) throws SerializationException {
        readContent(buf, expectedTag);
    }

    /**
     * Verifies that the next item has {@code expectedTag}, advances {@code buf} past the entire
     * {@code [Tag][Length][Content]} item, and returns a zero-copy {@link ByteBuffer} slice
     * bounded to its inner {@code [Content]} bytes.
     */
    public static ByteBuffer readContent(ByteBuffer buf, int expectedTag)
            throws SerializationException {
        int tagPosition = buf.position();
        int valueLen;
        try {
            int tag = readTag(buf);
            if (tag != expectedTag) {
                throw new SerializationException("Wrong DER tag, expected " + expectedTag + ", got "
                                                 + tag);
            }
            valueLen = readLength(buf);
        } catch (SerializationException e) {
            buf.position(tagPosition);
            throw e;
        }
        ByteBuffer content = buf.slice();
        content.limit(valueLen);
        buf.position(buf.position() + valueLen);
        return content;
    }

    /**
     * Reads a DER INTEGER (tag {@code 0x02}) and returns its value as a {@link BigInteger}.
     */
    public static BigInteger readBigInteger(ByteBuffer buf) throws SerializationException {
        ByteBuffer content = readContent(buf, TAG_INTEGER);
        if (!content.hasRemaining()) {
            throw new SerializationException("Empty DER INTEGER");
        }
        byte[] bytes = remainingBytesToArray(content);
        if (bytes.length > 1) {
            if ((bytes[0] == 0x00 && (bytes[1] & 0x80) == 0)
                || (bytes[0] == (byte) 0xFF && (bytes[1] & 0x80) != 0)) {
                throw new SerializationException("Non-minimal DER INTEGER encoding");
            }
        }
        return new BigInteger(bytes);
    }

    /**
     * Reads a DER OBJECT IDENTIFIER (tag {@code 0x06}) and decodes it into a dot-separated
     * decimal string (e.g. {@code "1.3.6.1.4.1.44363.47.3"}).
     */
    public static String readOid(ByteBuffer buf) throws SerializationException {
        ByteBuffer content = readContent(buf, TAG_OID);
        long firstSubId = readBase128SubIdentifier(content);
        long firstArc = Math.min(2L, firstSubId / 40L);
        long secondArc = firstSubId - (firstArc * 40L);
        StringBuilder sb = new StringBuilder();
        sb.append(firstArc).append('.').append(secondArc);
        while (content.hasRemaining()) {
            sb.append('.').append(readBase128SubIdentifier(content));
        }
        return sb.toString();
    }

    /**
     * Reads a DER RELATIVE-OID (tag {@code 0x0D}) from {@code buf}, validates that its base-128
     * subidentifiers are well-formed and minimally encoded, and returns its raw content bytes.
     */
    public static byte[] readRelativeOidBytes(ByteBuffer buf) throws SerializationException {
        ByteBuffer content = readContent(buf, TAG_RELATIVE_OID);
        do {
            readBase128SubIdentifier(content);
        } while (content.hasRemaining());
        // readContent returns a ByteBuffer.slice(), so rewind() resets position to the start of
        // the RELATIVE-OID content (not the start of the outer backing buffer).
        content.rewind();
        return remainingBytesToArray(content);
    }

    /**
     * Decodes raw base-128 RELATIVE-OID content bytes (without tag/length header) into a
     * canonical dot-separated decimal string (e.g. {@code "32473.1"}).
     */
    public static String formatRelativeOid(byte[] relativeOidBytes) throws SerializationException {
        if (relativeOidBytes == null || relativeOidBytes.length == 0) {
            throw new SerializationException("Empty RELATIVE-OID bytes");
        }
        ByteBuffer content = ByteBuffer.wrap(relativeOidBytes);
        StringBuilder sb = new StringBuilder();
        while (content.hasRemaining()) {
            if (sb.length() > 0) {
                sb.append('.');
            }
            sb.append(readBase128SubIdentifier(content));
        }
        return sb.toString();
    }

    private static long readBase128SubIdentifier(ByteBuffer content) throws SerializationException {
        long value = 0;
        boolean firstByte = true;
        while (content.hasRemaining()) {
            int b = Byte.toUnsignedInt(content.get());
            if (firstByte && b == 0x80) {
                throw new SerializationException("Non-minimal base-128 OID component");
            }
            firstByte = false;
            if ((value & (0x7FL << 56)) != 0) {
                throw new SerializationException("OID component exceeds 63 bits");
            }
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                return value;
            }
        }
        throw new SerializationException("Truncated base-128 OID component");
    }

    /**
     * Unwraps a raw byte array ({@code OCTET STRING}, {@code 0x04}) and returns only its inner
     * {@code [Content]} bytes (without the tag and length header).
     */
    public static byte[] readOctetString(ByteBuffer buf) throws SerializationException {
        return remainingBytesToArray(readContent(buf, TAG_OCTET_STRING));
    }

    private static byte[] remainingBytesToArray(ByteBuffer buf) {
        byte[] bytes = new byte[buf.remaining()];
        buf.get(bytes);
        return bytes;
    }

    /**
     * Reads a DER-encoded OCTET STRING from a byte array, verifying that no trailing bytes follow,
     * and returns its payload bytes.
     */
    public static byte[] readOctetString(byte[] input) throws SerializationException {
        if (input == null) {
            throw new SerializationException("Input is null");
        }
        ByteBuffer buf = ByteBuffer.wrap(input);
        byte[] payload = readOctetString(buf);
        if (buf.hasRemaining()) {
            throw new SerializationException("Trailing data after DER OCTET STRING");
        }
        return payload;
    }

    private static int readTag(ByteBuffer buf) throws SerializationException {
        if (!buf.hasRemaining()) {
            throw new SerializationException("Unexpected end of DER encoding");
        }
        int tag = Byte.toUnsignedInt(buf.get());
        // Bits 5-1 set to all ones (0x1F) indicates high tag number form (multi-byte tag).
        // Standard X.509 certificates only use single-byte tags (< 31).
        if ((tag & 0x1F) == 0x1F) {
            throw new SerializationException("High tag number form not supported");
        }
        return tag;
    }

    private static int readLength(ByteBuffer buf) throws SerializationException {
        if (!buf.hasRemaining()) {
            throw new SerializationException("Unexpected end of DER encoding");
        }
        int initialByte = Byte.toUnsignedInt(buf.get());
        return (initialByte < 128) ? readShortFormLength(buf, initialByte)
                                   : readLongFormLength(buf, initialByte);
    }

    private static int readShortFormLength(ByteBuffer buf, int initialByte)
            throws SerializationException {
        int len = initialByte;
        if (buf.remaining() < len) {
            throw new SerializationException("DER element length exceeds data bounds");
        }
        return len;
    }

    private static int readLongFormLength(ByteBuffer buf, int initialByte)
            throws SerializationException {
        int numBytes = initialByte & 0x7F;
        if (numBytes == 0 || numBytes > 4 || buf.remaining() < numBytes) {
            throw new SerializationException("Invalid DER length encoding");
        }
        int len = 0;
        for (int i = 0; i < numBytes; i++) {
            len = (len << 8) | Byte.toUnsignedInt(buf.get());
        }
        // DER requires minimal length encoding (ITU-T X.690 Section 10.1):
        // 1. Long form cannot be used for lengths < 128 (must use short form).
        // 2. Multi-byte lengths (numBytes > 1) cannot have leading zero bytes;
        //    the value must be >= 1 << ((numBytes - 1) * 8), meaning it cannot fit in fewer bytes.
        if (len < 128 || len < (1 << ((numBytes - 1) * 8))) {
            throw new SerializationException("Non-minimal DER length encoding");
        }
        if (len < 0 || buf.remaining() < len) {
            throw new SerializationException("DER element length exceeds data bounds");
        }
        return len;
    }
}
