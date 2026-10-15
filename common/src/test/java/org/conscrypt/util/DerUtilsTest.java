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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.math.BigInteger;
import java.nio.ByteBuffer;

@RunWith(JUnit4.class)
public class DerUtilsTest {
    @Test
    public void testReadOctetString_shortForm() throws Exception {
        byte[] input = new byte[] {0x04, 0x04, 0x01, 0x02, 0x03, 0x04};
        byte[] expected = new byte[] {0x01, 0x02, 0x03, 0x04};

        assertArrayEquals(expected, DerUtils.readOctetString(input));
        assertArrayEquals(expected, DerUtils.readOctetString(ByteBuffer.wrap(input)));
    }

    @Test
    public void testReadOctetString_longForm() throws Exception {
        byte[] payload = new byte[200];
        payload[0] = 0x42;
        payload[199] = 0x24;

        byte[] input = new byte[203];
        input[0] = 0x04; // TAG_OCTET_STRING
        input[1] = (byte) 0x81; // long form, 1 length byte
        input[2] = (byte) 200; // length
        System.arraycopy(payload, 0, input, 3, 200);

        assertArrayEquals(payload, DerUtils.readOctetString(input));
        assertArrayEquals(payload, DerUtils.readOctetString(ByteBuffer.wrap(input)));
    }

    @Test
    public void testReadOctetString_invalidTag() {
        byte[] input = new byte[] {0x30, 0x02, 0x01, 0x02}; // SEQUENCE tag instead of OCTET STRING
        assertThrows(SerializationException.class, () -> DerUtils.readOctetString(input));
        assertThrows(SerializationException.class,
                     () -> DerUtils.readOctetString(ByteBuffer.wrap(input)));

        // Context-specific [4] IMPLICIT (0x84) has low 6 bits 0x04, but must be rejected
        byte[] contextTagInput = new byte[] {(byte) 0x84, 0x02, 0x01, 0x02};
        assertThrows(SerializationException.class, () -> DerUtils.readOctetString(contextTagInput));
        assertThrows(SerializationException.class,
                     () -> DerUtils.readOctetString(ByteBuffer.wrap(contextTagInput)));
    }

    @Test
    public void testReadOctetString_truncatedPayload() {
        byte[] input = new byte[] {0x04, 0x05, 0x01, 0x02}; // length claims 5 bytes, only 2 present
        assertThrows(SerializationException.class, () -> DerUtils.readOctetString(input));
        assertThrows(SerializationException.class,
                     () -> DerUtils.readOctetString(ByteBuffer.wrap(input)));
    }

    @Test
    public void testReadOctetString_nonMinimalLength() {
        // Long form length 0x81 0x04 for length 4, which could fit in short form
        byte[] input = new byte[] {0x04, (byte) 0x81, 0x04, 0x01, 0x02, 0x03, 0x04};
        assertThrows(SerializationException.class, () -> DerUtils.readOctetString(input));
        assertThrows(SerializationException.class,
                     () -> DerUtils.readOctetString(ByteBuffer.wrap(input)));
    }

    @Test
    public void testReadOctetString_nullInput() {
        assertThrows(SerializationException.class, () -> DerUtils.readOctetString((byte[]) null));
    }

    @Test
    public void testReadOctetString_trailingBytes() {
        byte[] input = new byte[] {0x04, 0x02, 0x01, 0x02, (byte) 0xFF};
        assertThrows(SerializationException.class, () -> DerUtils.readOctetString(input));
    }

    @Test
    public void testReadSequenceElement() throws Exception {
        byte[] raw = new byte[] {0x30, 0x03, 0x02, 0x01,
                                 0x05, 0x00}; // SEQUENCE containing INTEGER 5, + trailing byte
        ByteBuffer buf = ByteBuffer.wrap(raw);
        byte[] element = DerUtils.readSequenceElement(buf);

        assertArrayEquals(new byte[] {0x30, 0x03, 0x02, 0x01, 0x05}, element);
        assertEquals(1, buf.remaining());
    }

    @Test
    public void testReadSequenceElement_wrongTag() {
        ByteBuffer buf = ByteBuffer.wrap(new byte[] {0x02, 0x01, 0x05});
        assertThrows(SerializationException.class, () -> DerUtils.readSequenceElement(buf));
        assertEquals(0, buf.position());
    }

    @Test
    public void testSkipIntegerAndSequence() throws Exception {
        byte[] raw = new byte[] {0x02, 0x01, 0x05, 0x30, 0x01, 0x00, 0x04};
        ByteBuffer buf = ByteBuffer.wrap(raw);
        DerUtils.skipInteger(buf);
        assertEquals(4, buf.remaining());
        DerUtils.skipSequence(buf);
        assertEquals(1, buf.remaining());
        assertEquals(0x04, buf.get());

        assertThrows(SerializationException.class,
                     () -> DerUtils.skipSequence(ByteBuffer.wrap(raw)));
        assertThrows(SerializationException.class,
                     () -> DerUtils.skipInteger(ByteBuffer.wrap(new byte[] {0x30, 0x00})));
    }

    @Test
    public void testReadSequence() throws Exception {
        byte[] raw = new byte[] {0x30, 0x03, 0x02, 0x01, 0x05, (byte) 0xFF};
        ByteBuffer buf = ByteBuffer.wrap(raw);
        ByteBuffer seq = DerUtils.readSequence(buf);

        assertEquals(1, buf.remaining());
        assertEquals((byte) 0xFF, buf.get());
        assertEquals(3, seq.remaining());
        assertEquals(0x02, seq.get());
        ByteBuffer wrongTagBuf = ByteBuffer.wrap(new byte[] {0x02, 0x01, 0x05});
        assertThrows(SerializationException.class, () -> DerUtils.readSequence(wrongTagBuf));
        assertEquals(0, wrongTagBuf.position());
    }

    @Test
    public void testReadOptionalElement() throws Exception {
        byte[] withVersion = new byte[] {(byte) 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01};
        ByteBuffer buf1 = ByteBuffer.wrap(withVersion);
        byte[] version = DerUtils.readOptionalElement(buf1, DerUtils.TAG_CONTEXT_EXPLICIT_0);
        assertArrayEquals(new byte[] {(byte) 0xA0, 0x03, 0x02, 0x01, 0x02}, version);
        assertEquals(3, buf1.remaining());

        byte[] withoutVersion = new byte[] {0x02, 0x01, 0x01};
        ByteBuffer buf2 = ByteBuffer.wrap(withoutVersion);
        assertEquals(null, DerUtils.readOptionalElement(buf2, DerUtils.TAG_CONTEXT_EXPLICIT_0));
        assertEquals(3, buf2.remaining());
    }

    @Test
    public void testReadBigInteger() throws Exception {
        // Positive integer 0x01000000000000 (2^48)
        byte[] valid = new byte[] {0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        assertEquals(BigInteger.ONE.shiftLeft(48), DerUtils.readBigInteger(ByteBuffer.wrap(valid)));

        // Positive integer requiring leading 0x00 sign byte (0x80 = 128)
        byte[] leadingZero = new byte[] {0x02, 0x02, 0x00, (byte) 0x80};
        assertEquals(BigInteger.valueOf(128),
                     DerUtils.readBigInteger(ByteBuffer.wrap(leadingZero)));

        // Non-minimal leading 0x00 (next byte < 0x80) must be rejected
        byte[] nonMinimalZero = new byte[] {0x02, 0x02, 0x00, 0x01};
        assertThrows(SerializationException.class,
                     () -> DerUtils.readBigInteger(ByteBuffer.wrap(nonMinimalZero)));

        // Non-minimal leading 0xFF (next byte >= 0x80) must be rejected
        byte[] nonMinimalNeg = new byte[] {0x02, 0x02, (byte) 0xFF, (byte) 0x80};
        assertThrows(SerializationException.class,
                     () -> DerUtils.readBigInteger(ByteBuffer.wrap(nonMinimalNeg)));

        // Empty INTEGER payload must be rejected
        byte[] empty = new byte[] {0x02, 0x00};
        assertThrows(SerializationException.class,
                     () -> DerUtils.readBigInteger(ByteBuffer.wrap(empty)));
    }

    @Test
    public void testReadRelativeOidBytesAndFormatRelativeOid() throws Exception {
        // 32473.1 -> 81 fd 59 01
        byte[] valid = new byte[] {0x0D, 0x04, (byte) 0x81, (byte) 0xFD, 0x59, 0x01};
        byte[] rawBytes = DerUtils.readRelativeOidBytes(ByteBuffer.wrap(valid));
        assertArrayEquals(new byte[] {(byte) 0x81, (byte) 0xFD, 0x59, 0x01}, rawBytes);
        assertEquals("32473.1", DerUtils.formatRelativeOid(rawBytes));

        // Non-minimal sub-identifier (leading 0x80) must be rejected
        byte[] nonMinimal = new byte[] {0x0D, 0x02, (byte) 0x80, 0x01};
        assertThrows(SerializationException.class,
                     () -> DerUtils.readRelativeOidBytes(ByteBuffer.wrap(nonMinimal)));

        // Truncated sub-identifier (continuation bit set on final byte) must be rejected
        byte[] truncated = new byte[] {0x0D, 0x01, (byte) 0x81};
        assertThrows(SerializationException.class,
                     () -> DerUtils.readRelativeOidBytes(ByteBuffer.wrap(truncated)));

        // Empty RELATIVE-OID payload must be rejected
        assertThrows(SerializationException.class,
                     () -> DerUtils.readRelativeOidBytes(ByteBuffer.wrap(new byte[] {0x0D, 0x00})));
    }

    @Test
    public void testReadSetAndReadOid() throws Exception {
        // SET containing OID 1.3.6.1.4.1.44363.47.3 (06 0A 2B 06 01 04 01 82 DA 4B 2F 03)
        byte[] setWithOid = new byte[] {0x31, 0x0C, 0x06,        0x0A,        0x2B, 0x06, 0x01,
                                        0x04, 0x01, (byte) 0x82, (byte) 0xDA, 0x4B, 0x2F, 0x03};
        ByteBuffer setBuf = DerUtils.readSet(ByteBuffer.wrap(setWithOid));
        assertEquals("1.3.6.1.4.1.44363.47.3", DerUtils.readOid(setBuf));
        assertEquals(0, setBuf.remaining());

        // OID under joint-iso-itu-t (2.16.840.1.101.3.4.3.17 = ML-DSA-44)
        byte[] mlDsa44Oid = new byte[] {0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01,
                                        0x65, 0x03, 0x04, 0x03,        0x11};
        assertEquals("2.16.840.1.101.3.4.3.17", DerUtils.readOid(ByteBuffer.wrap(mlDsa44Oid)));

        // Empty OID payload must be rejected
        assertThrows(SerializationException.class,
                     () -> DerUtils.readOid(ByteBuffer.wrap(new byte[] {0x06, 0x00})));
    }
}
