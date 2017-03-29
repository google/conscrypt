/*
 * Copyright (C) 2016 The Android Open Source Project
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

/*
 * Copyright 2016 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.conscrypt;

import static java.lang.Math.min;
import static org.conscrypt.NativeConstants.SSL3_RT_ALERT;
import static org.conscrypt.NativeConstants.SSL3_RT_APPLICATION_DATA;
import static org.conscrypt.NativeConstants.SSL3_RT_CHANGE_CIPHER_SPEC;
import static org.conscrypt.NativeConstants.SSL3_RT_HANDSHAKE;
import static org.conscrypt.NativeConstants.SSL3_RT_HEADER_LENGTH;
import static org.conscrypt.NativeConstants.SSL3_RT_MAX_PACKET_SIZE;

import java.nio.ByteBuffer;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

/**
 * Utility methods for SSL packet processing. Copied from the Netty project.
 * <p>
 * This is a public class to allow testing to occur on Android via CTS.
 *
 * @hide
 */
public final class SSLUtils {
    static final boolean USE_ENGINE_SOCKET_BY_DEFAULT =
            Boolean.parseBoolean(System.getProperty("org.conscrypt.useEngineSocketByDefault"));
    static final int MAX_PROTOCOL_LENGTH = 255;

    /**
     * This is the maximum overhead when encrypting plaintext as defined by
     * <a href="https://www.ietf.org/rfc/rfc5246.txt">rfc5264</a>,
     * <a href="https://www.ietf.org/rfc/rfc5289.txt">rfc5289</a> and openssl implementation itself.
     *
     * Please note that we use a padding of 16 here as openssl uses PKC#5 which uses 16 bytes
     * whilethe spec itself allow up to 255 bytes. 16 bytes is the max for PKC#5 (which handles it
     * the same way as PKC#7) as we use a block size of 16. See <a
     * href="https://tools.ietf.org/html/rfc5652#section-6.3">rfc5652#section-6.3</a>.
     *
     * 16 (IV) + 48 (MAC) + 1 (Padding_length field) + 15 (Padding) + 1 (ContentType) + 2
     * (ProtocolVersion) + 2 (Length)
     *
     * TODO: We may need to review this calculation once TLS 1.3 becomes available.
     */
    private static final int MAX_ENCRYPTION_OVERHEAD_LENGTH = 15 + 48 + 1 + 16 + 1 + 2 + 2;

    private static final int MAX_ENCRYPTION_OVERHEAD_DIFF =
            Integer.MAX_VALUE - MAX_ENCRYPTION_OVERHEAD_LENGTH;

    /**
     * Calculates the minimum bytes required in the encrypted output buffer for the given number of
     * plaintext source bytes.
     */
    public static int calculateOutNetBufSize(int pendingBytes) {
        return min(SSL3_RT_MAX_PACKET_SIZE,
                MAX_ENCRYPTION_OVERHEAD_LENGTH + min(MAX_ENCRYPTION_OVERHEAD_DIFF, pendingBytes));
    }

    /**
     * Wraps the given exception if it's not already a {@link SSLHandshakeException}.
     */
    static SSLHandshakeException toSSLHandshakeException(Throwable e) {
        if (e instanceof SSLHandshakeException) {
            return (SSLHandshakeException) e;
        }

        return (SSLHandshakeException) new SSLHandshakeException(e.getMessage()).initCause(e);
    }

    /**
     * Wraps the given exception if it's not already a {@link SSLException}.
     */
    static SSLException toSSLException(Throwable e) {
        if (e instanceof SSLException) {
            return (SSLException) e;
        }
        return new SSLException(e);
    }

    /**
     * Return how much bytes can be read out of the encrypted data. Be aware that this method will
     * not
     * increase the readerIndex of the given {@link ByteBuffer}.
     *
     * @param buffers The {@link ByteBuffer}s to read from. Be aware that they must have at least
     * {@link org.conscrypt.NativeConstants#SSL3_RT_HEADER_LENGTH} bytes to read, otherwise it will
     * throw an {@link IllegalArgumentException}.
     * @return length The length of the encrypted packet that is included in the buffer. This will
     * return {@code -1} if the given {@link ByteBuffer} is not encrypted at all.
     * @throws IllegalArgumentException Is thrown if the given {@link ByteBuffer} has not at least
     * {@link org.conscrypt.NativeConstants#SSL3_RT_HEADER_LENGTH} bytes to read.
     */
    public static int getEncryptedPacketLength(ByteBuffer[] buffers, int offset) {
        ByteBuffer buffer = buffers[offset];

        // Check if everything we need is in one ByteBuffer. If so we can make use of the fast-path.
        if (buffer.remaining() >= SSL3_RT_HEADER_LENGTH) {
            return getEncryptedPacketLength(buffer);
        }

        // We need to copy 5 bytes into a temporary buffer so we can parse out the packet length
        // easily.
        ByteBuffer tmp = ByteBuffer.allocate(SSL3_RT_HEADER_LENGTH);
        do {
            buffer = buffers[offset++];
            int pos = buffer.position();
            int limit = buffer.limit();
            if (buffer.remaining() > tmp.remaining()) {
                buffer.limit(pos + tmp.remaining());
            }
            try {
                tmp.put(buffer);
            } finally {
                // Restore the original indices.
                buffer.limit(limit);
                buffer.position(pos);
            }
        } while (tmp.hasRemaining());

        // Done, flip the buffer so we can read from it.
        tmp.flip();
        return getEncryptedPacketLength(tmp);
    }

    /**
     * Encodes a list of protocols into the wire-format (length-prefixed 8-bit strings).
     * Requires that all strings be encoded with US-ASCII.
     *
     * @param protocols the list of protocols to be encoded
     * @return the encoded form of the protocol list.
     */
    public static byte[] toLengthPrefixedList(String... protocols) {
        // Calculate the encoded length.
        int length = 0;
        for (int i = 0; i < protocols.length; ++i) {
            int protocolLength = protocols[i].length();

            // Verify that the length is valid here, so that we don't attempt to allocate an array
            // below if the threshold is violated.
            if (protocolLength == 0 || protocolLength > MAX_PROTOCOL_LENGTH) {
                throw new IllegalArgumentException("Protocol has invalid length ("
                        + protocolLength + "): " + protocols[i]);
            }

            // Include a 1-byte prefix for each protocol.
            length += 1 + protocolLength;
        }

        byte[] data = new byte[length];
        for (int dataIndex = 0, i = 0; i < protocols.length; ++i) {
            String protocol = protocols[i];
            int protocolLength = protocol.length();

            // Add the length prefix.
            data[dataIndex++] = (byte) protocolLength;
            for (int ci = 0; ci < protocolLength; ++ci) {
                char c = protocol.charAt(ci);
                if (c > Byte.MAX_VALUE) {
                    // Enforce US-ASCII
                    throw new IllegalArgumentException("Protocol contains invalid character: "
                            + c + "(protocol=" + protocol + ")");
                }
                data[dataIndex++] = (byte) c;
            }
        }
        return data;
    }

    private static int getEncryptedPacketLength(ByteBuffer buffer) {
        int packetLength = 0;
        int pos = buffer.position();
        // SSLv3 or TLS - Check ContentType
        switch (unsignedByte(buffer.get(pos))) {
            case SSL3_RT_CHANGE_CIPHER_SPEC:
            case SSL3_RT_ALERT:
            case SSL3_RT_HANDSHAKE:
            case SSL3_RT_APPLICATION_DATA:
                break;
            default:
                // SSLv2 or bad data
                return -1;
        }

        // SSLv3 or TLS - Check ProtocolVersion
        int majorVersion = unsignedByte(buffer.get(pos + 1));
        if (majorVersion != 3) {
            // Neither SSLv3 or TLSv1 (i.e. SSLv2 or bad data)
            return -1;
        }

        // SSLv3 or TLS
        packetLength = unsignedShort(buffer.getShort(pos + 3)) + SSL3_RT_HEADER_LENGTH;
        if (packetLength <= SSL3_RT_HEADER_LENGTH) {
            // Neither SSLv3 or TLSv1 (i.e. SSLv2 or bad data)
            return -1;
        }
        return packetLength;
    }

    private static short unsignedByte(byte b) {
        return (short) (b & 0xFF);
    }

    private static int unsignedShort(short s) {
        return s & 0xFFFF;
    }

    private SSLUtils() {}
}
