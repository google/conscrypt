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

import static org.conscrypt.NativeConstants.SSL3_RT_ALERT;
import static org.conscrypt.NativeConstants.SSL3_RT_APPLICATION_DATA;
import static org.conscrypt.NativeConstants.SSL3_RT_CHANGE_CIPHER_SPEC;
import static org.conscrypt.NativeConstants.SSL3_RT_HANDSHAKE;
import static org.conscrypt.NativeConstants.SSL3_RT_HEADER_LENGTH;

import java.nio.ByteBuffer;

/**
 * Utility methods for SSL packet processing. Copied from the Netty project.
 */
final class SSLUtils {
    /**
     * Return how much bytes can be read out of the encrypted data. Be aware that this method will
     * not
     * increase the readerIndex of the given {@link ByteBuffer}.
     *
     * @param buffers The {@link ByteBuffer}s to read from. Be aware that they must have at least
     * {@link #SSL3_RT_HEADER_LENGTH} bytes to read, otherwise it will throw an {@link
     * IllegalArgumentException}.
     * @return length The length of the encrypted packet that is included in the buffer. This will
     * return {@code -1} if the given {@link ByteBuffer} is not encrypted at all.
     * @throws IllegalArgumentException Is thrown if the given {@link ByteBuffer} has not at least
     * {@link #SSL3_RT_HEADER_LENGTH} bytes to read.
     */
    static int getEncryptedPacketLength(ByteBuffer[] buffers, int offset) {
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
