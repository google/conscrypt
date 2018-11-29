/*
 * Copyright (C) 2012 The Android Open Source Project
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

package org.conscrypt;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Provides an interface to OpenSSL's BIO system directly from a Java
 * InputStream. It allows an OpenSSL API to read directly from something more
 * flexible interface than a byte array.
 */
class OpenSSLBIOInputStream extends FilterInputStream {
    private long ctx;

    OpenSSLBIOInputStream(InputStream is, boolean isFinite) {
        super(is);

        ctx = NativeCrypto.create_BIO_InputStream(this, isFinite);
    }

    long getBioContext() {
        return ctx;
    }

    void release() {
        NativeCrypto.BIO_free_all(ctx);
    }

    /**
     * Similar to a {@code readLine} method, but matches what OpenSSL expects
     * from a {@code BIO_gets} method.
     */
    int gets(byte[] buffer) throws IOException {
        if (buffer == null || buffer.length == 0) {
            return 0;
        }

        int offset = 0;
        int inputByte = 0;
        while (offset < buffer.length) {
            inputByte = read();
            if (inputByte == -1) {
                // EOF
                break;
            }
            if (inputByte == '\n') {
                if (offset == 0) {
                    // If we haven't read anything yet, ignore CRLF.
                    continue;
                } else {
                    break;
                }
            }

            buffer[offset++] = (byte) inputByte;
        }

        return offset;
    }

    @Override
    public int read(byte[] buffer) throws IOException {
        return read(buffer, 0, buffer.length);
    }

    // InputStream.read() is allowed to return less than len bytes, and the socket InputStreams
    // that are used with this class typically do so when the length requested is more than what
    // is already buffered, but some users of BoringSSL's BIO APIs expect that any read call either
    // fills the buffer completely, fails, or reaches EOF.  We patch over this difference by
    // repeatedly calling super.read() until it indicates EOF or we fill the buffer.
    @Override
    public int read(byte[] buffer, int offset, int len) throws IOException {
        if (offset < 0 || len < 0 || len > buffer.length - offset) {
            throw new IndexOutOfBoundsException("Invalid bounds");
        }
        if (len == 0) {
            return 0;
        }
        int totalRead = 0;
        int read;
        do {
            read = super.read(buffer, offset + totalRead, len - totalRead - offset);
            if (read == -1) {
                break;
            }
            totalRead += read;
        } while (offset + totalRead < len);

        return totalRead == 0 ? -1 : totalRead;
    }
}
