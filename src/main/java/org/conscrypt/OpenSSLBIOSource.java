/*
 * Copyright (C) 2014 The Android Open Source Project
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

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public final class OpenSSLBIOSource {
    private OpenSSLBIOInputStream source;

    public static OpenSSLBIOSource wrap(ByteBuffer buffer) {
        return new OpenSSLBIOSource(
            new OpenSSLBIOInputStream(new ByteBufferInputStream(buffer), false));
    }

    public OpenSSLBIOSource(OpenSSLBIOInputStream source) {
        this.source = source;
    }

    public long getContext() {
        return source.getBioContext();
    }

    public synchronized void release() {
        if (source != null) {
            NativeCrypto.BIO_free_all(source.getBioContext());
            source = null;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            release();
        } finally {
            super.finalize();
        }
    }

    private static class ByteBufferInputStream extends InputStream {
        private final ByteBuffer source;

        public ByteBufferInputStream(ByteBuffer source) {
            this.source = source;
        }

        @Override
        public int read() throws IOException {
            if (source.remaining() > 0) {
                return source.get();
            } else {
                return -1;
            }
        }

        @Override
        public int available() throws IOException {
            return source.limit() - source.position();
        }

        @Override
        public int read(byte[] buffer) throws IOException {
            int originalPosition = source.position();
            source.get(buffer);
            return source.position() - originalPosition;
        }

        @Override
        public int read(byte[] buffer, int byteOffset, int byteCount) throws IOException {
            int toRead = Math.min(source.remaining(), byteCount);
            int originalPosition = source.position();
            source.get(buffer, byteOffset, toRead);
            return source.position() - originalPosition;
        }

        @Override
        public void reset() throws IOException {
            source.reset();
        }

        @Override
        public long skip(long byteCount) throws IOException {
            int originalPosition = source.position();
            source.position((int) (originalPosition + byteCount));
            return source.position() - originalPosition;
        }
    }
}
