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

import java.io.ByteArrayOutputStream;

public final class OpenSSLBIOSink {
    private final long ctx;
    private final ByteArrayOutputStream buffer;
    private int position;

    public static OpenSSLBIOSink create() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        return new OpenSSLBIOSink(buffer);
    }

    private OpenSSLBIOSink(ByteArrayOutputStream buffer) {
        ctx = NativeCrypto.create_BIO_OutputStream(buffer);
        this.buffer = buffer;
    }

    public int available() {
        return buffer.size() - position;
    }

    public void reset() {
        buffer.reset();
        position = 0;
    }

    public long skip(long byteCount) {
        int maxLength = Math.min(available(), (int) byteCount);
        position += maxLength;
        if (position == buffer.size()) {
            reset();
        }
        return maxLength;
    }

    public long getContext() {
        return ctx;
    }

    public byte[] toByteArray() {
        return buffer.toByteArray();
    }

    public int position() {
        return position;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            NativeCrypto.BIO_free_all(ctx);
        } finally {
            super.finalize();
        }
    }
}
