/*
 * Copyright (C) 2017 The Android Open Source Project
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

import java.nio.ByteBuffer;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

/**
 * Benchmark for comparing cipher encoding performance.
 */
public final class CipherEncodingBenchmark {
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 128;

    public enum BufferType {
        ARRAY,
        HEAP_HEAP,
        HEAP_DIRECT,
        DIRECT_DIRECT,
        DIRECT_HEAP
    }

    /**
     * Provider for the benchmark configuration
     */
    interface Config {
        int plainTextLength();
        BufferType bufferType();
        CipherFactory cipherFactory();
        String transformation();
    }

    private final Encoder encoder;

    CipherEncodingBenchmark(Config config) throws Exception {
        switch (config.bufferType()) {
            case ARRAY:
                encoder = new ArrayEncoder(config);
                break;
            default:
                encoder = new ByteBufferEncoder(config);
                break;
        }
    }

    int encode() throws Exception {
        return encoder.encode();
    }

    private static abstract class Encoder {
        final Key key;
        final Cipher cipher;
        final int outputSize;

        Encoder(Config config) throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(KEY_SIZE);
            key = keyGen.generateKey();
            cipher = config.cipherFactory().newCipher(config.transformation());
            cipher.init(Cipher.ENCRYPT_MODE, key);
            outputSize = cipher.getOutputSize(config.plainTextLength());
        }

        abstract int encode() throws Exception;
    }

    private static byte[] newMessage(Config config) {
        return TestUtils.newTextMessage(config.plainTextLength());
    }

    private static final class ArrayEncoder extends Encoder {
        private final byte[] plainBytes;
        private final byte[] cipherBytes;

        ArrayEncoder(Config config) throws Exception {
            super(config);

            plainBytes = newMessage(config);
            cipherBytes = new byte[outputSize];
        }

        @Override
        int encode() throws Exception {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plainBytes, 0, plainBytes.length, cipherBytes, 0);
        }
    }

    private static final class ByteBufferEncoder extends Encoder {
        private final ByteBuffer input;
        private final ByteBuffer output;

        ByteBufferEncoder(Config config) throws Exception {
            super(config);

            switch (config.bufferType()) {
                case HEAP_HEAP:
                    input = ByteBuffer.wrap(newMessage(config));
                    output = ByteBuffer.allocate(outputSize);
                    break;
                case HEAP_DIRECT:
                    input = ByteBuffer.wrap(newMessage(config));
                    output = ByteBuffer.allocateDirect(outputSize);
                    break;
                case DIRECT_DIRECT:
                    input = toDirect(newMessage(config));
                    output = ByteBuffer.allocateDirect(outputSize);
                    break;
                case DIRECT_HEAP:
                    input = toDirect(newMessage(config));
                    output = ByteBuffer.allocate(outputSize);
                    break;
                default: {
                    throw new IllegalStateException(
                            "Unexpected buffertype: " + config.bufferType());
                }
            }
        }

        @Override
        int encode() throws Exception {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            input.position(0);
            output.clear();
            return cipher.doFinal(input, output);
        }

        private static ByteBuffer toDirect(byte[] data) {
            ByteBuffer buffer = ByteBuffer.allocateDirect(data.length);
            buffer.put(data);
            buffer.flip();
            return buffer;
        }
    }
}
