/*
 * Copyright 2017 The Android Open Source Project
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
 * Copyright 2017 The Netty Project
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

import static org.conscrypt.TestUtils.doEngineHandshake;
import static org.conscrypt.TestUtils.newTextMessage;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

/**
 * Benchmark comparing performance of various engine implementations to conscrypt.
 */
public final class EngineWrapBenchmark {
    /**
     * Provider for the benchmark configuration
     */
    interface Config {
        BufferType bufferType();
        EngineType engineType();
        int messageSize();
        String cipher();
    }

    private final EngineType engineType;
    private final String cipher;
    private final SSLEngine clientEngine;
    private final SSLEngine serverEngine;

    private final ByteBuffer messageBuffer;
    private final ByteBuffer clientApplicationBuffer;
    private final ByteBuffer clientPacketBuffer;
    private final ByteBuffer serverApplicationBuffer;
    private final ByteBuffer serverPacketBuffer;
    private final ByteBuffer preEncryptedBuffer;

    EngineWrapBenchmark(Config config) throws Exception {
        engineType = config.engineType();
        cipher = config.cipher();
        BufferType bufferType = config.bufferType();

        clientEngine = engineType.newClientEngine(cipher, false);
        serverEngine = engineType.newServerEngine(cipher, false);

        // Create the application and packet buffers for both endpoints.
        clientApplicationBuffer = bufferType.newApplicationBuffer(clientEngine);
        serverApplicationBuffer = bufferType.newApplicationBuffer(serverEngine);
        clientPacketBuffer = bufferType.newPacketBuffer(clientEngine);
        serverPacketBuffer = bufferType.newPacketBuffer(serverEngine);

        // Generate the message to be sent from the client.
        int messageSize = config.messageSize();
        messageBuffer = bufferType.newBuffer(messageSize);
        messageBuffer.put(newTextMessage(messageSize));
        messageBuffer.flip();

        // Complete the initial TLS handshake.
        doEngineHandshake(clientEngine, serverEngine, clientApplicationBuffer, clientPacketBuffer,
                serverApplicationBuffer, serverPacketBuffer);

        // Populate the pre-encrypted buffer for use with the unwrap benchmark.
        preEncryptedBuffer = bufferType.newBuffer(clientEngine.getSession().getPacketBufferSize());
        doWrap(messageBuffer, preEncryptedBuffer);
        doUnwrap(preEncryptedBuffer, serverApplicationBuffer);
    }

    void teardown() {
        engineType.dispose(clientEngine);
        engineType.dispose(serverEngine);
    }

    void wrap() throws SSLException {
        // Reset the buffers.
        messageBuffer.position(0);
        clientPacketBuffer.clear();

        // Wrap the original message and create the encrypted data.
        doWrap(messageBuffer, clientPacketBuffer);

        // Lightweight comparison - just make sure the data length is correct.
        assertEquals(preEncryptedBuffer.limit(), clientPacketBuffer.limit());
    }

    /**
     * Simple benchmark that sends a single message from client to server.
     */
    void wrapAndUnwrap() throws SSLException {
        // Reset the buffers.
        messageBuffer.position(0);
        clientPacketBuffer.clear();
        serverApplicationBuffer.clear();

        // Wrap the original message and create the encrypted data.
        doWrap(messageBuffer, clientPacketBuffer);

        // Unwrap the encrypted data and get back the original result.
        doUnwrap(clientPacketBuffer, serverApplicationBuffer);

        // Lightweight comparison - just make sure the unencrypted data length is correct.
        assertEquals(messageBuffer.limit(), serverApplicationBuffer.limit());
    }

    private void doWrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        // Wrap the original message and create the encrypted data.
        verifyResult(src, clientEngine.wrap(src, dst));
        dst.flip();
    }

    private void doUnwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        verifyResult(src, serverEngine.unwrap(src, dst));
        dst.flip();
    }

    private void verifyResult(ByteBuffer src, SSLEngineResult result) {
        if (result.getStatus() != SSLEngineResult.Status.OK) {
            throw new RuntimeException("Operation returned unexpected result " + result);
        }
        if (result.bytesConsumed() != src.limit()) {
            throw new RuntimeException(
                    String.format("Operation didn't consume all bytes. Expected %d, consumed %d.",
                            src.limit(), result.bytesConsumed()));
        }
    }

    /**
     * A simple main for profiling.
     */
    public static void main(String[] args) throws Exception {
        EngineWrapBenchmark bm = new EngineWrapBenchmark(new Config() {
            @Override
            public BufferType bufferType() {
                return BufferType.HEAP;
            }

            @Override
            public EngineType engineType() {
                return EngineType.CONSCRYPT_POOLED;
            }

            @Override
            public int messageSize() {
                return 512;
            }

            @Override
            public String cipher() {
                return TestUtils.TEST_CIPHER;
            }
        });

        // Just run forever for profiling.
        while (true) {
            bm.wrapAndUnwrap();
        }
    }
}
