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

import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

/**
 * Benchmark comparing handshake performance of various engine implementations to conscrypt.
 */
public final class EngineHandshakeBenchmark {
    /**
     * Provider for the benchmark configuration
     */
    interface Config {
        BufferType bufferType();
        EngineFactory engineFactory();
        String cipher();
        boolean useAlpn();
    }

    private final EngineFactory engineFactory;
    private final String cipher;
    private final boolean useAlpn;

    private final ByteBuffer clientApplicationBuffer;
    private final ByteBuffer clientPacketBuffer;
    private final ByteBuffer serverApplicationBuffer;
    private final ByteBuffer serverPacketBuffer;

    EngineHandshakeBenchmark(Config config) throws Exception {
        engineFactory = config.engineFactory();
        cipher = config.cipher();
        useAlpn = config.useAlpn();
        BufferType bufferType = config.bufferType();

        SSLEngine clientEngine = engineFactory.newClientEngine(cipher, useAlpn);
        SSLEngine serverEngine = engineFactory.newServerEngine(cipher, useAlpn);

        // Create the application and packet buffers for both endpoints.
        clientApplicationBuffer = bufferType.newApplicationBuffer(clientEngine);
        serverApplicationBuffer = bufferType.newApplicationBuffer(serverEngine);
        clientPacketBuffer = bufferType.newPacketBuffer(clientEngine);
        serverPacketBuffer = bufferType.newPacketBuffer(serverEngine);

        engineFactory.dispose(clientEngine);
        engineFactory.dispose(serverEngine);
    }

    void handshake() throws SSLException {
        SSLEngine client = engineFactory.newClientEngine(cipher, useAlpn);
        SSLEngine server = engineFactory.newServerEngine(cipher, useAlpn);
        clientApplicationBuffer.clear();
        clientPacketBuffer.clear();
        serverApplicationBuffer.clear();
        serverPacketBuffer.clear();

        doEngineHandshake(client, server, clientApplicationBuffer, clientPacketBuffer,
                serverApplicationBuffer, serverPacketBuffer, true);
        engineFactory.dispose(client);
        engineFactory.dispose(server);
    }
}
