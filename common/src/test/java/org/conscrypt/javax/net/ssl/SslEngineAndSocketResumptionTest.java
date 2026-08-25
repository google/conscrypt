/*
 * Copyright (C) 2026 The Android Open Source Project
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

package org.conscrypt.javax.net.ssl;

import static org.conscrypt.TestUtils.UTF_8;
import static org.junit.Assert.assertEquals;

import static java.util.concurrent.TimeUnit.SECONDS;

import org.conscrypt.Conscrypt;
import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;

@RunWith(JUnit4.class)
public class SslEngineAndSocketResumptionTest {
    private static void exchangeEngineMessages(SSLEngine client, SSLEngine server)
            throws SSLException {
        ByteBuffer clientOut = ByteBuffer.allocate(client.getSession().getPacketBufferSize());
        ByteBuffer serverIn = ByteBuffer.allocate(server.getSession().getApplicationBufferSize());
        SSLEngineResult wrapRes = client.wrap(ByteBuffer.wrap("ping".getBytes(UTF_8)), clientOut);
        assertEquals(SSLEngineResult.Status.OK, wrapRes.getStatus());
        clientOut.flip();

        while (clientOut.hasRemaining()) {
            SSLEngineResult unwrapRes = server.unwrap(clientOut, serverIn);
            assertEquals(SSLEngineResult.Status.OK, unwrapRes.getStatus());
        }

        ByteBuffer serverOut = ByteBuffer.allocate(server.getSession().getPacketBufferSize());
        ByteBuffer clientIn = ByteBuffer.allocate(client.getSession().getApplicationBufferSize());
        wrapRes = server.wrap(ByteBuffer.wrap("pong".getBytes(UTF_8)), serverOut);
        assertEquals(SSLEngineResult.Status.OK, wrapRes.getStatus());
        serverOut.flip();

        while (serverOut.hasRemaining()) {
            SSLEngineResult unwrapRes = client.unwrap(serverOut, clientIn);
            assertEquals(SSLEngineResult.Status.OK, unwrapRes.getStatus());
        }
    }

    private static void exchangeSocketMessages(SSLSocket client, SSLSocket server)
            throws IOException {
        client.getOutputStream().write('A');
        assertEquals((int) 'A', server.getInputStream().read());
        server.getOutputStream().write('B');
        assertEquals((int) 'B', client.getInputStream().read());
    }

    private static void connectSockets(final SSLSocket client, final SSLSocket server)
            throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        Future<Void> s = executor.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                TestUtils.setUseSessionTickets(server, true);
                server.startHandshake();
                return null;
            }
        });
        Future<Void> c = executor.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                TestUtils.setUseSessionTickets(client, true);
                client.startHandshake();
                return null;
            }
        });
        executor.shutdown();

        c.get(30, SECONDS);
        s.get(30, SECONDS);
    }

    @Test
    public void test_resumption_engineThenSocket() throws Exception {
        TestSSLContext context = TestSSLContext.newBuilder()
                                         .clientProtocol("TLSv1.3")
                                         .serverProtocol("TLSv1.3")
                                         .build();
        try {
            // 1. First handshake via SSLEngine
            TestSSLEnginePair.Hooks hooks = new TestSSLEnginePair.Hooks() {
                @Override
                void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                    Conscrypt.setUseSessionTickets(client, true);
                    Conscrypt.setUseSessionTickets(server, true);
                }
            };
            SSLEngine[] engines = TestSSLEnginePair.connect(context, hooks);
            SSLEngine serverEngine = engines[0];
            SSLEngine clientEngine = engines[1];

            // Exchange messages to ensure TLS 1.3 NewSessionTicket is received and cached
            exchangeEngineMessages(clientEngine, serverEngine);

            TestSSLEnginePair.close(engines);

            // 2. Second handshake via SSLSocket using the same clientContext (same host and port)
            SSLSocket clientSocket =
                    (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                    context.host.getHostName(), context.port);
            SSLSocket serverSocket = (SSLSocket) context.serverSocket.accept();

            try {
                connectSockets(clientSocket, serverSocket);
                exchangeSocketMessages(clientSocket, serverSocket);
            } finally {
                clientSocket.close();
                serverSocket.close();
            }
        } finally {
            context.close();
        }
    }

    @Test
    public void test_resumption_socketThenEngine() throws Exception {
        TestSSLContext context = TestSSLContext.newBuilder()
                                         .clientProtocol("TLSv1.3")
                                         .serverProtocol("TLSv1.3")
                                         .build();
        try {
            // 1. First handshake via SSLSocket
            SSLSocket clientSocket =
                    (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                    context.host.getHostName(), context.port);
            SSLSocket serverSocket = (SSLSocket) context.serverSocket.accept();

            connectSockets(clientSocket, serverSocket);
            exchangeSocketMessages(clientSocket, serverSocket);

            clientSocket.close();
            serverSocket.close();

            // 2. Second handshake via SSLEngine using the same clientContext (same host and port)
            TestSSLEnginePair.Hooks hooks = new TestSSLEnginePair.Hooks() {
                @Override
                void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                    Conscrypt.setUseSessionTickets(client, true);
                    Conscrypt.setUseSessionTickets(server, true);
                }
            };
            SSLEngine[] engines = null;
            try {
                engines = TestSSLEnginePair.connect(context, hooks);
                exchangeEngineMessages(engines[1], engines[0]);
            } finally {
                if (engines != null) {
                    TestSSLEnginePair.close(engines);
                }
            }
        } finally {
            context.close();
        }
    }
}
