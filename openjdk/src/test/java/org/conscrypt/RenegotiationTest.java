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
 * limitations under the License
 */

package org.conscrypt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.conscrypt.java.security.TestKeyStore;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * This tests that server-initiated cipher renegotiation works properly with a Conscrypt client.
 * BoringSSL does not support user-initiated renegotiation, so we use the JDK implementation for
 * the server.
 */
@RunWith(Parameterized.class)
public class RenegotiationTest {
    private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocateDirect(0);
    private static final byte[] MESSAGE_BYTES = "Hello".getBytes(TestUtils.UTF_8);
    private static final ByteBuffer MESSAGE_BUFFER =
            ByteBuffer.wrap(MESSAGE_BYTES).asReadOnlyBuffer();
    private static final int MESSAGE_LENGTH = MESSAGE_BYTES.length;

    public enum SocketType {
        FILE_DESCRIPTOR {
            @Override
            Client newClient(int port) {
                return new Client(false, port);
            }
        },
        ENGINE {
            @Override
            Client newClient(int port) {
                return new Client(true, port);
            }
        };

        abstract Client newClient(int port);
    }

    @Parameters(name = "{0}")
    public static Object[] data() {
        return new Object[] {SocketType.FILE_DESCRIPTOR, SocketType.ENGINE};
    }

    @Parameter
    public SocketType socketType;

    private Client client;
    private Server server;

    @Before
    public void setup() throws Exception {
        server = new Server();
        Future<?> connectedFuture = server.start();

        client = socketType.newClient(server.port());
        client.start();

        // Wait for the initial connection to complete.
        connectedFuture.get(5, TimeUnit.SECONDS);
    }

    @After
    public void teardown() {
        client.stop();
        server.stop();
    }

    @Test
    public void test() throws Exception {
        client.socket.startHandshake();
        String initialCipher = client.socket.getSession().getCipherSuite();

        client.sendMessage();

        Future<?> repliesFuture = client.readReplies();
        server.await(5, TimeUnit.SECONDS);
        repliesFuture.get(5, TimeUnit.SECONDS);

        // Verify that the cipher has changed.
        assertNotEquals(initialCipher, client.socket.getSession().getCipherSuite());
    }

    private static SSLContext newConscryptClientContext() {
        SSLContext context = TestUtils.newContext(TestUtils.getConscryptProvider());
        return TestUtils.initSslContext(context, TestKeyStore.getClient());
    }

    private static SSLContext newJdkServerContext() {
        SSLContext context = TestUtils.newContext(TestUtils.getJdkProvider());
        return TestUtils.initSslContext(context, TestKeyStore.getServer());
    }

    private static final class Client {
        private final SSLSocket socket;
        private ExecutorService executor;

        Client(boolean useEngineSocket, int port) {
            try {
                SSLSocketFactory socketFactory = newConscryptClientContext().getSocketFactory();
                Conscrypt.setUseEngineSocket(socketFactory, useEngineSocket);
                socket = (SSLSocket) socketFactory.createSocket(
                        TestUtils.getLoopbackAddress(), port);
                socket.setEnabledProtocols(TestUtils.getProtocols());
                socket.setEnabledCipherSuites(TestUtils.getCommonCipherSuites());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        void start() {
            try {
                executor = Executors.newSingleThreadExecutor();
                socket.startHandshake();
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }

        void stop() {
            try {
                socket.close();

                if (executor != null) {
                    executor.shutdown();
                    executor.awaitTermination(5, TimeUnit.SECONDS);
                    executor = null;
                }
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        Future<?> readReplies() {
            return executor.submit(new Runnable() {
                @Override
                public void run() {
                    readReply();
                }
            });
        }

        private void readReply() {
            try {
                byte[] buffer = new byte[MESSAGE_LENGTH];
                int totalBytesRead = 0;
                while (totalBytesRead < MESSAGE_LENGTH) {
                    int remaining = MESSAGE_LENGTH - totalBytesRead;
                    int bytesRead = socket.getInputStream().read(buffer, totalBytesRead, remaining);
                    if (bytesRead == -1) {
                        throw new EOFException();
                    }
                    totalBytesRead += bytesRead;
                }

                // Verify the reply is correct.
                assertEquals(MESSAGE_LENGTH, totalBytesRead);
                assertArrayEquals(MESSAGE_BYTES, buffer);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        void sendMessage() throws IOException {
            try {
                socket.getOutputStream().write(MESSAGE_BYTES);
                socket.getOutputStream().flush();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static final class Server {
        private final ServerSocketChannel serverChannel;
        private final SSLEngine engine;
        private final ByteBuffer inboundPacketBuffer;
        private final ByteBuffer inboundAppBuffer;
        private final ByteBuffer outboundPacketBuffer;
        private final Set<String> ciphers = new LinkedHashSet<String>(Arrays.asList(
            TestUtils.getCommonCipherSuites()));
        private SocketChannel channel;
        private ExecutorService executor;
        private volatile boolean stopping;
        private volatile Future<?> echoFuture;

        Server() throws IOException {
            serverChannel = ServerSocketChannel.open();
            serverChannel.socket().bind(new InetSocketAddress(TestUtils.getLoopbackAddress(), 0));
            engine = newJdkServerContext().createSSLEngine();
            engine.setEnabledProtocols(TestUtils.getProtocols());
            engine.setEnabledCipherSuites(TestUtils.getCommonCipherSuites());
            engine.setUseClientMode(false);

            inboundPacketBuffer =
                    ByteBuffer.allocateDirect(engine.getSession().getPacketBufferSize());
            inboundAppBuffer =
                    ByteBuffer.allocateDirect(engine.getSession().getApplicationBufferSize());
            outboundPacketBuffer =
                    ByteBuffer.allocateDirect(engine.getSession().getPacketBufferSize());
        }

        Future<?> start() throws IOException {
            executor = Executors.newSingleThreadExecutor();
            return executor.submit(new AcceptTask());
        }

        void await(long timeout, TimeUnit unit)
                throws InterruptedException, ExecutionException, TimeoutException {
            echoFuture.get(timeout, unit);
        }

        void stop() {
            try {
                stopping = true;

                if (channel != null) {
                    channel.close();
                    channel = null;
                }

                serverChannel.close();

                if (executor != null) {
                    executor.shutdown();
                    executor.awaitTermination(5, TimeUnit.SECONDS);
                    executor = null;
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }

        int port() {
            return serverChannel.socket().getLocalPort();
        }

        private final class AcceptTask implements Runnable {
            @Override
            public void run() {
                try {
                    if (stopping) {
                        return;
                    }
                    channel = serverChannel.accept();
                    channel.configureBlocking(false);

                    doHandshake();

                    if (stopping) {
                        return;
                    }
                    echoFuture = executor.submit(new EchoTask());
                } catch (Throwable e) {
                    e.printStackTrace();
                    throw new RuntimeException(e);
                }
            }
        }

        private final class EchoTask implements Runnable {
            @Override
            public void run() {
                try {
                    readMessage();
                    renegotiate();
                    reply();
                } catch (Throwable e) {
                    e.printStackTrace();
                    throw new RuntimeException(e);
                }
            }

            private void renegotiate() throws Exception {
                // Remove the current cipher from the set and renegotiate to force a new
                // cipher to be selected.
                String currentCipher = engine.getSession().getCipherSuite();
                ciphers.remove(currentCipher);
                engine.setEnabledCipherSuites(ciphers.toArray(new String[ciphers.size()]));
                doHandshake();
            }

            private void reply() throws IOException {
                SSLEngineResult result = wrap(newMessage());
                if (result.getStatus() != Status.OK) {
                    throw new RuntimeException("Wrap failed. Status: " + result.getStatus());
                }
            }

            private ByteBuffer newMessage() {
                return MESSAGE_BUFFER.duplicate();
            }

            private void readMessage() throws IOException {
                int totalProduced = 0;
                while (!stopping) {
                    SSLEngineResult result = unwrap();
                    if (result.getStatus() != Status.OK) {
                        throw new RuntimeException("Failed reading message: " + result);
                    }
                    totalProduced += result.bytesProduced();
                    if (totalProduced == MESSAGE_LENGTH) {
                        return;
                    }
                }
            }
        }

        private SSLEngineResult wrap(ByteBuffer src) throws IOException {
            outboundPacketBuffer.clear();

            // Check if the engine has bytes to wrap.
            SSLEngineResult result = engine.wrap(src, outboundPacketBuffer);

            // Write any wrapped bytes to the socket.
            outboundPacketBuffer.flip();

            do {
                channel.write(outboundPacketBuffer);
            } while (outboundPacketBuffer.hasRemaining());

            return result;
        }

        private SSLEngineResult unwrap() throws IOException {
            // Unwrap any available bytes from the socket.
            SSLEngineResult result = null;
            boolean done = false;
            while (!done) {
                if (channel.read(inboundPacketBuffer) == -1) {
                    throw new EOFException();
                }
                // Just clear the app buffer - we don't really use it.
                inboundAppBuffer.clear();
                inboundPacketBuffer.flip();
                result = engine.unwrap(inboundPacketBuffer, inboundAppBuffer);
                switch (result.getStatus()) {
                    case BUFFER_UNDERFLOW:
                        // Continue reading from the socket in a moment.
                        try {
                            Thread.sleep(10);
                        } catch (InterruptedException e) {
                            throw new RuntimeException(e);
                        }
                        break;
                    case OK:
                        done = true;
                        break;
                    default: { throw new RuntimeException("Unexpected unwrap result: " + result); }
                }

                // Compact for the next socket read.
                inboundPacketBuffer.compact();
            }
            return result;
        }

        private void doHandshake() throws IOException {
            engine.beginHandshake();

            boolean done = false;
            while (!done) {
                switch (engine.getHandshakeStatus()) {
                    case NEED_WRAP: {
                        wrap(EMPTY_BUFFER);
                        break;
                    }
                    case NEED_UNWRAP: {
                        unwrap();
                        break;
                    }
                    case NEED_TASK: {
                        runDelegatedTasks();
                        break;
                    }
                    default: {
                        done = true;
                        break;
                    }
                }
            }
        }

        private void runDelegatedTasks() {
            for (;;) {
                Runnable task = engine.getDelegatedTask();
                if (task == null) {
                    break;
                }
                task.run();
            }
        }
    }
}
