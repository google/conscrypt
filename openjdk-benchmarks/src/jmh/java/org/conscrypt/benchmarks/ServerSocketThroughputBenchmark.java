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

package org.conscrypt.benchmarks;

import static org.conscrypt.testing.TestUtil.LOCALHOST;
import static org.conscrypt.testing.TestUtil.getConscryptServerSocketFactory;
import static org.conscrypt.testing.TestUtil.getJdkServerSocketFactory;
import static org.conscrypt.testing.TestUtil.getJdkSocketFactory;
import static org.conscrypt.testing.TestUtil.getProtocols;
import static org.conscrypt.testing.TestUtil.newTextMessage;
import static org.conscrypt.testing.TestUtil.pickUnusedPort;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.conscrypt.testing.TestClient;
import org.conscrypt.testing.TestServer;
import org.conscrypt.testing.TestServer.MessageProcessor;
import org.openjdk.jmh.annotations.AuxCounters;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

/**
 * Benchmark for comparing performance of server socket implementations. All benchmarks use the
 * standard JDK TLS implementation.
 */
@State(Scope.Benchmark)
public class ServerSocketThroughputBenchmark {
    /**
     * Use an AuxCounter so we can measure that bytes per second as they accumulate without
     * consuming CPU in the benchmark method.
     */
    @AuxCounters
    @State(Scope.Thread)
    public static class BytesPerSecondCounter {
        @Setup(Level.Iteration)
        public void clean() {
            bytesCounter.set(0);
        }

        public long bytesPerSecond() {
            return bytesCounter.get();
        }
    }

    /**
     * Various factories for SSL server sockets.
     */
    public enum SslProvider {
        JDK(getJdkServerSocketFactory()),
        CONSCRYPT(getConscryptServerSocketFactory(false)),
        CONSCRYPT_ENGINE(getConscryptServerSocketFactory(true));

        private final SSLServerSocketFactory serverSocketFactory;

        SslProvider(SSLServerSocketFactory serverSocketFactory) {
            this.serverSocketFactory = serverSocketFactory;
        }

        final SSLServerSocket newServerSocket(String cipher) {
            try {
                int port = pickUnusedPort();
                SSLServerSocket sslSocket =
                        (SSLServerSocket) serverSocketFactory.createServerSocket(port);
                sslSocket.setEnabledProtocols(getProtocols());
                sslSocket.setEnabledCipherSuites(new String[] {cipher});
                return sslSocket;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Param public SslProvider sslProvider;

    @Param({"64", "1024"}) public int messageSize;

    @Param({"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}) public String cipher;

    private TestClient client;
    private TestServer server;
    private byte[] message;
    private ExecutorService executor;
    private volatile boolean stopping;
    private static final AtomicLong bytesCounter = new AtomicLong();
    private AtomicBoolean recording = new AtomicBoolean();

    @Setup
    public void setup() throws Exception {
        recording.set(false);

        message = newTextMessage(messageSize);

        server = new TestServer(sslProvider.newServerSocket(cipher), messageSize);
        server.setMessageProcessor(new MessageProcessor() {
            @Override
            public void processMessage(byte[] inMessage, int numBytes, OutputStream os) {
                try {
                    while (!stopping) {
                        os.write(inMessage, 0, numBytes);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        });

        Future<?> connectedFuture = server.start();

        SSLSocket socket;
        try {
            SSLSocketFactory socketFactory = getJdkSocketFactory();
            socket = (SSLSocket) socketFactory.createSocket(LOCALHOST, server.port());
            socket.setEnabledProtocols(getProtocols());
            socket.setEnabledCipherSuites(new String[] {cipher});
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        client = new TestClient(socket);
        client.start();

        // Wait for the initial connection to complete.
        connectedFuture.get(5, TimeUnit.SECONDS);

        // Start the server-side streaming by sending a message to the server.
        client.sendMessage(message);
        client.flush();

        executor = Executors.newSingleThreadExecutor();
        executor.submit(new Runnable() {
            @Override
            public void run() {
                Thread thread = Thread.currentThread();
                byte[] buffer = new byte[messageSize];
                while (!stopping && !thread.isInterrupted()) {
                    int numBytes = client.readMessage(buffer);
                    assertEquals(messageSize, numBytes);

                    // Increment the message counter if we're recording.
                    if (recording.get()) {
                        bytesCounter.addAndGet(numBytes);
                    }
                }
            }
        });
    }

    @TearDown
    public void teardown() throws Exception {
        stopping = true;
        client.stop();
        server.stop();
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);
    }

    @Benchmark
    public final void throughput(BytesPerSecondCounter counter) throws Exception {
        recording.set(true);
        // No need to do anything, just sleep here.
        Thread.sleep(1001);
        recording.set(false);
    }
}
