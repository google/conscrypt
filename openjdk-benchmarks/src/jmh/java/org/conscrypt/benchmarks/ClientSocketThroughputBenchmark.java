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
import static org.conscrypt.testing.TestUtil.getConscryptSocketFactory;
import static org.conscrypt.testing.TestUtil.getJdkServerSocketFactory;
import static org.conscrypt.testing.TestUtil.getJdkSocketFactory;
import static org.conscrypt.testing.TestUtil.getProtocols;
import static org.conscrypt.testing.TestUtil.newTextMessage;
import static org.conscrypt.testing.TestUtil.pickUnusedPort;

import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.conscrypt.testing.TestClient;
import org.conscrypt.testing.TestServer;
import org.openjdk.jmh.annotations.AuxCounters;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

/**
 * Benchmark for comparing performance of client socket implementations. All benchmarks use Netty
 * with tcnative as the server.
 */
@State(Scope.Benchmark)
@Fork(1)
public class ClientSocketThroughputBenchmark {
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
     * Various factories for SSL sockets.
     */
    public enum SslProvider {
        JDK(getJdkSocketFactory(), getJdkServerSocketFactory()),
        CONSCRYPT(getConscryptSocketFactory(false), getConscryptServerSocketFactory(false)),
        CONSCRYPT_ENGINE(getConscryptSocketFactory(true), getConscryptServerSocketFactory(true)) {
            @Override
            SSLSocket newClientSocket(String host, int port, SSLSocketFactory socketFactory)  throws IOException {
                return (SSLSocket) socketFactory.createSocket(
                    SocketFactory.getDefault().createSocket(host, port), host, port, true);
            }
        };

        private final SSLSocketFactory clientSocketFactory;
        private final SSLServerSocketFactory serverSocketFactory;

        SslProvider(SSLSocketFactory clientSocketFactory, SSLServerSocketFactory serverSocketFactory) {
            this.clientSocketFactory = clientSocketFactory;
            this.serverSocketFactory = serverSocketFactory;
        }

        final SSLSocket newClientSocket(String host, int port, String cipher) {
            try {
                SSLSocket sslSocket = newClientSocket(host, port, clientSocketFactory);
                sslSocket.setEnabledProtocols(getProtocols());
                sslSocket.setEnabledCipherSuites(new String[] {cipher});
                return sslSocket;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        SSLSocket newClientSocket(String host, int port, SSLSocketFactory socketFactory)  throws IOException {
            return (SSLSocket) socketFactory.createSocket(host, port);
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

    @Setup(Level.Trial)
    public void setup() throws Exception {
        recording.set(false);

        message = newTextMessage(messageSize);

        server = new TestServer(sslProvider.newServerSocket(cipher), messageSize);
        server.setMessageProcessor(new TestServer.MessageProcessor() {
            @Override
            public void processMessage(byte[] inMessage, int numBytes, OutputStream os) {
                if (recording.get()) {
                    // Server received a message, increment the count.
                    bytesCounter.addAndGet(numBytes);
                }
            }
        });
        Future<?> connectedFuture = server.start();

        client = new TestClient(sslProvider.newClientSocket(LOCALHOST, server.port(), cipher));
        client.start();

        // Wait for the initial connection to complete.
        connectedFuture.get(5, TimeUnit.SECONDS);

        executor = Executors.newSingleThreadExecutor();
        executor.submit(new Runnable() {
            @Override
            public void run() {
                Thread thread = Thread.currentThread();
                while (!stopping && !thread.isInterrupted()) {
                    client.sendMessage(message);
                }
            }
        });
    }

    @TearDown(Level.Trial)
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
