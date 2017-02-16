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
import static org.conscrypt.testing.TestUtil.getConscryptSocketFactory;
import static org.conscrypt.testing.TestUtil.getJdkSocketFactory;
import static org.conscrypt.testing.TestUtil.getProtocols;
import static org.conscrypt.testing.TestUtil.newTextMessage;
import static org.conscrypt.testing.TestUtil.pickUnusedPort;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.conscrypt.testing.NettyServer;
import org.conscrypt.testing.NettyServer.MessageProcessor;
import org.conscrypt.testing.TestClient;
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
     * Use an AuxCounter so we can measure that messages per second as they occur without consuming
     * CPU in the benchmark method.
     */
    @AuxCounters
    @State(Scope.Thread)
    public static class MessagesPerSecondCounter {
        @Setup(Level.Iteration)
        public void clean() {
            messageCounter.set(0);
        }

        public long messagesPerSecond() {
            return messageCounter.get();
        }
    }

    /**
     * Various factories for SSL sockets.
     */
    public enum SslProvider {
        JDK {
            private final SSLSocketFactory socketFactory = getJdkSocketFactory();
            @Override
            SSLSocket newSslSocket(String host, int port) throws IOException  {
                    return (SSLSocket) socketFactory.createSocket(host, port);
            }
        },
        CONSCRYPT {
            private final SSLSocketFactory socketFactory = getConscryptSocketFactory(false);
            @Override
            SSLSocket newSslSocket(String host, int port)  throws IOException {
                    return (SSLSocket) socketFactory.createSocket(host, port);
            }
        },
        CONSCRYPT_ENGINE {
            private final SSLSocketFactory socketFactory = getConscryptSocketFactory(true);
            @Override
            SSLSocket newSslSocket(String host, int port)  throws IOException {
                    return (SSLSocket) socketFactory.createSocket(
                            SocketFactory.getDefault().createSocket(host, port), host, port, true);
            }
        };

        final SSLSocket newSslSocket(String host, int port, String cipher) {
            try {
                SSLSocket sslSocket = newSslSocket(host, port);
                sslSocket.setEnabledProtocols(getProtocols());
                sslSocket.setEnabledCipherSuites(new String[] {cipher});
                return sslSocket;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        abstract SSLSocket newSslSocket(String host, int port) throws IOException;
    }

    @Param public SslProvider sslProvider;

    @Param({"64", "1024"}) public int messageSize;

    @Param({"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}) public String cipher;

    private TestClient client;
    private NettyServer server;
    private byte[] message;
    private ExecutorService executor;
    private volatile boolean stopping;

    private static final AtomicLong messageCounter = new AtomicLong();
    private AtomicBoolean recording = new AtomicBoolean();

    @Setup(Level.Trial)
    public void setup() throws Exception {
        recording.set(false);

        message = newTextMessage(messageSize);

        int port = pickUnusedPort();
        server = new NettyServer(port, messageSize, cipher);
        server.setMessageProcessor(new MessageProcessor() {
            @Override
            public void processMessage(ChannelHandlerContext ctx, ByteBuf request) {
                if (recording.get()) {
                    // Server received a message, increment the count.
                    messageCounter.incrementAndGet();
                }
            }
        });
        server.start();

        client = new TestClient(sslProvider.newSslSocket(LOCALHOST, port, cipher));
        client.start();

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
    public final void throughput(MessagesPerSecondCounter counter) throws Exception {
        recording.set(true);
        // No need to do anything, just sleep here.
        Thread.sleep(1001);
        recording.set(false);
    }
}
