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

package org.conscrypt;

import static org.conscrypt.TestUtils.getProtocols;
import static org.conscrypt.TestUtils.newTextMessage;

import java.io.OutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Benchmark for comparing performance of client socket implementations. All benchmarks use Netty
 * with tcnative as the server.
 */
public final class ClientSocketBenchmark {
    /**
     * Provider for the benchmark configuration
     */
    interface Config {
        SocketType socketType();
        int messageSize();
        String cipher();
        WrappedSocketType wrappedSocketType();
    }

    private ClientEndpoint client;
    private ServerEndpoint server;
    private byte[] message;
    private ExecutorService executor;
    private Future<?> sendingFuture;
    private volatile boolean stopping;

    private static final AtomicLong bytesCounter = new AtomicLong();
    private AtomicBoolean recording = new AtomicBoolean();

    ClientSocketBenchmark(Config config) throws Exception {
        recording.set(false);

        message = newTextMessage(config.messageSize());

        // Always use the same server for consistency across the benchmarks.
        server = SocketType.CONSCRYPT_ENGINE.newServer(
                WrappedSocketType.CHANNEL, config.messageSize(), getProtocols(), ciphers(config));

        server.setMessageProcessor(new ServerEndpoint.MessageProcessor() {
            @Override
            public void processMessage(byte[] inMessage, int numBytes, OutputStream os) {
                if (recording.get()) {
                    // Server received a message, increment the count.
                    bytesCounter.addAndGet(numBytes);
                }
            }
        });
        Future<?> connectedFuture = server.start();

        client = config.socketType().newClient(
            config.wrappedSocketType(), server.port(), getProtocols(), ciphers(config));
        client.start();

        // Wait for the initial connection to complete.
        connectedFuture.get(5, TimeUnit.SECONDS);

        executor = Executors.newSingleThreadExecutor();
        sendingFuture = executor.submit(new Runnable() {
            @Override
            public void run() {
                Thread thread = Thread.currentThread();
                while (!stopping && !thread.isInterrupted()) {
                    client.sendMessage(message);
                }
            }
        });
    }

    void close() throws Exception {
        stopping = true;
        client.stop();
        server.stop();
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);
        sendingFuture.get(5, TimeUnit.SECONDS);
    }

    /**
     * Simple benchmark for throughput.
     */
    void throughput() throws Exception {
        recording.set(true);
        // No need to do anything, just sleep here.
        Thread.sleep(1001);
        recording.set(false);
    }

    static void reset() {
        bytesCounter.set(0);
    }

    static long bytesPerSecond() {
        return bytesCounter.get();
    }

    private String[] ciphers(Config config) {
        return new String[] {config.cipher()};
    }

    /**
     * A simple main for profiling.
     */
    public static void main(String[] args) throws Exception {
        ClientSocketBenchmark bm = new ClientSocketBenchmark(new Config() {
            @Override
            public SocketType socketType() {
                return SocketType.CONSCRYPT_ENGINE;
            }

            @Override
            public int messageSize() {
                return 512;
            }

            @Override
            public String cipher() {
                return TestUtils.TEST_CIPHER;
            }

            @Override
            public WrappedSocketType wrappedSocketType() {
                return WrappedSocketType.CHANNEL;
            }
        });

        // Just run forever for profiling.
        while (true) {
            bm.throughput();
        }
    }
}
