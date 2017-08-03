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
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.conscrypt.ServerEndpoint.MessageProcessor;

/**
 * Benchmark for comparing performance of server socket implementations.
 */
public final class ServerSocketBenchmark {
    /**
     * Provider for the benchmark configuration
     */
    interface Config {
        SocketType socketType();
        int messageSize();
        String cipher();
        ChannelType channelType();
    }

    private ClientEndpoint client;
    private ServerEndpoint server;
    private ExecutorService executor;
    private Future<?> receivingFuture;
    private volatile boolean stopping;
    private static final AtomicLong bytesCounter = new AtomicLong();
    private AtomicBoolean recording = new AtomicBoolean();

    ServerSocketBenchmark(final Config config) throws Exception {
        recording.set(false);

        byte[] message = newTextMessage(config.messageSize());

        final ChannelType channelType = config.channelType();

        server = config.socketType().newServer(
            channelType, config.messageSize(), getProtocols(), ciphers(config));
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

        // Always use the same client for consistency across the benchmarks.
        client = SocketType.CONSCRYPT_ENGINE.newClient(
                ChannelType.CHANNEL, server.port(), getProtocols(), ciphers(config));
        client.start();

        // Wait for the initial connection to complete.
        connectedFuture.get(5, TimeUnit.SECONDS);

        // Start the server-side streaming by sending a message to the server.
        client.sendMessage(message);
        client.flush();

        executor = Executors.newSingleThreadExecutor();
        receivingFuture = executor.submit(new Runnable() {
            @Override
            public void run() {
                Thread thread = Thread.currentThread();
                byte[] buffer = new byte[config.messageSize()];
                while (!stopping && !thread.isInterrupted()) {
                    int numBytes = client.readMessage(buffer);
                    assertEquals(config.messageSize(), numBytes);

                    // Increment the message counter if we're recording.
                    if (recording.get()) {
                        bytesCounter.addAndGet(numBytes);
                    }
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
        receivingFuture.get(5, TimeUnit.SECONDS);
    }

    void throughput() throws Exception {
        recording.set(true);
        // Send as many messages as we can in a second.
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
        ServerSocketBenchmark bm = new ServerSocketBenchmark(new Config() {
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
            public ChannelType channelType() {
                return ChannelType.CHANNEL;
            }
        });

        // Just run forever for profiling.
        while (true) {
            bm.throughput();
        }
    }
}
