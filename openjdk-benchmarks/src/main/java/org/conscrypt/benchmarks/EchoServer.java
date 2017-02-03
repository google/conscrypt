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

import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * Simple echo server that responds with an identical message to the one received.
 */
final class EchoServer {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final SSLServerSocket serverSocket;
    private final int messageSize;
    private final byte[] buffer;
    private SSLSocket socket;
    private volatile boolean stopping;

    EchoServer(SSLServerSocket serverSocket, int messageSize) {
        this.serverSocket = serverSocket;
        this.messageSize = messageSize;
        buffer = new byte[messageSize];
    }

    Future<?> start() {
        return executor.submit(new AcceptTask());
    }

    void stop() {
        try {
            stopping = true;
            if (socket != null) {
                socket.close();
            }
            serverSocket.close();
            executor.shutdown();
            executor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    int port() {
        return serverSocket.getLocalPort();
    }

    private final class AcceptTask implements Runnable {
        @Override
        public void run() {
            try {
                if (stopping) {
                    return;
                }
                socket = (SSLSocket) serverSocket.accept();

                if (stopping) {
                    return;
                }
                executor.execute(new ReadTask());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private final class ReadTask implements Runnable {
        @Override
        public void run() {
            try {
                if (stopping) {
                    return;
                }
                byte[] output = readMessage();
                sendMessage(output);

                if (stopping) {
                    return;
                }
                // Keep running the task until it's being shut down.
                executor.execute(this);
            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
        }
    }

    private byte[] readMessage() {
        try {
            int totalBytesRead = 0;
            while (totalBytesRead < messageSize) {
                int remaining = messageSize - totalBytesRead;
                int bytesRead = socket.getInputStream().read(buffer, totalBytesRead, remaining);
                if (bytesRead == -1) {
                    break;
                }
                totalBytesRead += bytesRead;
            }
            return Arrays.copyOfRange(buffer, 0, totalBytesRead);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    private void sendMessage(byte[] data) {
        try {
            socket.getOutputStream().write(data);
            socket.getOutputStream().flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
