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

import static org.conscrypt.benchmarks.Util.LOCALHOST;
import static org.conscrypt.benchmarks.Util.getConscryptSocketFactory;
import static org.conscrypt.benchmarks.Util.getJdkSocketFactory;
import static org.conscrypt.benchmarks.Util.getProtocols;
import static org.conscrypt.benchmarks.Util.newTextMessage;
import static org.conscrypt.benchmarks.Util.pickUnusedPort;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.openjdk.jmh.annotations.Benchmark;
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
public class ClientSocketBenchmark {
    /**
     * Various factories for SSL sockets.
     */
    public enum SslSocketType {
        JDK {
            private final SSLSocketFactory socketFactory = getJdkSocketFactory();
            @Override
            SSLSocket newSslSocket(String host, int port) {
                try {
                    return (SSLSocket) socketFactory.createSocket(host, port);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        },
        CONSCRYPT {
            private final SSLSocketFactory socketFactory = getConscryptSocketFactory(false);
            @Override
            SSLSocket newSslSocket(String host, int port) {
                try {
                    return (SSLSocket) socketFactory.createSocket(host, port);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        },
        CONSCRYPT_ENGINE {
            private final SSLSocketFactory socketFactory = getConscryptSocketFactory(true);
            @Override
            SSLSocket newSslSocket(String host, int port) {
                try {
                    return (SSLSocket) socketFactory.createSocket(
                            SocketFactory.getDefault().createSocket(host, port), host, port, true);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
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

        abstract SSLSocket newSslSocket(String host, int port);
    }

    /**
     * Various factories for the raw socket that backs the SSL socket.
     */
    public enum SocketType {
        DEFAULT {
            @Override
            Socket newSocket(String host, int port) {
                try {
                    return SocketFactory.getDefault().createSocket(host, port);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        },
        CHANNEL {
            @Override
            Socket newSocket(String host, int port) {
                try {
                    SocketChannel socketChannel =
                            SocketChannel.open(new InetSocketAddress(host, port));
                    return socketChannel.socket();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };

        abstract Socket newSocket(String host, int port);
    }

    @Param public SslSocketType sslSocketType;

    @Param({"64", "128", "512", "1024", "4096"}) public int messageSize;

    @Param({"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"}) public String cipher;

    @Param SocketType socketType;

    private Client client;
    private NettyEchoServer server;
    private byte[] message;

    @Setup
    public void setup() throws Exception {
        message = newTextMessage(messageSize);

        int port = pickUnusedPort();
        server = new NettyEchoServer(port, messageSize, cipher);
        server.start();

        client = new Client(port);
        client.start();
    }

    @TearDown
    public void teardown() throws Exception {
        client.stop();
        server.stop();
    }

    @Benchmark
    public void pingPong() throws IOException {
        client.sendMessage(message);
        byte[] output = client.readMessage();
        assertTrue(Arrays.equals(message, output));
    }

    /**
     * Client-side endpoint. Provides basic services for sending/receiving messages from the client
     * socket.
     */
    private final class Client {
        private byte[] buffer = new byte[messageSize];
        private final SSLSocket socket;

        Client(int port) {
            socket = sslSocketType.newSslSocket(LOCALHOST, port, cipher);
        }

        void start() {
            try {
                socket.startHandshake();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        void stop() {
            try {
                socket.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        byte[] readMessage() {
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

        void sendMessage(byte[] data) {
            try {
                socket.getOutputStream().write(data);
                socket.getOutputStream().flush();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
