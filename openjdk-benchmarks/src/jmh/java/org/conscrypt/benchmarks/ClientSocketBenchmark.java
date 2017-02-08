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
import static org.junit.Assert.assertEquals;

import java.io.IOException;
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

    @Param public SslSocketType sslSocketType;

    @Param({"64", "128", "512", "1024", "4096"}) public int messageSize;

    @Param({"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"}) public String cipher;

    private TestClient client;
    private NettyEchoServer server;
    private byte[] message;
    private byte[] response;

    @Setup
    public void setup() throws Exception {
        message = newTextMessage(messageSize);
        response = new byte[messageSize];

        int port = pickUnusedPort();
        server = new NettyEchoServer(port, messageSize, cipher);
        server.start();

        client = new TestClient(sslSocketType.newSslSocket(LOCALHOST, port, cipher));
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
        int numBytes = client.readMessage(response);
        assertEquals(messageSize, numBytes);
    }

    public static void main(String[] args) throws Exception {
        ClientSocketBenchmark bm = new ClientSocketBenchmark();
        bm.sslSocketType = SslSocketType.CONSCRYPT_ENGINE;
        bm.messageSize = 1024;
        bm.cipher = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
        bm.setup();
        try {
            while (true) {
                if (Thread.interrupted()) {
                    break;
                }
                bm.pingPong();
            }
        } finally {
            bm.teardown();
        }
    }
}
