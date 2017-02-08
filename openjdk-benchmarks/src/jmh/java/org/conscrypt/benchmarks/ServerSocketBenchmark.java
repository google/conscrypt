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
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.openjdk.jmh.annotations.Benchmark;
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
public class ServerSocketBenchmark {
    /**
     * Various factories for SSL server sockets.
     */
    public enum SslSocketType {
        JDK(getJdkServerSocketFactory()),
        CONSCRYPT(getConscryptServerSocketFactory());

        private final SSLServerSocketFactory serverSocketFactory;

        SslSocketType(SSLServerSocketFactory serverSocketFactory) {
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

    @Param public SslSocketType sslSocketType;

    @Param({"64", "128", "512", "1024", "4096"}) public int messageSize;

    @Param({"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"}) public String cipher;

    private TestClient client;
    private EchoServer server;
    private byte[] message;
    private byte[] response;

    @Setup
    public void setup() throws Exception {
        message = newTextMessage(messageSize);
        response = new byte[messageSize];

        server = new EchoServer(sslSocketType.newServerSocket(cipher), messageSize);

        Future connectedFuture = server.start();

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
}
