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

import static org.conscrypt.testing.TestUtil.LOCALHOST;
import static org.conscrypt.testing.TestUtil.getConscryptServerSocketFactory;
import static org.conscrypt.testing.TestUtil.getJdkSocketFactory;
import static org.conscrypt.testing.TestUtil.getProtocols;
import static org.conscrypt.testing.TestUtil.newTextMessage;
import static org.conscrypt.testing.TestUtil.pickUnusedPort;
import static org.junit.Assert.assertArrayEquals;

import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.conscrypt.testing.TestClient;
import org.conscrypt.testing.TestServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class OpenSSLServerSocketImplTest {
    private static final String CIPHER = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
    private static final int MESSAGE_SIZE = 4096;

    /**
     * Various factories for SSL server sockets.
     */
    public enum SocketType {
        DEFAULT(getConscryptServerSocketFactory(false)),
        ENGINE(getConscryptServerSocketFactory(true));

        private final SSLServerSocketFactory serverSocketFactory;

        SocketType(SSLServerSocketFactory serverSocketFactory) {
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

    @Parameters(name = "{0}")
    public static Iterable<SocketType> data() {
        return Arrays.asList(SocketType.DEFAULT, SocketType.ENGINE);
    }

    @Parameter public SocketType socketType;

    private TestClient client;
    private TestServer server;

    @Before
    public void setup() throws Exception {
        // Create and start the server.
        server = new TestServer(socketType.newServerSocket(CIPHER), MESSAGE_SIZE);
        Future<?> connectedFuture = server.start();

        // Create and start the client.
        SSLSocketFactory socketFactory = getJdkSocketFactory();
        SSLSocket socket = (SSLSocket) socketFactory.createSocket(LOCALHOST, server.port());
        socket.setEnabledProtocols(getProtocols());
        socket.setEnabledCipherSuites(new String[] {CIPHER});
        client = new TestClient(socket);
        client.start();

        // Wait for the initial connection to complete.
        connectedFuture.get(5, TimeUnit.SECONDS);
    }

    @After
    public void teardown() throws Exception {
        client.stop();
        server.stop();
    }

    @Test
    public void pingPong() throws IOException {
        byte[] request = newTextMessage(MESSAGE_SIZE);
        byte[] responseBuffer = new byte[MESSAGE_SIZE];
        client.sendMessage(request);
        client.flush();
        int numBytes = client.readMessage(responseBuffer);
        byte[] response = Arrays.copyOfRange(responseBuffer, 0, numBytes);
        assertArrayEquals(request, response);
    }
}
