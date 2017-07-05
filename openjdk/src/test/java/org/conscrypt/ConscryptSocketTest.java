/*
 * Copyright (C) 2015 The Android Open Source Project
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

import static org.conscrypt.TestUtils.openTestFile;
import static org.conscrypt.TestUtils.readTestFile;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class ConscryptSocketTest {
    private static final long TIMEOUT_SECONDS = 5;
    private static final char[] EMPTY_PASSWORD = new char[0];

    /**
     * Factories for underlying sockets.
     */
    public enum UnderlyingSocketType {
        NONE {
            @Override
            Socket newClientSocket(
                    OpenSSLContextImpl context, ServerSocket server, SSLSocketFactory factory) {
                return null;
            }

            @Override
            Socket newServerSocket(OpenSSLContextImpl context, ServerSocket server,
                    SSLSocketFactory factory) throws IOException {
                return server.accept();
            }
        },
        PLAIN {
            @Override
            Socket newClientSocket(OpenSSLContextImpl context, ServerSocket server,
                    SSLSocketFactory factory) throws IOException {
                return new Socket(server.getInetAddress(), server.getLocalPort());
            }

            @Override
            Socket newServerSocket(OpenSSLContextImpl context, ServerSocket server,
                    SSLSocketFactory factory) throws IOException {
                return server.accept();
            }
        },
        SSL {
            @Override
            Socket newClientSocket(OpenSSLContextImpl context, ServerSocket server,
                    SSLSocketFactory factory) throws IOException {
                SSLSocket sslSocket = (SSLSocket) factory.createSocket(
                        server.getInetAddress(), server.getLocalPort());
                sslSocket.setUseClientMode(true);
                return sslSocket;
            }

            @Override
            Socket newServerSocket(OpenSSLContextImpl context, ServerSocket server,
                    SSLSocketFactory factory) throws IOException {
                SSLSocket sslSocket =
                        (SSLSocket) factory.createSocket(server.accept(), null, -1, true);
                sslSocket.setUseClientMode(false);
                return sslSocket;
            }
        };

        abstract Socket newClientSocket(OpenSSLContextImpl context, ServerSocket server,
                SSLSocketFactory factory) throws IOException;
        abstract Socket newServerSocket(OpenSSLContextImpl context, ServerSocket server,
                SSLSocketFactory factory) throws IOException;
    }

    /**
     * Various factories for SSL server sockets.
     */
    public enum SocketType {
        FILE_DESCRIPTOR(false) {
            @Override
            void assertSocketType(Socket socket) {
                assertTrue("Unexpected socket type: " + socket.getClass().getName(),
                        socket instanceof OpenSSLSocketImpl);
            }
        },
        ENGINE(true) {
            @Override
            void assertSocketType(Socket socket) {
                assertTrue("Unexpected socket type: " + socket.getClass().getName(),
                        socket instanceof ConscryptEngineSocket);
            }
        };

        private final boolean useEngineSocket;

        SocketType(boolean useEngineSocket) {
            this.useEngineSocket = useEngineSocket;
        }

        AbstractConscryptSocket newClientSocket(OpenSSLContextImpl context, ServerSocket server,
                UnderlyingSocketType underlyingSocketType) throws IOException {
            SSLSocketFactory factory = socketFactory(context);
            Socket underlying = underlyingSocketType.newClientSocket(context, server, factory);
            if (underlying != null) {
                return newClientSocket(context, server, underlying);
            }
            return init(factory.createSocket(server.getInetAddress(), server.getLocalPort()), true);
        }

        AbstractConscryptSocket newClientSocket(OpenSSLContextImpl context, ServerSocket server,
                Socket underlying) throws IOException {
            SSLSocketFactory factory = socketFactory(context);
            return init(factory.createSocket(underlying, server.getInetAddress().getHostName(),
                                server.getLocalPort(), true),
                    true);
        }

        AbstractConscryptSocket newServerSocket(OpenSSLContextImpl context, ServerSocket server,
                UnderlyingSocketType underlyingSocketType) throws IOException {
            SSLSocketFactory factory = socketFactory(context);
            Socket underlying = underlyingSocketType.newServerSocket(context, server, factory);
            return init(socketFactory(context).createSocket(underlying, null, -1, true), false);
        }

        abstract void assertSocketType(Socket socket);

        private SSLSocketFactory socketFactory(OpenSSLContextImpl context) {
            SSLSocketFactory factory = context.engineGetSocketFactory();
            Conscrypt.SocketFactories.setUseEngineSocket(factory, useEngineSocket);
            return factory;
        }

        private AbstractConscryptSocket init(Socket socket, boolean useClientMode) {
            assertSocketType(socket);
            AbstractConscryptSocket sslSocket = (AbstractConscryptSocket) socket;
            sslSocket.setUseClientMode(useClientMode);
            return sslSocket;
        }
    }

    @Parameters(name = "{0} wrapping {1}")
    public static Object[][] data() {
        return new Object[][] {
            {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.NONE},
            {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.PLAIN},
            // Not supported: {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.SSL},
            {SocketType.ENGINE, UnderlyingSocketType.NONE},
            {SocketType.ENGINE, UnderlyingSocketType.PLAIN},
            {SocketType.ENGINE, UnderlyingSocketType.SSL}};
    }

    @Parameter
    public SocketType socketType;

    @Parameter(1)
    public UnderlyingSocketType underlyingSocketType;

    private X509Certificate ca;
    private X509Certificate cert;
    private X509Certificate certEmbedded;
    private PrivateKey certKey;

    private Field contextSSLParameters;
    private ExecutorService executor;

    @Before
    public void setUp() throws Exception {
        contextSSLParameters = OpenSSLContextImpl.class.getDeclaredField("sslParameters");
        contextSSLParameters.setAccessible(true);

        ca = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem"));
        cert = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert.pem"));
        certEmbedded =
                OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert-ct-embedded.pem"));
        certKey = OpenSSLKey.fromPrivateKeyPemInputStream(openTestFile("cert-key.pem"))
                          .getPrivateKey();
        executor = Executors.newCachedThreadPool();
    }

    @After
    public void teardown() throws Exception {
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);
    }

    abstract class Hooks implements HandshakeCompletedListener {
        KeyManager[] keyManagers;
        TrustManager[] trustManagers;

        abstract AbstractConscryptSocket createSocket(ServerSocket listener) throws IOException;

        OpenSSLContextImpl createContext() throws IOException {
            OpenSSLContextImpl context = OpenSSLContextImpl.getPreferred();
            try {
                context.engineInit(keyManagers, trustManagers, null);
            } catch (KeyManagementException e) {
                throw new IOException(e);
            }
            return context;
        }

        boolean isHandshakeCompleted = false;
        @Override
        public void handshakeCompleted(HandshakeCompletedEvent event) {
            isHandshakeCompleted = true;
        }

        SSLParametersImpl getContextSSLParameters(OpenSSLContextImpl context)
                throws IllegalAccessException {
            return (SSLParametersImpl) contextSSLParameters.get(context);
        }
    }

    class ClientHooks extends Hooks {
        String hostname = "example.com";

        @Override
        public OpenSSLContextImpl createContext() throws IOException {
            OpenSSLContextImpl context = super.createContext();
            try {
                SSLParametersImpl sslParameters = getContextSSLParameters(context);
                sslParameters.setCTVerificationEnabled(true);
            } catch (IllegalAccessException e) {
                throw new IOException(e);
            }
            return context;
        }

        @Override
        AbstractConscryptSocket createSocket(ServerSocket listener) throws IOException {
            AbstractConscryptSocket socket =
                    socketType.newClientSocket(createContext(), listener, underlyingSocketType);
            socket.setHostname(hostname);
            return socket;
        }
    }

    class ServerHooks extends Hooks {
        byte[] sctTLSExtension;
        byte[] ocspResponse;

        @Override
        public OpenSSLContextImpl createContext() throws IOException {
            OpenSSLContextImpl context = super.createContext();
            try {
                SSLParametersImpl sslParameters = getContextSSLParameters(context);
                sslParameters.setSCTExtension(sctTLSExtension);
                sslParameters.setOCSPResponse(ocspResponse);
                return context;
            } catch (IllegalAccessException e) {
                throw new IOException(e);
            }
        }

        @Override
        AbstractConscryptSocket createSocket(ServerSocket listener) throws IOException {
            return socketType.newServerSocket(createContext(), listener, underlyingSocketType);
        }
    }

    class TestConnection {
        ServerHooks serverHooks;
        ClientHooks clientHooks;

        AbstractConscryptSocket client;
        AbstractConscryptSocket server;

        Exception clientException;
        Exception serverException;

        TestConnection(X509Certificate[] chain, PrivateKey key) throws Exception {
            clientHooks = new ClientHooks();
            serverHooks = new ServerHooks();
            setCertificates(chain, key);
        }

        private void setCertificates(X509Certificate[] chain, PrivateKey key) throws Exception {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setKeyEntry("default", key, EMPTY_PASSWORD, chain);
            ks.setCertificateEntry("CA", chain[chain.length - 1]);

            TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            TrustManager[] tms = tmf.getTrustManagers();

            KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, EMPTY_PASSWORD);
            KeyManager[] kms = kmf.getKeyManagers();

            clientHooks.trustManagers = tms;
            serverHooks.keyManagers = kms;
            serverHooks.trustManagers = tms;
        }

        private <T> T getOrThrowCause(Future<T> future, long timeout, TimeUnit timeUnit)
                throws Exception {
            try {
                return future.get(timeout, timeUnit);
            } catch (ExecutionException e) {
                if (e.getCause() instanceof Exception) {
                    throw(Exception) e.getCause();
                } else {
                    throw e;
                }
            }
        }

        void doHandshake() throws Exception {
            ServerSocket listener = newServerSocket();
            Future<AbstractConscryptSocket> clientFuture = handshake(listener, clientHooks);
            Future<AbstractConscryptSocket> serverFuture = handshake(listener, serverHooks);

            try {
                client = getOrThrowCause(clientFuture, TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (Exception e) {
                clientException = e;
            }
            try {
                server = getOrThrowCause(serverFuture, TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (Exception e) {
                serverException = e;
            }
        }

        Future<AbstractConscryptSocket> handshake(final ServerSocket listener, final Hooks hooks) {
            return executor.submit(() -> {
                AbstractConscryptSocket socket = hooks.createSocket(listener);
                socket.addHandshakeCompletedListener(hooks);

                socket.startHandshake();

                return socket;
            });
        }
    }

    @Test
    public void test_handshake() throws Exception {
        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);
        connection.doHandshake();

        assertTrue(connection.clientHooks.isHandshakeCompleted);
        assertTrue(connection.serverHooks.isHandshakeCompleted);
    }

    @Test
    public void test_handshakeWithEmbeddedSCT() throws Exception {
        TestConnection connection =
                new TestConnection(new X509Certificate[] {certEmbedded, ca}, certKey);

        connection.doHandshake();

        assertTrue(connection.clientHooks.isHandshakeCompleted);
        assertTrue(connection.serverHooks.isHandshakeCompleted);
    }

    @Test
    public void test_handshakeWithSCTFromOCSPResponse() throws Exception {
        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);

        connection.serverHooks.ocspResponse = readTestFile("ocsp-response.der");

        connection.doHandshake();

        assertTrue(connection.clientHooks.isHandshakeCompleted);
        assertTrue(connection.serverHooks.isHandshakeCompleted);
    }

    @Test
    public void test_handshakeWithSCTFromTLSExtension() throws Exception {
        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);

        connection.serverHooks.sctTLSExtension = readTestFile("ct-signed-timestamp-list");

        connection.doHandshake();

        assertTrue(connection.clientHooks.isHandshakeCompleted);
        assertTrue(connection.serverHooks.isHandshakeCompleted);
    }

    @Ignore("TODO(nathanmittler): Fix or remove")
    @Test
    public void test_handshake_failsWithMissingSCT() throws Exception {
        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);

        connection.doHandshake();
        assertThat(connection.clientException, instanceOf(SSLHandshakeException.class));
        assertThat(connection.clientException.getCause(), instanceOf(CertificateException.class));
    }

    @Ignore("TODO(nathanmittler): Fix or remove")
    @Test
    public void test_handshake_failsWithInvalidSCT() throws Exception {
        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);

        connection.serverHooks.sctTLSExtension = readTestFile("ct-signed-timestamp-list-invalid");

        connection.doHandshake();
        assertThat(connection.clientException, instanceOf(SSLHandshakeException.class));
        assertThat(connection.clientException.getCause(), instanceOf(CertificateException.class));
    }

    // http://b/27250522
    @Test
    public void test_setSoTimeout_doesNotCreateSocketImpl() throws Exception {
        ServerSocket listening = newServerSocket();
        Socket underlying = new Socket(listening.getInetAddress(), listening.getLocalPort());

        Socket socket = socketType.newClientSocket(
                new ClientHooks().createContext(), listening, underlying);
        socketType.assertSocketType(socket);
        socket.setSoTimeout(1000);
        socket.close();

        Field f = Socket.class.getDeclaredField("created");
        f.setAccessible(true);
        assertFalse(f.getBoolean(socket));
    }

    @Test
    public void test_setEnabledProtocols_FiltersSSLv3_HandshakeException() throws Exception {
        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);

        connection.clientHooks = new ClientHooks() {
            @Override
            public AbstractConscryptSocket createSocket(ServerSocket listener) throws IOException {
                AbstractConscryptSocket socket = super.createSocket(listener);
                socket.setEnabledProtocols(new String[] {"SSLv3"});
                assertEquals(
                        "SSLv3 should be filtered out", 0, socket.getEnabledProtocols().length);
                return socket;
            }
        };

        connection.doHandshake();
        assertThat(connection.clientException, instanceOf(SSLHandshakeException.class));
        assertTrue(
                connection.clientException.getMessage().contains("SSLv3 is no longer supported"));
        assertThat(connection.serverException, instanceOf(SSLHandshakeException.class));

        assertFalse(connection.clientHooks.isHandshakeCompleted);
        assertFalse(connection.serverHooks.isHandshakeCompleted);
    }

    private static ServerSocket newServerSocket() throws IOException {
        return new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    }
}
