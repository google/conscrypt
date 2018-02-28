/*
 * Copyright (C) 2010 The Android Open Source Project
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

package org.conscrypt.javax.net.ssl;

import static org.conscrypt.TestUtils.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeNoException;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import libcore.java.security.StandardNames;
import libcore.tlswire.handshake.CipherSuite;
import libcore.tlswire.handshake.ClientHello;
import libcore.tlswire.handshake.CompressionMethod;
import libcore.tlswire.handshake.EllipticCurve;
import libcore.tlswire.handshake.EllipticCurvesHelloExtension;
import libcore.tlswire.handshake.HandshakeMessage;
import libcore.tlswire.handshake.HelloExtension;
import libcore.tlswire.handshake.ServerNameHelloExtension;
import libcore.tlswire.record.TlsProtocols;
import libcore.tlswire.record.TlsRecord;
import libcore.tlswire.util.TlsProtocolVersion;
import org.conscrypt.Conscrypt;
import org.conscrypt.TestUtils;
import org.conscrypt.java.security.TestKeyStore;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.net.DelegatingSSLSocketFactory;
import tests.util.ForEachRunner;
import tests.util.ForEachRunner.Callback;
import tests.util.Pair;

@RunWith(JUnit4.class)
public class SSLSocketTest {
    private ExecutorService executor;
    private ThreadGroup threadGroup;

    @Before
    public void setup() {
        threadGroup = new ThreadGroup("SSLSocketTest");
        executor = Executors.newCachedThreadPool(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                return new Thread(threadGroup, r);
            }
        });
    }

    @After
    public void teardown() throws InterruptedException {
        executor.shutdownNow();
        executor.awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    public void test_SSLSocket_defaultConfiguration() throws Exception {
        SSLConfigurationAsserts.assertSSLSocketDefaultConfiguration(
                (SSLSocket) SSLSocketFactory.getDefault().createSocket());
    }

    @Test
    public void test_SSLSocket_getSupportedCipherSuites_returnsCopies() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket ssl = (SSLSocket) sf.createSocket();
        assertNotSame(ssl.getSupportedCipherSuites(), ssl.getSupportedCipherSuites());
    }

    @Test
    public void test_SSLSocket_getSupportedCipherSuites_connect() throws Exception {
        // note the rare usage of non-RSA keys
        TestKeyStore testKeyStore = new TestKeyStore.Builder()
                                            .keyAlgorithms("RSA", "DSA", "EC", "EC_RSA")
                                            .aliasPrefix("rsa-dsa-ec")
                                            .ca(true)
                                            .build();
        StringBuilder error = new StringBuilder();
        test_SSLSocket_getSupportedCipherSuites_connect(testKeyStore, error);
        if (error.length() > 0) {
            throw new Exception("One or more problems in "
                    + "test_SSLSocket_getSupportedCipherSuites_connect:\n" + error);
        }
    }
    private void test_SSLSocket_getSupportedCipherSuites_connect(
            TestKeyStore testKeyStore, StringBuilder error) throws Exception {
        String clientToServerString = "this is sent from the client to the server...";
        String serverToClientString = "... and this from the server to the client";
        byte[] clientToServer = clientToServerString.getBytes(UTF_8);
        byte[] serverToClient = serverToClientString.getBytes(UTF_8);
        KeyManager pskKeyManager =
                PSKKeyManagerProxy.getConscryptPSKKeyManager(new PSKKeyManagerProxy() {
                    @Override
                    protected SecretKey getKey(
                            String identityHint, String identity, Socket socket) {
                        return newKey();
                    }

                    @Override
                    protected SecretKey getKey(
                            String identityHint, String identity, SSLEngine engine) {
                        return newKey();
                    }

                    private SecretKey newKey() {
                        return new SecretKeySpec("Just an arbitrary key".getBytes(UTF_8), "RAW");
                    }
                });
        TestSSLContext c = TestSSLContext.newBuilder()
                                   .client(testKeyStore)
                                   .server(testKeyStore)
                                   .additionalClientKeyManagers(new KeyManager[] {pskKeyManager})
                                   .additionalServerKeyManagers(new KeyManager[] {pskKeyManager})
                                   .build();
        String[] cipherSuites = c.clientContext.getSocketFactory().getSupportedCipherSuites();
        for (String cipherSuite : cipherSuites) {
            try {
                /*
                 * TLS_EMPTY_RENEGOTIATION_INFO_SCSV cannot be used on
                 * its own, but instead in conjunction with other
                 * cipher suites.
                 */
                if (cipherSuite.equals(StandardNames.CIPHER_SUITE_SECURE_RENEGOTIATION)) {
                    continue;
                }
                /*
                 * Similarly with the TLS_FALLBACK_SCSV suite, it is not
                 * a selectable suite, but is used in conjunction with
                 * other cipher suites.
                 */
                if (cipherSuite.equals(StandardNames.CIPHER_SUITE_FALLBACK)) {
                    continue;
                }
                /*
                 * Kerberos cipher suites require external setup. See "Kerberos Requirements" in
                 * https://java.sun.com/j2se/1.5.0/docs/guide/security/jsse/JSSERefGuide.html
                 * #KRBRequire
                 */
                if (cipherSuite.startsWith("TLS_KRB5_")) {
                    continue;
                }
                String[] clientCipherSuiteArray =
                        new String[] {cipherSuite, StandardNames.CIPHER_SUITE_SECURE_RENEGOTIATION};
                TestSSLSocketPair socketPair = TestSSLSocketPair.create(c).connect(
                        clientCipherSuiteArray, clientCipherSuiteArray);
                SSLSocket server = socketPair.server;
                SSLSocket client = socketPair.client;
                // Check that the client can read the message sent by the server
                server.getOutputStream().write(serverToClient);
                byte[] clientFromServer = new byte[serverToClient.length];
                readFully(client.getInputStream(), clientFromServer);
                assertEquals(serverToClientString, new String(clientFromServer, UTF_8));
                // Check that the server can read the message sent by the client
                client.getOutputStream().write(clientToServer);
                byte[] serverFromClient = new byte[clientToServer.length];
                readFully(server.getInputStream(), serverFromClient);
                assertEquals(clientToServerString, new String(serverFromClient, UTF_8));
                // Check that the server and the client cannot read anything else
                // (reads should time out)
                server.setSoTimeout(10);
                try {
                    @SuppressWarnings("unused")
                    int value = server.getInputStream().read();
                    fail();
                } catch (IOException expected) {
                    // Ignored.
                }
                client.setSoTimeout(10);
                try {
                    @SuppressWarnings("unused")
                    int value = client.getInputStream().read();
                    fail();
                } catch (IOException expected) {
                    // Ignored.
                }
                client.close();
                server.close();
            } catch (Exception maybeExpected) {
                String message = ("Problem trying to connect cipher suite " + cipherSuite);
                System.out.println(message);
                maybeExpected.printStackTrace();
                error.append(message);
                error.append('\n');
            }
        }
        c.close();
    }

    @Test
    public void test_SSLSocket_getEnabledCipherSuites_returnsCopies() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket ssl = (SSLSocket) sf.createSocket();
        assertNotSame(ssl.getEnabledCipherSuites(), ssl.getEnabledCipherSuites());
    }

    @Test
    public void test_SSLSocket_setEnabledCipherSuites_storesCopy() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket ssl = (SSLSocket) sf.createSocket();
        String[] array = new String[] {ssl.getEnabledCipherSuites()[0]};
        String originalFirstElement = array[0];
        ssl.setEnabledCipherSuites(array);
        array[0] = "Modified after having been set";
        assertEquals(originalFirstElement, ssl.getEnabledCipherSuites()[0]);
    }

    @Test
    public void test_SSLSocket_setEnabledCipherSuites() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket ssl = (SSLSocket) sf.createSocket();
        try {
            ssl.setEnabledCipherSuites(null);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        try {
            ssl.setEnabledCipherSuites(new String[1]);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        try {
            ssl.setEnabledCipherSuites(new String[] {"Bogus"});
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        ssl.setEnabledCipherSuites(new String[0]);
        ssl.setEnabledCipherSuites(ssl.getEnabledCipherSuites());
        ssl.setEnabledCipherSuites(ssl.getSupportedCipherSuites());
        // Check that setEnabledCipherSuites affects getEnabledCipherSuites
        String[] cipherSuites = new String[] {ssl.getSupportedCipherSuites()[0]};
        ssl.setEnabledCipherSuites(cipherSuites);
        assertEquals(Arrays.asList(cipherSuites), Arrays.asList(ssl.getEnabledCipherSuites()));
    }

    @Test
    public void test_SSLSocket_getSupportedProtocols_returnsCopies() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket ssl = (SSLSocket) sf.createSocket();
        assertNotSame(ssl.getSupportedProtocols(), ssl.getSupportedProtocols());
    }

    @Test
    public void test_SSLSocket_getEnabledProtocols_returnsCopies() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket ssl = (SSLSocket) sf.createSocket();
        assertNotSame(ssl.getEnabledProtocols(), ssl.getEnabledProtocols());
    }

    @Test
    public void test_SSLSocket_setEnabledProtocols_storesCopy() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket ssl = (SSLSocket) sf.createSocket();
        String[] array = new String[] {ssl.getEnabledProtocols()[0]};
        String originalFirstElement = array[0];
        ssl.setEnabledProtocols(array);
        array[0] = "Modified after having been set";
        assertEquals(originalFirstElement, ssl.getEnabledProtocols()[0]);
    }

    @Test
    public void test_SSLSocket_setEnabledProtocols() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket ssl = (SSLSocket) sf.createSocket();
        try {
            ssl.setEnabledProtocols(null);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        try {
            ssl.setEnabledProtocols(new String[1]);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        try {
            ssl.setEnabledProtocols(new String[] {"Bogus"});
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        ssl.setEnabledProtocols(new String[0]);
        ssl.setEnabledProtocols(ssl.getEnabledProtocols());
        ssl.setEnabledProtocols(ssl.getSupportedProtocols());
        // Check that setEnabledProtocols affects getEnabledProtocols
        for (String protocol : ssl.getSupportedProtocols()) {
            if ("SSLv2Hello".equals(protocol)) {
                try {
                    ssl.setEnabledProtocols(new String[] {protocol});
                    fail("Should fail when SSLv2Hello is set by itself");
                } catch (IllegalArgumentException expected) {
                    // Ignored.
                }
            } else {
                String[] protocols = new String[] {protocol};
                ssl.setEnabledProtocols(protocols);
                assertEquals(Arrays.deepToString(protocols),
                        Arrays.deepToString(ssl.getEnabledProtocols()));
            }
        }
    }

    /**
     * Tests that when the client has a hole in their supported protocol list, the
     * lower span of contiguous protocols is used in practice.
     */
    @Test
    public void test_SSLSocket_noncontiguousProtocols_useLower() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLContext serverContext = c.serverContext;
        SSLContext clientContext = c.clientContext;
        SSLSocket client = (SSLSocket)
                clientContext.getSocketFactory().createSocket(c.host, c.port);
        client.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1"});
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        server.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.1", "TLSv1"});
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Void> future = executor.submit(new Callable<Void>() {
            @Override public Void call() throws Exception {
                server.startHandshake();
                return null;
            }
        });
        executor.shutdown();
        client.startHandshake();

        assertEquals("TLSv1", client.getSession().getProtocol());

        future.get();
        client.close();
        server.close();
        c.close();
    }

    /**
     * Tests that protocol negotiation succeeds when the highest-supported protocol
     * for both client and server isn't supported by the other.
     */
    @Test
    public void test_SSLSocket_noncontiguousProtocols_canNegotiate() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLContext serverContext = c.serverContext;
        SSLContext clientContext = c.clientContext;
        SSLSocket client = (SSLSocket)
                clientContext.getSocketFactory().createSocket(c.host, c.port);
        client.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1"});
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        server.setEnabledProtocols(new String[] {"TLSv1.1", "TLSv1"});
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Void> future = executor.submit(new Callable<Void>() {
            @Override public Void call() throws Exception {
                server.startHandshake();
                return null;
            }
        });
        executor.shutdown();
        client.startHandshake();

        assertEquals("TLSv1", client.getSession().getProtocol());

        future.get();
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_getSession() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket ssl = (SSLSocket) sf.createSocket();
        SSLSession session = ssl.getSession();
        assertNotNull(session);
        assertFalse(session.isValid());
    }

    @Test
    public void test_SSLSocket_getHandshakeSession() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) sf.createSocket();
        SSLSession session = getHandshakeSession(socket);
        assertNull(session);
    }

    @Test
    public void test_SSLSocket_startHandshake() throws Exception {
        final TestSSLContext c = TestSSLContext.create();
        SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                server.startHandshake();
                assertNotNull(server.getSession());
                assertNull(getHandshakeSession(server));
                try {
                    server.getSession().getPeerCertificates();
                    fail();
                } catch (SSLPeerUnverifiedException expected) {
                    // Ignored.
                }
                Certificate[] localCertificates = server.getSession().getLocalCertificates();
                assertNotNull(localCertificates);
                TestKeyStore.assertChainLength(localCertificates);
                assertNotNull(localCertificates[0]);
                TestSSLContext
                    .assertServerCertificateChain(c.serverTrustManager, localCertificates);
                TestSSLContext.assertCertificateInKeyStore(localCertificates[0], c.serverKeyStore);
                return null;
            }
        });
        client.startHandshake();
        assertNotNull(client.getSession());
        assertNull(client.getSession().getLocalCertificates());
        Certificate[] peerCertificates = client.getSession().getPeerCertificates();
        assertNotNull(peerCertificates);
        TestKeyStore.assertChainLength(peerCertificates);
        assertNotNull(peerCertificates[0]);
        TestSSLContext.assertServerCertificateChain(c.clientTrustManager, peerCertificates);
        TestSSLContext.assertCertificateInKeyStore(peerCertificates[0], c.serverKeyStore);
        future.get();
        client.close();
        server.close();
        c.close();
    }
    private static final class SSLServerSessionIdCallable implements Callable<byte[]> {
        private final SSLSocket server;
        private SSLServerSessionIdCallable(SSLSocket server) {
            this.server = server;
        }
        @Override
        public byte[] call() throws Exception {
            server.startHandshake();
            assertNotNull(server.getSession());
            assertNotNull(server.getSession().getId());
            return server.getSession().getId();
        }
    }

    @Test
    public void test_SSLSocket_confirmSessionReuse() throws Exception {
        final TestSSLContext c = TestSSLContext.create();
        final SSLSocket client1 = (SSLSocket) c.clientContext.getSocketFactory().createSocket(
                c.host.getHostName(), c.port);
        final SSLSocket server1 = (SSLSocket) c.serverSocket.accept();
        final Future<byte[]> future1 = runAsync(new SSLServerSessionIdCallable(server1));
        client1.startHandshake();
        assertNotNull(client1.getSession());
        assertNotNull(client1.getSession().getId());
        final byte[] clientSessionId1 = client1.getSession().getId();
        final byte[] serverSessionId1 = future1.get();
        assertTrue(Arrays.equals(clientSessionId1, serverSessionId1));
        client1.close();
        server1.close();
        final SSLSocket client2 = (SSLSocket) c.clientContext.getSocketFactory().createSocket(
                c.host.getHostName(), c.port);
        final SSLSocket server2 = (SSLSocket) c.serverSocket.accept();
        final Future<byte[]> future2 = runAsync(new SSLServerSessionIdCallable(server2));
        client2.startHandshake();
        assertNotNull(client2.getSession());
        assertNotNull(client2.getSession().getId());
        final byte[] clientSessionId2 = client2.getSession().getId();
        final byte[] serverSessionId2 = future2.get();
        assertTrue(Arrays.equals(clientSessionId2, serverSessionId2));
        client2.close();
        server2.close();
        assertTrue(Arrays.equals(clientSessionId1, clientSessionId2));
        c.close();
    }

    @Test
    public void test_SSLSocket_NoEnabledCipherSuites_Failure() throws Exception {
        TestSSLContext c = TestSSLContext.newBuilder()
                                   .useDefaults(false)
                                   .clientContext(SSLContext.getDefault())
                                   .serverContext(SSLContext.getDefault())
                                   .build();
        SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        client.setEnabledCipherSuites(new String[0]);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                    fail();
                } catch (SSLHandshakeException expected) {
                    // Ignored.
                }
                return null;
            }
        });
        try {
            client.startHandshake();
            fail();
        } catch (SSLHandshakeException expected) {
            // Ignored.
        }
        future.get();
        server.close();
        client.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_startHandshake_noKeyStore() throws Exception {
        TestSSLContext c = TestSSLContext.newBuilder()
                                   .useDefaults(false)
                                   .clientContext(SSLContext.getDefault())
                                   .serverContext(SSLContext.getDefault())
                                   .build();
        SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                    fail();
                } catch (SSLHandshakeException expected) {
                    // Ignored.
                }
                return null;
            }
        });
        try {
            client.startHandshake();
            fail();
        } catch (SSLHandshakeException expected) {
            // Ignored.
        }
        future.get();
        server.close();
        client.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_startHandshake_noClientCertificate() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLContext clientContext = c.clientContext;
        SSLSocket client =
                (SSLSocket) clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                server.startHandshake();
                return null;
            }
        });
        client.startHandshake();
        future.get();
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_HandshakeCompletedListener() throws Exception {
        final TestSSLContext c = TestSSLContext.create();
        final SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                server.startHandshake();
                return null;
            }
        });
        final boolean[] handshakeCompletedListenerCalled = new boolean[1];
        client.addHandshakeCompletedListener(new HandshakeCompletedListener() {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent event) {
                try {
                    SSLSession session = event.getSession();
                    String cipherSuite = event.getCipherSuite();
                    Certificate[] localCertificates = event.getLocalCertificates();
                    Certificate[] peerCertificates = event.getPeerCertificates();
                    javax.security.cert.X509Certificate[] peerCertificateChain =
                        event.getPeerCertificateChain();
                    Principal peerPrincipal = event.getPeerPrincipal();
                    Principal localPrincipal = event.getLocalPrincipal();
                    Socket socket = event.getSocket();
                    assertNotNull(session);
                    byte[] id = session.getId();
                    assertNotNull(id);
                    assertEquals(32, id.length);
                    assertNotNull(c.clientContext.getClientSessionContext().getSession(id));

                    assertNotNull(cipherSuite);
                    assertTrue(
                        Arrays.asList(client.getEnabledCipherSuites()).contains(cipherSuite));
                    assertTrue(Arrays.asList(c.serverSocket.getEnabledCipherSuites())
                        .contains(cipherSuite));
                    assertNull(localCertificates);
                    assertNotNull(peerCertificates);
                    TestKeyStore.assertChainLength(peerCertificates);
                    assertNotNull(peerCertificates[0]);
                    TestSSLContext
                        .assertServerCertificateChain(c.clientTrustManager, peerCertificates);
                    TestSSLContext
                        .assertCertificateInKeyStore(peerCertificates[0], c.serverKeyStore);
                    assertNotNull(peerCertificateChain);
                    TestKeyStore.assertChainLength(peerCertificateChain);
                    assertNotNull(peerCertificateChain[0]);
                    TestSSLContext.assertCertificateInKeyStore(
                        peerCertificateChain[0].getSubjectDN(), c.serverKeyStore);
                    assertNotNull(peerPrincipal);
                    TestSSLContext.assertCertificateInKeyStore(peerPrincipal, c.serverKeyStore);
                    assertNull(localPrincipal);
                    assertNotNull(socket);
                    assertSame(client, socket);
                    assertNull(getHandshakeSession((SSLSocket) socket));
                    synchronized (handshakeCompletedListenerCalled) {
                        handshakeCompletedListenerCalled[0] = true;
                        handshakeCompletedListenerCalled.notify();
                    }
                    handshakeCompletedListenerCalled[0] = true;
                } catch (RuntimeException e) {
                    throw e;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
        client.startHandshake();
        future.get();
        assertNotNull(
                c.serverContext.getServerSessionContext().getSession(client.getSession().getId()));
        synchronized (handshakeCompletedListenerCalled) {
            while (!handshakeCompletedListenerCalled[0]) {
                handshakeCompletedListenerCalled.wait();
            }
        }
        client.close();
        server.close();
        c.close();
    }
    private static final class TestUncaughtExceptionHandler implements UncaughtExceptionHandler {
        Throwable actualException;
        @Override
        public void uncaughtException(Thread thread, Throwable ex) {
            assertNull(actualException);
            actualException = ex;
        }
    }

    @Test
    public void test_SSLSocket_HandshakeCompletedListener_RuntimeException() throws Exception {
        final Thread self = Thread.currentThread();
        final UncaughtExceptionHandler original = self.getUncaughtExceptionHandler();
        final RuntimeException expectedException = new RuntimeException("expected");
        final TestUncaughtExceptionHandler test = new TestUncaughtExceptionHandler();
        self.setUncaughtExceptionHandler(test);
        final TestSSLContext c = TestSSLContext.create();
        final SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                server.startHandshake();
                return null;
            }
        });
        client.addHandshakeCompletedListener(new HandshakeCompletedListener() {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent event) {
                throw expectedException;
            }
        });
        client.startHandshake();
        future.get();
        client.close();
        server.close();
        c.close();
        assertSame(expectedException, test.actualException);
        self.setUncaughtExceptionHandler(original);
    }

    @Test
    public void test_SSLSocket_getUseClientMode() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        SSLSocket server = (SSLSocket) c.serverSocket.accept();
        assertTrue(client.getUseClientMode());
        assertFalse(server.getUseClientMode());
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void testClientMode_normal() throws Exception {
        // Client is client and server is server.
        test_SSLSocket_setUseClientMode(true, false);
    }

    @Test(expected = SSLHandshakeException.class)
    public void testClientMode_reverse() throws Exception {
        // Client is server and server is client.
        test_SSLSocket_setUseClientMode(false, true);
    }

    @Test(expected = SSLHandshakeException.class)
    public void testClientMode_bothClient() throws Exception {
        test_SSLSocket_setUseClientMode(true, true);
    }

    @Test
    public void testClientMode_bothServer() throws Exception {
        try {
            test_SSLSocket_setUseClientMode(false, false);
            fail();
        } catch (SocketTimeoutException expected) {
            // Ignore
        } catch (SSLHandshakeException expected) {
            // Depending on the timing of the socket closures, this can happen as well.
            assertTrue("Unexpected handshake error: " + expected.getMessage(),
                    expected.getMessage().toLowerCase().contains("connection closed"));
        }
    }

    private void test_SSLSocket_setUseClientMode(
            final boolean clientClientMode, final boolean serverClientMode) throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<IOException> future = runAsync(new Callable<IOException>() {
            @Override
            public IOException call() throws Exception {
                try {
                    if (!serverClientMode) {
                        server.setSoTimeout(1000);
                    }
                    server.setUseClientMode(serverClientMode);
                    server.startHandshake();
                    return null;
                } catch (SSLHandshakeException e) {
                    return e;
                } catch (SocketTimeoutException e) {
                    return e;
                }
            }
        });
        if (!clientClientMode) {
            client.setSoTimeout(1000);
        }
        client.setUseClientMode(clientClientMode);
        client.startHandshake();
        IOException ioe = future.get();
        if (ioe != null) {
            throw ioe;
        }
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_setUseClientMode_afterHandshake() throws Exception {
        // can't set after handshake
        TestSSLSocketPair pair = TestSSLSocketPair.create().connect();
        try {
            pair.server.setUseClientMode(false);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        try {
            pair.client.setUseClientMode(false);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
    }

    @Test
    public void test_SSLSocket_untrustedServer() throws Exception {
        TestSSLContext c =
                TestSSLContext.create(TestKeyStore.getClientCA2(), TestKeyStore.getServer());
        SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                    fail();
                } catch (SSLHandshakeException expected) {
                    // Ignored.
                }
                return null;
            }
        });
        try {
            client.startHandshake();
            fail();
        } catch (SSLHandshakeException expected) {
            assertTrue(expected.getCause() instanceof CertificateException);
        }
        future.get();
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_clientAuth() throws Exception {
        TestSSLContext c = TestSSLContext.create(
                TestKeyStore.getClientCertificate(), TestKeyStore.getServer());
        SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                assertFalse(server.getWantClientAuth());
                assertFalse(server.getNeedClientAuth());
                // confirm turning one on by itself
                server.setWantClientAuth(true);
                assertTrue(server.getWantClientAuth());
                assertFalse(server.getNeedClientAuth());
                // confirm turning setting on toggles the other
                server.setNeedClientAuth(true);
                assertFalse(server.getWantClientAuth());
                assertTrue(server.getNeedClientAuth());
                // confirm toggling back
                server.setWantClientAuth(true);
                assertTrue(server.getWantClientAuth());
                assertFalse(server.getNeedClientAuth());
                server.startHandshake();
                return null;
            }
        });
        client.startHandshake();
        assertNotNull(client.getSession().getLocalCertificates());
        TestKeyStore.assertChainLength(client.getSession().getLocalCertificates());
        TestSSLContext.assertClientCertificateChain(
                c.clientTrustManager, client.getSession().getLocalCertificates());
        future.get();
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_clientAuth_bogusAlias() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLContext clientContext = SSLContext.getInstance("TLS");
        X509KeyManager keyManager = new X509KeyManager() {
            @Override
            public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
                return "bogus";
            }
            @Override
            public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
                throw new AssertionError();
            }
            @Override
            public X509Certificate[] getCertificateChain(String alias) {
                // return null for "bogus" alias
                return null;
            }
            @Override
            public String[] getClientAliases(String keyType, Principal[] issuers) {
                throw new AssertionError();
            }
            @Override
            public String[] getServerAliases(String keyType, Principal[] issuers) {
                throw new AssertionError();
            }
            @Override
            public PrivateKey getPrivateKey(String alias) {
                // return null for "bogus" alias
                return null;
            }
        };
        clientContext.init(
                new KeyManager[] {keyManager}, new TrustManager[] {c.clientTrustManager}, null);
        SSLSocket client =
                (SSLSocket) clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.setNeedClientAuth(true);
                    server.startHandshake();
                    fail();
                } catch (SSLHandshakeException expected) {
                    // Ignored.
                }
                return null;
            }
        });
        try {
            client.startHandshake();
            fail();
        } catch (SSLHandshakeException expected) {
            // before we would get a NullPointerException from passing
            // due to the null PrivateKey return by the X509KeyManager.
        }
        future.get();
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_clientAuth_OpaqueKey_RSA() throws Exception {
        run_SSLSocket_clientAuth_OpaqueKey(TestKeyStore.getClientCertificate());
    }

    @Test
    public void test_SSLSocket_clientAuth_OpaqueKey_EC_RSA() throws Exception {
        run_SSLSocket_clientAuth_OpaqueKey(TestKeyStore.getClientEcRsaCertificate());
    }

    @Test
    public void test_SSLSocket_clientAuth_OpaqueKey_EC_EC() throws Exception {
        run_SSLSocket_clientAuth_OpaqueKey(TestKeyStore.getClientEcEcCertificate());
    }
    private void run_SSLSocket_clientAuth_OpaqueKey(TestKeyStore keyStore) throws Exception {
        try {
            Security.insertProviderAt(new OpaqueProvider(), 1);
            final TestSSLContext c = TestSSLContext.create(keyStore, TestKeyStore.getServer());
            SSLContext clientContext = SSLContext.getInstance("TLS");
            final X509KeyManager delegateKeyManager = (X509KeyManager) c.clientKeyManagers[0];
            X509KeyManager keyManager = new X509KeyManager() {
                @Override
                public String chooseClientAlias(
                        String[] keyType, Principal[] issuers, Socket socket) {
                    return delegateKeyManager.chooseClientAlias(keyType, issuers, socket);
                }
                @Override
                public String chooseServerAlias(
                        String keyType, Principal[] issuers, Socket socket) {
                    return delegateKeyManager.chooseServerAlias(keyType, issuers, socket);
                }
                @Override
                public X509Certificate[] getCertificateChain(String alias) {
                    return delegateKeyManager.getCertificateChain(alias);
                }
                @Override
                public String[] getClientAliases(String keyType, Principal[] issuers) {
                    return delegateKeyManager.getClientAliases(keyType, issuers);
                }
                @Override
                public String[] getServerAliases(String keyType, Principal[] issuers) {
                    return delegateKeyManager.getServerAliases(keyType, issuers);
                }
                @Override
                public PrivateKey getPrivateKey(String alias) {
                    PrivateKey privKey = delegateKeyManager.getPrivateKey(alias);
                    if (privKey instanceof RSAPrivateKey) {
                        return new OpaqueDelegatingRSAPrivateKey((RSAPrivateKey) privKey);
                    } else if (privKey instanceof ECPrivateKey) {
                        return new OpaqueDelegatingECPrivateKey((ECPrivateKey) privKey);
                    } else {
                        return null;
                    }
                }
            };
            clientContext.init(
                    new KeyManager[] {keyManager}, new TrustManager[] {c.clientTrustManager}, null);
            SSLSocket client =
                    (SSLSocket) clientContext.getSocketFactory().createSocket(c.host, c.port);
            final SSLSocket server = (SSLSocket) c.serverSocket.accept();
            Future<Void> future = runAsync(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    server.setNeedClientAuth(true);
                    server.startHandshake();
                    return null;
                }
            });
            client.startHandshake();
            assertNotNull(client.getSession().getLocalCertificates());
            TestKeyStore.assertChainLength(client.getSession().getLocalCertificates());
            TestSSLContext.assertClientCertificateChain(
                    c.clientTrustManager, client.getSession().getLocalCertificates());
            future.get();
            client.close();
            server.close();
            c.close();
        } finally {
            Security.removeProvider(OpaqueProvider.NAME);
        }
    }
    @SuppressWarnings("serial")
    public static class OpaqueProvider extends Provider {
        static final String NAME = "OpaqueProvider";
        public OpaqueProvider() {
            super(NAME, 1.0, "test provider");
            put("Signature.NONEwithRSA", OpaqueSignatureSpi.RSA.class.getName());
            put("Signature.NONEwithECDSA", OpaqueSignatureSpi.ECDSA.class.getName());
            put("Cipher.RSA/ECB/NoPadding", OpaqueCipherSpi.class.getName());
        }
    }
    protected static class OpaqueSignatureSpi extends SignatureSpi {
        private final String algorithm;
        private Signature delegate;
        OpaqueSignatureSpi(String algorithm) {
            this.algorithm = algorithm;
        }
        public final static class RSA extends OpaqueSignatureSpi {
            public RSA() {
                super("NONEwithRSA");
            }
        }
        public final static class ECDSA extends OpaqueSignatureSpi {
            public ECDSA() {
                super("NONEwithECDSA");
            }
        }
        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            fail("Cannot verify");
        }
        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            DelegatingPrivateKey opaqueKey = (DelegatingPrivateKey) privateKey;
            try {
                delegate = Signature.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new InvalidKeyException(e);
            }
            delegate.initSign(opaqueKey.getDelegate());
        }
        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            delegate.update(b);
        }
        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
            delegate.update(b, off, len);
        }
        @Override
        protected byte[] engineSign() throws SignatureException {
            return delegate.sign();
        }
        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            return delegate.verify(sigBytes);
        }
        @SuppressWarnings("deprecation")
        @Override
        protected void engineSetParameter(String param, Object value)
                throws InvalidParameterException {
            delegate.setParameter(param, value);
        }
        @SuppressWarnings("deprecation")
        @Override
        protected Object engineGetParameter(String param) throws InvalidParameterException {
            return delegate.getParameter(param);
        }
    }
    public static class OpaqueCipherSpi extends CipherSpi {
        private Cipher delegate;
        public OpaqueCipherSpi() {}
        @Override
        protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
            fail();
        }
        @Override
        protected void engineSetPadding(String padding) throws NoSuchPaddingException {
            fail();
        }
        @Override
        protected int engineGetBlockSize() {
            return delegate.getBlockSize();
        }
        @Override
        protected int engineGetOutputSize(int inputLen) {
            return delegate.getOutputSize(inputLen);
        }
        @Override
        protected byte[] engineGetIV() {
            return delegate.getIV();
        }
        @Override
        protected AlgorithmParameters engineGetParameters() {
            return delegate.getParameters();
        }
        @Override
        protected void engineInit(int opmode, Key key, SecureRandom random)
                throws InvalidKeyException {
            getCipher();
            delegate.init(opmode, key, random);
        }
        void getCipher() throws InvalidKeyException {
            try {
                delegate = Cipher.getInstance("RSA/ECB/NoPadding");
            } catch (NoSuchAlgorithmException e) {
                throw new InvalidKeyException(e);
            } catch (NoSuchPaddingException e) {
                throw new InvalidKeyException(e);
            }
        }
        @Override
        protected void engineInit(
                int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            getCipher();
            delegate.init(opmode, key, params, random);
        }
        @Override
        protected void engineInit(
                int opmode, Key key, AlgorithmParameters params, SecureRandom random)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            getCipher();
            delegate.init(opmode, key, params, random);
        }
        @Override
        protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
            return delegate.update(input, inputOffset, inputLen);
        }
        @Override
        protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
                int outputOffset) throws ShortBufferException {
            return delegate.update(input, inputOffset, inputLen, output, outputOffset);
        }
        @Override
        protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
                throws IllegalBlockSizeException, BadPaddingException {
            return delegate.update(input, inputOffset, inputLen);
        }
        @Override
        protected int engineDoFinal(
                byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
                throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
            return delegate.doFinal(input, inputOffset, inputLen, output, outputOffset);
        }
    }
    private interface DelegatingPrivateKey { PrivateKey getDelegate(); }
    @SuppressWarnings("serial")
    private static class OpaqueDelegatingECPrivateKey
            implements ECKey, PrivateKey, DelegatingPrivateKey {
        private final ECPrivateKey delegate;
        OpaqueDelegatingECPrivateKey(ECPrivateKey delegate) {
            this.delegate = delegate;
        }
        @Override
        public PrivateKey getDelegate() {
            return delegate;
        }
        @Override
        public String getAlgorithm() {
            return delegate.getAlgorithm();
        }
        @Override
        public String getFormat() {
            return null;
        }
        @Override
        public byte[] getEncoded() {
            return null;
        }
        @Override
        public ECParameterSpec getParams() {
            return delegate.getParams();
        }
    }
    @SuppressWarnings("serial")
    private static class OpaqueDelegatingRSAPrivateKey
            implements RSAKey, PrivateKey, DelegatingPrivateKey {
        private final RSAPrivateKey delegate;
        OpaqueDelegatingRSAPrivateKey(RSAPrivateKey delegate) {
            this.delegate = delegate;
        }
        @Override
        public String getAlgorithm() {
            return delegate.getAlgorithm();
        }
        @Override
        public String getFormat() {
            return null;
        }
        @Override
        public byte[] getEncoded() {
            return null;
        }
        @Override
        public BigInteger getModulus() {
            return delegate.getModulus();
        }
        @Override
        public PrivateKey getDelegate() {
            return delegate;
        }
    }

    @Test
    public void test_SSLSocket_TrustManagerRuntimeException() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLContext clientContext = SSLContext.getInstance("TLS");
        X509TrustManager trustManager = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                throw new AssertionError();
            }
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                throw new RuntimeException(); // throw a RuntimeException from custom TrustManager
            }
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                throw new AssertionError();
            }
        };
        clientContext.init(null, new TrustManager[] {trustManager}, null);
        SSLSocket client =
                (SSLSocket) clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                    fail();
                } catch (SSLHandshakeException expected) {
                    // Ignored.
                }
                return null;
            }
        });
        try {
            client.startHandshake();
            fail();
        } catch (SSLHandshakeException expected) {
            // before we would get a RuntimeException from checkServerTrusted.
        }
        future.get();
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_getEnableSessionCreation() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        SSLSocket server = (SSLSocket) c.serverSocket.accept();
        assertTrue(client.getEnableSessionCreation());
        assertTrue(server.getEnableSessionCreation());
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_setEnableSessionCreation_server() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                server.setEnableSessionCreation(false);
                try {
                    server.startHandshake();
                    fail();
                } catch (SSLException expected) {
                    // Ignored.
                }
                return null;
            }
        });
        try {
            client.startHandshake();
            fail();
        } catch (SSLException expected) {
            // Ignored.
        }
        future.get();
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_setEnableSessionCreation_client() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                    fail();
                } catch (SSLException expected) {
                    // Ignored.
                }
                return null;
            }
        });
        client.setEnableSessionCreation(false);
        try {
            client.startHandshake();
            fail();
        } catch (SSLException expected) {
            // Ignored.
        }
        future.get();
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_getSSLParameters() throws Exception {
        TestUtils.assumeSetEndpointIdentificationAlgorithmAvailable();
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket ssl = (SSLSocket) sf.createSocket();
        SSLParameters p = ssl.getSSLParameters();
        assertNotNull(p);
        String[] cipherSuites = p.getCipherSuites();
        assertNotSame(cipherSuites, ssl.getEnabledCipherSuites());
        assertEquals(Arrays.asList(cipherSuites), Arrays.asList(ssl.getEnabledCipherSuites()));
        String[] protocols = p.getProtocols();
        assertNotSame(protocols, ssl.getEnabledProtocols());
        assertEquals(Arrays.asList(protocols), Arrays.asList(ssl.getEnabledProtocols()));
        assertEquals(p.getWantClientAuth(), ssl.getWantClientAuth());
        assertEquals(p.getNeedClientAuth(), ssl.getNeedClientAuth());
        assertNull(p.getEndpointIdentificationAlgorithm());
        p.setEndpointIdentificationAlgorithm(null);
        assertNull(p.getEndpointIdentificationAlgorithm());
        p.setEndpointIdentificationAlgorithm("HTTPS");
        assertEquals("HTTPS", p.getEndpointIdentificationAlgorithm());
        p.setEndpointIdentificationAlgorithm("FOO");
        assertEquals("FOO", p.getEndpointIdentificationAlgorithm());
    }

    @Test
    public void test_SSLSocket_setSSLParameters() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket ssl = (SSLSocket) sf.createSocket();
        String[] defaultCipherSuites = ssl.getEnabledCipherSuites();
        String[] defaultProtocols = ssl.getEnabledProtocols();
        String[] supportedCipherSuites = ssl.getSupportedCipherSuites();
        String[] supportedProtocols = ssl.getSupportedProtocols();
        {
            SSLParameters p = new SSLParameters();
            ssl.setSSLParameters(p);
            assertEquals(Arrays.asList(defaultCipherSuites),
                    Arrays.asList(ssl.getEnabledCipherSuites()));
            assertEquals(Arrays.asList(defaultProtocols), Arrays.asList(ssl.getEnabledProtocols()));
        }
        {
            SSLParameters p = new SSLParameters(supportedCipherSuites, supportedProtocols);
            ssl.setSSLParameters(p);
            assertEquals(Arrays.asList(supportedCipherSuites),
                    Arrays.asList(ssl.getEnabledCipherSuites()));
            assertEquals(
                    Arrays.asList(supportedProtocols), Arrays.asList(ssl.getEnabledProtocols()));
        }
        {
            SSLParameters p = new SSLParameters();
            p.setNeedClientAuth(true);
            assertFalse(ssl.getNeedClientAuth());
            assertFalse(ssl.getWantClientAuth());
            ssl.setSSLParameters(p);
            assertTrue(ssl.getNeedClientAuth());
            assertFalse(ssl.getWantClientAuth());
            p.setWantClientAuth(true);
            assertTrue(ssl.getNeedClientAuth());
            assertFalse(ssl.getWantClientAuth());
            ssl.setSSLParameters(p);
            assertFalse(ssl.getNeedClientAuth());
            assertTrue(ssl.getWantClientAuth());
            p.setWantClientAuth(false);
            assertFalse(ssl.getNeedClientAuth());
            assertTrue(ssl.getWantClientAuth());
            ssl.setSSLParameters(p);
            assertFalse(ssl.getNeedClientAuth());
            assertFalse(ssl.getWantClientAuth());
        }
    }

    @Test
    public void test_SSLSocket_close() throws Exception {
        TestSSLSocketPair pair = TestSSLSocketPair.create().connect();
        SSLSocket server = pair.server;
        SSLSocket client = pair.client;
        assertFalse(server.isClosed());
        assertFalse(client.isClosed());
        InputStream input = client.getInputStream();
        OutputStream output = client.getOutputStream();
        server.close();
        client.close();
        assertTrue(server.isClosed());
        assertTrue(client.isClosed());
        // close after close is okay...
        server.close();
        client.close();
        // ...so are a lot of other operations...
        HandshakeCompletedListener l = new HandshakeCompletedListener() {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent e) {
            }
        };
        client.addHandshakeCompletedListener(l);
        assertNotNull(client.getEnabledCipherSuites());
        assertNotNull(client.getEnabledProtocols());
        client.getEnableSessionCreation();
        client.getNeedClientAuth();
        assertNotNull(client.getSession());
        assertNotNull(client.getSSLParameters());
        assertNotNull(client.getSupportedProtocols());
        client.getUseClientMode();
        client.getWantClientAuth();
        client.removeHandshakeCompletedListener(l);
        client.setEnabledCipherSuites(new String[0]);
        client.setEnabledProtocols(new String[0]);
        client.setEnableSessionCreation(false);
        client.setNeedClientAuth(false);
        client.setSSLParameters(client.getSSLParameters());
        client.setWantClientAuth(false);
        // ...but some operations are expected to give SocketException...
        try {
            client.startHandshake();
            fail();
        } catch (SocketException expected) {
            // Ignored.
        }
        try {
            client.getInputStream();
            fail();
        } catch (SocketException expected) {
            // Ignored.
        }
        try {
            client.getOutputStream();
            fail();
        } catch (SocketException expected) {
            // Ignored.
        }
        try {
            @SuppressWarnings("unused")
            int value = input.read();
            fail();
        } catch (SocketException expected) {
            // Ignored.
        }
        try {
            @SuppressWarnings("unused")
            int bytesRead = input.read(null, -1, -1);
            fail();
        } catch (NullPointerException expected) {
            // Ignored.
        } catch (SocketException expected) {
            // Ignored.
        }
        try {
            output.write(-1);
            fail();
        } catch (SocketException expected) {
            // Ignored.
        }
        try {
            output.write(null, -1, -1);
            fail();
        } catch (NullPointerException expected) {
            // Ignored.
        } catch (SocketException expected) {
            // Ignored.
        }
        // ... and one gives IllegalArgumentException
        try {
            client.setUseClientMode(false);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        pair.close();
    }
    /**
     * b/3350645 Test to confirm that an SSLSocket.close() performing
     * an SSL_shutdown does not throw an IOException if the peer
     * socket has been closed.
     */
    @Test
    public void test_SSLSocket_shutdownCloseOnClosedPeer() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        final Socket underlying = new Socket(c.host, c.port);
        final SSLSocket wrapping = (SSLSocket) c.clientContext.getSocketFactory().createSocket(
                underlying, c.host.getHostName(), c.port, false);
        Future<Void> clientFuture = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                wrapping.startHandshake();
                wrapping.getOutputStream().write(42);
                // close the underlying socket,
                // so that no SSL shutdown is sent
                underlying.close();
                wrapping.close();
                return null;
            }
        });
        SSLSocket server = (SSLSocket) c.serverSocket.accept();
        server.startHandshake();
        @SuppressWarnings("unused")
        int value = server.getInputStream().read();
        // wait for thread to finish so we know client is closed.
        clientFuture.get();
        // close should cause an SSL_shutdown which will fail
        // because the peer has closed, but it shouldn't throw.
        server.close();
    }

    @Test
    public void test_SSLSocket_endpointIdentification_Success() throws Exception {
        TestUtils.assumeSetEndpointIdentificationAlgorithmAvailable();
        final TestSSLContext c = TestSSLContext.create();
        SSLSocket client = (SSLSocket) c.clientContext.getSocketFactory().createSocket();
        SSLParameters p = client.getSSLParameters();
        p.setEndpointIdentificationAlgorithm("HTTPS");
        client.setSSLParameters(p);
        client.connect(new InetSocketAddress(c.host, c.port));
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                server.startHandshake();
                assertNotNull(server.getSession());
                try {
                    server.getSession().getPeerCertificates();
                    fail();
                } catch (SSLPeerUnverifiedException expected) {
                    // Ignored.
                }
                Certificate[] localCertificates = server.getSession().getLocalCertificates();
                assertNotNull(localCertificates);
                TestKeyStore.assertChainLength(localCertificates);
                assertNotNull(localCertificates[0]);
                TestSSLContext.assertCertificateInKeyStore(localCertificates[0], c.serverKeyStore);
                return null;
            }
        });
        client.startHandshake();
        assertNotNull(client.getSession());
        assertNull(client.getSession().getLocalCertificates());
        Certificate[] peerCertificates = client.getSession().getPeerCertificates();
        assertNotNull(peerCertificates);
        TestKeyStore.assertChainLength(peerCertificates);
        assertNotNull(peerCertificates[0]);
        TestSSLContext.assertCertificateInKeyStore(peerCertificates[0], c.serverKeyStore);
        future.get();
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_endpointIdentification_Failure() throws Exception {
        TestUtils.assumeSetEndpointIdentificationAlgorithmAvailable();
        final TestSSLContext c = TestSSLContext.create();
        SSLSocket client = (SSLSocket) c.clientContext.getSocketFactory().createSocket();
        SSLParameters p = client.getSSLParameters();
        p.setEndpointIdentificationAlgorithm("HTTPS");
        client.setSSLParameters(p);
        client.connect(c.getLoopbackAsHostname("unmatched.example.com", c.port));
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                    fail("Should receive SSLHandshakeException as server");
                } catch (SSLHandshakeException expected) {
                    // Ignored.
                }
                return null;
            }
        });
        try {
            client.startHandshake();
            fail("Should throw when hostname does not match expected");
        } catch (SSLHandshakeException expected) {
            // Ignored.
        } finally {
            try {
                future.get();
            } finally {
                client.close();
                server.close();
                c.close();
            }
        }
    }

    @Test
    public void test_SSLSocket_setSoTimeout_basic() throws Exception {
        ServerSocket listening = new ServerSocket(0);
        Socket underlying = new Socket(listening.getInetAddress(), listening.getLocalPort());
        assertEquals(0, underlying.getSoTimeout());
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        Socket wrapping = sf.createSocket(underlying, null, -1, false);
        assertEquals(0, wrapping.getSoTimeout());
        // setting wrapper sets underlying and ...
        int expectedTimeoutMillis = 1000; // 10 was too small because it was affected by rounding
        wrapping.setSoTimeout(expectedTimeoutMillis);
        // The kernel can round the requested value based on the HZ setting. We allow up to 10ms.
        assertTrue(Math.abs(expectedTimeoutMillis - wrapping.getSoTimeout()) <= 10);
        assertTrue(Math.abs(expectedTimeoutMillis - underlying.getSoTimeout()) <= 10);
        // ... getting wrapper inspects underlying
        underlying.setSoTimeout(0);
        assertEquals(0, wrapping.getSoTimeout());
        assertEquals(0, underlying.getSoTimeout());
    }

    @Test
    public void test_SSLSocket_setSoTimeout_wrapper() throws Exception {
        ServerSocket listening = new ServerSocket(0);
        // setSoTimeout applies to read, not connect, so connect first
        Socket underlying = new Socket(listening.getInetAddress(), listening.getLocalPort());
        Socket server = listening.accept();
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        Socket clientWrapping = sf.createSocket(underlying, null, -1, false);
        underlying.setSoTimeout(1);
        try {
            @SuppressWarnings("unused")
            int value = clientWrapping.getInputStream().read();
            fail();
        } catch (SocketTimeoutException expected) {
            // Ignored.
        }
        clientWrapping.close();
        server.close();
        underlying.close();
        listening.close();
    }

    @Test(expected = SocketTimeoutException.class)
    public void test_SSLSocket_setSoWriteTimeout() throws Exception {
        // Only run this test on Linux since it relies on non-posix methods.
        assumeTrue("Test only runs on Linux. Current OS: " + osName(), isLinux());

        // In jb-mr2 it was found that we need to also set SO_RCVBUF
        // to a minimal size or the write would not block.
        final int receiveBufferSize = 128;
        TestSSLContext c =
                TestSSLContext.newBuilder().serverReceiveBufferSize(receiveBufferSize).build();

        final SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);

        // Try to make the client SO_SNDBUF size as small as possible
        // (it can default to 512k or even megabytes).  Note that
        // socket(7) says that the kernel will double the request to
        // leave room for its own book keeping and that the minimal
        // value will be 2048. Also note that tcp(7) says the value
        // needs to be set before connect(2).
        int sendBufferSize = 1024;
        client.setSendBufferSize(sendBufferSize);
        sendBufferSize = client.getSendBufferSize();

        // Start the handshake.
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                client.startHandshake();
                return null;
            }
        });
        server.startHandshake();

        assertTrue(isConscryptSocket(client));
        // The concrete class that Conscrypt returns has methods on it that have no
        // equivalent on the public API (like setSoWriteTimeout), so users have
        // previously used reflection to access those otherwise-inaccessible methods
        // on that class.  The concrete class used to be named OpenSSLSocketImpl, so
        // check that OpenSSLSocketImpl is still in the class hierarchy so applications
        // that rely on getting that class back still work.
        Class<?> superClass = client.getClass();
        do {
            superClass = superClass.getSuperclass();
        } while (superClass != Object.class && !superClass.getName().endsWith("OpenSSLSocketImpl"));
        assertEquals("OpenSSLSocketImpl", superClass.getSimpleName());


        try {
            setWriteTimeout(client, 1);

            // Add extra space to the write to exceed the send buffer
            // size and cause the write to block.
            final int extra = 1;
            client.getOutputStream().write(new byte[sendBufferSize + extra]);
        } finally {
            future.get();
            client.close();
            server.close();
            c.close();
        }
    }

    @Test
    public void test_SSLSocket_reusedNpnSocket() throws Exception {
        byte[] npnProtocols = new byte[] {
                8, 'h', 't', 't', 'p', '/', '1', '.', '1'
        };

        final TestSSLContext c = TestSSLContext.create();
        SSLSocket client = (SSLSocket) c.clientContext.getSocketFactory().createSocket();

        assertTrue(isConscryptSocket(client));
        Class<?> actualClass = client.getClass();
        Method setNpnProtocols = actualClass.getMethod("setNpnProtocols", byte[].class);

        ExecutorService executor = Executors.newSingleThreadExecutor();

        // First connection with NPN set on client and server
        {
            setNpnProtocols.invoke(client, npnProtocols);
            client.connect(new InetSocketAddress(c.host, c.port));

            final SSLSocket server = (SSLSocket) c.serverSocket.accept();
            assertTrue(isConscryptSocket(server));
            setNpnProtocols.invoke(server, npnProtocols);

            Future<Void> future = executor.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    server.startHandshake();
                    return null;
                }
            });
            client.startHandshake();

            future.get();
            client.close();
            server.close();
        }

        // Second connection with client NPN already set on the SSL context, but
        // without server NPN set.
        {
            SSLServerSocket serverSocket = (SSLServerSocket) c.serverContext
                    .getServerSocketFactory().createServerSocket(0);
            InetAddress host = InetAddress.getLocalHost();
            int port = serverSocket.getLocalPort();

            client = (SSLSocket) c.clientContext.getSocketFactory().createSocket();
            client.connect(new InetSocketAddress(host, port));

            final SSLSocket server = (SSLSocket) serverSocket.accept();

            Future<Void> future = executor.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    server.startHandshake();
                    return null;
                }
            });
            client.startHandshake();

            future.get();
            client.close();
            server.close();
            serverSocket.close();
        }

        c.close();
    }

    // TODO(nmittler): Conscrypt socket read may return -1 instead of SocketException.
    @Test
    public void test_SSLSocket_interrupt_readUnderlyingAndCloseUnderlying() throws Exception {
        test_SSLSocket_interrupt_case(true, true);
    }

    // TODO(nmittler): Conscrypt socket read may return -1 instead of SocketException.
    @Test
    public void test_SSLSocket_interrupt_readUnderlyingAndCloseWrapper() throws Exception {
        test_SSLSocket_interrupt_case(true, false);
    }

    // TODO(nmittler): FD socket gets stuck in read on Windows and OSX.
    @Test
    public void test_SSLSocket_interrupt_readWrapperAndCloseUnderlying() throws Exception {
        test_SSLSocket_interrupt_case(false, true);
    }

    // TODO(nmittler): Conscrypt socket read may return -1 instead of SocketException.
    @Test
    public void test_SSLSocket_interrupt_readWrapperAndCloseWrapper() throws Exception {
        test_SSLSocket_interrupt_case(false, false);
    }

    private void test_SSLSocket_interrupt_case(boolean readUnderlying, boolean closeUnderlying)
            throws Exception {
        final int readingTimeoutMillis = 5000;
        TestSSLContext c = TestSSLContext.create();
        final Socket underlying = new Socket(c.host, c.port);
        final SSLSocket clientWrapping =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(
                        underlying, c.host.getHostName(), c.port, true);

        if (isConscryptFdSocket(clientWrapping) && !readUnderlying && closeUnderlying) {
            // TODO(nmittler): FD socket gets stuck in the read on Windows and OSX.
            assumeFalse("Skipping interrupt test on Windows", isWindows());
            assumeFalse("Skipping interrupt test on OSX", isOsx());
        }

        SSLSocket server = (SSLSocket) c.serverSocket.accept();

        // Start the handshake.
        Future<Void> handshakeFuture = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                clientWrapping.startHandshake();
                return null;
            }
        });
        server.startHandshake();
        handshakeFuture.get();

        final Socket toRead = (readUnderlying) ? underlying : clientWrapping;
        final Socket toClose = (closeUnderlying) ? underlying : clientWrapping;

        // Schedule the socket to be closed in 1 second.
        Future<Void> future = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                Thread.sleep(1000);
                toClose.close();
                return null;
            }
        });

        // Read from the socket.
        try {
            toRead.setSoTimeout(readingTimeoutMillis);
            int read = toRead.getInputStream().read();
            // In the case of reading the wrapper and closing the underlying socket,
            // there is a race condition between the reading thread being woken and
            // reading the socket again and the closing thread marking the file descriptor
            // as invalid.  If the latter happens first, a SocketException is thrown,
            // but if the former happens first it just looks like the peer closed the
            // connection and a -1 return is acceptable.
            if (read != -1 || readUnderlying || !closeUnderlying) {
                fail();
            }
        } catch (SocketTimeoutException e) {
            throw e;
        } catch (IOException expected) {
            // Expected
        }

        future.get();
        server.close();
        underlying.close();
        server.close();
    }

    /**
     * b/7014266 Test to confirm that an SSLSocket.close() on one
     * thread will interrupt another thread blocked reading on the same
     * socket.
     */
    // TODO(nmittler): Interrupts do not work with the engine-based socket.
    @Test
    public void test_SSLSocket_interrupt_read_withoutAutoClose() throws Exception {
        final int readingTimeoutMillis = 5000;
        TestSSLContext c = TestSSLContext.create();
        final Socket underlying = new Socket(c.host, c.port);
        final SSLSocket wrapping = (SSLSocket) c.clientContext.getSocketFactory().createSocket(
                underlying, c.host.getHostName(), c.port, false);

        // TODO(nmittler): Interrupts do not work with the engine-based socket.
        assumeFalse(isConscryptEngineSocket(wrapping));

        Future<Void> clientFuture = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                wrapping.startHandshake();
                try {
                    wrapping.setSoTimeout(readingTimeoutMillis);
                    wrapping.getInputStream().read();
                    fail();
                } catch (SocketException expected) {
                    // Conscrypt throws an exception complaining that the socket is closed
                    // if it's interrupted by a close() in the middle of a read()
                    assertTrue(expected.getMessage().contains("closed"));
                }
                return null;
            }
        });
        SSLSocket server = (SSLSocket) c.serverSocket.accept();
        server.startHandshake();

        // Wait for the client to at least be in the "read" method before calling close()
        Thread[] threads = new Thread[1];
        threadGroup.enumerate(threads);
        if (threads[0] != null) {
            boolean clientInRead = false;
            while (!clientInRead) {
                StackTraceElement[] elements = threads[0].getStackTrace();
                for (StackTraceElement element : elements) {
                    if ("read".equals(element.getMethodName())) {
                        // The client might be executing "read" but still not have reached the
                        // point in which it's blocked reading. This is causing flakiness
                        // (b/24367646). Delaying for a fraction of the timeout.
                        Thread.sleep(1000);
                        clientInRead = true;
                        break;
                    }
                }
            }
        }

        wrapping.close();

        clientFuture.get();
        server.close();
    }

    @Test
    public void test_TestSSLSocketPair_create() {
        TestSSLSocketPair test = TestSSLSocketPair.create().connect();
        assertNotNull(test.c);
        assertNotNull(test.server);
        assertNotNull(test.client);
        assertTrue(test.server.isConnected());
        assertTrue(test.client.isConnected());
        assertFalse(test.server.isClosed());
        assertFalse(test.client.isClosed());
        assertNotNull(test.server.getSession());
        assertNotNull(test.client.getSession());
        assertTrue(test.server.getSession().isValid());
        assertTrue(test.client.getSession().isValid());
        test.close();
    }

    @Test
    public void test_SSLSocket_ClientHello_record_size() throws Exception {
        // This test checks the size of ClientHello of the default SSLSocket. TLS/SSL handshakes
        // with older/unpatched F5/BIG-IP appliances are known to stall and time out when
        // the fragment containing ClientHello is between 256 and 511 (inclusive) bytes long.
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        sslSocketFactory = new DelegatingSSLSocketFactory(sslSocketFactory) {
            @Override
            protected SSLSocket configureSocket(SSLSocket socket) {
                // Enable SNI extension on the socket (this is typically enabled by default)
                // to increase the size of ClientHello.
                setHostname(socket);

                // Enable Session Tickets extension on the socket (this is typically enabled
                // by default) to increase the size of ClientHello.
                enableSessionTickets(socket);
                return socket;
            }
        };
        TlsRecord firstReceivedTlsRecord = captureTlsHandshakeFirstTlsRecord(sslSocketFactory);
        assertEquals("TLS record type", TlsProtocols.HANDSHAKE, firstReceivedTlsRecord.type);
        HandshakeMessage handshakeMessage = HandshakeMessage.read(
                new DataInputStream(new ByteArrayInputStream(firstReceivedTlsRecord.fragment)));
        assertEquals(
                "HandshakeMessage type", HandshakeMessage.TYPE_CLIENT_HELLO, handshakeMessage.type);
        int fragmentLength = firstReceivedTlsRecord.fragment.length;
        if ((fragmentLength >= 256) && (fragmentLength <= 511)) {
            fail("Fragment containing ClientHello is of dangerous length: " + fragmentLength
                    + " bytes");
        }
    }

    @Test
    public void test_SSLSocket_ClientHello_cipherSuites() throws Exception {
        ForEachRunner.runNamed(new Callback<SSLSocketFactory>() {
            @Override
            public void run(SSLSocketFactory sslSocketFactory) throws Exception {
                ClientHello clientHello = SSLSocketTest.this
                    .captureTlsHandshakeClientHello(sslSocketFactory);
                final String[] cipherSuites;
                // RFC 5746 allows you to send an empty "renegotiation_info" extension *or*
                // a special signaling cipher suite. The TLS API has no way to check or
                // indicate that a certain TLS extension should be used.
                HelloExtension renegotiationInfoExtension =
                    clientHello.findExtensionByType(HelloExtension.TYPE_RENEGOTIATION_INFO);
                if (renegotiationInfoExtension != null
                    && renegotiationInfoExtension.data.length == 1
                    && renegotiationInfoExtension.data[0] == 0) {
                    cipherSuites = new String[clientHello.cipherSuites.size() + 1];
                    cipherSuites[clientHello.cipherSuites.size()] =
                        StandardNames.CIPHER_SUITE_SECURE_RENEGOTIATION;
                } else {
                    cipherSuites = new String[clientHello.cipherSuites.size()];
                }
                for (int i = 0; i < clientHello.cipherSuites.size(); i++) {
                    CipherSuite cipherSuite = clientHello.cipherSuites.get(i);
                    cipherSuites[i] = cipherSuite.getAndroidName();
                }
                StandardNames.assertDefaultCipherSuites(cipherSuites);
            }
        }, getSSLSocketFactoriesToTest());
    }

    @Test
    public void test_SSLSocket_ClientHello_supportedCurves() throws Exception {
        ForEachRunner.runNamed(new Callback<SSLSocketFactory>() {
            @Override
            public void run(SSLSocketFactory sslSocketFactory) throws Exception {
                ClientHello clientHello = SSLSocketTest.this
                    .captureTlsHandshakeClientHello(sslSocketFactory);
                EllipticCurvesHelloExtension ecExtension =
                    (EllipticCurvesHelloExtension) clientHello.findExtensionByType(
                        HelloExtension.TYPE_ELLIPTIC_CURVES);
                final String[] supportedCurves;
                if (ecExtension == null) {
                    supportedCurves = new String[0];
                } else {
                    assertTrue(ecExtension.wellFormed);
                    supportedCurves = new String[ecExtension.supported.size()];
                    for (int i = 0; i < ecExtension.supported.size(); i++) {
                        EllipticCurve curve = ecExtension.supported.get(i);
                        supportedCurves[i] = curve.toString();
                    }
                }
                StandardNames.assertDefaultEllipticCurves(supportedCurves);
            }
        }, getSSLSocketFactoriesToTest());
    }

    @Test
    public void test_SSLSocket_ClientHello_clientProtocolVersion() throws Exception {
        ForEachRunner.runNamed(new Callback<SSLSocketFactory>() {
            @Override
            public void run(SSLSocketFactory sslSocketFactory) throws Exception {
                ClientHello clientHello = SSLSocketTest.this
                    .captureTlsHandshakeClientHello(sslSocketFactory);
                assertEquals(TlsProtocolVersion.TLSv1_2, clientHello.clientVersion);
            }
        }, getSSLSocketFactoriesToTest());
    }

    @Test
    public void test_SSLSocket_ClientHello_compressionMethods() throws Exception {
        ForEachRunner.runNamed(new Callback<SSLSocketFactory>() {
            @Override
            public void run(SSLSocketFactory sslSocketFactory) throws Exception {
                ClientHello clientHello = SSLSocketTest.this
                    .captureTlsHandshakeClientHello(sslSocketFactory);
                assertEquals(Collections.singletonList(CompressionMethod.NULL),
                    clientHello.compressionMethods);
            }
        }, getSSLSocketFactoriesToTest());
    }

    @Test
    public void test_SSLSocket_ClientHello_SNI() throws Exception {
        ForEachRunner.runNamed(new Callback<SSLSocketFactory>() {
            @Override
            public void run(SSLSocketFactory sslSocketFactory) throws Exception {
                ClientHello clientHello = SSLSocketTest.this
                    .captureTlsHandshakeClientHello(sslSocketFactory);
                ServerNameHelloExtension sniExtension =
                    (ServerNameHelloExtension) clientHello.findExtensionByType(
                        HelloExtension.TYPE_SERVER_NAME);
                assertNotNull(sniExtension);
                assertEquals(
                    Collections.singletonList("localhost.localdomain"), sniExtension.hostnames);
            }
        }, getSSLSocketFactoriesToTest());
    }
    private List<Pair<String, SSLSocketFactory>> getSSLSocketFactoriesToTest()
            throws NoSuchAlgorithmException, KeyManagementException {
        List<Pair<String, SSLSocketFactory>> result =
                new ArrayList<Pair<String, SSLSocketFactory>>();
        result.add(Pair.of("default", (SSLSocketFactory) SSLSocketFactory.getDefault()));
        for (String sslContextProtocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            SSLContext sslContext = SSLContext.getInstance(sslContextProtocol);
            if (StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT.equals(sslContextProtocol)) {
                continue;
            }
            sslContext.init(null, null, null);
            result.add(Pair.of("SSLContext(\"" + sslContext.getProtocol() + "\")",
                    sslContext.getSocketFactory()));
        }
        return result;
    }
    private ClientHello captureTlsHandshakeClientHello(SSLSocketFactory sslSocketFactory)
            throws Exception {
        TlsRecord record = captureTlsHandshakeFirstTlsRecord(sslSocketFactory);
        assertEquals("TLS record type", TlsProtocols.HANDSHAKE, record.type);
        ByteArrayInputStream fragmentIn = new ByteArrayInputStream(record.fragment);
        HandshakeMessage handshakeMessage = HandshakeMessage.read(new DataInputStream(fragmentIn));
        assertEquals(
                "HandshakeMessage type", HandshakeMessage.TYPE_CLIENT_HELLO, handshakeMessage.type);
        // Assert that the fragment does not contain any more messages
        assertEquals(0, fragmentIn.available());
        return (ClientHello) handshakeMessage;
    }
    private TlsRecord captureTlsHandshakeFirstTlsRecord(SSLSocketFactory sslSocketFactory)
            throws Exception {
        byte[] firstReceivedChunk = captureTlsHandshakeFirstTransmittedChunkBytes(sslSocketFactory);
        ByteArrayInputStream firstReceivedChunkIn = new ByteArrayInputStream(firstReceivedChunk);
        TlsRecord record = TlsRecord.read(new DataInputStream(firstReceivedChunkIn));
        // Assert that the chunk does not contain any more data
        assertEquals(0, firstReceivedChunkIn.available());
        return record;
    }
    @SuppressWarnings("FutureReturnValueIgnored")
    private byte[] captureTlsHandshakeFirstTransmittedChunkBytes(
            final SSLSocketFactory sslSocketFactory) throws Exception {
        // Since there's no straightforward way to obtain a ClientHello from SSLSocket, this test
        // does the following:
        // 1. Creates a listening server socket (a plain one rather than a TLS/SSL one).
        // 2. Creates a client SSLSocket, which connects to the server socket and initiates the
        //    TLS/SSL handshake.
        // 3. Makes the server socket accept an incoming connection on the server socket, and reads
        //    the first chunk of data received. This chunk is assumed to be the ClientHello.
        // NOTE: Steps 2 and 3 run concurrently.
        ServerSocket listeningSocket = null;
        // Some Socket operations are not interruptible via Thread.interrupt for some reason. To
        // work around, we unblock these sockets using Socket.close.
        final Socket[] sockets = new Socket[2];
        try {
            // 1. Create the listening server socket.
            listeningSocket = ServerSocketFactory.getDefault().createServerSocket(0);
            final ServerSocket finalListeningSocket = listeningSocket;
            // 2. (in background) Wait for an incoming connection and read its first chunk.
            final Future<byte[]> readFirstReceivedChunkFuture = runAsync(new Callable<byte[]>() {
                @Override
                public byte[] call() throws Exception {
                    Socket socket = finalListeningSocket.accept();
                    sockets[1] = socket;
                    try {
                        byte[] buffer = new byte[64 * 1024];
                        int bytesRead = socket.getInputStream().read(buffer);
                        if (bytesRead == -1) {
                            throw new EOFException("Failed to read anything");
                        }
                        return Arrays.copyOf(buffer, bytesRead);
                    } finally {
                        closeQuietly(socket);
                    }
                }
            });
            // 3. Create a client socket, connect it to the server socket, and start the TLS/SSL
            //    handshake.
            runAsync(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    Socket client = new Socket();
                    sockets[0] = client;
                    try {
                        client.connect(finalListeningSocket.getLocalSocketAddress());
                        // Initiate the TLS/SSL handshake which is expected to fail as soon as the
                        // server socket receives a ClientHello.
                        try {
                            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(client,
                                    "localhost.localdomain", finalListeningSocket.getLocalPort(),
                                    true);
                            sslSocket.startHandshake();
                            fail();
                            return null;
                        } catch (IOException expected) {
                            // Ignored.
                        }
                        return null;
                    } finally {
                        closeQuietly(client);
                    }
                }
            });
            // Wait for the ClientHello to arrive
            return readFirstReceivedChunkFuture.get(10, TimeUnit.SECONDS);
        } finally {
            closeQuietly(listeningSocket);
            closeQuietly(sockets[0]);
            closeQuietly(sockets[1]);
        }
    }
    // http://b/18428603
    @Test
    public void test_SSLSocket_getPortWithSNI() throws Exception {
        TestSSLContext context = TestSSLContext.create();
        SSLSocket client =
            (SSLSocket) context.clientContext.getSocketFactory().createSocket();
        try {
            client.connect(new InetSocketAddress(context.host, context.port));
            setHostname(client);
            assertTrue(client.getPort() > 0);
        } finally {
            client.close();
            context.close();
        }
    }

    @Test
    public void test_SSLSocket_SNIHostName() throws Exception {
        TestUtils.assumeSNIHostnameAvailable();
        TestSSLContext c = TestSSLContext.create();
        final SSLSocket client = (SSLSocket) c.clientContext.getSocketFactory().createSocket();
        SSLParameters clientParams = client.getSSLParameters();
        clientParams.setServerNames(
                Collections.singletonList((SNIServerName) new SNIHostName("www.example.com")));
        client.setSSLParameters(clientParams);
        SSLParameters serverParams = c.serverSocket.getSSLParameters();
        serverParams.setSNIMatchers(
                Collections.singletonList(SNIHostName.createSNIMatcher("www\\.example\\.com")));
        c.serverSocket.setSSLParameters(serverParams);
        client.connect(new InetSocketAddress(c.host, c.port));
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        @SuppressWarnings("unused")
        Future<?> future = runAsync(new Callable<Object>() {
            @Override
            public Object call() throws Exception {
                client.startHandshake();
                return null;
            }
        });
        server.startHandshake();
        SSLSession serverSession = server.getSession();
        assertTrue(serverSession instanceof ExtendedSSLSession);
        ExtendedSSLSession extendedServerSession = (ExtendedSSLSession) serverSession;
        List<SNIServerName> requestedNames = extendedServerSession.getRequestedServerNames();
        assertNotNull(requestedNames);
        assertEquals(1, requestedNames.size());
        SNIServerName serverName = requestedNames.get(0);
        assertEquals(StandardConstants.SNI_HOST_NAME, serverName.getType());
        assertTrue(serverName instanceof SNIHostName);
        SNIHostName serverHostName = (SNIHostName) serverName;
        assertEquals("www.example.com", serverHostName.getAsciiName());
    }

    @Test
    public void test_SSLSocket_sendsTlsFallbackScsv_Fallback_Success() throws Exception {
        TestSSLContext context = TestSSLContext.create();
        final SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                context.host, context.port);
        final SSLSocket server = (SSLSocket) context.serverSocket.accept();
        final String[] serverCipherSuites = server.getEnabledCipherSuites();
        final String[] clientCipherSuites = new String[serverCipherSuites.length + 1];
        System.arraycopy(serverCipherSuites, 0, clientCipherSuites, 0, serverCipherSuites.length);
        clientCipherSuites[serverCipherSuites.length] = StandardNames.CIPHER_SUITE_FALLBACK;
        Future<Void> s = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                server.setEnabledProtocols(new String[]{"TLSv1.2"});
                server.setEnabledCipherSuites(serverCipherSuites);
                server.startHandshake();
                return null;
            }
        });
        Future<Void> c = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                client.setEnabledProtocols(new String[]{"TLSv1.2"});
                client.setEnabledCipherSuites(clientCipherSuites);
                client.startHandshake();
                return null;
            }
        });
        s.get();
        c.get();
        client.close();
        server.close();
        context.close();
    }
    // Confirms that communication without the TLS_FALLBACK_SCSV cipher works as it always did.
    @Test
    public void test_SSLSocket_sendsNoTlsFallbackScsv_Fallback_Success() throws Exception {
        TestSSLContext context = TestSSLContext.create();
        final SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                context.host, context.port);
        final SSLSocket server = (SSLSocket) context.serverSocket.accept();
        // Confirm absence of TLS_FALLBACK_SCSV.
        assertFalse(Arrays.asList(client.getEnabledCipherSuites())
                            .contains(StandardNames.CIPHER_SUITE_FALLBACK));
        Future<Void> s = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                server.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.1"});
                server.startHandshake();
                return null;
            }
        });
        Future<Void> c = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                client.setEnabledProtocols(new String[]{"TLSv1.1"});
                client.startHandshake();
                return null;
            }
        });
        s.get();
        c.get();
        client.close();
        server.close();
        context.close();
    }

    private static void assertInappropriateFallbackIsCause(Throwable cause) {
        assertTrue(cause.getMessage(),
                cause.getMessage().contains("inappropriate fallback")
                        || cause.getMessage().contains("INAPPROPRIATE_FALLBACK"));
    }

    @Test
    public void test_SSLSocket_sendsTlsFallbackScsv_InappropriateFallback_Failure()
            throws Exception {
        TestSSLContext context = TestSSLContext.create();
        final SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                context.host, context.port);
        final SSLSocket server = (SSLSocket) context.serverSocket.accept();
        final String[] serverCipherSuites = server.getEnabledCipherSuites();
        // Add TLS_FALLBACK_SCSV
        final String[] clientCipherSuites = new String[serverCipherSuites.length + 1];
        System.arraycopy(serverCipherSuites, 0, clientCipherSuites, 0, serverCipherSuites.length);
        clientCipherSuites[serverCipherSuites.length] = StandardNames.CIPHER_SUITE_FALLBACK;
        Future<Void> s = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                server.setEnabledProtocols(new String[] {"TLSv1.1", "TLSv1"});
                server.setEnabledCipherSuites(serverCipherSuites);
                try {
                    server.startHandshake();
                    fail("Should result in inappropriate fallback");
                } catch (SSLHandshakeException expected) {
                    Throwable cause = expected.getCause();
                    assertEquals(SSLProtocolException.class, cause.getClass());
                    assertInappropriateFallbackIsCause(cause);
                }
                return null;
            }
        });
        Future<Void> c = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                client.setEnabledProtocols(new String[]{"TLSv1"});
                client.setEnabledCipherSuites(clientCipherSuites);
                try {
                    client.startHandshake();
                    fail("Should receive TLS alert inappropriate fallback");
                } catch (SSLHandshakeException expected) {
                    Throwable cause = expected.getCause();
                    assertEquals(SSLProtocolException.class, cause.getClass());
                    assertInappropriateFallbackIsCause(cause);
                }
                return null;
            }
        });
        s.get();
        c.get();
        client.close();
        server.close();
        context.close();
    }

    @Test
    public void test_SSLSocket_ClientGetsAlertDuringHandshake_HasGoodExceptionMessage()
            throws Exception {
        TestSSLContext context = TestSSLContext.create();
        final ServerSocket listener = ServerSocketFactory.getDefault().createServerSocket(0);
        final SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                context.host, listener.getLocalPort());
        final Socket server = listener.accept();
        Future<Void> c = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    client.startHandshake();
                    fail("Should receive handshake exception");
                } catch (SSLHandshakeException expected) {
                    assertFalse(expected.getMessage().contains("SSL_ERROR_ZERO_RETURN"));
                    assertFalse(expected.getMessage().contains("You should never see this."));
                }
                return null;
            }
        });
        Future<Void> s = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                // Wait until the client sends something.
                byte[] scratch = new byte[8192];
                @SuppressWarnings("unused")
                int bytesRead = server.getInputStream().read(scratch);
                // Write a bogus TLS alert:
                // TLSv1.2 Record Layer: Alert (Level: Warning, Description: Protocol Version)
                server.getOutputStream()
                    .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x46});
                // TLSv1.2 Record Layer: Alert (Level: Warning, Description: Close Notify)
                server.getOutputStream()
                    .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00});
                return null;
            }
        });
        c.get(5, TimeUnit.SECONDS);
        s.get(5, TimeUnit.SECONDS);
        client.close();
        server.close();
        listener.close();
        context.close();
    }

    @Test
    public void test_SSLSocket_ServerGetsAlertDuringHandshake_HasGoodExceptionMessage()
            throws Exception {
        TestSSLContext context = TestSSLContext.create();
        final Socket client = SocketFactory.getDefault().createSocket(context.host, context.port);
        final SSLSocket server = (SSLSocket) context.serverSocket.accept();
        Future<Void> s = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                    fail("Should receive handshake exception");
                } catch (SSLHandshakeException expected) {
                    assertFalse(expected.getMessage().contains("SSL_ERROR_ZERO_RETURN"));
                    assertFalse(expected.getMessage().contains("You should never see this."));
                }
                return null;
            }
        });
        Future<Void> c = runAsync(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                // Send bogus ClientHello:
                // TLSv1.2 Record Layer: Handshake Protocol: Client Hello
                client.getOutputStream().write(new byte[]{
                    (byte) 0x16, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0xb9,
                    (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0xb5, (byte) 0x03,
                    (byte) 0x03, (byte) 0x5a, (byte) 0x31, (byte) 0xba, (byte) 0x44,
                    (byte) 0x24, (byte) 0xfd, (byte) 0xf0, (byte) 0x56, (byte) 0x46,
                    (byte) 0xea, (byte) 0xee, (byte) 0x1c, (byte) 0x62, (byte) 0x8f,
                    (byte) 0x18, (byte) 0x04, (byte) 0xbd, (byte) 0x1c, (byte) 0xbc,
                    (byte) 0xbf, (byte) 0x6d, (byte) 0x84, (byte) 0x12, (byte) 0xe9,
                    (byte) 0x94, (byte) 0xf5, (byte) 0x1c, (byte) 0x15, (byte) 0x3e,
                    (byte) 0x79, (byte) 0x01, (byte) 0xe2, (byte) 0x00, (byte) 0x00,
                    (byte) 0x28, (byte) 0xc0, (byte) 0x2b, (byte) 0xc0, (byte) 0x2c,
                    (byte) 0xc0, (byte) 0x2f, (byte) 0xc0, (byte) 0x30, (byte) 0x00,
                    (byte) 0x9e, (byte) 0x00, (byte) 0x9f, (byte) 0xc0, (byte) 0x09,
                    (byte) 0xc0, (byte) 0x0a, (byte) 0xc0, (byte) 0x13, (byte) 0xc0,
                    (byte) 0x14, (byte) 0x00, (byte) 0x33, (byte) 0x00, (byte) 0x39,
                    (byte) 0xc0, (byte) 0x07, (byte) 0xc0, (byte) 0x11, (byte) 0x00,
                    (byte) 0x9c, (byte) 0x00, (byte) 0x9d, (byte) 0x00, (byte) 0x2f,
                    (byte) 0x00, (byte) 0x35, (byte) 0x00, (byte) 0x05, (byte) 0x00,
                    (byte) 0xff, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x64,
                    (byte) 0x00, (byte) 0x0b, (byte) 0x00, (byte) 0x04, (byte) 0x03,
                    (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x00, (byte) 0x0a,
                    (byte) 0x00, (byte) 0x34, (byte) 0x00, (byte) 0x32, (byte) 0x00,
                    (byte) 0x0e, (byte) 0x00, (byte) 0x0d, (byte) 0x00, (byte) 0x19,
                    (byte) 0x00, (byte) 0x0b, (byte) 0x00, (byte) 0x0c, (byte) 0x00,
                    (byte) 0x18, (byte) 0x00, (byte) 0x09, (byte) 0x00, (byte) 0x0a,
                    (byte) 0x00, (byte) 0x16, (byte) 0x00, (byte) 0x17, (byte) 0x00,
                    (byte) 0x08, (byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x07,
                    (byte) 0x00, (byte) 0x14, (byte) 0x00, (byte) 0x15, (byte) 0x00,
                    (byte) 0x04, (byte) 0x00, (byte) 0x05, (byte) 0x00, (byte) 0x12,
                    (byte) 0x00, (byte) 0x13, (byte) 0x00, (byte) 0x01, (byte) 0x00,
                    (byte) 0x02, (byte) 0x00, (byte) 0x03, (byte) 0x00, (byte) 0x0f,
                    (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x11, (byte) 0x00,
                    (byte) 0x0d, (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x1e,
                    (byte) 0x06, (byte) 0x01, (byte) 0x06, (byte) 0x02, (byte) 0x06,
                    (byte) 0x03, (byte) 0x05, (byte) 0x01, (byte) 0x05, (byte) 0x02,
                    (byte) 0x05, (byte) 0x03, (byte) 0x04, (byte) 0x01, (byte) 0x04,
                    (byte) 0x02, (byte) 0x04, (byte) 0x03, (byte) 0x03, (byte) 0x01,
                    (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x03, (byte) 0x02,
                    (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x03,
                });
                // Wait until the server sends something.
                byte[] scratch = new byte[8192];
                @SuppressWarnings("unused")
                int bytesRead = client.getInputStream().read(scratch);
                // Write a bogus TLS alert:
                // TLSv1.2 Record Layer: Alert (Level: Warning, Description:
                // Protocol Version)
                client.getOutputStream()
                    .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x46});
                // TLSv1.2 Record Layer: Alert (Level: Warning, Description:
                // Close Notify)
                client.getOutputStream()
                    .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00});
                return null;
            }
        });
        c.get(5, TimeUnit.SECONDS);
        s.get(5, TimeUnit.SECONDS);
        client.close();
        server.close();
        context.close();
    }

    @Test
    public void test_SSLSocket_SSLv3Unsupported() throws Exception {
        TestSSLContext context = TestSSLContext.create();
        final SSLSocket client =
                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
        // For app compatibility, SSLv3 is stripped out when setting only.
        client.setEnabledProtocols(new String[] {"SSLv3"});
        assertEquals(0, client.getEnabledProtocols().length);
        try {
            client.setEnabledProtocols(new String[] {"SSL"});
            fail("SSLSocket should not support SSL protocol");
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
    }

    // Under some circumstances, the file descriptor socket may get finalized but still
    // be reused by the JDK's built-in HTTP connection reuse code.  Ensure that a
    // SocketException is thrown if that happens.
    @Test
    public void test_SSLSocket_finalizeThrowsProperException() throws Exception {
        TestSSLSocketPair test = TestSSLSocketPair.create().connect();
        try {
            if (isConscryptFdSocket(test.client)) {
                // The finalize method might be declared on a superclass rather than this
                // class.
                Method method = null;
                Class<?> clazz = test.client.getClass();
                while (clazz != null) {
                    try {
                        method = clazz.getDeclaredMethod("finalize");
                        break;
                    } catch (NoSuchMethodException e) {
                        // Try the superclass
                    }
                    clazz = clazz.getSuperclass();
                }
                assertNotNull(method);
                method.setAccessible(true);
                method.invoke(test.client);
                try {
                    test.client.getOutputStream().write(new byte[] { 0x01 });
                    fail("The socket shouldn't work after being finalized");
                } catch (SocketException expected) {
                    // Expected
                }
            }
        } finally {
            test.close();
        }
    }

    @Test
    public void test_SSLSocket_TlsUnique() throws Exception {
        TestSSLSocketPair pair = TestSSLSocketPair.create();
        try {
            assertNull(Conscrypt.getTlsUnique(pair.client));
            assertNull(Conscrypt.getTlsUnique(pair.server));

            pair.connect();

            byte[] clientTlsUnique = Conscrypt.getTlsUnique(pair.client);
            byte[] serverTlsUnique = Conscrypt.getTlsUnique(pair.server);
            assertNotNull(clientTlsUnique);
            assertNotNull(serverTlsUnique);
            assertArrayEquals(clientTlsUnique, serverTlsUnique);
        } finally {
            pair.close();
        }
    }

    // Tests that all cipher suites have a 12-byte tls-unique channel binding value.  If this
    // test fails, that means some cipher suite has been added that uses a customized verify_data
    // length and we need to update MAX_TLS_UNIQUE_LENGTH in native_crypto.cc to account for that.
    @Test
    public void test_SSLSocket_TlsUniqueLength() throws Exception {
        // note the rare usage of non-RSA keys
        TestKeyStore testKeyStore = new TestKeyStore.Builder()
                .keyAlgorithms("RSA", "DSA", "EC", "EC_RSA")
                .aliasPrefix("rsa-dsa-ec")
                .ca(true)
                .build();
        KeyManager pskKeyManager =
                PSKKeyManagerProxy.getConscryptPSKKeyManager(new PSKKeyManagerProxy() {
                    @Override
                    protected SecretKey getKey(
                            String identityHint, String identity, Socket socket) {
                        return newKey();
                    }

                    @Override
                    protected SecretKey getKey(
                            String identityHint, String identity, SSLEngine engine) {
                        return newKey();
                    }

                    private SecretKey newKey() {
                        return new SecretKeySpec("Just an arbitrary key".getBytes(UTF_8), "RAW");
                    }
                });
        TestSSLContext c = TestSSLContext.newBuilder()
                .client(testKeyStore)
                .server(testKeyStore)
                .additionalClientKeyManagers(new KeyManager[] {pskKeyManager})
                .additionalServerKeyManagers(new KeyManager[] {pskKeyManager})
                .build();
        for (String cipherSuite : c.clientContext.getSocketFactory().getSupportedCipherSuites()) {
            if (cipherSuite.equals(StandardNames.CIPHER_SUITE_FALLBACK)
                    || cipherSuite.equals(StandardNames.CIPHER_SUITE_SECURE_RENEGOTIATION)) {
                continue;
            }
            TestSSLSocketPair pair = TestSSLSocketPair.create(c);
            try {
                String[] cipherSuites =
                        new String[] {cipherSuite, StandardNames.CIPHER_SUITE_SECURE_RENEGOTIATION};
                pair.connect(cipherSuites, cipherSuites);

                assertEquals(cipherSuite, pair.client.getSession().getCipherSuite());

                byte[] clientTlsUnique = Conscrypt.getTlsUnique(pair.client);
                byte[] serverTlsUnique = Conscrypt.getTlsUnique(pair.server);
                assertNotNull(clientTlsUnique);
                assertNotNull(serverTlsUnique);
                assertArrayEquals(clientTlsUnique, serverTlsUnique);
                assertEquals(12, clientTlsUnique.length);
            } catch (Exception e) {
                throw new AssertionError("Cipher suite is " + cipherSuite, e);
            } finally {
                pair.client.close();
                pair.server.close();
            }
        }
    }

    // Tests that a socket will close cleanly even if it fails to create due to an
    // internal IOException
    @Test
    public void test_SSLSocket_CloseCleanlyOnConstructorFailure() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        try {
            c.clientContext.getSocketFactory().createSocket(c.host, 1);
            fail();
        } catch (ConnectException ignored) {
            // Ignored.
        }
    }

    private static void setWriteTimeout(Object socket, int timeout) {
        Exception ex = null;
        try {
            Method method = socket.getClass().getMethod("setSoWriteTimeout", int.class);
            method.setAccessible(true);
            method.invoke(socket, timeout);
        } catch (Exception e) {
            ex = e;
        }
        // Engine-based socket currently has the method but throws UnsupportedOperationException.
        assumeNoException("Client socket does not support setting write timeout", ex);
    }

    private static void setHostname(SSLSocket socket) {
        try {
            Method method = socket.getClass().getMethod("setHostname", String.class);
            method.setAccessible(true);
            method.invoke(socket, "sslsockettest.androidcts.google.com");
        } catch (NoSuchMethodException ignored) {
            // Ignored.
        } catch (Exception e) {
            throw new RuntimeException("Failed to enable SNI", e);
        }
    }

    private static void enableSessionTickets(SSLSocket socket) {
        try {
            Method method =
                    socket.getClass().getMethod("setUseSessionTickets", boolean.class);
            method.setAccessible(true);
            method.invoke(socket, true);
        } catch (NoSuchMethodException ignored) {
            // Ignored.
        } catch (Exception e) {
            throw new RuntimeException("Failed to enable Session Tickets", e);
        }
    }

    private static boolean isConscryptSocket(SSLSocket socket) {
        return isConscryptFdSocket(socket) || isConscryptEngineSocket(socket);
    }

    private static boolean isConscryptFdSocket(SSLSocket socket) {
        Class<?> clazz = socket.getClass();
        while (clazz != Object.class && !"ConscryptFileDescriptorSocket".equals(clazz.getSimpleName())) {
            clazz = clazz.getSuperclass();
        }
        return "ConscryptFileDescriptorSocket".equals(clazz.getSimpleName());
    }

    private static boolean isConscryptEngineSocket(SSLSocket socket) {
        Class<?> clazz = socket.getClass();
        while (clazz != Object.class && !"ConscryptEngineSocket".equals(clazz.getSimpleName())) {
            clazz = clazz.getSuperclass();
        }
        return "ConscryptEngineSocket".equals(clazz.getSimpleName());
    }

    private static String osName() {
        return System.getProperty("os.name").toLowerCase(Locale.US).replaceAll("[^a-z0-9]+", "");
    }

    private static boolean isLinux() {
        return osName().startsWith("linux");
    }

    private static boolean isWindows() {
        return osName().startsWith("windows");
    }

    private static boolean isOsx() {
        String name = osName();
        return name.startsWith("macosx") || name.startsWith("osx");
    }

    private <T> Future<T> runAsync(Callable<T> callable) {
        return executor.submit(callable);
    }

    private static void readFully(InputStream in, byte[] dst) throws IOException {
        int offset = 0;
        int byteCount = dst.length;
        while (byteCount > 0) {
            int bytesRead = in.read(dst, offset, byteCount);
            if (bytesRead < 0) {
                throw new EOFException();
            }
            offset += bytesRead;
            byteCount -= bytesRead;
        }
    }

    private static SSLSession getHandshakeSession(SSLSocket socket) {
        try {
            Method method = socket.getClass().getMethod("getHandshakeSession");
            return (SSLSession) method.invoke(socket);
        } catch (Exception e) {
            return null;
        }
    }

    private static void closeQuietly(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (Exception ignored) {
                // Ignored.
            }
        }
    }

    private static void closeQuietly(ServerSocket serverSocket) {
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (Exception ignored) {
                // Ignored.
            }
        }
    }
}
