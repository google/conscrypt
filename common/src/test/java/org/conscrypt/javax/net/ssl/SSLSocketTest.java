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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import org.conscrypt.TestUtils;
import org.conscrypt.java.security.StandardNames;
import org.conscrypt.java.security.TestKeyStore;
import org.conscrypt.tlswire.TlsTester;
import org.conscrypt.tlswire.handshake.CipherSuite;
import org.conscrypt.tlswire.handshake.ClientHello;
import org.conscrypt.tlswire.handshake.CompressionMethod;
import org.conscrypt.tlswire.handshake.EllipticCurve;
import org.conscrypt.tlswire.handshake.EllipticCurvesHelloExtension;
import org.conscrypt.tlswire.handshake.HelloExtension;
import org.conscrypt.tlswire.util.TlsProtocolVersion;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.net.DelegatingSSLSocketFactory;
import tests.util.ForEachRunner;
import tests.util.Pair;

@RunWith(JUnit4.class)
public class SSLSocketTest {
    private final ThreadGroup threadGroup = new ThreadGroup("SSLSocketTest");
    private final ExecutorService executor =
        Executors.newCachedThreadPool(t -> new Thread(threadGroup, t));

    @After
    public void teardown() throws InterruptedException {
        executor.shutdownNow();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }

    @Test
    public void test_SSLSocket_defaultConfiguration() throws Exception {
        SSLConfigurationAsserts.assertSSLSocketDefaultConfiguration(
                (SSLSocket) SSLSocketFactory.getDefault().createSocket());
    }

    @Test
    public void test_SSLSocket_getSupportedCipherSuites_returnsCopies() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket ssl = (SSLSocket) sf.createSocket()) {
            assertNotSame(ssl.getSupportedCipherSuites(), ssl.getSupportedCipherSuites());
        }
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
            TestKeyStore testKeyStore, StringBuilder error) {
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
                                   .clientProtocol("TLSv1.2")
                                   .serverProtocol("TLSv1.2")
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
                 * This test uses TLS 1.2, and the TLS 1.3 cipher suites aren't customizable
                 * anyway.
                 */
                if (StandardNames.CIPHER_SUITES_TLS13.contains(cipherSuite)) {
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
                assertThrows(IOException.class, () -> server.getInputStream().read());
                client.setSoTimeout(10);
                assertThrows(IOException.class, () -> client.getInputStream().read());
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
    public void test_SSLSocket_getInputStream_available() throws Exception {
        TestSSLSocketPair pair = TestSSLSocketPair.create().connect();

        pair.client.getOutputStream().write(new byte[] { 1, 2, 3, 4 });
        // We read a single byte first because it's okay if available() returns zero
        // before we've checked the network to see if any packets are available to
        // be decrypted, but we should show available bytes once we've decrypted a packet
        assertEquals(1, pair.server.getInputStream().read());
        assertTrue(pair.server.getInputStream().available() > 0);
        assertEquals(3, pair.server.getInputStream().read(new byte[4]));
        assertEquals(0, pair.server.getInputStream().available());

        pair.server.getOutputStream().write(new byte[] { 1, 2, 3, 4 });
        // We read a single byte first because it's okay if available() returns zero
        // before we've checked the network to see if any packets are available to
        // be decrypted, but we should show available bytes once we've decrypted a packet
        assertEquals(1, pair.client.getInputStream().read());
        assertTrue(pair.client.getInputStream().available() > 0);
        assertEquals(3, pair.client.getInputStream().read(new byte[4]));
        assertEquals(0, pair.client.getInputStream().available());
    }

    @Test
    public void test_SSLSocket_InputStream_read() throws Exception {
        // Regression test for https://github.com/google/conscrypt/issues/738
        // Ensure values returned from InputStream.read() are unsigned.
        TestSSLSocketPair pair = TestSSLSocketPair.create().connect();

        for (int i = 0; i < 256; i++) {
            pair.client.getOutputStream().write(i);
            assertEquals(i, pair.server.getInputStream().read());
        }
    }

    @Test
    public void test_SSLSocket_getEnabledCipherSuites_returnsCopies() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket ssl = (SSLSocket) sf.createSocket()) {
            assertNotSame(ssl.getEnabledCipherSuites(), ssl.getEnabledCipherSuites());
        }
    }

    @Test
    public void test_SSLSocket_setEnabledCipherSuites_storesCopy() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket ssl = (SSLSocket) sf.createSocket()) {
            String[] array = new String[]{ssl.getEnabledCipherSuites()[0]};
            String originalFirstElement = array[0];
            ssl.setEnabledCipherSuites(array);
            array[0] = "Modified after having been set";
            assertEquals(originalFirstElement, ssl.getEnabledCipherSuites()[0]);
        }
    }

    @Test
    public void test_SSLSocket_setEnabledCipherSuites_TLS12() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(null, null, null);
        try (SSLSocket ssl = (SSLSocket) context.getSocketFactory().createSocket()) {
            assertThrows(IllegalArgumentException.class,
                () -> ssl.setEnabledCipherSuites(null));
            assertThrows(IllegalArgumentException.class,
                () -> ssl.setEnabledCipherSuites(new String[1]));
            assertThrows(IllegalArgumentException.class,
                () -> ssl.setEnabledCipherSuites(new String[]{"Bogus"}));
            ssl.setEnabledCipherSuites(new String[0]);
            ssl.setEnabledCipherSuites(ssl.getEnabledCipherSuites());
            ssl.setEnabledCipherSuites(ssl.getSupportedCipherSuites());
            // Check that setEnabledCipherSuites affects getEnabledCipherSuites
            String[] cipherSuites = new String[]{
                    TestUtils.pickArbitraryNonTls13Suite(ssl.getSupportedCipherSuites())
            };
            ssl.setEnabledCipherSuites(cipherSuites);
            assertEquals(Arrays.asList(cipherSuites), Arrays.asList(ssl.getEnabledCipherSuites()));
        }
    }

    @Test
    public void test_SSLSocket_setEnabledCipherSuites_TLS13() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(null, null, null);
        SSLSocketFactory sf = context.getSocketFactory();
        try (SSLSocket ssl = (SSLSocket) sf.createSocket()) {
            // The TLS 1.3 cipher suites should be enabled by default
            assertTrue(new HashSet<>(Arrays.asList(ssl.getEnabledCipherSuites()))
                    .containsAll(StandardNames.CIPHER_SUITES_TLS13));
            // Disabling them should be ignored
            ssl.setEnabledCipherSuites(new String[0]);
            assertTrue(new HashSet<>(Arrays.asList(ssl.getEnabledCipherSuites()))
                    .containsAll(StandardNames.CIPHER_SUITES_TLS13));

            ssl.setEnabledCipherSuites(new String[]{
                    TestUtils.pickArbitraryNonTls13Suite(ssl.getSupportedCipherSuites())
            });
            assertTrue(new HashSet<>(Arrays.asList(ssl.getEnabledCipherSuites()))
                    .containsAll(StandardNames.CIPHER_SUITES_TLS13));

            // Disabling TLS 1.3 should disable 1.3 cipher suites
            ssl.setEnabledProtocols(new String[]{"TLSv1.2"});
            assertFalse(new HashSet<>(Arrays.asList(ssl.getEnabledCipherSuites()))
                    .containsAll(StandardNames.CIPHER_SUITES_TLS13));
        }
    }

    @Test
    public void test_SSLSocket_getSupportedProtocols_returnsCopies() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket ssl = (SSLSocket) sf.createSocket()) {
            assertNotSame(ssl.getSupportedProtocols(), ssl.getSupportedProtocols());
        }
    }

    @Test
    public void test_SSLSocket_getEnabledProtocols_returnsCopies() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket ssl = (SSLSocket) sf.createSocket()) {
            assertNotSame(ssl.getEnabledProtocols(), ssl.getEnabledProtocols());
        }
    }

    @Test
    public void test_SSLSocket_setEnabledProtocols_storesCopy() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket ssl = (SSLSocket) sf.createSocket()) {
            String[] array = new String[]{ssl.getEnabledProtocols()[0]};
            String originalFirstElement = array[0];
            ssl.setEnabledProtocols(array);
            array[0] = "Modified after having been set";
            assertEquals(originalFirstElement, ssl.getEnabledProtocols()[0]);
        }
    }

    @Test
    public void test_SSLSocket_setEnabledProtocols() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket ssl = (SSLSocket) sf.createSocket()) {
            assertThrows(IllegalArgumentException.class,
                () -> ssl.setEnabledProtocols(null));
            assertThrows(IllegalArgumentException.class,
                () -> ssl.setEnabledProtocols(new String[1]));
            assertThrows(IllegalArgumentException.class,
                () -> ssl.setEnabledProtocols(new String[]{"Bogus"}));
            ssl.setEnabledProtocols(new String[0]);
            ssl.setEnabledProtocols(ssl.getEnabledProtocols());
            ssl.setEnabledProtocols(ssl.getSupportedProtocols());
            // Check that setEnabledProtocols affects getEnabledProtocols
            for (String protocol : ssl.getSupportedProtocols()) {
                if ("SSLv2Hello".equals(protocol)) {
                    // Should fail when SSLv2Hello is set by itself
                    assertThrows(IllegalArgumentException.class,
                        () -> ssl.setEnabledProtocols(new String[]{protocol}));
                } else {
                    String[] protocols = new String[]{protocol};
                    ssl.setEnabledProtocols(protocols);
                    assertEquals(Arrays.deepToString(protocols),
                            Arrays.deepToString(ssl.getEnabledProtocols()));
                }
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
        SSLContext clientContext = c.clientContext;
        // Can't test fallback without at least 3 protocol versions enabled.
        TestUtils.assumeTlsV11Enabled(clientContext);
        SSLSocket client = (SSLSocket)
                clientContext.getSocketFactory().createSocket(c.host, c.port);
        client.setEnabledProtocols(new String[] {"TLSv1.3", "TLSv1.1"});
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        server.setEnabledProtocols(new String[] {"TLSv1.3", "TLSv1.2", "TLSv1.1"});
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Void> future = executor.submit(() -> {
            server.startHandshake();
            return null;
        });
        executor.shutdown();
        client.startHandshake();

        assertEquals("TLSv1.1", client.getSession().getProtocol());

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
        SSLContext clientContext = c.clientContext;
        // Can't test fallback without at least 3 protocol versions enabled.
        TestUtils.assumeTlsV11Enabled(clientContext);
        SSLSocket client = (SSLSocket)
                clientContext.getSocketFactory().createSocket(c.host, c.port);
        client.setEnabledProtocols(new String[] {"TLSv1.3", "TLSv1.1"});
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        server.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.1"});
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Void> future = executor.submit(() -> {
            server.startHandshake();
            return null;
        });
        executor.shutdown();
        client.startHandshake();

        assertEquals("TLSv1.1", client.getSession().getProtocol());

        future.get();
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_getSession() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket ssl = (SSLSocket) sf.createSocket()) {
            SSLSession session = ssl.getSession();
            assertNotNull(session);
            assertFalse(session.isValid());
        }
    }

    @Test
    public void test_SSLSocket_getHandshakeSession_unconnected() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket socket = (SSLSocket) sf.createSocket()) {
            SSLSession session = socket.getHandshakeSession();
            assertNull(session);
        }
    }

    @Test
    public void test_SSLSocket_getHandshakeSession_duringHandshake_client() throws Exception {
        // We can't reference the actual context we're using, since we need to pass
        // the test trust manager in to construct it, so create reference objects that
        // we can test against.
        final TestSSLContext referenceContext = TestSSLContext.create();
        final SSLSocket referenceClientSocket =
            (SSLSocket) referenceContext.clientContext.getSocketFactory().createSocket();

        final AtomicInteger checkServerTrustedWasCalled = new AtomicInteger(0);
        TestSSLContext c = TestSSLContext.newBuilder()
            .clientTrustManager(new X509ExtendedTrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s,
                    Socket socket) throws CertificateException {
                    throw new CertificateException("Shouldn't be called");
                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s,
                    Socket socket) throws CertificateException {
                    try {
                        SSLSocket sslSocket = (SSLSocket) socket;
                        SSLSession session = sslSocket.getHandshakeSession();
                        assertNotNull(session);
                        // By the point of the handshake where we're validating certificates,
                        // the hostname is known and the cipher suite should be agreed
                        assertEquals(referenceContext.host.getHostName(), session.getPeerHost());

                        // The negotiated cipher suite should be one of the enabled ones, but
                        // BoringSSL may have reordered them based on things like hardware support,
                        // so we don't know which one may have been negotiated.
                        String sessionSuite = session.getCipherSuite();
                        List<String> enabledSuites =
                            Arrays.asList(referenceClientSocket.getEnabledCipherSuites());
                        String message = "Handshake session has invalid cipher suite: "
                                + (sessionSuite == null ? "(null)" : sessionSuite);
                        assertTrue(message, enabledSuites.contains(sessionSuite));

                        checkServerTrustedWasCalled.incrementAndGet();
                    } catch (Exception e) {
                        throw new CertificateException("Something broke", e);
                    }
                }

                @Override
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s,
                    SSLEngine sslEngine) throws CertificateException {
                    throw new CertificateException("Shouldn't be called");
                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s,
                    SSLEngine sslEngine) throws CertificateException {
                    throw new CertificateException("Shouldn't be called");
                }

                @Override
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
                    throws CertificateException {
                    throw new CertificateException("Shouldn't be called");
                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
                    throws CertificateException {
                    throw new CertificateException("Shouldn't be called");
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }).build();
        SSLContext clientContext = c.clientContext;
        SSLSocket client = (SSLSocket)
            clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Void> future = executor.submit(() -> {
            server.startHandshake();
            return null;
        });
        executor.shutdown();
        client.startHandshake();

        future.get();
        client.close();
        server.close();
        c.close();
        assertEquals(1, checkServerTrustedWasCalled.get());
    }

    @Test
    public void test_SSLSocket_getHandshakeSession_duringHandshake_server() throws Exception {
        // We can't reference the actual context we're using, since we need to pass
        // the test trust manager in to construct it, so create reference objects that
        // we can test against.
        final TestSSLContext referenceContext = TestSSLContext.create();
        final SSLSocket referenceClientSocket =
            (SSLSocket) referenceContext.clientContext.getSocketFactory().createSocket();

        final AtomicInteger checkClientTrustedWasCalled = new AtomicInteger(0);
        TestSSLContext c = TestSSLContext.newBuilder()
            .client(TestKeyStore.getClientCertificate())
            .serverTrustManager(new X509ExtendedTrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s,
                    Socket socket) throws CertificateException {
                    try {
                        SSLSocket sslSocket = (SSLSocket) socket;
                        SSLSession session = sslSocket.getHandshakeSession();
                        assertNotNull(session);
                        // By the point of the handshake where we're validating client certificates,
                        // the cipher suite should be agreed and the server's own certificates
                        // should have been delivered

                        // The negotiated cipher suite should be one of the enabled ones, but
                        // BoringSSL may have reordered them based on things like hardware support,
                        // so we don't know which one may have been negotiated.
                        String sessionSuite = session.getCipherSuite();
                        List<String> enabledSuites =
                                Arrays.asList(referenceClientSocket.getEnabledCipherSuites());
                        String message = "Handshake session has invalid cipher suite: "
                                + (sessionSuite == null ? "(null)" : sessionSuite);
                        assertTrue(message, enabledSuites.contains(sessionSuite));

                        assertNotNull(session.getLocalCertificates());
                        assertEquals("CN=localhost",
                            ((X509Certificate) session.getLocalCertificates()[0])
                                .getSubjectDN().getName());
                        assertEquals("CN=Test Intermediate Certificate Authority",
                            ((X509Certificate) session.getLocalCertificates()[0])
                                .getIssuerDN().getName());
                        checkClientTrustedWasCalled.incrementAndGet();
                    } catch (Exception e) {
                        throw new CertificateException("Something broke", e);
                    }
                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s,
                    Socket socket) throws CertificateException {
                    throw new CertificateException("Shouldn't be called");
                }

                @Override
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s,
                    SSLEngine sslEngine) throws CertificateException {
                    throw new CertificateException("Shouldn't be called");
                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s,
                    SSLEngine sslEngine) throws CertificateException {
                    throw new CertificateException("Shouldn't be called");
                }

                @Override
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
                    throws CertificateException {
                    throw new CertificateException("Shouldn't be called");
                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
                    throws CertificateException {
                    throw new CertificateException("Shouldn't be called");
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return referenceContext.serverTrustManager.getAcceptedIssuers();
                }
            }).build();
        SSLContext clientContext = c.clientContext;
        SSLSocket client = (SSLSocket)
            clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Void> future = executor.submit(() -> {
            server.setNeedClientAuth(true);
            server.startHandshake();
            return null;
        });
        executor.shutdown();
        client.startHandshake();

        future.get();
        client.close();
        server.close();
        c.close();
        assertEquals(1, checkClientTrustedWasCalled.get());
    }

    @Test
    public void test_SSLSocket_setUseClientMode_afterHandshake() {
        // can't set after handshake
        TestSSLSocketPair pair = TestSSLSocketPair.create().connect();
        assertThrows(IllegalArgumentException.class, () -> pair.server.setUseClientMode(true));
        assertThrows(IllegalArgumentException.class, () -> pair.client.setUseClientMode(false));
    }

    @Test
    public void test_SSLSocket_untrustedServer() throws Exception {
        TestSSLContext c =
                TestSSLContext.create(TestKeyStore.getClientCA2(), TestKeyStore.getServer());
        SSLSocket client =
                (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
        Future<Void> future = runAsync(() -> {
            assertThrows(SSLHandshakeException.class, server::startHandshake);
            return null;
        });
        SSLHandshakeException expected =
            assertThrows(SSLHandshakeException.class, client::startHandshake);
        assertTrue(expected.getCause() instanceof CertificateException);

        future.get();
        client.close();
        server.close();
        c.close();
    }

    @Test
    public void test_SSLSocket_getSSLParameters() throws Exception {
        TestUtils.assumeSetEndpointIdentificationAlgorithmAvailable();
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket ssl = (SSLSocket) sf.createSocket()) {
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
    }

    @Test
    public void test_SSLSocket_setSSLParameters() throws Exception {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket ssl = (SSLSocket) sf.createSocket()) {
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
    }

    @Test
    public void test_SSLSocket_setSoTimeout_basic() throws Exception {
        try (ServerSocket listening = new ServerSocket(0)) {
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
        assertThrows(SocketTimeoutException.class, () -> clientWrapping.getInputStream().read());
        clientWrapping.close();
        server.close();
        underlying.close();
        listening.close();
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
    public void test_SSLSocket_ClientHello_cipherSuites() throws Exception {
        ForEachRunner.runNamed(sslSocketFactory -> {
            ClientHello clientHello = TlsTester
                    .captureTlsHandshakeClientHello(executor, sslSocketFactory);
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
        },
            getSSLSocketFactoriesToTest());
    }

    @Test
    public void test_SSLSocket_ClientHello_supportedCurves() throws Exception {
        ForEachRunner.runNamed(sslSocketFactory -> {
            ClientHello clientHello = TlsTester
                    .captureTlsHandshakeClientHello(executor, sslSocketFactory);
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
        },
            getSSLSocketFactoriesToTest());
    }

    @Test
    public void test_SSLSocket_ClientHello_clientProtocolVersion() throws Exception {
        ForEachRunner.runNamed(sslSocketFactory -> {
            ClientHello clientHello = TlsTester
                    .captureTlsHandshakeClientHello(executor, sslSocketFactory);
            assertEquals(TlsProtocolVersion.TLSv1_2, clientHello.clientVersion);
        },
            getSSLSocketFactoriesToTest());
    }

    @Test
    public void test_SSLSocket_ClientHello_compressionMethods() throws Exception {
        ForEachRunner.runNamed(sslSocketFactory -> {
            ClientHello clientHello = TlsTester
                    .captureTlsHandshakeClientHello(executor, sslSocketFactory);
            assertEquals(Collections.singletonList(CompressionMethod.NULL),
                clientHello.compressionMethods);
        },
            getSSLSocketFactoriesToTest());
    }

    private List<Pair<String, SSLSocketFactory>> getSSLSocketFactoriesToTest()
            throws NoSuchAlgorithmException, KeyManagementException {
        List<Pair<String, SSLSocketFactory>> result = new ArrayList<>();
        result.add(Pair.of("default", (SSLSocketFactory) SSLSocketFactory.getDefault()));
        for (String sslContextProtocol : StandardNames.SSL_CONTEXT_PROTOCOLS_WITH_DEFAULT_CONFIG) {
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
        Future<Void> s = runAsync(() -> {
            server.setEnabledProtocols(new String[]{"TLSv1.2"});
            server.setEnabledCipherSuites(serverCipherSuites);
            server.startHandshake();
            return null;
        });
        Future<Void> c = runAsync(() -> {
            client.setEnabledProtocols(new String[]{"TLSv1.2"});
            client.setEnabledCipherSuites(clientCipherSuites);
            client.startHandshake();
            return null;
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
        // TLS_FALLBACK_SCSV is only applicable to TLS <= 1.2
        TestUtils.assumeTlsV11Enabled(context.clientContext);
        final SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                context.host, context.port);
        final SSLSocket server = (SSLSocket) context.serverSocket.accept();
        // Confirm absence of TLS_FALLBACK_SCSV.
        assertFalse(Arrays.asList(client.getEnabledCipherSuites())
                            .contains(StandardNames.CIPHER_SUITE_FALLBACK));
        Future<Void> s = runAsync(() -> {
            server.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.1"});
            server.startHandshake();
            return null;
        });
        Future<Void> c = runAsync(() -> {
            client.setEnabledProtocols(new String[]{"TLSv1.1"});
            client.startHandshake();
            return null;
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
        // TLS_FALLBACK_SCSV is only applicable to TLS <= 1.2
        TestUtils.assumeTlsV11Enabled(context.clientContext);
        final SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                context.host, context.port);
        final SSLSocket server = (SSLSocket) context.serverSocket.accept();
        final String[] serverCipherSuites = server.getEnabledCipherSuites();
        // Add TLS_FALLBACK_SCSV
        final String[] clientCipherSuites = new String[serverCipherSuites.length + 1];
        System.arraycopy(serverCipherSuites, 0, clientCipherSuites, 0, serverCipherSuites.length);
        clientCipherSuites[serverCipherSuites.length] = StandardNames.CIPHER_SUITE_FALLBACK;
        Future<Void> s = runAsync(() -> {
            server.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.1"});
            server.setEnabledCipherSuites(serverCipherSuites);
            SSLHandshakeException expected =
                assertThrows(SSLHandshakeException.class, server::startHandshake);
            Throwable cause = expected.getCause();
            assertEquals(SSLProtocolException.class, cause.getClass());
            assertInappropriateFallbackIsCause(cause);
            return null;
        });
        Future<Void> c = runAsync(() -> {
            client.setEnabledProtocols(new String[]{"TLSv1.1"});
            client.setEnabledCipherSuites(clientCipherSuites);
            SSLHandshakeException expected =
                assertThrows(SSLHandshakeException.class, client::startHandshake);
            Throwable cause = expected.getCause();
            assertEquals(SSLProtocolException.class, cause.getClass());
            assertInappropriateFallbackIsCause(cause);
            return null;
        });
        s.get();
        c.get();
        client.close();
        server.close();
        context.close();
    }

    @Test
    public void test_SSLSocket_tlsFallback_byVersion() throws Exception {
        String[] supportedProtocols =
                SSLContext.getDefault().getDefaultSSLParameters().getProtocols();
        for (final String protocol : supportedProtocols) {
            SSLSocketFactory factory = new DelegatingSSLSocketFactory(
                    (SSLSocketFactory) SSLSocketFactory.getDefault()) {
                @Override protected SSLSocket configureSocket(SSLSocket socket) {
                    socket.setEnabledProtocols(new String[] {protocol});
                    String[] enabled = socket.getEnabledCipherSuites();
                    String[] cipherSuites = new String[socket.getEnabledCipherSuites().length + 1];
                    System.arraycopy(enabled, 0, cipherSuites, 0, enabled.length);
                    cipherSuites[cipherSuites.length - 1] = StandardNames.CIPHER_SUITE_FALLBACK;
                    socket.setEnabledCipherSuites(cipherSuites);
                    return socket;
                }
            };
            ClientHello clientHello = TlsTester.captureTlsHandshakeClientHello(executor, factory);
            if (protocol.equals("TLSv1.2") || protocol.equals("TLSv1.3")) {
                assertFalse(clientHello.cipherSuites.contains(CipherSuite.valueOf("TLS_FALLBACK_SCSV")));
            } else {
                assertTrue(clientHello.cipherSuites.contains(CipherSuite.valueOf("TLS_FALLBACK_SCSV")));
            }
        }
    }

    @Test
    public void handshakeListenersRunExactlyOnce() {
        AtomicInteger count = new AtomicInteger(0);
        TestSSLSocketPair pair = TestSSLSocketPair.create();
        pair.client.addHandshakeCompletedListener(event -> count.addAndGet(1));
        pair.client.addHandshakeCompletedListener(event -> count.addAndGet(2));
        pair.client.addHandshakeCompletedListener(event -> count.addAndGet(4));
        pair.connect();
        assertEquals(1 + 2 + 4, count.get());
    }

    @Test
    public void closeFromHandshakeListener() throws Exception {
        TestUtils.assumeEngineSocket();

        TestSSLSocketPair pair = TestSSLSocketPair.create();
        pair.client.addHandshakeCompletedListener(event -> socketClose(pair.client));
        Future<Void> serverFuture = runAsync((Callable<Void>) () -> {
            pair.server.startHandshake();
            return null;
        });
        pair.client.startHandshake();
        assertThrows(SocketException.class, pair.client::getInputStream);
        serverFuture.get();
        InputStream istream = pair.server.getInputStream();
        assertEquals(-1, istream.read());
    }

    @Test
    public void writeFromHandshakeListener() throws Exception {
        TestUtils.assumeEngineSocket();

        byte[] ping = "ping".getBytes(UTF_8);
        byte[] pong = "pong".getBytes(UTF_8);
        TestSSLSocketPair pair = TestSSLSocketPair.create();
        pair.client.addHandshakeCompletedListener(event -> socketWrite(pair.client, ping));
        pair.server.addHandshakeCompletedListener(event -> socketWrite(pair.server, pong));
        Future<Void> serverFuture = runAsync(() -> {
            pair.server.startHandshake();
            return null;
        });
        byte[] buffer = new byte[4];
        InputStream clientStream = pair.client.getInputStream();
        assertEquals(4, clientStream.read(buffer));
        assertArrayEquals(pong, buffer);

        serverFuture.get();
        InputStream serverStream = pair.server.getInputStream();
        assertEquals(4, serverStream.read(buffer));
        assertArrayEquals(ping, buffer);
    }

    private void socketClose(Socket socket) {
        try {
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void socketWrite(Socket socket, byte[] data) {
        try {
            socket.getOutputStream().write(data);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
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
}
