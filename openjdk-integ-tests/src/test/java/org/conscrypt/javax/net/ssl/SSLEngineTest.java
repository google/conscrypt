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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;
import libcore.java.security.StandardNames;
import org.conscrypt.Conscrypt;
import org.conscrypt.TestUtils;
import org.conscrypt.java.security.TestKeyStore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SSLEngineTest {
    @Test
    public void test_SSLEngine_defaultConfiguration() throws Exception {
        SSLConfigurationAsserts.assertSSLEngineDefaultConfiguration(
                TestSSLContext.create().clientContext.createSSLEngine());
    }

    @Test
    public void test_SSLEngine_getSupportedCipherSuites_returnsCopies() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();
        assertNotSame(e.getSupportedCipherSuites(), e.getSupportedCipherSuites());
        c.close();
    }

    @Test
    public void test_SSLEngine_getSupportedCipherSuites_connect() throws Exception {
        // note the rare usage of non-RSA keys
        TestKeyStore testKeyStore = new TestKeyStore.Builder()
                                            .keyAlgorithms("RSA", "DSA", "EC", "EC_RSA")
                                            .aliasPrefix("rsa-dsa-ec")
                                            .ca(true)
                                            .build();
        test_SSLEngine_getSupportedCipherSuites_connect(testKeyStore, false);
        test_SSLEngine_getSupportedCipherSuites_connect(testKeyStore, true);
    }

    // http://b/18554122
    @Test
    public void test_SSLEngine_underflowsOnEmptyBuffersDuringHandshake() throws Exception {
        final SSLEngine sslEngine = SSLContext.getDefault().createSSLEngine();
        sslEngine.setUseClientMode(false);
        ByteBuffer input = ByteBuffer.allocate(1024);
        input.flip();
        ByteBuffer output = ByteBuffer.allocate(1024);
        sslEngine.beginHandshake();
        assertEquals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, sslEngine.getHandshakeStatus());
        SSLEngineResult result = sslEngine.unwrap(input, output);
        assertEquals(SSLEngineResult.Status.BUFFER_UNDERFLOW, result.getStatus());
        assertEquals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());
    }

    // http://b/18554122
    @Test
    public void test_SSLEngine_underflowsOnEmptyBuffersAfterHandshake() throws Exception {
        // Note that create performs the handshake.
        final TestSSLEnginePair engines = TestSSLEnginePair.create(null /* hooks */);
        ByteBuffer input = ByteBuffer.allocate(1024);
        input.flip();
        ByteBuffer output = ByteBuffer.allocate(1024);
        assertEquals(SSLEngineResult.Status.BUFFER_UNDERFLOW,
                engines.client.unwrap(input, output).getStatus());
    }

    private void test_SSLEngine_getSupportedCipherSuites_connect(
            TestKeyStore testKeyStore, boolean secureRenegotiation) throws Exception {
        KeyManager pskKeyManager =
                PSKKeyManagerProxy.getConscryptPSKKeyManager(new PSKKeyManagerProxy() {
                    @Override
                    protected SecretKey getKey(
                            String identityHint, String identity, SSLEngine engine) {
                        return new SecretKeySpec("Just an arbitrary key".getBytes(UTF_8), "RAW");
                    }
                });
        TestSSLContext c = TestSSLContext.newBuilder()
                                   .client(testKeyStore)
                                   .server(testKeyStore)
                                   .additionalClientKeyManagers(new KeyManager[] {pskKeyManager})
                                   .additionalServerKeyManagers(new KeyManager[] {pskKeyManager})
                                   .build();

        // Create a TestSSLContext where the KeyManager returns wrong (randomly generated) private
        // keys, matching the algorithm and parameters of the correct keys.
        // I couldn't find a more elegant way to achieve this other than temporarily replacing the
        // first X509ExtendedKeyManager element of TestKeyStore.keyManagers while invoking
        // TestSSLContext.create.
        TestSSLContext cWithWrongPrivateKeys;
        {
            // Create a RandomPrivateKeyX509ExtendedKeyManager based on the first
            // X509ExtendedKeyManager in c.serverKeyManagers.
            KeyManager randomPrivateKeyX509ExtendedKeyManager = null;
            for (KeyManager keyManager : c.serverKeyManagers) {
                if (keyManager instanceof X509ExtendedKeyManager) {
                    randomPrivateKeyX509ExtendedKeyManager =
                            new RandomPrivateKeyX509ExtendedKeyManager(
                                    (X509ExtendedKeyManager) keyManager);
                    break;
                }
            }
            if (randomPrivateKeyX509ExtendedKeyManager == null) {
                fail("No X509ExtendedKeyManager in c.serverKeyManagers");
            }

            // Find the first X509ExtendedKeyManager in testKeyStore.keyManagers
            int replaceIndex = -1;
            for (int i = 0; i < testKeyStore.keyManagers.length; i++) {
                KeyManager keyManager = testKeyStore.keyManagers[i];
                if (keyManager instanceof X509ExtendedKeyManager) {
                    replaceIndex = i;
                    break;
                }
            }
            if (replaceIndex == -1) {
                fail("No X509ExtendedKeyManager in testKeyStore.keyManagers");
            }

            // Temporarily substitute the RandomPrivateKeyX509ExtendedKeyManager in place of the
            // original X509ExtendedKeyManager.
            KeyManager originalKeyManager = testKeyStore.keyManagers[replaceIndex];
            testKeyStore.keyManagers[replaceIndex] = randomPrivateKeyX509ExtendedKeyManager;
            cWithWrongPrivateKeys = TestSSLContext.create(testKeyStore, testKeyStore);
            testKeyStore.keyManagers[replaceIndex] = originalKeyManager;
        }

        // To catch all the errors.
        StringBuilder error = new StringBuilder();

        String[] cipherSuites = c.clientContext.createSSLEngine().getSupportedCipherSuites();
        for (String cipherSuite : cipherSuites) {
            try {
                // Skip cipher suites that are obsoleted.
                if (StandardNames.IS_RI && "TLSv1.2".equals(c.clientContext.getProtocol())
                        && StandardNames.CIPHER_SUITES_OBSOLETE_TLS12.contains(cipherSuite)) {
                    continue;
                }
                /*
                 * Signaling Cipher Suite Values (SCSV) cannot be used on their own, but instead in
                 * conjunction with other cipher suites.
                 */
                if (cipherSuite.equals(StandardNames.CIPHER_SUITE_SECURE_RENEGOTIATION)
                        || cipherSuite.equals(StandardNames.CIPHER_SUITE_FALLBACK)) {
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

                final String[] cipherSuiteArray = (secureRenegotiation
                                ? new String[] {cipherSuite,
                                          StandardNames.CIPHER_SUITE_SECURE_RENEGOTIATION}
                                : new String[] {cipherSuite});

                // Check that handshake succeeds.
                TestSSLEnginePair pair = null;
                try {
                    pair = TestSSLEnginePair.create(c, new TestSSLEnginePair.Hooks() {
                        @Override
                        void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                            client.setEnabledCipherSuites(cipherSuiteArray);
                            server.setEnabledCipherSuites(cipherSuiteArray);
                        }
                    });
                    assertConnected(pair);

                    boolean needsRecordSplit = "TLS".equalsIgnoreCase(c.clientContext.getProtocol())
                            && cipherSuite.contains("_CBC_");

                    assertSendsCorrectly("This is the client. Hello!".getBytes(UTF_8), pair.client,
                            pair.server, needsRecordSplit);
                    assertSendsCorrectly("This is the server. Hi!".getBytes(UTF_8), pair.server,
                            pair.client, needsRecordSplit);
                } finally {
                    if (pair != null) {
                        pair.close();
                    }
                }

                // Check that handshake fails when the server does not possess the private key
                // corresponding to the server's certificate. This is achieved by using SSLContext
                // cWithWrongPrivateKeys whose KeyManager returns wrong private keys that match
                // the algorithm (and parameters) of the correct keys.
                boolean serverAuthenticatedUsingPublicKey = true;
                if (cipherSuite.contains("_anon_")) {
                    serverAuthenticatedUsingPublicKey = false;
                } else if ((cipherSuite.startsWith("TLS_PSK_"))
                        || (cipherSuite.startsWith("TLS_ECDHE_PSK_"))) {
                    serverAuthenticatedUsingPublicKey = false;
                }
                if (serverAuthenticatedUsingPublicKey) {
                    TestSSLEnginePair p = null;
                    try {
                        p = TestSSLEnginePair.create(
                                cWithWrongPrivateKeys, new TestSSLEnginePair.Hooks() {
                                    @Override
                                    void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                                        client.setEnabledCipherSuites(cipherSuiteArray);
                                        server.setEnabledCipherSuites(cipherSuiteArray);
                                    }
                                });
                        assertNotConnected(p);
                    } catch (IOException expected) {
                        // Ignored.
                    } finally {
                        if (p != null) {
                            p.close();
                        }
                    }
                }
            } catch (Exception e) {
                String message = ("Problem trying to connect cipher suite " + cipherSuite);
                System.out.println(message);
                e.printStackTrace();
                error.append(message);
                error.append('\n');
            }
        }
        c.close();

        if (error.length() > 0) {
            throw new Exception("One or more problems in "
                    + "test_SSLEngine_getSupportedCipherSuites_connect:\n" + error);
        }
    }

    private static void assertSendsCorrectly(final byte[] sourceBytes, SSLEngine source,
            SSLEngine dest, boolean needsRecordSplit) throws SSLException {
        ByteBuffer sourceOut = ByteBuffer.wrap(sourceBytes);
        SSLSession sourceSession = source.getSession();
        ByteBuffer sourceToDest = ByteBuffer.allocate(sourceSession.getPacketBufferSize());
        SSLEngineResult sourceOutRes = source.wrap(sourceOut, sourceToDest);
        sourceToDest.flip();

        String sourceCipherSuite = source.getSession().getCipherSuite();
        assertEquals(sourceCipherSuite, sourceBytes.length, sourceOutRes.bytesConsumed());
        assertEquals(sourceCipherSuite, HandshakeStatus.NOT_HANDSHAKING,
                sourceOutRes.getHandshakeStatus());

        SSLSession destSession = dest.getSession();
        ByteBuffer destIn = ByteBuffer.allocate(destSession.getApplicationBufferSize());

        int numUnwrapCalls = 0;
        while (destIn.position() != sourceOut.limit()) {
            SSLEngineResult destRes = dest.unwrap(sourceToDest, destIn);
            assertEquals(sourceCipherSuite, HandshakeStatus.NOT_HANDSHAKING,
                    destRes.getHandshakeStatus());
            if (needsRecordSplit && numUnwrapCalls == 0) {
                assertEquals(sourceCipherSuite, 1, destRes.bytesProduced());
            }
            numUnwrapCalls++;
        }

        destIn.flip();
        byte[] actual = new byte[destIn.remaining()];
        destIn.get(actual);
        assertEquals(sourceCipherSuite, Arrays.toString(sourceBytes), Arrays.toString(actual));

        if (needsRecordSplit) {
            assertEquals(sourceCipherSuite, 2, numUnwrapCalls);
        } else {
            assertEquals(sourceCipherSuite, 1, numUnwrapCalls);
        }
    }

    @Test
    public void test_SSLEngine_getEnabledCipherSuites_returnsCopies() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();
        assertNotSame(e.getEnabledCipherSuites(), e.getEnabledCipherSuites());
        c.close();
    }

    @Test
    public void test_SSLEngine_setEnabledCipherSuites_storesCopy() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();
        String[] array = new String[] {e.getEnabledCipherSuites()[0]};
        String originalFirstElement = array[0];
        e.setEnabledCipherSuites(array);
        array[0] = "Modified after having been set";
        assertEquals(originalFirstElement, e.getEnabledCipherSuites()[0]);
    }

    @Test
    public void test_SSLEngine_setEnabledCipherSuites() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();

        try {
            e.setEnabledCipherSuites(null);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        try {
            e.setEnabledCipherSuites(new String[1]);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        try {
            e.setEnabledCipherSuites(new String[] {"Bogus"});
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }

        e.setEnabledCipherSuites(new String[0]);
        e.setEnabledCipherSuites(e.getEnabledCipherSuites());
        e.setEnabledCipherSuites(e.getSupportedCipherSuites());

        // Check that setEnabledCipherSuites affects getEnabledCipherSuites
        String[] cipherSuites = new String[] {e.getSupportedCipherSuites()[0]};
        e.setEnabledCipherSuites(cipherSuites);
        assertEquals(Arrays.asList(cipherSuites), Arrays.asList(e.getEnabledCipherSuites()));

        c.close();
    }

    @Test
    public void test_SSLEngine_getSupportedProtocols_returnsCopies() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();
        assertNotSame(e.getSupportedProtocols(), e.getSupportedProtocols());
        c.close();
    }

    @Test
    public void test_SSLEngine_getEnabledProtocols_returnsCopies() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();
        assertNotSame(e.getEnabledProtocols(), e.getEnabledProtocols());
        c.close();
    }

    @Test
    public void test_SSLEngine_setEnabledProtocols_storesCopy() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();
        String[] array = new String[] {e.getEnabledProtocols()[0]};
        String originalFirstElement = array[0];
        e.setEnabledProtocols(array);
        array[0] = "Modified after having been set";
        assertEquals(originalFirstElement, e.getEnabledProtocols()[0]);
    }

    @Test
    public void test_SSLEngine_setEnabledProtocols() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();

        try {
            e.setEnabledProtocols(null);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        try {
            e.setEnabledProtocols(new String[1]);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        try {
            e.setEnabledProtocols(new String[] {"Bogus"});
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        e.setEnabledProtocols(new String[0]);
        e.setEnabledProtocols(e.getEnabledProtocols());
        e.setEnabledProtocols(e.getSupportedProtocols());

        // Check that setEnabledProtocols affects getEnabledProtocols
        for (String protocol : e.getSupportedProtocols()) {
            if ("SSLv2Hello".equals(protocol)) {
                try {
                    e.setEnabledProtocols(new String[] {protocol});
                    fail("Should fail when SSLv2Hello is set by itself");
                } catch (IllegalArgumentException expected) {
                    // Ignored.
                }
            } else {
                String[] protocols = new String[] {protocol};
                e.setEnabledProtocols(protocols);
                assertEquals(Arrays.deepToString(protocols),
                        Arrays.deepToString(e.getEnabledProtocols()));
            }
        }

        c.close();
    }

    @Test
    public void test_SSLEngine_getSession() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();
        SSLSession session = e.getSession();
        assertNotNull(session);
        assertFalse(session.isValid());
        c.close();
    }

    @Test
    public void test_SSLEngine_beginHandshake() throws Exception {
        TestSSLContext c = TestSSLContext.create();

        try {
            c.clientContext.createSSLEngine().beginHandshake();
            fail();
        } catch (IllegalStateException expected) {
            // Ignored.
        }
        c.close();

        TestSSLEnginePair p = TestSSLEnginePair.create(null);
        assertConnected(p);
        p.close();
    }

    @Test
    public void test_SSLEngine_beginHandshake_noKeyStore() throws Exception {
        TestSSLContext c = TestSSLContext.newBuilder()
                                   .useDefaults(false)
                                   .clientContext(SSLContext.getDefault())
                                   .serverContext(SSLContext.getDefault())
                                   .build();
        SSLEngine[] p = null;
        try {
            // TODO Fix KnownFailure AlertException "NO SERVER CERTIFICATE FOUND"
            // ServerHandshakeImpl.selectSuite should not select a suite without a required cert
            p = TestSSLEnginePair.connect(c, null);
            fail();
        } catch (SSLHandshakeException expected) {
            // Ignored.
        } finally {
            if (p != null) {
                TestSSLEnginePair.close(p);
            }
        }
        c.close();
    }

    @Test
    public void test_SSLEngine_beginHandshake_noClientCertificate() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine[] engines = TestSSLEnginePair.connect(c, null);
        assertConnected(engines[0], engines[1]);
        c.close();
        TestSSLEnginePair.close(engines);
    }

    // http://b/37078438
    @Test
    public void test_SSLEngine_beginHandshake_redundantCalls() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine client = c.clientContext.createSSLEngine(c.host.getHostName(), c.port);
        client.setUseClientMode(true);
        client.beginHandshake();
        client.beginHandshake(); // This call should be ignored
        c.close();
    }

    @Test
    public void test_SSLEngine_getUseClientMode() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        assertFalse(c.clientContext.createSSLEngine().getUseClientMode());
        assertFalse(c.clientContext.createSSLEngine(null, -1).getUseClientMode());
        c.close();
    }

    @Test
    public void test_SSLEngine_setUseClientMode() throws Exception {
        boolean[] finished;
        TestSSLEnginePair p;

        // client is client, server is server
        finished = new boolean[2];
        p = test_SSLEngine_setUseClientMode(true, false, finished);
        assertConnected(p);
        assertTrue(finished[0]);
        assertTrue(finished[1]);
        p.close();

        // client is server, server is client
        finished = new boolean[2];
        p = test_SSLEngine_setUseClientMode(false, true, finished);
        assertConnected(p);
        assertTrue(finished[0]);
        assertTrue(finished[1]);
        p.close();

        // both are client
        /*
         * Our implementation throws an SSLHandshakeException, but RI just
         * stalls forever
         */
        p = null;
        try {
            p = test_SSLEngine_setUseClientMode(true, true, null);
            assertNotConnected(p);
        } catch (SSLHandshakeException maybeExpected) {
            // Ignored.
        } finally {
            if (p != null) {
                p.close();
            }
        }

        p = test_SSLEngine_setUseClientMode(false, false, null);
        // both are server
        assertNotConnected(p);
        p.close();
    }

    @Test
    public void test_SSLEngine_setUseClientMode_afterHandshake() throws Exception {
        // can't set after handshake
        TestSSLEnginePair pair = TestSSLEnginePair.create(null);
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
        pair.close();
    }

    private TestSSLEnginePair test_SSLEngine_setUseClientMode(final boolean clientClientMode,
            final boolean serverClientMode, final boolean[] finished) throws Exception {
        TestSSLContext c;
        if (!clientClientMode && serverClientMode) {
            c = TestSSLContext.create(TestKeyStore.getServer(), TestKeyStore.getClient());
        } else {
            c = TestSSLContext.create();
        }

        return TestSSLEnginePair.create(c, new TestSSLEnginePair.Hooks() {
            @Override
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                client.setUseClientMode(clientClientMode);
                server.setUseClientMode(serverClientMode);
            }
        }, finished);
    }

    @Test
    public void test_SSLEngine_clientAuth() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();

        assertFalse(e.getWantClientAuth());
        assertFalse(e.getNeedClientAuth());

        // confirm turning one on by itself
        e.setWantClientAuth(true);
        assertTrue(e.getWantClientAuth());
        assertFalse(e.getNeedClientAuth());

        // confirm turning setting on toggles the other
        e.setNeedClientAuth(true);
        assertFalse(e.getWantClientAuth());
        assertTrue(e.getNeedClientAuth());

        // confirm toggling back
        e.setWantClientAuth(true);
        assertTrue(e.getWantClientAuth());
        assertFalse(e.getNeedClientAuth());

        // TODO Fix KnownFailure "init - invalid private key"
        TestSSLContext clientAuthContext = TestSSLContext.create(
                TestKeyStore.getClientCertificate(), TestKeyStore.getServer());
        TestSSLEnginePair p =
                TestSSLEnginePair.create(clientAuthContext, new TestSSLEnginePair.Hooks() {
                    @Override
                    void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                        server.setWantClientAuth(true);
                    }
                });
        assertConnected(p);
        assertNotNull(p.client.getSession().getLocalCertificates());
        TestKeyStore.assertChainLength(p.client.getSession().getLocalCertificates());
        TestSSLContext.assertClientCertificateChain(
                clientAuthContext.clientTrustManager, p.client.getSession().getLocalCertificates());
        clientAuthContext.close();
        c.close();
        p.close();
    }

    /**
     * http://code.google.com/p/android/issues/detail?id=31903
     * This test case directly tests the fix for the issue.
     */
    @Test
    public void test_SSLEngine_clientAuthWantedNoClientCert() throws Exception {
        TestSSLContext clientAuthContext =
                TestSSLContext.create(TestKeyStore.getClient(), TestKeyStore.getServer());
        TestSSLEnginePair p =
                TestSSLEnginePair.create(clientAuthContext, new TestSSLEnginePair.Hooks() {
                    @Override
                    void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                        server.setWantClientAuth(true);
                    }
                });
        assertConnected(p);
        clientAuthContext.close();
        p.close();
    }

    /**
     * http://code.google.com/p/android/issues/detail?id=31903
     * This test case verifies that if the server requires a client cert
     * (setNeedClientAuth) but the client does not provide one SSL connection
     * establishment will fail
     */
    @Test
    public void test_SSLEngine_clientAuthNeededNoClientCert() throws Exception {
        TestSSLContext clientAuthContext =
                TestSSLContext.create(TestKeyStore.getClient(), TestKeyStore.getServer());
        TestSSLEnginePair p = null;
        try {
            p = TestSSLEnginePair.create(clientAuthContext, new TestSSLEnginePair.Hooks() {
                @Override
                void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                    server.setNeedClientAuth(true);
                }
            });
            fail();
        } catch (SSLHandshakeException expected) {
            // Ignored.
        } finally {
            clientAuthContext.close();
            if (p != null) {
                p.close();
            }
        }
    }

    @Test
    public void test_SSLEngine_endpointVerification_Success() throws Exception {
        TestUtils.assumeSetEndpointIdentificationAlgorithmAvailable();
        TestSSLContext c = TestSSLContext.create();
        TestSSLEnginePair p = TestSSLEnginePair.create(c, new TestSSLEnginePair.Hooks() {
            @Override
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                SSLParameters p = client.getSSLParameters();
                p.setEndpointIdentificationAlgorithm("HTTPS");
                client.setSSLParameters(p);
            }
        });
        assertConnected(p);
        c.close();
    }

    @Test
    public void test_SSLEngine_getEnableSessionCreation() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();
        assertTrue(e.getEnableSessionCreation());
        c.close();
        TestSSLEnginePair.close(new SSLEngine[] {e});
    }

    @Test
    public void test_SSLEngine_setEnableSessionCreation_server() throws Exception {
        TestSSLEnginePair p = null;
        try {
            p = TestSSLEnginePair.create(new TestSSLEnginePair.Hooks() {
                @Override
                void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                    server.setEnableSessionCreation(false);
                }
            });
            assertNotConnected(p);
        } catch (SSLException maybeExpected) {
            // Ignored.
        } finally {
            if (p != null) {
                p.close();
            }
        }
    }

    @Test
    public void test_SSLEngine_setEnableSessionCreation_client() throws Exception {
        TestSSLEnginePair p = null;
        try {
            p = TestSSLEnginePair.create(new TestSSLEnginePair.Hooks() {
                @Override
                void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                    client.setEnableSessionCreation(false);
                }
            });
            fail();
        } catch (SSLException expected) {
            // Ignored.
        } finally {
            if (p != null) {
                p.close();
            }
        }
    }

    @Test
    public void test_SSLEngine_getSSLParameters() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();

        SSLParameters p = e.getSSLParameters();
        assertNotNull(p);

        String[] cipherSuites = p.getCipherSuites();
        assertNotSame(cipherSuites, e.getEnabledCipherSuites());
        assertEquals(Arrays.asList(cipherSuites), Arrays.asList(e.getEnabledCipherSuites()));

        String[] protocols = p.getProtocols();
        assertNotSame(protocols, e.getEnabledProtocols());
        assertEquals(Arrays.asList(protocols), Arrays.asList(e.getEnabledProtocols()));

        assertEquals(p.getWantClientAuth(), e.getWantClientAuth());
        assertEquals(p.getNeedClientAuth(), e.getNeedClientAuth());

        c.close();
    }

    @Test
    public void test_SSLEngine_setSSLParameters() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        SSLEngine e = c.clientContext.createSSLEngine();
        String[] defaultCipherSuites = e.getEnabledCipherSuites();
        String[] defaultProtocols = e.getEnabledProtocols();
        String[] supportedCipherSuites = e.getSupportedCipherSuites();
        String[] supportedProtocols = e.getSupportedProtocols();

        {
            SSLParameters p = new SSLParameters();
            e.setSSLParameters(p);
            assertEquals(
                    Arrays.asList(defaultCipherSuites), Arrays.asList(e.getEnabledCipherSuites()));
            assertEquals(Arrays.asList(defaultProtocols), Arrays.asList(e.getEnabledProtocols()));
        }

        {
            SSLParameters p = new SSLParameters(supportedCipherSuites, supportedProtocols);
            e.setSSLParameters(p);
            assertEquals(Arrays.asList(supportedCipherSuites),
                    Arrays.asList(e.getEnabledCipherSuites()));
            assertEquals(Arrays.asList(supportedProtocols), Arrays.asList(e.getEnabledProtocols()));
        }
        {
            SSLParameters p = new SSLParameters();

            p.setNeedClientAuth(true);
            assertFalse(e.getNeedClientAuth());
            assertFalse(e.getWantClientAuth());
            e.setSSLParameters(p);
            assertTrue(e.getNeedClientAuth());
            assertFalse(e.getWantClientAuth());

            p.setWantClientAuth(true);
            assertTrue(e.getNeedClientAuth());
            assertFalse(e.getWantClientAuth());
            e.setSSLParameters(p);
            assertFalse(e.getNeedClientAuth());
            assertTrue(e.getWantClientAuth());

            p.setWantClientAuth(false);
            assertFalse(e.getNeedClientAuth());
            assertTrue(e.getWantClientAuth());
            e.setSSLParameters(p);
            assertFalse(e.getNeedClientAuth());
            assertFalse(e.getWantClientAuth());
        }
        c.close();
    }

    @Test
    public void test_TestSSLEnginePair_create() throws Exception {
        TestSSLEnginePair test = TestSSLEnginePair.create(null);
        assertNotNull(test.c);
        assertNotNull(test.server);
        assertNotNull(test.client);
        assertConnected(test);
        test.close();
    }

    private final int NUM_STRESS_ITERATIONS = 1000;

    @Test
    public void test_SSLEngine_Multiple_Thread_Success() throws Exception {
        final TestSSLEnginePair pair = TestSSLEnginePair.create();
        try {
            assertConnected(pair);

            final CountDownLatch startUpSync = new CountDownLatch(2);
            ExecutorService executor = Executors.newFixedThreadPool(2);
            Future<Void> client = executor.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    startUpSync.countDown();

                    for (int i = 0; i < NUM_STRESS_ITERATIONS; i++) {
                        assertSendsCorrectly("This is the client. Hello!".getBytes(UTF_8),
                                pair.client, pair.server, false);
                    }

                    return null;
                }
            });
            Future<Void> server = executor.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    startUpSync.countDown();

                    for (int i = 0; i < NUM_STRESS_ITERATIONS; i++) {
                        assertSendsCorrectly("This is the server. Hi!".getBytes(UTF_8), pair.server,
                                pair.client, false);
                    }

                    return null;
                }
            });
            executor.shutdown();
            client.get();
            server.get();
        } finally {
            pair.close();
        }
    }

    @Test
    public void test_SSLEngine_CloseOutbound() throws Exception {
        final TestSSLEnginePair pair = TestSSLEnginePair.create();
        try {
            assertConnected(pair);

            // Closing the outbound direction should cause a close_notify to be sent
            pair.client.closeOutbound();
            ByteBuffer clientOut = ByteBuffer
                    .allocate(pair.client.getSession().getPacketBufferSize());
            SSLEngineResult res = pair.client.wrap(ByteBuffer.wrap(new byte[0]), clientOut);
            assertEquals(Status.CLOSED, res.getStatus());
            assertEquals(HandshakeStatus.NOT_HANDSHAKING, res.getHandshakeStatus());
            assertTrue(res.bytesProduced() > 0);

            // Read the close_notify in the server
            clientOut.flip();
            ByteBuffer serverIn = ByteBuffer
                    .allocate(pair.server.getSession().getApplicationBufferSize());
            res = pair.server.unwrap(clientOut, serverIn);
            assertEquals(Status.CLOSED, res.getStatus());
            assertEquals(HandshakeStatus.NEED_WRAP, res.getHandshakeStatus());

            // Reading the close_notify should cause a close_notify to be sent back
            ByteBuffer serverOut = ByteBuffer
                    .allocate(pair.server.getSession().getPacketBufferSize());
            res = pair.server.wrap(ByteBuffer.wrap(new byte[0]), serverOut);
            assertEquals(Status.CLOSED, res.getStatus());
            assertEquals(HandshakeStatus.NOT_HANDSHAKING, res.getHandshakeStatus());
            assertTrue(res.bytesProduced() > 0);

            // Read the close_notify in the client
            serverOut.flip();
            ByteBuffer clientIn = ByteBuffer
                    .allocate(pair.client.getSession().getApplicationBufferSize());
            res = pair.client.unwrap(serverOut, clientIn);
            assertEquals(Status.CLOSED, res.getStatus());
            assertEquals(HandshakeStatus.NOT_HANDSHAKING, res.getHandshakeStatus());

            // Both sides have received close_notify messages, so both peers should have
            // registered that they're finished
            assertTrue(pair.client.isInboundDone() && pair.client.isOutboundDone());
            assertTrue(pair.server.isInboundDone() && pair.server.isOutboundDone());
        } finally {
            pair.close();
        }
    }

    @Test
    public void test_SSLEngine_TlsUnique() throws Exception {
        TestSSLEnginePair pair = TestSSLEnginePair.create(new TestSSLEnginePair.Hooks() {
            @Override
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                assertNull(Conscrypt.getTlsUnique(client));
                assertNull(Conscrypt.getTlsUnique(server));
            }
        });
        try {
            assertConnected(pair);

            byte[] clientTlsUnique = Conscrypt.getTlsUnique(pair.client);
            byte[] serverTlsUnique = Conscrypt.getTlsUnique(pair.server);
            assertNotNull(clientTlsUnique);
            assertNotNull(serverTlsUnique);
            assertArrayEquals(clientTlsUnique, serverTlsUnique);
        } finally {
            pair.close();
        }
    }

    @Test
    public void test_SSLEngine_TokenBinding_Success() throws Exception {
        TestSSLEnginePair pair = TestSSLEnginePair.create(new TestSSLEnginePair.Hooks() {
            @Override
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                try {
                    Conscrypt.setTokenBindingParams(client, 1, 2);
                    Conscrypt.setTokenBindingParams(server, 2, 3);
                } catch (SSLException e) {
                    throw new RuntimeException(e);
                }
                assertEquals(-1, Conscrypt.getTokenBindingParams(client));
                assertEquals(-1, Conscrypt.getTokenBindingParams(server));
            }
        });
        try {
            assertConnected(pair);

            assertEquals(2, Conscrypt.getTokenBindingParams(pair.client));
            assertEquals(2, Conscrypt.getTokenBindingParams(pair.server));
        } finally {
            pair.close();
        }
    }

    @Test
    public void test_SSLEngine_TokenBinding_NoClientSupport() throws Exception {
        TestSSLEnginePair pair = TestSSLEnginePair.create(new TestSSLEnginePair.Hooks() {
            @Override
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                try {
                    // Do not enable on client
                    Conscrypt.setTokenBindingParams(server, 2, 3);
                } catch (SSLException e) {
                    throw new RuntimeException(e);
                }
                assertEquals(-1, Conscrypt.getTokenBindingParams(client));
                assertEquals(-1, Conscrypt.getTokenBindingParams(server));
            }
        });
        try {
            assertConnected(pair);

            assertEquals(-1, Conscrypt.getTokenBindingParams(pair.client));
            assertEquals(-1, Conscrypt.getTokenBindingParams(pair.server));
        } finally {
            pair.close();
        }
    }

    @Test
    public void test_SSLEngine_TokenBinding_NoServerSupport() throws Exception {
        TestSSLEnginePair pair = TestSSLEnginePair.create(new TestSSLEnginePair.Hooks() {
            @Override
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                try {
                    // Do not enable on server
                    Conscrypt.setTokenBindingParams(client, 2, 3);
                } catch (SSLException e) {
                    throw new RuntimeException(e);
                }
                assertEquals(-1, Conscrypt.getTokenBindingParams(client));
                assertEquals(-1, Conscrypt.getTokenBindingParams(server));
            }
        });
        try {
            assertConnected(pair);

            assertEquals(-1, Conscrypt.getTokenBindingParams(pair.client));
            assertEquals(-1, Conscrypt.getTokenBindingParams(pair.server));
        } finally {
            pair.close();
        }
    }

    @Test
    public void test_SSLEngine_TokenBinding_MismatchedSupport() throws Exception {
        TestSSLEnginePair pair = TestSSLEnginePair.create(new TestSSLEnginePair.Hooks() {
            @Override
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                try {
                    Conscrypt.setTokenBindingParams(client, 2);
                    Conscrypt.setTokenBindingParams(server, 1, 3);
                } catch (SSLException e) {
                    throw new RuntimeException(e);
                }
                assertEquals(-1, Conscrypt.getTokenBindingParams(client));
                assertEquals(-1, Conscrypt.getTokenBindingParams(server));
            }
        });
        try {
            assertConnected(pair);

            assertEquals(-1, Conscrypt.getTokenBindingParams(pair.client));
            assertEquals(-1, Conscrypt.getTokenBindingParams(pair.server));
        } finally {
            pair.close();
        }
    }

    @Test
    public void test_SSLEngine_TokenBinding_MismatchedOrdering() throws Exception {
        // When the server and client disagree on the preference order, the server should
        // select the server's most highly preferred value.
        TestSSLEnginePair pair = TestSSLEnginePair.create(new TestSSLEnginePair.Hooks() {
            @Override
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                try {
                    Conscrypt.setTokenBindingParams(client, 1, 2, 3, 4);
                    Conscrypt.setTokenBindingParams(server, 3, 2);
                } catch (SSLException e) {
                    throw new RuntimeException(e);
                }
                assertEquals(-1, Conscrypt.getTokenBindingParams(client));
                assertEquals(-1, Conscrypt.getTokenBindingParams(server));
            }
        });
        try {
            assertConnected(pair);

            assertEquals(3, Conscrypt.getTokenBindingParams(pair.client));
            assertEquals(3, Conscrypt.getTokenBindingParams(pair.server));
        } finally {
            pair.close();
        }
    }

    @Test
    public void test_SSLEngine_TokenBinding_ExceptionAfterConnect() throws Exception {
        TestSSLEnginePair pair = TestSSLEnginePair.create();
        try {
            assertConnected(pair);

            try {
                Conscrypt.setTokenBindingParams(pair.client, 1);
                fail("setTokenBindingParams after handshake should throw");
            } catch (IllegalStateException expected) {
            }
            try {
                Conscrypt.setTokenBindingParams(pair.server, 1);
                fail("setTokenBindingParams after handshake should throw");
            } catch (IllegalStateException expected) {
            }
        } finally {
            pair.close();
        }
    }

    @Test
    public void test_SSLEngine_EKM() throws Exception {
        TestSSLEnginePair pair = TestSSLEnginePair.create(new TestSSLEnginePair.Hooks() {
            @Override
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                try {
                    assertNull(Conscrypt.exportKeyingMaterial(client, "FOO", null, 20));
                    assertNull(Conscrypt.exportKeyingMaterial(server, "FOO", null, 20));
                } catch (SSLException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        try {
            assertConnected(pair);

            byte[] clientEkm = Conscrypt.exportKeyingMaterial(pair.client, "FOO", null, 20);
            byte[] serverEkm = Conscrypt.exportKeyingMaterial(pair.server, "FOO", null, 20);
            assertNotNull(clientEkm);
            assertNotNull(serverEkm);
            assertEquals(20, clientEkm.length);
            assertEquals(20, serverEkm.length);
            assertArrayEquals(clientEkm, serverEkm);

            byte[] clientContextEkm = Conscrypt.exportKeyingMaterial(
                    pair.client, "FOO", new byte[0], 20);
            byte[] serverContextEkm = Conscrypt.exportKeyingMaterial(
                    pair.server, "FOO", new byte[0], 20);
            assertNotNull(clientContextEkm);
            assertNotNull(serverContextEkm);
            assertEquals(20, clientContextEkm.length);
            assertEquals(20, serverContextEkm.length);
            assertArrayEquals(clientContextEkm, serverContextEkm);

            // An empty context should be different than a null context
            assertFalse(Arrays.equals(clientEkm, clientContextEkm));
        } finally {
            pair.close();
        }
    }

    private void assertConnected(TestSSLEnginePair e) {
        assertConnected(e.client, e.server);
    }

    private void assertNotConnected(TestSSLEnginePair e) {
        assertNotConnected(e.client, e.server);
    }

    private void assertConnected(SSLEngine a, SSLEngine b) {
        assertTrue(connected(a, b));
    }

    private void assertNotConnected(SSLEngine a, SSLEngine b) {
        assertFalse(connected(a, b));
    }

    private boolean connected(SSLEngine a, SSLEngine b) {
        return (a.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING
                && b.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING
                && a.getSession() != null && b.getSession() != null && !a.isInboundDone()
                && !b.isInboundDone() && !a.isOutboundDone() && !b.isOutboundDone());
    }
}
