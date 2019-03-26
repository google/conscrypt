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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
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
import javax.net.ssl.X509ExtendedTrustManager;
import org.conscrypt.TestUtils;
import org.conscrypt.java.security.StandardNames;
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
        final TestSSLEnginePair engines = TestSSLEnginePair.create();
        ByteBuffer input = ByteBuffer.allocate(1024);
        input.flip();
        ByteBuffer output = ByteBuffer.allocate(1024);
        assertEquals(SSLEngineResult.Status.BUFFER_UNDERFLOW,
                engines.client.unwrap(input, output).getStatus());
    }

    @Test
    public void test_SSLEngine_wrap_overflowOnEmptyOutputBuffer() throws Exception {
        TestSSLEnginePair pair = TestSSLEnginePair.create();
        ByteBuffer input = ByteBuffer.allocate(10);
        ByteBuffer output = ByteBuffer.allocate(1024);
        output.flip();
        assertEquals(Status.BUFFER_OVERFLOW, pair.client.wrap(input, output).getStatus());
    }

    @Test
    public void test_SSLEngine_unwrap_overflowOnEmptyOutputBuffer() throws Exception {
        TestSSLEnginePair pair = TestSSLEnginePair.create();
        ByteBuffer input = ByteBuffer.allocate(10);
        ByteBuffer wrapped = ByteBuffer.allocate(1024);
        assertEquals(Status.OK, pair.client.wrap(input, wrapped).getStatus());
        wrapped.flip();
        ByteBuffer output = ByteBuffer.allocate(1024);
        output.flip();
        assertEquals(Status.BUFFER_OVERFLOW, pair.server.unwrap(wrapped, output).getStatus());
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
                                   .clientProtocol("TLSv1.2")
                                   .serverProtocol("TLSv1.2")
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
                 * This test uses TLS 1.2, and the TLS 1.3 cipher suites aren't customizable
                 * anyway.
                 */
                if (StandardNames.CIPHER_SUITES_TLS13.contains(cipherSuite)) {
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
                } else if (cipherSuite.startsWith("TLS_PSK_")
                        || cipherSuite.startsWith("TLS_ECDHE_PSK_")) {
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
            assertSendsCorrectlyWhenSplit(sourceBytes, source, dest);
        }
    }

    private static void assertSendsCorrectlyWhenSplit(final byte[] sourceBytes, SSLEngine source,
            SSLEngine dest) throws SSLException {
        // Split the input into three to test the version that accepts ByteBuffer[].  Three
        // is chosen somewhat arbitrarily as a number larger than the minimum of 2 but small
        // enough that it's not unwieldy.
        ByteBuffer[] sourceBufs = new ByteBuffer[3];
        int sourceLen = sourceBytes.length;
        sourceBufs[0] = ByteBuffer.wrap(sourceBytes, 0, sourceLen / 3);
        sourceBufs[1] = ByteBuffer.wrap(sourceBytes, sourceLen / 3, sourceLen / 3);
        sourceBufs[2] = ByteBuffer.wrap(
            sourceBytes, 2 * (sourceLen / 3), sourceLen - 2 * (sourceLen / 3));
        SSLSession sourceSession = source.getSession();
        ByteBuffer sourceToDest = ByteBuffer.allocate(sourceSession.getPacketBufferSize());
        SSLEngineResult sourceOutRes = source.wrap(sourceBufs, sourceToDest);
        sourceToDest.flip();
        String sourceCipherSuite = source.getSession().getCipherSuite();
        assertEquals(sourceCipherSuite, sourceBytes.length, sourceOutRes.bytesConsumed());
        assertEquals(sourceCipherSuite, HandshakeStatus.NOT_HANDSHAKING,
                sourceOutRes.getHandshakeStatus());
        SSLSession destSession = dest.getSession();
        ByteBuffer destIn = ByteBuffer.allocate(destSession.getApplicationBufferSize());
        int numUnwrapCalls = 0;
        while (destIn.position() != sourceBytes.length) {
            SSLEngineResult destRes = dest.unwrap(sourceToDest, destIn);
            assertEquals(sourceCipherSuite, HandshakeStatus.NOT_HANDSHAKING,
                    destRes.getHandshakeStatus());
            numUnwrapCalls++;
        }
        destIn.flip();
        byte[] actual = new byte[destIn.remaining()];
        destIn.get(actual);
        assertEquals(sourceCipherSuite, Arrays.toString(sourceBytes), Arrays.toString(actual));
        assertEquals(sourceCipherSuite, 3, numUnwrapCalls);
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
    public void test_SSLEngine_setEnabledCipherSuites_TLS12() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(null, null, null);
        SSLEngine e = context.createSSLEngine();

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
        String[] cipherSuites = new String[] {
                TestUtils.pickArbitraryNonTls13Suite(e.getSupportedCipherSuites())
        };
        e.setEnabledCipherSuites(cipherSuites);
        assertEquals(Arrays.asList(cipherSuites), Arrays.asList(e.getEnabledCipherSuites()));
    }

    @Test
    public void test_SSLEngine_setEnabledCipherSuites_TLS13() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(null, null, null);
        SSLEngine e = context.createSSLEngine();
        // The TLS 1.3 cipher suites should be enabled by default
        assertTrue(new HashSet<String>(Arrays.asList(e.getEnabledCipherSuites()))
                .containsAll(StandardNames.CIPHER_SUITES_TLS13));
        // Disabling them should be ignored
        e.setEnabledCipherSuites(new String[0]);
        assertTrue(new HashSet<String>(Arrays.asList(e.getEnabledCipherSuites()))
                .containsAll(StandardNames.CIPHER_SUITES_TLS13));

        e.setEnabledCipherSuites(new String[] {
                TestUtils.pickArbitraryNonTls13Suite(e.getSupportedCipherSuites())
        });
        assertTrue(new HashSet<String>(Arrays.asList(e.getEnabledCipherSuites()))
                .containsAll(StandardNames.CIPHER_SUITES_TLS13));

        // Disabling TLS 1.3 should disable the 1.3 cipher suites
        e.setEnabledProtocols(new String[] { "TLSv1.2" });
        assertFalse(new HashSet<String>(Arrays.asList(e.getEnabledCipherSuites()))
                .containsAll(StandardNames.CIPHER_SUITES_TLS13));
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
    public void test_SSLEngine_getHandshakeSession_duringHandshake() throws Exception {
        // We can't reference the actual context we're using, since we need to pass
        // the test trust manager in to construct it, so create reference objects that
        // we can test against.
        final TestSSLContext referenceContext = TestSSLContext.create();
        final SSLEngine referenceEngine = referenceContext.clientContext.createSSLEngine();

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
                    try {
                        SSLSession session = sslEngine.getHandshakeSession();
                        assertNotNull(session);
                        // By the point of the handshake where we're validating certificates,
                        // the hostname is known and the cipher suite should be agreed
                        assertEquals(referenceContext.host.getHostName(), session.getPeerHost());
                        assertEquals(referenceEngine.getEnabledCipherSuites()[0],
                            session.getCipherSuite());
                    } catch (Exception e) {
                        throw new CertificateException("Something broke", e);
                    }
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
        TestSSLEnginePair pair = TestSSLEnginePair.create(c);
        pair.close();
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
        TestSSLEnginePair pair = TestSSLEnginePair.create();
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
