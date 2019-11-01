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

import static java.util.Collections.singleton;
import static org.conscrypt.TestUtils.UTF_8;
import static org.conscrypt.TestUtils.assumeJava8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
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
import javax.net.ssl.X509TrustManager;
import org.conscrypt.Conscrypt;
import org.conscrypt.TestUtils;
import org.conscrypt.java.security.TestKeyStore;
import org.conscrypt.testing.FailingSniMatcher;
import org.conscrypt.tlswire.TlsTester;
import org.conscrypt.tlswire.handshake.AlpnHelloExtension;
import org.conscrypt.tlswire.handshake.ClientHello;
import org.conscrypt.tlswire.handshake.HandshakeMessage;
import org.conscrypt.tlswire.handshake.HelloExtension;
import org.conscrypt.tlswire.handshake.ServerNameHelloExtension;
import org.conscrypt.tlswire.record.TlsProtocols;
import org.conscrypt.tlswire.record.TlsRecord;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * Tests for SSLSocket classes that ensure the TLS 1.2 and TLS 1.3 implementations
 * are compatible.
 */
@RunWith(Parameterized.class)
public class SSLEngineVersionCompatibilityTest {

    @Parameterized.Parameters(name = "{index}: {0} client, {1} server")
    public static Iterable<Object[]> data() {
        // We can't support TLS 1.3 without our own trust manager (which requires
        // X509ExtendedTrustManager), so only test TLS 1.2 if it's not available.
        if (TestUtils.isClassAvailable("javax.net.ssl.X509ExtendedTrustManager")) {
            return Arrays.asList(new Object[][] {
                    { "TLSv1.2", "TLSv1.2" },
                    { "TLSv1.2", "TLSv1.3" },
                    { "TLSv1.3", "TLSv1.2" },
                    { "TLSv1.3", "TLSv1.3" },
            });
        } else {
            return Arrays.asList(new Object[][]{{ "TLSv1.2", "TLSv1.2"}});
        }
    }

    private final String clientVersion;
    private final String serverVersion;

    public SSLEngineVersionCompatibilityTest(String clientVersion, String serverVersion) {
        this.clientVersion = clientVersion;
        this.serverVersion = serverVersion;
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
    public void test_SSLEngine_beginHandshake() throws Exception {
        TestSSLContext c = TestSSLContext.newBuilder()
                .clientProtocol(clientVersion)
                .serverProtocol(serverVersion).build();

        try {
            c.clientContext.createSSLEngine().beginHandshake();
            fail();
        } catch (IllegalStateException expected) {
            // Ignored.
        }
        c.close();

        TestSSLEnginePair p = TestSSLEnginePair.create();
        assertConnected(p);
        p.close();
    }

    @Test
    public void test_SSLEngine_beginHandshake_noKeyStore() throws Exception {
        SSLContext clientContext = SSLContext.getInstance(clientVersion);
        clientContext.init(null, null, null);
        SSLContext serverContext = SSLContext.getInstance(serverVersion);
        serverContext.init(null, null, null);
        TestSSLContext c = TestSSLContext.newBuilder()
                .useDefaults(false)
                .clientContext(clientContext)
                .serverContext(serverContext).build();
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
        TestSSLContext c = TestSSLContext.newBuilder()
                .clientProtocol(clientVersion)
                .serverProtocol(serverVersion).build();
        SSLEngine[] engines = TestSSLEnginePair.connect(c, null);
        assertConnected(engines[0], engines[1]);
        c.close();
        TestSSLEnginePair.close(engines);
    }

    @Test
    public void test_SSLEngine_clientAuth() throws Exception {
        TestSSLContext c = TestSSLContext.newBuilder()
                .clientProtocol(clientVersion)
                .serverProtocol(serverVersion).build();
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
        TestSSLContext clientAuthContext = new TestSSLContext.Builder()
                .client(TestKeyStore.getClientCertificate())
                .server(TestKeyStore.getServer())
                .clientProtocol(clientVersion)
                .serverProtocol(serverVersion).build();
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
        TestSSLContext clientAuthContext = new TestSSLContext.Builder()
                .client(TestKeyStore.getClient())
                .server(TestKeyStore.getServer())
                .clientProtocol(clientVersion)
                .serverProtocol(serverVersion).build();
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
        TestSSLContext clientAuthContext = new TestSSLContext.Builder()
                .client(TestKeyStore.getClient())
                .server(TestKeyStore.getServer())
                .clientProtocol(clientVersion)
                .serverProtocol(serverVersion).build();
        TestSSLEnginePair p = null;
        try {
            p = TestSSLEnginePair.create(clientAuthContext, new TestSSLEnginePair.Hooks() {
                @Override
                void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                    server.setNeedClientAuth(true);
                }
            });
            fail();
        } catch (SSLException expected) {
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
        // The default hostname verifier on OpenJDK just rejects all hostnames,
        // which is not helpful, so replace with a basic functional one.
        HostnameVerifier oldDefault = HttpsURLConnection.getDefaultHostnameVerifier();
        HttpsURLConnection.setDefaultHostnameVerifier(new TestHostnameVerifier());
        try {
            TestSSLContext c = TestSSLContext.newBuilder()
                    .clientProtocol(clientVersion)
                    .serverProtocol(serverVersion).build();
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
        } finally {
            HttpsURLConnection.setDefaultHostnameVerifier(oldDefault);
        }
    }

    @Test
    public void test_TestSSLEnginePair_create() throws Exception {
        TestSSLEnginePair test = TestSSLEnginePair.create(
                TestSSLContext.newBuilder()
                        .clientProtocol(clientVersion)
                        .serverProtocol(serverVersion).build());
        assertNotNull(test.c);
        assertNotNull(test.server);
        assertNotNull(test.client);
        assertConnected(test);
        test.close();
    }

    private final int NUM_STRESS_ITERATIONS = 1000;

    @Test
    public void test_SSLEngine_Multiple_Thread_Success() throws Exception {
        final TestSSLEnginePair pair = TestSSLEnginePair.create(
                TestSSLContext.newBuilder()
                        .clientProtocol(clientVersion)
                        .serverProtocol(serverVersion).build());
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
        final TestSSLEnginePair pair = TestSSLEnginePair.create(
                TestSSLContext.newBuilder()
                        .clientProtocol(clientVersion)
                        .serverProtocol(serverVersion).build());
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
    public void test_SSLEngine_Closed() throws Exception {
        final TestSSLEnginePair pair = TestSSLEnginePair.create(
                TestSSLContext.newBuilder()
                        .clientProtocol(clientVersion)
                        .serverProtocol(serverVersion).build());
        pair.close();
        ByteBuffer out = ByteBuffer.allocate(pair.client.getSession().getPacketBufferSize());
        SSLEngineResult res = pair.client.wrap(ByteBuffer.wrap(new byte[] { 0x01 }), out);
        assertEquals(Status.CLOSED, res.getStatus());
        // The engine should have a close_notify alert pending, so it should ignore the
        // proffered data and push the alert into out
        assertEquals(0, res.bytesConsumed());
        assertNotEquals(0, res.bytesProduced());

        res = pair.client.unwrap(ByteBuffer.wrap(new byte[] { 0x01} ), out);
        assertEquals(Status.CLOSED, res.getStatus());
        assertEquals(0, res.bytesConsumed());
        assertEquals(0, res.bytesProduced());
    }

    @Test
    public void test_SSLEngine_ClientHello_record_size() throws Exception {
        // This test checks the size of ClientHello of the default SSLEngine. TLS/SSL handshakes
        // with older/unpatched F5/BIG-IP appliances are known to stall and time out when
        // the fragment containing ClientHello is between 256 and 511 (inclusive) bytes long.
        SSLContext context = SSLContext.getInstance(clientVersion);
        context.init(null, null, null);
        SSLEngine e = context.createSSLEngine();
        e.setUseClientMode(true);

        // Enable SNI extension on the engine (this is typically enabled by default)
        // to increase the size of ClientHello.
        Conscrypt.setHostname(e, "sslenginetest.androidcts.google.com");

        // Enable Session Tickets extension on the engine (this is typically enabled
        // by default) to increase the size of ClientHello.
        Conscrypt.setUseSessionTickets(e, true);

        TlsRecord firstReceivedTlsRecord = TlsTester.parseRecord(getFirstChunk(e));

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
    public void test_SSLEngine_ClientHello_SNI() throws Exception {
        SSLContext context = SSLContext.getInstance(clientVersion);
        context.init(null, null, null);
        SSLEngine e = context.createSSLEngine();
        e.setUseClientMode(true);

        Conscrypt.setHostname(e, "sslenginetest.androidcts.google.com");

        ClientHello clientHello = TlsTester.parseClientHello(getFirstChunk(e));
        ServerNameHelloExtension sniExtension =
                (ServerNameHelloExtension) clientHello.findExtensionByType(
                        HelloExtension.TYPE_SERVER_NAME);

        assertNotNull(sniExtension);
        assertEquals(Arrays.asList("sslenginetest.androidcts.google.com"), sniExtension.hostnames);
    }

    @Test
    public void test_SSLEngine_ClientHello_ALPN() throws Exception {
        String[] protocolList = new String[] { "h2", "http/1.1" };

        SSLContext context = SSLContext.getInstance(clientVersion);
        context.init(null, null, null);
        SSLEngine e = context.createSSLEngine();
        e.setUseClientMode(true);

        Conscrypt.setApplicationProtocols(e, protocolList);

        ClientHello clientHello = TlsTester.parseClientHello(getFirstChunk(e));
        AlpnHelloExtension alpnExtension =
                (AlpnHelloExtension) clientHello.findExtensionByType(
                        HelloExtension.TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        assertNotNull(alpnExtension);
        assertEquals(Arrays.asList(protocolList), alpnExtension.protocols);
    }

    private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocate(0);

    private static byte[] getFirstChunk(SSLEngine e) throws SSLException {
        ByteBuffer out = ByteBuffer.allocate(64 * 1024);

        e.wrap(EMPTY_BUFFER, out);
        out.flip();
        byte[] data = new byte[out.limit()];
        out.get(data);

        return data;
    }

    @Test
    public void test_SSLEngine_TlsUnique() throws Exception {
        // tls_unique isn't supported in TLS 1.3
        assumeTlsV1_2Connection();
        TestSSLEnginePair pair = TestSSLEnginePair.create(
                TestSSLContext.newBuilder()
                        .clientProtocol(clientVersion)
                        .serverProtocol(serverVersion).build(),
                new TestSSLEnginePair.Hooks() {
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
    public void test_SSLEngine_EKM() throws Exception {
        TestSSLEnginePair pair = TestSSLEnginePair.create(
                TestSSLContext.newBuilder()
                        .clientProtocol(clientVersion)
                        .serverProtocol(serverVersion).build(),
                new TestSSLEnginePair.Hooks() {
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

            // In TLS 1.2, an empty context and a null context are different (RFC 5705, section 4),
            // but in TLS 1.3 they are the same (RFC 8446, section 7.5).
            if ("TLSv1.2".equals(negotiatedVersion())) {
                assertFalse(Arrays.equals(clientEkm, clientContextEkm));
            } else {
                assertTrue(Arrays.equals(clientEkm, clientContextEkm));
            }
        } finally {
            pair.close();
        }
    }

    // Test whether an exception thrown from within the TrustManager properly flows immediately
    // to the caller and doesn't get caught and held by the SSLEngine.  This was previously
    // the behavior of Conscrypt, see https://github.com/google/conscrypt/issues/577.
    @Test
    public void test_SSLEngine_Exception() throws Exception {
        final TestSSLContext referenceContext = TestSSLContext.create();
        class ThrowingTrustManager implements X509TrustManager {
            public boolean threw = false;
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
                throws CertificateException {
            }
            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
                throws CertificateException {
                threw = true;
                throw new CertificateException("Nope!");
            }
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return referenceContext.clientTrustManager.getAcceptedIssuers();
            }
        }
        ThrowingTrustManager trustManager = new ThrowingTrustManager();
        final TestSSLContext c = TestSSLContext.newBuilder()
            .clientProtocol(clientVersion)
            .serverProtocol(serverVersion)
            .clientTrustManager(trustManager).build();

        // The following code is taken from TestSSLEnginePair.connect()
        SSLSession session = c.clientContext.createSSLEngine().getSession();

        int packetBufferSize = session.getPacketBufferSize();
        ByteBuffer clientToServer = ByteBuffer.allocate(packetBufferSize);
        ByteBuffer serverToClient = ByteBuffer.allocate(packetBufferSize);

        int applicationBufferSize = session.getApplicationBufferSize();
        ByteBuffer scratch = ByteBuffer.allocate(applicationBufferSize);

        SSLEngine client = c.clientContext.createSSLEngine(c.host.getHostName(), c.port);
        SSLEngine server = c.serverContext.createSSLEngine();
        client.setUseClientMode(true);
        server.setUseClientMode(false);
        client.beginHandshake();
        server.beginHandshake();

        try {
            while (true) {
                boolean clientDone = client.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING;
                boolean serverDone = server.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING;
                if (clientDone && serverDone) {
                    break;
                }

                boolean progress = TestSSLEnginePair.handshakeStep(client,
                    clientToServer,
                    serverToClient,
                    scratch,
                    new boolean[1]);
                progress |= TestSSLEnginePair.handshakeStep(server,
                    serverToClient,
                    clientToServer,
                    scratch,
                    new boolean[1]);
                assertFalse(trustManager.threw);
                if (!progress) {
                    break;
                }
            }
            fail();
        } catch (SSLHandshakeException expected) {
            assertTrue(expected.getCause() instanceof CertificateException);
        }
        assertTrue(trustManager.threw);
    }

    @Test
    public void sniHandlerFailureResultsInHandshakeError() throws Exception {
        assumeJava8();

        try {
            TestSSLEnginePair.create(TestSSLContext.newBuilder()
                                             .clientProtocol(clientVersion)
                                             .serverProtocol(serverVersion)
                                             .build(),
                    new TestSSLEnginePair.Hooks() {
                        @Override
                        void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                            Conscrypt.setHostname(client, "any.host");

                            SSLParameters sslParameters = server.getSSLParameters();
                            sslParameters.setSNIMatchers(singleton(FailingSniMatcher.create()));
                            server.setSSLParameters(sslParameters);
                        }
                    });
            fail();
        } catch (SSLHandshakeException e) {
            assertEquals(e.getMessage(), "SNI match failed: any.host");
        }
    }

    @Test
    public void sniHandlerIsCalledAfterHandshakeAndBeforeServerCert() throws Exception {
        assumeJava8();

        final String host = "sni.con-scry.pt";

        final AtomicReference<String> serverHost = new AtomicReference<>();
        final AtomicBoolean serverAliasCalled = new AtomicBoolean(false);

        TestSSLEnginePair pair = TestSSLEnginePair.create(
                TestSSLContext.newBuilder()
                        .clientProtocol(clientVersion)
                        .serverProtocol(serverVersion)
                        .server(addServerCertListener(new Runnable() {
                            @Override
                            public void run() {
                                assertEquals("cert is loaded after sni", host, serverHost.get());
                                serverAliasCalled.set(true);
                            }
                        }))
                        .build(),
                new TestSSLEnginePair.Hooks() {
                    @Override
                    void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                        Conscrypt.setHostname(client, host);

                        SSLParameters sslParameters = server.getSSLParameters();
                        sslParameters.setSNIMatchers(
                                Collections.<SNIMatcher>singleton(new SNIMatcher(0) {
                                    @Override
                                    public boolean matches(SNIServerName sniServerName) {
                                        String host = ((SNIHostName) sniServerName).getAsciiName();
                                        serverHost.set(host);
                                        return true;
                                    }
                                }));
                        server.setSSLParameters(sslParameters);
                    }
                });

        ExtendedSSLSession session = (ExtendedSSLSession) pair.server.getSession();
        assertEquals(Collections.singletonList(new SNIHostName(host)),
                session.getRequestedServerNames());
        assertEquals(host, serverHost.get());
        assertTrue(serverAliasCalled.get());
    }

    private TestKeyStore addServerCertListener(final Runnable callback) {
        TestKeyStore store = TestKeyStore.getServer().copy();
        X509ExtendedKeyManager tm = new ForwardingX509ExtendedKeyManager(
                (X509ExtendedKeyManager) store.keyManagers[0]) {
            @Override
            public String chooseEngineServerAlias(
                    String keyType, Principal[] issuers, SSLEngine engine) {
                callback.run();
                return super.chooseEngineServerAlias(keyType, issuers, engine);
            }
        };
        store.keyManagers[0] = tm;
        return store;
    }

    private void assertConnected(TestSSLEnginePair e) {
        assertConnected(e.client, e.server);
    }

    private void assertConnected(SSLEngine a, SSLEngine b) {
        assertTrue(connected(a, b));
    }

    private boolean connected(SSLEngine a, SSLEngine b) {
        return (a.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING
                && b.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING
                && a.getSession() != null && b.getSession() != null && !a.isInboundDone()
                && !b.isInboundDone() && !a.isOutboundDone() && !b.isOutboundDone());
    }

    // Assumes that the negotiated connection will be TLS 1.2
    private void assumeTlsV1_2Connection() {
        assumeTrue("TLSv1.2".equals(negotiatedVersion()));
    }

    /**
     * Returns the version that a connection between {@code clientVersion} and
     * {@code serverVersion} should produce.
     */
    private String negotiatedVersion() {
        if (clientVersion.equals("TLSv1.3") && serverVersion.equals("TLSv1.3")) {
            return "TLSv1.3";
        } else {
            return "TLSv1.2";
        }
    }
}
