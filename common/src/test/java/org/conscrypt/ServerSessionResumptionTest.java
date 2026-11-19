/*
 * Copyright (C) 2026 The Android Open Source Project
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

import static org.conscrypt.TestUtils.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.conscrypt.java.security.TestKeyStore;
import org.conscrypt.javax.net.ssl.ForwardingX509ExtendedKeyManager;
import org.conscrypt.javax.net.ssl.TestSSLEnginePair;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Tests verifying that server-side TLS 1.2 and TLS 1.3 session resumption is partitioned across
 * distinct SNI names, client authentication modes, and endpoint identification algorithms.
 */
@RunWith(Parameterized.class)
public class ServerSessionResumptionTest {
    private static final String HOST_A = "a.example.com";
    private static final String HOST_B = "b.example.com";
    private static final String NO_SNI_HOST = "127.0.0.1";
    private static final int PORT = 8443;

    private static TestKeyStore caA;
    private static TestKeyStore clientA;
    private static TestKeyStore caB;

    @Parameters(name = "{0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                {"TLSv1.2_SessionCache", "TLSv1.2", false},
                {"TLSv1.2_SessionTicket", "TLSv1.2", true},
                {"TLSv1.3_SessionTicket", "TLSv1.3", true},
        });
    }

    @Parameter(0) public String modeName;
    @Parameter(1) public String protocol;
    @Parameter(2) public boolean useSessionTickets;

    @Before
    public void setUp() {
        TestUtils.installConscryptAsDefaultProvider();
        TestUtils.assumeSNIHostnameAvailable();
        initFixtures();
    }

    private static synchronized void initFixtures() {
        if (caA != null) {
            return;
        }
        caA = buildCa("ca-a", "CN=Test CA A");
        clientA = buildLeaf("client-a", "CN=client-a.example.com", caA);
        caB = buildCa("ca-b", "CN=Test CA B");
    }

    private static TestKeyStore buildCa(String prefix, String subject) {
        return new TestKeyStore.Builder()
                .aliasPrefix(prefix)
                .keyAlgorithms("RSA")
                .subject(subject)
                .ca(true)
                .build();
    }

    private static TestKeyStore buildLeaf(String prefix, String subject, TestKeyStore ca) {
        return new TestKeyStore.Builder()
                .aliasPrefix(prefix)
                .keyAlgorithms("RSA")
                .subject(subject)
                .signer(ca.getPrivateKey("RSA", "RSA"))
                .rootCa(ca.getRootCertificate("RSA"))
                .build();
    }

    // Resuming onto the same SNI host skips TrustManager re-verification and preserves the
    // authenticated client principal.
    @Test
    public void sameSniResumption_skipsReverificationAndPreservesPrincipal() throws Exception {
        SniAwareClientTrustManager serverTm = new SniAwareClientTrustManager();
        SSLContext serverCtx = newContext(TestKeyStore.getServer().keyManagers, serverTm);
        ClientRig initialClient = new ClientRig(clientA.keyManagers);
        runHandshake(initialClient, HOST_A, serverCtx, true);
        ClientRig resumingClient =
                new ClientRig(null).injectSession(initialClient.extractSessionBytes(), HOST_A);

        SSLSession resumed = runHandshake(resumingClient, HOST_A, serverCtx, true);

        assertEquals(0, resumingClient.serverAuthCalls.get());
        assertEquals(1, serverTm.clientAuthCalls.get());
        assertEquals("CN=client-a.example.com", resumed.getPeerPrincipal().getName());
    }

    // SNI hostnames are canonicalized case-insensitively, allowing a session from "A.EXAMPLE.COM"
    // to resume onto "a.example.com".
    @Test
    public void mixedCaseSniResumption_skipsReverificationAndPreservesPrincipal() throws Exception {
        SniAwareClientTrustManager serverTm = new SniAwareClientTrustManager();
        SSLContext serverCtx = newContext(TestKeyStore.getServer().keyManagers, serverTm);
        ClientRig initialClient = new ClientRig(clientA.keyManagers);
        runHandshake(initialClient, "A.EXAMPLE.COM", serverCtx, true);
        ClientRig resumingClient =
                new ClientRig(null).injectSession(initialClient.extractSessionBytes(), HOST_A);

        SSLSession resumed = runHandshake(resumingClient, HOST_A, serverCtx, true);

        assertEquals(0, resumingClient.serverAuthCalls.get());
        assertEquals(1, serverTm.clientAuthCalls.get());
        assertEquals("CN=client-a.example.com", resumed.getPeerPrincipal().getName());
    }

    // Replaying a session from HOST_A against HOST_B declines resumption and rejects the client
    // certificate under HOST_B's TrustManager policy.
    @Test
    public void crossSniResumption_wrongClientCert_rejected() throws Exception {
        SniAwareClientTrustManager serverTm = new SniAwareClientTrustManager();
        SSLContext serverCtx = newContext(TestKeyStore.getServer().keyManagers, serverTm);
        ClientRig rigA = new ClientRig(clientA.keyManagers);
        runHandshake(rigA, HOST_A, serverCtx, true);
        ClientRig wrongCertClient = new ClientRig(clientA.keyManagers)
                                            .injectSession(rigA.extractSessionBytes(), HOST_B);

        assertThrows(SSLHandshakeException.class,
                     () -> runHandshake(wrongCertClient, HOST_B, serverCtx, true));
        assertEquals(2, serverTm.clientAuthCalls.get());
    }

    // Replaying a session established with SNI on a connection without SNI declines resumption and
    // forces client certificate verification.
    @Test
    public void sniToNoSniResumption_declinesResumption() throws Exception {
        SniAwareClientTrustManager serverTm = new SniAwareClientTrustManager();
        SSLContext serverCtx = newContext(TestKeyStore.getServer().keyManagers, serverTm);
        ClientRig sniClient = new ClientRig(clientA.keyManagers);
        runHandshake(sniClient, HOST_A, serverCtx, true);
        // NO_SNI_HOST (127.0.0.1) omits SNI and trusts CA B.
        ClientRig toNoSni = new ClientRig(clientA.keyManagers)
                                    .injectSession(sniClient.extractSessionBytes(), NO_SNI_HOST);

        assertThrows(SSLHandshakeException.class,
                     () -> runHandshake(toNoSni, NO_SNI_HOST, serverCtx, true));
        assertEquals(2, serverTm.clientAuthCalls.get());
    }

    // An unauthenticated session from a needClientAuth=false engine cannot resume onto a
    // needClientAuth=true engine even with the same SNI.
    @Test
    public void clientAuthNoneToNeed_declinesResumption() throws Exception {
        SSLContext serverCtx = newContext(TestKeyStore.getServer().keyManagers, caA.trustManager);
        ClientRig unauthClient = new ClientRig(null);
        runHandshake(unauthClient, HOST_A, serverCtx, false);

        assertThrows(SSLHandshakeException.class,
                     () -> runHandshake(unauthClient, HOST_A, serverCtx, true));
    }

    // An unauthenticated session from a wantClientAuth=true engine cannot resume onto a
    // needClientAuth=true engine.
    @Test
    public void clientAuthWantToNeed_declinesResumption() throws Exception {
        SSLContext serverCtx = newContext(TestKeyStore.getServer().keyManagers, caA.trustManager);
        ClientRig wantClient = new ClientRig(null);
        SSLEngine wantServer = newServerEngine(serverCtx, false);
        wantServer.setWantClientAuth(true);
        handshake(wantClient.newEngine(HOST_A), wantServer);

        assertThrows(SSLHandshakeException.class,
                     () -> runHandshake(wantClient, HOST_A, serverCtx, true));
    }

    // Mutating setNeedClientAuth(true) mid-handshake inside KeyManager does not allow the
    // unauthenticated session to resume onto a needClientAuth=true engine.
    @Test
    public void midHandshakeSetNeedClientAuth_doesNotTagSessionAsClientAuthenticated()
            throws Exception {
        AtomicBoolean mutatedInKeyManager = new AtomicBoolean(false);
        X509ExtendedKeyManager baseKm =
                (X509ExtendedKeyManager) TestKeyStore.getServer().keyManagers[0];
        X509ExtendedKeyManager mutatingKm = new ForwardingX509ExtendedKeyManager(baseKm) {
            @Override
            public String chooseEngineServerAlias(String keyType, Principal[] issuers,
                                                  SSLEngine engine) {
                engine.setNeedClientAuth(true);
                mutatedInKeyManager.set(true);
                return super.chooseEngineServerAlias(keyType, issuers, engine);
            }
        };
        SSLContext serverCtx = newContext(new KeyManager[] {mutatingKm}, caA.trustManager);
        // Initial connection enforces needClientAuth=false (set before beginHandshake); mutating
        // needClientAuth inside KeyManager must not tag the session as client-authenticated.
        ClientRig unauthClient = new ClientRig(null);
        runHandshake(unauthClient, HOST_A, serverCtx, false);

        assertThrows(SSLHandshakeException.class,
                     () -> runHandshake(unauthClient, HOST_A, serverCtx, true));
        assertTrue(mutatedInKeyManager.get());
    }

    // Enabling endpoint identification on the server declines resumption of a session established
    // without endpoint identification and re-runs TrustManager verification.
    @Test
    public void endpointIdentificationAlgorithmChange_declinesResumption() throws Exception {
        TestUtils.assumeSetEndpointIdentificationAlgorithmAvailable();
        SniAwareClientTrustManager serverTm = new SniAwareClientTrustManager();
        SSLContext serverCtx = newContext(TestKeyStore.getServer().keyManagers, serverTm);
        ClientRig client = new ClientRig(clientA.keyManagers);
        runHandshake(client, HOST_A, serverCtx, true);
        SSLEngine serverWithHttpsId = newServerEngine(serverCtx, true);
        SSLParameters params = serverWithHttpsId.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        serverWithHttpsId.setSSLParameters(params);

        handshake(client.newEngine(HOST_A), serverWithHttpsId);

        assertEquals(2, client.serverAuthCalls.get());
        assertEquals(2, serverTm.clientAuthCalls.get());
    }

    // Cross-SNI session replay over SSLServerSocket and SSLSocket declines resumption and rejects
    // the client certificate under HOST_B's TrustManager policy.
    @Test
    public void socketCrossSniResumption_wrongClientCert_rejected() throws Exception {
        SniAwareClientTrustManager serverTm = new SniAwareClientTrustManager();
        SSLContext serverCtx = newContext(TestKeyStore.getServer().keyManagers, serverTm);
        try (SSLServerSocket serverSocket = newServerSocket(serverCtx, true)) {
            int port = serverSocket.getLocalPort();
            ClientRig rigA = new ClientRig(clientA.keyManagers);
            runSocketHandshake(rigA, HOST_A, serverSocket);
            ClientRig wrongCertClient =
                    new ClientRig(clientA.keyManagers)
                            .injectSession(rigA.extractSessionBytes(), HOST_B, port);

            assertThrows(SSLHandshakeException.class,
                         () -> runSocketHandshake(wrongCertClient, HOST_B, serverSocket));
            assertEquals(2, serverTm.clientAuthCalls.get());
        }
    }

    private static SSLContext newContext(KeyManager[] keyManagers, TrustManager trustManager)
            throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS", TestUtils.getConscryptProvider());
        ctx.init(keyManagers, new TrustManager[] {trustManager}, null);
        return ctx;
    }

    private SSLEngine newServerEngine(SSLContext serverCtx, boolean needClientAuth) {
        SSLEngine server = serverCtx.createSSLEngine();
        server.setUseClientMode(false);
        server.setEnabledProtocols(new String[] {protocol});
        server.setNeedClientAuth(needClientAuth);
        Conscrypt.setUseSessionTickets(server, useSessionTickets);
        return server;
    }

    private SSLServerSocket newServerSocket(SSLContext serverCtx, boolean needClientAuth)
            throws IOException {
        SSLServerSocket serverSocket =
                (SSLServerSocket) serverCtx.getServerSocketFactory().createServerSocket(
                        0, 50, TestUtils.getLoopbackAddress());
        serverSocket.setEnabledProtocols(new String[] {protocol});
        serverSocket.setNeedClientAuth(needClientAuth);
        return serverSocket;
    }

    private SSLSession runHandshake(ClientRig clientRig, String host, SSLContext serverCtx,
                                    boolean needClientAuth) throws IOException {
        SSLEngine server = newServerEngine(serverCtx, needClientAuth);
        handshake(clientRig.newEngine(host), server);
        return server.getSession();
    }

    private SSLSession runSocketHandshake(ClientRig clientRig, String host,
                                          SSLServerSocket serverSocket) throws Exception {
        int port = serverSocket.getLocalPort();
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try (Socket rawClient = new Socket(TestUtils.getLoopbackAddress(), port);
             SSLSocket client = clientRig.newSocket(rawClient, host, port);
             SSLSocket server = (SSLSocket) serverSocket.accept()) {
            Conscrypt.setUseSessionTickets(server, useSessionTickets);
            Future<SSLSession> serverFuture = executor.submit(() -> {
                server.startHandshake();
                server.getOutputStream().write('K');
                server.getOutputStream().flush();
                return server.getSession();
            });
            Future<Void> clientFuture = executor.submit(() -> {
                client.startHandshake();
                assertEquals('K', client.getInputStream().read());
                return null;
            });
            try {
                SSLSession session = serverFuture.get(30, TimeUnit.SECONDS);
                clientFuture.get(30, TimeUnit.SECONDS);
                return session;
            } catch (ExecutionException e) {
                closeQuietly(server);
                closeQuietly(client);
                try {
                    clientFuture.get(5, TimeUnit.SECONDS);
                } catch (Exception ignored) {
                    // Expected when handshake fails.
                }
                if (e.getCause() instanceof Exception) {
                    throw (Exception) e.getCause();
                }
                if (e.getCause() instanceof Error) {
                    throw (Error) e.getCause();
                }
                throw e;
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private static void handshake(SSLEngine client, SSLEngine server) throws IOException {
        ByteBuffer c2s = ByteBuffer.allocate(64 * 1024);
        ByteBuffer s2c = ByteBuffer.allocate(64 * 1024);
        ByteBuffer scratch = ByteBuffer.allocate(64 * 1024);
        boolean[] clientDoneFlag = new boolean[1];
        boolean[] serverDoneFlag = new boolean[1];
        client.beginHandshake();
        server.beginHandshake();
        try {
            while (client.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
                   || server.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
                   || c2s.position() > 0 || s2c.position() > 0) {
                boolean progress =
                        TestSSLEnginePair.handshakeStep(client, c2s, s2c, scratch, clientDoneFlag);
                progress |=
                        TestSSLEnginePair.handshakeStep(server, s2c, c2s, scratch, serverDoneFlag);
                if (!progress) {
                    throw new AssertionError("Handshake stalled");
                }
            }
            // Exchange one application record so post-handshake TLS 1.3 NewSessionTickets are read.
            assertEquals(SSLEngineResult.Status.OK,
                         server.wrap(ByteBuffer.wrap("ok".getBytes(UTF_8)), s2c).getStatus());
            s2c.flip();
            while (s2c.hasRemaining()) {
                assertEquals(SSLEngineResult.Status.OK, client.unwrap(s2c, scratch).getStatus());
            }
        } finally {
            closeQuietly(client);
            closeQuietly(server);
        }
    }

    private static void closeQuietly(SSLEngine engine) {
        try {
            engine.closeOutbound();
        } catch (Exception ignored) {
            // Ignored after failed handshake.
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (Exception ignored) {
            // Ignored after failed handshake.
        }
    }

    private final class ClientRig {
        final SSLContext context;
        final AtomicInteger serverAuthCalls = new AtomicInteger();

        ClientRig(KeyManager[] keyManagers) throws Exception {
            X509TrustManager baseTm = (X509TrustManager) TestKeyStore.getClient().trustManager;
            TrustManager countingTm = new X509TrustManager() {
                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType)
                        throws CertificateException {
                    serverAuthCalls.incrementAndGet();
                    baseTm.checkServerTrusted(chain, authType);
                }

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType)
                        throws CertificateException {
                    throw new CertificateException("Unexpected checkClientTrusted");
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return baseTm.getAcceptedIssuers();
                }
            };
            this.context = newContext(keyManagers, countingTm);
        }

        SSLEngine newEngine(String host) {
            SSLEngine engine = context.createSSLEngine(host, PORT);
            engine.setUseClientMode(true);
            engine.setEnabledProtocols(new String[] {protocol});
            Conscrypt.setUseSessionTickets(engine, useSessionTickets);
            Conscrypt.setHostname(engine, host);
            return engine;
        }

        SSLSocket newSocket(Socket rawSocket, String host, int port) throws IOException {
            SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(rawSocket, host,
                                                                                   port, true);
            socket.setUseClientMode(true);
            socket.setEnabledProtocols(new String[] {protocol});
            Conscrypt.setUseSessionTickets(socket, useSessionTickets);
            Conscrypt.setHostname(socket, host);
            return socket;
        }

        byte[] extractSessionBytes() {
            ClientSessionContext sessionCtx =
                    (ClientSessionContext) context.getClientSessionContext();
            Enumeration<byte[]> ids = sessionCtx.getIds();
            assertTrue(ids.hasMoreElements());
            NativeSslSession session = sessionCtx.getSessionFromCache(ids.nextElement());
            assertNotNull(session);
            byte[] bytes = session.toBytes();
            assertNotNull(bytes);
            return bytes;
        }

        ClientRig injectSession(byte[] sessionBytes, String targetHost) {
            return injectSession(sessionBytes, targetHost, PORT);
        }

        ClientRig injectSession(byte[] sessionBytes, String targetHost, int port) {
            ClientSessionContext sessionCtx =
                    (ClientSessionContext) context.getClientSessionContext();
            NativeSslSession transplanted =
                    NativeSslSession.newInstance(sessionCtx, sessionBytes, targetHost, port);
            assertNotNull(transplanted);
            sessionCtx.cacheSession(transplanted);
            return this;
        }
    }

    private static final class SniAwareClientTrustManager extends X509ExtendedTrustManager {
        private final X509TrustManager caATm = (X509TrustManager) caA.trustManager;
        private final X509TrustManager caBTm = (X509TrustManager) caB.trustManager;
        final AtomicInteger clientAuthCalls = new AtomicInteger();

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            verifyClient(chain, authType, engine.getHandshakeSession());
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            if (!(socket instanceof SSLSocket)) {
                throw new CertificateException("Expected SSLSocket");
            }
            verifyClient(chain, authType, ((SSLSocket) socket).getHandshakeSession());
        }

        private void verifyClient(X509Certificate[] chain, String authType, SSLSession session)
                throws CertificateException {
            clientAuthCalls.incrementAndGet();
            if (!(session instanceof ExtendedSSLSession)) {
                throw new CertificateException("Missing ExtendedSSLSession");
            }
            String sni = null;
            List<SNIServerName> names = ((ExtendedSSLSession) session).getRequestedServerNames();
            if (names != null) {
                for (SNIServerName name : names) {
                    if (name.getType() == StandardConstants.SNI_HOST_NAME
                        && name instanceof SNIHostName) {
                        sni = ((SNIHostName) name).getAsciiName();
                        break;
                    }
                }
            }
            if (HOST_A.equalsIgnoreCase(sni)) {
                caATm.checkClientTrusted(chain, authType);
            } else if (sni == null || HOST_B.equalsIgnoreCase(sni)) {
                caBTm.checkClientTrusted(chain, authType);
            } else {
                throw new CertificateException("Unknown SNI: " + sni);
            }
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new CertificateException("SNI unavailable in non-extended TrustManager");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            throw new CertificateException("Unexpected checkServerTrusted");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            throw new CertificateException("Unexpected checkServerTrusted");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new CertificateException("Unexpected checkServerTrusted");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            List<X509Certificate> issuers = new ArrayList<>();
            Collections.addAll(issuers, caATm.getAcceptedIssuers());
            Collections.addAll(issuers, caBTm.getAcceptedIssuers());
            return issuers.toArray(new X509Certificate[0]);
        }
    }
}
