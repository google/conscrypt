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

import static org.conscrypt.Conscrypt.isConscrypt;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SSLSessionContextTest {

    @Parameterized.Parameters(name = "{0}")
    public static Iterable<?> data() {
        // We can't support TLS 1.3 without our own trust manager (which requires
        // X509ExtendedTrustManager), so only test TLS 1.2 if it's not available.
        if (TestUtils.isClassAvailable("javax.net.ssl.X509ExtendedTrustManager")) {
            return Arrays.asList("TLSv1.2", "TLSv1.3");
        } else {
            return Arrays.asList("TLSv1.2");
        }
    }

    private final String protocol;

    public SSLSessionContextTest(String protocol) {
        this.protocol = protocol;
    }

    private TestSSLContext newTestContext() {
        return TestSSLContext.newBuilder()
            .clientProtocol(protocol).serverProtocol(protocol).build();
    }

    private boolean isTls13() {
        return "TLSv1.3".equals(protocol);
    }

    @Test
    public void test_SSLSessionContext_getIds() {
        TestSSLContext c = newTestContext();
        assertSSLSessionContextSize(0, c);
        c.close();

        TestSSLSocketPair s = TestSSLSocketPair.create(newTestContext()).connect();
        if (isTls13()) {
            assertSSLSessionContextSizeAtLeast(1, s.c);
        } else {
            assertSSLSessionContextSize(1, s.c);
        }
        Enumeration<byte[]> clientIds = s.c.clientContext.getClientSessionContext().getIds();
        Enumeration<byte[]> serverIds = s.c.serverContext.getServerSessionContext().getIds();
        byte[] clientId = clientIds.nextElement();
        assertEquals(32, clientId.length);
        if (TestSSLContext.sslServerSocketSupportsSessionTickets()) {
            assertFalse(serverIds.hasMoreElements());
        } else {
            byte[] serverId = serverIds.nextElement();
            assertEquals(32, serverId.length);
            assertTrue(Arrays.equals(clientId, serverId));
        }
        s.close();
    }

    @Test
    public void test_SSLSessionContext_getSession() {
        TestSSLContext c = newTestContext();
        try {
            c.clientContext.getClientSessionContext().getSession(null);
            fail();
        } catch (NullPointerException expected) {
            // Ignored.
        }
        assertNull(c.clientContext.getClientSessionContext().getSession(new byte[0]));
        assertNull(c.clientContext.getClientSessionContext().getSession(new byte[1]));
        try {
            c.serverContext.getServerSessionContext().getSession(null);
            fail();
        } catch (NullPointerException expected) {
            // Ignored.
        }
        assertNull(c.serverContext.getServerSessionContext().getSession(new byte[0]));
        assertNull(c.serverContext.getServerSessionContext().getSession(new byte[1]));
        c.close();

        TestSSLSocketPair s = TestSSLSocketPair.create(newTestContext()).connect();
        SSLSessionContext client = s.c.clientContext.getClientSessionContext();
        SSLSessionContext server = s.c.serverContext.getServerSessionContext();
        byte[] clientId = client.getIds().nextElement();
        assertNotNull(client.getSession(clientId));
        assertTrue(Arrays.equals(clientId, client.getSession(clientId).getId()));
        if (TestSSLContext.sslServerSocketSupportsSessionTickets()) {
            assertFalse(server.getIds().hasMoreElements());
        } else {
            byte[] serverId = server.getIds().nextElement();
            assertNotNull(server.getSession(serverId));
            assertTrue(Arrays.equals(serverId, server.getSession(serverId).getId()));
        }
        s.close();
    }

    @Test
    public void test_SSLSessionContext_getSessionCacheSize() {
        TestSSLContext c = newTestContext();
        int expectedClientSessionCacheSize = expectedClientSslSessionCacheSize(c);
        int expectedServerSessionCacheSize = expectedServerSslSessionCacheSize(c);
        assertEquals(expectedClientSessionCacheSize,
                c.clientContext.getClientSessionContext().getSessionCacheSize());
        assertEquals(expectedServerSessionCacheSize,
                c.serverContext.getServerSessionContext().getSessionCacheSize());
        c.close();

        TestSSLSocketPair s = TestSSLSocketPair.create(newTestContext()).connect();
        assertEquals(expectedClientSessionCacheSize,
                s.c.clientContext.getClientSessionContext().getSessionCacheSize());
        assertEquals(expectedServerSessionCacheSize,
                s.c.serverContext.getServerSessionContext().getSessionCacheSize());
        s.close();
    }

    @Test
    public void test_SSLSessionContext_setSessionCacheSize_noConnect() {
        TestSSLContext c = newTestContext();
        int expectedClientSessionCacheSize = expectedClientSslSessionCacheSize(c);
        int expectedServerSessionCacheSize = expectedServerSslSessionCacheSize(c);
        assertNoConnectSetSessionCacheSizeBehavior(
                expectedClientSessionCacheSize, c.clientContext.getClientSessionContext());
        assertNoConnectSetSessionCacheSizeBehavior(
                expectedServerSessionCacheSize, c.serverContext.getServerSessionContext());
        c.close();
    }

    private static void assertNoConnectSetSessionCacheSizeBehavior(
            int expectedDefault, SSLSessionContext s) {
        try {
            s.setSessionCacheSize(-1);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        assertEquals(expectedDefault, s.getSessionCacheSize());
        s.setSessionCacheSize(1);
        assertEquals(1, s.getSessionCacheSize());
    }

    @Test
    public void test_SSLSessionContext_setSessionCacheSize_oneConnect() {
        TestSSLSocketPair s = TestSSLSocketPair.create(newTestContext()).connect();
        int expectedClientSessionCacheSize = expectedClientSslSessionCacheSize(s.c);
        int expectedServerSessionCacheSize = expectedServerSslSessionCacheSize(s.c);
        SSLSessionContext client = s.c.clientContext.getClientSessionContext();
        SSLSessionContext server = s.c.serverContext.getServerSessionContext();
        assertEquals(expectedClientSessionCacheSize, client.getSessionCacheSize());
        assertEquals(expectedServerSessionCacheSize, server.getSessionCacheSize());
        if (isTls13()) {
            assertSSLSessionContextSizeAtLeast(1, s.c);
        } else {
            assertSSLSessionContextSize(1, s.c);
        }
        s.close();
    }

    @Test
    public void test_SSLSessionContext_setSessionCacheSize_dynamic() throws Exception {
        TestSSLContext c = newTestContext();
        SSLSessionContext client = c.clientContext.getClientSessionContext();
        SSLSessionContext server = c.serverContext.getServerSessionContext();

        String[] supportedCipherSuites = c.serverSocket.getSupportedCipherSuites();
        c.serverSocket.setEnabledCipherSuites(supportedCipherSuites);
        Deque<String> uniqueCipherSuites =
                new ArrayDeque<String>(Arrays.asList(supportedCipherSuites));
        // only use RSA cipher suites which will work with our TrustProvider
        Iterator<String> i = uniqueCipherSuites.iterator();
        while (i.hasNext()) {
            String cipherSuite = i.next();

            // Certificate key length too long for export ciphers
            if (cipherSuite.startsWith("SSL_RSA_EXPORT_")) {
                i.remove();
                continue;
            }

            if (cipherSuite.startsWith("SSL_RSA_")) {
                continue;
            }
            if (cipherSuite.startsWith("TLS_RSA_")) {
                continue;
            }
            if (cipherSuite.startsWith("TLS_DHE_RSA_")) {
                continue;
            }
            if (cipherSuite.startsWith("SSL_DHE_RSA_")) {
                continue;
            }
            i.remove();
        }

        /*
         * having more than 3 uniqueCipherSuites is a test
         * requirement, not a requirement of the interface or
         * implementation. It simply allows us to make sure that we
         * will not get a cached session ID since we'll have to
         * renegotiate a new session due to the new cipher suite
         * requirement. even this test only really needs three if it
         * reused the unique cipher suites every time it resets the
         * session cache.
         */
        assertTrue(uniqueCipherSuites.size() >= 3);
        String cipherSuite1 = uniqueCipherSuites.pop();
        String cipherSuite2 = uniqueCipherSuites.pop();
        String cipherSuite3 = uniqueCipherSuites.pop();

        List<SSLSocket[]> toClose = new ArrayList<SSLSocket[]>();
        toClose.add(
                TestSSLSocketPair.create(c).connect(new String[] {cipherSuite1}, null).sockets());
        if (isTls13()) {
            assertSSLSessionContextSizeAtLeast(1, c);
        } else {
            assertSSLSessionContextSize(1, c);
        }
        toClose.add(
                TestSSLSocketPair.create(c).connect(new String[] {cipherSuite2}, null).sockets());
        if (isTls13()) {
            assertSSLSessionContextSizeAtLeast(2, c);
        } else {
            assertSSLSessionContextSize(2, c);
        }
        toClose.add(
                TestSSLSocketPair.create(c).connect(new String[] {cipherSuite3}, null).sockets());
        if (isTls13()) {
            assertSSLSessionContextSizeAtLeast(3, c);
        } else {
            assertSSLSessionContextSize(3, c);
        }

        client.setSessionCacheSize(1);
        server.setSessionCacheSize(1);
        assertEquals(1, client.getSessionCacheSize());
        assertEquals(1, server.getSessionCacheSize());
        assertSSLSessionContextSize(1, c);
        toClose.add(
                TestSSLSocketPair.create(c).connect(new String[] {cipherSuite1}, null).sockets());
        assertSSLSessionContextSize(1, c);

        client.setSessionCacheSize(2);
        server.setSessionCacheSize(2);
        toClose.add(
                TestSSLSocketPair.create(c).connect(new String[] {cipherSuite2}, null).sockets());
        assertSSLSessionContextSize(2, c);
        toClose.add(
                TestSSLSocketPair.create(c).connect(new String[] {cipherSuite3}, null).sockets());
        assertSSLSessionContextSize(2, c);

        for (SSLSocket[] pair : toClose) {
            for (SSLSocket s : pair) {
                s.close();
            }
        }
        c.close();
    }

    @Test
    public void test_SSLSessionContext_getSessionTimeout() {
        TestSSLContext c = newTestContext();
        int expectedCacheTimeout = expectedSslSessionCacheTimeout(c);
        assertEquals(expectedCacheTimeout,
                c.clientContext.getClientSessionContext().getSessionTimeout());
        assertEquals(expectedCacheTimeout,
                c.serverContext.getServerSessionContext().getSessionTimeout());
        c.close();

        TestSSLSocketPair s = TestSSLSocketPair.create(newTestContext()).connect();
        assertEquals(expectedCacheTimeout,
                s.c.clientContext.getClientSessionContext().getSessionTimeout());
        assertEquals(expectedCacheTimeout,
                s.c.serverContext.getServerSessionContext().getSessionTimeout());
        s.close();
    }

    @Test
    public void test_SSLSessionContext_setSessionTimeout() throws Exception {
        TestSSLContext c = newTestContext();
        int expectedCacheTimeout = expectedSslSessionCacheTimeout(c);
        assertEquals(expectedCacheTimeout,
                c.clientContext.getClientSessionContext().getSessionTimeout());
        assertEquals(expectedCacheTimeout,
                c.serverContext.getServerSessionContext().getSessionTimeout());
        c.clientContext.getClientSessionContext().setSessionTimeout(0);
        c.serverContext.getServerSessionContext().setSessionTimeout(0);
        assertEquals(0, c.clientContext.getClientSessionContext().getSessionTimeout());
        assertEquals(0, c.serverContext.getServerSessionContext().getSessionTimeout());

        try {
            c.clientContext.getClientSessionContext().setSessionTimeout(-1);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        try {
            c.serverContext.getServerSessionContext().setSessionTimeout(-1);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        c.close();

        TestSSLSocketPair s = TestSSLSocketPair.create(newTestContext()).connect();
        if (isTls13()) {
            assertSSLSessionContextSizeAtLeast(1, s.c);
        } else {
            assertSSLSessionContextSize(1, s.c);
        }
        Thread.sleep(1000);
        s.c.clientContext.getClientSessionContext().setSessionTimeout(1);
        s.c.serverContext.getServerSessionContext().setSessionTimeout(1);
        assertSSLSessionContextSize(0, s.c);
        s.close();
    }

    private static void assertSSLSessionContextSize(int expected, TestSSLContext c) {
        assertSSLSessionContextSize(expected, c.clientContext.getClientSessionContext(),
                c.serverContext.getServerSessionContext());
        assertSSLSessionContextSize(0, c.serverContext.getClientSessionContext(),
                c.clientContext.getServerSessionContext());
    }

    private static void assertSSLSessionContextSize(
            int expected, SSLSessionContext client, SSLSessionContext server) {
        assertSSLSessionContextSize(expected, client, false);
        assertSSLSessionContextSize(expected, server, true);
    }

    private static void assertSSLSessionContextSize(
            int expected, SSLSessionContext s, boolean server) {
        if (server && TestSSLContext.sslServerSocketSupportsSessionTickets()) {
            assertEquals(0, numSessions(s));
        } else {
            assertEquals(expected, numSessions(s));
        }
    }

    private static void assertSSLSessionContextSizeAtLeast(int expected, TestSSLContext c) {
        assertSSLSessionContextSizeAtLeast(expected, c.clientContext.getClientSessionContext(),
            c.serverContext.getServerSessionContext());
        assertSSLSessionContextSizeAtLeast(0, c.serverContext.getClientSessionContext(),
            c.clientContext.getServerSessionContext());
    }

    private static void assertSSLSessionContextSizeAtLeast(
        int expected, SSLSessionContext client, SSLSessionContext server) {
        assertSSLSessionContextSizeAtLeast(expected, client, false);
        assertSSLSessionContextSizeAtLeast(expected, server, true);
    }

    private static void assertSSLSessionContextSizeAtLeast(
        int expected, SSLSessionContext s, boolean server) {
        if (server && TestSSLContext.sslServerSocketSupportsSessionTickets()) {
            assertEquals(0, numSessions(s));
        } else {
            assertTrue("numSessions: " + numSessions(s) + ", expected at least: " + expected,
                numSessions(s) >= expected);
        }
    }

    private int expectedClientSslSessionCacheSize(TestSSLContext c) {
        return isConscrypt(c.clientContext.getProvider()) ? 10 : 0;
    }

    private int expectedServerSslSessionCacheSize(TestSSLContext c) {
        return isConscrypt(c.serverContext.getProvider()) ? 100 : 0;
    }

    private int expectedSslSessionCacheTimeout(TestSSLContext c) {
        return isConscrypt(c.serverContext.getProvider()) ? 8 * 3600 : 24 * 3600;
    }

    private static int numSessions(SSLSessionContext s) {
        return Collections.list(s.getIds()).size();
    }

}
