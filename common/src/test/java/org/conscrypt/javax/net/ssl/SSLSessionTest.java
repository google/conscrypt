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

import static org.conscrypt.TestUtils.isWindows;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSocket;
import org.conscrypt.TestUtils;
import org.conscrypt.java.security.StandardNames;
import org.conscrypt.java.security.TestKeyStore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SSLSessionTest {
    @Test
    public void test_SSLSocket_TestSSLSessions_create() {
        TestSSLSessions s = TestSSLSessions.create();
        assertNotNull(s.invalid);
        assertFalse(s.invalid.isValid());
        assertTrue(s.server.isValid());
        assertTrue(s.client.isValid());
        s.close();
    }

    @Test
    public void test_SSLSession_getApplicationBufferSize() {
        TestSSLSessions s = TestSSLSessions.create();
        assertTrue(s.invalid.getApplicationBufferSize() > 0);
        assertTrue(s.server.getApplicationBufferSize() > 0);
        assertTrue(s.client.getApplicationBufferSize() > 0);
        s.close();
    }

    @Test
    public void test_SSLSession_getCipherSuite() {
        TestSSLSessions s = TestSSLSessions.create();
        assertNotNull(s.invalid.getCipherSuite());
        assertEquals(StandardNames.CIPHER_SUITE_INVALID, s.invalid.getCipherSuite());
        assertNotNull(s.server.getCipherSuite());
        assertNotNull(s.client.getCipherSuite());
        assertEquals(s.server.getCipherSuite(), s.client.getCipherSuite());
        StandardNames.assertValidCipherSuites(new String[] {s.server.getCipherSuite()});
        s.close();
    }

    @Test
    public void test_SSLSession_getCreationTime() {
        // TODO(prb) seems to fail regularly on Windows with sTime <= t1
        assumeFalse("Skipping SSLSession_getCreationTime() test on Windows", isWindows());

        // We use OpenSSL, which only returns times accurate to the nearest second.
        // NativeCrypto just multiplies by 1000, which looks like truncation, which
        // would make it appear as if the OpenSSL side of things was created before
        // we called it.
        long t0 = System.currentTimeMillis() / 1000;
        TestSSLSessions s = TestSSLSessions.create();
        long t1 = System.currentTimeMillis() / 1000;

        assertTrue(s.invalid.getCreationTime() > 0);

        long sTime = s.server.getCreationTime() / 1000;
        assertTrue(sTime + " >= " + t0, sTime >= t0);
        assertTrue(sTime + " <= " + t1, sTime <= t1);

        long cTime = s.client.getCreationTime() / 1000;
        assertTrue(cTime + " >= " + t0, cTime >= t0);
        assertTrue(cTime + " <= " + t1, cTime <= t1);

        s.close();
    }

    // TLS 1.2 and TLS 1.3 sessions are philosophically different: In TLS 1.3, sessions for
    // resumption are sent outside the handshake, are generally single-use, and there can be
    // multiple cached at any time, whereas in TLS 1.2 the session caching info is sent as part of
    // the handshake and effectively enhances the current session.  So in TLS 1.3, the current
    // session has no ID (and cannot be resumed), whereas in TLS 1.2, the current session gets
    // an ID and can be used for session resumption.

    @Test
    public void test_SSLSession_getId_TLS12() {
        TestSSLSessions s = TestSSLSessions.create(TestSSLContext.newBuilder()
            .clientProtocol("TLSv1.2").serverProtocol("TLSv1.2").build());
        assertNotNull(s.invalid.getId());
        assertNotNull(s.server.getId());
        assertNotNull(s.client.getId());
        assertEquals(0, s.invalid.getId().length);
        if (TestSSLContext.sslServerSocketSupportsSessionTickets()) {
            assertEquals(0, s.server.getId().length);
        } else {
            assertEquals(32, s.server.getId().length);
            assertTrue(Arrays.equals(s.server.getId(), s.client.getId()));
        }
        assertEquals(32, s.client.getId().length);
        s.close();
    }

    @Test
    public void test_SSLSession_getId_TLS13() {
        TestSSLSessions s = TestSSLSessions.create(TestSSLContext.newBuilder()
            .clientProtocol("TLSv1.3").serverProtocol("TLSv1.3").build());
        assertNotNull(s.invalid.getId());
        assertNotNull(s.server.getId());
        assertNotNull(s.client.getId());
        assertEquals(0, s.invalid.getId().length);
        assertEquals(0, s.server.getId().length);
        assertEquals(0, s.client.getId().length);
        s.close();
    }

    @Test
    public void test_SSLSession_getLastAccessedTime() {
        TestSSLSessions s = TestSSLSessions.create();
        assertTrue(s.invalid.getLastAccessedTime() > 0);
        assertTrue(s.server.getLastAccessedTime() > 0);
        assertTrue(s.client.getLastAccessedTime() > 0);
        assertTrue("s.server.getLastAccessedTime()=" + s.server.getLastAccessedTime() + " "
                        + "s.client.getLastAccessedTime()=" + s.client.getLastAccessedTime(),
                Math.abs(s.server.getLastAccessedTime() - s.client.getLastAccessedTime())
                        <= 1000);
        assertTrue(s.server.getLastAccessedTime() >= s.server.getCreationTime());
        assertTrue(s.client.getLastAccessedTime() >= s.client.getCreationTime());
        s.close();
    }

    @Test
    public void test_SSLSession_getLocalCertificates() throws Exception {
        TestSSLSessions s = TestSSLSessions.create();
        assertNull(s.invalid.getLocalCertificates());
        assertNull(s.client.getLocalCertificates());
        assertNotNull(s.server.getLocalCertificates());
        TestKeyStore.assertChainLength(s.server.getLocalCertificates());
        TestSSLContext.assertServerCertificateChain(
                s.s.c.serverTrustManager, s.server.getLocalCertificates());
        TestSSLContext.assertCertificateInKeyStore(
                s.server.getLocalCertificates()[0], s.s.c.serverKeyStore);
        s.close();
    }

    @Test
    public void test_SSLSession_getLocalPrincipal() throws Exception {
        TestSSLSessions s = TestSSLSessions.create();
        assertNull(s.invalid.getLocalPrincipal());
        assertNull(s.client.getLocalPrincipal());
        assertNotNull(s.server.getLocalPrincipal());
        assertNotNull(s.server.getLocalPrincipal().getName());
        TestSSLContext.assertCertificateInKeyStore(
                s.server.getLocalPrincipal(), s.s.c.serverKeyStore);
        s.close();
    }

    @Test
    public void test_SSLSession_getPacketBufferSize() {
        TestSSLSessions s = TestSSLSessions.create();
        assertTrue(s.invalid.getPacketBufferSize() > 0);
        assertTrue(s.server.getPacketBufferSize() > 0);
        assertTrue(s.client.getPacketBufferSize() > 0);
        s.close();
    }

    @Test
    public void test_SSLSession_getPeerCertificateChain() throws Exception {
        TestSSLSessions s = TestSSLSessions.create();
        try {
            s.invalid.getPeerCertificateChain();
            fail();
        } catch (SSLPeerUnverifiedException expected) {
            // Ignored.
        } catch (UnsupportedOperationException e) {
            if (!StandardNames.IS_15_OR_UP) {
                fail("Should only throw UnsupportedOperationException on OpenJDK 15 or up");
            }
        }
        assertNotNull(s.client.getPeerCertificates());
        TestKeyStore.assertChainLength(s.client.getPeerCertificates());
        try {
            assertNull(s.server.getPeerCertificateChain());
            fail();
        } catch (SSLPeerUnverifiedException expected) {
            // Ignored.
        } catch (UnsupportedOperationException e) {
            if (!StandardNames.IS_15_OR_UP) {
                fail("Should only throw UnsupportedOperationException on OpenJDK 15 or up");
            }
        }
        s.close();
    }

    @Test
    public void test_SSLSession_getPeerCertificates() throws Exception {
        TestSSLSessions s = TestSSLSessions.create();
        try {
            s.invalid.getPeerCertificates();
            fail();
        } catch (SSLPeerUnverifiedException expected) {
            // Ignored.
        }
        assertNotNull(s.client.getPeerCertificates());
        TestKeyStore.assertChainLength(s.client.getPeerCertificates());
        TestSSLContext.assertServerCertificateChain(
                s.s.c.serverTrustManager, s.client.getPeerCertificates());
        TestSSLContext.assertCertificateInKeyStore(
                s.client.getPeerCertificates()[0], s.s.c.serverKeyStore);
        try {
            s.server.getPeerCertificates();
            fail();
        } catch (SSLPeerUnverifiedException expected) {
            // Ignored.
        }
        s.close();
    }

    @Test
    public void test_SSLSession_getPeerCertificates_resumption() throws Exception {
        TestSSLContext context = TestSSLContext.create();

        // Ensure that the session is reused to the best of our ability
        context.clientContext.getClientSessionContext().setSessionTimeout(1000000);
        context.clientContext.getClientSessionContext().setSessionCacheSize(0);

        SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                context.host, context.port);
        SSLSocket server = (SSLSocket) context.serverSocket.accept();
        connect(client, server);

        assertNotNull(client.getSession().getPeerCertificates());

        client.close();
        server.close();

        client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                context.host, context.port);
        server = (SSLSocket) context.serverSocket.accept();
        connect(client, server);

        assertNotNull(client.getSession().getPeerCertificates());

        client.close();
        server.close();
        context.close();
    }

    private static void connect(final SSLSocket client, final SSLSocket server)
            throws InterruptedException, ExecutionException {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        Future<Void> s = executor.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                server.startHandshake();
                return null;
            }
        });
        Future<Void> c = executor.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                client.startHandshake();
                return null;
            }
        });
        executor.shutdown();
        s.get();
        c.get();
    }

    @Test
    public void test_SSLSession_getPeerHost() {
        TestSSLSessions s = TestSSLSessions.create();
        assertNull(s.invalid.getPeerHost());
        assertNotNull(s.server.getPeerHost());
        assertNotNull(s.client.getPeerHost());
        s.close();
    }

    @Test
    public void test_SSLSession_getPeerPort() {
        TestSSLSessions s = TestSSLSessions.create();
        assertEquals(-1, s.invalid.getPeerPort());
        assertTrue(s.server.getPeerPort() > 0);
        assertEquals(s.s.c.port, s.client.getPeerPort());
        s.close();
    }

    @Test
    public void test_SSLSession_getPeerPrincipal() throws Exception {
        TestSSLSessions s = TestSSLSessions.create();
        try {
            s.invalid.getPeerPrincipal();
            fail();
        } catch (SSLPeerUnverifiedException expected) {
            // Ignored.
        }
        try {
            s.server.getPeerPrincipal();
            fail();
        } catch (SSLPeerUnverifiedException expected) {
            // Ignored.
        }
        assertNotNull(s.client.getPeerPrincipal());
        assertNotNull(s.client.getPeerPrincipal().getName());
        TestSSLContext.assertCertificateInKeyStore(
                s.client.getPeerPrincipal(), s.s.c.serverKeyStore);
        s.close();
    }

    @Test
    public void test_SSLSession_getProtocol() {
        TestSSLSessions s = TestSSLSessions.create();
        assertNotNull(s.invalid.getProtocol());
        assertEquals("NONE", s.invalid.getProtocol());
        assertNotNull(s.server.getProtocol());
        assertNotNull(s.client.getProtocol());
        assertEquals(s.server.getProtocol(), s.client.getProtocol());
        assertTrue(StandardNames.SSL_SOCKET_PROTOCOLS.contains(s.server.getProtocol()));
        s.close();
    }

    @Test
    public void test_SSLSession_getSessionContext() {
        TestSSLSessions s = TestSSLSessions.create();
        assertNull(s.invalid.getSessionContext());
        assertNotNull(s.server.getSessionContext());
        assertNotNull(s.client.getSessionContext());
        assertEquals(s.s.c.serverContext.getServerSessionContext(), s.server.getSessionContext());
        assertEquals(s.s.c.clientContext.getClientSessionContext(), s.client.getSessionContext());
        assertNotSame(s.server.getSessionContext(), s.client.getSessionContext());
        s.close();
    }

    @Test
    public void test_SSLSession_getValue() {
        TestSSLSessions s = TestSSLSessions.create();
        try {
            s.invalid.getValue(null);
            fail();
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
        assertNull(s.invalid.getValue("BOGUS"));
        s.close();
    }

    @Test
    public void test_SSLSession_getValueNames() {
        TestSSLSessions s = TestSSLSessions.create();
        assertNotNull(s.invalid.getValueNames());
        assertEquals(0, s.invalid.getValueNames().length);
        s.close();
    }

    @Test
    public void test_SSLSession_invalidate() {
        TestSSLSessions s = TestSSLSessions.create();

        assertFalse(s.invalid.isValid());
        s.invalid.invalidate();
        assertFalse(s.invalid.isValid());
        assertNull(s.invalid.getSessionContext());

        assertTrue(s.server.isValid());
        s.server.invalidate();
        assertFalse(s.server.isValid());
        assertNull(s.server.getSessionContext());

        assertTrue(s.client.isValid());
        s.client.invalidate();
        assertFalse(s.client.isValid());
        assertNull(s.client.getSessionContext());

        s.close();
    }

    @Test
    public void test_SSLSession_isValid() {
        TestSSLSessions s = TestSSLSessions.create();
        assertFalse(s.invalid.isValid());
        assertTrue(s.server.isValid());
        assertTrue(s.client.isValid());
        s.close();
    }

    @Test
    public void test_SSLSession_putValue() {
        TestSSLSessions s = TestSSLSessions.create();
        String key = "KEY";
        String value = "VALUE";
        assertNull(s.invalid.getValue(key));
        assertEquals(0, s.invalid.getValueNames().length);
        s.invalid.putValue(key, value);
        assertSame(value, s.invalid.getValue(key));
        assertEquals(1, s.invalid.getValueNames().length);
        assertEquals(key, s.invalid.getValueNames()[0]);
        s.close();
    }

    @Test
    public void test_SSLSession_removeValue() {
        TestSSLSessions s = TestSSLSessions.create();
        String key = "KEY";
        String value = "VALUE";
        s.invalid.putValue(key, value);
        assertEquals(1, s.invalid.getValueNames().length);
        assertEquals(key, s.invalid.getValueNames()[0]);
        s.invalid.removeValue(key);
        assertNull(s.invalid.getValue(key));
        assertEquals(0, s.invalid.getValueNames().length);
        s.close();
    }

    @Test
    public void test_SSLSession_BindingListener() {
        final TestSSLSessions s = TestSSLSessions.create();
        final String key = "KEY";
        final boolean[] bound = new boolean[] { false };
        final Object value = new SSLSessionBindingListener() {
            @Override
            public void valueBound(SSLSessionBindingEvent e) {
                assertEquals(s.client, e.getSession());
                assertEquals(key, e.getName());
                assertFalse(bound[0]);
                bound[0] = true;
            }

            @Override
            public void valueUnbound(SSLSessionBindingEvent e) {
                assertEquals(s.client, e.getSession());
                assertEquals(key, e.getName());
                assertTrue(bound[0]);
                bound[0] = false;
            }
        };
        s.client.putValue(key, value);
        assertSame(value, s.client.getValue(key));
        assertTrue(bound[0]);
        s.client.removeValue(key);
        assertFalse(bound[0]);
    }

    @Test
    public void test_SSLSession_valueIndependence() {
        // Multiple sessions should have independent value stores
        for (int i = 0; i < 2; i++) {
            TestSSLSessions s = TestSSLSessions.create();
            String key = "KEY";
            String value = "VALUE";
            assertNull(s.invalid.getValue(key));
            assertEquals(0, s.invalid.getValueNames().length);
            s.invalid.putValue(key, value);
            assertSame(value, s.invalid.getValue(key));
            assertEquals(1, s.invalid.getValueNames().length);
            assertEquals(key, s.invalid.getValueNames()[0]);
            s.close();
        }
    }

    private static String alterOriginalHostName(InetAddress inetAddress, String originalHostName)
            throws Exception {
        Method getHolder = InetAddress.class.getDeclaredMethod("holder");
        getHolder.setAccessible(true);

        Field originalHostNameField = Class.forName("java.net.InetAddress$InetAddressHolder")
                .getDeclaredField("originalHostName");
        originalHostNameField.setAccessible(true);

        Object holder = getHolder.invoke(inetAddress);
        String oldValue = (String)originalHostNameField.get(holder);
        originalHostNameField.set(holder, originalHostName);
        return oldValue;
    }

    // http://b/35942385
    @Test
    public void test_SSLSession_getPeerHostFromInetAddress() throws Exception {
        TestUtils.assumeAndroid();
        InetAddress inetAddress = TestUtils.getLoopbackAddress();
        String oldOriginalHostName = alterOriginalHostName(inetAddress, "foobar");
        try {
            final TestSSLContext c = TestSSLContext.create();
            final SSLSocket client = (SSLSocket) c.clientContext.getSocketFactory().createSocket(
                    TestUtils.getLoopbackAddress(), c.port);
            final SSLSocket server = (SSLSocket) c.serverSocket.accept();

            ExecutorService executor = Executors.newSingleThreadExecutor();
            Future<Void> future = executor.submit(new Callable<Void>() {
                                                      @Override
                                                      public Void call() throws Exception {
                                                          server.startHandshake();
                                                          return null;
                                                      }
                                                  });
            executor.shutdown();
            client.startHandshake();

            SSLSession sslSession = client.getSession();
            assertEquals("foobar", sslSession.getPeerHost());

            future.get();
            client.close();
            server.close();
            c.close();
        } finally {
            // Restore the original value (InetAddress objects are cached).
            alterOriginalHostName(inetAddress, oldOriginalHostName);
        }
    }
}
