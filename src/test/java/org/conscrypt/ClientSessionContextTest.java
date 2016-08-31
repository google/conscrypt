/*
 * Copyright (C) 2009 The Android Open Source Project
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

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.SSLSession;
import junit.framework.TestCase;
import libcore.javax.net.ssl.FakeSSLSession;

public final class ClientSessionContextTest extends TestCase {

    public void testSimpleAddition() {
        ClientSessionContext context = new ClientSessionContext();
        SSLSession a = new ValidSSLSession("a");
        SSLSession b = new ValidSSLSession("b");

        context.putSession(a);
        assertSessionContextContents(context, new SSLSession[] { a }, new SSLSession[] { b });

        context.putSession(b);
        assertSessionContextContents(context, new SSLSession[] { a, b }, new SSLSession[0]);
    }

    public void testTrimToSize() {
        ClientSessionContext context = new ClientSessionContext();
        ValidSSLSession a = new ValidSSLSession("a");
        ValidSSLSession b = new ValidSSLSession("b");
        ValidSSLSession c = new ValidSSLSession("c");
        ValidSSLSession d = new ValidSSLSession("d");

        context.putSession(a);
        assertSessionContextContents(context, new SSLSession[] { a }, new SSLSession[] { b, c, d });

        context.putSession(b);
        assertSessionContextContents(context, new SSLSession[] { a, b }, new SSLSession[] { c, d });

        context.putSession(c);
        assertSessionContextContents(context, new SSLSession[] { a, b, c }, new SSLSession[] { d });

        context.putSession(d);
        assertSessionContextContents(context, new SSLSession[] { a, b, c, d }, new SSLSession[0]);

        context.setSessionCacheSize(2);
        assertSessionContextContents(context, new SSLSession[] { c, d }, new SSLSession[] { a, b });
    }

    public void testImplicitRemovalOfOldest() {
        ClientSessionContext context = new ClientSessionContext();
        context.setSessionCacheSize(2);
        ValidSSLSession a = new ValidSSLSession("a");
        ValidSSLSession b = new ValidSSLSession("b");
        ValidSSLSession c = new ValidSSLSession("c");
        ValidSSLSession d = new ValidSSLSession("d");

        context.putSession(a);
        assertSessionContextContents(context, new SSLSession[] { a }, new SSLSession[] { b, c, d });

        context.putSession(b);
        assertSessionContextContents(context, new SSLSession[] { a, b }, new SSLSession[] { c, d });

        context.putSession(c);
        assertSessionContextContents(context, new SSLSession[] { b, c }, new SSLSession[] { a, d });

        context.putSession(d);
        assertSessionContextContents(context, new SSLSession[] { c, d }, new SSLSession[] { a, b });
    }

    public void testSerializeSession_NoStatusResponses() throws Exception {
        OpenSSLSessionImpl mockSession = mock(OpenSSLSessionImpl.class);
        when(mockSession.getId()).thenReturn(new byte[] { 0x11, 0x09, 0x03, 0x20 });
        when(mockSession.getPeerHost()).thenReturn("ssl.example.com");
        when(mockSession.getPeerPort()).thenReturn(443);
        when(mockSession.getEncoded()).thenReturn(new byte[] { 0x01, 0x02, 0x03 });
        when(mockSession.getStatusResponses()).thenReturn(Collections.<byte[]>emptyList());

        Certificate mockCert = mock(Certificate.class);
        when(mockCert.getEncoded()).thenReturn(new byte[] { 0x05, 0x06, 0x07, 0x10 });

        when(mockSession.getPeerCertificates()).thenReturn(new Certificate[] { mockCert });

        SSLClientSessionCache mockCache = mock(SSLClientSessionCache.class);
        ClientSessionContext context = new ClientSessionContext();
        context.setPersistentCache(mockCache);

        context.putSession(mockSession);
        verify(mockCache).putSessionData(eq(mockSession), any(byte[].class));
    }


    private static void assertSessionContextContents(ClientSessionContext context,
                                                     SSLSession[] contains,
                                                     SSLSession[] exludes) {
        assertEquals(contains.length, context.size());

        for (SSLSession s : contains) {
            assertSame(s.getPeerHost(), s, context.getSession(s.getId()));
            assertSame(s.getPeerHost(), s, context.getSession(s.getPeerHost(), 443));
        }
        for (SSLSession s : exludes) {
            assertNull(s.getPeerHost(), context.getSession(s.getId()));
            assertNull(s.getPeerHost(), context.getSession(s.getPeerHost(), 443));
        }

        Set<SSLSession> sessions = new HashSet<SSLSession>();
        Enumeration<byte[]> ids = context.getIds();
        while (ids.hasMoreElements()) {
            byte[] id = ids.nextElement();
            sessions.add(context.getSession(id));
        }

        Set<SSLSession> expected = new HashSet<SSLSession>();
        for (SSLSession s : sessions) {
            expected.add(s);
        }
        assertEquals(expected, sessions);
    }

    static class ValidSSLSession extends FakeSSLSession {
        ValidSSLSession(String host) {
            super(host);
        }
        @Override public boolean isValid() {
            return true;
        }
    }
}
