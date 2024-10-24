/*
 * Copyright (C) 2017 The Android Open Source Project
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.cert.Certificate;
import javax.net.ssl.SSLSession;
import org.junit.Before;
import org.junit.Test;

public abstract class AbstractSessionContextTest<T extends AbstractSessionContext> {
    private T context;

    @Before
    public void setup() {
        context = newContext();
    }

    abstract T newContext();
    abstract int size(T context);
    private static NativeSslSession[] toArray(NativeSslSession... sessions) {
        return sessions;
    }

    abstract NativeSslSession getCachedSession(T context, NativeSslSession s);

    @Test
    public void testSimpleAddition() {
        NativeSslSession a = newSession("a");
        NativeSslSession b = newSession("b");

        context.cacheSession(a);
        assertSessionContextContents(toArray(a), toArray(b));

        context.cacheSession(b);
        assertSessionContextContents(toArray(a, b), toArray());
    }

    @Test
    public void testTrimToSize() {
        NativeSslSession a = newSession("a");
        NativeSslSession b = newSession("b");
        NativeSslSession c = newSession("c");
        NativeSslSession d = newSession("d");

        context.cacheSession(a);
        context.cacheSession(b);
        context.cacheSession(c);
        context.cacheSession(d);
        assertSessionContextContents(toArray(a, b, c, d), toArray());

        context.setSessionCacheSize(2);
        assertSessionContextContents(toArray(c, d), toArray(a, b));
    }

    @Test
    public void testImplicitRemovalOfOldest() {
        context.setSessionCacheSize(2);
        NativeSslSession a = newSession("a");
        NativeSslSession b = newSession("b");
        NativeSslSession c = newSession("c");
        NativeSslSession d = newSession("d");

        context.cacheSession(a);
        assertSessionContextContents(toArray(a), toArray(b, c, d));

        context.cacheSession(b);
        assertSessionContextContents(toArray(a, b), toArray(c, d));

        context.cacheSession(c);
        assertSessionContextContents(toArray(b, c), toArray(a, d));

        context.cacheSession(d);
        assertSessionContextContents(toArray(c, d), toArray(a, b));
    }

    @Test
    public void testRemoveIfSingleUse() {
        NativeSslSession multi = new MockSessionBuilder().host("multi").singleUse(false).build();
        NativeSslSession single = new MockSessionBuilder().host("single").singleUse(true).build();

        context.cacheSession(multi);
        assertEquals(1, size(context));

        context.cacheSession(single);
        assertEquals(2, size(context));

        NativeSslSession out = getCachedSession(context, multi);
        assertEquals(multi, out);
        assertEquals(2, size(context));

        out = getCachedSession(context, single);
        assertEquals(single, out);
        assertEquals(1, size(context));

        assertNull(getCachedSession(context, single));
    }

    @Test
    public void testSerializeSession() throws Exception {
        byte[] encodedBytes = new byte[] {0x01, 0x02, 0x03};
        NativeSslSession session = new MockSessionBuilder()
                .id(new byte[] {0x11, 0x09, 0x03, 0x20})
                .host("ssl.example.com")
                .encodedBytes(encodedBytes)
                .build();

        SSLClientSessionCache mockCache = mock(SSLClientSessionCache.class);
        ClientSessionContext context = new ClientSessionContext();
        context.setPersistentCache(mockCache);

        context.cacheSession(session);
        verify(mockCache).putSessionData(any(SSLSession.class), same(encodedBytes));
    }

    private void assertSessionContextContents(
            NativeSslSession[] contains, NativeSslSession[] excludes) {
        assertEquals(contains.length, size(context));

        for (NativeSslSession s : contains) {
            assertSame(s.getPeerHost(), s, getCachedSession(context, s));
        }
        for (NativeSslSession s : excludes) {
            assertNull(s.getPeerHost(), getCachedSession(context, s));
        }
    }

    private NativeSslSession newSession(String host) {
        return new MockSessionBuilder().host(host).build();
    }
}
