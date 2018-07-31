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

import static org.conscrypt.MockSessionBuilder.DEFAULT_PORT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

import java.security.KeyManagementException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ClientSessionContextTest extends AbstractSessionContextTest<ClientSessionContext> {

    @Override
    ClientSessionContext newContext() {
        return new ClientSessionContext();
    }

    @Override
    NativeSslSession getCachedSession(ClientSessionContext context, NativeSslSession s) {
        return context.getCachedSession(s.getPeerHost(), DEFAULT_PORT,
                getDefaultSSLParameters());
    }

    @Override
    int size(ClientSessionContext context) {
        return context.size();
    }

    private static SSLParametersImpl getDefaultSSLParameters() {
        try {
            return SSLParametersImpl.getDefault();
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testNoMixingOfSingleAndMultiUseSessions() {
        ClientSessionContext context = newContext();

        NativeSslSession a = new MockSessionBuilder().host("a").singleUse(false).build();
        NativeSslSession bSingle1 = new MockSessionBuilder()
                .id(new byte[] {1}).host("b").singleUse(true).build();
        NativeSslSession bSingle2 = new MockSessionBuilder()
                .id(new byte[] {2}).host("b").singleUse(true).build();
        NativeSslSession bMulti = new MockSessionBuilder()
                .id(new byte[] {3}).host("b").singleUse(false).build();

        context.cacheSession(a);
        assertEquals(1, size(context));

        context.cacheSession(bSingle1);
        assertEquals(2, size(context));

        context.cacheSession(bSingle2);
        assertEquals(3, size(context));

        context.cacheSession(bMulti);
        assertEquals(2, size(context));

        NativeSslSession out = context.getCachedSession(
                "b", DEFAULT_PORT, getDefaultSSLParameters());
        assertEquals(bMulti, out);

        context.cacheSession(bSingle2);
        assertEquals(2, size(context));

        out = context.getCachedSession("b", DEFAULT_PORT, getDefaultSSLParameters());
        assertEquals(bSingle2, out);

        out = context.getCachedSession("b", DEFAULT_PORT, getDefaultSSLParameters());
        assertNull(out);
    }

    @Test
    public void testCanRetrieveMultipleSingleUseSessions() {
        ClientSessionContext context = newContext();

        NativeSslSession single1 = new MockSessionBuilder()
                .id(new byte[] {1}).host("host").singleUse(true).build();
        NativeSslSession single2 = new MockSessionBuilder()
                .id(new byte[] {2}).host("host").singleUse(true).build();

        context.cacheSession(single1);
        assertEquals(1, size(context));

        context.cacheSession(single2);
        assertEquals(2, size(context));

        assertSame(single1,
                context.getCachedSession("host", DEFAULT_PORT, getDefaultSSLParameters()));
        assertEquals(1, size(context));
        assertSame(single2,
                context.getCachedSession("host", DEFAULT_PORT, getDefaultSSLParameters()));
        assertEquals(0, size(context));
    }
}
