/*
 * Copyright 2018 The Android Open Source Project
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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.Provider;
import java.security.Security;
import javax.net.ssl.SSLContext;

import org.conscrypt.java.security.StandardNames;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ConscryptTest {

    /**
     * This confirms that the version machinery is working.
     */
    @Test
    public void testVersionIsSensible() {
        Conscrypt.Version version = Conscrypt.version();
        assertNotNull(version);
        // The version object should be a singleton
        assertSame(version, Conscrypt.version());

        assertTrue("Major version: " + version.major(), 1 <= version.major());
        assertTrue("Minor version: " + version.minor(), 0 <= version.minor());
        assertTrue("Patch version: " + version.patch(), 0 <= version.patch());
    }

    @Test
    public void buildTls12WithTrustManager() throws Exception {
        buildProvider("TLSv1.2", true);
    }
    @Test
    public void buildTls12WithoutTrustManager() throws Exception {
        buildProvider("TLSv1.2", false);
    }

    @Test
    public void buildTls13WithTrustManager() throws Exception {
        buildProvider("TLSv1.3", true);
    }

    @Test
    public void buildTls13WithoutTrustManager() throws Exception {
        buildProvider("TLSv1.3", false);
    }

    @Test
    public void buildInvalid() {
        try {
            Conscrypt.newProviderBuilder()
                .defaultTlsProtocol("invalid").build();
            fail();
        } catch (IllegalArgumentException e) {
            // Expected.
        }
    }

    private void buildProvider(String defaultProtocol, boolean withTrustManager) throws Exception {
        Provider provider = Conscrypt.newProviderBuilder()
            .setName("test name")
            .provideTrustManager(withTrustManager)
            .defaultTlsProtocol(defaultProtocol)
            .build();

        assertEquals("test name", provider.getName());
        assertEquals(withTrustManager, provider.containsKey("TrustManagerFactory.PKIX"));

        try {
            Security.insertProviderAt(provider, 1);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            assertEquals(provider, context.getProvider());
            StandardNames.assertSSLContextEnabledProtocols(
                defaultProtocol, context.createSSLEngine().getEnabledProtocols());


            context = SSLContext.getInstance("Default");
            assertEquals(provider, context.getProvider());
            StandardNames.assertSSLContextEnabledProtocols(
                defaultProtocol, context.createSSLEngine().getEnabledProtocols());
        } finally {
            Security.removeProvider("test name");
        }
    }
}
