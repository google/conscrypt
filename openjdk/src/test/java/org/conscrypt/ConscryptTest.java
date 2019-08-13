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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.SSLContext;
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
    public void testProviderBuilder() throws Exception {
        Provider p = Conscrypt.newProviderBuilder()
            .setName("test name")
            .provideTrustManager(true)
            .defaultTlsProtocol("TLSv1.2").build();

        assertEquals("test name", p.getName());
        assertTrue(p.containsKey("TrustManagerFactory.PKIX"));

        try {
            Security.insertProviderAt(p, 1);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            assertEquals(p, context.getProvider());
            Set<String> expected = new HashSet<>(Arrays.asList("TLSv1.2", "TLSv1.1", "TLSv1"));
            Set<String> found =
                new HashSet<>(Arrays.asList(context.createSSLEngine().getEnabledProtocols()));
            assertEquals(expected, found);

            context = SSLContext.getInstance("Default");
            assertEquals(p, context.getProvider());
            expected = new HashSet<>(Arrays.asList("TLSv1.2", "TLSv1.1", "TLSv1"));
            found = new HashSet<>(Arrays.asList(context.createSSLEngine().getEnabledProtocols()));
            assertEquals(expected, found);
        } finally {
            Security.removeProvider("test name");
        }

        p = Conscrypt.newProviderBuilder()
            .setName("test name 2")
            .provideTrustManager(false)
            .defaultTlsProtocol("TLSv1.3").build();

        assertEquals("test name 2", p.getName());
        assertFalse(p.containsKey("TrustManagerFactory.PKIX"));
        
        try {
            Security.insertProviderAt(p, 1);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            assertEquals(p, context.getProvider());
            Set<String> expected =
                new HashSet<>(Arrays.asList("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"));
            Set<String> found =
                new HashSet<>(Arrays.asList(context.createSSLEngine().getEnabledProtocols()));
            assertEquals(expected, found);

            context = SSLContext.getInstance("Default");
            assertEquals(p, context.getProvider());
            expected = new HashSet<>(Arrays.asList("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"));
            found = new HashSet<>(Arrays.asList(context.createSSLEngine().getEnabledProtocols()));
            assertEquals(expected, found);
        } finally {
            Security.removeProvider("test name 2");
        }

        try {
            Conscrypt.newProviderBuilder()
                .defaultTlsProtocol("invalid").build();
            fail();
        } catch (IllegalArgumentException expected) {
        }
    }
}
