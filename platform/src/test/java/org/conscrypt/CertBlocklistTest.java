/*
 * Copyright (C) 2016 The Android Open Source Project
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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import javax.net.ssl.X509TrustManager;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CertBlocklistTest {

    private static final String BLOCKLIST_CA = "test_blocklist_ca.pem";
    private static final String BLOCKLIST_CA2 = "test_blocklist_ca2.pem";
    private static final String BLOCKLISTED_CHAIN = "blocklist_test_chain.pem";
    private static final String BLOCKLIST_FALLBACK_VALID_CA = "blocklist_test_valid_ca.pem";
    private static final String BLOCKLISTED_VALID_CHAIN = "blocklist_test_valid_chain.pem";

    /**
     * Ensure that the test blocklisted CA is actually blocklisted by default.
     */
    @Test
    public void testBlocklistedPublicKey() throws Exception {
        X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA);
        CertBlocklist blocklist = CertBlocklistImpl.getDefault();
        assertTrue(blocklist.isPublicKeyBlockListed(blocklistedCa.getPublicKey()));
    }

    /**
     * Ensure that the test blocklisted CA 2 is actually blocklisted by default.
     */
    @Test
    public void testBlocklistedPublicKeySHA256() throws Exception {
        X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA2);
        CertBlocklist blocklist = CertBlocklistImpl.getDefault();
        assertTrue(blocklist.isPublicKeyBlockListed(blocklistedCa.getPublicKey()));
    }

    /**
     * Check that the blocklisted CA is rejected even if it used as a root of trust
     */
    @Test
    public void testBlocklistedCaUntrusted() throws Exception {
        X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA);
        assertUntrusted(new X509Certificate[] {blocklistedCa}, getTrustManager(blocklistedCa));
    }

    /**
     * Check that a chain that is rooted in a blocklisted trusted CA is rejected.
     */
    @Test
    public void testBlocklistedRootOfTrust() throws Exception {
        // Chain is leaf -> blocklisted
        X509Certificate[] chain = loadCertificates(BLOCKLISTED_CHAIN);
        X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA);
        assertUntrusted(chain, getTrustManager(blocklistedCa));
    }

    /** Test that the path building correctly routes around a blocklisted cert where there are
     * other valid paths available. This prevents breakage where a cert was cross signed by a
     * blocklisted CA but is still valid due to also being cross signed by CAs that remain trusted.
     * Path:
     *
     * leaf -> intermediate -> blocklisted_ca
     *               \
     *                -------> trusted_ca
     */
    @Test
    public void testBlocklistedIntermediateFallback() throws Exception {
        X509Certificate[] chain = loadCertificates(BLOCKLISTED_VALID_CHAIN);
        X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA);
        X509Certificate validCa = loadCertificate(BLOCKLIST_FALLBACK_VALID_CA);
        assertTrusted(chain, getTrustManager(blocklistedCa, validCa));
        // Check that without the trusted_ca the chain is invalid (since it only chains to a
        // blocklisted ca)
        assertUntrusted(chain, getTrustManager(blocklistedCa));
    }

    private static X509Certificate loadCertificate(String file) throws Exception {
        return loadCertificates(file)[0];
    }

    private static X509Certificate[] loadCertificates(String file) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream is = TestUtils.openTestFile(file)) {
            Collection<? extends Certificate> collection = factory.generateCertificates(is);
            is.close();
            X509Certificate[] certs = new X509Certificate[collection.size()];
            int i = 0;
            for (Certificate cert : collection) {
                certs[i++] = (X509Certificate) cert;
            }
            return certs;
        }
    }

    private static TrustManagerImpl getTrustManager(X509Certificate... trustedCas)
            throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null);
        int i = 0;
        for (X509Certificate ca : trustedCas) {
            ks.setCertificateEntry(String.valueOf(i++), ca);
        }
        return new TrustManagerImpl(ks);
    }

    private static void assertTrusted(X509Certificate[] certs, X509TrustManager tm)
            throws Exception {
        tm.checkServerTrusted(certs, "RSA");
    }

    private static void assertUntrusted(X509Certificate[] certs, X509TrustManager tm) {
        try {
            tm.checkServerTrusted(certs, "RSA");
            fail();
        } catch (CertificateException expected) {
        }
    }
}
