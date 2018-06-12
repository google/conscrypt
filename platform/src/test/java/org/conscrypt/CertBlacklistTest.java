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

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import javax.net.ssl.X509TrustManager;
import junit.framework.TestCase;

public class CertBlacklistTest extends TestCase {

    private static final String BLACKLIST_CA = "test_blacklist_ca.pem";
    private static final String BLACKLISTED_CHAIN = "blacklist_test_chain.pem";
    private static final String BLACKLIST_FALLBACK_VALID_CA = "blacklist_test_valid_ca.pem";
    private static final String BLACKLISTED_VALID_CHAIN = "blacklist_test_valid_chain.pem";

    /**
     * Ensure that the test blacklisted CA is actually blacklisted by default.
     */
    public void testBlacklistedPublicKey() throws Exception {
        X509Certificate blacklistedCa = loadCertificate(BLACKLIST_CA);
        CertBlacklist blacklist = CertBlacklistImpl.getDefault();
        assertTrue(blacklist.isPublicKeyBlackListed(blacklistedCa.getPublicKey()));
    }

    /**
     * Check that the blacklisted CA is rejected even if it used as a root of trust
     */
    public void testBlacklistedCaUntrusted() throws Exception {
        X509Certificate blacklistedCa = loadCertificate(BLACKLIST_CA);
        assertUntrusted(new X509Certificate[] {blacklistedCa}, getTrustManager(blacklistedCa));
    }

    /**
     * Check that a chain that is rooted in a blacklisted trusted CA is rejected.
     */
    public void testBlacklistedRootOfTrust() throws Exception {
        // Chain is leaf -> blacklisted
        X509Certificate[] chain = loadCertificates(BLACKLISTED_CHAIN);
        X509Certificate blacklistedCa = loadCertificate(BLACKLIST_CA);
        assertUntrusted(chain, getTrustManager(blacklistedCa));
    }

    /** Test that the path building correctly routes around a blacklisted cert where there are
     * other valid paths available. This prevents breakage where a cert was cross signed by a
     * blacklisted CA but is still valid due to also being cross signed by CAs that remain trusted.
     * Path:
     *
     * leaf -> intermediate -> blacklisted_ca
     *               \
     *                -------> trusted_ca
     */
    public void testBlacklistedIntermediateFallback() throws Exception {
        X509Certificate[] chain = loadCertificates(BLACKLISTED_VALID_CHAIN);
        X509Certificate blacklistedCa = loadCertificate(BLACKLIST_CA);
        X509Certificate validCa = loadCertificate(BLACKLIST_FALLBACK_VALID_CA);
        assertTrusted(chain, getTrustManager(blacklistedCa, validCa));
        // Check that without the trusted_ca the chain is invalid (since it only chains to a
        // blacklisted ca)
        assertUntrusted(chain, getTrustManager(blacklistedCa));
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
