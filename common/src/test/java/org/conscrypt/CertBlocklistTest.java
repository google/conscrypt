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

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.conscrypt.metrics.NoopStatsLog;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;

import javax.net.ssl.X509TrustManager;

@RunWith(JUnit4.class)
public class CertBlocklistTest {
    private static final String BLOCKLIST_CA = "test_blocklist_ca.pem";
    private static final String BLOCKLIST_CA2 = "test_blocklist_ca2.pem";
    private static final String BLOCKLISTED_CHAIN = "blocklist_test_chain.pem";
    private static final String BLOCKLIST_FALLBACK_VALID_CA = "blocklist_test_valid_ca.pem";
    private static final String BLOCKLISTED_VALID_CHAIN = "blocklist_test_valid_chain.pem";
    // SPKI from Chromium's kSPKIBlockList
    // (2740d956b1127b791aa1b3cc644a4dbedba76186a23638b95102351a834ea861.pem), SHA-256 =
    // 04dde9aa9a79f61498682325fa0870276707fb9ca95384120b46893268494fc9 (entry 0).
    private static final String BUILT_IN_BLOCKLISTED_RSA_SPKI_BASE64 =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApfl1DAau7gwRzZYzTWvO"
            + "wEoMPV3r0ksJf+dHLKxxAPkIrzTxo2rH/OarztC+ys0qmJi50I4zSQdhINFaNM6D"
            + "FAZ5jhq/2+SgODrulLmjoFg6iRSsYD4D1MfNOxywmogaSRCpsLL95ejhBOLqgm3+"
            + "DFFFka11Iq7/T5ALwFNldz4ewla1NsbWhcwOgxozH3aZWyuXK4vX0RQVTJ1Z14Av"
            + "pKKF1Yg2AmBVyljfk/xKYgeW08T6v40BJ5cvplx08TpCbl15FDAxGjzZsldN4Lg/"
            + "D2kxop1lmdnWMYe1mCbf8Mu7FcAkE2JSGmvLRQeX48SUXskNRyzpz+n0j/414TLn"
            + "MQIDAQAB";
    // SPKI added in updated Chromium kSPKIBlockList
    // (9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4.pem), SHA-256 =
    // ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6 (entry 99).
    private static final String UPDATED_BUILT_IN_BLOCKLISTED_EC_SPKI_BASE64 =
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqrsPsGZqz88B+tUr/P1MK/LLPDSX3nOV"
            + "DlgZth/mlQmHQcjEkUObNKBDHK/+W/m0wcjorgAB+fTcitgsWfNjnpbNbD1NsM7+"
            + "wmw9YlF7N3YTcnQ/jordd7EAZPKr5eBQ";
    // SPKI present in both kSPKIBlockList and kKnownInterceptionList
    // (1df696f021ab1c3ace9a376b07ed7256a40214cd3396d7934087614924e2d7ef.pem),
    // SHA-256 = b13fa2e6131a888a01f3d62056fb0efbe999eb6b6e14927613e02ba8b8fb046e.
    private static final String KNOWN_INTERCEPTION_RSA_SPKI_BASE64 =
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuk3c6ihIdvnAiirmvpWs"
            + "v83rtXBvJNXvzBa7ZbEBjedU/2JysXoKNPYmKYRAB2TKMHVm8LfiLK7Sj04crQV+"
            + "0oc5iWQBiwv6G5RFJDdYapAp0uQBnmmZED5nnXc51/fuvDZgHAqFWgTuUTaCCwDJ"
            + "btdx7xL4TYeIfjErKpzACVmuxqxjxZauNJrzut5DV4oWBaxpta9sflq6gbZu5LXt"
            + "bP4FiYpi+lHeX1SwJpVscAZEqGVlShaBFJdC/HHBDbngo7E6oEPeYu8laPaxhoXl"
            + "aYo+w/DFjA+KPF3gKgkp5UhaneHVyAOgmrf2VByxjhe86ZD5HbVM2ar8srMMfNlw"
            + "QmPYzy4yf/yKPJeUbsWNMda5pgtNeAxss4HuOU/o5ejWoD4FKyMhUjeZyDTvWZ3T"
            + "mQ0YqJGd2frbjeqTiU+QnAjJi0mq3V7v5Kr6uMfFOLyZ6E+DEJIVgGNMLvIP4v5y"
            + "gjGJTGjhesF2EeNI3EG4qQEUj6bxGRSQOv1W2Dfum/Gck2ARPFUL0msz9+20Oh4x"
            + "0/jpCxvPgHyJK4gvbIxs7z+s4ZMuLVVCHb6gjLEMY9N4rCGmT1gsupD9lYYyvwdq"
            + "bttBZ8I5FgdqWzqIk9PIaVQjJ06u5zac9Nao2JrrAbbGKgbiRk5dwzjpZZFFlVs/"
            + "rd1rcbhVQ9r5Bjajh5o3sZ8CAwEAAQ==";

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

    /**
     * Test that the path building correctly routes around a blocklisted cert where there are
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

    static class FakeStatsLog extends NoopStatsLog {
        public ArrayList<CertBlocklistEntry> entries = new ArrayList<>();

        @Override
        public void reportBlocklistHit(CertBlocklistEntry entry) {
            entries.add(entry);
        }
    }

    @Test
    public void isPublicKeyBlockListed_hitBlocklist_hitIsReported() throws Exception {
        X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA);
        FakeStatsLog fakeMetrics = new FakeStatsLog();
        CertBlocklist blocklist =
                new CertBlocklistImpl.Builder().loadAllDefaults().setMetrics(fakeMetrics).build();

        blocklist.isPublicKeyBlockListed(blocklistedCa.getPublicKey());

        assertThat(fakeMetrics.entries).hasSize(1);
        CertBlocklistEntry entry = fakeMetrics.entries.get(0);
        assertThat(entry.getOrigin()).isEqualTo(CertBlocklistEntry.Origin.SHA1_TEST);
        assertThat(entry.getIndex()).isEqualTo(0);
    }

    @Test
    public void isPublicKeyBlockListed_hitBlocklistTwiceWithSameKey_hitIsReportedTwice()
            throws Exception {
        X509Certificate blocklistedCa = loadCertificate(BLOCKLIST_CA);
        FakeStatsLog fakeMetrics = new FakeStatsLog();
        CertBlocklist blocklist =
                new CertBlocklistImpl.Builder().loadAllDefaults().setMetrics(fakeMetrics).build();

        blocklist.isPublicKeyBlockListed(blocklistedCa.getPublicKey());
        blocklist.isPublicKeyBlockListed(blocklistedCa.getPublicKey());

        assertThat(fakeMetrics.entries).hasSize(2);
    }

    @Test
    public void isPublicKeyBlockListed_builtInKey_hitIsReported() throws Exception {
        PublicKey builtInBlockedKey =
                KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(
                        TestUtils.decodeBase64(BUILT_IN_BLOCKLISTED_RSA_SPKI_BASE64)));
        FakeStatsLog fakeMetrics = new FakeStatsLog();
        CertBlocklist blocklist =
                new CertBlocklistImpl.Builder().loadSha256Default().setMetrics(fakeMetrics).build();

        assertTrue(blocklist.isPublicKeyBlockListed(builtInBlockedKey));
        assertThat(fakeMetrics.entries).hasSize(1);
        CertBlocklistEntry entry = fakeMetrics.entries.get(0);
        assertThat(entry.getOrigin()).isEqualTo(CertBlocklistEntry.Origin.SHA256_BUILT_IN);
        assertThat(entry.getIndex()).isEqualTo(0);
    }

    @Test
    public void isPublicKeyBlockListed_updatedBlocklistKey_hitIsReported() throws Exception {
        PublicKey updatedBlockedKey =
                KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(
                        TestUtils.decodeBase64(UPDATED_BUILT_IN_BLOCKLISTED_EC_SPKI_BASE64)));
        FakeStatsLog fakeMetrics = new FakeStatsLog();
        CertBlocklist blocklist =
                new CertBlocklistImpl.Builder().loadSha256Default().setMetrics(fakeMetrics).build();

        assertTrue(blocklist.isPublicKeyBlockListed(updatedBlockedKey));
        assertThat(fakeMetrics.entries).hasSize(1);
        CertBlocklistEntry entry = fakeMetrics.entries.get(0);
        assertThat(entry.getOrigin()).isEqualTo(CertBlocklistEntry.Origin.SHA256_BUILT_IN);
        assertThat(entry.getIndex()).isEqualTo(99);
    }

    @Test
    public void isPublicKeyBlockListed_knownInterceptionKey_notBlocked() throws Exception {
        PublicKey knownInterceptionKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(TestUtils.decodeBase64(KNOWN_INTERCEPTION_RSA_SPKI_BASE64)));
        CertBlocklist blocklist = CertBlocklistImpl.getDefault();

        assertFalse(blocklist.isPublicKeyBlockListed(knownInterceptionKey));
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

    private static X509TrustManager getTrustManager(X509Certificate... trustedCas)
            throws Exception {
        TestUtils.assumeExtendedTrustManagerAvailable();
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
