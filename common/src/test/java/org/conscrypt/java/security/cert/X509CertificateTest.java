/*
 * Copyright (C) 2018 The Android Open Source Project
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

package org.conscrypt.java.security.cert;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class X509CertificateTest {

    private static final String VALID_CERT =
            "-----BEGIN CERTIFICATE-----\n"
            + "MIIFMjCCAxqgAwIBAgIJAL0mG5fOeJ7xMA0GCSqGSIb3DQEBCwUAMC0xCzAJBgNV\n"
            + "BAYTAkdCMQ8wDQYDVQQHDAZMb25kb24xDTALBgNVBAoMBFRlc3QwIBcNMTgwOTE3\n"
            + "MTIxNzU3WhgPMjExODA4MjQxMjE3NTdaMC0xCzAJBgNVBAYTAkdCMQ8wDQYDVQQH\n"
            + "DAZMb25kb24xDTALBgNVBAoMBFRlc3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw\n"
            + "ggIKAoICAQDCMhBrRAGGw+n2GdctBr/cEK4FZA6ajiHjihgpCHoSBdyL4R2jGKLS\n"
            + "g0WgaMXa1HpkKN7LcIySosEBPlmcRkr1RqbEvQStOSvoFCXYvtx3alM6HTbXMcDR\n"
            + "mqoKoABP6LXsPSoMWIgqMtP2X9EOppzHVIK1yFYFfbIlvYUV2Ka+MuMe0Vh5wvD1\n"
            + "4GanPb+cWSKgdRSVQovCCMY3yWtZKVEaxRpCsk/mYYIFWz0tcgMjIKwDx1XXgiAV\n"
            + "nU6NK43xbaw3XhtnaD/pv9lhTTbNrlcln9LjTD097BaK4R+1AEPHnpfxA9Ui3upn\n"
            + "kbsNUdGdOB0ksZi/vd7lh833YgquQUIAhYrbfvq/HFCpVV1gljzlS3sqULYpLE//\n"
            + "i3OsuL2mE+CYIJGpIi2GeJJWXciNMTJDOqTn+fRDtVb4RPp4Y70DJirp7XzaBi3q\n"
            + "H0edANCzPSRCDbZsOhzIXhXshldiXVRX666DDlbMQgLTEnNKrkwv6DmU8o15XQsb\n"
            + "8k1Os2YwXmkEOxUQ7AJZXVTZSf6UK9Znmdq1ZrHjybMfRUkHVxJcnKvrxfryralv\n"
            + "gzfvu+D6HuxrCo3Ojqa+nDgIbxKEBtdrcsMhq1jWPFhjwo1fSadAkKOfdCAuXJRD\n"
            + "THg3b4Sf+W7Cpc570YHrIpBf7WFl2XsPcEM0mJZ5+yATASCubNozQwIDAQABo1Mw\n"
            + "UTAdBgNVHQ4EFgQUES0hupZSqY21JOba10QyZuxm91EwHwYDVR0jBBgwFoAUES0h\n"
            + "upZSqY21JOba10QyZuxm91EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsF\n"
            + "AAOCAgEABTN5S30ng/RMpBweDm2N561PdpaCdiRXtAFCRVWR2mkDYC/Xj9Vqe6be\n"
            + "PyM7L/5OKYVjzF1yJu67z/dx+ja5o+41g17jdqla7hyPx+9B4uRyDh+1KJTa+duj\n"
            + "mw/aA1LCr6O6W4WizDOsChJ6FaB2Y1+GlFnKWb5nUdhVJqXQE1WOX9dZnw8Y4Npd\n"
            + "VmAsjWot0BZorJrt3fwfcv3QfA896twkbo7Llv/8qzg4sXZXZ4ZtgAOqnPngiSn+\n"
            + "JT/vYCXZ406VvAFpFqMcVz2dO/VGuL8lGIMHRKNyafrsV81EzH1W/XmRWOgvgj6r\n"
            + "yQI63ln/AMY72HQ97xLkE1xKunGz6bK5Ug5+O43Uftc4Mb6MUgzo+ZqEQ3Ob+cAV\n"
            + "cvjmtwDaPO/O39O5Xq0tLTlkn2/cKf4OQ6S++GDxzyRVHh5JXgP4j9+jfZY57Woy\n"
            + "R1bE7N50JjY4cDermBJKdlBIjL7UPhqmLyaG7V0hBitFlgGBUCcJtJOV0xYd5aF3\n"
            + "pxNkvMXhBmh95fjxJ0cJjpO7tN1RAwtMMNgsl7OUbuVRQCHOPW5DgP5qY21jDeRn\n"
            + "BY82382l+9QzykmJLI5MZnmj4BA9uIDCwMtoTTvP++SsvhUAbuvh7MOOUQL0EY4m\n"
            + "KStYq7X9PKseN+PvmfeoffIKc5R/Ha39oi7cGMVHCr8aiEhsf94=\n"
            + "-----END CERTIFICATE-----";

    /*
     This certificate is a modified version of the above self-signed cert. The cert has
     been modified to change the certificate data's signature algorithm
     declaration from sha256withRSAEncryption to sha512withRSAEncryption.  This causes
     the signature block's algorithm (which is unmodified) to not match the cert info.
     */
    private static final String MISMATCHED_ALGORITHM_CERT =
            "-----BEGIN CERTIFICATE-----\n"
            + "MIIFMjCCAxqgAwIBAgIJAL0mG5fOeJ7xMA0GCSqGSIb3DQEBDQUAMC0xCzAJBgNV\n"
            + "BAYTAkdCMQ8wDQYDVQQHDAZMb25kb24xDTALBgNVBAoMBFRlc3QwIBcNMTgwOTE3\n"
            + "MTIxNzU3WhgPMjExODA4MjQxMjE3NTdaMC0xCzAJBgNVBAYTAkdCMQ8wDQYDVQQH\n"
            + "DAZMb25kb24xDTALBgNVBAoMBFRlc3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw\n"
            + "ggIKAoICAQDCMhBrRAGGw+n2GdctBr/cEK4FZA6ajiHjihgpCHoSBdyL4R2jGKLS\n"
            + "g0WgaMXa1HpkKN7LcIySosEBPlmcRkr1RqbEvQStOSvoFCXYvtx3alM6HTbXMcDR\n"
            + "mqoKoABP6LXsPSoMWIgqMtP2X9EOppzHVIK1yFYFfbIlvYUV2Ka+MuMe0Vh5wvD1\n"
            + "4GanPb+cWSKgdRSVQovCCMY3yWtZKVEaxRpCsk/mYYIFWz0tcgMjIKwDx1XXgiAV\n"
            + "nU6NK43xbaw3XhtnaD/pv9lhTTbNrlcln9LjTD097BaK4R+1AEPHnpfxA9Ui3upn\n"
            + "kbsNUdGdOB0ksZi/vd7lh833YgquQUIAhYrbfvq/HFCpVV1gljzlS3sqULYpLE//\n"
            + "i3OsuL2mE+CYIJGpIi2GeJJWXciNMTJDOqTn+fRDtVb4RPp4Y70DJirp7XzaBi3q\n"
            + "H0edANCzPSRCDbZsOhzIXhXshldiXVRX666DDlbMQgLTEnNKrkwv6DmU8o15XQsb\n"
            + "8k1Os2YwXmkEOxUQ7AJZXVTZSf6UK9Znmdq1ZrHjybMfRUkHVxJcnKvrxfryralv\n"
            + "gzfvu+D6HuxrCo3Ojqa+nDgIbxKEBtdrcsMhq1jWPFhjwo1fSadAkKOfdCAuXJRD\n"
            + "THg3b4Sf+W7Cpc570YHrIpBf7WFl2XsPcEM0mJZ5+yATASCubNozQwIDAQABo1Mw\n"
            + "UTAdBgNVHQ4EFgQUES0hupZSqY21JOba10QyZuxm91EwHwYDVR0jBBgwFoAUES0h\n"
            + "upZSqY21JOba10QyZuxm91EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsF\n"
            + "AAOCAgEABTN5S30ng/RMpBweDm2N561PdpaCdiRXtAFCRVWR2mkDYC/Xj9Vqe6be\n"
            + "PyM7L/5OKYVjzF1yJu67z/dx+ja5o+41g17jdqla7hyPx+9B4uRyDh+1KJTa+duj\n"
            + "mw/aA1LCr6O6W4WizDOsChJ6FaB2Y1+GlFnKWb5nUdhVJqXQE1WOX9dZnw8Y4Npd\n"
            + "VmAsjWot0BZorJrt3fwfcv3QfA896twkbo7Llv/8qzg4sXZXZ4ZtgAOqnPngiSn+\n"
            + "JT/vYCXZ406VvAFpFqMcVz2dO/VGuL8lGIMHRKNyafrsV81EzH1W/XmRWOgvgj6r\n"
            + "yQI63ln/AMY72HQ97xLkE1xKunGz6bK5Ug5+O43Uftc4Mb6MUgzo+ZqEQ3Ob+cAV\n"
            + "cvjmtwDaPO/O39O5Xq0tLTlkn2/cKf4OQ6S++GDxzyRVHh5JXgP4j9+jfZY57Woy\n"
            + "R1bE7N50JjY4cDermBJKdlBIjL7UPhqmLyaG7V0hBitFlgGBUCcJtJOV0xYd5aF3\n"
            + "pxNkvMXhBmh95fjxJ0cJjpO7tN1RAwtMMNgsl7OUbuVRQCHOPW5DgP5qY21jDeRn\n"
            + "BY82382l+9QzykmJLI5MZnmj4BA9uIDCwMtoTTvP++SsvhUAbuvh7MOOUQL0EY4m\n"
            + "KStYq7X9PKseN+PvmfeoffIKc5R/Ha39oi7cGMVHCr8aiEhsf94=\n"
            + "-----END CERTIFICATE-----\n";

    /**
     * This cert has an EC key with curve prime256v1 encoded using explicit params.
     */
    private static final String EC_EXPLICIT_KEY_CERT =
            "-----BEGIN CERTIFICATE-----\n"
            + "MIICAjCCAagCCQCrIzClvU58azAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDARUZXN0\n"
            + "MB4XDTE4MTAwMjEyNDQzMloXDTE4MTEwMTEyNDQzMlowDzENMAsGA1UEAwwEVGVz\n"
            + "dDCCAUswggEDBgcqhkjOPQIBMIH3AgEBMCwGByqGSM49AQECIQD/////AAAAAQAA\n"
            + "AAAAAAAAAAAAAP///////////////zBbBCD/////AAAAAQAAAAAAAAAAAAAAAP//\n"
            + "/////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsDFQDE\n"
            + "nTYIhucEk2pmeOETnSa3gZ9+kARBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPSh\n"
            + "OUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfUCIQD/////AAAA\n"
            + "AP//////////vOb6racXnoTzucrC/GMlUQIBAQNCAAQXU+GFdLabcY/RvzoNjLhC\n"
            + "6uN1Yt1baN2NYyKYEhwR9nb8nLa/m7f30OOi/8OrxQhnUl5qW0I0IbHflGnsqQ6s\n"
            + "MAoGCCqGSM49BAMCA0gAMEUCIQDRXoZwmnsIJfg4mTemkM+heMS1iXRYUO0Dar5u\n"
            + "Qhy0YgIgYWr0qSCLqxUQv3oQHMUpSmfHtP0Pwvb3DbbH6lY7TkI=\n"
            + "-----END CERTIFICATE-----\n";

    // See issue #539.
    @Test
    public void testMismatchedAlgorithm() throws Exception {
        ServiceTester.test("CertificateFactory")
            .withAlgorithm("X509")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    CertificateFactory cf = CertificateFactory.getInstance("X509", p);
                    try {
                        Certificate c = cf.generateCertificate(new ByteArrayInputStream(
                            MISMATCHED_ALGORITHM_CERT.getBytes(Charset.forName("US-ASCII"))));
                        c.verify(c.getPublicKey());
                        fail();
                    } catch (CertificateException expected) {
                    }
                }
            });
    }

    /**
     * Confirm that explicit EC params aren't accepted in certificates.
     */
    @Test
    public void testExplicitEcParams() throws Exception {
        ServiceTester.test("CertificateFactory")
            .withAlgorithm("X509")
            // Bouncy Castle allows explicit EC params in certificates, even though they're
            // barred by RFC 5480
            .skipProvider("BC")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    try {
                        CertificateFactory cf = CertificateFactory.getInstance("X509", p);
                        Certificate c = cf.generateCertificate(new ByteArrayInputStream(
                            EC_EXPLICIT_KEY_CERT.getBytes(Charset.forName("US-ASCII"))));
                        c.verify(c.getPublicKey());
                        fail();
                    } catch (InvalidKeyException expected) {
                        // TODO: Should we throw CertificateParsingException at parse time
                        // instead of waiting for when the user accesses the key?
                    } catch (CertificateParsingException expected) {
                    }
                }
            });
    }

    @Test
    public void testSigAlgName() throws Exception {
        ServiceTester.test("CertificateFactory")
            .withAlgorithm("X509")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    CertificateFactory cf = CertificateFactory.getInstance("X509", p);
                    Certificate c = cf.generateCertificate(new ByteArrayInputStream(
                        VALID_CERT.getBytes(Charset.forName("US-ASCII"))));
                    assertEquals("SHA256WITHRSA",
                        ((X509Certificate) c).getSigAlgName().toUpperCase());
                }
            });
    }
}
