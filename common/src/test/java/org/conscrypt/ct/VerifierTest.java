/*
 * Copyright (C) 2015 The Android Open Source Project
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

package org.conscrypt.ct;

import static org.conscrypt.TestUtils.openTestFile;
import static org.conscrypt.TestUtils.readTestFile;
import static org.junit.Assert.assertEquals;

import java.security.PublicKey;
import java.util.Arrays;
import org.conscrypt.OpenSSLX509Certificate;
import org.conscrypt.TestUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class VerifierTest {
    private OpenSSLX509Certificate ca;
    private OpenSSLX509Certificate cert;
    private OpenSSLX509Certificate certEmbedded;
    private Verifier ctVerifier;

    @Before
    public void setUp() throws Exception {
        ca = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem"));
        cert = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert.pem"));
        certEmbedded =
                OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert-ct-embedded.pem"));

        PublicKey key = TestUtils.readPublicKeyPemFile("ct-server-key-public.pem");

        final LogInfo log = new LogInfo(key, LogInfo.STATE_USABLE, "Test Log", "foo");
        LogStore store = new LogStore() {
            @Override
            public LogInfo getKnownLog(byte[] logId) {
                if (Arrays.equals(logId, log.getID())) {
                    return log;
                } else {
                    return null;
                }
            }
        };

        ctVerifier = new Verifier(store);
    }

    @Test
    public void test_verifySignedCertificateTimestamps_withOCSPResponse() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};

        byte[] ocspResponse = readTestFile("ocsp-response.der");
        VerificationResult result =
                ctVerifier.verifySignedCertificateTimestamps(chain, null, ocspResponse);
        assertEquals(1, result.getValidSCTs().size());
        assertEquals(0, result.getInvalidSCTs().size());
    }

    @Test
    public void test_verifySignedCertificateTimestamps_withTLSExtension() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};

        byte[] tlsExtension = readTestFile("ct-signed-timestamp-list");
        VerificationResult result =
                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
        assertEquals(1, result.getValidSCTs().size());
        assertEquals(0, result.getInvalidSCTs().size());
    }

    @Test
    public void test_verifySignedCertificateTimestamps_withEmbeddedExtension() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {certEmbedded, ca};

        VerificationResult result = ctVerifier.verifySignedCertificateTimestamps(chain, null, null);
        assertEquals(1, result.getValidSCTs().size());
        assertEquals(0, result.getInvalidSCTs().size());
    }

    @Test
    public void test_verifySignedCertificateTimestamps_withoutTimestamp() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};

        VerificationResult result = ctVerifier.verifySignedCertificateTimestamps(chain, null, null);
        assertEquals(0, result.getValidSCTs().size());
        assertEquals(0, result.getInvalidSCTs().size());
    }

    @Test
    public void test_verifySignedCertificateTimestamps_withInvalidSignature() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};

        byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-invalid");

        VerificationResult result =
                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
        assertEquals(0, result.getValidSCTs().size());
        assertEquals(1, result.getInvalidSCTs().size());
        assertEquals(VerifiedSCT.Status.INVALID_SIGNATURE, result.getInvalidSCTs().get(0).status);
    }

    @Test
    public void test_verifySignedCertificateTimestamps_withUnknownLog() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};

        byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-unknown");

        VerificationResult result =
                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
        assertEquals(0, result.getValidSCTs().size());
        assertEquals(1, result.getInvalidSCTs().size());
        assertEquals(VerifiedSCT.Status.UNKNOWN_LOG, result.getInvalidSCTs().get(0).status);
    }

    @Test
    public void test_verifySignedCertificateTimestamps_withInvalidEncoding() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};

        // Just some garbage data which will fail to deserialize
        byte[] tlsExtension = new byte[] {1, 2, 3, 4};

        VerificationResult result =
                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, null);
        assertEquals(0, result.getValidSCTs().size());
        assertEquals(0, result.getInvalidSCTs().size());
    }

    @Test
    public void test_verifySignedCertificateTimestamps_withInvalidOCSPResponse() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};

        // Just some garbage data which will fail to deserialize
        byte[] ocspResponse = new byte[] {1, 2, 3, 4};

        VerificationResult result =
                ctVerifier.verifySignedCertificateTimestamps(chain, null, ocspResponse);
        assertEquals(0, result.getValidSCTs().size());
        assertEquals(0, result.getInvalidSCTs().size());
    }

    @Test
    public void test_verifySignedCertificateTimestamps_withMultipleTimestamps() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {cert, ca};

        byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-invalid");
        byte[] ocspResponse = readTestFile("ocsp-response.der");

        VerificationResult result =
                ctVerifier.verifySignedCertificateTimestamps(chain, tlsExtension, ocspResponse);
        assertEquals(1, result.getValidSCTs().size());
        assertEquals(1, result.getInvalidSCTs().size());
        assertEquals(SignedCertificateTimestamp.Origin.OCSP_RESPONSE,
                result.getValidSCTs().get(0).sct.getOrigin());
        assertEquals(SignedCertificateTimestamp.Origin.TLS_EXTENSION,
                result.getInvalidSCTs().get(0).sct.getOrigin());
    }
}
