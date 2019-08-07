/*
 * Copyright (C) 2019 The Android Open Source Project
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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.SignatureException;
import java.security.cert.CRLReason;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collections;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class X509CRLTest {

    private static final String CA_CERT =
        "-----BEGIN CERTIFICATE-----\n"
            + "MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk\n"
            + "MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX\n"
            + "YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw\n"
            + "MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu\n"
            + "c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf\n"
            + "MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7\n"
            + "jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP\n"
            + "KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL\n"
            + "svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk\n"
            + "tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG\n"
            + "A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO\n"
            + "MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB\n"
            + "/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt\n"
            + "OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy\n"
            + "f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP\n"
            + "OwqULg==\n"
            + "-----END CERTIFICATE-----\n";

    private static final String REVOKED_CERT =
        "-----BEGIN CERTIFICATE-----\n"
            + "MIICyjCCAjOgAwIBAgIBBzANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk\n"
            + "MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX\n"
            + "YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw\n"
            + "MDAwMDBaMFIxCzAJBgNVBAYTAkdCMSEwHwYDVQQKExhDZXJ0aWZpY2F0ZSBUcmFu\n"
            + "c3BhcmVuY3kxDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGfMA0G\n"
            + "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+75jnwmh3rjhfdTJaDB0ym+3xj6r015a/\n"
            + "BH634c4VyVui+A7kWL19uG+KSyUhkaeb1wDDjpwDibRc1NyaEgqyHgy0HNDnKAWk\n"
            + "EM2cW9tdSSdyba8XEPYBhzd+olsaHjnu0LiBGdwVTcaPfajjDK8VijPmyVCfSgWw\n"
            + "FAn/Xdh+tQIDAQABo4GsMIGpMB0GA1UdDgQWBBQgMVQa8lwF/9hli2hDeU9ekDb3\n"
            + "tDB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkGA1UE\n"
            + "BhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEOMAwG\n"
            + "A1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwCQYDVR0TBAIwADANBgkq\n"
            + "hkiG9w0BAQUFAAOBgQAEWQDIDds2NTDt4ySO6fDthUXoBcp+LM1ipk6dKKgC94J5\n"
            + "k1lta//1sl4/PEgEKnuk5APH87zgzG0it8EjurQg2SNlHlhGZ86AmZSCwHvmk8z9\n"
            + "g7HSVIKtrKOdMhrHE3nW649PWUdRcbGjCeaC9MTxWv9cGC7NqDKRNcGWWiN3Dg==\n"
            + "-----END CERTIFICATE-----\n";

    private static final String CRL =
        "-----BEGIN X509 CRL-----\n"
            + "MIIBUTCBuwIBATANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJHQjEkMCIGA1UE\n"
            + "ChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVXYWxlczEQ\n"
            + "MA4GA1UEBxMHRXJ3IFdlbhcNMTkwODA3MTAyNzEwWhcNMTkwOTA2MTAyNzEwWjAi\n"
            + "MCACAQcXDTE5MDgwNzEwMjY1NFowDDAKBgNVHRUEAwoBAaAOMAwwCgYDVR0UBAMC\n"
            + "AQIwDQYJKoZIhvcNAQELBQADgYEAzF/DLiIvZDX4FpSjNCnwKRblnhJLZ1NNBAHx\n"
            + "cRbfFY3psobvbGGOjxzCQW/03gkngG5VrSfdVOLMmQDrAxpKqeYqFDj0HAenWugb\n"
            + "CCHWAw8WN9XSJ4nGxdRiacG/5vEIx00ICUGCeGcnqWsSnFtagDtvry2c4MMexbSP\n"
            + "nDN0LLg=\n"
            + "-----END X509 CRL-----\n";

    @Test
    public void testCrl() throws Exception {
        ServiceTester.test("CertificateFactory")
            .withAlgorithm("X509")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    CertificateFactory cf = CertificateFactory.getInstance("X509", p);

                    X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(CRL.getBytes(
                            StandardCharsets.US_ASCII)));
                    X509Certificate revoked = (X509Certificate) cf.generateCertificate(
                            new ByteArrayInputStream(REVOKED_CERT.getBytes(StandardCharsets.US_ASCII)));
                    X509Certificate ca = (X509Certificate) cf.generateCertificate(
                            new ByteArrayInputStream(CA_CERT.getBytes(StandardCharsets.US_ASCII)));

                    assertEquals("SHA256WITHRSA", crl.getSigAlgName().toUpperCase());
                    crl.verify(ca.getPublicKey());
                    try {
                        crl.verify(revoked.getPublicKey());
                        fail();
                    } catch (SignatureException expected) {
                    }

                    assertTrue(crl.isRevoked(revoked));
                    X509CRLEntry entry = crl.getRevokedCertificate(revoked);
                    assertEquals(CRLReason.KEY_COMPROMISE, entry.getRevocationReason());
                    assertTrue(entry.getCriticalExtensionOIDs().isEmpty());
                    assertEquals(Collections.singleton("2.5.29.21"), entry.getNonCriticalExtensionOIDs());
                    assertFalse(entry.hasUnsupportedCriticalExtension());

                    assertFalse(crl.isRevoked(ca));
                    assertNull(crl.getRevokedCertificate(ca));

                    assertEquals(Collections.singleton(entry), crl.getRevokedCertificates());
                }
            });
    }
}
