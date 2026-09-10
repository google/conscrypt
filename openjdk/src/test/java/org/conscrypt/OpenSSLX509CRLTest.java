/*
 * Copyright 2026 The Android Open Source Project
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

import static org.conscrypt.TestUtils.openTestFile;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import static java.nio.charset.StandardCharsets.US_ASCII;

import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

@RunWith(JUnit4.class)
public class OpenSSLX509CRLTest {
    private static final String VALID_CRL_PKCS7_PEM = "-----BEGIN PKCS7-----\n"
            + "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgAKGCAVUw\n"
            + "ggFRMIG7AgEBMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQK\n"
            + "ExtDZXJ0aWZpY2F0ZSBUcmFuc3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAw\n"
            + "DgYDVQQHEwdFcncgV2VuFw0xOTA4MDcxMDI3MTBaFw0xOTA5MDYxMDI3MTBaMCIw\n"
            + "IAIBBxcNMTkwODA3MTAyNjU0WjAMMAoGA1UdFQQDCgEBoA4wDDAKBgNVHRQEAwIB\n"
            + "AjANBgkqhkiG9w0BAQsFAAOBgQDMX8MuIi9kNfgWlKM0KfApFuWeEktnU00EAfFx\n"
            + "Ft8Vjemyhu9sYY6PHMJBb/TeCSeAblWtJ91U4syZAOsDGkqp5ioUOPQcB6da6BsI\n"
            + "IdYDDxY31dInicbF1GJpwb/m8QjHTQgJQYJ4ZyepaxKcW1qAO2+vLZzgwx7FtI+c\n"
            + "M3QsuDEA\n"
            + "-----END PKCS7-----\n";

    private static final String VALID_CRL_PKCS7_DER_BASE64 =
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgAKGCAVUw"
            + "ggFRMIG7AgEBMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQK"
            + "ExtDZXJ0aWZpY2F0ZSBUcmFuc3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAw"
            + "DgYDVQQHEwdFcncgV2VuFw0xOTA4MDcxMDI3MTBaFw0xOTA5MDYxMDI3MTBaMCIw"
            + "IAIBBxcNMTkwODA3MTAyNjU0WjAMMAoGA1UdFQQDCgEBoA4wDDAKBgNVHRQEAwIB"
            + "AjANBgkqhkiG9w0BAQsFAAOBgQDMX8MuIi9kNfgWlKM0KfApFuWeEktnU00EAfFx"
            + "Ft8Vjemyhu9sYY6PHMJBb/TeCSeAblWtJ91U4syZAOsDGkqp5ioUOPQcB6da6BsI"
            + "IdYDDxY31dInicbF1GJpwb/m8QjHTQgJQYJ4ZyepaxKcW1qAO2+vLZzgwx7FtI+c"
            + "M3QsuDEA";

    private static final String UNKNOWN_SIGNATURE_OID = "-----BEGIN X509 CRL-----\n"
            + "MIIBVzCBvgIBATAQBgwqhkiG9xIEAYS3CQIFADBVMQswCQYDVQQGEwJHQjEkMCIG\n"
            + "A1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVXYWxl\n"
            + "czEQMA4GA1UEBxMHRXJ3IFdlbhcNMTkwODA3MTAyNzEwWhcNMTkwOTA2MTAyNzEw\n"
            + "WjAiMCACAQcXDTE5MDgwNzEwMjY1NFowDDAKBgNVHRUEAwoBAaAOMAwwCgYDVR0U\n"
            + "BAMCAQIwEAYMKoZIhvcSBAGEtwkCBQADgYEAzF/DLiIvZDX4FpSjNCnwKRblnhJL\n"
            + "Z1NNBAHxcRbfFY3psobvbGGOjxzCQW/03gkngG5VrSfdVOLMmQDrAxpKqeYqFDj0\n"
            + "HAenWugbCCHWAw8WN9XSJ4nGxdRiacG/5vEIx00ICUGCeGcnqWsSnFtagDtvry2c\n"
            + "4MMexbSPnDN0LLg=\n"
            + "-----END X509 CRL-----\n";

    private OpenSSLX509CRL loadTestCrl(String name) throws FileNotFoundException, ParsingException {
        return OpenSSLX509CRL.fromX509PemInputStream(openTestFile(name));
    }

    private OpenSSLX509Certificate loadTestCertificate(String name)
            throws FileNotFoundException, ParsingException {
        return OpenSSLX509Certificate.fromX509PemInputStream(openTestFile(name));
    }

    @Test
    public void fromX509PemInputStream_success() throws Exception {
        OpenSSLX509CRL crl = loadTestCrl("crl.pem");
        assertNotNull(crl);
        assertEquals(2, crl.getVersion());
    }

    @Test
    public void fromX509PemInputStream_emptyThrows() {
        assertThrows(
                ParsingException.class,
                () -> OpenSSLX509CRL.fromX509PemInputStream(new ByteArrayInputStream(new byte[0])));
    }

    @Test
    public void fromX509PemInputStream_invalidThrows() {
        assertThrows(ParsingException.class,
                     ()
                             -> OpenSSLX509CRL.fromX509PemInputStream(new ByteArrayInputStream(
                                     "not a valid crl".getBytes(US_ASCII))));
    }

    @Test
    public void fromX509DerInputStream_success() throws Exception {
        OpenSSLX509CRL pemCrl = loadTestCrl("crl.pem");
        OpenSSLX509CRL derCrl = OpenSSLX509CRL.fromX509DerInputStream(
                new ByteArrayInputStream(pemCrl.getEncoded()));
        assertNotNull(derCrl);
        assertArrayEquals(pemCrl.getEncoded(), derCrl.getEncoded());
    }

    @Test
    public void fromX509DerInputStream_emptyThrows() {
        assertThrows(
                ParsingException.class,
                () -> OpenSSLX509CRL.fromX509DerInputStream(new ByteArrayInputStream(new byte[0])));
    }

    @Test
    public void fromX509DerInputStream_invalidThrows() {
        assertThrows(ParsingException.class,
                     ()
                             -> OpenSSLX509CRL.fromX509DerInputStream(
                                     new ByteArrayInputStream(new byte[] {0x30, 0x01, 0x00})));
    }

    @Test
    public void fromPkcs7PemInputStream_success() throws Exception {
        List<OpenSSLX509CRL> crls = OpenSSLX509CRL.fromPkcs7PemInputStream(
                new ByteArrayInputStream(VALID_CRL_PKCS7_PEM.getBytes(US_ASCII)));
        assertNotNull(crls);
        assertThat(crls).hasSize(1);
        assertEquals(2, crls.get(0).getVersion());
    }

    @Test
    public void fromPkcs7PemInputStream_emptyThrows() {
        assertThrows(ParsingException.class,
                     ()
                             -> OpenSSLX509CRL.fromPkcs7PemInputStream(
                                     new ByteArrayInputStream(new byte[0])));
    }

    @Test
    public void fromPkcs7PemInputStream_invalidThrows() {
        assertThrows(ParsingException.class,
                     ()
                             -> OpenSSLX509CRL.fromPkcs7PemInputStream(new ByteArrayInputStream(
                                     "invalid pkcs7".getBytes(US_ASCII))));
    }

    @Test
    public void fromPkcs7DerInputStream_success() throws Exception {
        byte[] pkcs7Der = TestUtils.decodeBase64(VALID_CRL_PKCS7_DER_BASE64);
        List<OpenSSLX509CRL> crls =
                OpenSSLX509CRL.fromPkcs7DerInputStream(new ByteArrayInputStream(pkcs7Der));
        assertNotNull(crls);
        assertThat(crls).hasSize(1);
        assertEquals(2, crls.get(0).getVersion());
    }

    @Test
    public void fromPkcs7DerInputStream_emptyThrows() {
        assertThrows(ParsingException.class,
                     ()
                             -> OpenSSLX509CRL.fromPkcs7DerInputStream(
                                     new ByteArrayInputStream(new byte[0])));
    }

    @Test
    public void fromPkcs7DerInputStream_invalidThrows() {
        assertThrows(ParsingException.class,
                     ()
                             -> OpenSSLX509CRL.fromPkcs7DerInputStream(
                                     new ByteArrayInputStream(new byte[] {0x30, 0x01, 0x00})));
    }

    @Test
    public void toString_printsCRL() throws Exception {
        String expectedToString = "Certificate Revocation List (CRL):\n"
                + "        Version 2 (0x1)\n"
                + "    Signature Algorithm: sha256WithRSAEncryption\n"
                + "        Issuer: /C=GB/O=Certificate Transparency CA/ST=Wales/L=Erw Wen\n"
                + "        Last Update: Aug  7 10:27:10 2019 GMT\n"
                + "        Next Update: Sep  6 10:27:10 2019 GMT\n"
                + "        CRL extensions:\n"
                + "            X509v3 CRL Number:\n"
                + "                2\n"
                + "Revoked Certificates:\n"
                + "    Serial Number: 07\n"
                + "        Revocation Date: Aug  7 10:26:54 2019 GMT\n"
                + "        CRL entry extensions:\n"
                + "            X509v3 CRL Reason Code:\n"
                + "                Key Compromise\n"
                + "    Signature Algorithm: sha256WithRSAEncryption\n"
                + "         cc:5f:c3:2e:22:2f:64:35:f8:16:94:a3:34:29:f0:29:16:e5:\n"
                + "         9e:12:4b:67:53:4d:04:01:f1:71:16:df:15:8d:e9:b2:86:ef:\n"
                + "         6c:61:8e:8f:1c:c2:41:6f:f4:de:09:27:80:6e:55:ad:27:dd:\n"
                + "         54:e2:cc:99:00:eb:03:1a:4a:a9:e6:2a:14:38:f4:1c:07:a7:\n"
                + "         5a:e8:1b:08:21:d6:03:0f:16:37:d5:d2:27:89:c6:c5:d4:62:\n"
                + "         69:c1:bf:e6:f1:08:c7:4d:08:09:41:82:78:67:27:a9:6b:12:\n"
                + "         9c:5b:5a:80:3b:6f:af:2d:9c:e0:c3:1e:c5:b4:8f:9c:33:74:\n"
                + "         2c:b8\n";
        OpenSSLX509CRL crl = loadTestCrl("crl.pem");
        assertEquals(expectedToString, crl.toString());
    }

    @Test
    public void toString_revokedEntry_printsRevokedEntry() throws Exception {
        OpenSSLX509CRL crl = loadTestCrl("crl.pem");
        X509CRLEntry entry = crl.getRevokedCertificate(BigInteger.valueOf(7));
        assertNotNull(entry);
        String expectedEntryToString = "Serial Number: 07\n"
                + "Revocation Date: Aug  7 10:26:54 2019 GMT\n"
                + "CRL entry extensions:\n"
                + "    X509v3 CRL Reason Code:\n"
                + "        Key Compromise\n";
        assertEquals(expectedEntryToString, entry.toString());
    }

    @Test
    public void crlPropertiesAndGetters() throws Exception {
        OpenSSLX509CRL crl = loadTestCrl("crl.pem");
        assertEquals(2, crl.getVersion());

        Principal issuerDn = crl.getIssuerDN();
        assertNotNull(issuerDn);
        assertEquals("L=Erw Wen,ST=Wales,O=Certificate Transparency CA,C=GB", issuerDn.getName());

        X500Principal issuerPrincipal = crl.getIssuerX500Principal();
        assertNotNull(issuerPrincipal);
        OpenSSLX509Certificate caCert = loadTestCertificate("ca-cert.pem");
        assertEquals(caCert.getSubjectX500Principal(), issuerPrincipal);
        assertEquals("L=Erw Wen,ST=Wales,O=Certificate Transparency CA,C=GB",
                     issuerPrincipal.getName());

        Date thisUpdate = crl.getThisUpdate();
        assertNotNull(thisUpdate);
        Date nextUpdate = crl.getNextUpdate();
        assertNotNull(nextUpdate);
        assertTrue(nextUpdate.after(thisUpdate));

        assertEquals("SHA256withRSA", crl.getSigAlgName());
        assertEquals("1.2.840.113549.1.1.11", crl.getSigAlgOID());
        assertArrayEquals(new byte[] {0x05, 0x00}, crl.getSigAlgParams());

        assertNotNull(crl.getSignature());
        assertThat(crl.getSignature()).isNotEmpty();

        assertNotNull(crl.getTBSCertList());
        assertThat(crl.getTBSCertList()).isNotEmpty();

        assertNotNull(crl.getEncoded());
        assertThat(crl.getEncoded()).isNotEmpty();
    }

    @Test
    public void crlExtensions() throws Exception {
        OpenSSLX509CRL crl = loadTestCrl("crl.pem");

        Set<String> critOids = crl.getCriticalExtensionOIDs();
        assertNotNull(critOids);
        assertThat(critOids).isEmpty();
        assertFalse(crl.hasUnsupportedCriticalExtension());

        Set<String> nonCrit = crl.getNonCriticalExtensionOIDs();
        assertNotNull(nonCrit);
        assertThat(nonCrit).contains("2.5.29.20"); // CRL Number

        byte[] crlNumberExt = crl.getExtensionValue("2.5.29.20");
        assertNotNull(crlNumberExt);
        assertNull(crl.getExtensionValue("1.2.3.4.5.6.7.8"));
    }

    @Test
    public void verify_withOpenSSLKey() throws Exception {
        OpenSSLX509CRL crl = loadTestCrl("crl.pem");
        OpenSSLX509Certificate caCert = loadTestCertificate("ca-cert.pem");
        OpenSSLX509Certificate leafCert = loadTestCertificate("cert.pem");

        // Verification with signer public key succeeds
        crl.verify(caCert.getPublicKey());

        // Verification with wrong key fails
        assertThrows(SignatureException.class, () -> crl.verify(leafCert.getPublicKey()));
    }

    @Test
    public void verify_withNonOpenSSLKey() throws Exception {
        OpenSSLX509CRL crl = loadTestCrl("crl.pem");
        OpenSSLX509Certificate caCert = loadTestCertificate("ca-cert.pem");

        // Wrap the key so it does not implement OpenSSLKeyHolder
        PublicKey wrappedKey = new DelegatingPublicKey(caCert.getPublicKey());
        assertThat(wrappedKey).isNotInstanceOf(OpenSSLKeyHolder.class);

        // Verifies via verifyInternal
        crl.verify(wrappedKey);

        // With sigProvider
        crl.verify(wrappedKey, TestUtils.getConscryptProvider().getName());

        assertThrows(NoSuchProviderException.class,
                     () -> crl.verify(wrappedKey, "NonExistentProvider"));
    }

    @Test
    public void isRevoked_and_getRevokedCertificate() throws Exception {
        OpenSSLX509CRL crl = loadTestCrl("crl.pem");
        OpenSSLX509Certificate revokedCert = loadTestCertificate("cert.pem");
        OpenSSLX509Certificate unrevokedCert = loadTestCertificate("ca-cert.pem");

        // Check OpenSSLX509Certificate instances
        assertTrue(crl.isRevoked(revokedCert));
        assertFalse(crl.isRevoked(unrevokedCert));

        X509CRLEntry entryByCert = crl.getRevokedCertificate(revokedCert);
        assertNotNull(entryByCert);
        assertEquals(BigInteger.valueOf(7), entryByCert.getSerialNumber());
        assertNull(crl.getRevokedCertificate(unrevokedCert));

        // Check by serial number
        X509CRLEntry entryBySerial = crl.getRevokedCertificate(BigInteger.valueOf(7));
        assertNotNull(entryBySerial);
        assertEquals(BigInteger.valueOf(7), entryBySerial.getSerialNumber());
        assertNull(crl.getRevokedCertificate(BigInteger.valueOf(999)));

        // Check getRevokedCertificates set
        Set<? extends X509CRLEntry> entries = crl.getRevokedCertificates();
        assertNotNull(entries);
        assertThat(entries).hasSize(1);
        assertEquals(entryBySerial, entries.iterator().next());

        // Check non-OpenSSL X509Certificate (DelegatingX509Certificate)
        X509Certificate wrappedRevoked = new DelegatingX509Certificate(revokedCert);
        assertThat(wrappedRevoked).isNotInstanceOf(OpenSSLX509Certificate.class);
        assertTrue(crl.isRevoked(wrappedRevoked));

        X509CRLEntry entryByWrappedCert = crl.getRevokedCertificate(wrappedRevoked);
        assertNotNull(entryByWrappedCert);
        assertEquals(BigInteger.valueOf(7), entryByWrappedCert.getSerialNumber());

        X509Certificate wrappedUnrevoked = new DelegatingX509Certificate(unrevokedCert);
        assertFalse(crl.isRevoked(wrappedUnrevoked));
        assertNull(crl.getRevokedCertificate(wrappedUnrevoked));

        // Check non-X509 Certificate
        Certificate nonX509Cert = new NonX509Certificate();
        assertFalse(crl.isRevoked(nonX509Cert));
    }

    @Test
    public void crlEntryPropertiesAndGetters() throws Exception {
        OpenSSLX509CRL crl = loadTestCrl("crl.pem");
        X509CRLEntry entry = crl.getRevokedCertificate(BigInteger.valueOf(7));
        assertNotNull(entry);

        assertEquals(BigInteger.valueOf(7), entry.getSerialNumber());
        assertNotNull(entry.getRevocationDate());
        assertTrue(entry.hasExtensions());

        Set<String> critOids = entry.getCriticalExtensionOIDs();
        assertNotNull(critOids);
        assertThat(critOids).isEmpty();
        assertFalse(entry.hasUnsupportedCriticalExtension());

        Set<String> nonCrit = entry.getNonCriticalExtensionOIDs();
        assertNotNull(nonCrit);
        assertTrue(nonCrit.contains("2.5.29.21")); // CRL Reason Code

        byte[] reasonCodeExt = entry.getExtensionValue("2.5.29.21");
        assertNotNull(reasonCodeExt);
        assertNull(entry.getExtensionValue("1.2.3.4.5"));

        byte[] encoded = entry.getEncoded();
        assertNotNull(encoded);
        assertTrue(encoded.length > 0);
    }

    @Test
    public void unknownSigAlgOID() throws Exception {
        OpenSSLX509CRL crl = OpenSSLX509CRL.fromX509PemInputStream(
                new ByteArrayInputStream(UNKNOWN_SIGNATURE_OID.getBytes(US_ASCII)));
        assertNotNull(crl);
        assertEquals("1.2.840.113554.4.1.72585.2", crl.getSigAlgOID());
        assertEquals("1.2.840.113554.4.1.72585.2", crl.getSigAlgName());
    }

    private static class DelegatingPublicKey implements PublicKey {
        private final PublicKey delegate;

        DelegatingPublicKey(PublicKey delegate) {
            this.delegate = delegate;
        }

        @Override
        public String getAlgorithm() {
            return delegate.getAlgorithm();
        }

        @Override
        public String getFormat() {
            return delegate.getFormat();
        }

        @Override
        public byte[] getEncoded() {
            return delegate.getEncoded();
        }
    }

    private static class DelegatingX509Certificate extends X509Certificate {
        private final X509Certificate delegate;

        DelegatingX509Certificate(X509Certificate delegate) {
            this.delegate = delegate;
        }

        @Override
        public void checkValidity()
                throws CertificateExpiredException, CertificateNotYetValidException {
            delegate.checkValidity();
        }

        @Override
        public void checkValidity(Date date)
                throws CertificateExpiredException, CertificateNotYetValidException {
            delegate.checkValidity(date);
        }

        @Override
        public int getVersion() {
            return delegate.getVersion();
        }

        @Override
        public BigInteger getSerialNumber() {
            return delegate.getSerialNumber();
        }

        @Override
        public Principal getIssuerDN() {
            return delegate.getIssuerDN();
        }

        @Override
        public Principal getSubjectDN() {
            return delegate.getSubjectDN();
        }

        @Override
        public Date getNotBefore() {
            return delegate.getNotBefore();
        }

        @Override
        public Date getNotAfter() {
            return delegate.getNotAfter();
        }

        @Override
        public byte[] getTBSCertificate() throws CertificateEncodingException {
            return delegate.getTBSCertificate();
        }

        @Override
        public byte[] getSignature() {
            return delegate.getSignature();
        }

        @Override
        public String getSigAlgName() {
            return delegate.getSigAlgName();
        }

        @Override
        public String getSigAlgOID() {
            return delegate.getSigAlgOID();
        }

        @Override
        public byte[] getSigAlgParams() {
            return delegate.getSigAlgParams();
        }

        @Override
        public boolean[] getIssuerUniqueID() {
            return delegate.getIssuerUniqueID();
        }

        @Override
        public boolean[] getSubjectUniqueID() {
            return delegate.getSubjectUniqueID();
        }

        @Override
        public boolean[] getKeyUsage() {
            return delegate.getKeyUsage();
        }

        @Override
        public int getBasicConstraints() {
            return delegate.getBasicConstraints();
        }

        @Override
        public byte[] getEncoded() throws CertificateEncodingException {
            return delegate.getEncoded();
        }

        @Override
        public void verify(PublicKey key)
                throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
                       NoSuchProviderException, SignatureException {
            delegate.verify(key);
        }

        @Override
        public void verify(PublicKey key, String sigProvider)
                throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
                       NoSuchProviderException, SignatureException {
            delegate.verify(key, sigProvider);
        }

        @Override
        public String toString() {
            return delegate.toString();
        }

        @Override
        public PublicKey getPublicKey() {
            return delegate.getPublicKey();
        }

        @Override
        public boolean hasUnsupportedCriticalExtension() {
            return delegate.hasUnsupportedCriticalExtension();
        }

        @Override
        public Set<String> getCriticalExtensionOIDs() {
            return delegate.getCriticalExtensionOIDs();
        }

        @Override
        public Set<String> getNonCriticalExtensionOIDs() {
            return delegate.getNonCriticalExtensionOIDs();
        }

        @Override
        public byte[] getExtensionValue(String oid) {
            return delegate.getExtensionValue(oid);
        }
    }

    private static class NonX509Certificate extends Certificate {
        NonX509Certificate() {
            super("custom");
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }

        @Override
        public void verify(PublicKey key) {}

        @Override
        public void verify(PublicKey key, String sigProvider) {}

        @Override
        public String toString() {
            return "custom";
        }

        @Override
        public PublicKey getPublicKey() {
            return null;
        }
    }
}
