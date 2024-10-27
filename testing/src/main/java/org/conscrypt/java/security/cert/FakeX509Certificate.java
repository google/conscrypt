/*
 * Copyright (C) 2024 The Android Open Source Project
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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

@SuppressWarnings("serial")
public class FakeX509Certificate extends X509Certificate {
    @Override
    public void checkValidity() {}

    @Override
    public void checkValidity(Date date) {}

    @Override
    public int getBasicConstraints() {
        return 0;
    }

    @Override
    public Principal getIssuerDN() {
        return new MockPrincipal();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return null;
    }

    @Override
    public boolean[] getKeyUsage() {
        return null;
    }

    @Override
    @SuppressWarnings("JavaUtilDate")
    public Date getNotAfter() {
        return new Date(System.currentTimeMillis());
    }

    @Override
    @SuppressWarnings("JavaUtilDate")
    public Date getNotBefore() {
        return new Date(System.currentTimeMillis() - 1000);
    }

    @Override
    public BigInteger getSerialNumber() {
        return null;
    }

    @Override
    public String getSigAlgName() {
        return null;
    }

    @Override
    public String getSigAlgOID() {
        return null;
    }

    @Override
    public byte[] getSigAlgParams() {
        return null;
    }

    @Override
    public byte[] getSignature() {
        return null;
    }

    @Override
    public Principal getSubjectDN() {
        return new MockPrincipal();
    }

    static class MockPrincipal implements Principal {
        @Override
        public String getName() {
            return null;
        }
    }
    @Override
    public boolean[] getSubjectUniqueID() {
        return null;
    }

    @Override
    public byte[] getTBSCertificate() {
        return null;
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return null;
    }

    @Override
    public PublicKey getPublicKey() {
        return null;
    }

    @Override
    public String toString() {
        return "null";
    }

    @Override
    public void verify(PublicKey key)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
                   NoSuchProviderException, SignatureException {}

    @Override
    public void verify(PublicKey key, String sigProvider)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
                   NoSuchProviderException, SignatureException {}

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return null;
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return null;
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return null;
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return false;
    }
}
