/*
 * Copyright (C) 2012 The Android Open Source Project
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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public final class ChainStrengthAnalyzer {

    private static final int MIN_RSA_MODULUS_LEN_BITS = 1024;

    private static final int MIN_EC_FIELD_SIZE_BITS = 160;

    private static final int MIN_DSA_P_LEN_BITS = 1024;
    private static final int MIN_DSA_Q_LEN_BITS = 160;

    private static final String[] SIGNATURE_ALGORITHM_OID_BLACKLIST = {
        "1.2.840.113549.1.1.2", // md2WithRSAEncryption
        "1.2.840.113549.1.1.3", // md4WithRSAEncryption
        "1.2.840.113549.1.1.4", // md5WithRSAEncryption
    };

    public static final void check(X509Certificate[] chain) throws CertificateException {
        for (X509Certificate cert : chain) {
            checkCert(cert);
        }
    }

    private static final void checkCert(X509Certificate cert) throws CertificateException {
        checkKeyLength(cert);
        checkSignatureAlgorithm(cert);
    }

    private static final void checkKeyLength(X509Certificate cert) throws CertificateException {
        Object pubkey = cert.getPublicKey();
        if (pubkey instanceof RSAPublicKey) {
            int modulusLength = ((RSAPublicKey) pubkey).getModulus().bitLength();
            if (modulusLength < MIN_RSA_MODULUS_LEN_BITS) {
                throw new CertificateException(
                        "RSA modulus is < " + MIN_RSA_MODULUS_LEN_BITS + " bits");
            }
        } else if (pubkey instanceof ECPublicKey) {
            int fieldSizeBits =
                    ((ECPublicKey) pubkey).getParams().getCurve().getField().getFieldSize();
            if (fieldSizeBits < MIN_EC_FIELD_SIZE_BITS) {
                throw new CertificateException(
                        "EC key field size is < " + MIN_EC_FIELD_SIZE_BITS + " bits");
            }
        } else if (pubkey instanceof DSAPublicKey) {
            int pLength = ((DSAPublicKey) pubkey).getParams().getP().bitLength();
            int qLength = ((DSAPublicKey) pubkey).getParams().getQ().bitLength();
            if ((pLength < MIN_DSA_P_LEN_BITS) || (qLength < MIN_DSA_Q_LEN_BITS)) {
                throw new CertificateException(
                        "DSA key length is < (" + MIN_DSA_P_LEN_BITS + ", " + MIN_DSA_Q_LEN_BITS
                        + ") bits");
            }
        } else {
            // Unknown keys will be of type X509PublicKey.
            throw new CertificateException("Rejecting unknown key class " + pubkey.getClass().getName());
        }
    }

    private static final void checkSignatureAlgorithm(
            X509Certificate cert) throws CertificateException {
        String oid = cert.getSigAlgOID();
        for (String blacklisted : SIGNATURE_ALGORITHM_OID_BLACKLIST) {
            if (oid.equals(blacklisted)) {
                throw new CertificateException("Signature uses an insecure hash function: " + oid);
            }
        }
    }
}

