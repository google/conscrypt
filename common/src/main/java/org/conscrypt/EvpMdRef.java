/*
 * Copyright 2016 The Android Open Source Project
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

import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * Utility class to convert between BoringSSL- and JCE-style message digest identifiers.
 */
final class EvpMdRef {
    static final String MGF1_ALGORITHM_NAME = "MGF1";
    static final String MGF1_OID = "1.2.840.113549.1.1.8";

    /**
     * Returns the canonical JCA digest algorithm name for the provided digest
     * algorithm name or {@code null} if the digest algorithm is not known.
     */
    static String getJcaDigestAlgorithmStandardName(String algorithm) {
        String algorithmUpper = algorithm.toUpperCase(Locale.US);
        if (SHA256.JCA_NAME.equals(algorithmUpper)
            || SHA256.OID.equals(algorithmUpper)) {
            return SHA256.JCA_NAME;
        } else if (SHA512.JCA_NAME.equals(algorithmUpper)
                || SHA512.OID.equals(algorithmUpper)) {
            return SHA512.JCA_NAME;
        } else if (SHA1.JCA_NAME.equals(algorithmUpper)
                || SHA1.OID.equals(algorithmUpper)) {
            return SHA1.JCA_NAME;
        } else if (SHA384.JCA_NAME.equals(algorithmUpper)
                || SHA384.OID.equals(algorithmUpper)) {
            return SHA384.JCA_NAME;
        } else if (SHA224.JCA_NAME.equals(algorithmUpper)
                || SHA224.OID.equals(algorithmUpper)) {
            return SHA224.JCA_NAME;
        } else {
            return null;
        }
    }

    static long getEVP_MDByJcaDigestAlgorithmStandardName(String algorithm)
            throws NoSuchAlgorithmException {
        String algorithmUpper = algorithm.toUpperCase(Locale.US);
        if (SHA256.JCA_NAME.equals(algorithmUpper)) {
            return EvpMdRef.SHA256.EVP_MD;
        } else if (SHA512.JCA_NAME.equals(algorithmUpper)) {
            return EvpMdRef.SHA512.EVP_MD;
        } else if (SHA1.JCA_NAME.equals(algorithmUpper)) {
            return EvpMdRef.SHA1.EVP_MD;
        } else if (SHA384.JCA_NAME.equals(algorithmUpper)) {
            return EvpMdRef.SHA384.EVP_MD;
        } else if (SHA224.JCA_NAME.equals(algorithmUpper)) {
            return EvpMdRef.SHA224.EVP_MD;
        } else {
            throw new NoSuchAlgorithmException("Unsupported algorithm: " + algorithm);
        }
    }

    static int getDigestSizeBytesByJcaDigestAlgorithmStandardName(String algorithm)
            throws NoSuchAlgorithmException {
        String algorithmUpper = algorithm.toUpperCase(Locale.US);
        if (SHA256.JCA_NAME.equals(algorithmUpper)) {
            return EvpMdRef.SHA256.SIZE_BYTES;
        } else if (SHA512.JCA_NAME.equals(algorithmUpper)) {
            return EvpMdRef.SHA512.SIZE_BYTES;
        } else if (SHA1.JCA_NAME.equals(algorithmUpper)) {
            return EvpMdRef.SHA1.SIZE_BYTES;
        } else if (SHA384.JCA_NAME.equals(algorithmUpper)) {
            return EvpMdRef.SHA384.SIZE_BYTES;
        } else if (SHA224.JCA_NAME.equals(algorithmUpper)) {
            return EvpMdRef.SHA224.SIZE_BYTES;
        } else {
            throw new NoSuchAlgorithmException("Unsupported algorithm: " + algorithm);
        }
    }

    static String getJcaDigestAlgorithmStandardNameFromEVP_MD(long evpMdRef) {
        if (evpMdRef == MD5.EVP_MD) {
            return MD5.JCA_NAME;
        } else if (evpMdRef == SHA1.EVP_MD) {
            return SHA1.JCA_NAME;
        } else if (evpMdRef == SHA224.EVP_MD) {
            return SHA224.JCA_NAME;
        } else if (evpMdRef == SHA256.EVP_MD) {
            return SHA256.JCA_NAME;
        } else if (evpMdRef == SHA384.EVP_MD) {
            return SHA384.JCA_NAME;
        } else if (evpMdRef == SHA512.EVP_MD) {
            return SHA512.JCA_NAME;
        } else {
            throw new IllegalArgumentException("Unknown EVP_MD reference");
        }
    }

    static final class MD5 {
        static final String JCA_NAME = "MD5";
        static final String OID = "1.2.840.113549.2.5";
        static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("md5");
        static final int SIZE_BYTES = NativeCrypto.EVP_MD_size(EVP_MD);

        private MD5() {}
    }

    static final class SHA1 {
        static final String JCA_NAME = "SHA-1";
        static final String OID = "1.3.14.3.2.26";
        static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha1");
        static final int SIZE_BYTES = NativeCrypto.EVP_MD_size(EVP_MD);
        private SHA1() {}
    }

    static final class SHA224 {
        static final String JCA_NAME = "SHA-224";
        static final String OID = "2.16.840.1.101.3.4.2.4";
        static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha224");
        static final int SIZE_BYTES = NativeCrypto.EVP_MD_size(EVP_MD);

        private SHA224() {}
    }

    static final class SHA256 {
        static final String JCA_NAME = "SHA-256";
        static final String OID = "2.16.840.1.101.3.4.2.1";
        static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha256");
        static final int SIZE_BYTES = NativeCrypto.EVP_MD_size(EVP_MD);

        private SHA256() {}
    }

    static final class SHA384 {
        static final String JCA_NAME = "SHA-384";
        static final String OID = "2.16.840.1.101.3.4.2.2";
        static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha384");
        static final int SIZE_BYTES = NativeCrypto.EVP_MD_size(EVP_MD);

        private SHA384() {}
    }

    static final class SHA512 {
        static final String JCA_NAME = "SHA-512";
        static final String OID = "2.16.840.1.101.3.4.2.3";
        static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha512");
        static final int SIZE_BYTES = NativeCrypto.EVP_MD_size(EVP_MD);

        private SHA512() {}
    }

    private EvpMdRef() {}
}
