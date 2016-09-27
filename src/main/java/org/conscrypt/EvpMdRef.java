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

public final class EvpMdRef {
    /**
     * Returns the canonical JCA digest algorithm name for the provided digest
     * algorithm name or {@code null} if the digest algorithm is not known.
     */
    public static String getJcaDigestAlgorithmStandardName(String algorithm) {
        String algorithmUpper = algorithm.toUpperCase(Locale.US);
        if ((SHA256.JCA_NAME.equals(algorithmUpper)) || (SHA256.OID.equals(algorithmUpper))) {
            return SHA256.JCA_NAME;
        } else if ((SHA512.JCA_NAME.equals(algorithmUpper))
                || (SHA512.OID.equals(algorithmUpper))) {
            return SHA512.JCA_NAME;
        } else if ((SHA1.JCA_NAME.equals(algorithmUpper)) || (SHA1.OID.equals(algorithmUpper))) {
            return SHA1.JCA_NAME;
        } else if ((SHA384.JCA_NAME.equals(algorithmUpper))
                || (SHA384.OID.equals(algorithmUpper))) {
            return SHA384.JCA_NAME;
        } else if ((SHA224.JCA_NAME.equals(algorithmUpper))
                || (SHA224.OID.equals(algorithmUpper))) {
            return SHA224.JCA_NAME;
        } else {
            return null;
        }
    }

    public static long getEVP_MDByJcaDigestAlgorithmStandardName(String algorithm)
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

    public static final class MD5 {
        public static final String JCA_NAME = "MD5";
        public static final String OID = "1.2.840.113549.2.5";
        public static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("md5");
        public static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
    }

    public static final class SHA1 {
        public static final String JCA_NAME = "SHA-1";
        public static final String OID = "1.3.14.3.2.26";
        public static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha1");
        public static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
    }

    public static final class SHA224 {
        public static final String JCA_NAME = "SHA-224";
        public static final String OID = "2.16.840.1.101.3.4.2.4";
        public static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha224");
        public static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
    }

    public static final class SHA256 {
        public static final String JCA_NAME = "SHA-256";
        public static final String OID = "2.16.840.1.101.3.4.2.1";
        public static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha256");
        public static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
    }

    public static final class SHA384 {
        public static final String JCA_NAME = "SHA-384";
        public static final String OID = "2.16.840.1.101.3.4.2.2";
        public static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha384");
        public static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
    }

    public static final class SHA512 {
        public static final String JCA_NAME = "SHA-512";
        public static final String OID = "2.16.840.1.101.3.4.2.3";
        public static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha512");
        public static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
    }
}
