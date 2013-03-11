/*
 * Copyright (C) 2010 The Android Open Source Project
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

package org.apache.harmony.xnet.provider.jsse;

import java.security.Provider;

/**
 * Provider that goes through OpenSSL for operations.
 * <p>
 * Every algorithm should have its IANA assigned OID as an alias. See the following URLs for each type:
 * <ul>
 * <li><a href="http://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xml">Hash functions</a></li>
 * <li><a href="http://www.iana.org/assignments/dssc/dssc.xml">Signature algorithms</a></li>
 * <li><a href="http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/algorithms.html">NIST cryptographic algorithms</a></li>
 * </ul>
 */
public final class OpenSSLProvider extends Provider {
    public static final String PROVIDER_NAME = "AndroidOpenSSL";

    public OpenSSLProvider() {
        super(PROVIDER_NAME, 1.0, "Android's OpenSSL-backed security provider");

        /* === SSL Contexts === */
        put("SSLContext.SSL", OpenSSLContextImpl.class.getName());
        put("SSLContext.SSLv3", OpenSSLContextImpl.class.getName());
        put("SSLContext.TLS", OpenSSLContextImpl.class.getName());
        put("SSLContext.TLSv1", OpenSSLContextImpl.class.getName());
        put("SSLContext.TLSv1.1", OpenSSLContextImpl.class.getName());
        put("SSLContext.TLSv1.2", OpenSSLContextImpl.class.getName());
        put("SSLContext.Default", DefaultSSLContextImpl.class.getName());

        /* === Message Digests === */
        put("MessageDigest.SHA-1",
            "org.apache.harmony.xnet.provider.jsse.OpenSSLMessageDigestJDK$SHA1");
        put("Alg.Alias.MessageDigest.SHA1", "SHA-1");
        put("Alg.Alias.MessageDigest.SHA", "SHA-1");
        put("Alg.Alias.MessageDigest.1.3.14.3.2.26", "SHA-1");

        put("MessageDigest.SHA-256",
            "org.apache.harmony.xnet.provider.jsse.OpenSSLMessageDigestJDK$SHA256");
        put("Alg.Alias.MessageDigest.SHA256", "SHA-256");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.1", "SHA-256");

        put("MessageDigest.SHA-384",
            "org.apache.harmony.xnet.provider.jsse.OpenSSLMessageDigestJDK$SHA384");
        put("Alg.Alias.MessageDigest.SHA384", "SHA-384");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.2", "SHA-384");

        put("MessageDigest.SHA-512",
            "org.apache.harmony.xnet.provider.jsse.OpenSSLMessageDigestJDK$SHA512");
        put("Alg.Alias.MessageDigest.SHA512", "SHA-512");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.3", "SHA-512");

        // iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) md5(5)
        put("MessageDigest.MD5",
            "org.apache.harmony.xnet.provider.jsse.OpenSSLMessageDigestJDK$MD5");
        put("Alg.Alias.MessageDigest.1.2.840.113549.2.5", "MD5");

        /* == KeyPairGenerators == */
        put("KeyPairGenerator.RSA", OpenSSLRSAKeyPairGenerator.class.getName());
        put("Alg.Alias.KeyPairGenerator.1.2.840.113549.1.1.1", "RSA");

        put("KeyPairGenerator.DSA", OpenSSLDSAKeyPairGenerator.class.getName());

        put("KeyPairGenerator.EC", OpenSSLECKeyPairGenerator.class.getName());

        /* == KeyFactory == */
        put("KeyFactory.RSA", OpenSSLRSAKeyFactory.class.getName());
        put("Alg.Alias.KeyFactory.1.2.840.113549.1.1.1", "RSA");

        put("KeyFactory.DSA", OpenSSLDSAKeyFactory.class.getName());

        put("KeyFactory.EC", OpenSSLECKeyFactory.class.getName());

        /* == KeyAgreement == */
        put("KeyAgreement.ECDH", OpenSSLECDHKeyAgreement.class.getName());

        /* == Signatures == */
        put("Signature.MD5WithRSA", OpenSSLSignature.MD5RSA.class.getName());
        put("Alg.Alias.Signature.MD5WithRSAEncryption", "MD5WithRSA");
        put("Alg.Alias.Signature.MD5/RSA", "MD5WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.4", "MD5WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.2.5with1.2.840.113549.1.1.1", "MD5WithRSA");

        put("Signature.SHA1WithRSA", OpenSSLSignature.SHA1RSA.class.getName());
        put("Alg.Alias.Signature.SHA1WithRSAEncryption", "SHA1WithRSA");
        put("Alg.Alias.Signature.SHA1/RSA", "SHA1WithRSA");
        put("Alg.Alias.Signature.SHA-1/RSA", "SHA1WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1WithRSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.113549.1.1.1", "SHA1WithRSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.113549.1.1.5", "SHA1WithRSA");
        put("Alg.Alias.Signature.1.3.14.3.2.29", "SHA1WithRSA");

        put("Signature.SHA256WithRSA", OpenSSLSignature.SHA256RSA.class.getName());
        put("Alg.Alias.Signature.SHA256WithRSAEncryption", "SHA256WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.11", "SHA256WithRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.113549.1.1.1",
                "SHA256WithRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.113549.1.1.11",
                "SHA256WithRSA");

        put("Signature.SHA384WithRSA", OpenSSLSignature.SHA384RSA.class.getName());
        put("Alg.Alias.Signature.SHA384WithRSAEncryption", "SHA384WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.12", "SHA384WithRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.2with1.2.840.113549.1.1.1",
                "SHA384WithRSA");

        put("Signature.SHA512WithRSA", OpenSSLSignature.SHA512RSA.class.getName());
        put("Alg.Alias.Signature.SHA512WithRSAEncryption", "SHA512WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.13", "SHA512WithRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.3with1.2.840.113549.1.1.1",
                "SHA512WithRSA");

        put("Signature.SHA1withDSA", OpenSSLSignature.SHA1DSA.class.getName());
        put("Alg.Alias.Signature.SHA/DSA", "SHA1withDSA");
        put("Alg.Alias.Signature.DSA", "SHA1withDSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10040.4.1", "SHA1withDSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10040.4.3", "SHA1withDSA");
        put("Alg.Alias.Signature.DSAWithSHA1", "SHA1withDSA");
        put("Alg.Alias.Signature.1.2.840.10040.4.3", "SHA1withDSA");

        put("Signature.NONEwithRSA", OpenSSLSignatureRawRSA.class.getName());

        put("Signature.ECDSA", OpenSSLSignature.SHA1ECDSA.class.getName());
        put("Alg.Alias.Signature.SHA1withECDSA", "ECDSA");
        put("Alg.Alias.Signature.ECDSAwithSHA1", "ECDSA");
        // iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA1(1)
        put("Alg.Alias.Signature.1.2.840.10045.4.1", "ECDSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10045.2.1", "ECDSA");

        // iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA2(3)
        put("Signature.SHA256withECDSA", OpenSSLSignature.SHA256ECDSA.class.getName());
        // ecdsa-with-SHA256(2)
        put("Alg.Alias.Signature.1.2.840.10045.4.3.2", "SHA256withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.10045.2.1", "SHA256withECDSA");

        put("Signature.SHA384withECDSA", OpenSSLSignature.SHA384ECDSA.class.getName());
        // ecdsa-with-SHA384(3)
        put("Alg.Alias.Signature.1.2.840.10045.4.3.3", "SHA384withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.2with1.2.840.10045.2.1", "SHA384withECDSA");

        put("Signature.SHA512withECDSA", OpenSSLSignature.SHA512ECDSA.class.getName());
        // ecdsa-with-SHA512(4)
        put("Alg.Alias.Signature.1.2.840.10045.4.3.4", "SHA512withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.3with1.2.840.10045.2.1", "SHA512withECDSA");

        /* === SecureRandom === */
        /*
         * We have to specify SHA1PRNG because various documentation mentions
         * that algorithm by name instead of just recommending calling
         * "new SecureRandom()"
         */
        put("SecureRandom.SHA1PRNG", OpenSSLRandom.class.getName());
        put("SecureRandom.SHA1PRNG ImplementedIn", "Software");

        /* === Cipher === */
        put("Cipher.RSA/ECB/NoPadding", OpenSSLCipherRSA.Raw.class.getName());
        put("Alg.Alias.Cipher.RSA/None/NoPadding", "RSA/ECB/NoPadding");
        put("Cipher.RSA/ECB/PKCS1Padding", OpenSSLCipherRSA.PKCS1.class.getName());
        put("Alg.Alias.Cipher.RSA/None/PKCS1Padding", "RSA/ECB/PKCS1Padding");

        /*
         * OpenSSL only supports a subset of modes, so we'll name them
         * explicitly here.
         */
        put("Cipher.AES/ECB/NoPadding", OpenSSLCipher.AES.ECB.NoPadding.class.getName());
        put("Cipher.AES/ECB/PKCS5Padding", OpenSSLCipher.AES.ECB.PKCS5Padding.class.getName());
        put("Cipher.AES/CBC/NoPadding", OpenSSLCipher.AES.CBC.NoPadding.class.getName());
        put("Cipher.AES/CBC/PKCS5Padding", OpenSSLCipher.AES.CBC.PKCS5Padding.class.getName());
        put("Cipher.AES/CFB/NoPadding", OpenSSLCipher.AES.CFB.NoPadding.class.getName());
        put("Cipher.AES/CFB/PKCS5Padding", OpenSSLCipher.AES.CFB.PKCS5Padding.class.getName());
        put("Cipher.AES/CTR/NoPadding", OpenSSLCipher.AES.CTR.NoPadding.class.getName());
        put("Cipher.AES/CTR/PKCS5Padding", OpenSSLCipher.AES.CTR.PKCS5Padding.class.getName());
        put("Cipher.AES/OFB/NoPadding", OpenSSLCipher.AES.OFB.NoPadding.class.getName());
        put("Cipher.AES/OFB/PKCS5Padding", OpenSSLCipher.AES.OFB.PKCS5Padding.class.getName());

        put("Cipher.DESEDE/CBC/NoPadding", OpenSSLCipher.DESEDE.CBC.NoPadding.class.getName());
        put("Cipher.DESEDE/CBC/PKCS5Padding", OpenSSLCipher.DESEDE.CBC.PKCS5Padding.class.getName());
        put("Cipher.DESEDE/CFB/NoPadding", OpenSSLCipher.DESEDE.CFB.NoPadding.class.getName());
        put("Cipher.DESEDE/CFB/PKCS5Padding", OpenSSLCipher.DESEDE.CFB.PKCS5Padding.class.getName());
        put("Cipher.DESEDE/ECB/NoPadding", OpenSSLCipher.DESEDE.ECB.NoPadding.class.getName());
        put("Cipher.DESEDE/ECB/PKCS5Padding", OpenSSLCipher.DESEDE.ECB.PKCS5Padding.class.getName());
        put("Cipher.DESEDE/OFB/NoPadding", OpenSSLCipher.DESEDE.OFB.NoPadding.class.getName());
        put("Cipher.DESEDE/OFB/PKCS5Padding", OpenSSLCipher.DESEDE.OFB.PKCS5Padding.class.getName());

        put("Cipher.ARC4", OpenSSLCipher.ARC4.class.getName());

        /* === Mac === */

        put("Mac.HmacMD5", OpenSSLMac.HmacMD5.class.getName());

        // PKCS#2 - iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2)
        // http://www.oid-info.com/get/1.2.840.113549.2

        // HMAC-SHA-1 PRF (7)
        put("Mac.HmacSHA1", OpenSSLMac.HmacSHA1.class.getName());
        put("Alg.Alias.Mac.1.2.840.113549.2.7", "HmacSHA1");
        put("Alg.Alias.Mac.HMAC-SHA1", "HmacSHA1");
        put("Alg.Alias.Mac.HMAC/SHA1", "HmacSHA1");

        // id-hmacWithSHA256 (9)
        put("Mac.HmacSHA256", OpenSSLMac.HmacSHA256.class.getName());
        put("Alg.Alias.Mac.1.2.840.113549.2.9", "HmacSHA256");
        put("Alg.Alias.Mac.HMAC-SHA256", "HmacSHA256");
        put("Alg.Alias.Mac.HMAC/SHA256", "HmacSHA256");

        // id-hmacWithSHA384 (10)
        put("Mac.HmacSHA384", OpenSSLMac.HmacSHA384.class.getName());
        put("Alg.Alias.Mac.1.2.840.113549.2.10", "HmacSHA384");
        put("Alg.Alias.Mac.HMAC-SHA384", "HmacSHA384");
        put("Alg.Alias.Mac.HMAC/SHA384", "HmacSHA384");

        // id-hmacWithSHA384 (11)
        put("Mac.HmacSHA512", OpenSSLMac.HmacSHA512.class.getName());
        put("Alg.Alias.Mac.1.2.840.113549.2.11", "HmacSHA512");
        put("Alg.Alias.Mac.HMAC-SHA512", "HmacSHA512");
        put("Alg.Alias.Mac.HMAC/SHA512", "HmacSHA512");

        /* === Certificate === */

        put("CertificateFactory.X509", OpenSSLX509CertificateFactory.class.getName());
        put("Alg.Alias.CertificateFactory.X.509", "X509");
    }
}
