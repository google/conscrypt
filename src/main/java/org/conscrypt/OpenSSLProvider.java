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

package org.conscrypt;

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
    private static final long serialVersionUID = 2996752495318905136L;

    public static final String PROVIDER_NAME = "AndroidOpenSSL";

    private static final String PREFIX = OpenSSLProvider.class.getPackage().getName() + ".";

    private static final String STANDARD_EC_PRIVATE_KEY_INTERFACE_CLASS_NAME =
            "java.security.interfaces.ECPrivateKey";
    private static final String STANDARD_RSA_PRIVATE_KEY_INTERFACE_CLASS_NAME =
            "java.security.interfaces.RSAPrivateKey";
    private static final String STANDARD_RSA_PUBLIC_KEY_INTERFACE_CLASS_NAME =
            "java.security.interfaces.RSAPublicKey";

    public OpenSSLProvider() {
        this(PROVIDER_NAME);
    }

    public OpenSSLProvider(String providerName) {
        super(providerName, 1.0, "Android's OpenSSL-backed security provider");

        // Make sure the platform is initialized.
        Platform.setup();

        /* === SSL Contexts === */
        final String classOpenSSLContextImpl = PREFIX + "OpenSSLContextImpl";
        final String tls12SSLContext = classOpenSSLContextImpl + "$TLSv12";
        final String ssl3SSLContext = classOpenSSLContextImpl + "$SSLv3";
        put("SSLContext.SSL", ssl3SSLContext);
        put("SSLContext.SSLv3", ssl3SSLContext);
        put("SSLContext.TLS", tls12SSLContext);
        put("SSLContext.TLSv1", classOpenSSLContextImpl + "$TLSv1");
        put("SSLContext.TLSv1.1", classOpenSSLContextImpl + "$TLSv11");
        put("SSLContext.TLSv1.2", tls12SSLContext);
        put("SSLContext.Default", PREFIX + "DefaultSSLContextImpl");

        /* === Message Digests === */
        put("MessageDigest.SHA-1", PREFIX + "OpenSSLMessageDigestJDK$SHA1");
        put("Alg.Alias.MessageDigest.SHA1", "SHA-1");
        put("Alg.Alias.MessageDigest.SHA", "SHA-1");
        put("Alg.Alias.MessageDigest.1.3.14.3.2.26", "SHA-1");

        put("MessageDigest.SHA-224", PREFIX + "OpenSSLMessageDigestJDK$SHA224");
        put("Alg.Alias.MessageDigest.SHA224", "SHA-224");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.4", "SHA-224");

        put("MessageDigest.SHA-256", PREFIX + "OpenSSLMessageDigestJDK$SHA256");
        put("Alg.Alias.MessageDigest.SHA256", "SHA-256");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.1", "SHA-256");

        put("MessageDigest.SHA-384", PREFIX + "OpenSSLMessageDigestJDK$SHA384");
        put("Alg.Alias.MessageDigest.SHA384", "SHA-384");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.2", "SHA-384");

        put("MessageDigest.SHA-512", PREFIX + "OpenSSLMessageDigestJDK$SHA512");
        put("Alg.Alias.MessageDigest.SHA512", "SHA-512");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.3", "SHA-512");

        // iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) md5(5)
        put("MessageDigest.MD5", PREFIX + "OpenSSLMessageDigestJDK$MD5");
        put("Alg.Alias.MessageDigest.1.2.840.113549.2.5", "MD5");

        /* == KeyPairGenerators == */
        put("KeyPairGenerator.RSA", PREFIX + "OpenSSLRSAKeyPairGenerator");
        put("Alg.Alias.KeyPairGenerator.1.2.840.113549.1.1.1", "RSA");

        put("KeyPairGenerator.EC", PREFIX + "OpenSSLECKeyPairGenerator");

        /* == KeyFactory == */
        put("KeyFactory.RSA", PREFIX + "OpenSSLRSAKeyFactory");
        put("Alg.Alias.KeyFactory.1.2.840.113549.1.1.1", "RSA");

        put("KeyFactory.EC", PREFIX + "OpenSSLECKeyFactory");

        /* == KeyAgreement == */
        putECDHKeyAgreementImplClass("OpenSSLECDHKeyAgreement");

        /* == Signatures == */
        putSignatureImplClass("MD5WithRSA", "OpenSSLSignature$MD5RSA");
        put("Alg.Alias.Signature.MD5WithRSAEncryption", "MD5WithRSA");
        put("Alg.Alias.Signature.MD5/RSA", "MD5WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.4", "MD5WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.2.5with1.2.840.113549.1.1.1", "MD5WithRSA");

        putSignatureImplClass("SHA1WithRSA", "OpenSSLSignature$SHA1RSA");
        put("Alg.Alias.Signature.SHA1WithRSAEncryption", "SHA1WithRSA");
        put("Alg.Alias.Signature.SHA1/RSA", "SHA1WithRSA");
        put("Alg.Alias.Signature.SHA-1/RSA", "SHA1WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1WithRSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.113549.1.1.1", "SHA1WithRSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.113549.1.1.5", "SHA1WithRSA");
        put("Alg.Alias.Signature.1.3.14.3.2.29", "SHA1WithRSA");

        putSignatureImplClass("SHA224WithRSA", "OpenSSLSignature$SHA224RSA");
        put("Alg.Alias.Signature.SHA224WithRSAEncryption", "SHA224WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.11", "SHA224WithRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.4with1.2.840.113549.1.1.1",
                "SHA224WithRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.4with1.2.840.113549.1.1.11",
                "SHA224WithRSA");

        putSignatureImplClass("SHA256WithRSA", "OpenSSLSignature$SHA256RSA");
        put("Alg.Alias.Signature.SHA256WithRSAEncryption", "SHA256WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.11", "SHA256WithRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.113549.1.1.1",
                "SHA256WithRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.113549.1.1.11",
                "SHA256WithRSA");

        putSignatureImplClass("SHA384WithRSA", "OpenSSLSignature$SHA384RSA");
        put("Alg.Alias.Signature.SHA384WithRSAEncryption", "SHA384WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.12", "SHA384WithRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.2with1.2.840.113549.1.1.1",
                "SHA384WithRSA");

        putSignatureImplClass("SHA512WithRSA", "OpenSSLSignature$SHA512RSA");
        put("Alg.Alias.Signature.SHA512WithRSAEncryption", "SHA512WithRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.13", "SHA512WithRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.3with1.2.840.113549.1.1.1",
                "SHA512WithRSA");

        putRAWRSASignatureImplClass("OpenSSLSignatureRawRSA");

        putSignatureImplClass("ECDSA", "OpenSSLSignature$SHA1ECDSA");
        put("Alg.Alias.Signature.SHA1withECDSA", "ECDSA");
        put("Alg.Alias.Signature.ECDSAwithSHA1", "ECDSA");
        // iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA1(1)
        put("Alg.Alias.Signature.1.2.840.10045.4.1", "ECDSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10045.2.1", "ECDSA");

        // iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA2(3)
        putSignatureImplClass("SHA224withECDSA", "OpenSSLSignature$SHA224ECDSA");
        // ecdsa-with-SHA224(1)
        put("Alg.Alias.Signature.1.2.840.10045.4.3.1", "SHA224withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.4with1.2.840.10045.2.1", "SHA224withECDSA");

        // iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA2(3)
        putSignatureImplClass("SHA256withECDSA", "OpenSSLSignature$SHA256ECDSA");
        // ecdsa-with-SHA256(2)
        put("Alg.Alias.Signature.1.2.840.10045.4.3.2", "SHA256withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.10045.2.1", "SHA256withECDSA");

        putSignatureImplClass("SHA384withECDSA", "OpenSSLSignature$SHA384ECDSA");
        // ecdsa-with-SHA384(3)
        put("Alg.Alias.Signature.1.2.840.10045.4.3.3", "SHA384withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.2with1.2.840.10045.2.1", "SHA384withECDSA");

        putSignatureImplClass("SHA512withECDSA", "OpenSSLSignature$SHA512ECDSA");
        // ecdsa-with-SHA512(4)
        put("Alg.Alias.Signature.1.2.840.10045.4.3.4", "SHA512withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.3with1.2.840.10045.2.1", "SHA512withECDSA");

        /* === SecureRandom === */
        /*
         * We have to specify SHA1PRNG because various documentation mentions
         * that algorithm by name instead of just recommending calling
         * "new SecureRandom()"
         */
        put("SecureRandom.SHA1PRNG", PREFIX + "OpenSSLRandom");
        put("SecureRandom.SHA1PRNG ImplementedIn", "Software");

        /* === Cipher === */
        putRSACipherImplClass("RSA/ECB/NoPadding", "OpenSSLCipherRSA$Raw");
        put("Alg.Alias.Cipher.RSA/None/NoPadding", "RSA/ECB/NoPadding");
        putRSACipherImplClass("RSA/ECB/PKCS1Padding", "OpenSSLCipherRSA$PKCS1");
        put("Alg.Alias.Cipher.RSA/None/PKCS1Padding", "RSA/ECB/PKCS1Padding");

        /*
         * OpenSSL only supports a subset of modes, so we'll name them
         * explicitly here.
         *
         * Moreover, OpenSSL only supports PKCS#7 padding. PKCS#5 padding
         * is also supported because it's a special case of PKCS#7 for 64-bit
         * blocks. PKCS#5 technically supports only 64-bit blocks and won't
         * produce the same result as PKCS#7 for blocks that are not 64 bits
         * long. However, everybody assumes PKCS#7 when they say PKCS#5. For
         * example, lots of code uses PKCS#5 with AES whose blocks are longer
         * than 64 bits. We solve this confusion by making PKCS7Padding an
         * alias for PKCS5Padding.
         */
        putSymmetricCipherImplClass("AES/ECB/NoPadding",
                "OpenSSLCipher$EVP_CIPHER$AES$ECB$NoPadding");
        putSymmetricCipherImplClass("AES/ECB/PKCS5Padding",
                "OpenSSLCipher$EVP_CIPHER$AES$ECB$PKCS5Padding");
        put("Alg.Alias.Cipher.AES/ECB/PKCS7Padding", "AES/ECB/PKCS5Padding");
        putSymmetricCipherImplClass("AES/CBC/NoPadding",
                "OpenSSLCipher$EVP_CIPHER$AES$CBC$NoPadding");
        putSymmetricCipherImplClass("AES/CBC/PKCS5Padding",
                "OpenSSLCipher$EVP_CIPHER$AES$CBC$PKCS5Padding");
        put("Alg.Alias.Cipher.AES/CBC/PKCS7Padding", "AES/CBC/PKCS5Padding");
        putSymmetricCipherImplClass("AES/CTR/NoPadding", "OpenSSLCipher$EVP_CIPHER$AES$CTR");

        putSymmetricCipherImplClass("DESEDE/CBC/NoPadding",
                "OpenSSLCipher$EVP_CIPHER$DESEDE$CBC$NoPadding");
        putSymmetricCipherImplClass("DESEDE/CBC/PKCS5Padding",
                "OpenSSLCipher$EVP_CIPHER$DESEDE$CBC$PKCS5Padding");
        put("Alg.Alias.Cipher.DESEDE/CBC/PKCS7Padding", "DESEDE/CBC/PKCS5Padding");

        putSymmetricCipherImplClass("ARC4", "OpenSSLCipher$EVP_CIPHER$ARC4");

        if (NativeConstants.IS_BORINGSSL) {
            /* EVP_AEAD is only supported in BoringSSL right now. */
            putSymmetricCipherImplClass("AES/GCM/NoPadding", "OpenSSLCipher$EVP_AEAD$AES$GCM");
            put("Alg.Alias.Cipher.GCM", "AES/GCM/NoPadding");
        }

        /* === Mac === */

        putMacImplClass("HmacMD5", "OpenSSLMac$HmacMD5");

        // PKCS#2 - iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2)
        // http://www.oid-info.com/get/1.2.840.113549.2

        // HMAC-SHA-1 PRF (7)
        putMacImplClass("HmacSHA1", "OpenSSLMac$HmacSHA1");
        put("Alg.Alias.Mac.1.2.840.113549.2.7", "HmacSHA1");
        put("Alg.Alias.Mac.HMAC-SHA1", "HmacSHA1");
        put("Alg.Alias.Mac.HMAC/SHA1", "HmacSHA1");

        // id-hmacWithSHA224 (8)
        putMacImplClass("HmacSHA224", "OpenSSLMac$HmacSHA224");
        put("Alg.Alias.Mac.1.2.840.113549.2.9", "HmacSHA224");
        put("Alg.Alias.Mac.HMAC-SHA224", "HmacSHA224");
        put("Alg.Alias.Mac.HMAC/SHA224", "HmacSHA224");

        // id-hmacWithSHA256 (9)
        putMacImplClass("HmacSHA256", "OpenSSLMac$HmacSHA256");
        put("Alg.Alias.Mac.1.2.840.113549.2.9", "HmacSHA256");
        put("Alg.Alias.Mac.HMAC-SHA256", "HmacSHA256");
        put("Alg.Alias.Mac.HMAC/SHA256", "HmacSHA256");

        // id-hmacWithSHA384 (10)
        putMacImplClass("HmacSHA384", "OpenSSLMac$HmacSHA384");
        put("Alg.Alias.Mac.1.2.840.113549.2.10", "HmacSHA384");
        put("Alg.Alias.Mac.HMAC-SHA384", "HmacSHA384");
        put("Alg.Alias.Mac.HMAC/SHA384", "HmacSHA384");

        // id-hmacWithSHA384 (11)
        putMacImplClass("HmacSHA512", "OpenSSLMac$HmacSHA512");
        put("Alg.Alias.Mac.1.2.840.113549.2.11", "HmacSHA512");
        put("Alg.Alias.Mac.HMAC-SHA512", "HmacSHA512");
        put("Alg.Alias.Mac.HMAC/SHA512", "HmacSHA512");

        /* === Certificate === */

        put("CertificateFactory.X509", PREFIX + "OpenSSLX509CertificateFactory");
        put("Alg.Alias.CertificateFactory.X.509", "X509");
    }

    private void putMacImplClass(String algorithm, String className) {
        // Accept only keys for which any of the following is true:
        // * the key is from this provider (subclass of OpenSSLKeyHolder),
        // * the key provides its key material in "RAW" encoding via Key.getEncoded.
        String supportedKeyClasses = PREFIX + "OpenSSLKeyHolder";
        String supportedKeyFormats = "RAW";
        putImplClassWithKeyConstraints(
                "Mac." + algorithm,
                PREFIX + className,
                supportedKeyClasses,
                supportedKeyFormats);
    }

    private void putSymmetricCipherImplClass(String transformation, String className) {
        // Accept only keys for which any of the following is true:
        // * the key provides its key material in "RAW" encoding via Key.getEncoded.
        String supportedKeyClasses = null; // ignored -- filtered based on encoding format only
        String supportedKeyFormats = "RAW";
        putImplClassWithKeyConstraints(
                "Cipher." + transformation,
                PREFIX + className,
                supportedKeyClasses,
                supportedKeyFormats);
    }

    private void putRSACipherImplClass(String transformation, String className) {
        // Accept only keys for which any of the following is true:
        // * the key is instance of OpenSSLRSAPrivateKey, RSAPrivateKey, OpenSSLRSAPublicKey, or
        //   RSAPublicKey.
        String supportedKeyClasses = PREFIX + "OpenSSLRSAPrivateKey"
                + "|" + STANDARD_RSA_PRIVATE_KEY_INTERFACE_CLASS_NAME
                + "|" + PREFIX + "OpenSSLRSAPublicKey"
                + "|" + STANDARD_RSA_PUBLIC_KEY_INTERFACE_CLASS_NAME;
        String supportedKeyFormats = null; // ignored -- filtered based on class only
        putImplClassWithKeyConstraints(
                "Cipher." + transformation,
                PREFIX + className,
                supportedKeyClasses,
                supportedKeyFormats);
    }

    private void putSignatureImplClass(String algorithm, String className) {
        // Accept only keys for which any of the following is true:
        // * the key is from this provider (subclass of OpenSSLKeyHolder),
        // * the key provides its key material in "PKCS#8" or "X.509" encodings via Key.getEncoded.
        // * the key is a transparent private key (subclass of RSAPrivateKey or ECPrivateKey). For
        //   some reason this provider's Signature implementation does not unconditionally accept
        //   transparent public keys -- it only accepts them if they provide their key material in
        //   encoded form (see above).
        String supportedKeyClasses = PREFIX + "OpenSSLKeyHolder"
                + "|" + STANDARD_RSA_PRIVATE_KEY_INTERFACE_CLASS_NAME
                + "|" + STANDARD_EC_PRIVATE_KEY_INTERFACE_CLASS_NAME
                + "|" + STANDARD_RSA_PUBLIC_KEY_INTERFACE_CLASS_NAME;
        String supportedKeyFormats = "PKCS#8|X.509";
        putImplClassWithKeyConstraints(
                "Signature." + algorithm,
                PREFIX + className,
                supportedKeyClasses,
                supportedKeyFormats);
    }

    private void putRAWRSASignatureImplClass(String className) {
        // Accept only keys for which any of the following is true:
        // * the key is instance of OpenSSLRSAPrivateKey, RSAPrivateKey, OpenSSLRSAPublicKey, or
        //   RSAPublicKey.
        String supportedKeyClasses = PREFIX + "OpenSSLRSAPrivateKey"
                + "|" + STANDARD_RSA_PRIVATE_KEY_INTERFACE_CLASS_NAME
                + "|" + PREFIX + "OpenSSLRSAPublicKey"
                + "|" + STANDARD_RSA_PUBLIC_KEY_INTERFACE_CLASS_NAME;
        String supportedKeyFormats = null; // ignored -- filtered based on class only
        putImplClassWithKeyConstraints(
                "Signature.NONEwithRSA",
                PREFIX + className,
                supportedKeyClasses,
                supportedKeyFormats);
    }

    private void putECDHKeyAgreementImplClass(String className) {
        // Accept only keys for which any of the following is true:
        // * the key is from this provider (subclass of OpenSSLKeyHolder),
        // * the key provides its key material in "PKCS#8" encoding via Key.getEncoded.
        // * the key is a transparent EC private key (subclass of ECPrivateKey).
        String supportedKeyClasses = PREFIX + "OpenSSLKeyHolder"
                + "|" + STANDARD_EC_PRIVATE_KEY_INTERFACE_CLASS_NAME;
        String supportedKeyFormats = "PKCS#8";
        putImplClassWithKeyConstraints(
                "KeyAgreement.ECDH",
                PREFIX + className,
                supportedKeyClasses,
                supportedKeyFormats);
    }

    private void putImplClassWithKeyConstraints(String typeAndAlgName,
            String fullyQualifiedClassName,
            String supportedKeyClasses,
            String supportedKeyFormats) {
        put(typeAndAlgName, fullyQualifiedClassName);
        if (supportedKeyClasses != null) {
            put(typeAndAlgName + " SupportedKeyClasses", supportedKeyClasses);
        }
        if (supportedKeyFormats != null) {
            put(typeAndAlgName + " SupportedKeyFormats", supportedKeyFormats);
        }
    }
}
