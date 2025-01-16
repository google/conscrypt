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
 * Provider that uses BoringSSL to perform the actual cryptographic operations.
 * <p>
 * Every algorithm should have its IANA assigned OID as an alias. See the following URLs for each
 * type: <ul> <li><a
 * href="http://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xml">Hash
 * functions</a></li> <li><a href="http://www.iana.org/assignments/dssc/dssc.xml">Signature
 * algorithms</a></li> <li><a
 * href="http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/algorithms.html">NIST cryptographic
 * algorithms</a></li>
 * </ul>
 */
@Internal
public final class OpenSSLProvider extends Provider {
    private static final long serialVersionUID = 2996752495318905136L;

    private static final String PREFIX = OpenSSLProvider.class.getPackage().getName() + ".";

    private static final String STANDARD_EC_PRIVATE_KEY_INTERFACE_CLASS_NAME =
            "java.security.interfaces.ECPrivateKey";
    private static final String STANDARD_XEC_PRIVATE_KEY_INTERFACE_CLASS_NAME =
            "java.security.interfaces.XECPrivateKey";
    private static final String STANDARD_RSA_PRIVATE_KEY_INTERFACE_CLASS_NAME =
            "java.security.interfaces.RSAPrivateKey";
    private static final String STANDARD_RSA_PUBLIC_KEY_INTERFACE_CLASS_NAME =
            "java.security.interfaces.RSAPublicKey";

    public OpenSSLProvider() {
        this(Platform.getDefaultProviderName());
    }

    @SuppressWarnings("deprecation")
    public OpenSSLProvider(String providerName) {
        this(providerName, Platform.provideTrustManagerByDefault(), "TLSv1.3",
            Platform.DEPRECATED_TLS_V1, Platform.ENABLED_TLS_V1);
    }

    OpenSSLProvider(String providerName, boolean includeTrustManager,
            String defaultTlsProtocol) {
        this(providerName, includeTrustManager, defaultTlsProtocol,
            Platform.DEPRECATED_TLS_V1, Platform.ENABLED_TLS_V1);
    }

    OpenSSLProvider(String providerName, boolean includeTrustManager,
            String defaultTlsProtocol, boolean deprecatedTlsV1,
            boolean enabledTlsV1) {
        super(providerName, 1.0, "Android's OpenSSL-backed security provider");

        // Ensure that the native library has been loaded.
        NativeCrypto.checkAvailability();

        if (!deprecatedTlsV1 && !enabledTlsV1) {
            throw new IllegalArgumentException("TLSv1 is not deprecated and cannot be disabled.");
        }
        // Make sure the platform is initialized.
        Platform.setup(deprecatedTlsV1, enabledTlsV1);

        /* === SSL Contexts === */
        String classOpenSSLContextImpl = PREFIX + "OpenSSLContextImpl";
        String tls12SSLContextSuffix = "$TLSv12";
        String tls13SSLContextSuffix = "$TLSv13";
        String defaultSSLContextSuffix;
        switch (defaultTlsProtocol) {
            case "TLSv1.2":
                defaultSSLContextSuffix = tls12SSLContextSuffix;
                break;
            case "TLSv1.3":
                defaultSSLContextSuffix = tls13SSLContextSuffix;
                break;
            default:
                throw new IllegalArgumentException(
                    "Choice of default protocol is unsupported: " + defaultTlsProtocol);
        }
        // Keep SSL as an alias to TLS
        put("SSLContext.SSL", classOpenSSLContextImpl + defaultSSLContextSuffix);
        put("SSLContext.TLS", classOpenSSLContextImpl + defaultSSLContextSuffix);
        put("SSLContext.TLSv1", classOpenSSLContextImpl + "$TLSv1");
        put("SSLContext.TLSv1.1", classOpenSSLContextImpl + "$TLSv11");
        put("SSLContext.TLSv1.2", classOpenSSLContextImpl + tls12SSLContextSuffix);
        put("SSLContext.TLSv1.3", classOpenSSLContextImpl + tls13SSLContextSuffix);
        put("SSLContext.Default", PREFIX + "DefaultSSLContextImpl" + defaultSSLContextSuffix);

        if (includeTrustManager) {
            put("TrustManagerFactory.PKIX", TrustManagerFactoryImpl.class.getName());
            put("Alg.Alias.TrustManagerFactory.X509", "PKIX");
        }

        put("KeyManagerFactory.PKIX", KeyManagerFactoryImpl.class.getName());
        put("Alg.Alias.KeyManagerFactory.X509", "PKIX");

        /* === AlgorithmParameters === */
        put("AlgorithmParameters.AES", PREFIX + "IvParameters$AES");
        put("Alg.Alias.AlgorithmParameters.2.16.840.1.101.3.4.1.2", "AES");
        put("Alg.Alias.AlgorithmParameters.2.16.840.1.101.3.4.1.22", "AES");
        put("Alg.Alias.AlgorithmParameters.2.16.840.1.101.3.4.1.42", "AES");

        put("AlgorithmParameters.ChaCha20", PREFIX + "IvParameters$ChaCha20");

        put("AlgorithmParameters.DESEDE", PREFIX + "IvParameters$DESEDE");
        put("Alg.Alias.AlgorithmParameters.TDEA", "DESEDE");
        put("Alg.Alias.AlgorithmParameters.1.2.840.113549.3.7", "DESEDE");

        put("AlgorithmParameters.GCM", PREFIX + "GCMParameters");
        put("Alg.Alias.AlgorithmParameters.2.16.840.1.101.3.4.1.6", "GCM");
        put("Alg.Alias.AlgorithmParameters.2.16.840.1.101.3.4.1.26", "GCM");
        put("Alg.Alias.AlgorithmParameters.2.16.840.1.101.3.4.1.46", "GCM");
        put("AlgorithmParameters.OAEP", PREFIX + "OAEPParameters");
        put("AlgorithmParameters.PSS", PREFIX + "PSSParameters");
        put("AlgorithmParameters.EC", PREFIX + "ECParameters");

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

        /* == KeyGenerators == */
        put("KeyGenerator.ARC4", PREFIX + "KeyGeneratorImpl$ARC4");
        put("Alg.Alias.KeyGenerator.RC4", "ARC4");
        put("Alg.Alias.KeyGenerator.1.2.840.113549.3.4", "ARC4");

        put("KeyGenerator.AES", PREFIX + "KeyGeneratorImpl$AES");

        put("KeyGenerator.ChaCha20", PREFIX + "KeyGeneratorImpl$ChaCha20");

        put("KeyGenerator.DESEDE", PREFIX + "KeyGeneratorImpl$DESEDE");
        put("Alg.Alias.KeyGenerator.TDEA", "DESEDE");

        put("KeyGenerator.HmacMD5", PREFIX + "KeyGeneratorImpl$HmacMD5");
        put("Alg.Alias.KeyGenerator.1.3.6.1.5.5.8.1.1", "HmacMD5");
        put("Alg.Alias.KeyGenerator.HMAC-MD5", "HmacMD5");
        put("Alg.Alias.KeyGenerator.HMAC/MD5", "HmacMD5");

        put("KeyGenerator.HmacSHA1", PREFIX + "KeyGeneratorImpl$HmacSHA1");
        put("Alg.Alias.KeyGenerator.1.2.840.113549.2.7", "HmacSHA1");
        put("Alg.Alias.KeyGenerator.1.3.6.1.5.5.8.1.2", "HmacSHA1");
        put("Alg.Alias.KeyGenerator.HMAC-SHA1", "HmacSHA1");
        put("Alg.Alias.KeyGenerator.HMAC/SHA1", "HmacSHA1");

        put("KeyGenerator.HmacSHA224", PREFIX + "KeyGeneratorImpl$HmacSHA224");
        put("Alg.Alias.KeyGenerator.1.2.840.113549.2.8", "HmacSHA224");
        put("Alg.Alias.KeyGenerator.HMAC-SHA224", "HmacSHA224");
        put("Alg.Alias.KeyGenerator.HMAC/SHA224", "HmacSHA224");

        put("KeyGenerator.HmacSHA256", PREFIX + "KeyGeneratorImpl$HmacSHA256");
        put("Alg.Alias.KeyGenerator.1.2.840.113549.2.9", "HmacSHA256");
        put("Alg.Alias.KeyGenerator.2.16.840.1.101.3.4.2.1", "HmacSHA256");
        put("Alg.Alias.KeyGenerator.HMAC-SHA256", "HmacSHA256");
        put("Alg.Alias.KeyGenerator.HMAC/SHA256", "HmacSHA256");

        put("KeyGenerator.HmacSHA384", PREFIX + "KeyGeneratorImpl$HmacSHA384");
        put("Alg.Alias.KeyGenerator.1.2.840.113549.2.10", "HmacSHA384");
        put("Alg.Alias.KeyGenerator.HMAC-SHA384", "HmacSHA384");
        put("Alg.Alias.KeyGenerator.HMAC/SHA384", "HmacSHA384");

        put("KeyGenerator.HmacSHA512", PREFIX + "KeyGeneratorImpl$HmacSHA512");
        put("Alg.Alias.KeyGenerator.1.2.840.113549.2.11", "HmacSHA512");
        put("Alg.Alias.KeyGenerator.HMAC-SHA512", "HmacSHA512");
        put("Alg.Alias.KeyGenerator.HMAC/SHA512", "HmacSHA512");

        /* == KeyPairGenerators == */
        put("KeyPairGenerator.RSA", PREFIX + "OpenSSLRSAKeyPairGenerator");
        put("Alg.Alias.KeyPairGenerator.1.2.840.113549.1.1.1", "RSA");
        put("Alg.Alias.KeyPairGenerator.1.2.840.113549.1.1.7", "RSA");
        put("Alg.Alias.KeyPairGenerator.2.5.8.1.1", "RSA");

        put("KeyPairGenerator.EC", PREFIX + "OpenSSLECKeyPairGenerator");
        put("Alg.Alias.KeyPairGenerator.1.2.840.10045.2.1", "EC");
        put("Alg.Alias.KeyPairGenerator.1.3.133.16.840.63.0.2", "EC");

        put("KeyPairGenerator.XDH", PREFIX + "OpenSSLXDHKeyPairGenerator");
        put("Alg.Alias.KeyPairGenerator.1.3.101.110", "XDH");
        put("Alg.Alias.KeyPairGenerator.X25519", "XDH");

        /* == KeyFactory == */
        put("KeyFactory.RSA", PREFIX + "OpenSSLRSAKeyFactory");
        put("Alg.Alias.KeyFactory.1.2.840.113549.1.1.1", "RSA");
        put("Alg.Alias.KeyFactory.1.2.840.113549.1.1.7", "RSA");
        put("Alg.Alias.KeyFactory.2.5.8.1.1", "RSA");

        put("KeyFactory.EC", PREFIX + "OpenSSLECKeyFactory");
        put("Alg.Alias.KeyFactory.1.2.840.10045.2.1", "EC");
        put("Alg.Alias.KeyFactory.1.3.133.16.840.63.0.2", "EC");

        put("KeyFactory.XDH", PREFIX + "OpenSSLXDHKeyFactory");
        put("Alg.Alias.KeyFactory.1.3.101.110", "XDH");
        put("Alg.Alias.KeyFactory.X25519", "XDH");

        /* == SecretKeyFactory == */
        put("SecretKeyFactory.DESEDE", PREFIX + "DESEDESecretKeyFactory");
        put("Alg.Alias.SecretKeyFactory.TDEA", "DESEDE");
        put("SecretKeyFactory.SCRYPT", PREFIX + "ScryptSecretKeyFactory");
        put("Alg.Alias.SecretKeyFactory.1.3.6.1.4.1.11591.4.11", "SCRYPT");
        put("Alg.Alias.SecretKeyFactory.OID.1.3.6.1.4.1.11591.4.11", "SCRYPT");

        /* == KeyAgreement == */
        putECDHKeyAgreementImplClass("OpenSSLECDHKeyAgreement");
        putXDHKeyAgreementImplClass("OpenSSLXDHKeyAgreement");

        /* == Signatures == */
        putSignatureImplClass("MD5withRSA", "OpenSSLSignature$MD5RSA");
        put("Alg.Alias.Signature.MD5withRSAEncryption", "MD5withRSA");
        put("Alg.Alias.Signature.MD5/RSA", "MD5withRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.4", "MD5withRSA");
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.4", "MD5withRSA");
        put("Alg.Alias.Signature.1.2.840.113549.2.5with1.2.840.113549.1.1.1", "MD5withRSA");

        putSignatureImplClass("SHA1withRSA", "OpenSSLSignature$SHA1RSA");
        put("Alg.Alias.Signature.SHA1withRSAEncryption", "SHA1withRSA");
        put("Alg.Alias.Signature.SHA1/RSA", "SHA1withRSA");
        put("Alg.Alias.Signature.SHA-1/RSA", "SHA1withRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1withRSA");
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5", "SHA1withRSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.113549.1.1.1", "SHA1withRSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.113549.1.1.5", "SHA1withRSA");
        put("Alg.Alias.Signature.1.3.14.3.2.29", "SHA1withRSA");
        put("Alg.Alias.Signature.OID.1.3.14.3.2.29", "SHA1withRSA");

        putSignatureImplClass("SHA224withRSA", "OpenSSLSignature$SHA224RSA");
        put("Alg.Alias.Signature.SHA224withRSAEncryption", "SHA224withRSA");
        put("Alg.Alias.Signature.SHA224/RSA", "SHA224withRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.14", "SHA224withRSA");
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.14", "SHA224withRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.4with1.2.840.113549.1.1.1",
                "SHA224withRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.4with1.2.840.113549.1.1.14",
                "SHA224withRSA");

        putSignatureImplClass("SHA256withRSA", "OpenSSLSignature$SHA256RSA");
        put("Alg.Alias.Signature.SHA256withRSAEncryption", "SHA256withRSA");
        put("Alg.Alias.Signature.SHA256/RSA", "SHA256withRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.11", "SHA256withRSA");
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.11", "SHA256withRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.113549.1.1.1",
                "SHA256withRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.113549.1.1.11",
                "SHA256withRSA");

        putSignatureImplClass("SHA384withRSA", "OpenSSLSignature$SHA384RSA");
        put("Alg.Alias.Signature.SHA384withRSAEncryption", "SHA384withRSA");
        put("Alg.Alias.Signature.SHA384/RSA", "SHA384withRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.12", "SHA384withRSA");
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.12", "SHA384withRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.2with1.2.840.113549.1.1.1",
                "SHA384withRSA");

        putSignatureImplClass("SHA512withRSA", "OpenSSLSignature$SHA512RSA");
        put("Alg.Alias.Signature.SHA512withRSAEncryption", "SHA512withRSA");
        put("Alg.Alias.Signature.SHA512/RSA", "SHA512withRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.13", "SHA512withRSA");
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.13", "SHA512withRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.3with1.2.840.113549.1.1.1",
                "SHA512withRSA");

        putRAWRSASignatureImplClass("OpenSSLSignatureRawRSA");

        putSignatureImplClass("NONEwithECDSA", "OpenSSLSignatureRawECDSA");

        putSignatureImplClass("SHA1withECDSA", "OpenSSLSignature$SHA1ECDSA");
        put("Alg.Alias.Signature.ECDSA", "SHA1withECDSA");
        put("Alg.Alias.Signature.ECDSAwithSHA1", "SHA1withECDSA");
        // iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA1(1)
        put("Alg.Alias.Signature.1.2.840.10045.4.1", "SHA1withECDSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10045.2.1", "SHA1withECDSA");

        // iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA2(3)
        putSignatureImplClass("SHA224withECDSA", "OpenSSLSignature$SHA224ECDSA");
        put("Alg.Alias.Signature.SHA224/ECDSA", "SHA224withECDSA");
        // ecdsa-with-SHA224(1)
        put("Alg.Alias.Signature.1.2.840.10045.4.3.1", "SHA224withECDSA");
        put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.1", "SHA224withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.4with1.2.840.10045.2.1", "SHA224withECDSA");

        // iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA2(3)
        putSignatureImplClass("SHA256withECDSA", "OpenSSLSignature$SHA256ECDSA");
        put("Alg.Alias.Signature.SHA256/ECDSA", "SHA256withECDSA");
        // ecdsa-with-SHA256(2)
        put("Alg.Alias.Signature.1.2.840.10045.4.3.2", "SHA256withECDSA");
        put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.2", "SHA256withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.10045.2.1", "SHA256withECDSA");

        putSignatureImplClass("SHA384withECDSA", "OpenSSLSignature$SHA384ECDSA");
        put("Alg.Alias.Signature.SHA384/ECDSA", "SHA384withECDSA");
        // ecdsa-with-SHA384(3)
        put("Alg.Alias.Signature.1.2.840.10045.4.3.3", "SHA384withECDSA");
        put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.3", "SHA384withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.2with1.2.840.10045.2.1", "SHA384withECDSA");

        putSignatureImplClass("SHA512withECDSA", "OpenSSLSignature$SHA512ECDSA");
        put("Alg.Alias.Signature.SHA512/ECDSA", "SHA512withECDSA");
        // ecdsa-with-SHA512(4)
        put("Alg.Alias.Signature.1.2.840.10045.4.3.4", "SHA512withECDSA");
        put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.4", "SHA512withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.3with1.2.840.10045.2.1", "SHA512withECDSA");

        putSignatureImplClass("SHA1withRSA/PSS", "OpenSSLSignature$SHA1RSAPSS");
        put("Alg.Alias.Signature.SHA1withRSAandMGF1", "SHA1withRSA/PSS");

        putSignatureImplClass("SHA224withRSA/PSS", "OpenSSLSignature$SHA224RSAPSS");
        put("Alg.Alias.Signature.SHA224withRSAandMGF1", "SHA224withRSA/PSS");

        putSignatureImplClass("SHA256withRSA/PSS", "OpenSSLSignature$SHA256RSAPSS");
        put("Alg.Alias.Signature.SHA256withRSAandMGF1", "SHA256withRSA/PSS");

        putSignatureImplClass("SHA384withRSA/PSS", "OpenSSLSignature$SHA384RSAPSS");
        put("Alg.Alias.Signature.SHA384withRSAandMGF1", "SHA384withRSA/PSS");

        putSignatureImplClass("SHA512withRSA/PSS", "OpenSSLSignature$SHA512RSAPSS");
        put("Alg.Alias.Signature.SHA512withRSAandMGF1", "SHA512withRSA/PSS");

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

        putRSACipherImplClass("RSA/ECB/OAEPPadding", "OpenSSLCipherRSA$OAEP$SHA1");
        put("Alg.Alias.Cipher.RSA/None/OAEPPadding", "RSA/ECB/OAEPPadding");
        putRSACipherImplClass("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "OpenSSLCipherRSA$OAEP$SHA1");
        put("Alg.Alias.Cipher.RSA/None/OAEPWithSHA-1AndMGF1Padding",
                "RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        putRSACipherImplClass(
                "RSA/ECB/OAEPWithSHA-224AndMGF1Padding", "OpenSSLCipherRSA$OAEP$SHA224");
        put("Alg.Alias.Cipher.RSA/None/OAEPWithSHA-224AndMGF1Padding",
                "RSA/ECB/OAEPWithSHA-224AndMGF1Padding");
        putRSACipherImplClass(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "OpenSSLCipherRSA$OAEP$SHA256");
        put("Alg.Alias.Cipher.RSA/None/OAEPWithSHA-256AndMGF1Padding",
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        putRSACipherImplClass(
                "RSA/ECB/OAEPWithSHA-384AndMGF1Padding", "OpenSSLCipherRSA$OAEP$SHA384");
        put("Alg.Alias.Cipher.RSA/None/OAEPWithSHA-384AndMGF1Padding",
                "RSA/ECB/OAEPWithSHA-384AndMGF1Padding");
        putRSACipherImplClass(
                "RSA/ECB/OAEPWithSHA-512AndMGF1Padding", "OpenSSLCipherRSA$OAEP$SHA512");
        put("Alg.Alias.Cipher.RSA/None/OAEPWithSHA-512AndMGF1Padding",
                "RSA/ECB/OAEPWithSHA-512AndMGF1Padding");

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
                "OpenSSLEvpCipherAES$AES$ECB$NoPadding");
        putSymmetricCipherImplClass("AES/ECB/PKCS5Padding",
                "OpenSSLEvpCipherAES$AES$ECB$PKCS5Padding");
        put("Alg.Alias.Cipher.AES/ECB/PKCS7Padding", "AES/ECB/PKCS5Padding");
        putSymmetricCipherImplClass("AES/CBC/NoPadding",
                "OpenSSLEvpCipherAES$AES$CBC$NoPadding");
        putSymmetricCipherImplClass("AES/CBC/PKCS5Padding",
                "OpenSSLEvpCipherAES$AES$CBC$PKCS5Padding");
        put("Alg.Alias.Cipher.AES/CBC/PKCS7Padding", "AES/CBC/PKCS5Padding");
        putSymmetricCipherImplClass("AES/CTR/NoPadding", "OpenSSLEvpCipherAES$AES$CTR");

        putSymmetricCipherImplClass(
                "AES_128/ECB/NoPadding", "OpenSSLEvpCipherAES$AES_128$ECB$NoPadding");
        putSymmetricCipherImplClass(
                "AES_128/ECB/PKCS5Padding", "OpenSSLEvpCipherAES$AES_128$ECB$PKCS5Padding");
        put("Alg.Alias.Cipher.AES_128/ECB/PKCS7Padding", "AES_128/ECB/PKCS5Padding");
        putSymmetricCipherImplClass(
                "AES_128/CBC/NoPadding", "OpenSSLEvpCipherAES$AES_128$CBC$NoPadding");
        putSymmetricCipherImplClass(
                "AES_128/CBC/PKCS5Padding", "OpenSSLEvpCipherAES$AES_128$CBC$PKCS5Padding");
        put("Alg.Alias.Cipher.AES_128/CBC/PKCS7Padding", "AES_128/CBC/PKCS5Padding");

        put("Alg.Alias.Cipher.PBEWithHmacSHA1AndAES_128", "AES_128/CBC/PKCS5PADDING");
        put("Alg.Alias.Cipher.PBEWithHmacSHA224AndAES_128", "AES_128/CBC/PKCS5PADDING");
        put("Alg.Alias.Cipher.PBEWithHmacSHA256AndAES_128", "AES_128/CBC/PKCS5PADDING");
        put("Alg.Alias.Cipher.PBEWithHmacSHA384AndAES_128", "AES_128/CBC/PKCS5PADDING");
        put("Alg.Alias.Cipher.PBEWithHmacSHA512AndAES_128", "AES_128/CBC/PKCS5PADDING");

        putSymmetricCipherImplClass(
                "AES_256/ECB/NoPadding", "OpenSSLEvpCipherAES$AES_256$ECB$NoPadding");
        putSymmetricCipherImplClass(
                "AES_256/ECB/PKCS5Padding", "OpenSSLEvpCipherAES$AES_256$ECB$PKCS5Padding");
        put("Alg.Alias.Cipher.AES_256/ECB/PKCS7Padding", "AES_256/ECB/PKCS5Padding");
        putSymmetricCipherImplClass(
                "AES_256/CBC/NoPadding", "OpenSSLEvpCipherAES$AES_256$CBC$NoPadding");
        putSymmetricCipherImplClass(
                "AES_256/CBC/PKCS5Padding", "OpenSSLEvpCipherAES$AES_256$CBC$PKCS5Padding");
        put("Alg.Alias.Cipher.AES_256/CBC/PKCS7Padding", "AES_256/CBC/PKCS5Padding");

        put("Alg.Alias.Cipher.PBEWithHmacSHA1AndAES_256", "AES_256/CBC/PKCS5PADDING");
        put("Alg.Alias.Cipher.PBEWithHmacSHA224AndAES_256", "AES_256/CBC/PKCS5PADDING");
        put("Alg.Alias.Cipher.PBEWithHmacSHA256AndAES_256", "AES_256/CBC/PKCS5PADDING");
        put("Alg.Alias.Cipher.PBEWithHmacSHA384AndAES_256", "AES_256/CBC/PKCS5PADDING");
        put("Alg.Alias.Cipher.PBEWithHmacSHA512AndAES_256", "AES_256/CBC/PKCS5PADDING");

        putSymmetricCipherImplClass("DESEDE/CBC/NoPadding",
                "OpenSSLEvpCipherDESEDE$CBC$NoPadding");
        putSymmetricCipherImplClass("DESEDE/CBC/PKCS5Padding",
                "OpenSSLEvpCipherDESEDE$CBC$PKCS5Padding");
        put("Alg.Alias.Cipher.DESEDE/CBC/PKCS7Padding", "DESEDE/CBC/PKCS5Padding");

        putSymmetricCipherImplClass("ARC4", "OpenSSLEvpCipherARC4");
        put("Alg.Alias.Cipher.ARCFOUR", "ARC4");
        put("Alg.Alias.Cipher.RC4", "ARC4");
        put("Alg.Alias.Cipher.1.2.840.113549.3.4", "ARC4");
        put("Alg.Alias.Cipher.OID.1.2.840.113549.3.4", "ARC4");

        putSymmetricCipherImplClass("AES/GCM/NoPadding", "OpenSSLAeadCipherAES$GCM");
        put("Alg.Alias.Cipher.GCM", "AES/GCM/NoPadding");
        put("Alg.Alias.Cipher.2.16.840.1.101.3.4.1.6", "AES/GCM/NoPadding");
        put("Alg.Alias.Cipher.2.16.840.1.101.3.4.1.26", "AES/GCM/NoPadding");
        put("Alg.Alias.Cipher.2.16.840.1.101.3.4.1.46", "AES/GCM/NoPadding");
        putSymmetricCipherImplClass(
                "AES_128/GCM/NoPadding", "OpenSSLAeadCipherAES$GCM$AES_128");
        putSymmetricCipherImplClass(
                "AES_256/GCM/NoPadding", "OpenSSLAeadCipherAES$GCM$AES_256");

        putSymmetricCipherImplClass("AES/GCM-SIV/NoPadding", "OpenSSLAeadCipherAES$GCM_SIV");
        putSymmetricCipherImplClass(
            "AES_128/GCM-SIV/NoPadding", "OpenSSLAeadCipherAES$GCM_SIV$AES_128");
        putSymmetricCipherImplClass(
            "AES_256/GCM-SIV/NoPadding", "OpenSSLAeadCipherAES$GCM_SIV$AES_256");

        putSymmetricCipherImplClass("ChaCha20",
                "OpenSSLCipherChaCha20");
        putSymmetricCipherImplClass("ChaCha20/Poly1305/NoPadding",
                "OpenSSLAeadCipherChaCha20");
        put("Alg.Alias.Cipher.ChaCha20-Poly1305", "ChaCha20/Poly1305/NoPadding");

        /* === Mac === */

        putMacImplClass("HmacMD5", "OpenSSLMac$HmacMD5");
        put("Alg.Alias.Mac.1.3.6.1.5.5.8.1.1", "HmacMD5");
        put("Alg.Alias.Mac.HMAC-MD5", "HmacMD5");
        put("Alg.Alias.Mac.HMAC/MD5", "HmacMD5");

        // PKCS#2 - iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2)
        // http://www.oid-info.com/get/1.2.840.113549.2

        // HMAC-SHA-1 PRF (7)
        putMacImplClass("HmacSHA1", "OpenSSLMac$HmacSHA1");
        put("Alg.Alias.Mac.1.2.840.113549.2.7", "HmacSHA1");
        put("Alg.Alias.Mac.1.3.6.1.5.5.8.1.2", "HmacSHA1");
        put("Alg.Alias.Mac.HMAC-SHA1", "HmacSHA1");
        put("Alg.Alias.Mac.HMAC/SHA1", "HmacSHA1");

        // id-hmacWithSHA224 (8)
        putMacImplClass("HmacSHA224", "OpenSSLMac$HmacSHA224");
        put("Alg.Alias.Mac.1.2.840.113549.2.8", "HmacSHA224");
        put("Alg.Alias.Mac.HMAC-SHA224", "HmacSHA224");
        put("Alg.Alias.Mac.HMAC/SHA224", "HmacSHA224");
        put("Alg.Alias.Mac.PBEWITHHMACSHA224", "HmacSHA224");

        // id-hmacWithSHA256 (9)
        putMacImplClass("HmacSHA256", "OpenSSLMac$HmacSHA256");
        put("Alg.Alias.Mac.1.2.840.113549.2.9", "HmacSHA256");
        put("Alg.Alias.Mac.2.16.840.1.101.3.4.2.1", "HmacSHA256");
        put("Alg.Alias.Mac.HMAC-SHA256", "HmacSHA256");
        put("Alg.Alias.Mac.HMAC/SHA256", "HmacSHA256");
        put("Alg.Alias.Mac.PBEWITHHMACSHA256", "HmacSHA256");

        // id-hmacWithSHA384 (10)
        putMacImplClass("HmacSHA384", "OpenSSLMac$HmacSHA384");
        put("Alg.Alias.Mac.1.2.840.113549.2.10", "HmacSHA384");
        put("Alg.Alias.Mac.HMAC-SHA384", "HmacSHA384");
        put("Alg.Alias.Mac.HMAC/SHA384", "HmacSHA384");
        put("Alg.Alias.Mac.PBEWITHHMACSHA384", "HmacSHA384");

        // id-hmacWithSHA384 (11)
        putMacImplClass("HmacSHA512", "OpenSSLMac$HmacSHA512");
        put("Alg.Alias.Mac.1.2.840.113549.2.11", "HmacSHA512");
        put("Alg.Alias.Mac.HMAC-SHA512", "HmacSHA512");
        put("Alg.Alias.Mac.HMAC/SHA512", "HmacSHA512");
        put("Alg.Alias.Mac.PBEWITHHMACSHA512", "HmacSHA512");

        putMacImplClass("AESCMAC", "OpenSSLMac$AesCmac");

        /* === Certificate === */
        put("CertificateFactory.X509", PREFIX + "OpenSSLX509CertificateFactory");
        put("Alg.Alias.CertificateFactory.X.509", "X509");

        /* === HPKE === */
        String baseClass = classExists("android.crypto.hpke.HpkeSpi")
                ? PREFIX + "AndroidHpkeSpi"
                : PREFIX + "HpkeImpl";

        put("ConscryptHpke.DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM",
                baseClass + "$X25519_AES_128");
        put("Alg.Alias.ConscryptHpke.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
                "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM");
        put("ConscryptHpke.DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM",
                baseClass + "$X25519_AES_256");
        put("Alg.Alias.ConscryptHpke.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
                "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM");
        put("ConscryptHpke.DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/CHACHA20POLY1305",
                baseClass + "$X25519_CHACHA20");
        put("Alg.Alias.ConscryptHpke.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_GhpkeCHACHA20POLY1305",
                "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/CHACHA20POLY1305");

        /* === PAKE === */
        if (Platform.isPakeSupported()) {
            put("TrustManagerFactory.PAKE", PREFIX + "PakeTrustManagerFactory");
            put("KeyManagerFactory.PAKE", PREFIX + "PakeKeyManagerFactory");
        }
    }

    private boolean classExists(String classname) {
        try {
            Class.forName(classname);
        } catch (ClassNotFoundException e) {
            return false;
        }
        return true;
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

    private void putXDHKeyAgreementImplClass(String className) {
        // Accept only keys for which any of the following is true:
        // * the key is from this provider (subclass of OpenSSLKeyHolder),
        // * the key provides its key material in "PKCS#8" encoding via Key.getEncoded.
        // * the key is a transparent XEC private key (subclass of XECPrivateKey).
        String supportedKeyClasses = PREFIX + "OpenSSLKeyHolder"
                + "|" + STANDARD_XEC_PRIVATE_KEY_INTERFACE_CLASS_NAME
                + "|" + PREFIX + "OpenSSLX25519PrivateKey";
        String supportedKeyFormats = "PKCS#8";
        putImplClassWithKeyConstraints(
                "KeyAgreement.XDH",
                PREFIX + className,
                supportedKeyClasses,
                supportedKeyFormats);

        put("Alg.Alias.KeyAgreement.X25519", "XDH");
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
