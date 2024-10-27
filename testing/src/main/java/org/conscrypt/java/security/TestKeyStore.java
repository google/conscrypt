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

package org.conscrypt.java.security;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.conscrypt.javax.net.ssl.TestKeyManager;
import org.conscrypt.javax.net.ssl.TestTrustManager;

/**
 * TestKeyStore is a convenience class for other tests that
 * want a canned KeyStore with a variety of key pairs.
 * <p>
 * Creating a key store is relatively slow, so a singleton instance is
 * accessible via TestKeyStore.get().
 */
public final class TestKeyStore {
    /** Size of DSA keys to generate for testing. */
    private static final int DSA_KEY_SIZE_BITS = 1024;

    /** Size of EC keys to generate for testing. */
    private static final int EC_KEY_SIZE_BITS = 256;

    /** Size of RSA keys to generate for testing. */
    private static final int RSA_KEY_SIZE_BITS = 1024;

    // Generated with: openssl dhparam -C 1024
    private static final BigInteger DH_PARAMS_P = new BigInteger(1,
            new byte[] {
                    (byte) 0xA2, (byte) 0x31, (byte) 0xB4, (byte) 0xB3, (byte) 0x6D, (byte) 0x9B,
                    (byte) 0x7E, (byte) 0xF4, (byte) 0xE7, (byte) 0x21, (byte) 0x51, (byte) 0x40,
                    (byte) 0xEB, (byte) 0xC6, (byte) 0xB6, (byte) 0xD6, (byte) 0x54, (byte) 0x56,
                    (byte) 0x72, (byte) 0xBE, (byte) 0x43, (byte) 0x18, (byte) 0x30, (byte) 0x5C,
                    (byte) 0x15, (byte) 0x5A, (byte) 0xF9, (byte) 0x19, (byte) 0x62, (byte) 0xAD,
                    (byte) 0xF4, (byte) 0x29, (byte) 0xCB, (byte) 0xC6, (byte) 0xF6, (byte) 0x64,
                    (byte) 0x0B, (byte) 0x9D, (byte) 0x23, (byte) 0x80, (byte) 0xF9, (byte) 0x5B,
                    (byte) 0x1C, (byte) 0x1C, (byte) 0x6A, (byte) 0xB4, (byte) 0xEA, (byte) 0xB9,
                    (byte) 0x80, (byte) 0x98, (byte) 0x8B, (byte) 0xAF, (byte) 0x15, (byte) 0xA8,
                    (byte) 0x5C, (byte) 0xC4, (byte) 0xB0, (byte) 0x41, (byte) 0x29, (byte) 0x66,
                    (byte) 0x9F, (byte) 0x9F, (byte) 0x1F, (byte) 0x88, (byte) 0x50, (byte) 0x97,
                    (byte) 0x38, (byte) 0x0B, (byte) 0x01, (byte) 0x16, (byte) 0xD6, (byte) 0x84,
                    (byte) 0x1D, (byte) 0x48, (byte) 0x6F, (byte) 0x7C, (byte) 0x06, (byte) 0x8C,
                    (byte) 0x6E, (byte) 0x68, (byte) 0xCD, (byte) 0x38, (byte) 0xE6, (byte) 0x22,
                    (byte) 0x30, (byte) 0x61, (byte) 0x37, (byte) 0x02, (byte) 0x3D, (byte) 0x47,
                    (byte) 0x62, (byte) 0xCE, (byte) 0xB9, (byte) 0x1A, (byte) 0x69, (byte) 0x9D,
                    (byte) 0xA1, (byte) 0x9F, (byte) 0x10, (byte) 0xA1, (byte) 0xAA, (byte) 0x70,
                    (byte) 0xF7, (byte) 0x27, (byte) 0x9C, (byte) 0xD4, (byte) 0xA5, (byte) 0x15,
                    (byte) 0xE2, (byte) 0x15, (byte) 0x0C, (byte) 0x20, (byte) 0x90, (byte) 0x08,
                    (byte) 0xB6, (byte) 0xF5, (byte) 0xDF, (byte) 0x1C, (byte) 0xCB, (byte) 0x82,
                    (byte) 0x6D, (byte) 0xC0, (byte) 0xE1, (byte) 0xBD, (byte) 0xCC, (byte) 0x4A,
                    (byte) 0x76, (byte) 0xE3,
            });

    // generator of 2
    private static final BigInteger DH_PARAMS_G = BigInteger.valueOf(2);

    private static TestKeyStore ROOT_CA;
    private static TestKeyStore INTERMEDIATE_CA;
    private static TestKeyStore INTERMEDIATE_CA_2;
    private static TestKeyStore INTERMEDIATE_CA_EC;

    private static TestKeyStore SERVER;
    private static TestKeyStore SERVER_HOSTNAME;
    private static TestKeyStore CLIENT;
    private static TestKeyStore CLIENT_CERTIFICATE;
    private static TestKeyStore CLIENT_EC_RSA_CERTIFICATE;
    private static TestKeyStore CLIENT_EC_EC_CERTIFICATE;

    private static TestKeyStore CLIENT_2;

    static {
        if (!StandardNames.IS_RI
            && !BouncyCastleProvider.class.getName().startsWith("com.android")) {
            // If we run outside of the Android system, we need to make sure
            // that the BouncyCastleProvider's static field keyInfoConverters
            // is initialized. This happens in the default constructor only.
            new BouncyCastleProvider();
        }
    }

    private static final byte[] LOCAL_HOST_ADDRESS = {127, 0, 0, 1};
    private static final String LOCAL_HOST_NAME = "localhost";
    private static final String LOCAL_HOST_NAME_IPV6 = "ip6-localhost";
    public static final String CERT_HOSTNAME = "example.com";

    public final KeyStore keyStore;
    public final char[] storePassword;
    public final char[] keyPassword;
    public final KeyManager[] keyManagers;
    public final TrustManager[] trustManagers;
    public final TrustManager trustManager;

    private TestKeyStore(KeyStore keyStore, char[] storePassword, char[] keyPassword) {
        this.keyStore = keyStore;
        this.storePassword = storePassword;
        this.keyPassword = keyPassword;
        this.keyManagers = createKeyManagers(keyStore, storePassword);
        this.trustManagers = createTrustManagers(keyStore);
        this.trustManager = trustManagers[0];
    }

    public static KeyManager[] createKeyManagers(KeyStore keyStore, char[] storePassword) {
        try {
            String kmfa = KeyManagerFactory.getDefaultAlgorithm();
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(kmfa);
            kmf.init(keyStore, storePassword);
            return TestKeyManager.wrap(kmf.getKeyManagers());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static TrustManager[] createTrustManagers(final KeyStore keyStore) {
        try {
            String tmfa = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfa);
            tmf.init(keyStore);
            return TestTrustManager.wrap(tmf.getTrustManagers());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public TestKeyStore copy() {
        return new TestKeyStore(keyStore, storePassword, keyPassword);
    }

    /**
     * Lazily create shared test certificates.
     */
    private static synchronized void initCerts() {
        if (ROOT_CA != null) {
            return;
        }
        ROOT_CA = new Builder()
                          .aliasPrefix("RootCA")
                          .subject("CN=Test Root Certificate Authority")
                          .ca(true)
                          .certificateSerialNumber(BigInteger.valueOf(1))
                          .build();
        INTERMEDIATE_CA_EC = new Builder()
                                     .aliasPrefix("IntermediateCA-EC")
                                     .keyAlgorithms("EC")
                                     .subject("CN=Test Intermediate Certificate Authority ECDSA")
                                     .ca(true)
                                     .signer(ROOT_CA.getPrivateKey("RSA", "RSA"))
                                     .rootCa(ROOT_CA.getRootCertificate("RSA"))
                                     .certificateSerialNumber(BigInteger.valueOf(2))
                                     .build();
        INTERMEDIATE_CA = new Builder()
                                  .aliasPrefix("IntermediateCA")
                                  .subject("CN=Test Intermediate Certificate Authority")
                                  .ca(true)
                                  .signer(ROOT_CA.getPrivateKey("RSA", "RSA"))
                                  .rootCa(ROOT_CA.getRootCertificate("RSA"))
                                  .certificateSerialNumber(BigInteger.valueOf(2))
                                  .build();
        SERVER = new Builder()
                         .aliasPrefix("server")
                         .signer(INTERMEDIATE_CA.getPrivateKey("RSA", "RSA"))
                         .rootCa(INTERMEDIATE_CA.getRootCertificate("RSA"))
                         .addSubjectAltNameIpAddress(LOCAL_HOST_ADDRESS)
                         .certificateSerialNumber(BigInteger.valueOf(3))
                         .build();
        SERVER_HOSTNAME = new Builder()
            .aliasPrefix("server-hostname")
            .signer(INTERMEDIATE_CA.getPrivateKey("RSA", "RSA"))
            .rootCa(INTERMEDIATE_CA.getRootCertificate("RSA"))
            .addSubjectAltNameDnsName(CERT_HOSTNAME)
            .certificateSerialNumber(BigInteger.valueOf(4))
            .build();
        CLIENT = new TestKeyStore(createClient(INTERMEDIATE_CA.keyStore), null, null);
        CLIENT_EC_RSA_CERTIFICATE = new Builder()
                                            .aliasPrefix("client-ec")
                                            .keyAlgorithms("EC")
                                            .subject("emailAddress=test-ec@user")
                                            .signer(INTERMEDIATE_CA.getPrivateKey("RSA", "RSA"))
                                            .rootCa(INTERMEDIATE_CA.getRootCertificate("RSA"))
                                            .build();
        CLIENT_EC_EC_CERTIFICATE = new Builder()
                                           .aliasPrefix("client-ec")
                                           .keyAlgorithms("EC")
                                           .subject("emailAddress=test-ec@user")
                                           .signer(INTERMEDIATE_CA_EC.getPrivateKey("EC", "RSA"))
                                           .rootCa(INTERMEDIATE_CA_EC.getRootCertificate("RSA"))
                                           .build();
        CLIENT_CERTIFICATE = new Builder()
                                     .aliasPrefix("client")
                                     .subject("emailAddress=test@user")
                                     .signer(INTERMEDIATE_CA.getPrivateKey("RSA", "RSA"))
                                     .rootCa(INTERMEDIATE_CA.getRootCertificate("RSA"))
                                     .build();
        TestKeyStore rootCa2 = new Builder()
                                       .aliasPrefix("RootCA2")
                                       .subject("CN=Test Root Certificate Authority 2")
                                       .ca(true)
                                       .build();
        INTERMEDIATE_CA_2 = new Builder()
                                    .aliasPrefix("IntermediateCA")
                                    .subject("CN=Test Intermediate Certificate Authority")
                                    .ca(true)
                                    .signer(rootCa2.getPrivateKey("RSA", "RSA"))
                                    .rootCa(rootCa2.getRootCertificate("RSA"))
                                    .build();
        CLIENT_2 = new TestKeyStore(createClient(rootCa2.keyStore), null, null);
    }

    /**
     * Return an root CA that can be used to issue new certificates.
     */
    public static TestKeyStore getRootCa() {
        initCerts();
        return ROOT_CA;
    }

    /**
     * Return an intermediate CA that can be used to issue new certificates.
     */
    public static TestKeyStore getIntermediateCa() {
        initCerts();
        return INTERMEDIATE_CA;
    }

    /**
     * Return an intermediate CA that can be used to issue new certificates.
     */
    public static TestKeyStore getIntermediateCa2() {
        initCerts();
        return INTERMEDIATE_CA_2;
    }

    /**
     * Return a server keystore with a matched RSA certificate and
     * private key as well as a CA certificate.
     */
    public static TestKeyStore getServer() {
        initCerts();
        return SERVER;
    }

    /**
     * Return a server keystore with a matched RSA certificate with SAN hostname and private key
     * as well as a CA certificate.
     */
    public static TestKeyStore getServerHostname() {
        initCerts();
        return SERVER_HOSTNAME;
    }

    /**
     * Return a keystore with a CA certificate
     */
    public static TestKeyStore getClient() {
        initCerts();
        return CLIENT;
    }

    /**
     * Return a client keystore with a matched RSA certificate and
     * private key as well as a CA certificate.
     */
    public static TestKeyStore getClientCertificate() {
        initCerts();
        return CLIENT_CERTIFICATE;
    }

    /**
     * Return a client keystore with a matched RSA certificate and
     * private key as well as a CA certificate.
     */
    public static TestKeyStore getClientEcRsaCertificate() {
        initCerts();
        return CLIENT_EC_RSA_CERTIFICATE;
    }

    /**
     * Return a client keystore with a matched RSA certificate and
     * private key as well as a CA certificate.
     */
    public static TestKeyStore getClientEcEcCertificate() {
        initCerts();
        return CLIENT_EC_EC_CERTIFICATE;
    }

    /**
     * Return a keystore with a second CA certificate that does not
     * trust the server certificate returned by getServer for negative
     * testing.
     */
    public static TestKeyStore getClientCA2() {
        initCerts();
        return CLIENT_2;
    }

    /**
     * Creates KeyStores containing the requested key types. Since key
     * generation can be expensive, most tests should reuse the RSA-only
     * singleton instance returned by TestKeyStore.get.
     */
    public static class Builder {
        private String[] keyAlgorithms = {"RSA"};
        private char[] storePassword;
        private char[] keyPassword;
        private String aliasPrefix;
        private X500Principal subject;
        private int keyUsage;
        private boolean ca;
        private PrivateKeyEntry privateEntry;
        private PrivateKeyEntry signer;
        private Certificate rootCa;
        private final List<KeyPurposeId> extendedKeyUsages = new ArrayList<>();
        private final List<Boolean> criticalExtendedKeyUsages = new ArrayList<>();
        private final List<GeneralName> subjectAltNames = new ArrayList<>();
        private final List<GeneralSubtree> permittedNameConstraints =
                new ArrayList<>();
        private final List<GeneralSubtree> excludedNameConstraints =
                new ArrayList<>();
        // Generated randomly if not set
        private BigInteger certificateSerialNumber = null;

        public Builder() {
        }

        /**
         * Sets the requested key types to generate and include. The default is
         * RSA only.
         */
        public Builder keyAlgorithms(String... keyAlgorithms) {
            this.keyAlgorithms = keyAlgorithms;
            return this;
        }

        /** A unique prefix to identify the key aliases */
        public Builder aliasPrefix(String aliasPrefix) {
            this.aliasPrefix = aliasPrefix;
            return this;
        }

        /**
         * Sets the subject common name. The default is the local host's
         * canonical name.
         */
        public Builder subject(X500Principal subject) {
            this.subject = subject;
            return this;
        }

        public Builder subject(String commonName) {
            return subject(new X500Principal(commonName));
        }

        /** {@link KeyUsage} bit mask for 2.5.29.15 extension */
        public Builder keyUsage(int keyUsage) {
            this.keyUsage = keyUsage;
            return this;
        }

        /** true If the keys being created are for a CA */
        public Builder ca(boolean ca) {
            this.ca = ca;
            return this;
        }

        /** a private key entry to use for the generation of the certificate */
        public Builder privateEntry(PrivateKeyEntry privateEntry) {
            this.privateEntry = privateEntry;
            return this;
        }

        /** a private key entry to be used for signing, otherwise self-sign */
        public Builder signer(PrivateKeyEntry signer) {
            this.signer = signer;
            return this;
        }

        /** a root CA to include in the final store */
        public Builder rootCa(Certificate rootCa) {
            this.rootCa = rootCa;
            return this;
        }

        public Builder addExtendedKeyUsage(KeyPurposeId keyPurposeId, boolean critical) {
            extendedKeyUsages.add(keyPurposeId);
            criticalExtendedKeyUsages.add(critical);
            return this;
        }

        public Builder addSubjectAltName(GeneralName generalName) {
            subjectAltNames.add(generalName);
            return this;
        }

        public Builder addSubjectAltNameDnsName(String dnsName) {
            return addSubjectAltName(
                    new GeneralName(GeneralName.dNSName, dnsName));
        }

        public Builder addSubjectAltNameIpAddress(byte[] ipAddress) {
            return addSubjectAltName(
                    new GeneralName(GeneralName.iPAddress, new DEROctetString(ipAddress)));
        }

        private Builder addNameConstraint(boolean permitted, GeneralName generalName) {
            if (permitted) {
                permittedNameConstraints.add(new GeneralSubtree(generalName));
            } else {
                excludedNameConstraints.add(new GeneralSubtree(generalName));
            }
            return this;
        }

        public Builder addNameConstraint(boolean permitted, byte[] ipAddress) {
            return addNameConstraint(permitted,
                    new GeneralName(GeneralName.iPAddress, new DEROctetString(ipAddress)));
        }

        public Builder certificateSerialNumber(BigInteger certificateSerialNumber) {
            this.certificateSerialNumber = certificateSerialNumber;
            return this;
        }

        public TestKeyStore build() {
            try {
                if (StandardNames.IS_RI) {
                    // JKS does not allow null password
                    if (storePassword == null) {
                        storePassword = "password".toCharArray();
                    }
                    if (keyPassword == null) {
                        keyPassword = "password".toCharArray();
                    }
                }

                /*
                 * This is not implemented for other key types because the logic
                 * would be long to write and it's not needed currently.
                 */
                if (privateEntry != null
                        && (keyAlgorithms.length != 1 || !"RSA".equals(keyAlgorithms[0]))) {
                    throw new IllegalStateException(
                            "Only reusing an existing key is implemented for RSA");
                }

                KeyStore keyStore = createKeyStore();
                for (String keyAlgorithm : keyAlgorithms) {
                    String publicAlias = aliasPrefix + "-public-" + keyAlgorithm;
                    String privateAlias = aliasPrefix + "-private-" + keyAlgorithm;
                    if ((keyAlgorithm.equals("EC_RSA") || keyAlgorithm.equals("DH_RSA"))
                            && signer == null && rootCa == null) {
                        createKeys(keyStore, keyAlgorithm, publicAlias, privateAlias, null,
                                privateKey(keyStore, keyPassword, "RSA", "RSA"));
                        continue;
                    } else if (keyAlgorithm.equals("DH_DSA") && signer == null && rootCa == null) {
                        createKeys(keyStore, keyAlgorithm, publicAlias, privateAlias, null,
                                privateKey(keyStore, keyPassword, "DSA", "DSA"));
                        continue;
                    }
                    createKeys(keyStore, keyAlgorithm, publicAlias, privateAlias, privateEntry,
                            signer);
                }
                if (rootCa != null) {
                    keyStore.setCertificateEntry(
                            aliasPrefix + "-root-ca-" + rootCa.getPublicKey().getAlgorithm(),
                            rootCa);
                }
                return new TestKeyStore(keyStore, storePassword, keyPassword);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        /**
         * Add newly generated keys of a given key type to an existing
         * KeyStore. The PrivateKey will be stored under the specified
         * private alias name. The X509Certificate will be stored on the
         * public alias name and have the given subject distinguished
         * name.
         * <p>
         * If a CA is provided, it will be used to sign the generated
         * certificate and OCSP responses. Otherwise, the certificate
         * will be self signed. The certificate will be valid for one
         * day before and one day after the time of creation.
         * <p>
         * Based on:
         * org.bouncycastle.jce.provider.test.SigTest
         * org.bouncycastle.jce.provider.test.CertTest
         */
        private KeyStore createKeys(KeyStore keyStore, String keyAlgorithm, String publicAlias,
                String privateAlias, PrivateKeyEntry privateEntry, PrivateKeyEntry signer)
                throws Exception {
            PrivateKey caKey;
            X509Certificate caCert;
            X509Certificate[] caCertChain;
            if (signer == null) {
                caKey = null;
                caCert = null;
                caCertChain = null;
            } else {
                caKey = signer.getPrivateKey();
                caCert = (X509Certificate) signer.getCertificate();
                caCertChain = (X509Certificate[]) signer.getCertificateChain();
            }

            // Default to localhost if nothing was specified.
            if (subject == null) {
                subject = localhost();
                addSubjectAltNameDnsName(LOCAL_HOST_NAME);
                addSubjectAltNameDnsName(LOCAL_HOST_NAME_IPV6);
            }

            final PrivateKey privateKey;
            final PublicKey publicKey;
            X509Certificate x509c;
            if (publicAlias == null && privateAlias == null) {
                // don't want anything apparently
                privateKey = null;
                x509c = null;
            } else {
                if (privateEntry == null) {
                    // 1a.) we make the keys
                    int keySize = -1;
                    AlgorithmParameterSpec spec = null;
                    if (keyAlgorithm.equals("RSA")) {
                        keySize = RSA_KEY_SIZE_BITS;
                    } else if (keyAlgorithm.equals("DH_RSA")) {
                        spec = new DHParameterSpec(DH_PARAMS_P, DH_PARAMS_G);
                        keyAlgorithm = "DH";
                    } else if (keyAlgorithm.equals("DSA")) {
                        keySize = DSA_KEY_SIZE_BITS;
                    } else if (keyAlgorithm.equals("DH_DSA")) {
                        spec = new DHParameterSpec(DH_PARAMS_P, DH_PARAMS_G);
                        keyAlgorithm = "DH";
                    } else if (keyAlgorithm.equals("EC")) {
                        keySize = EC_KEY_SIZE_BITS;
                    } else if (keyAlgorithm.equals("EC_RSA")) {
                        keySize = EC_KEY_SIZE_BITS;
                        keyAlgorithm = "EC";
                    } else {
                        throw new IllegalArgumentException("Unknown key algorithm " + keyAlgorithm);
                    }

                    KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm);
                    if (spec != null) {
                        kpg.initialize(spec);
                    } else {
                        kpg.initialize(keySize);
                    }

                    KeyPair kp = kpg.generateKeyPair();
                    privateKey = kp.getPrivate();
                    publicKey = kp.getPublic();
                } else {
                    // 1b.) we use the previous keys
                    privateKey = privateEntry.getPrivateKey();
                    publicKey = privateEntry.getCertificate().getPublicKey();
                }

                // 2.) use keys to make certificate
                X500Principal issuer =
                        ((caCert != null) ? caCert.getSubjectX500Principal() : subject);
                PrivateKey signingKey = (caKey == null) ? privateKey : caKey;
                x509c = createCertificate(publicKey, signingKey, subject, issuer, keyUsage, ca,
                        extendedKeyUsages, criticalExtendedKeyUsages, subjectAltNames,
                        permittedNameConstraints, excludedNameConstraints, certificateSerialNumber);
            }

            X509Certificate[] x509cc;
            if (privateAlias == null) {
                // don't need certificate chain
                x509cc = null;
            } else if (caCertChain == null) {
                x509cc = new X509Certificate[] {x509c};
            } else {
                x509cc = new X509Certificate[caCertChain.length + 1];
                x509cc[0] = x509c;
                System.arraycopy(caCertChain, 0, x509cc, 1, caCertChain.length);
            }

            // 3.) put certificate and private key into the key store
            if (privateAlias != null) {
                keyStore.setKeyEntry(privateAlias, privateKey, keyPassword, x509cc);
            }
            if (publicAlias != null) {
                keyStore.setCertificateEntry(publicAlias, x509c);
            }
            return keyStore;
        }

        private X500Principal localhost() {
            return new X500Principal("CN=" + LOCAL_HOST_NAME);
        }
    }

    public static X509Certificate createCa(
            PublicKey publicKey, PrivateKey privateKey, String subject) {
        try {
            X500Principal principal = new X500Principal(subject);
            return createCertificate(publicKey, privateKey, principal, principal, 0, true,
                    new ArrayList<>(), new ArrayList<>(),
                    new ArrayList<>(), new ArrayList<>(),
                    new ArrayList<>(), null /* serialNumber, generated randomly */);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("JavaUtilDate")
    private static X509Certificate createCertificate(PublicKey publicKey, PrivateKey privateKey,
            X500Principal subject, X500Principal issuer, int keyUsage, boolean ca,
            List<KeyPurposeId> extendedKeyUsages, List<Boolean> criticalExtendedKeyUsages,
            List<GeneralName> subjectAltNames, List<GeneralSubtree> permittedNameConstraints,
            List<GeneralSubtree> excludedNameConstraints, BigInteger serialNumber)
            throws Exception {
        // Note that there is no way to programmatically make a
        // Certificate using java.* or javax.* APIs. The
        // CertificateFactory interface assumes you want to read
        // in a stream of bytes, typically the X.509 factory would
        // allow ASN.1 DER encoded bytes and optionally some PEM
        // formats. Here we use Bouncy Castle's
        // X509V3CertificateGenerator and related classes.

        long millisPerDay = 24 * 60 * 60 * 1000;
        long now = System.currentTimeMillis();
        Date start = new Date(now - millisPerDay);
        Date end = new Date(now + millisPerDay);

        String keyAlgorithm = privateKey.getAlgorithm();
        String signatureAlgorithm;
        if (keyAlgorithm.equals("RSA")) {
            signatureAlgorithm = "sha256WithRSA";
        } else if (keyAlgorithm.equals("DSA")) {
            signatureAlgorithm = "sha256WithDSA";
        } else if (keyAlgorithm.equals("EC")) {
            signatureAlgorithm = "sha256WithECDSA";
        } else if (keyAlgorithm.equals("EC_RSA")) {
            signatureAlgorithm = "sha256WithRSA";
        } else {
            throw new IllegalArgumentException("Unknown key algorithm " + keyAlgorithm);
        }

        if (serialNumber == null) {
            byte[] serialBytes = new byte[16];
            new SecureRandom().nextBytes(serialBytes);
            serialNumber = new BigInteger(1, serialBytes);
        }

        X509v3CertificateBuilder x509cg =
                new X509v3CertificateBuilder(X500Name.getInstance(issuer.getEncoded()),
                        serialNumber, start, end, X500Name.getInstance(subject.getEncoded()),
                        SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
        if (keyUsage != 0) {
            x509cg.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        }
        if (ca) {
            x509cg.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        }
        for (int i = 0; i < extendedKeyUsages.size(); i++) {
            KeyPurposeId keyPurposeId = extendedKeyUsages.get(i);
            boolean critical = criticalExtendedKeyUsages.get(i);
            x509cg.addExtension(
                    Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(keyPurposeId));
        }
        if (!subjectAltNames.isEmpty()) {
            x509cg.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(subjectAltNames.toArray(new GeneralName[0])).getEncoded());
        }
        if (!permittedNameConstraints.isEmpty() || !excludedNameConstraints.isEmpty()) {
            x509cg.addExtension(Extension.nameConstraints, true,
                    new NameConstraints(
                            permittedNameConstraints.toArray(new GeneralSubtree[0]),
                            excludedNameConstraints.toArray(new GeneralSubtree[0])));
        }

        X509CertificateHolder x509holder =
                x509cg.build(new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey));
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate x509c = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(x509holder.getEncoded()));
        if (StandardNames.IS_RI) {
            /*
             * The RI can't handle the BC EC signature algorithm
             * string of "ECDSA", since it expects "...WITHEC...",
             * so convert from BC to RI X509Certificate
             * implementation via bytes.
             */
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bais = new ByteArrayInputStream(x509c.getEncoded());
            Certificate c = cf.generateCertificate(bais);
            x509c = (X509Certificate) c;
        }
        return x509c;
    }

    /**
     * Return the key algorithm for a possible compound algorithm
     * identifier containing an underscore. If not underscore is
     * present, the argument is returned unmodified. However for an
     * algorithm such as EC_RSA, return EC.
     */
    public static String keyAlgorithm(String algorithm) {
        int index = algorithm.indexOf('_');
        if (index == -1) {
            return algorithm;
        }
        return algorithm.substring(0, index);
    }

    /**
     * Return the signature algorithm for a possible compound
     * algorithm identifier containing an underscore. If not
     * underscore is present, the argument is returned
     * unmodified. However for an algorithm such as EC_RSA, return
     * RSA.
     */
    public static String signatureAlgorithm(String algorithm) {
        int index = algorithm.indexOf('_');
        if (index == -1) {
            return algorithm;
        }
        return algorithm.substring(index + 1);
    }

    /**
     * Create an empty KeyStore
     */
    public static KeyStore createKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance(StandardNames.KEY_STORE_ALGORITHM);
            keyStore.load(null, null);
            return keyStore;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Return the only private key in a TestKeyStore for the given
     * algorithms. Throws IllegalStateException if there are are more
     * or less than one.
     */
    public PrivateKeyEntry getPrivateKey(String keyAlgorithm, String signatureAlgorithm) {
        return privateKey(keyStore, keyPassword, keyAlgorithm, signatureAlgorithm);
    }

    /**
     * Return the only private key in a keystore for the given
     * algorithms. Throws IllegalStateException if there are are more
     * or less than one.
     */
    public static PrivateKeyEntry privateKey(
            KeyStore keyStore, char[] keyPassword, String keyAlgorithm, String signatureAlgorithm) {
        try {
            PrivateKeyEntry found = null;
            PasswordProtection password = new PasswordProtection(keyPassword);
            for (String alias : Collections.list(keyStore.aliases())) {
                if (!keyStore.entryInstanceOf(alias, PrivateKeyEntry.class)) {
                    continue;
                }
                PrivateKeyEntry privateKey = (PrivateKeyEntry) keyStore.getEntry(alias, password);
                if (!privateKey.getPrivateKey().getAlgorithm().equals(keyAlgorithm)) {
                    continue;
                }
                X509Certificate certificate = (X509Certificate) privateKey.getCertificate();
                if (!certificate.getSigAlgName().contains(signatureAlgorithm)) {
                    continue;
                }
                if (found != null) {
                    throw new IllegalStateException("KeyStore has more than one private key for"
                            + " keyAlgorithm: " + keyAlgorithm + " signatureAlgorithm: "
                            + signatureAlgorithm + "\nfirst: " + found.getPrivateKey()
                            + "\nsecond: " + privateKey.getPrivateKey());
                }
                found = privateKey;
            }
            if (found == null) {
                throw new IllegalStateException("KeyStore contained no private key for"
                        + " keyAlgorithm: " + keyAlgorithm
                        + " signatureAlgorithm: " + signatureAlgorithm);
            }
            return found;
        } catch (Exception e) {
            throw new RuntimeException("Problem getting key for " + keyAlgorithm + " and signature "
                            + signatureAlgorithm,
                    e);
        }
    }

    /**
     * Return the issuing CA certificate of the given
     * certificate. Throws IllegalStateException if there are are more
     * or less than one.
     */
    public Certificate getIssuer(Certificate cert) throws Exception {
        return issuer(keyStore, cert);
    }

    /**
     * Return the issuing CA certificate of the given
     * certificate. Throws IllegalStateException if there are are more
     * or less than one.
     */
    public static Certificate issuer(KeyStore keyStore, Certificate c) throws Exception {
        if (!(c instanceof X509Certificate)) {
            throw new IllegalStateException("issuer requires an X509Certificate, found " + c);
        }
        X509Certificate cert = (X509Certificate) c;

        Certificate found = null;
        for (String alias : Collections.list(keyStore.aliases())) {
            if (!keyStore.entryInstanceOf(alias, TrustedCertificateEntry.class)) {
                continue;
            }
            TrustedCertificateEntry certificateEntry =
                    (TrustedCertificateEntry) keyStore.getEntry(alias, null);
            Certificate certificate = certificateEntry.getTrustedCertificate();
            if (!(certificate instanceof X509Certificate)) {
                continue;
            }
            X509Certificate x = (X509Certificate) certificate;
            if (!cert.getIssuerDN().equals(x.getSubjectDN())) {
                continue;
            }
            if (found != null) {
                throw new IllegalStateException("KeyStore has more than one issuing CA for " + cert
                        + "\nfirst: " + found + "\nsecond: " + certificate);
            }
            found = certificate;
        }
        if (found == null) {
            throw new IllegalStateException("KeyStore contained no issuing CA for " + cert);
        }
        return found;
    }

    /**
     * Return the only self-signed root certificate in a TestKeyStore
     * for the given algorithm. Throws IllegalStateException if there
     * are are more or less than one.
     */
    public X509Certificate getRootCertificate(String algorithm) {
        return rootCertificate(keyStore, algorithm);
    }

    @SuppressWarnings("JavaUtilDate")
    private static OCSPResp generateOCSPResponse(PrivateKeyEntry server, PrivateKeyEntry issuer,
            CertificateStatus status) throws CertificateException {
        try {
            X509Certificate serverCertJca = (X509Certificate) server.getCertificate();
            X509Certificate caCertJca = (X509Certificate) issuer.getCertificate();

            X509CertificateHolder caCert = new JcaX509CertificateHolder(caCertJca);

            DigestCalculatorProvider digCalcProv = new BcDigestCalculatorProvider();
            BasicOCSPRespBuilder basicBuilder = new BasicOCSPRespBuilder(
                    SubjectPublicKeyInfo.getInstance(caCertJca.getPublicKey().getEncoded()),
                    digCalcProv.get(CertificateID.HASH_SHA1));

            CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
                    caCert, serverCertJca.getSerialNumber());

            basicBuilder.addResponse(certId, status);

            BasicOCSPResp resp = basicBuilder.build(
                    new JcaContentSignerBuilder("SHA256withRSA").build(issuer.getPrivateKey()),
                    null, new Date());

            OCSPRespBuilder builder = new OCSPRespBuilder();
            return builder.build(OCSPRespBuilder.SUCCESSFUL, resp);
        } catch (Exception e) {
            throw new CertificateException("cannot generate OCSP response", e);
        }
    }

    @SuppressWarnings({"JavaUtilDate", "unused"}) // TODO(prb): Use this.
    private static byte[] getOCSPResponseForGood(PrivateKeyEntry server, PrivateKeyEntry issuer)
            throws CertificateException {
        try {
            return generateOCSPResponse(server, issuer, CertificateStatus.GOOD).getEncoded();
        } catch (IOException e) {
            throw new CertificateException(e);
        }
    }

    @SuppressWarnings({"JavaUtilDate", "unused"}) // TODO(prb): Use this.
    private static byte[] getOCSPResponseForRevoked(PrivateKeyEntry server, PrivateKeyEntry issuer)
            throws CertificateException {
        try {
            return generateOCSPResponse(
                    server, issuer, new RevokedStatus(new Date(), CRLReason.keyCompromise))
                    .getEncoded();
        } catch (IOException e) {
            throw new CertificateException(e);
        }
    }

    /**
     * Return the only self-signed root certificate in a keystore for
     * the given algorithm. Throws IllegalStateException if there are
     * are more or less than one.
     */
    @SuppressWarnings("JavaUtilDate")
    public static X509Certificate rootCertificate(KeyStore keyStore, String algorithm) {
        try {
            X509Certificate found = null;
            for (String alias : Collections.list(keyStore.aliases())) {
                if (!keyStore.entryInstanceOf(alias, TrustedCertificateEntry.class)) {
                    continue;
                }
                TrustedCertificateEntry certificateEntry =
                        (TrustedCertificateEntry) keyStore.getEntry(alias, null);
                Certificate certificate = certificateEntry.getTrustedCertificate();
                if (!certificate.getPublicKey().getAlgorithm().equals(algorithm)) {
                    continue;
                }
                if (!(certificate instanceof X509Certificate)) {
                    continue;
                }
                X509Certificate x = (X509Certificate) certificate;
                if (!x.getIssuerDN().equals(x.getSubjectDN())) {
                    continue;
                }
                if (found != null) {
                    throw new IllegalStateException("KeyStore has more than one root CA for "
                            + algorithm + "\nfirst: " + found + "\nsecond: " + certificate);
                }
                found = x;
            }
            if (found == null) {
                throw new IllegalStateException("KeyStore contained no root CA for " + algorithm);
            }
            return found;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Return an {@code X509Certificate} that matches the given {@code alias}.
     */
    public KeyStore.Entry getEntryByAlias(String alias) {
        return entryByAlias(keyStore, alias);
    }

    /**
     * Finds an entry in the keystore by the given alias.
     */
    public static KeyStore.Entry entryByAlias(KeyStore keyStore, String alias) {
        try {
            return keyStore.getEntry(alias, null);
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create a client key store that only contains self-signed certificates but no private keys
     */
    public static KeyStore createClient(KeyStore caKeyStore) {
        KeyStore clientKeyStore = createKeyStore();
        copySelfSignedCertificates(clientKeyStore, caKeyStore);
        return clientKeyStore;
    }

    /**
     * Copy self-signed certificates from one key store to another.
     * Returns true if successful, false if no match found.
     */
    public static boolean copySelfSignedCertificates(KeyStore dst, KeyStore src) {
        try {
            boolean copied = false;
            for (String alias : Collections.list(src.aliases())) {
                if (!src.isCertificateEntry(alias)) {
                    continue;
                }
                X509Certificate cert = (X509Certificate) src.getCertificate(alias);
                if (!cert.getSubjectDN().equals(cert.getIssuerDN())) {
                    continue;
                }
                dst.setCertificateEntry(alias, cert);
                copied = true;
            }
            return copied;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Copy named certificates from one key store to another.
     * Returns true if successful, false if no match found.
     */
    public static boolean copyCertificate(Principal subject, KeyStore dst, KeyStore src)
            throws Exception {
        for (String alias : Collections.list(src.aliases())) {
            if (!src.isCertificateEntry(alias)) {
                continue;
            }
            X509Certificate cert = (X509Certificate) src.getCertificate(alias);
            if (!cert.getSubjectDN().equals(subject)) {
                continue;
            }
            dst.setCertificateEntry(alias, cert);
            return true;
        }
        return false;
    }

    /**
     * Dump a key store for debugging.
     */
    public void dump(String context) throws KeyStoreException, NoSuchAlgorithmException {
        dump(context, keyStore, keyPassword);
    }

    /**
     * Dump a key store for debugging.
     */
    public static void dump(String context, KeyStore keyStore, char[] keyPassword)
            throws KeyStoreException, NoSuchAlgorithmException {
        PrintStream out = System.out;
        out.println("context=" + context);
        out.println("\tkeyStore=" + keyStore);
        out.println("\tkeyStore.type=" + keyStore.getType());
        out.println("\tkeyStore.provider=" + keyStore.getProvider());
        out.println("\tkeyPassword=" + ((keyPassword == null) ? null : new String(keyPassword)));
        out.println("\tsize=" + keyStore.size());
        for (String alias : Collections.list(keyStore.aliases())) {
            out.println("alias=" + alias);
            out.println("\tcreationDate=" + keyStore.getCreationDate(alias));
            if (keyStore.isCertificateEntry(alias)) {
                out.println("\tcertificate:");
                out.println("==========================================");
                out.println(keyStore.getCertificate(alias));
                out.println("==========================================");
                continue;
            }
            if (keyStore.isKeyEntry(alias)) {
                out.println("\tkey:");
                out.println("==========================================");
                String key;
                try {
                    key = ("Key retrieved using password\n" + keyStore.getKey(alias, keyPassword));
                } catch (UnrecoverableKeyException e1) {
                    try {
                        key = ("Key retrieved without password\n" + keyStore.getKey(alias, null));
                    } catch (UnrecoverableKeyException e2) {
                        key = "Key could not be retrieved";
                    }
                }
                out.println(key);
                out.println("==========================================");
                Certificate[] chain = keyStore.getCertificateChain(alias);
                if (chain == null) {
                    out.println("No certificate chain associated with key");
                    out.println("==========================================");
                } else {
                    for (int i = 0; i < chain.length; i++) {
                        out.println("Certificate chain element #" + i);
                        out.println(chain[i]);
                        out.println("==========================================");
                    }
                }
                continue;
            }
            out.println("\tunknown entry type");
        }
    }

    public static void assertChainLength(Object[] chain) {
        /*
         * Note chain is Object[] to support both
         * java.security.cert.X509Certificate and
         * javax.security.cert.X509Certificate
         */
        assertEquals(3, chain.length);
    }
}
