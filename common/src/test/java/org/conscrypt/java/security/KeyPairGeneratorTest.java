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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class KeyPairGeneratorTest {

    @Test
    public void test_getInstance() throws Exception {
        ServiceTester.test("KeyPairGenerator")
            // Do not test AndroidKeyStore Provider. It does not accept vanilla public keys for
            // signature verification. It's OKish not to test here because it's tested by
            // cts/tests/tests/keystore.
            .skipProvider("AndroidKeyStore")
            // The SunEC provider tries to pass a sun-only AlgorithmParameterSpec to the default
            // AlgorithmParameters:EC when its KeyPairGenerator is initialized.  Since Conscrypt
            // is the highest-ranked provider when running our tests, its implementation of
            // AlgorithmParameters:EC is returned, and it doesn't understand the special
            // AlgorithmParameterSpec, so the KeyPairGenerator can't be initialized.
            .skipProvider("SunEC")
            // The SunPKCS11-NSS provider on OpenJDK 7 attempts to delegate to the SunEC provider,
            // which doesn't exist on OpenJDK 7, and thus totally fails.  This appears to be a bug
            // introduced into later revisions of OpenJDK 7.
            .skipProvider("SunPKCS11-NSS")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider provider, String algorithm) throws Exception {
                    AlgorithmParameterSpec params = null;

                    if ("DH".equals(algorithm) || "DiffieHellman".equalsIgnoreCase(algorithm)) {
                        params = getDHParams();
                    }
                    // KeyPairGenerator.getInstance(String)
                    KeyPairGenerator kpg1 = KeyPairGenerator.getInstance(algorithm);
                    assertEquals(algorithm, kpg1.getAlgorithm());
                    if (params != null) {
                        kpg1.initialize(params);
                    }
                    test_KeyPairGenerator(kpg1);

                    // KeyPairGenerator.getInstance(String, Provider)
                    KeyPairGenerator kpg2 = KeyPairGenerator.getInstance(algorithm, provider);
                    assertEquals(algorithm, kpg2.getAlgorithm());
                    assertEquals(provider, kpg2.getProvider());
                    if (params != null) {
                        kpg2.initialize(params);
                    }
                    test_KeyPairGenerator(kpg2);

                    // KeyPairGenerator.getInstance(String, String)
                    KeyPairGenerator kpg3 = KeyPairGenerator.getInstance(algorithm,
                        provider.getName());
                    assertEquals(algorithm, kpg3.getAlgorithm());
                    assertEquals(provider, kpg3.getProvider());
                    if (params != null) {
                        kpg3.initialize(params);
                    }
                    test_KeyPairGenerator(kpg3);
                }
            });
    }

    private static final Map<String, List<Integer>> KEY_SIZES
            = new HashMap<String, List<Integer>>();
    private static void putKeySize(String algorithm, int keySize) {
        algorithm = algorithm.toUpperCase();
        List<Integer> keySizes = KEY_SIZES.get(algorithm);
        if (keySizes == null) {
            keySizes = new ArrayList<Integer>();
            KEY_SIZES.put(algorithm, keySizes);
        }
        keySizes.add(keySize);
    }
    private static List<Integer> getKeySizes(String algorithm) throws Exception {
        algorithm = algorithm.toUpperCase();
        List<Integer> keySizes = KEY_SIZES.get(algorithm);
        if (keySizes == null) {
            throw new Exception("Unknown key sizes for KeyPairGenerator." + algorithm);
        }
        return keySizes;
    }
    static {
        putKeySize("DSA", 512);
        putKeySize("DSA", 512+64);
        putKeySize("DSA", 1024);
        putKeySize("RSA", 512);
        putKeySize("RSASSA-PSS", 512);
        putKeySize("DH", 512);
        putKeySize("DH", 512+64);
        putKeySize("DH", 1024);
        putKeySize("DiffieHellman", 512);
        putKeySize("DiffieHellman", 512+64);
        putKeySize("DiffieHellman", 1024);
        putKeySize("EC", 224);
        putKeySize("EC", 256);
        putKeySize("EC", 384);
        putKeySize("EC", 521);
        putKeySize("XDH", 256);
    }

    /** Elliptic Curve Crypto named curves that should be supported. */
    private static final String[] EC_NAMED_CURVES = {
        // NIST P-256 aka SECG secp256r1 aka ANSI X9.62 prime256v1
        "secp256r1", "prime256v1",
        // NIST P-521 aka SECG secp521r1
        "secp521r1",
    };

    private void test_KeyPairGenerator(KeyPairGenerator kpg) throws Exception {
        // without a call to initialize
        test_KeyPair(kpg, kpg.genKeyPair());
        test_KeyPair(kpg, kpg.generateKeyPair());

        String algorithm = kpg.getAlgorithm();

        // TODO: detect if we're running in vogar and run the full test
        if ("DH".equals(algorithm) || "DiffieHellman".equalsIgnoreCase(algorithm)) {
            // Disabled because this takes too long on devices.
            // TODO: Re-enable DH test. http://b/5513723.
            return;
        }

        List<Integer> keySizes = getKeySizes(algorithm);
        for (int keySize : keySizes) {
            // TODO(flooey): Remove when we don't support Java 6 anymore
            if ("DSA".equals(algorithm)
                    && ("SUN".equalsIgnoreCase(kpg.getProvider().getName())
                        || "SunPKCS11-NSS".equalsIgnoreCase(kpg.getProvider().getName()))
                    && keySize != 512 && keySize != 1024) {
                // The Sun provider doesn't support DSA in all the key sizes, so ignore
                // the uncommon ones.
                continue;
            }
            kpg.initialize(keySize);
            test_KeyPair(kpg, kpg.genKeyPair());
            test_KeyPair(kpg, kpg.generateKeyPair());

            kpg.initialize(keySize, (SecureRandom) null);
            test_KeyPair(kpg, kpg.genKeyPair());
            test_KeyPair(kpg, kpg.generateKeyPair());

            kpg.initialize(keySize, new SecureRandom());
            test_KeyPair(kpg, kpg.genKeyPair());
            test_KeyPair(kpg, kpg.generateKeyPair());
        }

        if ("EC".equals(algorithm) || "ECDH".equals(algorithm)
                || "ECDSA".equals(algorithm)) {
            if ("SunPKCS11-NSS".equalsIgnoreCase(kpg.getProvider().getName())) {
                // SunPKCS11 doesn't support some of the named curves that we expect, so it
                // fails.  Skip it.
                return;
            }
            for (String curveName : EC_NAMED_CURVES) {
                kpg.initialize(new ECGenParameterSpec(curveName));
                test_KeyPair(kpg, kpg.genKeyPair());
                test_KeyPair(kpg, kpg.generateKeyPair());

                kpg.initialize(new ECGenParameterSpec(curveName), (SecureRandom) null);
                test_KeyPair(kpg, kpg.genKeyPair());
                test_KeyPair(kpg, kpg.generateKeyPair());

                kpg.initialize(new ECGenParameterSpec(curveName), new SecureRandom());
                test_KeyPair(kpg, kpg.genKeyPair());
                test_KeyPair(kpg, kpg.generateKeyPair());
            }
        }
    }

    private void test_KeyPair(KeyPairGenerator kpg, KeyPair kp) throws Exception {
        assertNotNull(kp);
        test_Key(kpg, kp.getPrivate());
        test_Key(kpg, kp.getPublic());
    }

    private void test_Key(KeyPairGenerator kpg, Key k) throws Exception {
        String expectedAlgorithm = kpg.getAlgorithm().toUpperCase(Locale.ROOT);
        if (StandardNames.IS_RI && expectedAlgorithm.equals("DIFFIEHELLMAN")) {
            expectedAlgorithm = "DH";
        }
        assertEquals(expectedAlgorithm, k.getAlgorithm().toUpperCase());
        if (expectedAlgorithm.equals("DH")) {
            if (k instanceof DHPublicKey) {
                DHPublicKey dhPub = (DHPublicKey) k;
                assertEquals(dhPub.getParams().getP(), getDHParams().getP());
            } else if (k instanceof DHPrivateKey) {
                DHPrivateKey dhPriv = (DHPrivateKey) k;
                assertEquals(dhPriv.getParams().getP(), getDHParams().getP());
            } else {
                fail("not a public or private key!?");
            }
        }
        if (kpg.getProvider().getName().equalsIgnoreCase("SunMSCAPI")
                && expectedAlgorithm.equals("RSA")) {
            // The SunMSCAPI RSA keys don't provide encoded versions at all, nor are they
            // serializable, so just skip them.
            return;
        }
        assertNotNull(k.getEncoded());
        assertNotNull(k.getFormat());

        // Test serialization
        // SunPKCS11-NSS on Java 6 replaces serialized keys with one from the default provider,
        // so the deserialized key doesn't match the original.
        if (!kpg.getProvider().getName().equalsIgnoreCase("SunPKCS11-NSS")) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(k);

            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
            ObjectInputStream ois = new ObjectInputStream(bais);
            Key inflatedKey = (Key) ois.readObject();

            assertEquals("Provider: " + kpg.getProvider(), k, inflatedKey);
        }

        test_KeyWithAllKeyFactories(k);
    }

    private void test_KeyWithAllKeyFactories(Key k) throws Exception {
        byte[] encoded = k.getEncoded();

        String keyAlgo = k.getAlgorithm();
        for (Provider p : Security.getProviders()) {
            Set<Provider.Service> services = p.getServices();
            for (Provider.Service service : services) {
                if (!"KeyFactory".equals(service.getType())) {
                    continue;
                }
                if (!service.getAlgorithm().equals(keyAlgo)) {
                    continue;
                }
                if (p.getName().equalsIgnoreCase("AndroidKeyStore")) {
                    // AndroidKeyStore only works with its own keys
                    continue;
                }
                if ("EC".equals(k.getAlgorithm())
                        && "SunPKCS11-NSS".equalsIgnoreCase(p.getName())) {
                    // SunPKCS11 doesn't support some of the named curves that we expect, so it
                    // fails.  Skip testing that combination.
                    continue;
                }
                if ("DH".equals(k.getAlgorithm())
                        && "SunPKCS11-NSS".equalsIgnoreCase(p.getName())) {
                    // SunPKCS11 omits the privateValueLength field from the DHParameter
                    // structure in its encoded keys, unlike every other provider seen,
                    // so ignore it.
                    continue;
                }
                if ("XDH".equals(k.getAlgorithm())
                        && "SunEC".equalsIgnoreCase(p.getName())
                        && "11".equals(System.getProperty("java.specification.version"))) {
                    // SunEC in OpenJDK 11 has a bug where the format specified in RFC 8410
                    // Section 7. It uses a single OCTET STRING to represent the key instead
                    // of an OCTET STRING inside of an OCTET STRING as defined in the RFC:
                    // ("For the keys defined in this document, the private key is always an
                    //   opaque byte sequence.  The ASN.1 type CurvePrivateKey is defined in
                    //   this document to hold the byte sequence.  Thus, when encoding a
                    //   OneAsymmetricKey object, the private key is wrapped in a
                    //   CurvePrivateKey object and wrapped by the OCTET STRING of the
                    //   "privateKey" field.")
                    continue;
                }

                if ("PKCS#8".equals(k.getFormat())) {
                    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
                    KeyFactory kf = KeyFactory.getInstance(k.getAlgorithm(), p);
                    PrivateKey privKey = kf.generatePrivate(spec);
                    assertNotNull(k.getAlgorithm() + ", provider=" + p.getName(), privKey);

                    /*
                     * EC keys are unique because they can have explicit parameters or a curve
                     * name. Check them specially so this test can continue to function.
                     */
                    if (k instanceof ECPrivateKey) {
                        assertECPrivateKeyEquals((ECPrivateKey) k, (ECPrivateKey) privKey);
                    } else {
                        assertEquals(k.getAlgorithm() + ", provider=" + p.getName(),
                                TestUtils.encodeBase64(encoded),
                                TestUtils.encodeBase64(privKey.getEncoded()));
                    }
                } else if ("X.509".equals(k.getFormat())) {
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
                    KeyFactory kf = KeyFactory.getInstance(k.getAlgorithm(), p);
                    PublicKey pubKey = kf.generatePublic(spec);
                    assertNotNull(pubKey);
                    assertEquals(k.getAlgorithm() + ", provider=" + p.getName(),
                            TestUtils.encodeBase64(encoded),
                            TestUtils.encodeBase64(pubKey.getEncoded()));
                }
            }
        }
    }

    private static void assertECPrivateKeyEquals(ECPrivateKey expected, ECPrivateKey actual) {
        assertEquals(expected.getS(), actual.getS());
        assertECParametersEquals(expected.getParams(), actual.getParams());
    }

    private static void assertECParametersEquals(ECParameterSpec expected, ECParameterSpec actual) {
        assertEquals(expected.getCurve(), actual.getCurve());
        assertEquals(expected.getGenerator(), actual.getGenerator());
        assertEquals(expected.getOrder(), actual.getOrder());
        assertEquals(expected.getCofactor(), actual.getCofactor());
    }

    /**
     * DH parameters pre-generated so that the test doesn't take too long.
     * These parameters were generated with:
     *
     * openssl gendh 512 | openssl dhparams -C
     */
    private static DHParameterSpec getDHParams() {
        BigInteger p = new BigInteger("E7AB1768BD75CD24700960FFA32D3F1557344E587101237532CC641646ED7A7C104743377F6D46251698B665CE2A6CBAB6714C2569A7D2CA22C0CF03FA40AC93", 16);
        BigInteger g = new BigInteger("02", 16);
        return new DHParameterSpec(p, g, 512);
    }

    private static final BigInteger DSA_P = new BigInteger(new byte[] {
        (byte) 0x00, (byte) 0x9e, (byte) 0x61, (byte) 0xc2, (byte) 0x89, (byte) 0xef, (byte) 0x77, (byte) 0xa9,
        (byte) 0x4e, (byte) 0x13, (byte) 0x67, (byte) 0x64, (byte) 0x1f, (byte) 0x09, (byte) 0x01, (byte) 0xfe,
        (byte) 0x24, (byte) 0x13, (byte) 0x53, (byte) 0xe0, (byte) 0xb7, (byte) 0x90, (byte) 0xa8, (byte) 0x4e,
        (byte) 0x76, (byte) 0xfe, (byte) 0x89, (byte) 0x82, (byte) 0x7f, (byte) 0x7a, (byte) 0xc5, (byte) 0x3c,
        (byte) 0x4e, (byte) 0x0c, (byte) 0x20, (byte) 0x55, (byte) 0x30, (byte) 0x95, (byte) 0x42, (byte) 0x85,
        (byte) 0xe1, (byte) 0x40, (byte) 0x7d, (byte) 0x27, (byte) 0x8f, (byte) 0x07, (byte) 0x0d, (byte) 0xe8,
        (byte) 0xdc, (byte) 0x99, (byte) 0xef, (byte) 0xb3, (byte) 0x07, (byte) 0x94, (byte) 0x34, (byte) 0xd6,
        (byte) 0x7c, (byte) 0xff, (byte) 0x9c, (byte) 0xbe, (byte) 0x69, (byte) 0xd3, (byte) 0xeb, (byte) 0x44,
        (byte) 0x37, (byte) 0x50, (byte) 0xef, (byte) 0x49, (byte) 0xf8, (byte) 0xe2, (byte) 0x5b, (byte) 0xd8,
        (byte) 0xd1, (byte) 0x10, (byte) 0x84, (byte) 0x97, (byte) 0xea, (byte) 0xe3, (byte) 0xa5, (byte) 0x1c,
        (byte) 0xc0, (byte) 0x4e, (byte) 0x69, (byte) 0xca, (byte) 0x70, (byte) 0x3d, (byte) 0x78, (byte) 0xb9,
        (byte) 0x16, (byte) 0xe5, (byte) 0xfe, (byte) 0x61, (byte) 0x5d, (byte) 0x8a, (byte) 0x5a, (byte) 0xb3,
        (byte) 0x2c, (byte) 0x61, (byte) 0xb6, (byte) 0x01, (byte) 0x3b, (byte) 0xd0, (byte) 0x01, (byte) 0x7c,
        (byte) 0x32, (byte) 0x8d, (byte) 0xe1, (byte) 0xf3, (byte) 0x69, (byte) 0x0e, (byte) 0x8b, (byte) 0x58,
        (byte) 0xc6, (byte) 0xcf, (byte) 0x00, (byte) 0x94, (byte) 0xf8, (byte) 0x49, (byte) 0x2a, (byte) 0x4b,
        (byte) 0xea, (byte) 0xda, (byte) 0x00, (byte) 0xff, (byte) 0x4b, (byte) 0xd0, (byte) 0xbe, (byte) 0x40,
        (byte) 0x23,
    });

    private static final BigInteger DSA_Q = new BigInteger(new byte[] {
        (byte) 0x00, (byte) 0xbf, (byte) 0xee, (byte) 0xaa, (byte) 0x0f, (byte) 0x12, (byte) 0x34, (byte) 0x50,
        (byte) 0x72, (byte) 0xf8, (byte) 0x60, (byte) 0x13, (byte) 0xd8, (byte) 0xf1, (byte) 0x41, (byte) 0x01,
        (byte) 0x10, (byte) 0xa5, (byte) 0x2f, (byte) 0x57, (byte) 0x5f,
    });

    private static final BigInteger DSA_G = new BigInteger(new byte[] {
        (byte) 0x77, (byte) 0xd4, (byte) 0x7a, (byte) 0x12, (byte) 0xcc, (byte) 0x81, (byte) 0x7e, (byte) 0x7e,
        (byte) 0xeb, (byte) 0x3a, (byte) 0xfb, (byte) 0xe6, (byte) 0x86, (byte) 0x6d, (byte) 0x5a, (byte) 0x10,
        (byte) 0x1d, (byte) 0xad, (byte) 0xa9, (byte) 0x4f, (byte) 0xb9, (byte) 0x03, (byte) 0x5d, (byte) 0x21,
        (byte) 0x1a, (byte) 0xe4, (byte) 0x30, (byte) 0x95, (byte) 0x75, (byte) 0x8e, (byte) 0xcd, (byte) 0x5e,
        (byte) 0xd1, (byte) 0xbd, (byte) 0x0a, (byte) 0x45, (byte) 0xee, (byte) 0xe7, (byte) 0xf7, (byte) 0x6b,
        (byte) 0x65, (byte) 0x02, (byte) 0x60, (byte) 0xd0, (byte) 0x2e, (byte) 0xaf, (byte) 0x3d, (byte) 0xbc,
        (byte) 0x07, (byte) 0xdd, (byte) 0x2b, (byte) 0x8e, (byte) 0x33, (byte) 0xc0, (byte) 0x93, (byte) 0x80,
        (byte) 0xd9, (byte) 0x2b, (byte) 0xa7, (byte) 0x71, (byte) 0x57, (byte) 0x76, (byte) 0xbc, (byte) 0x8e,
        (byte) 0xb9, (byte) 0xe0, (byte) 0xd7, (byte) 0xf4, (byte) 0x23, (byte) 0x8d, (byte) 0x41, (byte) 0x1a,
        (byte) 0x97, (byte) 0x4f, (byte) 0x2c, (byte) 0x1b, (byte) 0xd5, (byte) 0x4b, (byte) 0x66, (byte) 0xe8,
        (byte) 0xfa, (byte) 0xd2, (byte) 0x50, (byte) 0x0d, (byte) 0x17, (byte) 0xab, (byte) 0x34, (byte) 0x31,
        (byte) 0x3d, (byte) 0xa4, (byte) 0x88, (byte) 0xd8, (byte) 0x8e, (byte) 0xa8, (byte) 0xa7, (byte) 0x6e,
        (byte) 0x17, (byte) 0x03, (byte) 0xb7, (byte) 0x0f, (byte) 0x68, (byte) 0x7c, (byte) 0x64, (byte) 0x7b,
        (byte) 0x92, (byte) 0xb8, (byte) 0x63, (byte) 0xe4, (byte) 0x9a, (byte) 0x67, (byte) 0x18, (byte) 0x81,
        (byte) 0x27, (byte) 0xd4, (byte) 0x0b, (byte) 0x13, (byte) 0x48, (byte) 0xd3, (byte) 0x7d, (byte) 0x4e,
        (byte) 0xf6, (byte) 0xa8, (byte) 0x8f, (byte) 0x56, (byte) 0x17, (byte) 0x2d, (byte) 0x08, (byte) 0x51,
    });

    @Test
    public void testDSAGeneratorWithParams() throws Exception {
        final DSAParameterSpec dsaSpec = new DSAParameterSpec(DSA_P, DSA_Q, DSA_G);

        ServiceTester.test("KeyPairGenerator")
            .withAlgorithm("DSA")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", p);
                    kpg.initialize(dsaSpec);
                    KeyPair pair = kpg.generateKeyPair();
                    DSAPrivateKey privKey = (DSAPrivateKey) pair.getPrivate();
                    DSAPublicKey pubKey = (DSAPublicKey) pair.getPublic();

                    DSAParams actualParams = privKey.getParams();
                    assertNotNull("DSA params should not be null", actualParams);

                    assertEquals("DSA P should be the same as supplied",
                        DSA_P, actualParams.getP());
                    assertEquals("DSA Q should be the same as supplied",
                        DSA_Q, actualParams.getQ());
                    assertEquals("DSA G should be the same as supplied",
                        DSA_G, actualParams.getG());

                    actualParams = pubKey.getParams();
                    assertNotNull("DSA params should not be null", actualParams);

                    assertEquals("DSA P should be the same as supplied",
                        DSA_P, actualParams.getP());
                    assertEquals("DSA Q should be the same as supplied",
                        DSA_Q, actualParams.getQ());
                    assertEquals("DSA G should be the same as supplied",
                        DSA_G, actualParams.getG());

                }
            });
    }
}
