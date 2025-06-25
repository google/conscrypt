/*
 * Copyright (C) 2025 The Android Open Source Project
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

@RunWith(JUnit4.class)
public class MlDsaTest {
    private final Provider conscryptProvider = TestUtils.getConscryptProvider();

    @BeforeClass
    public static void setUp() {
        TestUtils.assumeAllowsUnsignedCrypto();
    }

    public static final class RawKeySpec extends EncodedKeySpec {
        public RawKeySpec(byte[] encoded) {
            super(encoded);
        }

        @Override
        public String getFormat() {
            return "raw";
        }
    }

    // Example from https://openjdk.org/jeps/497.
    @Test
    public void example_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] msg = new byte[123];
        Signature ss = Signature.getInstance("ML-DSA", conscryptProvider);
        ss.initSign(privateKey);
        ss.update(msg);
        byte[] sig = ss.sign();

        Signature sv = Signature.getInstance("ML-DSA", conscryptProvider);
        sv.initVerify(publicKey);
        sv.update(msg);
        boolean verified = sv.verify(sig);
        assertTrue(verified);
    }

    @Test
    public void emptyMessage_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-65", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] emptyMessage = new byte[0];

        Signature signature = Signature.getInstance("ML-DSA-65", conscryptProvider);

        signature.initSign(keyPair.getPrivate());
        signature.update(emptyMessage);
        byte[] sig = signature.sign();

        signature.initVerify(keyPair.getPublic());
        signature.update(emptyMessage);
        assertTrue(signature.verify(sig));

        // Create a signature without calling update.
        signature.initSign(keyPair.getPrivate());
        byte[] sig2 = signature.sign();

        signature.initVerify(keyPair.getPublic());
        assertTrue(signature.verify(sig2));

        signature.initVerify(keyPair.getPublic());
        signature.update(emptyMessage);
        assertTrue(signature.verify(sig2));
    }

    @Test
    public void mldsa65_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-65", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        assertEquals("ML-DSA", privateKey.getAlgorithm());
        assertEquals("ML-DSA", publicKey.getAlgorithm());

        byte[] msg = new byte[123];
        Signature ss = Signature.getInstance("ML-DSA-65", conscryptProvider);
        ss.initSign(privateKey);
        ss.update(msg);
        byte[] sig = ss.sign();
        assertEquals(3309, sig.length);

        Signature sv = Signature.getInstance("ML-DSA-65", conscryptProvider);
        sv.initVerify(publicKey);
        sv.update(msg);
        boolean verified = sv.verify(sig);
        assertTrue(verified);
    }

    @Test
    public void getRawKey_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", conscryptProvider);

        EncodedKeySpec privateKeySpec =
                keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
        assertEquals("raw", privateKeySpec.getFormat());
        assertEquals(32, privateKeySpec.getEncoded().length);

        EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
        assertEquals("raw", publicKeySpec.getFormat());
        assertEquals(1952, publicKeySpec.getEncoded().length);

        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        assertEquals(privateKey, keyPair.getPrivate());
        assertEquals(publicKey, keyPair.getPublic());
    }

    @Test
    public void mldsa65_getRawKey_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-65", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-65", conscryptProvider);

        EncodedKeySpec privateKeySpec =
                keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
        assertEquals("raw", privateKeySpec.getFormat());
        assertEquals(32, privateKeySpec.getEncoded().length);

        EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
        assertEquals("raw", publicKeySpec.getFormat());
        assertEquals(1952, publicKeySpec.getEncoded().length);

        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        assertEquals(privateKey, keyPair.getPrivate());
        assertEquals(publicKey, keyPair.getPublic());
    }

    @Test
    public void x509AndPkcs8_areNotSupported() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", conscryptProvider);

        assertThrows(UnsupportedOperationException.class,
                () -> keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class));
        assertThrows(UnsupportedOperationException.class,
                () -> keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class));
    }

    @Test
    public void testVectors() throws Exception {
        List<TestVector> vectors = TestUtils.readTestVectors("crypto/mldsa.txt");

        for (TestVector vector : vectors) {
            String errMsg = vector.getString("name");
            String algorithm = vector.getString("algorithm");
            byte[] seed = vector.getBytes("seed");
            byte[] publicKey = vector.getBytes("public_key");
            byte[] message = vector.getBytes("message");
            byte[] signature = vector.getBytes("signature");

            if (!algorithm.startsWith("ML-DSA")) {
                assertTrue(errMsg + ", algorithm must start with ML-DSA", false);
            }

            KeyFactory keyFactory = KeyFactory.getInstance(algorithm, conscryptProvider);

            Signature signer = Signature.getInstance(algorithm, conscryptProvider);
            signer.initSign(keyFactory.generatePrivate(new RawKeySpec(seed)));
            signer.update(message);
            byte[] sig = signer.sign();

            assertEquals(errMsg + ", signature length mismatch", signature.length, sig.length);

            Signature verifier = Signature.getInstance(algorithm, conscryptProvider);
            verifier.initVerify(keyFactory.generatePublic(new RawKeySpec(publicKey)));
            verifier.update(message);
            assertTrue(errMsg + ", new signature verification failed", verifier.verify(sig));

            verifier.initVerify(keyFactory.generatePublic(new RawKeySpec(publicKey)));
            verifier.update(message);
            assertTrue(errMsg + ", testvector signature verification failed. how about: ["
                            + TestUtils.encodeHex(sig) + "]",
                    verifier.verify(signature));
        }
    }

    @Test
    public void serializeAndDeserialize_65_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-65", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(keyPair.getPrivate());
            oos.writeObject(keyPair.getPublic());
        }

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        PrivateKey inflatedPrivateKey = (PrivateKey) ois.readObject();
        PublicKey inflatedPublicKey = (PublicKey) ois.readObject();

        assertEquals(inflatedPrivateKey, keyPair.getPrivate());
        assertEquals(inflatedPublicKey, keyPair.getPublic());
    }

    @Test
    public void serializePrivateKey_65_isEqualToTestVector() throws Exception {
        byte[] rawPrivateKey = TestUtils.decodeHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-65", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(privateKey);
        }

        String expectedHexEncoding = "aced000573720024"
                + "6f72672e636f6e7363727970742e" // hex("org.conscrypt.")
                + "4f70656e53736c4d6c447361507269766174654b6579" // hex("OpenSslMldsaPrivateKey")
                + "3bacc385e8e106a3" // serialVersionUID
                + "0200015b0004"
                + "73656564" // hex("seed")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "20" // hex(32), size of the raw private key
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"; // rawPrivateKey
        assertEquals(expectedHexEncoding, TestUtils.encodeHex(baos.toByteArray()));
    }

    @Test
    public void serializePublicKey_65_isEqualToTestVector() throws Exception {
        byte[] rawPublicKey = new byte[1952];

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-65", conscryptProvider);
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(publicKey);
        }

        String expectedHexEncoding = "aced000573720023"
                + "6f72672e636f6e7363727970742e" // hex("org.conscrypt.")
                + "4f70656e53736c4d6c4473615075626c69634b6579" // hex("OpenSslMldsaPublicKey")
                + "064c7113d078e42d" // serialVersionUID
                + "0200015b0003"
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e002000078700000"
                + "07a0" + TestUtils.encodeHex(rawPublicKey);
        assertEquals(expectedHexEncoding, TestUtils.encodeHex(baos.toByteArray()));
    }
}
