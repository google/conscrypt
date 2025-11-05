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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
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
        // KeyPairGenerator with generic "ML-DSA" will use ML-DSA-65 by default.
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
    public void mldsa65KeyPair_signVerify_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-65", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        assertEquals("ML-DSA", privateKey.getAlgorithm());
        assertEquals("ML-DSA", publicKey.getAlgorithm());

        for (String signatureAlgorithm : new String[] {"ML-DSA-65", "ML-DSA"}) {
            byte[] msg = new byte[123];
            Signature ss = Signature.getInstance(signatureAlgorithm, conscryptProvider);
            ss.initSign(privateKey);
            ss.update(msg);
            byte[] sig = ss.sign();
            assertEquals(3309, sig.length);

            Signature sv = Signature.getInstance(signatureAlgorithm, conscryptProvider);
            sv.initVerify(publicKey);
            sv.update(msg);
            boolean verified = sv.verify(sig);
            assertTrue(verified);
        }

        // ML-DSA-87 does not support ML-DSA-65 keys.
        Signature s87 = Signature.getInstance("ML-DSA-87", conscryptProvider);
        assertThrows(InvalidKeyException.class, () -> s87.initSign(privateKey));
        assertThrows(InvalidKeyException.class, () -> s87.initVerify(publicKey));
    }

    @Test
    public void mldsa87KeyPair_signVerify_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-87", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        assertEquals("ML-DSA", privateKey.getAlgorithm());
        assertEquals("ML-DSA", publicKey.getAlgorithm());

        for (String signatureAlgorithm : new String[] {"ML-DSA-87", "ML-DSA"}) {
            byte[] msg = new byte[123];
            Signature ss = Signature.getInstance(signatureAlgorithm, conscryptProvider);
            ss.initSign(privateKey);
            ss.update(msg);
            byte[] sig = ss.sign();
            assertEquals(4627, sig.length);

            Signature sv = Signature.getInstance(signatureAlgorithm, conscryptProvider);
            sv.initVerify(publicKey);
            sv.update(msg);
            boolean verified = sv.verify(sig);
            assertTrue(verified);
        }

        // ML-DSA-65 does not support ML-DSA-87 signatures.
        Signature s65 = Signature.getInstance("ML-DSA-65", conscryptProvider);
        assertThrows(InvalidKeyException.class, () -> s65.initSign(privateKey));
        assertThrows(InvalidKeyException.class, () -> s65.initVerify(publicKey));
    }

    @Test
    public void mldsa65KeyPair_toAndFromRaw_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-65", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        for (String keyFactoryAlgorithm : new String[] {"ML-DSA-65", "ML-DSA"}) {
            KeyFactory keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm, conscryptProvider);

            EncodedKeySpec privateKeySpec =
                    keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
            assertEquals("raw", privateKeySpec.getFormat());
            assertEquals(32, privateKeySpec.getEncoded().length);

            EncodedKeySpec publicKeySpec =
                    keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
            assertEquals("raw", publicKeySpec.getFormat());
            assertEquals(1952, publicKeySpec.getEncoded().length);

            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            assertEquals(privateKey, keyPair.getPrivate());
            assertEquals(publicKey, keyPair.getPublic());
        }

        // ML-DSA-87 key factory must not support ML-DSA-65 keys.
        KeyFactory keyFactory87 = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory87.getKeySpec(keyPair.getPrivate(), RawKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory87.getKeySpec(keyPair.getPublic(), RawKeySpec.class));
    }

    @Test
    public void mldsa87KeyPair_toAndFromRaw_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-87", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        {
            KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);

            EncodedKeySpec privateKeySpec =
                    keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
            assertEquals("raw", privateKeySpec.getFormat());
            assertEquals(32, privateKeySpec.getEncoded().length);

            EncodedKeySpec publicKeySpec =
                    keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
            assertEquals("raw", publicKeySpec.getFormat());
            assertEquals(2592, publicKeySpec.getEncoded().length);

            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            assertEquals(privateKey, keyPair.getPrivate());
            assertEquals(publicKey, keyPair.getPublic());
        }

        {
            // The generic ML-DSA algorithm supports exporting ML-DSA-87 keys.
            KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", conscryptProvider);

            EncodedKeySpec privateKeySpec =
                    keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
            assertEquals("raw", privateKeySpec.getFormat());
            assertEquals(32, privateKeySpec.getEncoded().length);

            EncodedKeySpec publicKeySpec =
                    keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
            assertEquals("raw", publicKeySpec.getFormat());
            assertEquals(2592, publicKeySpec.getEncoded().length);

            // Importing the private key works, but the generated key will be a ML-DSA-65 key.
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            assertNotEquals(privateKey, keyPair.getPrivate());

            // This fails because the key factory expects a ML-DSA-65 key, which has a different
            // length.
            assertThrows(
                    InvalidKeySpecException.class, () -> keyFactory.generatePublic(publicKeySpec));
        }

        // ML-DSA-65 key factory must not support ML-DSA-87 keys.
        KeyFactory keyFactory65 = KeyFactory.getInstance("ML-DSA-65", conscryptProvider);
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory65.getKeySpec(keyPair.getPrivate(), RawKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory65.getKeySpec(keyPair.getPublic(), RawKeySpec.class));
    }

    @Test
    public void generateFromInvalidRawKey_throws() throws Exception {
        for (String keyFactoryAlgorithm : new String[] {"ML-DSA-65", "ML-DSA-87", "ML-DSA"}) {
            KeyFactory keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm, conscryptProvider);

            assertThrows(InvalidKeySpecException.class, () -> keyFactory.generatePrivate(null));
            assertThrows(InvalidKeySpecException.class, () -> keyFactory.generatePublic(null));

            byte[] invalidRawKey = new byte[42];
            assertThrows(InvalidKeySpecException.class,
                    () -> keyFactory.generatePrivate(new RawKeySpec(invalidRawKey)));
            assertThrows(InvalidKeySpecException.class,
                    () -> keyFactory.generatePublic(new RawKeySpec(invalidRawKey)));
        }
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
    public void serializeAndDeserialize_87_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-87", conscryptProvider);
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

        String hexClassName = TestUtils.encodeHex(
                privateKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String expectedHexEncoding = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + hexClassName
                + "3bacc385e8e106a3" // serialVersionUID
                + "0200015b0004"
                + "73656564" // hex("seed")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "20" // hex(32), size of the raw private key
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"; // rawPrivateKey
        assertEquals(expectedHexEncoding, TestUtils.encodeHex(baos.toByteArray()));
    }

    @Test
    public void serializePrivateKey_87_isEqualToTestVector() throws Exception {
        byte[] rawPrivateKey = TestUtils.decodeHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(privateKey);
        }

        String hexClassName = TestUtils.encodeHex(
                privateKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String expectedHexEncoding = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + hexClassName
                + "3bacc385e8e106a3" // serialVersionUID
                + "0200015b0004"
                + "73656564" // hex("seed")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "21" // hex(33), size of "seed", which is 32 + 1
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" // rawPrivateKey
                + "57"; // hex(87)
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

        String hexClassName = TestUtils.encodeHex(
                publicKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String expectedHexEncoding = "aced0005737200"
                + Integer.toHexString(publicKey.getClass().getName().length()) + hexClassName
                + "064c7113d078e42d" // serialVersionUID
                + "0200015b0003"
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e002000078700000"
                + "07a0" + TestUtils.encodeHex(rawPublicKey);
        assertEquals(expectedHexEncoding, TestUtils.encodeHex(baos.toByteArray()));
    }

    @Test
    public void serializePublicKey_87_isEqualToTestVector() throws Exception {
        byte[] rawPublicKey = new byte[2592];

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(publicKey);
        }

        String hexClassName = TestUtils.encodeHex(
                publicKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String expectedHexEncoding = "aced0005737200"
                + Integer.toHexString(publicKey.getClass().getName().length()) + hexClassName
                + "064c7113d078e42d" // serialVersionUID
                + "0200015b0003"
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e002000078700000"
                + "0a20" // hex(2592), size of the raw public key
                + TestUtils.encodeHex(rawPublicKey);
        assertEquals(expectedHexEncoding, TestUtils.encodeHex(baos.toByteArray()));
    }

    @Test
    public void deserializePrivateKeyWithWrongSuffix_fails() throws Exception {
        byte[] rawPrivateKey = TestUtils.decodeHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));
        String hexClassName = TestUtils.encodeHex(
                privateKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String invalidPrivateKey = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + hexClassName
                + "3bacc385e8e106a3" // serialVersionUID
                + "0200015b0004"
                + "73656564" // hex("seed")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "21" // hex(33), size of encoded seed, which is 1 + 32
                // encoded seed.
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "41"; // wrong suffix.

        ByteArrayInputStream bais =
                new ByteArrayInputStream(TestUtils.decodeHex(invalidPrivateKey));
        ObjectInputStream ois = new ObjectInputStream(bais);

        try {
            ois.readObject();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException | EOFException e) {
            // Expected
        }
    }

    @Test
    public void deserializePrivateKeyWithWrongSize_fails() throws Exception {
        byte[] rawPrivateKey = TestUtils.decodeHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));
        String hexClassName = TestUtils.encodeHex(
                privateKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String invalidPrivateKey = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + hexClassName
                + "3bacc385e8e106a3" // serialVersionUID
                + "0200015b0004"
                + "73656564" // hex("seed")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "22" // hex(34), illegal size of encoded seed, only 32 or 33 are allowed.
                // encoded seed.
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "5757";

        ByteArrayInputStream bais =
                new ByteArrayInputStream(TestUtils.decodeHex(invalidPrivateKey));
        ObjectInputStream ois = new ObjectInputStream(bais);

        try {
            ois.readObject();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException | EOFException e) {
            // Expected
        }
    }

    @Test
    public void deserializeInvalidPublicKey_fails() throws Exception {
        byte[] rawPublicKey = new byte[2592];
        byte[] invalidRawPublicKey = new byte[2593]; // one byte too long.

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));
        String hexClassName = TestUtils.encodeHex(
                publicKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String hexPublicKey = "aced0005737200"
                + Integer.toHexString(publicKey.getClass().getName().length()) + hexClassName
                + "064c7113d078e42d" // serialVersionUID
                + "0200015b0003"
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e002000078700000"
                + "0a21" // hex(2593), size of the invalid raw public key
                + TestUtils.encodeHex(invalidRawPublicKey);

        ByteArrayInputStream bais = new ByteArrayInputStream(TestUtils.decodeHex(hexPublicKey));
        ObjectInputStream ois = new ObjectInputStream(bais);

        try {
            ois.readObject();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException | EOFException e) {
            // Expected
        }
    }
}
