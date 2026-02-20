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
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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
public class SlhDsaTest {
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

    @Test
    public void signAndVerify_works() throws Exception {
        KeyPairGenerator keyGen =
                KeyPairGenerator.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] msg = new byte[123];
        Signature ss = Signature.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
        ss.initSign(privateKey);
        ss.update(msg);
        byte[] sig = ss.sign();
        assertEquals(7856, sig.length);

        Signature sv = Signature.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
        sv.initVerify(publicKey);
        sv.update(msg);
        boolean verified = sv.verify(sig);
        assertTrue(verified);
    }

    @Test
    public void emptyMessage_works() throws Exception {
        KeyPairGenerator keyGen =
                KeyPairGenerator.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] emptyMessage = new byte[0];

        Signature signature = Signature.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);

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
    public void plainSlhDsa_isNotSupported() throws Exception {
        assertThrows(NoSuchAlgorithmException.class,
                     () -> KeyPairGenerator.getInstance("SLH-DSA", conscryptProvider));
        assertThrows(NoSuchAlgorithmException.class,
                     () -> Signature.getInstance("SLH-DSA", conscryptProvider));
        assertThrows(NoSuchAlgorithmException.class,
                     () -> KeyFactory.getInstance("SLH-DSA", conscryptProvider));
    }

    @Test
    public void getRawKey_works() throws Exception {
        KeyPairGenerator keyGen =
                KeyPairGenerator.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);

        EncodedKeySpec privateKeySpec =
                keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
        assertEquals("raw", privateKeySpec.getFormat());
        byte[] rawPrivateKey = privateKeySpec.getEncoded();
        assertEquals(64, rawPrivateKey.length);

        EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
        assertEquals("raw", publicKeySpec.getFormat());
        byte[] rawPublicKey = publicKeySpec.getEncoded();
        assertEquals(32, rawPublicKey.length);

        PrivateKey privateKey2 = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));
        PublicKey publicKey2 = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));

        assertEquals(keyPair.getPublic(), publicKey2);
        assertEquals(keyPair.getPrivate(), privateKey2);
    }

    @Test
    public void fromRawPrivateKey_checksSize() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);

        PrivateKey unused = keyFactory.generatePrivate(new RawKeySpec(new byte[64]));
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new RawKeySpec(new byte[63])));
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new RawKeySpec(new byte[65])));
    }

    @Test
    public void fromRawPublicKey_checksSize() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);

        PublicKey unused = keyFactory.generatePublic(new RawKeySpec(new byte[32]));
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePublic(new RawKeySpec(new byte[31])));
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePublic(new RawKeySpec(new byte[33])));
    }

    @Test
    public void x509AndPkcs8_areNotSupported() throws Exception {
        KeyPairGenerator keyGen =
                KeyPairGenerator.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);

        assertThrows(UnsupportedOperationException.class,
                     () -> keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class));
        assertThrows(UnsupportedOperationException.class,
                     () -> keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class));
    }

    @Test
    public void testVectors() throws Exception {
        List<TestVector> vectors = TestUtils.readTestVectors("crypto/slhdsa.txt");

        for (TestVector vector : vectors) {
            String errMsg = vector.getString("name");
            String algorithm = vector.getString("algorithm");
            byte[] privateKey = vector.getBytes("private_key");
            byte[] publicKey = vector.getBytes("public_key");
            byte[] message = vector.getBytes("message");
            byte[] signature = vector.getBytes("signature");

            assertEquals(errMsg + ", algorithm:", "SLH-DSA-SHA2-128S", algorithm);

            KeyFactory keyFactory = KeyFactory.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);

            Signature signer = Signature.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
            signer.initSign(keyFactory.generatePrivate(new RawKeySpec(privateKey)));
            signer.update(message);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
            verifier.initVerify(keyFactory.generatePublic(new RawKeySpec(publicKey)));
            verifier.update(message);
            assertTrue(verifier.verify(sig));

            verifier.initVerify(keyFactory.generatePublic(new RawKeySpec(publicKey)));
            verifier.update(message);
            assertTrue(verifier.verify(signature));
        }
    }

    @Test
    public void serializeAndDeserialize_works() throws Exception {
        KeyPairGenerator keyGen =
                KeyPairGenerator.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
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
    public void serializePrivateKey_isEqualToTestVector() throws Exception {
        byte[] rawPrivateKey = new byte[64];
        KeyFactory keyFactory = KeyFactory.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(privateKey);
        }

        String classNameHex = TestUtils.encodeHex(
                privateKey.getClass().getName().getBytes(StandardCharsets.UTF_8));
        String expectedHexEncoding = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + classNameHex
                + "87e8776a4491fecb" // serialVersionUID
                + "0300015b00"
                + "03" // size of raw
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "40" // size of raw key = 64
                + "0000000000000000000000000000000000000000000000000000000000000000"
                + "0000000000000000000000000000000000000000000000000000000000000000"
                + "78";
        assertEquals(expectedHexEncoding, TestUtils.encodeHex(baos.toByteArray()));
    }

    @Test
    public void serializePublicKey_isEqualToTestVector() throws Exception {
        byte[] rawPublicKey = new byte[32];
        KeyFactory keyFactory = KeyFactory.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(publicKey);
        }

        String classNameHex = TestUtils.encodeHex(
                publicKey.getClass().getName().getBytes(StandardCharsets.UTF_8));
        String expectedHexEncoding = "aced0005737200"
                + Integer.toHexString(publicKey.getClass().getName().length()) + classNameHex
                + "4589aa00e279d127" // serialVersionUID
                + "0300015b00"
                + "03" // size of raw
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "20" // size of raw key = 32
                + "0000000000000000000000000000000000000000000000000000000000000000"
                + "78";
        assertEquals(expectedHexEncoding, TestUtils.encodeHex(baos.toByteArray()));
    }

    @Test
    public void deserializeInvalidPrivateKey_fails() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(new byte[64]));

        String classNameHex = TestUtils.encodeHex(
                privateKey.getClass().getName().getBytes(StandardCharsets.UTF_8));
        String invalidPrivateKeySerialized = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + classNameHex
                + "87e8776a4491fecb" // serialVersionUID
                + "0300015b00"
                + "03" // length of string "raw"
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "3f" // length of invalid raw key = 63
                + "0000000000000000000000000000000000000000000000000000000000000000"
                + "00000000000000000000000000000000000000000000000000000000000000"
                + "78";

        ByteArrayInputStream bais =
                new ByteArrayInputStream(TestUtils.decodeHex(invalidPrivateKeySerialized));
        ObjectInputStream ois = new ObjectInputStream(bais);

        assertThrows(IOException.class, () -> ois.readObject());
    }

    @Test
    public void deserializeInvalidPublicKey_fails() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SLH-DSA-SHA2-128S", conscryptProvider);
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(new byte[32]));

        String classNameHex = TestUtils.encodeHex(
                publicKey.getClass().getName().getBytes(StandardCharsets.UTF_8));
        String invalidPublicKeySerialized = "aced0005737200"
                + Integer.toHexString(publicKey.getClass().getName().length()) + classNameHex
                + "4589aa00e279d127" // serialVersionUID
                + "0300015b00"
                + "03" // length of string "raw"
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "1f" // length of invalid raw key = 31
                + "00000000000000000000000000000000000000000000000000000000000000"
                + "78";

        ByteArrayInputStream bais =
                new ByteArrayInputStream(TestUtils.decodeHex(invalidPublicKeySerialized));
        ObjectInputStream ois = new ObjectInputStream(bais);

        assertThrows(IOException.class, () -> ois.readObject());
    }
}
