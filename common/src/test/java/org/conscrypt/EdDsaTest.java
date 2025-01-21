/*
 * Copyright 2025 The Android Open Source Project
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

import static org.conscrypt.TestUtils.decodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.nio.ByteBuffer;
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
import java.util.Arrays;
import java.util.List;

@RunWith(JUnit4.class)
public class EdDsaTest {
    private final Provider conscryptProvider = TestUtils.getConscryptProvider();

    @BeforeClass
    public static void setUp() {
        TestUtils.assumeAllowsUnsignedCrypto();
    }

    /** Implements a KeySpec that contains the raw bytes of a key. */
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
    public void generateKeyPairSignAndVerify_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] message = decodeHex("00112233");

        Signature signature = Signature.getInstance("Ed25519", conscryptProvider);
        signature.initSign(keyPair.getPrivate());
        signature.update(message);
        byte[] sig = signature.sign();

        assertEquals(64, sig.length);

        signature.initVerify(keyPair.getPublic());
        signature.update(message);
        assertTrue(signature.verify(sig));
    }

    @Test
    public void signAndVerifyWithOffset_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] message = decodeHex("00112233");
        Signature signature = Signature.getInstance("Ed25519", conscryptProvider);
        signature.initSign(keyPair.getPrivate());
        signature.update(message);
        byte[] sig = signature.sign();

        int offset = 5;

        signature.initSign(keyPair.getPrivate());
        byte[] messageWithOffset = new byte[message.length + 10];
        System.arraycopy(message, 0, messageWithOffset, 5, message.length);
        signature.update(messageWithOffset, 5, message.length);
        byte[] outputBuffer = new byte[100];
        int written = signature.sign(outputBuffer, offset, sig.length);

        assertEquals(written, sig.length);
        assertArrayEquals(sig, Arrays.copyOfRange(outputBuffer, offset, offset + sig.length));

        signature.initVerify(keyPair.getPublic());
        signature.update(message);

        assertTrue(signature.verify(outputBuffer, offset, sig.length));
    }

    @Test
    public void updateWithByteBuffer_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] message = decodeHex("00112233");
        Signature signature = Signature.getInstance("Ed25519", conscryptProvider);
        signature.initSign(keyPair.getPrivate());
        signature.update(message);
        byte[] sig = signature.sign();

        signature.initSign(keyPair.getPrivate());
        signature.update(ByteBuffer.wrap(message));
        assertArrayEquals(sig, signature.sign());

        signature.initVerify(keyPair.getPublic());
        signature.update(ByteBuffer.wrap(message));
        assertTrue(signature.verify(sig));
    }

    @Test
    public void generateKeyPairWithWrongKeySize_throws() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", conscryptProvider);
        assertThrows(IllegalArgumentException.class, () -> keyGen.initialize(256));
    }

    @Test
    public void generateKeyPairWithDefaultProvider_useWithConscrypt_works() throws Exception {
        // generate key pair with default provider
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] message = new byte[123];
        Signature signature = Signature.getInstance("Ed25519", conscryptProvider);
        signature.initSign(keyPair.getPrivate());
        signature.update(message);
        byte[] sig = signature.sign();
        signature.initVerify(keyPair.getPublic());
        signature.update(message);
        assertTrue(signature.verify(sig));
    }

    @Test
    public void keygenWithConscrypt_useWithDefaultProvider_fails() throws Exception {
        // generate key pair with conscrypt
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        // This fails because the default provider expects the key to implement
        // the EdECPrivateKey and EdECPublicKey interfaces, which we don't yet implement.
        assertThrows(InvalidKeyException.class,
                () -> Signature.getInstance("Ed25519").initSign(keyPair.getPrivate()));
        assertThrows(InvalidKeyException.class,
                () -> Signature.getInstance("Ed25519").initVerify(keyPair.getPublic()));
    }

    @Test
    public void pkcs8AndX509EncodedKeys_work() throws Exception {
        // Test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7
        // Encoding from https://datatracker.ietf.org/doc/html/rfc8410
        byte[] pkcs8EncodedPrivateKey = decodeHex(
                // PKCS#8 header
                "302e020100300506032b657004220420"
                // raw private key
                + "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] x509EncodedPublicKey = decodeHex(
                // X.509 header
                "302a300506032b6570032100"
                // raw public key
                + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] message = decodeHex("");
        byte[] expectedSig =
                decodeHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", conscryptProvider);
        PrivateKey privateKey =
                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedPrivateKey));
        PublicKey publicKey =
                keyFactory.generatePublic(new X509EncodedKeySpec(x509EncodedPublicKey));

        Signature signature = Signature.getInstance("Ed25519", conscryptProvider);

        signature.initSign(privateKey);
        signature.update(message);
        byte[] sig = signature.sign();
        assertArrayEquals(expectedSig, sig);

        signature.initVerify(publicKey);
        signature.update(message);
        assertTrue(signature.verify(sig));
    }

    @Test
    public void convertPrivateKeyToAndFromKeySpec_works() throws Exception {
        byte[] rawPrivateKey =
                decodeHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));
        assertEquals("EdDSA", privateKey.getAlgorithm());

        // RawKeySpec returns the raw private key.
        RawKeySpec rawPrivateKeySpec = keyFactory.getKeySpec(privateKey, RawKeySpec.class);
        assertEquals("raw", rawPrivateKeySpec.getFormat());
        assertArrayEquals(rawPrivateKey, rawPrivateKeySpec.getEncoded());

        // getEncoded() returns a PCKS#8 encoded private key.
        byte[] expectedPkcs8Prefix = decodeHex("302e020100300506032b657004220420");
        byte[] encodedPrivateKey = privateKey.getEncoded();
        assertEquals(48, encodedPrivateKey.length);
        assertArrayEquals(expectedPkcs8Prefix,
                Arrays.copyOfRange(encodedPrivateKey, 0, expectedPkcs8Prefix.length));
        assertArrayEquals(rawPrivateKey,
                Arrays.copyOfRange(
                        encodedPrivateKey, expectedPkcs8Prefix.length, encodedPrivateKey.length));

        // PKCS8EncodedKeySpec returns the same encoding as getEncoded().
        PKCS8EncodedKeySpec privateKeySpec =
                keyFactory.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
        assertEquals("PKCS#8", privateKeySpec.getFormat());
        assertArrayEquals(encodedPrivateKey, privateKeySpec.getEncoded());

        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.getKeySpec(privateKey, X509EncodedKeySpec.class));
    }

    @Test
    public void convertPublicKeyToFromRawKeySpec_works() throws Exception {
        byte[] rawPublicKey =
                decodeHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", conscryptProvider);
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));
        assertEquals("EdDSA", publicKey.getAlgorithm());

        // RawKeySpec returns the raw public key.
        RawKeySpec rawPublicKeySpec = keyFactory.getKeySpec(publicKey, RawKeySpec.class);
        assertEquals("raw", rawPublicKeySpec.getFormat());
        assertArrayEquals(rawPublicKey, rawPublicKeySpec.getEncoded());

        // getEncoded() returns an X.509 encoded public key.
        byte[] expectedX509Prefix = decodeHex("302a300506032b6570032100");
        byte[] encodedPublicKey = publicKey.getEncoded();
        assertEquals(44, encodedPublicKey.length);
        assertArrayEquals(expectedX509Prefix,
                Arrays.copyOfRange(encodedPublicKey, 0, expectedX509Prefix.length));
        assertArrayEquals(rawPublicKey,
                Arrays.copyOfRange(
                        encodedPublicKey, expectedX509Prefix.length, encodedPublicKey.length));

        // X509EncodedKeySpec returns the same encoding as getEncoded().
        X509EncodedKeySpec publicKeySpec =
                keyFactory.getKeySpec(publicKey, X509EncodedKeySpec.class);
        assertEquals("X.509", publicKeySpec.getFormat());
        assertArrayEquals(encodedPublicKey, publicKeySpec.getEncoded());

        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.getKeySpec(publicKey, PKCS8EncodedKeySpec.class));
    }

    @Test
    public void testVectors() throws Exception {
        List<TestVector> vectors = TestUtils.readTestVectors("crypto/eddsa.txt");

        for (TestVector vector : vectors) {
            String errMsg = vector.getString("name");
            String algorithm = vector.getString("algorithm");
            byte[] secretKey = vector.getBytes("secret_key");
            byte[] publicKey = vector.getBytes("public_key");
            byte[] message = vector.getBytes("message");
            byte[] signature = vector.getBytes("signature");

            assertEquals(errMsg + ", algorithm:", "Ed25519", algorithm);

            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", conscryptProvider);

            Signature signer = Signature.getInstance("Ed25519", conscryptProvider);
            signer.initSign(keyFactory.generatePrivate(new RawKeySpec(secretKey)));
            signer.update(message);
            byte[] sig = signer.sign();
            assertArrayEquals(errMsg + ", signature:", signature, sig);

            Signature verifier = Signature.getInstance("Ed25519", conscryptProvider);
            verifier.initVerify(keyFactory.generatePublic(new RawKeySpec(publicKey)));
            verifier.update(message);
            assertTrue(verifier.verify(sig));
        }
    }
}
