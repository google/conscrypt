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

            assertEquals(errMsg + ", algorithm:", "ML-DSA-65", algorithm);

            KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", conscryptProvider);

            Signature signer = Signature.getInstance("ML-DSA", conscryptProvider);
            signer.initSign(keyFactory.generatePrivate(new RawKeySpec(seed)));
            signer.update(message);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance("ML-DSA", conscryptProvider);
            verifier.initVerify(keyFactory.generatePublic(new RawKeySpec(publicKey)));
            verifier.update(message);
            assertTrue(verifier.verify(sig));

            verifier.initVerify(keyFactory.generatePublic(new RawKeySpec(publicKey)));
            verifier.update(message);
            assertTrue(verifier.verify(signature));
        }
    }
}
