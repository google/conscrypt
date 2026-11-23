/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.conscrypt.java.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@RunWith(JUnit4.class)
public class KeyPairGeneratorTestRSA extends AbstractKeyPairGeneratorTest {
    public KeyPairGeneratorTestRSA() {
        super("RSA", new CipherAsymmetricCryptHelper("RSA"));
    }

    private static Provider getConscryptProvider() {
        Provider p = Security.getProvider(StandardNames.JSSE_PROVIDER_NAME);
        if (p == null) {
            p = Security.getProvider("Conscrypt");
        }
        return (p != null) ? p : TestUtils.getConscryptProvider();
    }

    /**
     * ANDROID COMPATIBILITY GATE (b/473446952, b/493922460): BoringSSL enforces the minimum RSA
     * modulus size ({@code OPENSSL_RSA_MIN_MODULUS_BITS = 512}) at compile time in C++
     * ({@code RSA_generate_key_ex}), and legacy Android apps still rely on 512-bit RSA keys. Do NOT
     * raise this minimum key-size bound or relax/remove this test without an Android compatibility
     * review and an associated AppCompat / aconfig flag.
     */
    @Test
    public void rsa512BitKeyGenerationSupported() throws Exception {
        Provider p = getConscryptProvider();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", p);
        generator.initialize(512);
        KeyPair keyPair = generator.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        assertEquals(512, publicKey.getModulus().bitLength());
        assertEquals(512, privateKey.getModulus().bitLength());

        byte[] message = "conscrypt-rsa-compat-gate".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withRSA", p);
        signer.initSign(privateKey);
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA", p);
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertTrue(verifier.verify(signature));
    }
}
