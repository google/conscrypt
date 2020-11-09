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

import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class KeyFactoryTestRSA extends AbstractKeyFactoryTest<RSAPublicKeySpec, RSAPrivateKeySpec> {
    public KeyFactoryTestRSA() {
        super("RSA", RSAPublicKeySpec.class, RSAPrivateKeySpec.class);
    }

    @Override
    protected void check(KeyPair keyPair) throws Exception {
        new CipherAsymmetricCryptHelper("RSA").test(keyPair);
    }

    @Test
    public void testExtraBufferSpace_Private() throws Exception {
        PrivateKey privateKey = DefaultKeys.getPrivateKey("RSA");
        byte[] encoded = privateKey.getEncoded();
        byte[] longBuffer = new byte[encoded.length + 147];
        System.arraycopy(encoded, 0, longBuffer, 0, encoded.length);
        KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(longBuffer));
    }

    @Test
    public void testExtraBufferSpace_Public() throws Exception {
        PublicKey publicKey = DefaultKeys.getPublicKey("RSA");
        byte[] encoded = publicKey.getEncoded();
        byte[] longBuffer = new byte[encoded.length + 147];
        System.arraycopy(encoded, 0, longBuffer, 0, encoded.length);
        KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(longBuffer));
    }

    @Test
    public void shouldThrowInvalidKeySpec_whenKeyIsInvalid() throws Exception {
        Provider p = Security.getProvider(StandardNames.JSSE_PROVIDER_NAME);
        final KeyFactory factory = KeyFactory.getInstance("RSA", p);

        try {
            factory.getKeySpec(new TestPrivateKey(DefaultKeys.getPrivateKey("RSA"), "Invalid"),
                    RSAPrivateKeySpec.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            factory.getKeySpec(new TestPrivateKey(DefaultKeys.getPrivateKey("RSA"), "Invalid"),
                    RSAPrivateCrtKeySpec.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            factory.getKeySpec(new TestPublicKey(DefaultKeys.getPublicKey("RSA"), "Invalid"),
                    RSAPublicKeySpec.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }
    }

    @Test
    public void shouldThrowInvalidKeySpec_whenKeySpecIsOdd() throws Exception {
        Provider p = Security.getProvider(StandardNames.JSSE_PROVIDER_NAME);
        final KeyFactory factory = KeyFactory.getInstance("RSA", p);

        try {
            factory.getKeySpec(DefaultKeys.getPublicKey("RSA"), FakeRSAPublicKeySpec.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            factory.getKeySpec(generateRsaKey(), FakeRSAPrivateCrtKeySpec.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            factory.getKeySpec(DefaultKeys.getPrivateKey("RSA"), FakeRSAPrivateCrtKeySpec.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            factory.getKeySpec(DefaultKeys.getPrivateKey("RSA"), FakePKCS8.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            factory.getKeySpec(DefaultKeys.getPublicKey("RSA"), FakeX509.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }
    }

    private static RSAPrivateCrtKey generateRsaKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);

        KeyPair keyPair = kpg.generateKeyPair();
        return (RSAPrivateCrtKey) keyPair.getPrivate();
    }

    private static class FakeRSAPublicKeySpec extends RSAPublicKeySpec {
        public FakeRSAPublicKeySpec(BigInteger modulus, BigInteger publicExponent) {
            super(modulus, publicExponent);
        }
    }

    private static class FakePKCS8 extends PKCS8EncodedKeySpec {
        public FakePKCS8(byte[] encodedKey) {
            super(encodedKey);
        }
    }

    private static class FakeRSAPrivateCrtKeySpec extends RSAPrivateCrtKeySpec {
        public FakeRSAPrivateCrtKeySpec(BigInteger modulus, BigInteger publicExponent,
                BigInteger privateExponent, BigInteger primeP, BigInteger primeQ,
                BigInteger primeExponentP, BigInteger primeExponentQ, BigInteger crtCoefficient) {
            super(modulus, publicExponent, privateExponent, primeP, primeQ, primeExponentP,
                    primeExponentQ, crtCoefficient);
        }
    }

    private static class FakeX509 extends X509EncodedKeySpec {
        public FakeX509(byte[] encodedKey) {
            super(encodedKey);
        }
    }
}
