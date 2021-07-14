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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class KeyFactoryTestRSA extends
        AbstractKeyFactoryTest<RSAPublicKeySpec, RSAPrivateKeySpec> {

    public KeyFactoryTestRSA() {
        super("RSA", RSAPublicKeySpec.class, RSAPrivateKeySpec.class);
    }

    @Override
    protected void check(KeyPair keyPair) throws Exception {
        new CipherAsymmetricCryptHelper("RSA").test(keyPair);
    }

    @Test
    public void getEncodedFailsWhenCrtValuesMissing() throws Exception {
        PrivateKey privateKey = getPrivateKey();
        try {
            // Key has only modulus and private exponent so can't be encoded as PKCS#8
            privateKey.getEncoded();
            fail();
        } catch (RuntimeException e) {
            // Expected
        }
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
    public void testInvalidKeySpec() throws Exception {
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
    public void javaSerialization() throws Exception{
        PrivateKey privatekey = getPrivateKey();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bos);
        out.writeObject(privatekey);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        ObjectInputStream in = new ObjectInputStream(bis);
        PrivateKey copy = (PrivateKey) in.readObject();

        assertEquals(privatekey, copy);
    }

    @Override
    protected List<KeyPair> getKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return Arrays.asList(
                new KeyPair(DefaultKeys.getPublicKey(algorithmName), getPrivateKey())
        );
    }

    // The private RSA key returned by DefaultKeys.getPrivateKey() is built from a PKCS#8
    // KeySpec and so will be an instance of RSAPrivateCrtKey, but we want to test RSAPrivateKey
    // in this unit test and so we extract the modulus and private exponent to build the
    // correct private key subtype.
    private PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) DefaultKeys.getPrivateKey(algorithmName);
        RSAPrivateKeySpec spec =
                new RSAPrivateKeySpec(crtKey.getModulus(), crtKey.getPrivateExponent());
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
        assertTrue(privateKey instanceof RSAPrivateKey);
        assertFalse(privateKey instanceof RSAPrivateCrtKey);
        return privateKey;
    }
}
