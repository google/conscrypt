/*
 * Copyright 2023 The Android Open Source Project
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
package org.conscrypt.javax.crypto;

import static org.conscrypt.TestUtils.decodeBase64;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.conscrypt.OpenSSLX25519PrivateKey;
import org.conscrypt.OpenSSLX25519PublicKey;
import org.conscrypt.TestUtils;
import org.conscrypt.XdhKeySpec;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class XdhKeyFactoryTest {
    private final byte[] publicKeyX509Bytes =
            decodeBase64("MCowBQYDK2VuAyEAeNH3ZKS7SCZT495bvIvoyYB9PNIFefUSTfi6eNhFYXA=");
    private final byte[] privateKeyPkcs8Bytes =
            decodeBase64("MC4CAQAwBQYDK2VuBCIEIADBSHEZer+X0ZdqReHuMDx61nQwWwNHOnx9HHRNJBJK");
    private final KeyFactory factory =
            KeyFactory.getInstance("XDH", TestUtils.getConscryptProvider());
    private final PublicKey publicKey =
            factory.generatePublic(new X509EncodedKeySpec(publicKeyX509Bytes));
    private final PrivateKey privateKey =
            factory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyPkcs8Bytes));

    private final byte[] publicKeyRawBytes = ((OpenSSLX25519PublicKey) publicKey).getU();
    private final byte[] privateKeyRawBytes = ((OpenSSLX25519PrivateKey) privateKey).getU();

    public XdhKeyFactoryTest() throws NoSuchAlgorithmException, InvalidKeySpecException {
    }

    @Test
    public void constructor() {
        // Class init already implicitly tests generating public and private keys from their
        // encoded format, but we still need to check the opposite translation.
        assertEquals("X.509", publicKey.getFormat());
        assertArrayEquals(publicKeyX509Bytes, publicKey.getEncoded());

        assertEquals("PKCS#8", privateKey.getFormat());
        assertArrayEquals(privateKeyPkcs8Bytes, privateKey.getEncoded());

    }
    @Test
    public void generatePublic() throws Exception {
        PublicKey key = factory.generatePublic(new XdhKeySpec(publicKeyRawBytes));
        assertTrue(key instanceof OpenSSLX25519PublicKey);
        assertEquals("X.509", key.getFormat());
        assertArrayEquals(publicKeyX509Bytes, key.getEncoded());
        assertEquals(publicKey, key);
        assertNotSame(publicKey, key);

        key = factory.generatePublic(new TestKeySpec(publicKeyRawBytes));
        assertTrue(key instanceof OpenSSLX25519PublicKey);
        assertEquals("X.509", key.getFormat());
        assertArrayEquals(publicKeyX509Bytes, key.getEncoded());
        assertEquals(publicKey, key);
        assertNotSame(publicKey, key);
    }

    @Test
    public void generatePrivate() throws Exception{
        PrivateKey key = factory.generatePrivate(new XdhKeySpec(privateKeyRawBytes));
        assertTrue(key instanceof OpenSSLX25519PrivateKey);
        assertEquals("PKCS#8", key.getFormat());
        assertArrayEquals(privateKeyPkcs8Bytes, key.getEncoded());
        assertEquals(privateKey, key);
        assertNotSame(privateKey, key);

        key = factory.generatePrivate(new TestKeySpec(privateKeyRawBytes));
        assertTrue(key instanceof OpenSSLX25519PrivateKey);
        assertEquals("PKCS#8", key.getFormat());
        assertArrayEquals(privateKeyPkcs8Bytes, key.getEncoded());
        assertEquals(privateKey, key);
        assertNotSame(privateKey, key);
    }

    @Test
    public void publicKeySpec_Success() throws Exception {
        X509EncodedKeySpec x509Spec = factory.getKeySpec(publicKey, X509EncodedKeySpec.class);
        assertArrayEquals(publicKeyX509Bytes, x509Spec.getEncoded());

        XdhKeySpec xdhSpec = factory.getKeySpec(publicKey, XdhKeySpec.class);
        assertArrayEquals(publicKeyRawBytes, xdhSpec.getEncoded());

        TestKeySpec testSpec = factory.getKeySpec(publicKey, TestKeySpec.class);
        assertArrayEquals(publicKeyRawBytes, testSpec.getEncoded());

        x509Spec = factory.getKeySpec(new TestPublicKey(), X509EncodedKeySpec.class);
        assertArrayEquals(publicKeyX509Bytes, x509Spec.getEncoded());
    }

    @Test
    public void privateKeySpec_Success() throws Exception {
        PKCS8EncodedKeySpec pkcs8Spec = factory.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
        assertArrayEquals(privateKeyPkcs8Bytes, pkcs8Spec.getEncoded());

        XdhKeySpec xdhSpec = factory.getKeySpec(privateKey, XdhKeySpec.class);
        assertArrayEquals(privateKeyRawBytes, xdhSpec.getEncoded());

        TestKeySpec testSpec = factory.getKeySpec(privateKey, TestKeySpec.class);
        assertArrayEquals(privateKeyRawBytes, testSpec.getEncoded());

        pkcs8Spec = factory.getKeySpec(new TestPrivateKey(), PKCS8EncodedKeySpec.class);
        assertArrayEquals(privateKeyPkcs8Bytes, pkcs8Spec.getEncoded());
    }

    @Test
    public void keySpec_Fail() throws Exception {
        assertThrows(InvalidKeySpecException.class,
                () -> factory.getKeySpec(publicKey, PKCS8EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                () -> factory.getKeySpec(privateKey, X509EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class, () -> factory.getKeySpec(
                new TestPublicKeyWrongEncoding(), X509EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class, () -> factory.getKeySpec(
                new TestPrivateKeyWrongEncoding(), PKCS8EncodedKeySpec.class));

        assertThrows(InvalidKeySpecException.class,
                () -> factory.getKeySpec(publicKey, TestKeySpecWrongEncoding.class));
        assertThrows(InvalidKeySpecException.class,
                () -> factory.getKeySpec(privateKey, TestKeySpecWrongEncoding.class));


        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = kpg.generateKeyPair();

        assertThrows(InvalidKeySpecException.class,
                () -> factory.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                () -> factory.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class));
    }

    @Test
    @Ignore("Inconsistent results across platforms")
    public void xecPublicKeySpec() throws Exception {
        TestUtils.assumeXecClassesAvailable();
        @SuppressWarnings("unchecked")
        Class<? extends KeySpec> javaClass = (Class<? extends KeySpec>)
                TestUtils.findClass("java.security.spec.XECPublicKeySpec");
        KeySpec spec = factory.getKeySpec(publicKey, javaClass);
        assertNotNull(spec);

        try {
            // If SunEC is available, translate back and compare.
            KeyFactory sunKf = KeyFactory.getInstance("XDH", "SunEC");
            PublicKey sunKey = sunKf.generatePublic(spec);
            assertNotEquals(OpenSSLX25519PublicKey.class, sunKey.getClass());

            Key key = factory.translateKey(sunKey);
            assertTrue(key instanceof OpenSSLX25519PublicKey);
            assertEquals(publicKey, key);
        } catch (NoSuchProviderException e) {
            // Ignored
        }
    }

    @Test
    @Ignore("Inconsistent results across platforms")
    public void xecPrivateKeySpec() throws Exception {
        TestUtils.assumeXecClassesAvailable();
        @SuppressWarnings("unchecked")
        Class<? extends KeySpec> javaClass = (Class<? extends KeySpec>)
                TestUtils.findClass("java.security.spec.XECPrivateKeySpec");
        KeySpec spec = factory.getKeySpec(privateKey, javaClass);
        assertNotNull(spec);
        try {
            // If SunEC is available, translate back and compare.
            KeyFactory sunKf = KeyFactory.getInstance("XDH", "SunEC");
            PrivateKey sunKey = sunKf.generatePrivate(spec);
            assertNotEquals(OpenSSLX25519PrivateKey.class, sunKey.getClass());

            Key key = factory.translateKey(sunKey);
            assertTrue(key instanceof OpenSSLX25519PrivateKey);
            assertEquals(privateKey, key);
        } catch (NoSuchProviderException e) {
            // Ignored
        }
    }

    @Test
    public void translate() throws Exception {
        TestPublicKey testPublicKey = new TestPublicKey();
        Key translatedPublicKey = factory.translateKey(testPublicKey);
        assertTrue(translatedPublicKey instanceof OpenSSLX25519PublicKey);
        assertEquals(publicKey, translatedPublicKey);
        assertNotSame(publicKey, translatedPublicKey);

        TestPrivateKey testPrivateKey = new TestPrivateKey();
        Key translatedPrivateKey = factory.translateKey(testPrivateKey);
        assertTrue(translatedPrivateKey instanceof OpenSSLX25519PrivateKey);
        assertEquals(privateKey, translatedPrivateKey);
        assertNotSame(privateKey, translatedPrivateKey);

        translatedPublicKey = factory.translateKey(publicKey);
        assertSame(publicKey, translatedPublicKey);

        translatedPrivateKey = factory.translateKey(privateKey);
        assertSame(privateKey, translatedPrivateKey);
    }

    @Test
    public void translate_Fail() throws Exception {
        assertThrows(InvalidKeyException.class,
                () -> factory.translateKey(new TestPublicKeyWrongEncoding()));
        assertThrows(InvalidKeyException.class,
                () -> factory.translateKey(new TestPrivateKeyWrongEncoding()));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = kpg.generateKeyPair();
        assertThrows(InvalidKeyException.class,
                () -> factory.translateKey(kp.getPublic()));
        assertThrows(InvalidKeyException.class,
                () -> factory.translateKey(kp.getPrivate()));
    }

    /**
     * "foreign" KeySpec class which implements raw encoding.
     */
    public static final class TestKeySpec extends EncodedKeySpec {
        public TestKeySpec(byte[] encodedKey) {
            super(encodedKey);
        }

        @Override
        public String getFormat() {
            return "raw";
        }
    }
    /**
     * "foreign" KeySpec class which *doesn't* implement raw encoding.
     */
    public static final class TestKeySpecWrongEncoding extends EncodedKeySpec {
        public TestKeySpecWrongEncoding(byte[] encodedKey) {
            super(encodedKey);
        }

        @Override
        public String getFormat() {
            return "wrong";
        }
    }

    /**
     * "foreign" public key class which implements XDH and X.509
     */
    private final class TestPublicKey implements PublicKey {
        @Override
        public String getAlgorithm() {
            return "XDH";
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            return publicKeyX509Bytes;
        }
    }
    /**
     * "foreign" public key class which implements XDH and but not X.509
     */
    private final class TestPublicKeyWrongEncoding implements PublicKey {
        @Override
        public String getAlgorithm() {
            return "XDH";
        }

        @Override
        public String getFormat() {
            return "Some Format";
        }

        @Override
        public byte[] getEncoded() {
            return publicKeyX509Bytes;
        }
    }
    /**
     * "foreign" private key class which implements XDH and PKCS#8
     */
    private final class TestPrivateKey implements PrivateKey {
        @Override
        public String getAlgorithm() {
            return "XDH";
        }

        @Override
        public String getFormat() {
            return "PKCS#8";
        }

        @Override
        public byte[] getEncoded() {
            return privateKeyPkcs8Bytes;
        }
    }
    /**
     * "foreign" private key class which implements XDH but not PKCS#8
     */
    private final class TestPrivateKeyWrongEncoding implements PrivateKey {
        @Override
        public String getAlgorithm() {
            return "XDH";
        }

        @Override
        public String getFormat() {
            return "Some Format";
        }

        @Override
        public byte[] getEncoded() {
            return privateKeyPkcs8Bytes;
        }
    }
}
