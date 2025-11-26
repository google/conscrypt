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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

@RunWith(JUnit4.class)
public class X25519Test {
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
    public void generateKeyPairKeyAgreement_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("X25519", conscryptProvider);
        KeyPair keyPair1 = keyGen.generateKeyPair();
        KeyPair keyPair2 = keyGen.generateKeyPair();

        KeyAgreement ka1 = KeyAgreement.getInstance("X25519", conscryptProvider);
        ka1.init(keyPair1.getPrivate());
        ka1.doPhase(keyPair2.getPublic(), true);

        KeyAgreement ka2 = KeyAgreement.getInstance("X25519", conscryptProvider);
        ka2.init(keyPair2.getPrivate());
        ka2.doPhase(keyPair1.getPublic(), true);

        assertArrayEquals(ka1.generateSecret(), ka2.generateSecret());
    }

    @Test
    public void generateKeyPairWithWrongKeySize_throws() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("X25519", conscryptProvider);
        assertThrows(IllegalArgumentException.class, () -> keyGen.initialize(256));
    }

    @Test
    public void keyAgreement_rfc7748_success() throws Exception {
        // Test vector from RFC 7748, Section 5.2
        byte[] rawPrivateKey =
                decodeHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        byte[] rawPublicKey =
                decodeHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        byte[] expectedSecret =
                decodeHex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        KeyFactory keyFactory = KeyFactory.getInstance("X25519", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));

        KeyAgreement ka = KeyAgreement.getInstance("X25519", conscryptProvider);
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        assertArrayEquals(expectedSecret, ka.generateSecret());
    }

    @Test
    public void convertPrivateKeyToAndFromKeySpec_works() throws Exception {
        byte[] rawPrivateKey =
                decodeHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        KeyFactory keyFactory = KeyFactory.getInstance("X25519", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));
        assertEquals("XDH", privateKey.getAlgorithm());

        // RawKeySpec returns the raw private key.
        RawKeySpec rawPrivateKeySpec = keyFactory.getKeySpec(privateKey, RawKeySpec.class);
        assertEquals("raw", rawPrivateKeySpec.getFormat());
        assertArrayEquals(rawPrivateKey, rawPrivateKeySpec.getEncoded());

        // PKCS8EncodedKeySpec returns the same encoding as getEncoded().
        PKCS8EncodedKeySpec privateKeySpec =
                keyFactory.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
        assertEquals("PKCS#8", privateKeySpec.getFormat());
        assertArrayEquals(privateKey.getEncoded(), privateKeySpec.getEncoded());

        PrivateKey privateKey2 =
                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey.getEncoded()));
        assertArrayEquals(privateKey.getEncoded(), privateKey2.getEncoded());

        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.getKeySpec(privateKey, X509EncodedKeySpec.class));
    }

    @Test
    public void generateKey_invalidEncoding_throwsInvalidKeySpecException() throws Exception {
        byte[] invalidEncoding = decodeHex("012345");
        KeyFactory keyFactory = KeyFactory.getInstance("X25519", conscryptProvider);
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(invalidEncoding)));
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.generatePublic(new X509EncodedKeySpec(invalidEncoding)));
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.generatePrivate(new RawKeySpec(invalidEncoding)));
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.generatePublic(new RawKeySpec(invalidEncoding)));
    }

    @Test
    public void convertPublicKeyToFromKeySpec_works() throws Exception {
        byte[] rawPublicKey =
                decodeHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        KeyFactory keyFactory = KeyFactory.getInstance("X25519", conscryptProvider);
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));
        assertEquals("XDH", publicKey.getAlgorithm());

        // RawKeySpec returns the raw public key.
        RawKeySpec rawPublicKeySpec = keyFactory.getKeySpec(publicKey, RawKeySpec.class);
        assertEquals("raw", rawPublicKeySpec.getFormat());
        assertArrayEquals(rawPublicKey, rawPublicKeySpec.getEncoded());

        // X509EncodedKeySpec returns the same encoding as getEncoded().
        X509EncodedKeySpec publicKeySpec =
                keyFactory.getKeySpec(publicKey, X509EncodedKeySpec.class);
        assertEquals("X.509", publicKeySpec.getFormat());
        assertArrayEquals(publicKey.getEncoded(), publicKeySpec.getEncoded());

        PublicKey publicKey2 =
                keyFactory.generatePublic(new X509EncodedKeySpec(publicKey.getEncoded()));
        assertArrayEquals(publicKey.getEncoded(), publicKey2.getEncoded());

        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.getKeySpec(publicKey, PKCS8EncodedKeySpec.class));
    }

    @Test
    public void serializeAndDeserialize_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("X25519", conscryptProvider);
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
        byte[] rawPrivateKey =
                decodeHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        KeyFactory keyFactory = KeyFactory.getInstance("X25519", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(privateKey);
        }

        String classNameHex = TestUtils.encodeHex(
                privateKey.getClass().getName().getBytes(StandardCharsets.UTF_8));
        String expectedHexEncoding = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + classNameHex
                + "d479f95a133abadc" // serialVersionUID
                + "0300015b000b"
                + "75436f6f7264696e617465" // hex("uCoordinate")
                + "7400025b427870757200025b42acf317f8060854e0020000787000000020"
                + "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
                + "78";
        assertEquals(expectedHexEncoding, TestUtils.encodeHex(baos.toByteArray()));
    }

    @Test
    public void serializePublicKey_isEqualToTestVector() throws Exception {
        byte[] rawPublicKey =
                decodeHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        KeyFactory keyFactory = KeyFactory.getInstance("X25519", conscryptProvider);
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(publicKey);
        }

        String classNameHex = TestUtils.encodeHex(
                publicKey.getClass().getName().getBytes(StandardCharsets.UTF_8));
        String expectedHexEncoding = "aced0005737200"
                + Integer.toHexString(publicKey.getClass().getName().length()) + classNameHex
                + "064c7113d078e42d" // serialVersionUID
                + "0300015b000b"
                + "75436f6f7264696e617465" // hex("uCoordinate")
                + "7400025b427870757200025b42acf317f8060854e0020000787000000020"
                + "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
                + "78";
        assertEquals(expectedHexEncoding, TestUtils.encodeHex(baos.toByteArray()));
    }

    @Test
    public void deserializeInvalidPrivateKey_fails() throws Exception {
        byte[] rawPrivateKey =
                decodeHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        KeyFactory keyFactory = KeyFactory.getInstance("X25519", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(privateKey);
        }

        String classNameHex = TestUtils.encodeHex(
                privateKey.getClass().getName().getBytes(StandardCharsets.UTF_8));
        String invalidPrivateKeySerialized = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + classNameHex
                + "d479f95a133abadc" // serialVersionUID
                + "0300015b000b"
                + "75436f6f7264696e617465" // hex("uCoordinate")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "1f" // size of private key (is 31, which is invalid)
                + "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a"
                + "78";

        ByteArrayInputStream bais =
                new ByteArrayInputStream(TestUtils.decodeHex(invalidPrivateKeySerialized));
        ObjectInputStream ois = new ObjectInputStream(bais);

        assertThrows(IOException.class, () -> ois.readObject());
    }

    @Test
    public void deserializeInvalidPublicKey_fails() throws Exception {
        byte[] rawPublicKey =
                decodeHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        KeyFactory keyFactory = KeyFactory.getInstance("X25519", conscryptProvider);
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(publicKey);
        }

        String classNameHex = TestUtils.encodeHex(
                publicKey.getClass().getName().getBytes(StandardCharsets.UTF_8));
        String invalidPublicKeySerialized = "aced0005737200"
                + Integer.toHexString(publicKey.getClass().getName().length()) + classNameHex
                + "064c7113d078e42d" // serialVersionUID
                + "0300015b000b"
                + "75436f6f7264696e617465" // hex("uCoordinate")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "1f" // size of public key (is 31, which is invalid)
                + "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c"
                + "78";

        ByteArrayInputStream bais =
                new ByteArrayInputStream(TestUtils.decodeHex(invalidPublicKeySerialized));
        ObjectInputStream ois = new ObjectInputStream(bais);

        assertThrows(IOException.class, () -> ois.readObject());
    }
}
