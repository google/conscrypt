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

import static org.conscrypt.HpkeSuite.AEAD_AES_128_GCM;
import static org.conscrypt.HpkeSuite.AEAD_AES_256_GCM;
import static org.conscrypt.HpkeSuite.AEAD_CHACHA20POLY1305;
import static org.conscrypt.HpkeSuite.KDF_HKDF_SHA256;
import static org.conscrypt.HpkeSuite.KEM_XWING;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

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
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

@RunWith(JUnit4.class)
public class XwingTest {
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
    public void createKeyAndGetRawKey_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("XWING", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);

        EncodedKeySpec privateKeySpec =
                keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
        assertEquals("raw", privateKeySpec.getFormat());
        byte[] rawPrivateKey = privateKeySpec.getEncoded();
        assertEquals(32, rawPrivateKey.length);

        EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
        assertEquals("raw", publicKeySpec.getFormat());
        byte[] rawPublicKey = publicKeySpec.getEncoded();
        assertEquals(1216, rawPublicKey.length);

        PrivateKey privateKey2 = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));
        PublicKey publicKey2 = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));

        assertEquals(keyPair.getPublic(), publicKey2);
        assertEquals(keyPair.getPrivate(), privateKey2);
    }

    @Test
    public void generatePrivate_fromRawPrivateKey_validatesSize() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);

        PrivateKey unused = keyFactory.generatePrivate(new RawKeySpec(new byte[32]));
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new RawKeySpec(new byte[31])));
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new RawKeySpec(new byte[33])));
    }

    @Test
    public void generatePublic_fromRawPublicKey_validatesSize() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("XWING", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);
        EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
        byte[] rawPublicKey = publicKeySpec.getEncoded();

        PublicKey unused = keyFactory.generatePublic(new RawKeySpec(new byte[rawPublicKey.length]));
        assertThrows(
                InvalidKeySpecException.class,
                () -> keyFactory.generatePublic(new RawKeySpec(new byte[rawPublicKey.length - 1])));
        assertThrows(
                InvalidKeySpecException.class,
                () -> keyFactory.generatePublic(new RawKeySpec(new byte[rawPublicKey.length + 1])));
    }

    /** Helper class to test KeyFactory.translateKey. */
    static class TestPublicKey implements PublicKey {
        public TestPublicKey(byte[] x509encoded) {
            this.x509encoded = x509encoded;
        }

        private final byte[] x509encoded;

        @Override
        public String getAlgorithm() {
            return "XWING";
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            return x509encoded;
        }
    }

    /** Helper class to test KeyFactory.translateKey. */
    static class TestPrivateKey implements PrivateKey {
        public TestPrivateKey(byte[] pkcs8encoded) {
            this.pkcs8encoded = pkcs8encoded;
        }

        private final byte[] pkcs8encoded;

        @Override
        public String getAlgorithm() {
            return "XWING";
        }

        @Override
        public String getFormat() {
            return "PKCS#8";
        }

        @Override
        public byte[] getEncoded() {
            return pkcs8encoded;
        }
    }

    @Test
    public void toAndFromX509AndPkcs8_works() throws Exception {
        // from https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/, Appendix D
        byte[] rawPrivateKey = TestUtils.decodeHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] rawPublicKey = NativeCrypto.XWING_public_key_from_seed(rawPrivateKey);

        byte[] encodedPrivateKey = TestUtils.decodeBase64(
                "MDQCAQAwDQYLKwYBBAGD5i2ByHoEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f");
        byte[] encodedPublicKey = TestUtils.decodeBase64(
                "MIIE1DANBgsrBgEEAYPmLYHIegOCBMEAb1QJigoOZBFGYUtpYLpg2GA9YvRH+atJ"
                + "m0e9aQbMQLBh2GNKPoiQbyhJWOdEHKbHJcu5cJW3ZxpGK2aByeZYC7yNYLFJ+mAm"
                + "EEOvu6UvIFpgKDhIUVlq3zcavqmNM0c4PSu2c0OPZ4NhK/hwFPe5Gol0AmU0XfZ5"
                + "NARz0cTBdohuXim48Fi7fHNTFmhs/1w764wmHLAJcKacGvzFS5TLhuHOY7pjbjlc"
                + "pFEB4hx70EwxPqGa8kFB79KtREFqJbpPZZEO99iAnDCT8EqvAOPNluNcSqPIAsGK"
                + "1vOdpLS42YyL15Atg6B7pFOWZ0pgJDyrk+gP2bHId3N2qcwNb6EV4mOTgLnGvnhI"
                + "vRNYjGRwOgU10ZoPgWM6l2oKEFtm7ihdD9JV6CwDMZJfQ4O278dh72CZI1oLmHJj"
                + "WKqdAbi4llGfkhR0u3wUuyIlK1wvENQSRsmyPnZEhJNn9UGhX2O8koo5u3vHPwe2"
                + "ZcSWu2VYyPRUiacuxLrNNOnFlMM4cbcj8DSV6ItDkasm5DBD3rYRezkZ5FxMGxar"
                + "KOR93XI2Y4VHZhkvwYBspwq7eGy9swky5oyKNwvPsHmDoBLDJmuT76YmV/S4ODdM"
                + "sLuV4OwGVBsHZdmc8VO8a5YTXKeApVs2R3ieMZFeRig8+ce7boRT+2aCEFFB8dwN"
                + "ANhe7XA7bGyWH3nIRSdrQkiUnAZ4LlE+spkbldlgQuOMvto1JEmytQhOvaUiamIG"
                + "QAeJEwowlkSYSLYp/upKLCp0PEoN3Jyz89Z2/FY3MbJsShpm3IRZFwBW1XaX8UQ7"
                + "gamjRBK7e/BfMydXWlkR3TAdYFOGfzwwgHEfG/EVh7C7KYQnayaF53ViEOSz+JVT"
                + "hCMeVYxvUQyR4PxWtdGIX/KUnpWka8G+4fpx9QJ+EMRDsOkdD9dED0Z6JyISEuiP"
                + "XGumQpbK4NIHv8YPiMfPtcRaoYOdGMs3xFhD5UJqSpDIArZCj5U8NZxKwGA0UvrA"
                + "tzYeL9NdzIhakhRdT8oBWPG31wtLzRGOSipBVEON8xDESpobmepBWQcmeoiwYkJB"
                + "V5wXIvRu1hwuPspUXJlwUXF1OZuADbJdo5WT0GSQ1xQsAOiNLbBH6YmL23rLftkH"
                + "9uMEFswN5UokLAohJjAvXVTIW8Zqwvg8eXlFtQZ8qkK9LgwZypdQblB6sKXJ9WM3"
                + "CEmcGfJK7FE705A6XXO27EmR98cuuZHBw3iJgFyx6jigzAIXayfFjWOM5aMmaEV8"
                + "+bm+AnygIUBXlxcl1UEC6JlnFusq2CNFO2BbhVNwsbIbOTLN7UFgqplzx+uuWsR2"
                + "TZTPfMlQbwd7rXMBLbtKyBQKOHRkEuszyVFFliBfcHY1hiIX2bYJGMYmjZNEkVuE"
                + "eiR2waJw8VSlyEI0FlrPyGk5hwLOqemgfnsOmeqb3LeEH+nA+iXIM4CSVho+3dxw"
                + "AfR4rWV4GmAkqtFl2baXmtrESKRGL1ZGhVJ/diQ0/ppCWoRDe0VzkuyoDJE1BhUe"
                + "OhMjnzQvynZVtuquhFoiHOs+Z/VjnGGT9v3u9X45m4CLfzqitXQKre2QFj3F13XJ"
                + "+vfx+9B12rNE6dfRRmRygfu6ezxWyv1YM7epMOxCBufDptd2T+gdeg==");

        KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);

        // Check generatePrivate from PKCS8EncodedKeySpec works.
        PrivateKey privateKey =
                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
        assertArrayEquals(encodedPrivateKey, privateKey.getEncoded());
        assertArrayEquals(rawPrivateKey, ((OpenSslXwingPrivateKey) privateKey).getRaw());

        // Check generatePublic from X509EncodedKeySpec works.
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
        assertArrayEquals(encodedPublicKey, publicKey.getEncoded());
        assertArrayEquals(rawPublicKey, ((OpenSslXwingPublicKey) publicKey).getRaw());

        // Check getKeySpec with works for both private and public keys.
        EncodedKeySpec privateKeySpec =
                keyFactory.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
        assertEquals("PKCS#8", privateKeySpec.getFormat());
        assertArrayEquals(encodedPrivateKey, privateKeySpec.getEncoded());

        EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, X509EncodedKeySpec.class);
        assertEquals("X.509", publicKeySpec.getFormat());
        assertArrayEquals(encodedPublicKey, publicKeySpec.getEncoded());

        assertEquals(privateKey, keyFactory.translateKey(privateKey));
        assertEquals(privateKey,
                     keyFactory.translateKey(new TestPrivateKey(privateKey.getEncoded())));
        assertEquals(publicKey, keyFactory.translateKey(publicKey));
        assertEquals(publicKey, keyFactory.translateKey(new TestPublicKey(publicKey.getEncoded())));
    }

    @Test
    public void serialize_throwsUnsupportedOperationException() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("XWING", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        ObjectOutputStream oos = new ObjectOutputStream(new ByteArrayOutputStream(16384));
        assertThrows(UnsupportedOperationException.class,
                     () -> oos.writeObject(keyPair.getPrivate()));
        assertThrows(UnsupportedOperationException.class,
                     () -> oos.writeObject(keyPair.getPublic()));
    }

    @Test
    public void sealAndOpen_works() throws Exception {
        byte[] info = TestUtils.decodeHex("aa");
        byte[] plaintext = TestUtils.decodeHex("bb");
        byte[] aad = TestUtils.decodeHex("cc");
        for (int aead : new int[] {AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_CHACHA20POLY1305}) {
            HpkeSuite suite = new HpkeSuite(KEM_XWING, KDF_HKDF_SHA256, aead);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("XWING", conscryptProvider);
            KeyPair keyPairRecipient = keyGen.generateKeyPair();

            HpkeContextSender ctxSender =
                    HpkeContextSender.getInstance(suite.name(), conscryptProvider);
            ctxSender.init(keyPairRecipient.getPublic(), info);

            byte[] encapsulated = ctxSender.getEncapsulated();
            byte[] ciphertext = ctxSender.seal(plaintext, aad);

            HpkeContextRecipient contextRecipient =
                    HpkeContextRecipient.getInstance(suite.name(), conscryptProvider);
            contextRecipient.init(encapsulated, keyPairRecipient.getPrivate(), info);
            byte[] output = contextRecipient.open(ciphertext, aad);

            assertArrayEquals(plaintext, output);
        }
    }

    @Test
    public void sealAndOpenWithForeignKeys_works() throws Exception {
        byte[] info = TestUtils.decodeHex("aa");
        byte[] plaintext = TestUtils.decodeHex("bb");
        byte[] aad = TestUtils.decodeHex("cc");
        for (int aead : new int[] {AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_CHACHA20POLY1305}) {
            HpkeSuite suite = new HpkeSuite(KEM_XWING, KDF_HKDF_SHA256, aead);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("XWING", conscryptProvider);
            KeyPair keyPairRecipient = keyGen.generateKeyPair();
            PublicKey foreignPublicKey =
                    new TestPublicKey(keyPairRecipient.getPublic().getEncoded());
            PrivateKey foreignPrivateKey =
                    new TestPrivateKey(keyPairRecipient.getPrivate().getEncoded());

            HpkeContextSender ctxSender =
                    HpkeContextSender.getInstance(suite.name(), conscryptProvider);
            ctxSender.init(foreignPublicKey, info);

            byte[] encapsulated = ctxSender.getEncapsulated();
            byte[] ciphertext = ctxSender.seal(plaintext, aad);

            HpkeContextRecipient foreignContextRecipient =
                    HpkeContextRecipient.getInstance(suite.name(), conscryptProvider);
            foreignContextRecipient.init(encapsulated, foreignPrivateKey, info);

            byte[] foreignOutput = foreignContextRecipient.open(ciphertext, aad);

            assertArrayEquals(plaintext, foreignOutput);
        }
    }

    @Test
    public void kemTestVectors_encapsulatedIsCorrect() throws Exception {
        HpkeSuite suite = new HpkeSuite(KEM_XWING, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
        List<TestVector> vectors = TestUtils.readTestVectors("crypto/xwing.txt");
        byte[] unusedInfo = TestUtils.decodeHex("aa");

        for (TestVector vector : vectors) {
            String errMsg = vector.getString("name");
            byte[] eseed = vector.getBytes("eseed");
            byte[] pk = vector.getBytes("pk");
            byte[] ct = vector.getBytes("ct");

            KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);
            PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(pk));

            HpkeContextSender ctxSender =
                    HpkeContextSender.getInstance(suite.name(), conscryptProvider);
            ctxSender.initForTesting(publicKey, unusedInfo, eseed);
            byte[] encapsulated = ctxSender.getEncapsulated();

            assertArrayEquals("test case: " + errMsg, ct, encapsulated);
        }
    }
}
