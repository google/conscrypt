/*
 * Copyright (C) 2026 The Android Open Source Project
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

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.spec.DESKeySpec;

@RunWith(JUnit4.class)
@SuppressWarnings("InsecureCryptoUsage")
public class OpenSslCompositeMlDsaKeyFactoryTest {
    private static final Provider PROVIDER = TestUtils.getConscryptProvider();

    public static final class RawKeySpec extends EncodedKeySpec {
        public RawKeySpec(byte[] encoded) {
            super(encoded);
        }

        @Override
        public String getFormat() {
            return "raw";
        }
    }

    private static KeyFactory getInstance(String algName) throws NoSuchAlgorithmException {
        return KeyFactory.getInstance(algName, PROVIDER);
    }

    @Test
    public void mldsa44Ed25519Sha512_correctAlgorithm() throws Exception {
        OpenSslCompositeMlDsaKeyFactory keyFactory =
                new OpenSslCompositeMlDsaKeyFactory.Mldsa44Ed25519Sha512();

        assertEquals(CompositeMlDsaAlgorithm.MLDSA44_ED25519_SHA512, keyFactory.getAlgorithm());
    }

    @Test
    public void mldsa65Ed25519Sha512_correctAlgorithm() throws Exception {
        OpenSslCompositeMlDsaKeyFactory keyFactory =
                new OpenSslCompositeMlDsaKeyFactory.Mldsa65Ed25519Sha512();

        assertEquals(CompositeMlDsaAlgorithm.MLDSA65_ED25519_SHA512, keyFactory.getAlgorithm());
    }

    @Test
    public void generatePublic_works() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            byte[] pkBytes = TestUtils.decodeBase64(tv.getString("pk"));
            RawKeySpec rawKeySpec = new RawKeySpec(pkBytes);
            KeyFactory keyFactory = getInstance(algName);

            PublicKey publicKey = keyFactory.generatePublic(rawKeySpec);

            assertNotNull(publicKey);
            assertTrue(publicKey instanceof OpenSslCompositeMlDsaPublicKey);
            assertEquals(algName, publicKey.getAlgorithm());
            assertArrayEquals(pkBytes, ((OpenSslCompositeMlDsaPublicKey) publicKey).getRaw());
        }
    }

    @Test
    public void generatePrivate_works() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            byte[] skBytes = TestUtils.decodeBase64(tv.getString("sk"));
            RawKeySpec rawKeySpec = new RawKeySpec(skBytes);
            KeyFactory keyFactory = getInstance(algName);

            PrivateKey privateKey = keyFactory.generatePrivate(rawKeySpec);

            assertNotNull(privateKey);
            assertTrue(privateKey instanceof OpenSslCompositeMlDsaPrivateKey);
            assertEquals(algName, privateKey.getAlgorithm());
            assertArrayEquals(skBytes, ((OpenSslCompositeMlDsaPrivateKey) privateKey).getRaw());
        }
    }

    @Test
    public void getKeySpec_worksForPublicKey() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            byte[] pkBytes = TestUtils.decodeBase64(tv.getString("pk"));
            KeyFactory keyFactory = getInstance(algName);
            OpenSslCompositeMlDsaPublicKey publicKey = new OpenSslCompositeMlDsaPublicKey(
                    pkBytes, CompositeMlDsaAlgorithm.fromName(algName));

            RawKeySpec returnedSpec = keyFactory.getKeySpec(publicKey, RawKeySpec.class);

            assertNotNull(returnedSpec);
            assertEquals("raw", returnedSpec.getFormat());
            assertArrayEquals(pkBytes, returnedSpec.getEncoded());
        }
    }

    @Test
    public void getKeySpec_worksForPrivateKey() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            byte[] skBytes = TestUtils.decodeBase64(tv.getString("sk"));
            KeyFactory keyFactory = getInstance(algName);
            OpenSslCompositeMlDsaPrivateKey privateKey = new OpenSslCompositeMlDsaPrivateKey(
                    skBytes, CompositeMlDsaAlgorithm.fromName(algName));

            RawKeySpec returnedSpec = keyFactory.getKeySpec(privateKey, RawKeySpec.class);

            assertNotNull(returnedSpec);
            assertEquals("raw", returnedSpec.getFormat());
            assertArrayEquals(skBytes, returnedSpec.getEncoded());
        }
    }

    @Test
    public void getKeySpec_worksForPrivateKey_pkcs8() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            byte[] pkcs8Bytes = TestUtils.decodeBase64(tv.getString("skpkcs8"));
            byte[] rawBytes = TestUtils.decodeBase64(tv.getString("sk"));
            KeyFactory keyFactory = getInstance(algName);
            OpenSslCompositeMlDsaPrivateKey privateKey = new OpenSslCompositeMlDsaPrivateKey(
                    rawBytes, CompositeMlDsaAlgorithm.fromName(algName));

            PKCS8EncodedKeySpec returnedSpec =
                    keyFactory.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);

            assertNotNull(returnedSpec);
            assertEquals("PKCS#8", returnedSpec.getFormat());
            assertArrayEquals(pkcs8Bytes, returnedSpec.getEncoded());
            assertArrayEquals(pkcs8Bytes, privateKey.getEncoded());
        }
    }

    @Test
    public void getKeySpec_worksForPublicKey_x509() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            byte[] x509Bytes = Base64.getDecoder().decode(tv.getString("pkx509"));
            byte[] rawBytes = Base64.getDecoder().decode(tv.getString("pk"));
            KeyFactory keyFactory = getInstance(algName);
            OpenSslCompositeMlDsaPublicKey publicKey = new OpenSslCompositeMlDsaPublicKey(
                    rawBytes, CompositeMlDsaAlgorithm.fromName(algName));

            X509EncodedKeySpec returnedSpec =
                    keyFactory.getKeySpec(publicKey, X509EncodedKeySpec.class);

            assertNotNull(returnedSpec);
            assertEquals("X.509", returnedSpec.getFormat());
            assertArrayEquals(x509Bytes, returnedSpec.getEncoded());
            assertArrayEquals(x509Bytes, publicKey.getEncoded());
        }
    }

    @Test
    public void translateKey_works() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            byte[] pkBytes = TestUtils.decodeBase64(tv.getString("pk"));
            byte[] skBytes = TestUtils.decodeBase64(tv.getString("sk"));
            OpenSslCompositeMlDsaPublicKey publicKey = new OpenSslCompositeMlDsaPublicKey(
                    pkBytes, CompositeMlDsaAlgorithm.fromName(algName));
            OpenSslCompositeMlDsaPrivateKey privateKey = new OpenSslCompositeMlDsaPrivateKey(
                    skBytes, CompositeMlDsaAlgorithm.fromName(algName));
            KeyFactory keyFactory = getInstance(algName);

            Key translatedPublicKey = keyFactory.translateKey(publicKey);
            Key translatedPrivateKey = keyFactory.translateKey(privateKey);

            assertEquals(publicKey, translatedPublicKey);
            assertEquals(privateKey, translatedPrivateKey);
        }
    }

    @Test
    public void translateKey_throwsForUnsupportedKey() throws Exception {
        OpenSslMlDsaPrivateKey mlDsaPrivateKey =
                new OpenSslMlDsaPrivateKey(new byte[32], MlDsaAlgorithm.ML_DSA_44);
        KeyFactory keyFactory = KeyFactory.getInstance("MLDSA44-Ed25519-SHA512", PROVIDER);

        assertThrows(InvalidKeyException.class, () -> keyFactory.translateKey(mlDsaPrivateKey));
    }

    @Test
    public void generatePublic_nullKeySpec_throws() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            KeyFactory keyFactory = getInstance(algName);

            assertThrows(InvalidKeySpecException.class, () -> keyFactory.generatePublic(null));
        }
    }

    @Test
    public void generatePrivate_nullKeySpec_throws() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            KeyFactory keyFactory = getInstance(algName);

            assertThrows(InvalidKeySpecException.class, () -> keyFactory.generatePrivate(null));
        }
    }

    @Test
    public void generatePublic_unsupportedKeySpec_throws() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            KeyFactory keyFactory = getInstance(algName);
            DESKeySpec unsupportedKeySpec =
                    new DESKeySpec(TestUtils.decodeBase64(tv.getString("pkx509")));

            assertThrows(InvalidKeySpecException.class,
                         () -> keyFactory.generatePublic(unsupportedKeySpec));
        }
    }

    @Test
    public void generatePublic_invalidKeySpecValue_throws() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            KeyFactory keyFactory = getInstance(algName);
            X509EncodedKeySpec x509Spec =
                    new X509EncodedKeySpec(TestUtils.decodeBase64(tv.getString("pk")));

            assertThrows(InvalidKeySpecException.class,
                         () -> keyFactory.generatePublic(x509Spec));
        }
    }

    @Test
    public void generatePrivate_pkcs8_works() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            byte[] pkcs8Bytes = TestUtils.decodeBase64(tv.getString("skpkcs8"));
            byte[] rawBytes = TestUtils.decodeBase64(tv.getString("sk"));
            PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
            KeyFactory keyFactory = getInstance(algName);

            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8Spec);

            assertNotNull(privateKey);
            assertTrue(privateKey instanceof OpenSslCompositeMlDsaPrivateKey);
            assertEquals(algName, privateKey.getAlgorithm());
            assertArrayEquals(rawBytes, ((OpenSslCompositeMlDsaPrivateKey) privateKey).getRaw());
        }
    }

    @Test
    public void generatePrivate_invalidPkcs8_throws() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            KeyFactory keyFactory = getInstance(algName);
            PKCS8EncodedKeySpec pkcs8Spec =
                    new PKCS8EncodedKeySpec(TestUtils.decodeBase64(tv.getString("sk")));

            assertThrows(InvalidKeySpecException.class,
                         () -> keyFactory.generatePrivate(pkcs8Spec));
        }
    }

    @Test
    public void generatePrivate_unsupportedKeySpec_throws() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            KeyFactory keyFactory = getInstance(algName);
            DESKeySpec unsupportedKeySpec =
                    new DESKeySpec(TestUtils.decodeBase64(tv.getString("skpkcs8")));

            assertThrows(InvalidKeySpecException.class,
                         () -> keyFactory.generatePrivate(unsupportedKeySpec));
        }
    }

    @Test
    public void generatePrivate_pkcs8_shortKey_fails() throws Exception {
        byte[] pkcs8 = TestUtils.decodeHex("3012020100300a06082b060105050706270401aa");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8)));
    }

    @Test
    public void generatePrivate_pkcs8_corruptedHeader_fails() throws Exception {
        // Length byte 0x10 instead of 0x51.
        byte[] pkcs8 = TestUtils.decodeHex(
                "3010020100300a06082b06010505070627044001d8df59152d8a44e39a25e6775"
                + "ef18a0044b20e58c2c4346ac37c27d152176c5bea6c2454617bfb48479eb8b1"
                + "3b711a98116b73f7ecac30faf1dd9b4fa17d68");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8)));
    }

    @Test
    public void generatePrivate_pkcs8_wrongVersion_fails() throws Exception {
        // Version byte 0x01 instead of 0x00.
        byte[] pkcs8 = TestUtils.decodeHex(
                "3051020101300a06082b06010505070627044001d8df59152d8a44e39a25e6775"
                + "ef18a0044b20e58c2c4346ac37c27d152176c5bea6c2454617bfb48479eb8b1"
                + "3b711a98116b73f7ecac30faf1dd9b4fa17d68");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8)));
    }

    @Test
    public void generatePrivate_pkcs8_wrongOid_fails() throws Exception {
        // OID byte 0x28 instead of 0x27.
        byte[] pkcs8 = TestUtils.decodeHex(
                "3051020100300a06082b06010505070628044001d8df59152d8a44e39a25e6775"
                + "ef18a0044b20e58c2c4346ac37c27d152176c5bea6c2454617bfb48479eb8b1"
                + "3b711a98116b73f7ecac30faf1dd9b4fa17d68");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8)));
    }

    @Test
    public void generatePrivate_pkcs8_wrongOidTag_fails() throws Exception {
        // OID tag byte 0x07 instead of 0x06.
        byte[] pkcs8 = TestUtils.decodeHex(
                "3051020100300a07082b06010505070627044001d8df59152d8a44e39a25e6775"
                + "ef18a0044b20e58c2c4346ac37c27d152176c5bea6c2454617bfb48479eb8b1"
                + "3b711a98116b73f7ecac30faf1dd9b4fa17d68");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8)));
    }

    @Test
    public void generatePrivate_pkcs8_wrongOidLength_tooLong_fails() throws Exception {
        // OID length byte 0x13 instead of 0x08.
        byte[] pkcs8 = TestUtils.decodeHex(
                "3051020100300a06132b06010505070627044001d8df59152d8a44e39a25e6775"
                + "ef18a0044b20e58c2c4346ac37c27d152176c5bea6c2454617bfb48479eb8b1"
                + "3b711a98116b73f7ecac30faf1dd9b4fa17d68");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8)));
    }

    @Test
    public void generatePrivate_pkcs8_wrongOidLength_tooShort_fails() throws Exception {
        // OID length byte 0x01 instead of 0x08.
        byte[] pkcs8 = TestUtils.decodeHex(
                "3051020100300a06012b06010505070627044001d8df59152d8a44e39a25e6775"
                + "ef18a0044b20e58c2c4346ac37c27d152176c5bea6c2454617bfb48479eb8b1"
                + "3b711a98116b73f7ecac30faf1dd9b4fa17d68");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8)));
    }

    @Test
    public void generatePrivate_pkcs8_short_garbage_fails() throws Exception {
        byte[] pkcs8 = TestUtils.decodeHex("0102030405060708");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8)));
    }

    @Test
    public void generatePrivate_pkcs8_long_garbage_fails() throws Exception {
        byte[] pkcs8 = TestUtils.decodeHex(
                "12d0f753076b0c21d8565461f11e9b06baaf4a6fe504850df1aea1457a8be61386456aa7"
                + "56f3b729a5ec4e4f54dc5bb1d7f8efcca13a2bc94815e82e2ae0566f73777de07c6ea4"
                + "9ee5f1be1b069fbc96e6ae7359b92b52d2a70ffa1fd69e1bdeaa19322e3a1742fb46e3"
                + "86f043be30c8fd26e7bb91576515e75b097b8a3bbb");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8)));
    }

    @Test
    public void generatePublic_x509_works() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            byte[] pkX509Bytes = TestUtils.decodeBase64(tv.getString("pkx509"));
            byte[] rawBytes = TestUtils.decodeBase64(tv.getString("pk"));
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(pkX509Bytes);
            KeyFactory keyFactory = getInstance(algName);

            PublicKey publicKey = keyFactory.generatePublic(x509Spec);

            assertNotNull(publicKey);
            assertTrue(publicKey instanceof OpenSslCompositeMlDsaPublicKey);
            assertEquals(algName, publicKey.getAlgorithm());
            assertArrayEquals(rawBytes, ((OpenSslCompositeMlDsaPublicKey) publicKey).getRaw());
        }
    }

    @Test
    public void generatePublic_invalidX509_throws() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            KeyFactory keyFactory = getInstance(algName);
            // using `pk` (raw) as invalid X.509 SPKI encoded byte array
            X509EncodedKeySpec x509Spec =
                    new X509EncodedKeySpec(TestUtils.decodeBase64(tv.getString("pk")));

            assertThrows(InvalidKeySpecException.class, () -> keyFactory.generatePublic(x509Spec));
        }
    }

    @Test
    public void generatePublic_x509_shortKey_fails() throws Exception {
        // Only 10 byte payload inside bit string payload
        byte[] spki =
                TestUtils.decodeHex("30820551300a06082b06010505070628030b0011223344556677889900");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePublic(new X509EncodedKeySpec(spki)));
    }

    @Test
    public void generatePublic_x509_wrongOid_fails() throws Exception {
        // OID byte 0x28 instead of 0x27
        byte[] spki = TestUtils.decodeHex(
                "30820551300a06082b060105050706280382054100165a6569022056e604034e2737d557c8c58ae170"
                + "e14619da19a58ee85aa80ad883af9acbf3da261054887fcd755f16db1e928127344ea81a8a7db3e0"
                + "b2b31166305d1de467e4e8b8a4aedbb217630645e6ef20aa3df302e743e4cca2390854ecc35de290"
                + "0e14989b81ba94b15c3ce111c8472c2c9ba503c176bfbe4ebe0d2a1d1c11a0e2f461650ddccbb033"
                + "ffd5df43875379eeb1ce08f2e2ffbb639aa3d8ac2cc5b291000db0642817f03603d16a3ccc97c167"
                + "401f2a41f3332b9b623ba8ca11bf9f7740b9521c0e61ee0d5cb6b3a6a1adb15f36674202d43ad0bc"
                + "75cdbde3f21d3fe138049841028cec3f0c512b3de7850564f605aaf42b875272465fbcedc162a101"
                + "8e8df9f7b6ddae858a4cab3c91c9e6b2c23c2af2dc890b86401ae4d37c3a97afbe9076f4c1e25297"
                + "e36965832208741c1ce03063ba0598122551fcfc469b3c3220148cf4f8173c05be8a37c4932a9ac9"
                + "7d1c3d04456aa8ba24ac61834896003193b2c10af287d9c33e0def5d5ca3b2d1352a9f71115bf904"
                + "fdbf7680412fd566cc724f26cb1cba40083b2af6a0c272d7b01c4299a556b33854644d995322ca7f"
                + "60177d6af3131562206b14639ee2a268ba4c7a4d07971f4176f49033d6fbcc5948306c35d47041b6"
                + "0fd1db651f2bec76ccda9265e4b764de9fca57ee9b66009bb22b3739f871aafc83ae037d0e803191"
                + "de3cae1eaa5e5de67f224a1440153460f231afea991a40133539a3dc58c6dad5e0e270de69c82698"
                + "830ae1632db254ddee4ce178fd9d69c59f174370f1eb3900efd7f83fb74d86319d6279411f5c009f"
                + "04dd19e3f87a9937685de347f2498d1c743317af2c460a3770eb484e7cd0a59398610c33d51070fc"
                + "fdb09ffe560364811286457870d34d6af2f033121ae22fc9859d984168236f1936dc90f4c7e2b8b7"
                + "a961db883a73b738ea2a0eff6e665f950ecdef2dde5fcc16499d20d1887d28326ac2c21cee66a80f"
                + "6d0bc50442af6750649f2634e8ecafe3689c20cf040e2eb29f62d7a594d5b07045bf35a7e2ba316a"
                + "dac7ec06fa6d9e067fe7fed917058632d6bd1f05f8938b315063a6e76b41d2cd7a87930c260d8736"
                + "d191a8efb244e1b0656a0285435d96ef86d27bb1f03f6f03c6dbd6296e7a22cea532ea9956483c19"
                + "0316e08cf7857f522817bafedc34e8f7a03c36e9fd17c5031ceaf6f71be4553d92c84c767bd3018e"
                + "88ece8e054647c157378899011cd4e7e04141ae106e59310d4ca23cb4a3492017de82a45a6bbd4bd"
                + "2f19ab86c1e077628ea9b64bd7d12866bc7e790cac79a2e30ee179ebd0dae95d77dcda9e8f8e823d"
                + "364da7aa23c0d4808cf6366a2d43d2167c190a5369e4d146255c154a6ce141d10ac51b0524c2e512"
                + "4b5681aa8f478e4408626f8c69ec31a529feecd63f3c647d4e80ec3fac86c532cc8a490b0a2a6236"
                + "d81a37156da254bfd2a0f18e283ba931026fa25922795a8ad038d4c6c7c32dffd5a64acce9f1f714"
                + "88b0e83cfbbd2cf709f5084348037d08bfc34f165823fbd3a547783c17d6bb1c02f9f609cebfab74"
                + "db3fd6cc62812f4b4e29e4b3c6787b6f5ff3d5c9fbfd24da806eb4559adb9301dd6b42188f3472b9"
                + "247e5f7b079b97134eb25b8d1f9889dad1fbd11ff72dc6cbea38874bd0dfa31cc73e75f76ab5a954"
                + "5d596786998af78f00e5fc07d27bcdbc5d861754d5e50d16dfac12e1b203a56c4ec1dff1f65e5e96"
                + "cfc32d4e051326362277c06f95402ee0b933239e1b3b9258ee5a5859d4c96c9c6ae85fbcb9d71da5"
                + "efcaf79edc225e4a727e93818837b34c73eef2460c3642da6567a8e1bca0474e120fbe469a3c2460"
                + "6017292bcbd9732a4fc8823bcc1046b2a778878182640aa23a258f9110950218a6d0b31e3ab49155"
                + "68bade5a");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePublic(new X509EncodedKeySpec(spki)));
    }

    @Test
    public void generatePublic_x509_short_garbage_fails() throws Exception {
        byte[] spki = TestUtils.decodeHex("0102030405060708");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePublic(new X509EncodedKeySpec(spki)));
    }

    @Test
    public void generatePublic_x509_wrongPaddingBits_fails() throws Exception {
        // Padding bits byte 0x01 instead of 0x00 for the BIT STRING
        byte[] spki = TestUtils.decodeHex(
                "30820551300a06082b060105050706270382054101165a6569022056e604034e2737d557c8c58ae170"
                + "e14619da19a58ee85aa80ad883af9acbf3da261054887fcd755f16db1e928127344ea81a8a7db3e0"
                + "b2b31166305d1de467e4e8b8a4aedbb217630645e6ef20aa3df302e743e4cca2390854ecc35de290"
                + "0e14989b81ba94b15c3ce111c8472c2c9ba503c176bfbe4ebe0d2a1d1c11a0e2f461650ddccbb033"
                + "ffd5df43875379eeb1ce08f2e2ffbb639aa3d8ac2cc5b291000db0642817f03603d16a3ccc97c167"
                + "401f2a41f3332b9b623ba8ca11bf9f7740b9521c0e61ee0d5cb6b3a6a1adb15f36674202d43ad0bc"
                + "75cdbde3f21d3fe138049841028cec3f0c512b3de7850564f605aaf42b875272465fbcedc162a101"
                + "8e8df9f7b6ddae858a4cab3c91c9e6b2c23c2af2dc890b86401ae4d37c3a97afbe9076f4c1e25297"
                + "e36965832208741c1ce03063ba0598122551fcfc469b3c3220148cf4f8173c05be8a37c4932a9ac9"
                + "7d1c3d04456aa8ba24ac61834896003193b2c10af287d9c33e0def5d5ca3b2d1352a9f71115bf904"
                + "fdbf7680412fd566cc724f26cb1cba40083b2af6a0c272d7b01c4299a556b33854644d995322ca7f"
                + "60177d6af3131562206b14639ee2a268ba4c7a4d07971f4176f49033d6fbcc5948306c35d47041b6"
                + "0fd1db651f2bec76ccda9265e4b764de9fca57ee9b66009bb22b3739f871aafc83ae037d0e803191"
                + "de3cae1eaa5e5de67f224a1440153460f231afea991a40133539a3dc58c6dad5e0e270de69c82698"
                + "830ae1632db254ddee4ce178fd9d69c59f174370f1eb3900efd7f83fb74d86319d6279411f5c009f"
                + "04dd19e3f87a9937685de347f2498d1c743317af2c460a3770eb484e7cd0a59398610c33d51070fc"
                + "fdb09ffe560364811286457870d34d6af2f033121ae22fc9859d984168236f1936dc90f4c7e2b8b7"
                + "a961db883a73b738ea2a0eff6e665f950ecdef2dde5fcc16499d20d1887d28326ac2c21cee66a80f"
                + "6d0bc50442af6750649f2634e8ecafe3689c20cf040e2eb29f62d7a594d5b07045bf35a7e2ba316a"
                + "dac7ec06fa6d9e067fe7fed917058632d6bd1f05f8938b315063a6e76b41d2cd7a87930c260d8736"
                + "d191a8efb244e1b0656a0285435d96ef86d27bb1f03f6f03c6dbd6296e7a22cea532ea9956483c19"
                + "0316e08cf7857f522817bafedc34e8f7a03c36e9fd17c5031ceaf6f71be4553d92c84c767bd3018e"
                + "88ece8e054647c157378899011cd4e7e04141ae106e59310d4ca23cb4a3492017de82a45a6bbd4bd"
                + "2f19ab86c1e077628ea9b64bd7d12866bc7e790cac79a2e30ee179ebd0dae95d77dcda9e8f8e823d"
                + "364da7aa23c0d4808cf6366a2d43d2167c190a5369e4d146255c154a6ce141d10ac51b0524c2e512"
                + "4b5681aa8f478e4408626f8c69ec31a529feecd63f3c647d4e80ec3fac86c532cc8a490b0a2a6236"
                + "d81a37156da254bfd2a0f18e283ba931026fa25922795a8ad038d4c6c7c32dffd5a64acce9f1f714"
                + "88b0e83cfbbd2cf709f5084348037d08bfc34f165823fbd3a547783c17d6bb1c02f9f609cebfab74"
                + "db3fd6cc62812f4b4e29e4b3c6787b6f5ff3d5c9fbfd24da806eb4559adb9301dd6b42188f3472b9"
                + "247e5f7b079b97134eb25b8d1f9889dad1fbd11ff72dc6cbea38874bd0dfa31cc73e75f76ab5a954"
                + "5d596786998af78f00e5fc07d27bcdbc5d861754d5e50d16dfac12e1b203a56c4ec1dff1f65e5e96"
                + "cfc32d4e051326362277c06f95402ee0b933239e1b3b9258ee5a5859d4c96c9c6ae85fbcb9d71da5"
                + "efcaf79edc225e4a727e93818837b34c73eef2460c3642da6567a8e1bca0474e120fbe469a3c2460"
                + "6017292bcbd9732a4fc8823bcc1046b2a778878182640aa23a258f9110950218a6d0b31e3ab49155"
                + "68bade5a");
        KeyFactory keyFactory = getInstance("MLDSA44-Ed25519-SHA512");
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.generatePublic(new X509EncodedKeySpec(spki)));
    }
}
