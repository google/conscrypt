/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import static org.conscrypt.HpkeSuite.KEM_MLKEM_1024;
import static org.conscrypt.HpkeSuite.KEM_MLKEM_768;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
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
public class MlKemTest {
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

    public static MlKemAlgorithm toMlKemAlgorithm(String algorithm) {
        switch (algorithm) {
            case "ML-KEM":
            case "ML-KEM-768":
                return MlKemAlgorithm.ML_KEM_768;
            case "ML-KEM-1024":
                return MlKemAlgorithm.ML_KEM_1024;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    @Test
    public void generateKeyPair_works() throws Exception {
        for (String keyGenAlgorithm : new String[] {"ML-KEM", "ML-KEM-768", "ML-KEM-1024"}) {
            MlKemAlgorithm expectedAlgorithm = toMlKemAlgorithm(keyGenAlgorithm);

            KeyPairGenerator keyGen =
                    KeyPairGenerator.getInstance(keyGenAlgorithm, conscryptProvider);
            KeyPair keyPair = keyGen.generateKeyPair();
            OpenSslMlKemPrivateKey privateKey = (OpenSslMlKemPrivateKey) keyPair.getPrivate();
            OpenSslMlKemPublicKey publicKey = (OpenSslMlKemPublicKey) keyPair.getPublic();

            assertEquals(expectedAlgorithm, privateKey.getMlKemAlgorithm());
            assertEquals("ML-KEM", privateKey.getAlgorithm());
            byte[] seed = privateKey.getSeed();
            assertEquals(64, seed.length);

            assertEquals(expectedAlgorithm, publicKey.getMlKemAlgorithm());
            assertEquals("ML-KEM", publicKey.getAlgorithm());
            byte[] rawPublicKey = publicKey.getRaw();
            assertEquals(expectedAlgorithm.publicKeySize(), rawPublicKey.length);
        }
    }

    @Test
    public void keyFactory_toAndFromRaw_works() throws Exception {
        for (String factoryAlgorithm : new String[] {"ML-KEM", "ML-KEM-768", "ML-KEM-1024"}) {
            MlKemAlgorithm algorithm = toMlKemAlgorithm(factoryAlgorithm);
            // create random raw keys of the correct size.
            int publicKeySize = algorithm.publicKeySize();
            byte[] rawPrivateKey = new byte[64];
            NativeCrypto.RAND_bytes(rawPrivateKey);
            byte[] rawPublicKey = new byte[publicKeySize];
            NativeCrypto.RAND_bytes(rawPublicKey);

            KeyFactory keyFactory = KeyFactory.getInstance(factoryAlgorithm, conscryptProvider);

            // generatePrivate works.
            OpenSslMlKemPrivateKey privateKey = (OpenSslMlKemPrivateKey) keyFactory.generatePrivate(
                    new RawKeySpec(rawPrivateKey));
            assertEquals(algorithm, privateKey.getMlKemAlgorithm());
            assertEquals("ML-KEM", privateKey.getAlgorithm());
            assertArrayEquals(rawPrivateKey, privateKey.getSeed());

            // generatePublic works.
            OpenSslMlKemPublicKey publicKey =
                    (OpenSslMlKemPublicKey) keyFactory.generatePublic(new RawKeySpec(rawPublicKey));
            assertEquals(algorithm, publicKey.getMlKemAlgorithm());
            assertEquals("ML-KEM", publicKey.getAlgorithm());
            assertArrayEquals(rawPublicKey, publicKey.getRaw());

            // getKeySpec for private key with RawKeySpec works.
            EncodedKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RawKeySpec.class);
            assertEquals("raw", privateKeySpec.getFormat());
            assertArrayEquals(rawPrivateKey, privateKeySpec.getEncoded());

            // getKeySpec for public key with RawKeySpec works.
            EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RawKeySpec.class);
            assertEquals("raw", publicKeySpec.getFormat());
            assertArrayEquals(rawPublicKey, publicKeySpec.getEncoded());

            // generatePrivate and generatePublic for these keySpecs returns the same keys.
            PrivateKey privateKey2 = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));
            PublicKey publicKey2 = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));
            assertEquals(publicKey, publicKey2);
            assertEquals(privateKey, privateKey2);

            // check that generatePrivate and generatePublic reject keys of the wrong size.
            RawKeySpec tooSmallPrivateKeySpec = new RawKeySpec(new byte[rawPrivateKey.length - 1]);
            assertThrows(InvalidKeySpecException.class,
                         () -> keyFactory.generatePrivate(tooSmallPrivateKeySpec));
            RawKeySpec tooLargePrivateKeySpec = new RawKeySpec(new byte[rawPrivateKey.length + 1]);
            assertThrows(InvalidKeySpecException.class,
                         () -> keyFactory.generatePrivate(tooLargePrivateKeySpec));
            RawKeySpec tooSmallPublicKeySpec = new RawKeySpec(new byte[rawPublicKey.length - 1]);
            assertThrows(InvalidKeySpecException.class,
                         () -> keyFactory.generatePublic(tooSmallPublicKeySpec));
            RawKeySpec tooLargePublicKeySpec = new RawKeySpec(new byte[rawPublicKey.length + 1]);
            assertThrows(InvalidKeySpecException.class,
                         () -> keyFactory.generatePublic(tooLargePublicKeySpec));
        }
    }

    /** Helper class to test KeyFactory.translateKey. */
    private static class TestPublicKey implements PublicKey {
        TestPublicKey(byte[] x509Encoded) {
            this.x509Encoded = x509Encoded;
        }

        private final byte[] x509Encoded;

        @Override
        public String getAlgorithm() {
            return "ML-KEM";
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            return x509Encoded;
        }
    }

    /** Helper class to test KeyFactory.translateKey. */
    private static class TestPrivateKey implements PrivateKey {
        TestPrivateKey(byte[] pkcs8Encoded) {
            this.pkcs8Encoded = pkcs8Encoded;
        }

        private final byte[] pkcs8Encoded;

        @Override
        public String getAlgorithm() {
            return "ML-KEM";
        }

        @Override
        public String getFormat() {
            return "PKCS#8";
        }

        @Override
        public byte[] getEncoded() {
            return pkcs8Encoded;
        }
    }

    @Test
    public void mlKem768KeyPair_x509AndPkcs8_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-KEM-768", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        assertEquals("PKCS#8", keyPair.getPrivate().getFormat());
        // 64 bytes for the seed + 22 bytes for the preamble.
        assertEquals(86, keyPair.getPrivate().getEncoded().length);

        assertEquals("X.509", keyPair.getPublic().getFormat());
        // 1184 bytes for the raw key + 22 bytes for the preamble.
        assertEquals(1206, keyPair.getPublic().getEncoded().length);

        for (String algorithm : new String[] {"ML-KEM-768", "ML-KEM"}) {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm, conscryptProvider);

            PKCS8EncodedKeySpec privateKeySpec =
                    keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class);
            assertEquals("PKCS#8", privateKeySpec.getFormat());
            assertArrayEquals(keyPair.getPrivate().getEncoded(), privateKeySpec.getEncoded());

            X509EncodedKeySpec publicKeySpec =
                    keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class);
            assertEquals("X.509", publicKeySpec.getFormat());
            assertArrayEquals(keyPair.getPublic().getEncoded(), publicKeySpec.getEncoded());

            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            assertEquals(keyPair.getPrivate(), privateKey);
            assertEquals(keyPair.getPublic(), publicKey);

            assertEquals(keyPair.getPrivate(), keyFactory.translateKey(keyPair.getPrivate()));
            assertEquals(
                    keyPair.getPrivate(),
                    keyFactory.translateKey(new TestPrivateKey(keyPair.getPrivate().getEncoded())));
            assertEquals(keyPair.getPublic(), keyFactory.translateKey(keyPair.getPublic()));
            assertEquals(
                    keyPair.getPublic(),
                    keyFactory.translateKey(new TestPublicKey(keyPair.getPublic().getEncoded())));
        }

        KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM-1024", conscryptProvider);
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                     ()
                             -> keyFactory.generatePrivate(
                                     new RawKeySpec(keyPair.getPrivate().getEncoded())));
        assertThrows(
                InvalidKeySpecException.class,
                () -> keyFactory.generatePublic(new RawKeySpec(keyPair.getPublic().getEncoded())));

        assertThrows(InvalidKeyException.class,
                     () -> keyFactory.translateKey(keyPair.getPrivate()));
        assertThrows(InvalidKeyException.class,
                     ()
                             -> keyFactory.translateKey(
                                     new TestPrivateKey(keyPair.getPrivate().getEncoded())));
        assertThrows(InvalidKeyException.class, () -> keyFactory.translateKey(keyPair.getPublic()));
        assertThrows(
                InvalidKeyException.class,
                () -> keyFactory.translateKey(new TestPublicKey(keyPair.getPublic().getEncoded())));
    }

    @Test
    public void mlKem1024KeyPair_x509AndPkcs8_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-KEM-1024", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        assertEquals("PKCS#8", keyPair.getPrivate().getFormat());
        // 64 bytes for the seed + 22 bytes for the preamble.
        assertEquals(86, keyPair.getPrivate().getEncoded().length);

        assertEquals("X.509", keyPair.getPublic().getFormat());
        // 1568 bytes for the raw key + 22 bytes for the preamble.
        assertEquals(1590, keyPair.getPublic().getEncoded().length);

        for (String algorithm : new String[] {"ML-KEM-1024", "ML-KEM"}) {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm, conscryptProvider);

            PKCS8EncodedKeySpec privateKeySpec =
                    keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class);
            assertEquals("PKCS#8", privateKeySpec.getFormat());
            assertArrayEquals(keyPair.getPrivate().getEncoded(), privateKeySpec.getEncoded());

            X509EncodedKeySpec publicKeySpec =
                    keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class);
            assertEquals("X.509", publicKeySpec.getFormat());
            assertArrayEquals(keyPair.getPublic().getEncoded(), publicKeySpec.getEncoded());

            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            assertEquals(keyPair.getPrivate(), privateKey);
            assertEquals(keyPair.getPublic(), publicKey);

            assertEquals(keyPair.getPrivate(), keyFactory.translateKey(keyPair.getPrivate()));
            assertEquals(
                    keyPair.getPrivate(),
                    keyFactory.translateKey(new TestPrivateKey(keyPair.getPrivate().getEncoded())));
            assertEquals(keyPair.getPublic(), keyFactory.translateKey(keyPair.getPublic()));
            assertEquals(
                    keyPair.getPublic(),
                    keyFactory.translateKey(new TestPublicKey(keyPair.getPublic().getEncoded())));
        }

        KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM-768", conscryptProvider);
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                     () -> keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                     ()
                             -> keyFactory.generatePrivate(
                                     new RawKeySpec(keyPair.getPrivate().getEncoded())));
        assertThrows(
                InvalidKeySpecException.class,
                () -> keyFactory.generatePublic(new RawKeySpec(keyPair.getPublic().getEncoded())));

        assertThrows(InvalidKeyException.class,
                     () -> keyFactory.translateKey(keyPair.getPrivate()));
        assertThrows(InvalidKeyException.class,
                     ()
                             -> keyFactory.translateKey(
                                     new TestPrivateKey(keyPair.getPrivate().getEncoded())));
        assertThrows(InvalidKeyException.class, () -> keyFactory.translateKey(keyPair.getPublic()));
        assertThrows(
                InvalidKeyException.class,
                () -> keyFactory.translateKey(new TestPublicKey(keyPair.getPublic().getEncoded())));
    }

    @Test
    public void mlKem768_pkcs8TestVector_works() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM-768", conscryptProvider);

        // Example from RFC 9935, C.1.2.1
        String pcks8Base64 = "MFQCAQAwCwYJYIZIAWUDBAQCBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ"
                + "GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
        String rawHex = "000102030405060708090a0b0c0d0e0f10111213141"
                + "5161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343"
                + "5363738393a3b3c3d3e3f";

        byte[] seed = TestUtils.decodeHex(rawHex);
        byte[] encoded = TestUtils.decodeBase64(pcks8Base64);

        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(seed));
        assertArrayEquals(encoded, privateKey.getEncoded());

        EncodedKeySpec encodedKeySpec =
                keyFactory.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
        assertEquals("PKCS#8", encodedKeySpec.getFormat());
        assertArrayEquals(encoded, encodedKeySpec.getEncoded());

        PrivateKey privateKey2 = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        assertArrayEquals(encoded, privateKey2.getEncoded());
        OpenSslMlKemPrivateKey mlKemPrivateKey = (OpenSslMlKemPrivateKey) privateKey2;
        assertEquals(MlKemAlgorithm.ML_KEM_768, mlKemPrivateKey.getMlKemAlgorithm());
        assertArrayEquals(seed, mlKemPrivateKey.getSeed());
    }

    @Test
    public void mlKem1024_pkcs8TestVector_works() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM-1024", conscryptProvider);

        // Example from RFC 9935, C.1.3.1
        String pcks8Base64 = "MFQCAQAwCwYJYIZIAWUDBAQDBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ"
                + "GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
        String rawHex = "000102030405060708090a0b0c0d0e0f10111213141"
                + "5161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343"
                + "5363738393a3b3c3d3e3f";

        byte[] seed = TestUtils.decodeHex(rawHex);
        byte[] encoded = TestUtils.decodeBase64(pcks8Base64);

        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(seed));
        assertArrayEquals(encoded, privateKey.getEncoded());

        EncodedKeySpec encodedKeySpec =
                keyFactory.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
        assertEquals("PKCS#8", encodedKeySpec.getFormat());
        assertArrayEquals(encoded, encodedKeySpec.getEncoded());

        PrivateKey privateKey2 = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        assertArrayEquals(encoded, privateKey2.getEncoded());
        OpenSslMlKemPrivateKey mlKemPrivateKey = (OpenSslMlKemPrivateKey) privateKey2;
        assertEquals(MlKemAlgorithm.ML_KEM_1024, mlKemPrivateKey.getMlKemAlgorithm());
        assertArrayEquals(seed, mlKemPrivateKey.getSeed());
    }

    @Test
    public void mlKem768_x509TestVector_works() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM-768", conscryptProvider);

        // Example from RFC 9935, C.2
        String x509Base64 = "MIIEsjALBglghkgBZQMEBAIDggShACmKoQ1CPI3aBp0CvFnmzfA6CWuLPaTKubgM"
                + "pKFJB2cszvHsT68jSgvFt+nUc/KzEzs7JqHRdctnp4BZGWmcAvdlMbmcX4kYBwS7"
                + "TKRTXFuJcmecZgoHxeUUuHAJyGLrj1FXaV77P8QKne9rgcHMAqJJrk8JStDZvTSF"
                + "wcHGgIBSCnyMYyAyzuc4FU5cUXbAfaVgJHdqQw/nbqz2ZaP3uDIQIhW8gvEJOcg1"
                + "VwQzao+sHYHkuwSFql18dNa1m75cXpcqDYusQRtVtdVVfNaAoaj3G064a8SMmgUJ"
                + "cxpUvZ1ykLJ5Y+Q3Lcmxmc/crAsBrNKKYjlREuTENkjWIsSMgjTQFEDozDdskn8j"
                + "pa/JrAR0xmInTkJFJchVLs47P+JlFt6QG8fVFb3olVjmJslcgLkzQvgBAATznmxs"
                + "lIccXjRMqzlmyDX5qWpZr9McQChrOLHBp4RwurlHUYk0RTzoZzapGfH1ptUQqG9U"
                + "VPw5gMtcdlvSvV97NrFBDWY1yM60fE3aDXaijqyTnHHDAkgEhmxxYmZYRCFjwsIh"
                + "F+UKzvzmN4qYVlIwKk7wws4Mxxa3eW4ray43d9+hrD2iWaMbWptTD4y2OKgaYqww"
                + "GEmrr5WnMBvaMAaJCb/bfmfbzLs4pVUaJbGjoPaFdIrVdT2IgPABbGJ0hhZjhMVX"
                + "H+I2WQA2TQODEeLYdds2ZoaTK17GAkMKNp6Hpu9cM4eGZXglvUwFes65I+sJNeaQ"
                + "XmO0ztf4CFenc91ksVDSZhLqmsEgUtsgF78YQ8y0sygbaQ3HKK36hcACgbjjwJKH"
                + "M1+Fa0/CiS9povV5Ia2gGRTECYhmLVd2lmKnhjUbm2ZJPat5WU2YbeIQDWW6D/Tq"
                + "WLgVONJKRDWiWPrCVASqf0H2WLE4UGXhWNy2ARVzJyD0BFmqrBXkBpU6kKxSmX0c"
                + "zQcAYO/GXbnmUzVEZ/rVbscTyG51QMQjrPJmn1L6b0rGiI2HHvPoR8ApqKr7uS4X"
                + "skqgebH0GbphdbRCr7EZCdSla3CgM1soc5IYqnyTSOLDwvPrPRWkHmQXwN2Uv+sh"
                + "QZsxGnuxOhgLvoMyGKmmsXRHzIXyJYWVh6cwdwSay8/UTQ8CVDjhXRU4Jw1Ybhv4"
                + "MZKpRZz2PA6XL4UpdnmDHs8SFQmFHLg0D28Qew+hoO/Rs2qBibwIXE9ct4TlU/Qb"
                + "kY+AOXzhlW94W+43fKmqi+aZitowwmt8PYxrVSVMyWIDsgxCruCsTh67QI5JqeP4"
                + "edCrB4XrcCVCXRMFoimcAV4SDRY7DhlJTOVyU9AkbRgnRcuBl6t0OLPBu3lyvsWj"
                + "BuujVnhVwBRpn+9lrlTHcKDYXBhADPZCrtxmB3e6SxOFAr1aeBL2IfhKSClrmN1D"
                + "IrbxWCi4qPDgCoukSlPDqLFDVxsHQKvVZ9rxzenHnCBLbV4lnRdmoxu7y05qBc9F"
                + "AhdrMBwcL0Ekd1AVe87IXoCbMKTWDXdHzdD1uZqoyCaYdRd5OqqAgKCxJKhVjfcr"
                + "vje3X07btr6CFtbGM/srIoDiURPYaV5DSBw+6zl+sZJQUim2eiAeqJPD4ssy2ovD"
                + "QvpN6gV4";
        String rawHex = "298aa10d423c8dda069d02bc59e6cdf03a096b8b3da"
                + "4cab9b80ca4a14907672ccef1ec4faf234a0bc5b7e9d473f2b3133b3b26a1d17"
                + "5cb67a7805919699c02f76531b99c5f89180704bb4ca4535c5b8972679c660a0"
                + "7c5e514b87009c862eb8f5157695efb3fc40a9def6b81c1cc02a249ae4f094ad"
                + "0d9bd3485c1c1c68080520a7c8c632032cee738154e5c5176c07da56024776a4"
                + "30fe76eacf665a3f7b832102215bc82f10939c8355704336a8fac1d81e4bb048"
                + "5aa5d7c74d6b59bbe5c5e972a0d8bac411b55b5d5557cd680a1a8f71b4eb86bc"
                + "48c9a0509731a54bd9d7290b27963e4372dc9b199cfdcac0b01acd28a6239511"
                + "2e4c43648d622c48c8234d01440e8cc376c927f23a5afc9ac0474c662274e424"
                + "525c8552ece3b3fe26516de901bc7d515bde89558e626c95c80b93342f801000"
                + "4f39e6c6c94871c5e344cab3966c835f9a96a59afd31c40286b38b1c1a78470b"
                + "ab947518934453ce86736a919f1f5a6d510a86f5454fc3980cb5c765bd2bd5f7"
                + "b36b1410d6635c8ceb47c4dda0d76a28eac939c71c3024804866c71626658442"
                + "163c2c22117e50acefce6378a985652302a4ef0c2ce0cc716b7796e2b6b2e377"
                + "7dfa1ac3da259a31b5a9b530f8cb638a81a62ac301849abaf95a7301bda30068"
                + "909bfdb7e67dbccbb38a5551a25b1a3a0f685748ad5753d8880f0016c6274861"
                + "66384c5571fe2365900364d038311e2d875db366686932b5ec602430a369e87a"
                + "6ef5c338786657825bd4c057aceb923eb0935e6905e63b4ced7f80857a773dd6"
                + "4b150d26612ea9ac12052db2017bf1843ccb4b3281b690dc728adfa85c00281b"
                + "8e3c09287335f856b4fc2892f69a2f57921ada01914c40988662d57769662a78"
                + "6351b9b66493dab79594d986de2100d65ba0ff4ea58b81538d24a4435a258fac"
                + "25404aa7f41f658b1385065e158dcb60115732720f40459aaac15e406953a90a"
                + "c52997d1ccd070060efc65db9e653354467fad56ec713c86e7540c423acf2669"
                + "f52fa6f4ac6888d871ef3e847c029a8aafbb92e17b24aa079b1f419ba6175b44"
                + "2afb11909d4a56b70a0335b28739218aa7c9348e2c3c2f3eb3d15a41e6417c0d"
                + "d94bfeb21419b311a7bb13a180bbe833218a9a6b17447cc85f225859587a7307"
                + "7049acbcfd44d0f025438e15d1538270d586e1bf83192a9459cf63c0e972f852"
                + "97679831ecf121509851cb8340f6f107b0fa1a0efd1b36a8189bc085c4f5cb78"
                + "4e553f41b918f80397ce1956f785bee377ca9aa8be6998ada30c26b7c3d8c6b5"
                + "5254cc96203b20c42aee0ac4e1ebb408e49a9e3f879d0ab0785eb7025425d130"
                + "5a2299c015e120d163b0e19494ce57253d0246d182745cb8197ab7438b3c1bb7"
                + "972bec5a306eba3567855c014699fef65ae54c770a0d85c18400cf642aedc660"
                + "777ba4b138502bd5a7812f621f84a48296b98dd4322b6f15828b8a8f0e00a8ba"
                + "44a53c3a8b143571b0740abd567daf1cde9c79c204b6d5e259d1766a31bbbcb4"
                + "e6a05cf4502176b301c1c2f41247750157bcec85e809b30a4d60d7747cdd0f5b"
                + "99aa8c826987517793aaa8080a0b124a8558df72bbe37b75f4edbb6be8216d6c"
                + "633fb2b2280e25113d8695e43481c3eeb397eb192505229b67a201ea893c3e2c"
                + "b32da8bc342fa4dea0578";

        byte[] raw = TestUtils.decodeHex(rawHex);
        byte[] encoded = TestUtils.decodeBase64(x509Base64);

        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(raw));
        assertArrayEquals(encoded, publicKey.getEncoded());

        EncodedKeySpec encodedKeySpec = keyFactory.getKeySpec(publicKey, X509EncodedKeySpec.class);
        assertEquals("X.509", encodedKeySpec.getFormat());
        assertArrayEquals(encoded, encodedKeySpec.getEncoded());

        PublicKey publicKey2 = keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
        assertArrayEquals(encoded, publicKey2.getEncoded());
        OpenSslMlKemPublicKey mlKemPublicKey = (OpenSslMlKemPublicKey) publicKey2;
        assertEquals(MlKemAlgorithm.ML_KEM_768, mlKemPublicKey.getMlKemAlgorithm());
        assertArrayEquals(raw, mlKemPublicKey.getRaw());
    }

    @Test
    public void mlKem1024_x509TestVector_works() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM-1024", conscryptProvider);

        // Example from RFC 9935, C.2
        String x509Base64 = "MIIGMjALBglghkgBZQMEBAMDggYhAEuUwpRQERGRgjs1FMmsHqPZglzLhjk6LfsE"
                + "ZU+iGS03v60cSXxlAu7lyoCnO/zguvWlSohYWkATl6PSMvQmp6+wgrwhpEMXCQ6q"
                + "x1ksLqiKZTxEkeoZOTEzX1LpiaPEzFbZxVNzLVfEcPtBq3WbZdLQREU4L82cTjRK"
                + "ESj6nhHgQ1jhku0BSyMjKn7isi4jcX9EER7jNXU5nDdkbamBPsmyEq/pTl3FwjMK"
                + "cpTMH0I0ptP7tPFoWriJLASssXzRwXDXsGEbanF2x5TMjGf1X8kjwq0gMQDzZZkY"
                + "gsMCQ9d4E4Q7XsfJZAMiY3BgkuzwDHUWvmTkWYykImwGm7XmfkF1zyKGyN1cSIps"
                + "WGHzG6oL0CaUcOi1Ud07zTjIbBL5zbF2x33ItsAqcB9HiQLIVT9pTA2CcntMSlws"
                + "EEEhKqEnSAi4IRGzd+x1IU6bGXj3YATUE52YYT9LjpjSCve1NAc6UJqVm3p1ZPm0"
                + "DKIYv2GCkyCoUCAXlU0yjXrGx2nsKXAHVuewaFs0DV4RgFlQSkmppQoQGY6xCleE"
                + "Z460J9e0uruVUpM7BiiXlz4TGOrwoOrDdYSmVAGxcD4EKszYN1MUg/JBytzRwdN4"
                + "EZ5pRCnbGZrIkeTFNDdXCFuzrng2ZzUMRFjZdnLoYegLHSZ5UQ6jpvI2DHekaULH"
                + "oGpVTSKAgMhLR67xTbF2IMsWwGqzChvkzacIK+n4fpwhHEaRY0mluo6qUgHHKUo8"
                + "CIW1O2V0UhCIJexkbJCgRhIyTufQMa/lNDEyy+9ntu+xpewoCbdzU4znez2LBOsL"
                + "PCJWAR5McWwZqLoHUr9xSSEXZJ8GFcMpD8KaRv3kvVLbkobWAziCRCWcFaesK2QK"
                + "YMwDN2pYQaP7ikc1aPqbGiZyFfNMAWl7Dw5icXXXIQW3cHwpueYUvcM6b2yBipU3"
                + "C0J4gte0dnlqnsbrmTJ0zZsjkagrpF4zk9Lprpchyp1sG5iLWCdxP5CmWF3pQzUo"
                + "wCsDzhC7X3IBOND7tMMMEma5GOUpJd/hezf5XSK8pU9HWRmshZCYwPDQisWHXvKb"
                + "Vv0UHm7xX3AKC2bzlZXFiBdzc8RmmyG8Bx5MOqXwtKMbYljzXaJKw80px/IJJBDF"
                + "B4NVsTj7U6a5rm4LnAgkPnuqRcRzduuMfxPUz1Gqc2+jFUDJJB83DaVEv5+cKNml"
                + "fi8qfKlaTktGbmQas7zHat8ROdVnpvErUvOmXn7AquJryqjFWDOwTlmZjryaGTD7"
                + "ttIjPFPSwfi5UY48Lec6Gd7ms4Clsylxz2ThKf1sH6bnXUojRQHpZt06VAr1yPTz"
                + "SmtKJT7ihJJWbV5nxvVYVfywUG+wbBVnRNmgOjGib6lMrRTxV7fzA9B6acdzdo/L"
                + "TQecCQWXA6DDqU3kuZ6jovFlg9D5Fwo5UNsHtPC8MIApJ/n3lhtiWYkmNqlQKicF"
                + "MDY3eZ3TRNpFHBz3v2eEDOsweauMa4wZJ/ZAU8YSRQxFyeYDvBZmbllrNHHhA7bx"
                + "VEdCTRcCIEgRH/vTfhxnD2TxS4p7MrlMGkm0XdL8OM1SidkQrWNgLPXhMELGSsZ5"
                + "e4n7VRrQjgWpLSAMzLfnEu8jyTEss1DwKatTfihzR/0wdawQkGp4PxxsB8y4j0Ei"
                + "jEvhxkD3kLXDpdXTynkklddLxGFWJljAesYAJ2uSSrW8m+HwSUy3b4L0YKdICXJm"
                + "M4HhaZlgYdeZhZ7FTU9cpcQRwB2xWXsWWXdmneE6koo0r7rCWP6oxHZCOclCHcMR"
                + "m/W0dpkgaXgyexxTRe90anmDhB8FbiU0EAqyTU6au9CxfGqVvUw8DkD2nhYSrO6y"
                + "i5kIbJURbnIEJziTOQv0a4mbNihrDr8ZR7uYhPcyyifagrGbXcDMf4iFcUkQiIsj"
                + "EMT5MZ1BCzTmQzuQA+IXa7mVJXRWEG6JUhY7i6WSUwzFqgrrQ605j+npe6pSPXpE"
                + "MWd8PTrwcZ5HXbhcqVr1CJvqvrBbL6q0iWumD4HIhHKle0aoKIJqDN+0RvgYkYLS"
                + "v16sTsHMXer1mcihPkgjVAbRf/3cg0S2xmmEqGiqkvoCInoIaVDrDIcB7VjcYod2"
                + "uYOILhF1";
        String rawHex = "4b94c29450111191823b3514c9ac1ea3d9825ccb863"
                + "93a2dfb04654fa2192d37bfad1c497c6502eee5ca80a73bfce0baf5a54a88585"
                + "a401397a3d232f426a7afb082bc21a44317090eaac7592c2ea88a653c4491ea1"
                + "93931335f52e989a3c4cc56d9c553732d57c470fb41ab759b65d2d04445382fc"
                + "d9c4e344a1128fa9e11e04358e192ed014b23232a7ee2b22e23717f44111ee33"
                + "575399c37646da9813ec9b212afe94e5dc5c2330a7294cc1f4234a6d3fbb4f16"
                + "85ab8892c04acb17cd1c170d7b0611b6a7176c794cc8c67f55fc923c2ad20310"
                + "0f365991882c30243d77813843b5ec7c964032263706092ecf00c7516be64e45"
                + "98ca4226c069bb5e67e4175cf2286c8dd5c488a6c5861f31baa0bd0269470e8b"
                + "551dd3bcd38c86c12f9cdb176c77dc8b6c02a701f478902c8553f694c0d82727"
                + "b4c4a5c2c1041212aa1274808b82111b377ec75214e9b1978f76004d4139d986"
                + "13f4b8e98d20af7b534073a509a959b7a7564f9b40ca218bf61829320a850201"
                + "7954d328d7ac6c769ec29700756e7b0685b340d5e118059504a49a9a50a10198"
                + "eb10a5784678eb427d7b4babb9552933b062897973e1318eaf0a0eac37584a65"
                + "401b1703e042accd837531483f241cadcd1c1d378119e694429db199ac891e4c"
                + "5343757085bb3ae783667350c4458d97672e861e80b1d2679510ea3a6f2360c7"
                + "7a46942c7a06a554d228080c84b47aef14db17620cb16c06ab30a1be4cda7082"
                + "be9f87e9c211c46916349a5ba8eaa5201c7294a3c0885b53b657452108825ec6"
                + "46c90a04612324ee7d031afe5343132cbef67b6efb1a5ec2809b773538ce77b3"
                + "d8b04eb0b3c2256011e4c716c19a8ba0752bf71492117649f0615c3290fc29a4"
                + "6fde4bd52db9286d603388244259c15a7ac2b640a60cc03376a5841a3fb8a473"
                + "568fa9b1a267215f34c01697b0f0e627175d72105b7707c29b9e614bdc33a6f6"
                + "c818a95370b427882d7b476796a9ec6eb993274cd9b2391a82ba45e3393d2e9a"
                + "e9721ca9d6c1b988b5827713f90a6585de9433528c02b03ce10bb5f720138d0f"
                + "bb4c30c1266b918e52925dfe17b37f95d22bca54f475919ac859098c0f0d08ac"
                + "5875ef29b56fd141e6ef15f700a0b66f39595c588177373c4669b21bc071e4c3"
                + "aa5f0b4a31b6258f35da24ac3cd29c7f2092410c5078355b138fb53a6b9ae6e0"
                + "b9c08243e7baa45c47376eb8c7f13d4cf51aa736fa31540c9241f370da544bf9"
                + "f9c28d9a57e2f2a7ca95a4e4b466e641ab3bcc76adf1139d567a6f12b52f3a65"
                + "e7ec0aae26bcaa8c55833b04e59998ebc9a1930fbb6d2233c53d2c1f8b9518e3"
                + "c2de73a19dee6b380a5b32971cf64e129fd6c1fa6e75d4a234501e966dd3a540"
                + "af5c8f4f34a6b4a253ee28492566d5e67c6f55855fcb0506fb06c156744d9a03"
                + "a31a26fa94cad14f157b7f303d07a69c773768fcb4d079c09059703a0c3a94de"
                + "4b99ea3a2f16583d0f9170a3950db07b4f0bc30802927f9f7961b6259892636a"
                + "9502a2705303637799dd344da451c1cf7bf67840ceb3079ab8c6b8c1927f6405"
                + "3c612450c45c9e603bc16666e596b3471e103b6f15447424d17022048111ffbd"
                + "37e1c670f64f14b8a7b32b94c1a49b45dd2fc38cd5289d910ad63602cf5e1304"
                + "2c64ac6797b89fb551ad08e05a92d200cccb7e712ef23c9312cb350f029ab537"
                + "e287347fd3075ac10906a783f1c6c07ccb88f41228c4be1c640f790b5c3a5d5d"
                + "3ca792495d74bc461562658c07ac600276b924ab5bc9be1f0494cb76f82f460a"
                + "7480972663381e169996061d799859ec54d4f5ca5c411c01db1597b165977669"
                + "de13a928a34afbac258fea8c4764239c9421dc3119bf5b47699206978327b1c5"
                + "345ef746a7983841f056e2534100ab24d4e9abbd0b17c6a95bd4c3c0e40f69e1"
                + "612aceeb28b99086c95116e7204273893390bf46b899b36286b0ebf1947bb988"
                + "4f732ca27da82b19b5dc0cc7f8885714910888b2310c4f9319d410b34e6433b9"
                + "003e2176bb995257456106e8952163b8ba592530cc5aa0aeb43ad398fe9e97ba"
                + "a523d7a4431677c3d3af0719e475db85ca95af5089beabeb05b2faab4896ba60"
                + "f81c88472a57b46a828826a0cdfb446f8189182d2bf5eac4ec1cc5deaf599c8a"
                + "13e48235406d17ffddc8344b6c66984a868aa92fa02227a086950eb0c8701ed5"
                + "8dc628776b983882e1175";

        byte[] raw = TestUtils.decodeHex(rawHex);
        byte[] encoded = TestUtils.decodeBase64(x509Base64);

        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(raw));
        assertArrayEquals(encoded, publicKey.getEncoded());

        EncodedKeySpec encodedKeySpec = keyFactory.getKeySpec(publicKey, X509EncodedKeySpec.class);
        assertEquals("X.509", encodedKeySpec.getFormat());
        assertArrayEquals(encoded, encodedKeySpec.getEncoded());

        PublicKey publicKey2 = keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
        assertArrayEquals(encoded, publicKey2.getEncoded());
        OpenSslMlKemPublicKey mlKemPublicKey = (OpenSslMlKemPublicKey) publicKey2;
        assertEquals(MlKemAlgorithm.ML_KEM_1024, mlKemPublicKey.getMlKemAlgorithm());
        assertArrayEquals(raw, mlKemPublicKey.getRaw());
    }

    @Test
    public void sealAndOpen_mlkem768_works() throws Exception {
        byte[] info = TestUtils.decodeHex("aa");
        byte[] plaintext = TestUtils.decodeHex("bb");
        byte[] aad = TestUtils.decodeHex("cc");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-KEM-768", conscryptProvider);
        KeyPair keyPairRecipient = keyGen.generateKeyPair();

        for (int aead : new int[] {AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_CHACHA20POLY1305}) {
            HpkeSuite suite = new HpkeSuite(KEM_MLKEM_768, KDF_HKDF_SHA256, aead);

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
    public void sealAndOpen_mlkem1024_works() throws Exception {
        byte[] info = TestUtils.decodeHex("aa");
        byte[] plaintext = TestUtils.decodeHex("bb");
        byte[] aad = TestUtils.decodeHex("cc");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-KEM-1024", conscryptProvider);
        KeyPair keyPairRecipient = keyGen.generateKeyPair();

        for (int aead : new int[] {AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_CHACHA20POLY1305}) {
            HpkeSuite suite = new HpkeSuite(KEM_MLKEM_1024, KDF_HKDF_SHA256, aead);

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
    public void wrongInfoORAad_fails() throws Exception {
        byte[] info = TestUtils.decodeHex("aa");
        byte[] plaintext = TestUtils.decodeHex("bb");
        byte[] aad = TestUtils.decodeHex("cc");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-KEM-768", conscryptProvider);
        KeyPair keyPairRecipient = keyGen.generateKeyPair();

        String hpkeAlgorithm = "MLKEM_768/HKDF_SHA256/AES_128_GCM";

        HpkeContextSender ctxSender =
                HpkeContextSender.getInstance(hpkeAlgorithm, conscryptProvider);
        ctxSender.init(keyPairRecipient.getPublic(), info);

        byte[] encapsulated = ctxSender.getEncapsulated();
        byte[] ciphertext = ctxSender.seal(plaintext, aad);

        HpkeContextRecipient contextRecipient =
                HpkeContextRecipient.getInstance(hpkeAlgorithm, conscryptProvider);
        contextRecipient.init(encapsulated, keyPairRecipient.getPrivate(), info);

        // with correct info and aad, it works.
        assertArrayEquals(plaintext, contextRecipient.open(ciphertext, aad));

        // with correct info and wrong aad, it fails.
        assertThrows(GeneralSecurityException.class,
                     () -> contextRecipient.open(ciphertext, TestUtils.decodeHex("ff")));

        // with wrong info and correct aad, it fails.
        HpkeContextRecipient contextRecipient2 =
                HpkeContextRecipient.getInstance(hpkeAlgorithm, conscryptProvider);
        contextRecipient2.init(encapsulated, keyPairRecipient.getPrivate(),
                               TestUtils.decodeHex("ff"));
        assertThrows(GeneralSecurityException.class, () -> contextRecipient2.open(ciphertext, aad));
    }

    @Test
    public void hpkeContextRecipient_openTestVectors_works() throws Exception {
        List<TestVector> vectors = TestUtils.readTestVectors("crypto/mlkem.txt");

        for (TestVector vector : vectors) {
            String keyAlgorithm = vector.getString("key-algorithm");
            String hpkeAlgorithm = vector.getString("hpke-algorithm");
            byte[] info = vector.getBytes("info");
            byte[] pk = vector.getBytes("pk");
            byte[] sk = vector.getBytes("sk");
            byte[] enc = vector.getBytes("enc");
            byte[] ct = vector.getBytes("ct");
            byte[] pt = vector.getBytes("pt");
            byte[] aad = vector.getBytes("aad");

            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm, conscryptProvider);
            PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(sk));
            PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(pk));

            // Open enc/ct pair from test vector.
            HpkeContextRecipient ctxRecipient =
                    HpkeContextRecipient.getInstance(hpkeAlgorithm, conscryptProvider);

            ctxRecipient.init(enc, privateKey, info);
            byte[] decrypted = ctxRecipient.open(ct, aad);

            assertArrayEquals(pt, decrypted);

            // Create new enc/ct pair and open it.
            HpkeContextSender ctxSender =
                    HpkeContextSender.getInstance(hpkeAlgorithm, conscryptProvider);
            ctxSender.init(publicKey, info);

            byte[] enc2 = ctxSender.getEncapsulated();
            byte[] ct2 = ctxSender.seal(pt, aad);

            HpkeContextRecipient contextRecipient =
                    HpkeContextRecipient.getInstance(hpkeAlgorithm, conscryptProvider);
            contextRecipient.init(enc2, privateKey, info);
            byte[] output = contextRecipient.open(ct2, aad);

            assertArrayEquals(pt, output);
        }
    }

    @Test
    public void serialize_throwsUnsupportedOperationException() throws Exception {
        for (String algorithm : new String[] {"ML-KEM", "ML-KEM-768", "ML-KEM-1024"}) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm, conscryptProvider);
            KeyPair keyPair = keyGen.generateKeyPair();

            ObjectOutputStream oos = new ObjectOutputStream(new ByteArrayOutputStream(16384));
            PrivateKey privateKey = keyPair.getPrivate();
            assertThrows(UnsupportedOperationException.class, () -> oos.writeObject(privateKey));
            PublicKey publicKey = keyPair.getPublic();
            assertThrows(UnsupportedOperationException.class, () -> oos.writeObject(publicKey));
        }
    }
}
