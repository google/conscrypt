/*
 * Copyright 2026 The Android Open Source Project
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

import static org.conscrypt.TestUtils.UTF_8;
import static org.conscrypt.TestUtils.decodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@RunWith(JUnit4.class)
public class OpenSSLCipherTest {
    private static final Provider CONSCRYPT_PROVIDER = TestUtils.getConscryptProvider();

    // Fixed keys: bytes 0x00..0x0f (16B), 0x00..0x17 (24B), 0x00..0x1f (32B)
    private static final byte[] key16 = decodeHex("000102030405060708090a0b0c0d0e0f");
    private static final byte[] key24 =
            decodeHex("000102030405060708090a0b0c0d0e0f1011121314151617");
    private static final byte[] key32 =
            decodeHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    // Fixed IVs: 16B (0x10..0x1f), 12B (0x20..0x2b), 8B (0x2c..0x33), 24B (0x20..0x37)
    private static final byte[] iv16 = decodeHex("101112131415161718191a1b1c1d1e1f");
    private static final byte[] iv12 = decodeHex("202122232425262728292a2b");
    private static final byte[] iv8 = decodeHex("2c2d2e2f30313233");
    private static final byte[] iv24 =
            decodeHex("202122232425262728292a2b2c2d2e2f3031323334353637");

    // Expected plaintexts
    private static final byte[] plaintext16 = "0123456789abcdef".getBytes(UTF_8);
    private static final byte[] plaintext8 = "01234567".getBytes(UTF_8);
    private static final byte[] plaintextVar = "Hello, Conscrypt!".getBytes(UTF_8);

    // Hard-coded ciphertexts for the fixed keys, IVs, and plaintexts above
    private static final byte[] ciphertextAes128EcbNopad =
            decodeHex("281567ab2f4cf0d73d3198225b8b8393");
    private static final byte[] ciphertextAes192EcbNopad =
            decodeHex("d2a70d53d18493c560e5a1d505d2e23c");
    private static final byte[] ciphertextAes256EcbNopad =
            decodeHex("d8c95758e3353e530fa52bd10e73b986");

    private static final byte[] ciphertextAes128EcbPkcs5 =
            decodeHex("bd361e6a4c0aad7f724ce34310305771ec19c77a6de4cfedcef118e23f0be27e");
    private static final byte[] ciphertextAes192EcbPkcs5 =
            decodeHex("eca30916505a875a67f365f9c030be1bb4e5f73fbc7baf5aa9f913480e3a975b");
    private static final byte[] ciphertextAes256EcbPkcs5 =
            decodeHex("bb6e3ec15f5fbf3eeba5ec6edd0368c2caef675bce76924d1d7aa70dc1b15f34");

    private static final byte[] ciphertextAes128CbcNopad =
            decodeHex("eb9e5ba41b902db8252982aa1a23f4be");
    private static final byte[] ciphertextAes192CbcNopad =
            decodeHex("93c788f330932c697cd70aa68bd01a82");
    private static final byte[] ciphertextAes256CbcNopad =
            decodeHex("879adb94b99e35f6f6d9680548bb71d1");

    private static final byte[] ciphertextAes128CbcPkcs5 =
            decodeHex("bdff9f646b327909d89267efd062f844d57589515c4a97189d78ef2901acc071");
    private static final byte[] ciphertextAes192CbcPkcs5 =
            decodeHex("477fbc72b2d1dadd9d962737faee163d9b129ca32386828e9fdd02c2bfbd70c9");
    private static final byte[] ciphertextAes256CbcPkcs5 =
            decodeHex("c24df64088a8441e87c748ed9293c7061284b1838bb245320fbcd960da04c891");

    private static final byte[] ciphertextAes128CtrNopad =
            decodeHex("4f9b83188ef9232dff609d72fcede2e7b3");
    private static final byte[] ciphertextAes192CtrNopad =
            decodeHex("dbcb5713f0eec856f26bd5ca879b3f59da");
    private static final byte[] ciphertextAes256CtrNopad =
            decodeHex("a1a683e6dd1873a59f1aefb5449ed8fad8");

    private static final byte[] ciphertextDesede16CbcNopad = decodeHex("455d5301f20d180d");
    private static final byte[] ciphertextDesede24CbcNopad = decodeHex("61935a9f5bf72b04");
    private static final byte[] ciphertextDesede16CbcPkcs5 =
            decodeHex("c843bbb8630bb60e883242edce272b2aa1bd606dbae4fafc");
    private static final byte[] ciphertextDesede24CbcPkcs5 =
            decodeHex("5997754a0f569a40c3a6dcd73a0ec591bf09d61f4a452b78");

    private static final byte[] ciphertextArc4 = decodeHex("a1f92c9528ce398f69b5e4a57ca45a3bf2");

    private static final byte[] ciphertextAes128Gcm =
            decodeHex("88907ec8e9dc594ad426fcb703b6e40ae91eca5c8447a37c278cbc032780714159");
    private static final byte[] ciphertextAes256Gcm =
            decodeHex("9a5fca1c03b43a4d751231adb361848df194f008dd6916e85e10d81b12f2d14173");

    private static final byte[] ciphertextAes128GcmSiv =
            decodeHex("5bc107b4d1677192bbc5fa7fdab0b29731b96f294a81f90477361fb67713955848");
    private static final byte[] ciphertextAes256GcmSiv =
            decodeHex("6d8732d6258aae69bd2115e0d101da7f8d9bdd2a4dcaf960011b7c6492fd935c4c");

    private static final byte[] ciphertextChaCha20 =
            decodeHex("dbb73b8876f6da1d59a5fca3bd41efe411");
    private static final byte[] ciphertextChaCha20Poly1305 =
            decodeHex("3b82e4107ec3dc79f4abdeab3b46ffcc5a3ee281de608eecdc42b24c97abde66c4");
    private static final byte[] ciphertextXChaCha20Poly1305 =
            decodeHex("553c21a7141b34c857d023de3a3e71a51c8b62ec80526aaffea5e4f457dd9f59f7");

    @BeforeClass
    public static void setUp() {
        TestUtils.assumeAllowsUnsignedCrypto();
    }

    private static void assertDecryptsToExpectedPlaintext(
            String transformation, String keyAlg, byte[] keyBytes, AlgorithmParameterSpec paramSpec,
            byte[] ciphertext, byte[] expectedPlaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation, CONSCRYPT_PROVIDER);
        assertEquals(CONSCRYPT_PROVIDER, cipher.getProvider());
        SecretKey key = new SecretKeySpec(keyBytes, keyAlg);
        if (paramSpec == null) {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
        }
        byte[] decrypted = cipher.doFinal(ciphertext);
        assertArrayEquals(expectedPlaintext, decrypted);
    }

    private static void assertRejectsKey(String transformation, String keyAlg, byte[] keyBytes,
                                         AlgorithmParameterSpec paramSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation, CONSCRYPT_PROVIDER);
        assertEquals(CONSCRYPT_PROVIDER, cipher.getProvider());
        SecretKey key = new SecretKeySpec(keyBytes, keyAlg);
        if (paramSpec == null) {
            assertThrows(InvalidKeyException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, key));
            assertThrows(InvalidKeyException.class, () -> cipher.init(Cipher.DECRYPT_MODE, key));
        } else {
            assertThrows(InvalidKeyException.class,
                         () -> cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec));
            assertThrows(InvalidKeyException.class,
                         () -> cipher.init(Cipher.DECRYPT_MODE, key, paramSpec));
        }
    }

    // =========================================================================
    // 1. Cipher.getInstance + Hard-coded Ciphertext Decryption Tests
    //    for all symmetric cipher algorithms and aliases in OpenSSLProvider
    // =========================================================================

    @Test
    public void decrypt_aesEcbNoPadding() throws Exception {
        assertDecryptsToExpectedPlaintext("AES/ECB/NoPadding", "AES", key16, null,
                                          ciphertextAes128EcbNopad, plaintext16);
        assertDecryptsToExpectedPlaintext("AES/ECB/NoPadding", "AES", key24, null,
                                          ciphertextAes192EcbNopad, plaintext16);
        assertDecryptsToExpectedPlaintext("AES/ECB/NoPadding", "AES", key32, null,
                                          ciphertextAes256EcbNopad, plaintext16);
        assertDecryptsToExpectedPlaintext("Aes/EcB/noPadDing", "aEs", key32, null,
                                          ciphertextAes256EcbNopad, plaintext16);
    }

    @Test
    public void decrypt_aesEcbPkcs5Padding_andAliases() throws Exception {
        for (String transformation : new String[] {"AES/ECB/PKCS5Padding", "AES/ECB/PKCS7Padding",
                                                   "Aes/EcB/pkcs5Padding"}) {
            assertDecryptsToExpectedPlaintext(transformation, "AES", key16, null,
                                              ciphertextAes128EcbPkcs5, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "AES", key24, null,
                                              ciphertextAes192EcbPkcs5, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "AES", key32, null,
                                              ciphertextAes256EcbPkcs5, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "aEs", key16, null,
                                              ciphertextAes128EcbPkcs5, plaintextVar);
        }
    }

    @Test
    public void decrypt_aesCbcNoPadding() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv16);
        assertDecryptsToExpectedPlaintext("AES/CBC/NoPadding", "AES", key16, iv,
                                          ciphertextAes128CbcNopad, plaintext16);
        assertDecryptsToExpectedPlaintext("AES/CBC/NoPadding", "AES", key24, iv,
                                          ciphertextAes192CbcNopad, plaintext16);
        assertDecryptsToExpectedPlaintext("AES/CBC/NoPadding", "AES", key32, iv,
                                          ciphertextAes256CbcNopad, plaintext16);
        assertDecryptsToExpectedPlaintext("Aes/CbC/noPadding", "aEs", key32, iv,
                                          ciphertextAes256CbcNopad, plaintext16);
    }

    @Test
    public void decrypt_aesCbcPkcs5Padding_andAliases() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv16);
        for (String transformation : new String[] {"AES/CBC/PKCS5Padding", "AES/CBC/PKCS7Padding",
                                                   "Aes/CbC/pkcs5Padding"}) {
            assertDecryptsToExpectedPlaintext(transformation, "AES", key16, iv,
                                              ciphertextAes128CbcPkcs5, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "AES", key24, iv,
                                              ciphertextAes192CbcPkcs5, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "AES", key32, iv,
                                              ciphertextAes256CbcPkcs5, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "aEs", key16, iv,
                                              ciphertextAes128CbcPkcs5, plaintextVar);
        }
    }

    @Test
    public void decrypt_aesCtrNoPadding() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv16);
        assertDecryptsToExpectedPlaintext("AES/CTR/NoPadding", "AES", key16, iv,
                                          ciphertextAes128CtrNopad, plaintextVar);
        assertDecryptsToExpectedPlaintext("AES/CTR/NoPadding", "AES", key24, iv,
                                          ciphertextAes192CtrNopad, plaintextVar);
        assertDecryptsToExpectedPlaintext("AES/CTR/NoPadding", "AES", key32, iv,
                                          ciphertextAes256CtrNopad, plaintextVar);
        assertDecryptsToExpectedPlaintext("aEs/CtR/noPadding", "aEs", key32, iv,
                                          ciphertextAes256CtrNopad, plaintextVar);
    }

    @Test
    public void decrypt_aes128EcbNoPadding() throws Exception {
        assertDecryptsToExpectedPlaintext("AES_128/ECB/NoPadding", "AES", key16, null,
                                          ciphertextAes128EcbNopad, plaintext16);
        assertDecryptsToExpectedPlaintext("aEs_128/EcB/noPadding", "aEs", key16, null,
                                          ciphertextAes128EcbNopad, plaintext16);
    }

    @Test
    public void decrypt_aes128EcbPkcs5Padding_andAliases() throws Exception {
        for (String transformation :
             new String[] {"AES_128/ECB/PKCS5Padding", "AES_128/ECB/PKCS7Padding",
                           "aEs_128/EcB/pkcs5Padding"}) {
            assertDecryptsToExpectedPlaintext(transformation, "AES", key16, null,
                                              ciphertextAes128EcbPkcs5, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "aEs", key16, null,
                                              ciphertextAes128EcbPkcs5, plaintextVar);
        }
    }

    @Test
    public void decrypt_aes128CbcNoPadding() throws Exception {
        assertDecryptsToExpectedPlaintext("AES_128/CBC/NoPadding", "AES", key16,
                                          new IvParameterSpec(iv16), ciphertextAes128CbcNopad,
                                          plaintext16);
        assertDecryptsToExpectedPlaintext("aEs_128/CbC/noPadding", "aEs", key16,
                                          new IvParameterSpec(iv16), ciphertextAes128CbcNopad,
                                          plaintext16);
    }

    @Test
    public void decrypt_aes128CbcPkcs5Padding_andAliases() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv16);
        String[] transformations = {
                "AES_128/CBC/PKCS5Padding",
                "AES_128/CBC/PKCS7Padding",
                "PBEWithHmacSHA1AndAES_128",
                "PBEWithHmacSHA224AndAES_128",
                "PBEWithHmacSHA256AndAES_128",
                "PBEWithHmacSHA384AndAES_128",
                "PBEWithHmacSHA512AndAES_128",
                "aEs_128/cbc/pkcs5Padding",
                // Adding Mode and padding to alias also works.
                "PBEWithHmacSHA1AndAES_128/CBC/PKCS5Padding",
                "pbeWithHmacSHA1AndAES_128/cbc/pkcs5Padding",

        };
        for (String transformation : transformations) {
            assertDecryptsToExpectedPlaintext(transformation, "AES", key16, iv,
                                              ciphertextAes128CbcPkcs5, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "aEs", key16, iv,
                                              ciphertextAes128CbcPkcs5, plaintextVar);
        }
    }

    @Test
    public void decrypt_pbeWithHmacSHA1AndAES128_withEcbMode() throws Exception {
        // PBEWithHmacSHA1AndAES_128 is an alias for AES_128/CBC/PKCS5PADDING, but
        // the Cipher.getInstance allows to use a different mode/padding. So
        // PBEWithHmacSHA1AndAES_128/ECB/PKCS5Padding is an alias for
        // AES_128/ECB/PKCS5Padding and PBEWithHmacSHA1AndAES_128/ECB/NoPadding is an alias for
        // AES_128/ECB/NoPadding.
        assertDecryptsToExpectedPlaintext("PBEWithHmacSHA1AndAES_128/ECB/PKCS5Padding", "AES",
                                          key16, null, ciphertextAes128EcbPkcs5, plaintextVar);
        assertDecryptsToExpectedPlaintext("PBEWithHmacSHA1AndAES_128/ECB/PKCS7Padding", "AES",
                                          key16, null, ciphertextAes128EcbPkcs5, plaintextVar);
        assertDecryptsToExpectedPlaintext("PBEWithHmacSHA1AndAES_128/ECB/NoPadding", "AES",
                                          key16, null, ciphertextAes128EcbNopad, plaintext16);
        assertDecryptsToExpectedPlaintext("pbeWithHmacSHA1AndAES_128/ecb/pkcs5Padding", "aEs",
                                          key16, null, ciphertextAes128EcbPkcs5, plaintextVar);
        assertDecryptsToExpectedPlaintext("pbeWithHmacSHA1AndAES_128/ecb/nopadding", "aEs",
                                          key16, null, ciphertextAes128EcbNopad, plaintext16);
    }

    @Test
    public void decrypt_aes256EcbNoPadding() throws Exception {
        assertDecryptsToExpectedPlaintext("AES_256/ECB/NoPadding", "AES", key32, null,
                                          ciphertextAes256EcbNopad, plaintext16);
        assertDecryptsToExpectedPlaintext("aEs_256/EcB/noPadding", "aEs", key32, null,
                                          ciphertextAes256EcbNopad, plaintext16);
    }

    @Test
    public void decrypt_aes256EcbPkcs5Padding_andAliases() throws Exception {
        for (String transformation :
             new String[] {"AES_256/ECB/PKCS5Padding", "AES_256/ECB/PKCS7Padding",
                           "aEs_256/EcB/pkcs5Padding"}) {
            assertDecryptsToExpectedPlaintext(transformation, "AES", key32, null,
                                              ciphertextAes256EcbPkcs5, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "aEs", key32, null,
                                              ciphertextAes256EcbPkcs5, plaintextVar);
        }
    }

    @Test
    public void decrypt_aes256CbcNoPadding() throws Exception {
        assertDecryptsToExpectedPlaintext("AES_256/CBC/NoPadding", "AES", key32,
                                          new IvParameterSpec(iv16), ciphertextAes256CbcNopad,
                                          plaintext16);
        assertDecryptsToExpectedPlaintext("aEs_256/CbC/noPadding", "aEs", key32,
                                          new IvParameterSpec(iv16), ciphertextAes256CbcNopad,
                                          plaintext16);
    }

    @Test
    public void decrypt_aes256CbcPkcs5Padding_andAliases() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv16);
        String[] transformations = {"AES_256/CBC/PKCS5Padding", "AES_256/CBC/PKCS7Padding",
                                    "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_256",
                                    "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_256",
                                    "PBEWithHmacSHA512AndAES_256", "aEs_256/cbc/pkcs5Padding",
                                    // Adding Mode and padding to alias also works.
                                    "PBEWithHmacSHA1AndAES_256/CBC/PKCS5Padding",
                                    "pbeWithHmacSHA1AndAES_256/cbc/pkcs5Padding"};
        for (String transformation : transformations) {
            assertDecryptsToExpectedPlaintext(transformation, "AES", key32, iv,
                                              ciphertextAes256CbcPkcs5, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "aEs", key32, iv,
                                              ciphertextAes256CbcPkcs5, plaintextVar);
        }
    }

    @Test
    public void decrypt_pbeWithHmacSHA1AndAES256_withEcbMode() throws Exception {
        // PBEWithHmacSHA1AndAES_256 is an alias for AES_256/CBC/PKCS5PADDING, but
        // the Cipher.getInstance allows to use a different mode/padding.
        assertDecryptsToExpectedPlaintext("PBEWithHmacSHA1AndAES_256/ECB/PKCS5Padding", "AES",
                                          key32, null, ciphertextAes256EcbPkcs5, plaintextVar);
    }

    @Test
    public void decrypt_desedeCbcNoPadding() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv8);
        assertDecryptsToExpectedPlaintext("DESEDE/CBC/NoPadding", "DESEDE", key16, iv,
                                          ciphertextDesede16CbcNopad, plaintext8);
        assertDecryptsToExpectedPlaintext("DESEDE/CBC/NoPadding", "DESEDE", key24, iv,
                                          ciphertextDesede24CbcNopad, plaintext8);
    }

    @Test
    public void decrypt_desedeCbcPkcs5Padding_andAliases() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv8);
        for (String transformation :
             new String[] {"DESEDE/CBC/PKCS5Padding", "DESEDE/CBC/PKCS7Padding"}) {
            assertDecryptsToExpectedPlaintext(transformation, "DESEDE", key16, iv,
                                              ciphertextDesede16CbcPkcs5, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "DESEDE", key24, iv,
                                              ciphertextDesede24CbcPkcs5, plaintextVar);
        }
    }

    @Test
    public void decrypt_arc4_andAliases() throws Exception {
        String[] transformations = {
                "ARC4",
                "ARCFOUR",
                "RC4",
                "1.2.840.113549.3.4",
                "OID.1.2.840.113549.3.4",
                "aRc4",
                "arcFour",
                "rC4",
                // Adding Mode and padding to alias also works.
                "ARC4/NONE/NoPadding",
                "ARCFOUR/ECB/NoPadding",
                "RC4/NONE/NoPadding",
                "1.2.840.113549.3.4/NONE/NoPadding",
                "OID.1.2.840.113549.3.4/ECB/NoPadding",
        };
        for (String transformation : transformations) {
            assertDecryptsToExpectedPlaintext(transformation, "ARC4", key16, null, ciphertextArc4,
                                              plaintextVar);
        }
    }

    @Test
    public void decrypt_aesGcmNoPadding_andAliases() throws Exception {
        GCMParameterSpec spec = new GCMParameterSpec(128, iv12);
        String[] transformations = {
                "AES/GCM/NoPadding",
                "GCM",
                "aEs/gcm/noPadDing",
                "gcM",
                // OIDs for AES-128-GCM, AES-192-GCM and AES-192-GCM.
                // But they all accept 16-byte and 32-byte keys, but not 24-byte keys.
                "2.16.840.1.101.3.4.1.6",
                "2.16.840.1.101.3.4.1.26",
                "2.16.840.1.101.3.4.1.46",
                // Adding Mode and padding to alias also works.
                "GCM/GCM/NoPadding",
                "gcm/gcm/nopadding",
                "2.16.840.1.101.3.4.1.6/GCM/NoPadding",
                "2.16.840.1.101.3.4.1.26/GCM/NoPadding",
                "2.16.840.1.101.3.4.1.46/GCM/NoPadding",
        };
        for (String transformation : transformations) {
            assertDecryptsToExpectedPlaintext(transformation, "AES", key16, spec,
                                              ciphertextAes128Gcm, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "AES", key32, spec,
                                              ciphertextAes256Gcm, plaintextVar);
        }
    }

    @Test
    public void decrypt_aes128GcmNoPadding() throws Exception {
        assertDecryptsToExpectedPlaintext("AES_128/GCM/NoPadding", "AES", key16,
                                          new GCMParameterSpec(128, iv12), ciphertextAes128Gcm,
                                          plaintextVar);
    }

    @Test
    public void decrypt_aes256GcmNoPadding() throws Exception {
        assertDecryptsToExpectedPlaintext("AES_256/GCM/NoPadding", "AES", key32,
                                          new GCMParameterSpec(128, iv12), ciphertextAes256Gcm,
                                          plaintextVar);
        assertDecryptsToExpectedPlaintext("aEs_256/gcm/noPadding", "aEs", key32,
                                          new GCMParameterSpec(128, iv12), ciphertextAes256Gcm,
                                          plaintextVar);
    }

    @Test
    public void decrypt_aesGcmSivNoPadding() throws Exception {
        GCMParameterSpec spec = new GCMParameterSpec(128, iv12);
        assertDecryptsToExpectedPlaintext("AES/GCM-SIV/NoPadding", "AES", key16, spec,
                                          ciphertextAes128GcmSiv, plaintextVar);
        assertDecryptsToExpectedPlaintext("AES/GCM-SIV/NoPadding", "AES", key32, spec,
                                          ciphertextAes256GcmSiv, plaintextVar);
        assertDecryptsToExpectedPlaintext("aEs/gcm-siv/noPadding", "aEs", key16, spec,
                                          ciphertextAes128GcmSiv, plaintextVar);
        assertDecryptsToExpectedPlaintext("aEs/gcm-siv/noPadding", "aEs", key32, spec,
                                          ciphertextAes256GcmSiv, plaintextVar);
    }

    @Test
    public void decrypt_aes128GcmSivNoPadding() throws Exception {
        assertDecryptsToExpectedPlaintext("AES_128/GCM-SIV/NoPadding", "AES", key16,
                                          new GCMParameterSpec(128, iv12), ciphertextAes128GcmSiv,
                                          plaintextVar);
        assertDecryptsToExpectedPlaintext("aEs_128/gcm-siv/noPadding", "aEs", key16,
                                          new GCMParameterSpec(128, iv12), ciphertextAes128GcmSiv,
                                          plaintextVar);
    }

    @Test
    public void decrypt_aes256GcmSivNoPadding() throws Exception {
        assertDecryptsToExpectedPlaintext("AES_256/GCM-SIV/NoPadding", "AES", key32,
                                          new GCMParameterSpec(128, iv12), ciphertextAes256GcmSiv,
                                          plaintextVar);
        assertDecryptsToExpectedPlaintext("aEs_256/gcm-siv/noPadding", "aEs", key32,
                                          new GCMParameterSpec(128, iv12), ciphertextAes256GcmSiv,
                                          plaintextVar);
    }

    @Test
    public void decrypt_chaCha20() throws Exception {
        assertDecryptsToExpectedPlaintext("ChaCha20", "ChaCha20", key32, new IvParameterSpec(iv12),
                                          ciphertextChaCha20, plaintextVar);
        assertDecryptsToExpectedPlaintext("cHaCha20", "cHaCha20", key32, new IvParameterSpec(iv12),
                                          ciphertextChaCha20, plaintextVar);
    }

    @Test
    public void decrypt_chaCha20Poly1305_andAliases() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv12);
        for (String transformation : new String[] {
                     "ChaCha20/Poly1305/NoPadding",
                     "ChaCha20-Poly1305",
                     "chacha20/poly1305/nopadding",
                     // Adding Mode and padding to alias also works.
                     "ChaCha20-Poly1305/Poly1305/NoPadding",
                     "chacha20-poly1305/poly1305/nopadding",
             }) {
            assertDecryptsToExpectedPlaintext(transformation, "ChaCha20", key32, iv,
                                              ciphertextChaCha20Poly1305, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "chacha20", key32, iv,
                                              ciphertextChaCha20Poly1305, plaintextVar);
        }
    }

    @Test
    public void decrypt_xChaCha20Poly1305_andAliases() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv24);
        for (String transformation : new String[] {
                     "XChaCha20/Poly1305/NoPadding",
                     "XChaCha20-Poly1305",
                     "xChaCha20/poly1305/nopadding",
                     // Adding Mode and padding to alias also works.
                     "XChaCha20-Poly1305/Poly1305/NoPadding",
                     "xchacha20-poly1305/poly1305/nopadding",
             }) {
            assertDecryptsToExpectedPlaintext(transformation, "XChaCha20", key32, iv,
                                              ciphertextXChaCha20Poly1305, plaintextVar);
            assertDecryptsToExpectedPlaintext(transformation, "xchacha20", key32, iv,
                                              ciphertextXChaCha20Poly1305, plaintextVar);
        }
    }

    // =========================================================================
    // 2. Unsupported Key Size Rejection Tests
    // =========================================================================

    @Test
    public void initWithWrongKeySize_aes128EcbNoPadding_throws() throws Exception {
        assertRejectsKey("AES_128/ECB/NoPadding", "AES", key24, null);
        assertRejectsKey("AES_128/ECB/NoPadding", "AES", key32, null);
    }

    @Test
    public void initWithWrongKeySize_aes128EcbPkcs5Padding_andAliases_throws() throws Exception {
        for (String transformation :
             new String[] {"AES_128/ECB/PKCS5Padding", "AES_128/ECB/PKCS7Padding"}) {
            assertRejectsKey(transformation, "AES", key24, null);
            assertRejectsKey(transformation, "AES", key32, null);
        }
    }

    @Test
    public void initWithWrongKeySize_aes128CbcNoPadding_throws() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv16);
        assertRejectsKey("AES_128/CBC/NoPadding", "AES", key24, iv);
        assertRejectsKey("AES_128/CBC/NoPadding", "AES", key32, iv);
    }

    @Test
    public void initWithWrongKeySize_aes128CbcPkcs5Padding_andAliases_throws() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv16);
        String[] transformations = {
                "AES_128/CBC/PKCS5Padding",    "AES_128/CBC/PKCS7Padding",
                "PBEWithHmacSHA1AndAES_128",   "PBEWithHmacSHA224AndAES_128",
                "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA384AndAES_128",
                "PBEWithHmacSHA512AndAES_128",
        };
        for (String transformation : transformations) {
            assertRejectsKey(transformation, "AES", key24, iv);
            assertRejectsKey(transformation, "AES", key32, iv);
        }
    }

    @Test
    public void initWithWrongKeySize_aes256EcbNoPadding_throws() throws Exception {
        assertRejectsKey("AES_256/ECB/NoPadding", "AES", key16, null);
        assertRejectsKey("AES_256/ECB/NoPadding", "AES", key24, null);
    }

    @Test
    public void initWithWrongKeySize_aes256EcbPkcs5Padding_andAliases_throws() throws Exception {
        for (String transformation :
             new String[] {"AES_256/ECB/PKCS5Padding", "AES_256/ECB/PKCS7Padding"}) {
            assertRejectsKey(transformation, "AES", key16, null);
            assertRejectsKey(transformation, "AES", key24, null);
        }
    }

    @Test
    public void initWithWrongKeySize_aes256CbcNoPadding_throws() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv16);
        assertRejectsKey("AES_256/CBC/NoPadding", "AES", key16, iv);
        assertRejectsKey("AES_256/CBC/NoPadding", "AES", key24, iv);
    }

    @Test
    public void initWithWrongKeySize_aes256CbcPkcs5Padding_andAliases_throws() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv16);
        String[] transformations = {
                "AES_256/CBC/PKCS5Padding",    "AES_256/CBC/PKCS7Padding",
                "PBEWithHmacSHA1AndAES_256",   "PBEWithHmacSHA224AndAES_256",
                "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_256",
                "PBEWithHmacSHA512AndAES_256",
        };
        for (String transformation : transformations) {
            assertRejectsKey(transformation, "AES", key16, iv);
            assertRejectsKey(transformation, "AES", key24, iv);
        }
    }

    @Test
    public void initWith24ByteKey_aesGcmNoPadding_andAliases_throws() throws Exception {
        GCMParameterSpec spec = new GCMParameterSpec(128, iv12);
        String[] transformations = {
                "AES/GCM/NoPadding",       "GCM",
                "2.16.840.1.101.3.4.1.6",  "2.16.840.1.101.3.4.1.26",
                "2.16.840.1.101.3.4.1.46",
        };
        for (String transformation : transformations) {
            assertRejectsKey(transformation, "AES", key24, spec);
        }
    }

    @Test
    public void initWithWrongKeySize_aes128GcmNoPadding_throws() throws Exception {
        GCMParameterSpec spec = new GCMParameterSpec(128, iv12);
        assertRejectsKey("AES_128/GCM/NoPadding", "AES", key24, spec);
        assertRejectsKey("AES_128/GCM/NoPadding", "AES", key32, spec);
    }

    @Test
    public void initWithWrongKeySize_aes256GcmNoPadding_throws() throws Exception {
        GCMParameterSpec spec = new GCMParameterSpec(128, iv12);
        assertRejectsKey("AES_256/GCM/NoPadding", "AES", key16, spec);
        assertRejectsKey("AES_256/GCM/NoPadding", "AES", key24, spec);
    }

    @Test
    public void initWith24ByteKey_aesGcmSivNoPadding_throws() throws Exception {
        assertRejectsKey("AES/GCM-SIV/NoPadding", "AES", key24, new GCMParameterSpec(128, iv12));
    }

    @Test
    public void initWithWrongKeySize_aes128GcmSivNoPadding_throws() throws Exception {
        GCMParameterSpec spec = new GCMParameterSpec(128, iv12);
        assertRejectsKey("AES_128/GCM-SIV/NoPadding", "AES", key24, spec);
        assertRejectsKey("AES_128/GCM-SIV/NoPadding", "AES", key32, spec);
    }

    @Test
    public void initWithWrongKeySize_aes256GcmSivNoPadding_throws() throws Exception {
        GCMParameterSpec spec = new GCMParameterSpec(128, iv12);
        assertRejectsKey("AES_256/GCM-SIV/NoPadding", "AES", key16, spec);
        assertRejectsKey("AES_256/GCM-SIV/NoPadding", "AES", key24, spec);
    }

    @Test
    public void initWith24ByteKey_chaCha20_throws() throws Exception {
        assertRejectsKey("ChaCha20", "ChaCha20", key24, new IvParameterSpec(iv12));
    }

    @Test
    public void initWith24ByteKey_chaCha20Poly1305_andAliases_throws() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv12);
        for (String transformation :
             new String[] {"ChaCha20/Poly1305/NoPadding", "ChaCha20-Poly1305"}) {
            assertRejectsKey(transformation, "ChaCha20", key24, iv);
        }
    }

    @Test
    public void initWith24ByteKey_xChaCha20Poly1305_andAliases_throws() throws Exception {
        IvParameterSpec iv = new IvParameterSpec(iv24);
        for (String transformation :
             new String[] {"XChaCha20/Poly1305/NoPadding", "XChaCha20-Poly1305"}) {
            assertRejectsKey(transformation, "XChaCha20", key24, iv);
        }
    }
}
