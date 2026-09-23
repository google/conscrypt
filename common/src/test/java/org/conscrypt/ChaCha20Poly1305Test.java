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
import static org.junit.Assert.assertThrows;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.util.List;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@RunWith(JUnit4.class)
public class ChaCha20Poly1305Test {
    private final Provider conscryptProvider = TestUtils.getConscryptProvider();

    @BeforeClass
    public static void setUp() {
        TestUtils.assumeAllowsUnsignedCrypto();
    }

    @Test
    public void chaCha20Poly1305_encryptAndDecrypt_succeeds() throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", conscryptProvider);
        SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        IvParameterSpec iv = new IvParameterSpec(new byte[12]);

        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] plaintext = "Hello World".getBytes(TestUtils.UTF_8);
        byte[] ciphertext = c.doFinal(plaintext);

        c.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = c.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void chaCha20Poly1305_decryptWithDifferentKey_throwsException() throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", conscryptProvider);
        SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        IvParameterSpec iv = new IvParameterSpec(new byte[12]);

        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] plaintext = "Hello World".getBytes(TestUtils.UTF_8);
        byte[] ciphertext = c.doFinal(plaintext);

        byte[] differentKeyBytes = new byte[32];
        differentKeyBytes[0] = 1; // Change one byte
        SecretKeySpec differentKey = new SecretKeySpec(differentKeyBytes, "ChaCha20");

        c.init(Cipher.DECRYPT_MODE, differentKey, iv);
        assertThrows(AEADBadTagException.class, () -> c.doFinal(ciphertext));
    }

    @Test
    public void chaCha20Poly1305_decryptWithModifiedCiphertext_throwsException() throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", conscryptProvider);
        SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        IvParameterSpec iv = new IvParameterSpec(new byte[12]);

        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] plaintext = "Hello World".getBytes(TestUtils.UTF_8);
        byte[] ciphertext = c.doFinal(plaintext);

        ciphertext[0] ^= 1; // Flip a bit

        c.init(Cipher.DECRYPT_MODE, key, iv);
        assertThrows(AEADBadTagException.class, () -> c.doFinal(ciphertext));
    }

    @Test
    public void xChaCha20Poly1305_encryptAndDecrypt_succeeds() throws Exception {
        Cipher c = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", conscryptProvider);
        SecretKeySpec key = new SecretKeySpec(new byte[32], "XChaCha20");
        IvParameterSpec iv = new IvParameterSpec(new byte[24]);

        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] plaintext = "Hello World".getBytes(TestUtils.UTF_8);
        byte[] ciphertext = c.doFinal(plaintext);

        c.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = c.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void xChaCha20Poly1305_decryptWithDifferentKey_throwsException() throws Exception {
        Cipher c = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", conscryptProvider);
        SecretKeySpec key = new SecretKeySpec(new byte[32], "XChaCha20");
        IvParameterSpec iv = new IvParameterSpec(new byte[24]);

        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] plaintext = "Hello World".getBytes(TestUtils.UTF_8);
        byte[] ciphertext = c.doFinal(plaintext);

        byte[] differentKeyBytes = new byte[32];
        differentKeyBytes[0] = 1; // Change one byte
        SecretKeySpec differentKey = new SecretKeySpec(differentKeyBytes, "XChaCha20");

        c.init(Cipher.DECRYPT_MODE, differentKey, iv);
        assertThrows(AEADBadTagException.class, () -> c.doFinal(ciphertext));
    }

    @Test
    public void xChaCha20Poly1305_decryptWithModifiedCiphertext_throwsException() throws Exception {
        Cipher c = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", conscryptProvider);
        SecretKeySpec key = new SecretKeySpec(new byte[32], "XChaCha20");
        IvParameterSpec iv = new IvParameterSpec(new byte[24]);

        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] plaintext = "Hello World".getBytes(TestUtils.UTF_8);
        byte[] ciphertext = c.doFinal(plaintext);

        ciphertext[0] ^= 1; // Flip a bit

        c.init(Cipher.DECRYPT_MODE, key, iv);
        assertThrows(AEADBadTagException.class, () -> c.doFinal(ciphertext));
    }

    @Test
    public void xChaCha20Poly1305_alias_encryptAndDecrypt_succeeds() throws Exception {
        Cipher c = Cipher.getInstance("XChaCha20-Poly1305", conscryptProvider);
        SecretKeySpec key = new SecretKeySpec(new byte[32], "XChaCha20");
        IvParameterSpec iv = new IvParameterSpec(new byte[24]);

        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] plaintext = "Hello World".getBytes(TestUtils.UTF_8);
        byte[] ciphertext = c.doFinal(plaintext);

        c.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = c.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void chaCha20Poly1305_shortIv_throwsException() throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", conscryptProvider);
        SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        // ChaCha20/Poly1305/NoPadding expects 12 bytes IV
        IvParameterSpec shortIv = new IvParameterSpec(new byte[11]);

        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> c.init(Cipher.ENCRYPT_MODE, key, shortIv));
    }

    @Test
    public void xChaCha20Poly1305_shortIv_throwsException() throws Exception {
        Cipher c = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", conscryptProvider);
        SecretKeySpec key = new SecretKeySpec(new byte[32], "XChaCha20");
        // XChaCha20/Poly1305/NoPadding expects 24 bytes IV
        IvParameterSpec shortIv = new IvParameterSpec(new byte[23]);

        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> c.init(Cipher.ENCRYPT_MODE, key, shortIv));
    }

    @Test
    public void chaCha20Poly1305_longIv_throwsException() throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", conscryptProvider);
        SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        IvParameterSpec longIv = new IvParameterSpec(new byte[13]);

        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> c.init(Cipher.ENCRYPT_MODE, key, longIv));
    }

    @Test
    public void xChaCha20Poly1305_longIv_throwsException() throws Exception {
        Cipher c = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", conscryptProvider);
        SecretKeySpec key = new SecretKeySpec(new byte[32], "XChaCha20");
        IvParameterSpec longIv = new IvParameterSpec(new byte[25]);

        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> c.init(Cipher.ENCRYPT_MODE, key, longIv));
    }

    @Test
    public void chaCha20Poly1305_invalidKeySize_throwsException() throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", conscryptProvider);
        // Expects 32 bytes key
        SecretKeySpec shortKey = new SecretKeySpec(new byte[16], "ChaCha20");
        IvParameterSpec iv = new IvParameterSpec(new byte[12]);

        assertThrows(InvalidKeyException.class, () -> c.init(Cipher.ENCRYPT_MODE, shortKey, iv));
    }

    @Test
    public void xChaCha20Poly1305_invalidKeySize_throwsException() throws Exception {
        Cipher c = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", conscryptProvider);
        // Expects 32 bytes key
        SecretKeySpec shortKey = new SecretKeySpec(new byte[16], "XChaCha20");
        IvParameterSpec iv = new IvParameterSpec(new byte[24]);

        assertThrows(InvalidKeyException.class, () -> c.init(Cipher.ENCRYPT_MODE, shortKey, iv));
    }

    @Test
    public void xChaCha20Poly1305_chaCha20Key_encryptAndDecrypt_succeeds() throws Exception {
        Cipher c = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", conscryptProvider);

        byte[] keyBytes = new byte[32];
        SecretKeySpec chaCha20Key = new SecretKeySpec(keyBytes, "ChaCha20");
        SecretKeySpec xChaCha20Key = new SecretKeySpec(keyBytes, "XChaCha20");
        IvParameterSpec iv = new IvParameterSpec(new byte[24]);

        c.init(Cipher.ENCRYPT_MODE, chaCha20Key, iv);
        byte[] plaintext = "Hello World".getBytes(TestUtils.UTF_8);
        byte[] ciphertext = c.doFinal(plaintext);

        // Only the length of a key is checked, not its algorithm name.
        c.init(Cipher.DECRYPT_MODE, xChaCha20Key, iv);
        byte[] decrypted = c.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void chaCha20Poly1305_xChaCha20Key_encryptAndDecrypt_succeeds() throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", conscryptProvider);

        byte[] keyBytes = new byte[32];
        SecretKeySpec xChaCha20Key = new SecretKeySpec(keyBytes, "XChaCha20");
        SecretKeySpec chaCha20Key = new SecretKeySpec(keyBytes, "ChaCha20");
        IvParameterSpec iv = new IvParameterSpec(new byte[12]);

        c.init(Cipher.ENCRYPT_MODE, xChaCha20Key, iv);
        byte[] plaintext = "Hello World".getBytes(TestUtils.UTF_8);
        byte[] ciphertext = c.doFinal(plaintext);

        // Only the length of a key is checked, not its algorithm name.
        c.init(Cipher.DECRYPT_MODE, chaCha20Key, iv);
        byte[] decrypted = c.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void chaCha20_keyGenerator_generatesCorrectKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("ChaCha20", conscryptProvider);
        SecretKey key = kg.generateKey();
        assertThat(key.getAlgorithm()).isEqualTo("ChaCha20");
        assertThat(key.getEncoded()).hasLength(32); // 256 bits
    }

    @Test
    public void xChaCha20_keyGenerator_generatesCorrectKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("XChaCha20", conscryptProvider);
        SecretKey key = kg.generateKey();
        assertThat(key.getAlgorithm()).isEqualTo("XChaCha20");
        assertThat(key.getEncoded()).hasLength(32); // 256 bits
    }

    @Test
    public void xChaCha20Poly1305_testVectors_encryptAndDecrypt_succeeds() throws Exception {
        List<TestVector> vectors = TestUtils.readTestVectors("crypto/xchacha20-poly1305.txt");

        for (TestVector vector : vectors) {
            String name = vector.getString("name");
            byte[] keyBytes = vector.getBytes("key");
            byte[] ivBytes = vector.getBytes("iv");
            byte[] plaintext = vector.getBytes("plaintext");
            byte[] ciphertext = vector.getBytes("ciphertext");
            byte[] tag = vector.getBytes("tag");
            byte[] aad = vector.getBytes("aad");

            SecretKeySpec key = new SecretKeySpec(keyBytes, "XChaCha20");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            Cipher c = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", conscryptProvider);

            // Test encryption
            c.init(Cipher.ENCRYPT_MODE, key, iv);
            if (aad.length > 0) {
                c.updateAAD(aad);
            }
            byte[] encrypted = c.doFinal(plaintext);

            byte[] expectedOutput = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, expectedOutput, 0, ciphertext.length);
            System.arraycopy(tag, 0, expectedOutput, ciphertext.length, tag.length);

            assertArrayEquals("Encryption failed for " + name, expectedOutput, encrypted);

            // Test decryption
            c.init(Cipher.DECRYPT_MODE, key, iv);
            if (aad.length > 0) {
                c.updateAAD(aad);
            }
            byte[] decrypted = c.doFinal(encrypted);
            assertArrayEquals("Decryption failed for " + name, plaintext, decrypted);
        }
    }
}
