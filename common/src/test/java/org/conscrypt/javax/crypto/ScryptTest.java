/*
 * Copyright (C) 2022 The Android Open Source Project
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

package org.conscrypt.javax.crypto;

import static org.conscrypt.TestUtils.decodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.conscrypt.ScryptKeySpec;
import org.conscrypt.TestUtils;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ScryptTest {
    private final List<String[]> testVectors = readTestVectors();

    // Column indices in test vector CSV file
    private static final int PASSWORD_INDEX = 0;
    private static final int SALT_INDEX = 1;
    private static final int N_INDEX = 2;
    private static final int R_INDEX = 3;
    private static final int P_INDEX = 4;
    private static final int KEY_INDEX = 5;

    @BeforeClass
    public static void setUp() {
        TestUtils.assumeAllowsUnsignedCrypto();
    }

    @Test
    public void smokeTest() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("Scrypt");
        assertNotNull(factory);

        // One of the test vectors from RFC 7914
        ScryptKeySpec spec = new ScryptKeySpec(
                "password".getBytes(StandardCharsets.UTF_8),
                "NaCl".getBytes(StandardCharsets.UTF_8),
                1024,
                8,
                16,
                64);
        SecretKey key = factory.generateSecret(spec);
        assertNotNull(key);

        assertArrayEquals(
                decodeHex("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
                key.getEncoded());

        // Convert for use with AES
        SecretKeySpec aesKey = makeAesKeySpec(key);

        // Make sure we can actually use the result
        checkKeyIsUSableWithAes(aesKey);
    }

    @Test
    public void duckTypingTest() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("Scrypt");
        assertNotNull(factory);

        // One of the test vectors from RFC 7914
        KeySpec spec = new MyPrivateKeySpec(
                "password".getBytes(StandardCharsets.UTF_8),
                "NaCl".getBytes(StandardCharsets.UTF_8),
                1024,
                8,
                16,
                64);
        SecretKey key = factory.generateSecret(spec);
        assertNotNull(key);

        assertArrayEquals(
                decodeHex("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
                key.getEncoded());
    }


    private SecretKeySpec makeAesKeySpec(SecretKey key) {
        assertEquals("RAW", key.getFormat());
        byte[] bytes = key.getEncoded();
        // Truncate to first 32 bytes if necessary
        int len = Math.min(32, bytes.length);
        return new SecretKeySpec(bytes, 0, len, "AES");
    }

    private void checkKeyIsUSableWithAes(SecretKeySpec spec) throws Exception {
        // Terrible encryption mode but saves messing with IVs and padding which don't matter here.
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, spec);
        byte[] input = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = cipher.doFinal(input);
        assertNotEquals(encrypted[0], input[0]);

        cipher.init(Cipher.DECRYPT_MODE, spec);
        byte[] decrypted = cipher.doFinal(encrypted);
        assertArrayEquals(input, decrypted);
    }

    @Test
    public void knownAnswerTest() throws Exception {
        for (String[] entry : testVectors) {
            byte[] password = entry[PASSWORD_INDEX].getBytes(StandardCharsets.UTF_8);
            byte[] salt = entry[SALT_INDEX].getBytes(StandardCharsets.UTF_8);
            long n = Long.parseLong(entry[N_INDEX]);
            long r = Long.parseLong(entry[R_INDEX]);
            long p = Long.parseLong(entry[P_INDEX]);
            byte[] expectedBytes = decodeHex(entry[KEY_INDEX]);

            ScryptKeySpec spec = new ScryptKeySpec(password, salt, n, r, p, expectedBytes.length);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("Scrypt");
            SecretKey key = factory.generateSecret(spec);
            assertNotNull(key);
            assertArrayEquals(expectedBytes, key.getEncoded());
        }
    }

    private List<String[]> readTestVectors() {
        try {
            return TestUtils.readCsvResource("crypto/scrypt.csv");

        } catch (IOException e) {
            throw new AssertionError("Unable to load Scrypt test vectors", e);
        }
    }

    public static class MyPrivateKeySpec implements KeySpec {
        private final byte[] password;
        private final byte[] salt;
        private final long n;
        private final long r;
        private final long p;
        private final int keyLength;

        public MyPrivateKeySpec(byte[] password, byte[] salt, long n, long r, long p, int keyLength) {
            this.password = password;
            this.salt = salt;
            this.n = n;
            this.r = r;
            this.p = p;
            this.keyLength = keyLength;
        }

        public byte[] getPassword() {
            return password;
        }

        public byte[] getSalt() {
            return salt;
        }

        public long getN() {
            return n;
        }

        public long getR() {
            return r;
        }

        public long getP() {
            return p;
        }

        public int getKeyLength() {
            return keyLength;
        }
    }
}
