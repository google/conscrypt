/*
 * Copyright (C) 2022 The Android Open Source Project
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
import javax.crypto.spec.SecretKeySpec;
import org.conscrypt.ScryptKeySpec;
import org.conscrypt.TestUtils;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public final class ScryptTest {
    @Parameters(name = "{0}")
    public static String[] params() {
        return new String[] {
                "SCRYPT",
                "1.3.6.1.4.1.11591.4.11",
                "OID.1.3.6.1.4.1.11591.4.11"
        };
    }

    @Parameter
    public String alias;

    // One of the test vectors from RFC 7914
    private static final char[] TEST_PASSWORD = "password".toCharArray();
    private static final byte[] TEST_SALT = "NaCl".getBytes(StandardCharsets.UTF_8);
    private static final int TEST_COST = 1024;
    private static final int TEST_BLOCKSIZE = 8;
    private static final int TEST_PARALLELIZATION = 16;
    private static final int TEST_KEY_SIZE = 512;
    private static final byte[] TEST_KEY = decodeHex(
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
                    + "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");


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
        SecretKeyFactory factory = SecretKeyFactory.getInstance(alias);
        assertEquals(alias, factory.getAlgorithm());

        ScryptKeySpec spec = new ScryptKeySpec(TEST_PASSWORD, TEST_SALT,
                TEST_COST, TEST_BLOCKSIZE, TEST_PARALLELIZATION, TEST_KEY_SIZE);
        SecretKey key = factory.generateSecret(spec);
        assertArrayEquals(TEST_KEY, key.getEncoded());

        // Convert for use with AES
        SecretKeySpec aesKey = makeAesKeySpec(key);

        // Make sure we can actually use the result
        checkKeyIsUsableWithAes(aesKey);
    }

    @Test
    public void duckTypingTest() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(alias);

        KeySpec spec = new MyPrivateKeySpec(TEST_PASSWORD, TEST_SALT,
                TEST_COST, TEST_BLOCKSIZE, TEST_PARALLELIZATION, TEST_KEY_SIZE);

        SecretKey key = factory.generateSecret(spec);
        assertArrayEquals(TEST_KEY, key.getEncoded());
    }

    private SecretKeySpec makeAesKeySpec(SecretKey key) {
        assertEquals("RAW", key.getFormat());
        byte[] bytes = key.getEncoded();
        // Truncate to first 32 bytes if necessary
        int len = Math.min(32, bytes.length);
        return new SecretKeySpec(bytes, 0, len, "AES");
    }

    private void checkKeyIsUsableWithAes(SecretKeySpec spec) throws Exception {
        // Terrible encryption mode but saves messing with IVs which don't matter here.
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
            char[] password = entry[PASSWORD_INDEX].toCharArray();
            byte[] salt = entry[SALT_INDEX].getBytes(StandardCharsets.UTF_8);
            int n = Integer.parseInt(entry[N_INDEX]);
            int r = Integer.parseInt(entry[R_INDEX]);
            int p = Integer.parseInt(entry[P_INDEX]);
            byte[] expectedBytes = decodeHex(entry[KEY_INDEX]);

            ScryptKeySpec spec = new ScryptKeySpec(password, salt, n, r, p, expectedBytes.length * 8);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(alias);
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
        private final char[] password;
        private final byte[] salt;
        private final int n;
        private final int r;
        private final int p;
        private final int keyOutputBits;

        public MyPrivateKeySpec(char[] password, byte[] salt, int n, int r, int p, int keyOutputBits) {
            this.password = password;
            this.salt = salt;
            this.n = n;
            this.r = r;
            this.p = p;
            this.keyOutputBits = keyOutputBits;
        }

        public char[] getPassword() {
            return password;
        }

        public byte[] getSalt() {
            return salt;
        }

        public int getCostParameter() {
            return n;
        }

        public int getBlockSize() {
            return r;
        }

        public int getParallelizationParameter() {
            return p;
        }

        public int getKeyLength() {
            return keyOutputBits;
        }
    }
}
