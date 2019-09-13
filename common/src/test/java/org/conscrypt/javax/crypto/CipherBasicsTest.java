/*
 * Copyright (C) 2017 The Android Open Source Project
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.conscrypt.TestUtils;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test for basic compliance for ciphers.  This test uses reference vectors produced by
 * standards bodies and confirms that all implementations produce the correct answer
 * for the given inputs.
 */
@RunWith(JUnit4.class)
public final class CipherBasicsTest {

    private static final Map<String, String> BASIC_CIPHER_TO_TEST_DATA = new HashMap<String, String>();
    static {
        BASIC_CIPHER_TO_TEST_DATA.put("AES/ECB/NoPadding", "/crypto/aes-ecb.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("AES/CBC/NoPadding", "/crypto/aes-cbc.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("AES/CFB8/NoPadding", "/crypto/aes-cfb8.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("AES/CFB128/NoPadding", "/crypto/aes-cfb128.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("AES/OFB/NoPadding", "/crypto/aes-ofb.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("DESEDE/ECB/NoPadding", "/crypto/desede-ecb.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("DESEDE/CBC/NoPadding", "/crypto/desede-cbc.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("DESEDE/CFB8/NoPadding", "/crypto/desede-cfb8.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("DESEDE/CFB64/NoPadding", "/crypto/desede-cfb64.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("DESEDE/OFB/NoPadding", "/crypto/desede-ofb.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("ChaCha20", "/crypto/chacha20.csv");
    }

    private static final Map<String, String> AEAD_CIPHER_TO_TEST_DATA = new HashMap<String, String>();
    static {
        AEAD_CIPHER_TO_TEST_DATA.put("AES/GCM/NoPadding", "/crypto/aes-gcm.csv");
        AEAD_CIPHER_TO_TEST_DATA.put("AES/GCM-SIV/NoPadding", "/crypto/aes-gcm-siv.csv");
        AEAD_CIPHER_TO_TEST_DATA.put("ChaCha20/Poly1305/NoPadding", "/crypto/chacha20-poly1305.csv");
    }

    private static final int KEY_INDEX = 0;
    private static final int IV_INDEX = 1;
    private static final int PLAINTEXT_INDEX = 2;
    private static final int CIPHERTEXT_INDEX = 3;
    private static final int TAG_INDEX = 4;
    private static final int AAD_INDEX = 5;

    @BeforeClass
    public static void setUp() {
        TestUtils.assumeAllowsUnsignedCrypto();
    }

    @Test
    public void testBasicEncryption() throws Exception {
        for (Provider p : Security.getProviders()) {
            for (Map.Entry<String, String> entry : BASIC_CIPHER_TO_TEST_DATA.entrySet()) {
                String transformation = entry.getKey();

                // In OpenJDK 6, the SunPKCS11-NSS implementation of AES/ECB/NoPadding thinks
                // that it's AES/CTR/NoPadding during init() for some reason, which causes it
                // to throw an exception due to a lack of IV (required for CTR, prohibited for ECB).
                // We don't strongly care about checking this implementation, so just skip it.
                if (p.getName().equals("SunPKCS11-NSS")
                        && transformation.equals("AES/ECB/NoPadding")) {
                    continue;
                }

                // The SunJCE implementation of ChaCha20 only supports initializing with
                // ChaCha20ParameterSpec, introduced in Java 11.  For now, just skip testing it.
                if (transformation.equals("ChaCha20") && p.getName().equals("SunJCE")) {
                    continue;
                }

                Cipher cipher;
                try {
                    cipher = Cipher.getInstance(transformation, p);
                } catch (NoSuchAlgorithmException e) {
                    // This provider doesn't provide this algorithm, ignore it
                    continue;
                }

                List<String[]> data = readCsvResource(entry.getValue());
                for (String[] line : data) {
                    Key key = new SecretKeySpec(toBytes(line[KEY_INDEX]),
                            getBaseAlgorithm(transformation));
                    byte[] iv = toBytes(line[IV_INDEX]);
                    byte[] plaintext = toBytes(line[PLAINTEXT_INDEX]);
                    byte[] ciphertext = toBytes(line[CIPHERTEXT_INDEX]);

                    // Initialize the IV, if there is one
                    AlgorithmParameters params;
                    if (iv.length > 0) {
                        params = AlgorithmParameters.getInstance(getBaseAlgorithm(transformation));
                        params.init(iv, "RAW");
                    } else {
                        params = null;
                    }

                    try {
                        cipher.init(Cipher.ENCRYPT_MODE, key, params);
                        assertEquals("Provider " + p.getName()
                                        + ", algorithm " + transformation
                                        + " reported the wrong output size",
                                ciphertext.length, cipher.getOutputSize(plaintext.length));
                        assertTrue("Provider " + p.getName()
                                        + ", algorithm " + transformation
                                        + " failed on encryption, data is " + Arrays.toString(line),
                                Arrays.equals(ciphertext, cipher.doFinal(plaintext)));

                        cipher.init(Cipher.DECRYPT_MODE, key, params);
                        assertEquals("Provider " + p.getName()
                                        + ", algorithm " + transformation
                                        + " reported the wrong output size",
                                plaintext.length, cipher.getOutputSize(ciphertext.length));
                        assertTrue("Provider " + p.getName()
                                        + ", algorithm " + transformation
                                        + " failed on decryption, data is " + Arrays.toString(line),
                                Arrays.equals(plaintext, cipher.doFinal(ciphertext)));
                    } catch (InvalidKeyException e) {
                        // Some providers may not support raw SecretKeySpec keys, that's allowed
                    }
                }
            }
        }
    }

    @Test
    public void testAeadEncryption() throws Exception {
        TestUtils.assumeAEADAvailable();
        for (Provider p : Security.getProviders()) {
            for (Map.Entry<String, String> entry : AEAD_CIPHER_TO_TEST_DATA.entrySet()) {
                String transformation = entry.getKey();

                Cipher cipher;
                try {
                    cipher = Cipher.getInstance(transformation, p);
                } catch (NoSuchAlgorithmException e) {
                    // This provider doesn't provide this algorithm, ignore it
                    continue;
                }

                List<String[]> data = readCsvResource(entry.getValue());
                for (String[] line : data) {
                    Key key = new SecretKeySpec(toBytes(line[KEY_INDEX]),
                            getBaseAlgorithm(transformation));
                    byte[] iv = toBytes(line[IV_INDEX]);
                    byte[] plaintext = toBytes(line[PLAINTEXT_INDEX]);
                    byte[] ciphertext = toBytes(line[CIPHERTEXT_INDEX]);
                    byte[] tag = toBytes(line[TAG_INDEX]);
                    byte[] aad = toBytes(line[AAD_INDEX]);

                    // Some ChaCha20 tests include truncated tags, which the Java API doesn't
                    // support.  Skip those tests.
                    if (transformation.startsWith("ChaCha20") && tag.length < 16) {
                        continue;
                    }

                    AlgorithmParameterSpec params;
                    if (transformation.contains("GCM")) {
                        params = new GCMParameterSpec(8 * tag.length, iv);
                    } else {
                        params = new IvParameterSpec(iv);
                    }

                    try {
                        cipher.init(Cipher.ENCRYPT_MODE, key, params);
                        if (aad.length > 0) {
                            cipher.updateAAD(aad);
                        }
                        byte[] combinedOutput = new byte[ciphertext.length + tag.length];
                        assertEquals("Provider " + p.getName()
                                        + ", algorithm " + transformation
                                        + " reported the wrong output size",
                                combinedOutput.length, cipher.getOutputSize(plaintext.length));
                        System.arraycopy(ciphertext, 0, combinedOutput, 0, ciphertext.length);
                        System.arraycopy(tag, 0, combinedOutput, ciphertext.length, tag.length);
                        assertTrue("Provider " + p.getName()
                                        + ", algorithm " + transformation
                                        + " failed on encryption, data is " + Arrays.toString(line),
                                Arrays.equals(combinedOutput, cipher.doFinal(plaintext)));

                        cipher.init(Cipher.DECRYPT_MODE, key, params);
                        if (aad.length > 0) {
                            cipher.updateAAD(aad);
                        }
                        assertEquals("Provider " + p.getName()
                                        + ", algorithm " + transformation
                                        + " reported the wrong output size",
                                plaintext.length, cipher.getOutputSize(combinedOutput.length));
                        assertTrue("Provider " + p.getName()
                                        + ", algorithm " + transformation
                                        + " failed on decryption, data is " + Arrays.toString(line),
                                Arrays.equals(plaintext, cipher.doFinal(combinedOutput)));
                    } catch (InvalidKeyException e) {
                        // Some providers may not support raw SecretKeySpec keys, that's allowed
                    } catch (InvalidAlgorithmParameterException e) {
                        // Some providers may not support all tag lengths or nonce lengths,
                        // that's allowed
                    }
                }
            }
        }
    }

    private static List<String[]> readCsvResource(String resourceName) throws IOException {
        InputStream stream = CipherBasicsTest.class.getResourceAsStream(resourceName);
        List<String[]> lines = new ArrayList<String[]>();
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(stream, "UTF-8"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                lines.add(line.split(",", -1));
            }
        } finally {
            if (reader != null) {
                reader.close();
            }
        }
        return lines;
    }

    /**
     * Returns the underlying cipher name given a cipher transformation.  For example,
     * passing {@code AES/CBC/NoPadding} returns {@code AES}.
     */
    private static String getBaseAlgorithm(String transformation) {
        if (transformation.contains("/")) {
            return transformation.substring(0, transformation.indexOf('/'));
        }
        return transformation;
    }

    private static byte[] toBytes(String hex) {
        return TestUtils.decodeHex(hex, /* allowSingleChar= */ true);
    }
}
