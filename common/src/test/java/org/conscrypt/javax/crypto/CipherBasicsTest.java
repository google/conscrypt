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

import static org.conscrypt.TestUtils.decodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
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

    private static final Map<String, String> BASIC_CIPHER_TO_TEST_DATA = new HashMap<>();
    static {
        BASIC_CIPHER_TO_TEST_DATA.put("AES/ECB/NoPadding", "crypto/aes-ecb.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("AES/CBC/NoPadding", "crypto/aes-cbc.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("AES/CFB8/NoPadding", "crypto/aes-cfb8.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("AES/CFB128/NoPadding", "crypto/aes-cfb128.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("AES/OFB/NoPadding", "crypto/aes-ofb.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("DESEDE/ECB/NoPadding", "crypto/desede-ecb.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("DESEDE/CBC/NoPadding", "crypto/desede-cbc.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("DESEDE/CFB8/NoPadding", "crypto/desede-cfb8.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("DESEDE/CFB64/NoPadding", "crypto/desede-cfb64.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("DESEDE/OFB/NoPadding", "crypto/desede-ofb.csv");
        BASIC_CIPHER_TO_TEST_DATA.put("ChaCha20", "crypto/chacha20.csv");
    }

    private static final Map<String, String> AEAD_CIPHER_TO_TEST_DATA = new HashMap<>();
    static {
        AEAD_CIPHER_TO_TEST_DATA.put("AES/GCM/NoPadding", "crypto/aes-gcm.csv");
        AEAD_CIPHER_TO_TEST_DATA.put("AES/GCM-SIV/NoPadding", "crypto/aes-gcm-siv.csv");
        AEAD_CIPHER_TO_TEST_DATA.put("ChaCha20/Poly1305/NoPadding", "crypto/chacha20-poly1305.csv");
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

    private enum CallPattern {
        DO_FINAL,
        DO_FINAL_WITH_OFFSET,
        UPDATE_DO_FINAL,
        MULTIPLE_UPDATE_DO_FINAL,
        UPDATE_DO_FINAL_WITH_OUTPUT_ARRAY,
        UPDATE_DO_FINAL_WITH_OUTPUT_ARRAY_AND_OFFSET,
        DO_FINAL_WITH_INPUT_OUTPUT_ARRAY,
        DO_FINAL_WITH_INPUT_OUTPUT_ARRAY_AND_OFFSET,
        UPDATE_DO_FINAL_WITH_INPUT_OUTPUT_ARRAY
    }

    /** Concatenates the given arrays into a single array.*/
    byte[] concatArrays(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            if (array == null) {
                continue;
            }
            length += array.length;
        }
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] array : arrays) {
            if (array == null) {
                continue;
            }
            System.arraycopy(array, 0, result, pos, array.length);
            pos += array.length;
        }
        return result;
    }

    /** Calls an initialized cipher with different equivalent call patterns. */
    private byte[] callCipher(
            Cipher cipher, byte[] input, int expectedOutputLength, CallPattern callPattern)
            throws GeneralSecurityException {
        switch (callPattern) {
            case DO_FINAL: {
                return cipher.doFinal(input);
            }
            case DO_FINAL_WITH_OFFSET: {
                byte[] inputCopy = new byte[input.length + 100];
                int inputOffset = 42;
                System.arraycopy(input, 0, inputCopy, inputOffset, input.length);
                return cipher.doFinal(inputCopy, inputOffset, input.length);
            }
            case UPDATE_DO_FINAL: {
                byte[] output1 = cipher.update(input);
                byte[] output2 = cipher.doFinal();
                return concatArrays(output1, output2);
            }
            case MULTIPLE_UPDATE_DO_FINAL: {
                int input1Length = input.length / 2;
                int input2Length = input.length - input1Length;
                byte[] output1 = cipher.update(input, /*inputOffset= */ 0, input1Length);
                int input2Offset = input1Length;
                byte[] output2 = cipher.update(input, input2Offset, input2Length);
                byte[] output3 = cipher.update(new byte[0]);
                byte[] output4 = cipher.doFinal();
                return concatArrays(output1, output2, output3, output4);
            }
            case UPDATE_DO_FINAL_WITH_OUTPUT_ARRAY: {
                byte[] output1 = cipher.update(input);
                int output1Length = (output1 == null) ? 0 : output1.length;
                byte[] output2 = new byte[expectedOutputLength - output1Length];
                int written = cipher.doFinal(output2, /*outputOffset= */ 0);
                assertEquals(expectedOutputLength - output1Length, written);
                return concatArrays(output1, output2);
            }
            case UPDATE_DO_FINAL_WITH_OUTPUT_ARRAY_AND_OFFSET: {
                byte[] output1 = cipher.update(input);
                int output1Length = (output1 == null) ? 0 : output1.length;
                byte[] output2WithOffset = new byte[expectedOutputLength + 100];
                int outputOffset = 42;
                int written = cipher.doFinal(output2WithOffset, outputOffset);
                assertEquals(expectedOutputLength - output1Length, written);
                byte[] output2 = Arrays.copyOfRange(output2WithOffset, outputOffset, outputOffset + written);
                return concatArrays(output1, output2);
            }
            case DO_FINAL_WITH_INPUT_OUTPUT_ARRAY: {
                byte[] output = new byte[expectedOutputLength];
                int written = cipher.doFinal(input, /*inputOffset= */ 0, input.length, output);
                assertEquals(expectedOutputLength, written);
                return output;
            }
            case DO_FINAL_WITH_INPUT_OUTPUT_ARRAY_AND_OFFSET: {
                byte[] inputWithOffset = new byte[input.length + 100];
                int inputOffset = 37;
                System.arraycopy(input, 0, inputWithOffset, inputOffset, input.length);
                byte[] outputWithOffset = new byte[expectedOutputLength + 100];
                int outputOffset = 21;
                int written = cipher.doFinal(
                    inputWithOffset, inputOffset, input.length, outputWithOffset, outputOffset);
                return Arrays.copyOfRange(outputWithOffset, outputOffset, outputOffset + written);
            }
            case UPDATE_DO_FINAL_WITH_INPUT_OUTPUT_ARRAY: {
                int input1Length = input.length / 2;
                byte[] output = new byte[expectedOutputLength];
                int written1 = cipher.update(input, /*inputOffset= */ 0, input1Length, output);
                int input2Offset = input1Length;
                int input2Length = input.length - input1Length;
                int outputOffset = written1;
                int written2 = cipher.doFinal(
                    input, input2Offset, input2Length, output, outputOffset);
                assertEquals(expectedOutputLength, written1 + written2);
                return output;
            }
        }
        throw new IllegalArgumentException("Unsupported CallPattern: " + callPattern);
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

                List<String[]> data = TestUtils.readCsvResource(entry.getValue());
                for (String[] line : data) {
                    Key key = new SecretKeySpec(decodeHex(line[KEY_INDEX]),
                            getBaseAlgorithm(transformation));
                    byte[] iv = decodeHex(line[IV_INDEX]);
                    byte[] plaintext = decodeHex(line[PLAINTEXT_INDEX]);
                    byte[] ciphertext = decodeHex(line[CIPHERTEXT_INDEX]);

                    // Initialize the IV, if there is one
                    AlgorithmParameters params;
                    if (iv.length > 0) {
                        params = AlgorithmParameters.getInstance(getBaseAlgorithm(transformation));
                        params.init(iv, "RAW");
                    } else {
                        params = null;
                    }

                    try {
                        for (CallPattern callPattern: CallPattern.values()) {
                            cipher.init(Cipher.ENCRYPT_MODE, key, params);
                            assertEquals("Provider " + p.getName()
                                        + ", algorithm " + transformation
                                        + " reported the wrong output size",
                                ciphertext.length, cipher.getOutputSize(plaintext.length));
                            byte[] encrypted = callCipher(
                                cipher, plaintext, ciphertext.length, callPattern);
                            assertArrayEquals(
                                "Provider " + p.getName() + ", algorithm " + transformation
                                    + ", CallPattern " + callPattern
                                    + " failed on encryption, data is " + Arrays.toString(line),
                                ciphertext, encrypted);

                            cipher.init(Cipher.DECRYPT_MODE, key, params);
                            byte[] decrypted;
                            try {
                                decrypted = callCipher(
                                    cipher, ciphertext, plaintext.length, callPattern);
                            } catch (GeneralSecurityException e) {
                                throw new GeneralSecurityException("Provider " + p.getName()
                                + ", algorithm " + transformation + ", CallPattern " + callPattern
                                + " failed on decryption, data is " + Arrays.toString(line), e);
                            }
                            assertArrayEquals(
                                "Provider " + p.getName() + ", algorithm " + transformation
                                    + ", CallPattern " + callPattern
                                    + " failed on decryption, data is " + Arrays.toString(line),
                                plaintext, decrypted);
                        }
                    } catch (InvalidKeyException e) {
                        // Some providers may not support raw SecretKeySpec keys, that's allowed
                    }
                }
            }
        }
    }

    private static AlgorithmParameterSpec modifiedParams(AlgorithmParameterSpec params) {
        if (params instanceof IvParameterSpec) {
            IvParameterSpec ivSpec = (IvParameterSpec) params;
            byte[] iv = ivSpec.getIV();
            iv[0] = (byte) (iv[0] ^ 1);
            return new IvParameterSpec(iv);
        } else if (params instanceof GCMParameterSpec) {
            GCMParameterSpec gcmSpec = (GCMParameterSpec) params;
            byte[] iv = gcmSpec.getIV();
            iv[0] = (byte) (iv[0] ^ 1);
            return new GCMParameterSpec(gcmSpec.getTLen(), iv);
        } else {
            throw new IllegalArgumentException("Unsupported AlgorithmParameterSpec: " + params);
        }
    }

    static final byte[] EMPTY_AAD = new byte[0];

    public void arrayBasedAssessment(Cipher cipher, byte[] aad, byte[] tag, byte[] plaintext,
                                     byte[] ciphertext, Key key, AlgorithmParameterSpec params,
                                     String transformation, Provider p, String[] line) throws Exception {
        byte[] combinedCiphertext = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, combinedCiphertext, 0, ciphertext.length);
        System.arraycopy(tag, 0, combinedCiphertext, ciphertext.length, tag.length);

        for (CallPattern callPattern: CallPattern.values()) {
            // We first initialize the cipher with a modified IV to make sure that we don't trigger
            // an IV reuse check.
            cipher.init(Cipher.ENCRYPT_MODE, key, modifiedParams(params));

            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            if (aad.length > 0) {
                cipher.updateAAD(aad);
            }
            assertEquals("Provider " + p.getName()
                            + ", algorithm " + transformation
                            + " reported the wrong output size",
                    combinedCiphertext.length, cipher.getOutputSize(plaintext.length));
            byte[] encrypted = callCipher(cipher, plaintext, combinedCiphertext.length, callPattern);
            assertArrayEquals("Provider " + p.getName()
                + ", algorithm " + transformation + ", CallPattern " + callPattern
                + " failed on encryption, data is " + Arrays.toString(line),
                combinedCiphertext, encrypted);
        }

        for (CallPattern callPattern: CallPattern.values()) {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
            if (aad.length > 0) {
                cipher.updateAAD(aad);
            }
            assertEquals("Provider " + p.getName()
                            + ", algorithm " + transformation
                            + " reported the wrong output size",
                    plaintext.length, cipher.getOutputSize(combinedCiphertext.length));
            byte[] decrypted;
            try {
                decrypted = callCipher(cipher, combinedCiphertext, plaintext.length, callPattern);
            } catch (GeneralSecurityException e) {
                throw new GeneralSecurityException("Provider " + p.getName()
                + ", algorithm " + transformation + ", CallPattern " + callPattern
                + " failed on decryption, data is " + Arrays.toString(line), e);
            }
            assertArrayEquals("Provider " + p.getName()
                + ", algorithm " + transformation + ", CallPattern " + callPattern
                + " failed on decryption, data is " + Arrays.toString(line),
                plaintext, decrypted);
        }
    }

    @Test
    public void testAeadEncryption() throws Exception {
        TestUtils.assumeAEADAvailable();
        for (Provider p : Security.getProviders()) {
            for (Map.Entry<String, String> entry : AEAD_CIPHER_TO_TEST_DATA.entrySet()) {
                String transformation = entry.getKey();

                // On Android 10 and below, BC can return AES/GCM/NoPadding when asked for
                // AES/GCM-SIV/NoPadding. Android will never actually ship AES/GCM-SIV/NoPadding
                // in BC, so skip that combination.
                if (p.getName().equals("BC") && transformation.equals("AES/GCM-SIV/NoPadding")) {
                    continue;
                }

                Cipher cipher;
                try {
                    cipher = Cipher.getInstance(transformation, p);
                } catch (NoSuchAlgorithmException e) {
                    // This provider doesn't provide this algorithm, ignore it
                    continue;
                }

                List<String[]> data = TestUtils.readCsvResource(entry.getValue());
                for (String[] line : data) {
                    Key key = new SecretKeySpec(decodeHex(line[KEY_INDEX]),
                            getBaseAlgorithm(transformation));
                    byte[] iv = decodeHex(line[IV_INDEX]);
                    byte[] plaintext = decodeHex(line[PLAINTEXT_INDEX]);
                    byte[] ciphertext = decodeHex(line[CIPHERTEXT_INDEX]);
                    byte[] tag = decodeHex(line[TAG_INDEX]);
                    byte[] aad = decodeHex(line[AAD_INDEX]);

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
                        arrayBasedAssessment(cipher, aad, tag, plaintext, ciphertext, key, params, transformation, p,
                                line);
                        bufferBasedAssessment(cipher, aad, tag, plaintext, ciphertext, key, params, transformation, p,
                                false, false);
                        bufferBasedAssessment(cipher, aad, tag, plaintext, ciphertext, key, params, transformation, p,
                                true, true);
                        bufferBasedAssessment(cipher, aad, tag, plaintext, ciphertext, key, params, transformation, p,
                                true, false);
                        bufferBasedAssessment(cipher, aad, tag, plaintext, ciphertext, key, params, transformation, p,
                                false, true);
                        sharedBufferBasedAssessment(cipher, aad, tag, plaintext, ciphertext, key, params,
                                transformation, p);
                    } catch (InvalidKeyException e) {
                        // Some providers may not support raw SecretKeySpec keys, that's allowed
                    } catch (InvalidAlgorithmParameterException e) {
                        // Some providers may not support all tag lengths or nonce lengths,
                        // that's allowed
                        if (e.getMessage().contains("IV must not be re-used")) {
                            throw new AssertionError(
                                "The same IV was used twice and therefore some tests did not run." +
                                "Provider = " + p.getName() + ", algorithm = " + transformation,
                                e);
                        }
                    }
                }
            }
        }
    }

    public void sharedBufferBasedAssessment(Cipher cipher, byte[] aad, byte[] tag, byte[] _plaintext,
                                      byte[] _ciphertext, Key key, AlgorithmParameterSpec params,
                                      String transformation, Provider p) throws Exception {
        // We first initialize the cipher with a modified IV to make sure that we don't trigger
        // an IV reuse check.
        cipher.init(Cipher.ENCRYPT_MODE, key, modifiedParams(params));

        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        if (aad.length > 0) {
            cipher.updateAAD(aad);
        }
        byte[] _combinedOutput = new byte[_ciphertext.length + tag.length];
        byte[] _commonBacking = new byte[_plaintext.length + _combinedOutput.length];

        assertEquals("Provider " + p.getName()
                        + ", algorithm " + transformation
                        + " reported the wrong output size",
                _combinedOutput.length, cipher.getOutputSize(_plaintext.length));
        System.arraycopy(_ciphertext, 0, _combinedOutput, 0, _ciphertext.length);
        System.arraycopy(tag, 0, _combinedOutput, _ciphertext.length, tag.length);
        System.arraycopy(_plaintext, 0, _commonBacking, 0, _plaintext.length);
        System.arraycopy(_combinedOutput, 0, _commonBacking, _plaintext.length, _combinedOutput.length);
        ByteBuffer combinedOutput = ByteBuffer.wrap(_commonBacking);
        ByteBuffer plaintext = combinedOutput.slice();
        plaintext.limit(_plaintext.length);
        combinedOutput.position(_plaintext.length);
        // both byte buffers have been created from common backed array and have correct respecting positions and limits

        combinedOutput.position(combinedOutput.limit());
        ByteBuffer outputbuffer = ByteBuffer.allocate(cipher.getOutputSize(plaintext.remaining()));

        cipher.doFinal(plaintext, outputbuffer);
        assertEquals("Cipher doFinal did not encrypt correctly", combinedOutput, outputbuffer);
        assertEquals(" input was not shifted", plaintext.position(), plaintext.limit());

        cipher.init(Cipher.DECRYPT_MODE, key, params);
        if (aad.length > 0) {
            cipher.updateAAD(aad);
        }
        assertEquals("Provider " + p.getName()
                        + ", algorithm " + transformation
                        + " reported the wrong output size",
                _plaintext.length, cipher.getOutputSize(_combinedOutput.length));
        combinedOutput.position(_plaintext.length);

        outputbuffer = ByteBuffer.allocate(cipher.getOutputSize(combinedOutput.remaining()));

        combinedOutput.position(_plaintext.length);
        plaintext.position(plaintext.limit());
        cipher.doFinal(combinedOutput, outputbuffer);
        assertEquals("Cipher doFinal did not decrypt correctly", plaintext, outputbuffer);
        assertEquals(" input was not shifted", combinedOutput.position(), combinedOutput.limit());
    }

    public void bufferBasedAssessment(Cipher cipher, byte[] aad, byte[] tag, byte[] _plaintext,
                                           byte[] _ciphertext, Key key, AlgorithmParameterSpec params,
                                           String transformation, Provider p, boolean inBoolDirect, boolean outBoolDirect) throws Exception {
        // We first initialize the cipher with a modified IV to make sure that we don't trigger
        // an IV reuse check.
        cipher.init(Cipher.ENCRYPT_MODE, key, modifiedParams(params));

        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        if (aad.length > 0) {
            cipher.updateAAD(aad);
        }
        byte[] _combinedOutput = new byte[_ciphertext.length + tag.length];
        ByteBuffer plaintext = ByteBuffer.wrap(_plaintext);
        if (inBoolDirect) {
            ByteBuffer plaintext_ = plaintext;
            int incap = plaintext_.remaining();
            plaintext = ByteBuffer.allocateDirect(incap);
            plaintext.mark();
            plaintext.put(plaintext_);
            plaintext.reset();
        }

        assertEquals("Provider " + p.getName()
                        + ", algorithm " + transformation
                        + " reported the wrong output size",
                _combinedOutput.length, cipher.getOutputSize(_plaintext.length));
        System.arraycopy(_ciphertext, 0, _combinedOutput, 0, _ciphertext.length);
        System.arraycopy(tag, 0, _combinedOutput, _ciphertext.length, tag.length);

        ByteBuffer combinedOutput = ByteBuffer.wrap(_combinedOutput);
        if (outBoolDirect) {
            ByteBuffer combinedOutput_ = combinedOutput;
            int outcap = combinedOutput_.remaining();
            combinedOutput = ByteBuffer.allocateDirect(outcap);
            combinedOutput.mark();
            combinedOutput.put(combinedOutput_);
        }
        combinedOutput.position(combinedOutput.limit());
        ByteBuffer outputbuffer;
        if (outBoolDirect) {
            outputbuffer = ByteBuffer.allocateDirect(cipher.getOutputSize(plaintext.remaining()));
        } else {
            outputbuffer = ByteBuffer.allocate(cipher.getOutputSize(plaintext.remaining()));
        }

        cipher.doFinal(plaintext, outputbuffer);
        assertEquals("Cipher doFinal did not encrypt correctly", combinedOutput, outputbuffer);
        assertEquals(" input was not shifted", plaintext.position(), plaintext.limit());

        cipher.init(Cipher.DECRYPT_MODE, key, params);
        if (aad.length > 0) {
            cipher.updateAAD(aad);
        }
        assertEquals("Provider " + p.getName()
                        + ", algorithm " + transformation
                        + " reported the wrong output size",
                _plaintext.length, cipher.getOutputSize(_combinedOutput.length));
        combinedOutput = ByteBuffer.wrap(_combinedOutput);
        if (inBoolDirect) {
            ByteBuffer combinedOutput_ = combinedOutput;
            int incap = combinedOutput_.remaining();
            combinedOutput = ByteBuffer.allocateDirect(incap);
            combinedOutput.mark();
            combinedOutput.put(combinedOutput_);
            combinedOutput.reset();
        }
        if (outBoolDirect) {
            outputbuffer = ByteBuffer.allocateDirect(cipher.getOutputSize(combinedOutput.remaining()));
        } else {
            outputbuffer = ByteBuffer.allocate(cipher.getOutputSize(combinedOutput.remaining()));
        }
        combinedOutput.position(0);
        plaintext.position(plaintext.limit());
        cipher.doFinal(combinedOutput, outputbuffer);
        assertEquals("Cipher doFinal did not decrypt correctly", plaintext, outputbuffer);
        assertEquals(" input was not shifted", combinedOutput.position(), combinedOutput.limit());
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

    /**
     * Encryption with ByteBuffers should be copy-safe even if the buffers have different starting
     * offsets and/or do not make the backing array visible.
     *
     * <p>Note that bugs in this often require a sizeable input to reproduce; the default
     * implementation of engineUpdate(ByteBuffer, ByteBuffer) copies through 4KB bounce buffers, so we
     * need to use something larger to see any problems - 8KB is what we use here.
     *
     * @see https://bugs.openjdk.java.net/browse/JDK-8181386
     */
    @Test
    public void testByteBufferShiftedAlias() throws Exception {
        byte[] ptVector = new byte[8192];

        for (int i = 0; i < 3; i++) {
            // outputOffset = offset relative to start of input.
            for (int outputOffset = -1; outputOffset <= 1; outputOffset++) {

                SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
                GCMParameterSpec parameters = new GCMParameterSpec(128, new byte[12]);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, key, parameters);

                ByteBuffer output, input, inputRO;

                // We'll try three scenarios: Ordinary array backed buffers, array backed buffers where one
                // is read-only, and direct byte buffers.
                String mode;
                // offsets relative to start of buffer
                int inputOffsetInBuffer = 1;
                int outputOffsetInBuffer = inputOffsetInBuffer + outputOffset;
                int sliceLength = cipher.getOutputSize(ptVector.length);
                int bufferSize = sliceLength + Math.max(inputOffsetInBuffer, outputOffsetInBuffer);

                mode = "direct buffers";
                ByteBuffer buf = ByteBuffer.allocateDirect(bufferSize);
                output = buf.duplicate();
                output.position(outputOffsetInBuffer);
                output.limit(sliceLength + outputOffsetInBuffer);
                output = output.slice();

                input = buf.duplicate();
                input.position(inputOffsetInBuffer);
                input.limit(sliceLength + inputOffsetInBuffer);
                input = input.slice();

                inputRO = input.duplicate();

                // Now that we have our overlapping 'input' and 'output' buffers, we can write our plaintext
                // into the input buffer.
                input.put(ptVector);
                input.flip();
                // Make sure the RO input buffer has the same limit in case the plaintext is shorter than
                // sliceLength (which it generally will be for anything other than ECB or CTR mode)
                inputRO.limit(input.limit());

                try {
                    int ctSize = cipher.doFinal(inputRO, output);

                    // Now flip the buffers around and undo everything
                    byte[] tmp = new byte[ctSize];
                    output.flip();
                    output.get(tmp);

                    output.clear();
                    input.clear();
                    inputRO.clear();

                    input.put(tmp);
                    input.flip();
                    inputRO.limit(input.limit());

                    cipher.init(Cipher.DECRYPT_MODE, key, parameters);
                    cipher.doFinal(inputRO, output);

                    output.flip();
                    assertEquals(ByteBuffer.wrap(ptVector), output);
                } catch (Throwable t) {
                    throw new AssertionError(
                            "Overlapping buffers test failed with buffer type: "
                                    + mode
                                    + " and output offset "
                                    + outputOffset,
                            t);
                }
            }
        }
    }
}

