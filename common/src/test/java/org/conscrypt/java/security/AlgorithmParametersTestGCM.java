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
package org.conscrypt.java.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class AlgorithmParametersTestGCM extends AbstractAlgorithmParametersTest {

    private static final byte[] IV = new byte[] {
        (byte) 0x04, (byte) 0x08, (byte) 0x68, (byte) 0xC8,
        (byte) 0xFF, (byte) 0x64, (byte) 0x72, (byte) 0xF5,
        (byte) 0x04, (byte) 0x08, (byte) 0x68, (byte) 0xC8 };

    private static final int TLEN = 96;
    private static final int SUN_ALT_TLEN = 128;

    // The ASN.1 encoding for GCM params (specified in RFC 5084 section 3.2) specifies
    // a default value of 12 for TLEN, so both values with and without TLEN should work.
    // See README.ASN1 for how to understand and reproduce this data.

    // asn1=SEQUENCE:gcm
    // [gcm]
    // iv=FORMAT:HEX,OCTETSTRING:040868C8FF6472F5040868C8
    private static final String ENCODED_DATA_NO_TLEN = "MA4EDAQIaMj/ZHL1BAhoyA==";

    // asn1=SEQUENCE:gcm
    // [gcm]
    // iv=FORMAT:HEX,OCTETSTRING:040868C8FF6472F5040868C8
    // tlen=INT:12
    private static final String ENCODED_DATA_TLEN = "MBEEDAQIaMj/ZHL1BAhoyAIBDA==";

    public AlgorithmParametersTestGCM() {
        super("GCM", new AlgorithmParameterSymmetricHelper("AES", "GCM/NOPADDING", 128), new GCMParameterSpec(TLEN, IV));
    }

    @Test
    public void testEncoding() throws Exception {
        ServiceTester.test("AlgorithmParameters")
            .withAlgorithm("GCM")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    AlgorithmParameters params = AlgorithmParameters.getInstance("GCM", p);

                    params.init(new GCMParameterSpec(TLEN, IV));
                    String encoded = TestUtils.encodeBase64(params.getEncoded());
                    assertTrue("Encoded: " + encoded,
                        encoded.equals(ENCODED_DATA_TLEN) || encoded.equals(ENCODED_DATA_NO_TLEN));

                    params = AlgorithmParameters.getInstance("GCM", p);
                    params.init(TestUtils.decodeBase64(ENCODED_DATA_NO_TLEN));
                    GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);
                    if (!p.getName().equals("SunJCE")) {
                        assertEquals(TLEN, spec.getTLen());
                    } else {
                        // In some cases the SunJCE provider uses 128 as the default instead of 96
                        assertTrue(spec.getTLen() == TLEN || spec.getTLen() == SUN_ALT_TLEN);
                    }
                    assertArrayEquals(IV, spec.getIV());

                    params = AlgorithmParameters.getInstance("GCM", p);
                    params.init(TestUtils.decodeBase64(ENCODED_DATA_TLEN));
                    spec = params.getParameterSpec(GCMParameterSpec.class);
                    assertEquals(TLEN, spec.getTLen());
                    assertArrayEquals(IV, spec.getIV());
                }
            });
    }

    private static byte[] randomBytes(int n) {
        byte[] bytes = new byte[n];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    public static byte[] sequentialBytes(int length, byte startValue) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (startValue + i);
        }
        return bytes;
    }

    private static final int GCM_TAG_LENGTH_BITS = 128; // 16 bytes
    private static final int GCM_TAG_LENGTH_BYTES = GCM_TAG_LENGTH_BITS / 8;

    private void encryptAndDecrypt(byte[] sharedBuffer, int inputOffset, int plaintextLength,
            int outputOffset, boolean expectSuccess) throws Exception {
        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, randomBytes(12));
        SecretKeySpec skeySpec = new SecretKeySpec(randomBytes(16), "AES");
        byte[] associatedData = randomBytes(20);

        byte[] originalPlaintext = new byte[plaintextLength];
        System.arraycopy(sharedBuffer, inputOffset, originalPlaintext, 0, plaintextLength);

        // Calculate expected output length
        int expectedCiphertextLength = plaintextLength + GCM_TAG_LENGTH_BYTES;

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
            cipher.updateAAD(associatedData);

            int actualCiphertextLength = cipher.doFinal(
                    sharedBuffer, inputOffset, plaintextLength, sharedBuffer, outputOffset);

            if (!expectSuccess) {
                fail("Expected encryption to fail, but it succeeded.");
            }

            assertEquals(
                    "Ciphertext length mismatch", expectedCiphertextLength, actualCiphertextLength);

            // Decryption phase
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
            cipher.updateAAD(associatedData);
            byte[] decryptedPlaintext =
                    cipher.doFinal(sharedBuffer, outputOffset, actualCiphertextLength);

            assertArrayEquals("Decrypted plaintext does not match original", originalPlaintext,
                    decryptedPlaintext);

        } catch (ShortBufferException | IllegalArgumentException | IllegalStateException e) {
            if (expectSuccess) {
                fail("Encryption/decryption failed unexpectedly with "
                        + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }

    @Test
    public void encryptTest_originalOverlap() throws Exception {
        int plaintextLength = 12568;
        int inputOffset = 0;
        int outputOffset = inputOffset + 8;

        // Ensure sharedBuffer is large enough for both input and output
        int requiredInputEnd = inputOffset + plaintextLength;
        int requiredOutputEnd = outputOffset + plaintextLength + GCM_TAG_LENGTH_BYTES;
        int totalBufferSize = Math.max(requiredInputEnd, requiredOutputEnd);

        byte[] sharedBuffer = sequentialBytes(totalBufferSize, (byte) 0);

        encryptAndDecrypt(sharedBuffer, inputOffset, plaintextLength, outputOffset, true);
    }

    @Test
    public void aesGcm_ExactOverlap_Large() throws Exception {
        int plaintextLength = 1000;
        int inputOffset = 0;
        int outputOffset = 0; // Exact overlap
        int totalBufferSize = plaintextLength + GCM_TAG_LENGTH_BYTES; // Minimal size for in-place

        byte[] sharedBuffer = sequentialBytes(totalBufferSize, (byte) 0);

        encryptAndDecrypt(sharedBuffer, inputOffset, plaintextLength, outputOffset, true);
    }

    @Test
    public void aesGcm_BackwardOverlap_OutputBeforeInput() throws Exception {
        int plaintextLength = 100;
        int inputOffset = 20; // Input starts 20 bytes in
        int outputOffset = 0; // Output starts at beginning of buffer
        int totalBufferSize =
                inputOffset + plaintextLength + GCM_TAG_LENGTH_BYTES; // Enough for input+output

        byte[] sharedBuffer = sequentialBytes(totalBufferSize, (byte) 0);

        encryptAndDecrypt(sharedBuffer, inputOffset, plaintextLength, outputOffset, true);
    }

    @Test
    public void aesGcm_ForwardOverlap_OutputOverwritesUnreadInput() throws Exception {
        int plaintextLength = 100;
        int inputOffset = 0;
        int outputOffset = 10; // Output starts 10 bytes into input
        int totalBufferSize =
                outputOffset + plaintextLength + GCM_TAG_LENGTH_BYTES; // Enough for output

        byte[] sharedBuffer = sequentialBytes(totalBufferSize, (byte) 0);

        encryptAndDecrypt(sharedBuffer, inputOffset, plaintextLength, outputOffset, true);
    }

    @Test
    public void aesGcm_NoOverlap_AdjacentBuffers() throws Exception {
        int plaintextLength = 75;
        int inputOffset = 0;
        int outputOffset = plaintextLength; // Output starts immediately after input
        int totalBufferSize =
                outputOffset + plaintextLength + GCM_TAG_LENGTH_BYTES; // Exactly adjacent

        byte[] sharedBuffer = sequentialBytes(totalBufferSize, (byte) 0);

        encryptAndDecrypt(sharedBuffer, inputOffset, plaintextLength, outputOffset, true);
    }

    @Test
    public void aesGcm_BufferTooSmall() throws Exception {
        int plaintextLength = 50;
        int inputOffset = 0;
        int outputOffset = 0;
        // Buffer is smaller than needed for plaintext + tag
        int totalBufferSize = plaintextLength + GCM_TAG_LENGTH_BYTES - 1; // One byte too small

        byte[] sharedBuffer = randomBytes(totalBufferSize);

        // Expect ShortBufferException
        encryptAndDecrypt(sharedBuffer, inputOffset, plaintextLength, outputOffset, false);
    }

    @Test
    public void aesGcm_LargePlaintext_NoOverlap() throws Exception {
        int plaintextLength = 50000; // Large size
        int inputOffset = 0;
        int outputOffset = plaintextLength; // Adjacent
        int totalBufferSize = outputOffset + plaintextLength + GCM_TAG_LENGTH_BYTES;

        byte[] sharedBuffer = sequentialBytes(totalBufferSize, (byte) 0);

        encryptAndDecrypt(sharedBuffer, inputOffset, plaintextLength, outputOffset, true);
    }

    @Test
    public void aesGcm_LargePlaintext_BackwardOverlap() throws Exception {
        int plaintextLength = 50000;
        int inputOffset = 100; // Offset input a bit
        int outputOffset = 0; // Output at start, causing backward overlap
        int totalBufferSize = inputOffset + plaintextLength + GCM_TAG_LENGTH_BYTES;

        byte[] sharedBuffer = sequentialBytes(totalBufferSize, (byte) 0);

        encryptAndDecrypt(sharedBuffer, inputOffset, plaintextLength, outputOffset, true);
    }

    @Test
    public void aesGcm_LargePlaintext_BackwardWithEnoughSpace() throws Exception {
        int plaintextLength = 100;
        int inputOffset = 109; // Offset input with enough space for output
        int outputOffset = 0; // Output at start, causing backward overlap
        int totalBufferSize = inputOffset + plaintextLength + GCM_TAG_LENGTH_BYTES;

        byte[] sharedBuffer = sequentialBytes(totalBufferSize, (byte) 0);

        encryptAndDecrypt(sharedBuffer, inputOffset, plaintextLength, outputOffset, true);
    }

    @Test
    public void aesGcm_TinyPlaintext_VariousOverlaps() throws Exception {
        int plaintextLength = 1; // Smallest possible
        int totalBufferSize = 10 + GCM_TAG_LENGTH_BYTES; // Small buffer but sufficient

        // Exact overlap
        encryptAndDecrypt(sequentialBytes(totalBufferSize, (byte) 0), 0, plaintextLength, 0, true);
        // Backward overlap
        encryptAndDecrypt(sequentialBytes(totalBufferSize, (byte) 0), 5, plaintextLength, 0, true);
        // Forward overlap
        encryptAndDecrypt(sequentialBytes(totalBufferSize, (byte) 0), 0, plaintextLength, 5, true);
        // Adjacent
        encryptAndDecrypt(sequentialBytes(totalBufferSize, (byte) 0), 0, plaintextLength,
                plaintextLength, true);
    }
}
