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
import static org.conscrypt.TestUtils.encodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.nio.ByteBuffer;
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
import org.conscrypt.HpkeAlgorithmIdentifier;
import org.conscrypt.HpkeAlgorithmIdentifier.AEAD;
import org.conscrypt.HpkeAlgorithmIdentifier.KDF;
import org.conscrypt.HpkeAlgorithmIdentifier.KEM;
import org.conscrypt.HpkeParameterSpec;
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

    private static final Map<String, String> HPKE_ENC_CIPHER_TO_TEST_DATA = new HashMap<>();
    static {
        HPKE_ENC_CIPHER_TO_TEST_DATA.put("HPKE", "crypto/hpke/hpke-encryption.csv");
    }

    private static final Map<String, String> HPKE_EXP_CIPHER_TO_TEST_DATA = new HashMap<>();
    static {
        HPKE_EXP_CIPHER_TO_TEST_DATA.put("HPKE", "crypto/hpke/hpke-export.csv");
    }

    private static final int KEY_INDEX = 0;
    private static final int IV_INDEX = 1;
    private static final int PLAINTEXT_INDEX = 2;
    private static final int CIPHERTEXT_INDEX = 3;
    private static final int TAG_INDEX = 4;
    private static final int AAD_INDEX = 5;

    private static final int HPKE_KEM_ID = 0;
    private static final int HPKE_KDF_ID = 1;
    private static final int HPKE_AEAD_ID = 2;
    private static final int HPKE_INFO = 3;
    private static final int HPKE_SECRET_KEY_RECIPIENT = 4;
    private static final int HPKE_SECRET_KEY_EPHEMERAL = 5;
    private static final int HPKE_PUBLIC_KEY_RECIPIENT = 6;
    private static final int HPKE_PUBLIC_KEY_EPHEMERAL = 7;
    private static final int HPKE_AAD = 8;
    private static final int HPKE_CIPHERTEXT = 9;
    private static final int HPKE_PLAINTEXT = 10;
    private static final int HPKE_EXPORTER_CONTEXT = 8;
    private static final int HPKE_L = 9;
    private static final int HPKE_EXPORTED_VALUE = 10;

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
                        cipher.init(Cipher.ENCRYPT_MODE, key, params);
                        assertEquals("Provider " + p.getName()
                                        + ", algorithm " + transformation
                                        + " reported the wrong output size",
                                ciphertext.length, cipher.getOutputSize(plaintext.length));
                        assertArrayEquals("Provider " + p.getName()
                                + ", algorithm " + transformation
                                + " failed on encryption, data is " + Arrays.toString(line),
                                ciphertext, cipher.doFinal(plaintext));

                        cipher.init(Cipher.DECRYPT_MODE, key, params);
                        assertEquals("Provider " + p.getName()
                                        + ", algorithm " + transformation
                                        + " reported the wrong output size",
                                plaintext.length, cipher.getOutputSize(ciphertext.length));
                        assertArrayEquals("Provider " + p.getName()
                                + ", algorithm " + transformation
                                + " failed on decryption, data is " + Arrays.toString(line),
                                plaintext, cipher.doFinal(ciphertext));
                    } catch (InvalidKeyException e) {
                        // Some providers may not support raw SecretKeySpec keys, that's allowed
                    }
                }
            }
        }
    }

    public void arrayBasedAssessment(Cipher cipher, byte[] aad, byte[] tag, byte[] plaintext,
                                     byte[] ciphertext, Key key, AlgorithmParameterSpec params,
                                     String transformation, Provider p, String[] line) throws Exception {
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
        assertArrayEquals("Provider " + p.getName()
                + ", algorithm " + transformation
                + " failed on encryption, data is " + Arrays.toString(line),
                combinedOutput, cipher.doFinal(plaintext));

        cipher.init(Cipher.DECRYPT_MODE, key, params);
        if (aad.length > 0) {
            cipher.updateAAD(aad);
        }
        assertEquals("Provider " + p.getName()
                        + ", algorithm " + transformation
                        + " reported the wrong output size",
                plaintext.length, cipher.getOutputSize(combinedOutput.length));
        assertArrayEquals("Provider " + p.getName()
                + ", algorithm " + transformation
                + " failed on decryption, data is " + Arrays.toString(line),
                plaintext, cipher.doFinal(combinedOutput));
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
                    }
                }
            }
        }
    }

    public void sharedBufferBasedAssessment(Cipher cipher, byte[] aad, byte[] tag, byte[] _plaintext,
                                      byte[] _ciphertext, Key key, AlgorithmParameterSpec params,
                                      String transformation, Provider p) throws Exception {
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

    @Test
    public void testHpkeBasicEncryption() throws Exception {
        final Provider conscryptProvider = TestUtils.getConscryptProvider();
        for (Map.Entry<String, String> entry : HPKE_ENC_CIPHER_TO_TEST_DATA.entrySet()) {
            final String transformation = entry.getKey();
            final Cipher cipher = Cipher.getInstance(transformation, conscryptProvider);
            final List<HpkeData> records = getHpkeEncryptionRecords(entry.getValue(), transformation);
            for (HpkeData record : records) {
                testHpkeEncryption(cipher, transformation, record);
            }
        }
    }

    @Test
    public void testHpkeBasicExport() throws Exception {
        final Provider conscryptProvider = TestUtils.getConscryptProvider();
        for (Map.Entry<String, String> entry : HPKE_EXP_CIPHER_TO_TEST_DATA.entrySet()) {
            final String transformation = entry.getKey();
            final Cipher cipher = Cipher.getInstance(transformation, conscryptProvider);
            final List<HpkeData> records = getHpkeSecretExportRecords(entry.getValue(), transformation);
            for (HpkeData record : records) {
                testHpkeExport(cipher, transformation, record);
            }
        }
    }

    private void testHpkeEncryption(Cipher cipher, String transformation, HpkeData record)
            throws Exception {
        final byte[] enc = record.pkEm.getEncoded();

        // Encryption
        final HpkeParameterSpec encryptSpec = createHpkeEncryptionSpec(record, /* encrypting= */ true);
        cipher.init(Cipher.ENCRYPT_MODE, record.pkRm, encryptSpec);
        for (HpkeEncryptionData encryption : record.encryptions) {
            cipher.updateAAD(encryption.aad);

            assertEquals("Algorithm " + transformation + " reported the wrong output size",
                enc.length + encryption.ct.length, cipher.getOutputSize(encryption.pt.length));

            final byte[] encAndCt = cipher.update(encryption.pt);
            final byte[] ct = encryptSpec.getAlgorithmIdentifier().getKem().extract(encAndCt).getCt();
            assertArrayEquals("Algorithm " + transformation + " failed encryption on data : " + encryption,
                encryption.ct, ct);
        }
        cipher.doFinal();

        // Decryption
        final HpkeParameterSpec decryptSpec = createHpkeEncryptionSpec(record, /* encrypting= */ false);
        cipher.init(Cipher.DECRYPT_MODE, record.skRm, decryptSpec);
        for (HpkeEncryptionData encryption : record.encryptions) {
            cipher.updateAAD(encryption.aad);

            assertEquals("Algorithm " + transformation + " reported the wrong output size",
                encryption.pt.length, cipher.getOutputSize(encryption.ct.length));

            assertArrayEquals("Algorithm " + transformation + " failed decryption on data : " + encryption,
                encryption.pt,  cipher.update(encryption.ct));
        }
        cipher.doFinal();
    }

    private void testHpkeExport(Cipher cipher, String transformation, HpkeData record)
            throws Exception {
        final byte[] enc = record.pkEm.getEncoded();

        // Send secret export
        for (HpkeExporterData exporterData : record.exports) {
            final HpkeParameterSpec sendSecretExportSpec =
                createHpkeSecretExportsParams(record,  exporterData.l, /* sendingExport= */ true);
            cipher.init(Cipher.ENCRYPT_MODE, record.pkRm, sendSecretExportSpec);

            assertEquals("Algorithm " + transformation + " reported the wrong output size",
                enc.length + exporterData.l, cipher.getOutputSize(exporterData.exporterContext.length));

            final byte[] encAndExp = cipher.doFinal(exporterData.exporterContext);
            final byte[] exported = sendSecretExportSpec.getAlgorithmIdentifier().getKem().extract(encAndExp).getCt();
            assertArrayEquals("Algorithm " + transformation + " failed encryption on data : " + exporterData,
                exporterData.exportedValue, exported);
        }

        // Receive secret export
        for (HpkeExporterData exporterData : record.exports) {
            final HpkeParameterSpec receiveSecretExportSpec =
                createHpkeSecretExportsParams(record,  exporterData.l, /* sendingExport= */ false);
            cipher.init(Cipher.DECRYPT_MODE, record.skRm, receiveSecretExportSpec);

            assertEquals("Algorithm " + transformation + " reported the wrong output size",
                exporterData.l + enc.length, cipher.getOutputSize(exporterData.exporterContext.length));

            final byte[] encAndExp = cipher.doFinal(exporterData.exporterContext);
            final byte[] exportedValue = receiveSecretExportSpec.getAlgorithmIdentifier().getKem().extract(encAndExp).getCt();
            assertArrayEquals("Algorithm " + transformation + " failed encryption on data : " + exporterData,
                exporterData.exportedValue, exportedValue);
        }
    }

    private HpkeParameterSpec createHpkeEncryptionSpec(HpkeData record, boolean encrypting) {
        final byte[] enc = record.pkEm.getEncoded();
        final byte[] iv = record.skEm.getEncoded();

        final HpkeAlgorithmIdentifier id = new HpkeAlgorithmIdentifier(record.kem, record.kdf, record.aead);
        return encrypting ?
            new HpkeParameterSpec.Builder(id).modeBaseEncryption().info(record.info).iv(iv).build() :
            new HpkeParameterSpec.Builder(id).modeBaseDecryption(enc).info(record.info).iv(iv).build();
    }

    private HpkeParameterSpec createHpkeSecretExportsParams(HpkeData record, int l, boolean sendingExport) {
        final byte[] enc = record.pkEm.getEncoded();
        final byte[] iv = record.skEm.getEncoded();

        final HpkeAlgorithmIdentifier id = new HpkeAlgorithmIdentifier(record.kem, record.kdf, record.aead);
        return sendingExport ?
            new HpkeParameterSpec.Builder(id).modeBaseSendExport(l).info(record.info).iv(iv).build() :
            new HpkeParameterSpec.Builder(id).modeBaseReceiveExport(enc, l).info(record.info).iv(iv).build();
    }

    private List<HpkeData> getHpkeEncryptionRecords(String resourceName, String transformation)
            throws IOException {
        final List<HpkeData> records = new ArrayList<>();
        final List<String[]> data = TestUtils.readCsvResource(resourceName);
        for (String[] line : data) {
            if (!line[0].isEmpty()) {
                final HpkeData record = new HpkeData();
                record.kem = convertKem(line[HPKE_KEM_ID]);
                record.kdf = convertKdf(line[HPKE_KDF_ID]);
                record.aead = convertAead(line[HPKE_AEAD_ID]);
                record.info = decodeHex(line[HPKE_INFO]);
                record.skRm = new SecretKeySpec(
                    decodeHex(line[HPKE_SECRET_KEY_RECIPIENT]), getBaseAlgorithm(transformation));
                record.skEm = new SecretKeySpec(
                    decodeHex(line[HPKE_SECRET_KEY_EPHEMERAL]), getBaseAlgorithm(transformation));
                record.pkRm = new SecretKeySpec(
                    decodeHex(line[HPKE_PUBLIC_KEY_RECIPIENT]), getBaseAlgorithm(transformation));
                record.pkEm = new SecretKeySpec(
                    decodeHex(line[HPKE_PUBLIC_KEY_EPHEMERAL]), getBaseAlgorithm(transformation));
                final HpkeEncryptionData encryptionData = new HpkeEncryptionData();
                encryptionData.aad = decodeHex(line[HPKE_AAD]);
                encryptionData.ct = decodeHex(line[HPKE_CIPHERTEXT]);
                encryptionData.pt = decodeHex(line[HPKE_PLAINTEXT]);
                record.encryptions = new ArrayList<>();
                record.encryptions.add(encryptionData);
                records.add(record);
            } else {
                final HpkeEncryptionData encryptionData = new HpkeEncryptionData();
                encryptionData.aad = decodeHex(line[HPKE_AAD]);
                encryptionData.ct = decodeHex(line[HPKE_CIPHERTEXT]);
                encryptionData.pt = decodeHex(line[HPKE_PLAINTEXT]);
                final int lastRecord = records.size() - 1;
                records.get(lastRecord).encryptions.add(encryptionData);
            }
        }
        return records;
    }

    private List<HpkeData> getHpkeSecretExportRecords(String resourceName, String transformation)
            throws IOException {
        final List<HpkeData> records = new ArrayList<>();
        final List<String[]> data = TestUtils.readCsvResource(resourceName);
        for (String[] line : data) {
            if (!line[0].isEmpty()) {
                final HpkeData record = new HpkeData();
                record.kem = convertKem(line[HPKE_KEM_ID]);
                record.kdf = convertKdf(line[HPKE_KDF_ID]);
                record.aead = convertAead(line[HPKE_AEAD_ID]);
                record.info = decodeHex(line[HPKE_INFO]);
                record.skRm = new SecretKeySpec(
                    decodeHex(line[HPKE_SECRET_KEY_RECIPIENT]), getBaseAlgorithm(transformation));
                record.skEm = new SecretKeySpec(
                    decodeHex(line[HPKE_SECRET_KEY_EPHEMERAL]), getBaseAlgorithm(transformation));
                record.pkRm = new SecretKeySpec(
                    decodeHex(line[HPKE_PUBLIC_KEY_RECIPIENT]), getBaseAlgorithm(transformation));
                record.pkEm = new SecretKeySpec(
                    decodeHex(line[HPKE_PUBLIC_KEY_EPHEMERAL]), getBaseAlgorithm(transformation));
                final HpkeExporterData exporterData = new HpkeExporterData();
                exporterData.exporterContext = decodeHex(line[HPKE_EXPORTER_CONTEXT]);
                exporterData.l = Integer.parseInt(line[HPKE_L]);
                exporterData.exportedValue = decodeHex(line[HPKE_EXPORTED_VALUE]);
                record.exports = new ArrayList<>();
                record.exports.add(exporterData);
                records.add(record);
            } else {
                final HpkeExporterData exporterData = new HpkeExporterData();
                exporterData.exporterContext = decodeHex(line[HPKE_EXPORTER_CONTEXT]);
                exporterData.l = Integer.parseInt(line[HPKE_L]);
                exporterData.exportedValue = decodeHex(line[HPKE_EXPORTED_VALUE]);
                final int lastRecord = records.size() - 1;
                records.get(lastRecord).exports.add(exporterData);
            }
        }
        return records;
    }

    private AEAD convertAead(String aeadId) {
        switch (aeadId) {
            case "1":
                return AEAD.AES_128_GCM;
            case "2":
                return AEAD.AES_256_GCM;
            case "3":
                return AEAD.CHACHA20POLY1305;
            case "65535":
                return AEAD.EXPORT_ONLY_AEAD;
            default:
                throw new IllegalArgumentException("Invalid AEAD " + aeadId);
        }
    }

    private KEM convertKem(String kemId) {
        switch (kemId) {
            case "16":
                return KEM.DHKEM_P_256_HKDF_SHA256;
            case "17":
                return KEM.DHKEM_P_384_HKDF_SHA384;
            case "18":
                return KEM.DHKEM_P_521_HKDF_SHA512;
            case "32":
                return KEM.DHKEM_X25519_HKDF_SHA256;
            case "33":
                return KEM.DHKEM_X448_HKDF_SHA512;
            default:
                throw new IllegalArgumentException("Invalid KEM " + kemId);
        }
    }

    private KDF convertKdf(String kdfId) {
        switch (kdfId) {
            case "1":
                return KDF.HKDF_SHA256;
            case "2":
                return KDF.HKDF_SHA384;
            case "3":
                return KDF.HKDF_SHA512;
            default:
                throw new IllegalArgumentException("Invalid KDF " + kdfId);
        }
    }

    private static class HpkeData {
        KEM kem;
        KDF kdf;
        AEAD aead;
        byte[] info;
        Key skRm;
        Key skEm;
        Key pkRm;
        Key pkEm;
        List<HpkeEncryptionData> encryptions;
        List<HpkeExporterData> exports;

        @Override
        public String toString() {
            return "HpkeData{" +
                "kem=" + kem +
                ", kdf=" + kdf +
                ", aead=" + aead +
                ", info=" + encodeHex(info) +
                ", skRm=" + encodeHex(skRm.getEncoded()) +
                ", skEm=" + encodeHex(skEm.getEncoded()) +
                ", pkRm=" + encodeHex(pkRm.getEncoded()) +
                ", pkEm=" + encodeHex(pkEm.getEncoded()) +
                ", encryptions=" + encryptions +
                '}';
        }
    }

    private static class HpkeEncryptionData {
        byte[] aad;
        byte[] ct;
        byte[] pt;

        @Override
        public String toString() {
            return "HpkeEncryptionData{" +
                "aad=" + encodeHex(aad) +
                ", ct=" + encodeHex(ct) +
                ", pt=" + encodeHex(pt) +
                '}';
        }
    }

    private static class HpkeExporterData {
        byte[] exporterContext;
        int l;
        byte[] exportedValue;

        @Override
        public String toString() {
            return "HpkeExporterData{" +
                "exporter_context=" + encodeHex(exporterContext) +
                ", L=" + l +
                ", exported_value=" + encodeHex(exportedValue) +
                '}';
        }
    }
}
