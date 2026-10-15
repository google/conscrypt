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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KDF;
import javax.crypto.KDFParameters;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@SuppressWarnings("NewApi")
@RunWith(JUnit4.class)
public class OpenSslHkdfTest {
    // RFC 5869 Test Case 1 (SHA-256)
    private static final byte[] RFC5869_TC1_IKM =
            TestUtils.decodeHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    private static final byte[] RFC5869_TC1_SALT =
            TestUtils.decodeHex("000102030405060708090a0b0c");
    private static final byte[] RFC5869_TC1_INFO = TestUtils.decodeHex("f0f1f2f3f4f5f6f7f8f9");
    private static final int RFC5869_TC1_L = 42;
    private static final byte[] RFC5869_TC1_PRK =
            TestUtils.decodeHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    private static final byte[] RFC5869_TC1_OKM = TestUtils.decodeHex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    // RFC 5869 Test Case 2 (SHA-256 with long inputs)
    private static final byte[] RFC5869_TC2_IKM =
            TestUtils.decodeHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                                + "404142434445464748494a4b4c4d4e4f");
    private static final byte[] RFC5869_TC2_SALT =
            TestUtils.decodeHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                                + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                                + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    private static final byte[] RFC5869_TC2_INFO =
            TestUtils.decodeHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                                + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                                + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    private static final int RFC5869_TC2_L = 82;
    private static final byte[] RFC5869_TC2_PRK =
            TestUtils.decodeHex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
    private static final byte[] RFC5869_TC2_OKM =
            TestUtils.decodeHex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                                + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                                + "cc30c58179ec3e87c14c01d5c1f3434f1d87");

    // RFC 5869 Test Case 3 (SHA-256 zero-length salt/info)
    private static final byte[] RFC5869_TC3_IKM =
            TestUtils.decodeHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    private static final int RFC5869_TC3_L = 42;
    private static final byte[] RFC5869_TC3_PRK =
            TestUtils.decodeHex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    private static final byte[] RFC5869_TC3_OKM =
            TestUtils.decodeHex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                                + "9d201395faa4b61a96c8");

    @Test
    public void testParametersNotSupported() {
        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> new OpenSslHkdf.HkdfSha256(new KDFParameters() {}));
    }

    @Test
    public void testEngineGetParameters() throws Exception {
        OpenSslHkdf kdf = new OpenSslHkdf.HkdfSha256(null);
        assertNull(kdf.engineGetParameters());
    }

    @Test
    public void testRfc5869TestCase1_Extract() throws Exception {
        OpenSslHkdf kdf = new OpenSslHkdf.HkdfSha256(null);
        HKDFParameterSpec spec = HKDFParameterSpec.ofExtract()
                                         .addIKM(RFC5869_TC1_IKM)
                                         .addSalt(RFC5869_TC1_SALT)
                                         .extractOnly();

        byte[] prk = kdf.engineDeriveData(spec);
        assertArrayEquals(RFC5869_TC1_PRK, prk);
    }

    @Test
    public void testRfc5869TestCase1_Expand() throws Exception {
        OpenSslHkdf kdf = new OpenSslHkdf.HkdfSha256(null);
        SecretKey prkKey = new SecretKeySpec(RFC5869_TC1_PRK, "Generic");
        HKDFParameterSpec spec =
                HKDFParameterSpec.expandOnly(prkKey, RFC5869_TC1_INFO, RFC5869_TC1_L);

        byte[] okm = kdf.engineDeriveData(spec);
        assertArrayEquals(RFC5869_TC1_OKM, okm);
    }

    @Test
    public void testRfc5869TestCase1_ExtractThenExpand() throws Exception {
        OpenSslHkdf kdf = new OpenSslHkdf.HkdfSha256(null);
        HKDFParameterSpec spec = HKDFParameterSpec.ofExtract()
                                         .addIKM(RFC5869_TC1_IKM)
                                         .addSalt(RFC5869_TC1_SALT)
                                         .thenExpand(RFC5869_TC1_INFO, RFC5869_TC1_L);

        byte[] okm = kdf.engineDeriveData(spec);
        assertArrayEquals(RFC5869_TC1_OKM, okm);

        SecretKey derivedKey = kdf.engineDeriveKey("AES", spec);
        assertEquals("AES", derivedKey.getAlgorithm());
        assertArrayEquals(RFC5869_TC1_OKM, derivedKey.getEncoded());
    }

    @Test
    public void testRfc5869TestCase2_ExtractThenExpand() throws Exception {
        OpenSslHkdf kdf = new OpenSslHkdf.HkdfSha256(null);
        HKDFParameterSpec spec = HKDFParameterSpec.ofExtract()
                                         .addIKM(RFC5869_TC2_IKM)
                                         .addSalt(RFC5869_TC2_SALT)
                                         .thenExpand(RFC5869_TC2_INFO, RFC5869_TC2_L);

        byte[] okm = kdf.engineDeriveData(spec);
        assertArrayEquals(RFC5869_TC2_OKM, okm);
    }

    @Test
    public void testRfc5869TestCase3_NoSaltNoInfo() throws Exception {
        OpenSslHkdf kdf = new OpenSslHkdf.HkdfSha256(null);
        HKDFParameterSpec spec = HKDFParameterSpec.ofExtract()
                                         .addIKM(RFC5869_TC3_IKM)
                                         .thenExpand(null, RFC5869_TC3_L);

        byte[] okm = kdf.engineDeriveData(spec);
        assertArrayEquals(RFC5869_TC3_OKM, okm);
    }

    @Test
    public void testMultipleIKMsAndSaltsConcatenation() throws Exception {
        OpenSslHkdf kdf = new OpenSslHkdf.HkdfSha256(null);

        // Split RFC5869_TC1_IKM into 2 pieces: 10 bytes and 12 bytes
        byte[] ikmPart1 = new byte[10];
        byte[] ikmPart2 = new byte[12];
        System.arraycopy(RFC5869_TC1_IKM, 0, ikmPart1, 0, 10);
        System.arraycopy(RFC5869_TC1_IKM, 10, ikmPart2, 0, 12);

        // Split RFC5869_TC1_SALT into 2 pieces: 6 bytes and 7 bytes
        byte[] saltPart1 = new byte[6];
        byte[] saltPart2 = new byte[7];
        System.arraycopy(RFC5869_TC1_SALT, 0, saltPart1, 0, 6);
        System.arraycopy(RFC5869_TC1_SALT, 6, saltPart2, 0, 7);

        HKDFParameterSpec spec = HKDFParameterSpec.ofExtract()
                                         .addIKM(ikmPart1)
                                         .addIKM(ikmPart2)
                                         .addSalt(saltPart1)
                                         .addSalt(saltPart2)
                                         .thenExpand(RFC5869_TC1_INFO, RFC5869_TC1_L);

        byte[] okm = kdf.engineDeriveData(spec);
        assertArrayEquals(RFC5869_TC1_OKM, okm);
    }

    @Test
    public void testInvalidParameters() throws Exception {
        OpenSslHkdf kdf = new OpenSslHkdf.HkdfSha256(null);

        // Null derivationSpec
        assertThrows(NullPointerException.class, () -> kdf.engineDeriveData(null));

        // Unsupported derivationSpec
        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> kdf.engineDeriveData(new AlgorithmParameterSpec() {}));

        // Empty IKM in Extract
        HKDFParameterSpec emptyIkmExtract = HKDFParameterSpec.ofExtract().extractOnly();
        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> kdf.engineDeriveData(emptyIkmExtract));

        // Empty alg name in deriveKey
        HKDFParameterSpec validSpec = HKDFParameterSpec.ofExtract()
                                              .addIKM(RFC5869_TC1_IKM)
                                              .thenExpand(RFC5869_TC1_INFO, RFC5869_TC1_L);
        assertThrows(NoSuchAlgorithmException.class, () -> kdf.engineDeriveKey("", validSpec));
        assertThrows(NullPointerException.class, () -> kdf.engineDeriveKey(null, validSpec));

        // Output length > 255 * HashLen (255 * 32 + 1 = 8161 for SHA-256)
        HKDFParameterSpec tooLongExpand = HKDFParameterSpec.expandOnly(
                new SecretKeySpec(RFC5869_TC1_PRK, "RAW"), RFC5869_TC1_INFO, 255 * 32 + 1);
        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> kdf.engineDeriveData(tooLongExpand));
        HKDFParameterSpec tooLongExtractThenExpand =
                HKDFParameterSpec.ofExtract()
                        .addIKM(RFC5869_TC1_IKM)
                        .thenExpand(RFC5869_TC1_INFO, 255 * 32 + 1);
        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> kdf.engineDeriveData(tooLongExtractThenExpand));
    }

    @Test
    public void testNonRawKeyFormatRejection() throws Exception {
        OpenSslHkdf kdf = new OpenSslHkdf.HkdfSha256(null);
        SecretKey nonRawKey = new SecretKey() {
            @Override
            public String getAlgorithm() {
                return "Generic";
            }
            @Override
            public String getFormat() {
                return "PKCS#8";
            }
            @Override
            public byte[] getEncoded() {
                return new byte[32];
            }
        };

        HKDFParameterSpec specExpand =
                HKDFParameterSpec.expandOnly(nonRawKey, RFC5869_TC1_INFO, 32);
        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> kdf.engineDeriveData(specExpand));

        HKDFParameterSpec specExtract =
                HKDFParameterSpec.ofExtract().addIKM(nonRawKey).extractOnly();
        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> kdf.engineDeriveData(specExtract));
    }

    @Test
    public void testHKDFSHA384AndSHA512() throws Exception {
        OpenSslHkdf kdf384 = new OpenSslHkdf.HkdfSha384(null);
        HKDFParameterSpec spec384 = HKDFParameterSpec.ofExtract()
                                            .addIKM(RFC5869_TC1_IKM)
                                            .thenExpand(RFC5869_TC1_INFO, 48);
        byte[] okm384 = kdf384.engineDeriveData(spec384);
        assertEquals(48, okm384.length);

        OpenSslHkdf kdf512 = new OpenSslHkdf.HkdfSha512(null);
        HKDFParameterSpec spec512 = HKDFParameterSpec.ofExtract()
                                            .addIKM(RFC5869_TC1_IKM)
                                            .thenExpand(RFC5869_TC1_INFO, 64);
        byte[] okm512 = kdf512.engineDeriveData(spec512);
        assertEquals(64, okm512.length);
    }

    @Test
    public void testJceApi_Rfc5869AndAlgorithms() throws Exception {
        if (!Platform.isPqcKemKdfSupported()) {
            return;
        }
        Provider provider = TestUtils.getConscryptProvider();
        KDF kdf256 = KDF.getInstance("HKDF-SHA256", provider);

        // 1. Extract-only (RFC 5869 Test Case 1)
        HKDFParameterSpec extractSpec = HKDFParameterSpec.ofExtract()
                                                .addIKM(RFC5869_TC1_IKM)
                                                .addSalt(RFC5869_TC1_SALT)
                                                .extractOnly();
        assertArrayEquals(RFC5869_TC1_PRK, kdf256.deriveData(extractSpec));
        SecretKey prkKey = kdf256.deriveKey("Generic", extractSpec);
        assertEquals("Generic", prkKey.getAlgorithm());
        assertArrayEquals(RFC5869_TC1_PRK, prkKey.getEncoded());

        // 2. Expand-only (RFC 5869 Test Case 1)
        HKDFParameterSpec expandSpec =
                HKDFParameterSpec.expandOnly(prkKey, RFC5869_TC1_INFO, RFC5869_TC1_L);
        assertArrayEquals(RFC5869_TC1_OKM, kdf256.deriveData(expandSpec));
        SecretKey expandedKey = kdf256.deriveKey("AES", expandSpec);
        assertEquals("AES", expandedKey.getAlgorithm());
        assertArrayEquals(RFC5869_TC1_OKM, expandedKey.getEncoded());

        // 3. Extract-then-expand (RFC 5869 Test Case 1 & Test Case 3 with no salt/info)
        HKDFParameterSpec extractThenExpandSpec =
                HKDFParameterSpec.ofExtract()
                        .addIKM(RFC5869_TC1_IKM)
                        .addSalt(RFC5869_TC1_SALT)
                        .thenExpand(RFC5869_TC1_INFO, RFC5869_TC1_L);
        assertArrayEquals(RFC5869_TC1_OKM, kdf256.deriveData(extractThenExpandSpec));
        SecretKey derivedKey = kdf256.deriveKey("AES", extractThenExpandSpec);
        assertEquals("AES", derivedKey.getAlgorithm());
        assertArrayEquals(RFC5869_TC1_OKM, derivedKey.getEncoded());

        HKDFParameterSpec tc3Spec = HKDFParameterSpec.ofExtract()
                                            .addIKM(RFC5869_TC3_IKM)
                                            .thenExpand(null, RFC5869_TC3_L);
        assertArrayEquals(RFC5869_TC3_OKM, kdf256.deriveData(tc3Spec));

        // 4. Other HKDF hash variants (HKDF-SHA384, HKDF-SHA512, HKDF-SHA1)
        assertEquals(
                48,
                KDF.getInstance("HKDF-SHA384", provider)
                        .deriveData(
                                HKDFParameterSpec.ofExtract().addIKM(RFC5869_TC1_IKM).extractOnly())
                        .length);
        assertEquals(
                64,
                KDF.getInstance("HKDF-SHA512", provider)
                        .deriveData(
                                HKDFParameterSpec.ofExtract().addIKM(RFC5869_TC1_IKM).extractOnly())
                        .length);
        assertEquals(
                20,
                KDF.getInstance("HKDF-SHA1", provider)
                        .deriveData(
                                HKDFParameterSpec.ofExtract().addIKM(RFC5869_TC1_IKM).extractOnly())
                        .length);
    }
}
