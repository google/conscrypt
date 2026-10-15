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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.Objects;

import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * OpenSSL Key Derivation Function (KDF) implementation supporting HKDF algorithms per RFC 5869.
 */
@android.annotation.Hide
@SuppressWarnings("NewApi")
public abstract class OpenSslHkdf extends KDFSpi {
    private final Hkdf hkdf;

    protected OpenSslHkdf(String hmacAlgorithm, KDFParameters kdfParameters)
            throws InvalidAlgorithmParameterException {
        super(kdfParameters);
        if (kdfParameters != null) {
            throw new InvalidAlgorithmParameterException("KDFParameters are not supported");
        }
        Objects.requireNonNull(hmacAlgorithm, "hmacAlgorithm == null");
        try {
            this.hkdf = new Hkdf(hmacAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("Standard HMAC algorithm unavailable: " + hmacAlgorithm, e);
        }
    }

    @Override
    public KDFParameters engineGetParameters() {
        return null;
    }

    @Override
    public SecretKey engineDeriveKey(String alg, AlgorithmParameterSpec derivationSpec)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        Objects.requireNonNull(alg, "alg == null");
        if (alg.isEmpty()) {
            throw new NoSuchAlgorithmException("Algorithm name cannot be empty");
        }
        byte[] keyBytes = engineDeriveData(derivationSpec);
        return new SecretKeySpec(keyBytes, alg);
    }

    @Override
    public byte[] engineDeriveData(AlgorithmParameterSpec derivationSpec)
            throws InvalidAlgorithmParameterException {
        Objects.requireNonNull(derivationSpec, "derivationSpec == null");
        if (derivationSpec instanceof HKDFParameterSpec.Extract) {
            return deriveExtract((HKDFParameterSpec.Extract) derivationSpec);
        } else if (derivationSpec instanceof HKDFParameterSpec.Expand) {
            return deriveExpand((HKDFParameterSpec.Expand) derivationSpec);
        } else if (derivationSpec instanceof HKDFParameterSpec.ExtractThenExpand) {
            return deriveExtractThenExpand((HKDFParameterSpec.ExtractThenExpand) derivationSpec);
        } else {
            throw new InvalidAlgorithmParameterException("Unsupported derivationSpec: "
                                                         + derivationSpec.getClass().getName());
        }
    }

    private byte[] deriveExtract(HKDFParameterSpec.Extract extract)
            throws InvalidAlgorithmParameterException {
        byte[] ikm = concatKeys(extract.ikms(), "IKM");
        if (ikm.length == 0) {
            throw new InvalidAlgorithmParameterException(
                    "Input keying material (IKM) must not be empty");
        }
        byte[] salt = concatKeys(extract.salts(), "salt");
        try {
            return hkdf.extract(salt, ikm);
        } catch (InvalidKeyException | IllegalArgumentException e) {
            throw new InvalidAlgorithmParameterException("HKDF extract failed", e);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("Standard HMAC algorithm unavailable", e);
        }
    }

    private byte[] deriveExpand(HKDFParameterSpec.Expand expand)
            throws InvalidAlgorithmParameterException {
        SecretKey prkKey = expand.prk();
        if (prkKey == null) {
            throw new InvalidAlgorithmParameterException("PRK must not be null");
        }
        if (!"RAW".equalsIgnoreCase(prkKey.getFormat())) {
            throw new InvalidAlgorithmParameterException("PRK must be in RAW format, but was: "
                                                         + prkKey.getFormat());
        }
        byte[] prk = prkKey.getEncoded();
        if (prk == null) {
            throw new InvalidAlgorithmParameterException("PRK is not extractable");
        }
        if (prk.length < hkdf.getMacLength()) {
            throw new InvalidAlgorithmParameterException("PRK length (" + prk.length
                                                         + ") is less than HashLen ("
                                                         + hkdf.getMacLength() + ")");
        }
        byte[] info = expand.info();
        if (info == null) {
            info = new byte[0];
        }
        int length = expand.length();
        try {
            return hkdf.expand(prk, info, length);
        } catch (InvalidKeyException | IllegalArgumentException e) {
            throw new InvalidAlgorithmParameterException("HKDF expand failed", e);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("Standard HMAC algorithm unavailable", e);
        }
    }

    private byte[] deriveExtractThenExpand(HKDFParameterSpec.ExtractThenExpand extractThenExpand)
            throws InvalidAlgorithmParameterException {
        byte[] ikm = concatKeys(extractThenExpand.ikms(), "IKM");
        if (ikm.length == 0) {
            throw new InvalidAlgorithmParameterException(
                    "Input keying material (IKM) must not be empty");
        }
        byte[] salt = concatKeys(extractThenExpand.salts(), "salt");
        byte[] info = extractThenExpand.info();
        if (info == null) {
            info = new byte[0];
        }
        int length = extractThenExpand.length();
        try {
            byte[] prk = hkdf.extract(salt, ikm);
            return hkdf.expand(prk, info, length);
        } catch (InvalidKeyException | IllegalArgumentException e) {
            throw new InvalidAlgorithmParameterException("HKDF extract-then-expand failed", e);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("Standard HMAC algorithm unavailable", e);
        }
    }

    private static byte[] concatKeys(List<SecretKey> keys, String name)
            throws InvalidAlgorithmParameterException {
        if (keys == null || keys.isEmpty()) {
            return new byte[0];
        }
        int totalLen = 0;
        byte[][] encodedKeys = new byte[keys.size()][];
        for (int i = 0; i < keys.size(); i++) {
            SecretKey key = keys.get(i);
            if (key == null) {
                throw new InvalidAlgorithmParameterException("Null " + name + " in key list");
            }
            if (!"RAW".equalsIgnoreCase(key.getFormat())) {
                throw new InvalidAlgorithmParameterException(
                        name + " key must be in RAW format, but was: " + key.getFormat());
            }
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidAlgorithmParameterException(
                        name + " key does not provide encoded bytes (unextractable)");
            }
            encodedKeys[i] = encoded;
            totalLen += encoded.length;
        }
        if (keys.size() == 1) {
            return encodedKeys[0];
        }
        byte[] result = new byte[totalLen];
        int pos = 0;
        for (byte[] encoded : encodedKeys) {
            System.arraycopy(encoded, 0, result, pos, encoded.length);
            pos += encoded.length;
        }
        if (pos != totalLen) {
            throw new IllegalArgumentException("Unexpected concatenated key length");
        }
        return result;
    }

    public static final class HkdfSha256 extends OpenSslHkdf {
        public HkdfSha256(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException {
            super("HmacSHA256", kdfParameters);
        }
    }

    public static final class HkdfSha384 extends OpenSslHkdf {
        public HkdfSha384(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException {
            super("HmacSHA384", kdfParameters);
        }
    }

    public static final class HkdfSha512 extends OpenSslHkdf {
        public HkdfSha512(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException {
            super("HmacSHA512", kdfParameters);
        }
    }

    public static final class HkdfSha1 extends OpenSslHkdf {
        public HkdfSha1(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException {
            super("HmacSHA1", kdfParameters);
        }
    }
}
