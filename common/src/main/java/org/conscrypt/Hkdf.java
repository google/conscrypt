/*
 * Copyright (C) 2023 The Android Open Source Project
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
 * limitations under the License
 */

package org.conscrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import javax.crypto.spec.SecretKeySpec;

/**
 * Hkdf - perform HKDF key derivation operations per RFC 5869.
 * <p>
 * Instances should be instantiated using the standard JCA name for the required HMAC.
 * <p>
 * Each invocation of expand or extract uses a new OpenSSLMac.Hmac instance and so instances
 * of Hkdf are thread-safe.</p>
 */
public final class Hkdf {
    // HMAC algorithm to use.
    private final String hmacName;
    private final int macLength;

    /**
     * Creates an Hkdf instance which will use hmacName as the name for the underlying
     * HMAC algorithm, directly using Conscrypt's OpenSSLMac implementation.
     * <p>
     * @param hmacName the name of the HMAC algorithm to use
     * @throws NoSuchAlgorithmException if hmacName is not a supported HMAC name
     */
    public Hkdf(String hmacName) throws NoSuchAlgorithmException {
        Objects.requireNonNull(hmacName);
        if (!hmacName.equals("HmacSHA1") && !hmacName.equals("HmacSHA224")
            && !hmacName.equals("HmacSHA256") && !hmacName.equals("HmacSHA384")
            && !hmacName.equals("HmacSHA512")) {
            throw new NoSuchAlgorithmException("HMAC algorithm not supported: " + hmacName);
        }
        this.hmacName = hmacName;

        // Stash the MAC length with the bonus that we'll fail fast here if no such algorithm.
        OpenSSLMac.Hmac mac = createMac(hmacName);
        macLength = mac.engineGetMacLength();
    }

    private static OpenSSLMac.Hmac createMac(String hmacName) throws NoSuchAlgorithmException {
        if ("HmacSHA256".equalsIgnoreCase(hmacName)) {
            return new OpenSSLMac.HmacSHA256();
        } else if ("HmacSHA384".equalsIgnoreCase(hmacName)) {
            return new OpenSSLMac.HmacSHA384();
        } else if ("HmacSHA512".equalsIgnoreCase(hmacName)) {
            return new OpenSSLMac.HmacSHA512();
        } else if ("HmacSHA1".equalsIgnoreCase(hmacName)) {
            return new OpenSSLMac.HmacSHA1();
        } else if ("HmacSHA224".equalsIgnoreCase(hmacName)) {
            return new OpenSSLMac.HmacSHA224();
        } else if ("HmacMD5".equalsIgnoreCase(hmacName)) {
            return new OpenSSLMac.HmacMD5();
        }
        throw new NoSuchAlgorithmException("Unsupported HMAC algorithm: " + hmacName);
    }

    // Visible for testing.
    public int getMacLength() {
        return macLength;
    }

    /**
     * Performs an HKDF extract operation as specified in RFC 5869.
     *
     * @param salt the salt to use
     * @param ikm initial keying material
     * @return a pseudorandom key suitable for use in expand operations
     * @throws InvalidKeyException if the salt is not suitable for use as an HMAC key
     * @throws NoSuchAlgorithmException if the Mac algorithm is not available
     */
    public byte[] extract(byte[] salt, byte[] ikm)
            throws InvalidKeyException, NoSuchAlgorithmException {
        Objects.requireNonNull(salt);
        Objects.requireNonNull(ikm);
        Preconditions.checkArgument(ikm.length > 0, "Empty keying material");
        if (salt.length == 0) {
            salt = new byte[getMacLength()];
        }
        OpenSSLMac.Hmac mac = getMac(salt);
        mac.engineUpdate(ikm, 0, ikm.length);
        return mac.engineDoFinal();
    }

    /**
     * Performs an HKDF expand operation as specified in RFC 5869.
     *
     * @param prk a pseudorandom key of at least HashLen octets, usually the output from the
     *            extract step. Where HashLen is the key size of the underlying Mac
     * @param info optional context and application specific information, can be zero length
     * @param length length of output keying material in bytes (<= 255*HashLen)
     * @return output of keying material of length bytes
     * @throws InvalidKeyException if prk is not suitable for use as an HMAC key
     * @throws IllegalArgumentException if length is out of the allowed range
     * @throws NoSuchAlgorithmException if the Mac algorithm is not available
     */
    public byte[] expand(byte[] prk, byte[] info, int length)
            throws InvalidKeyException, NoSuchAlgorithmException {
        Objects.requireNonNull(prk);
        Objects.requireNonNull(info);
        Preconditions.checkArgument(length >= 0, "Negative length");
        Preconditions.checkArgument(length <= 255 * getMacLength(), "Length too long");
        OpenSSLMac.Hmac mac = getMac(prk);
        int macLength = getMacLength();

        byte[] t = new byte[0];
        byte[] output = new byte[length];
        int outputOffset = 0;
        byte[] counter = new byte[] {0x00};
        while (outputOffset < length) {
            counter[0]++;
            mac.engineUpdate(t, 0, t.length);
            mac.engineUpdate(info, 0, info.length);
            mac.engineUpdate(counter, 0, 1);
            t = mac.engineDoFinal();
            int size = Math.min(macLength, length - outputOffset);
            System.arraycopy(t, 0, output, outputOffset, size);
            outputOffset += size;
        }
        return output;
    }

    private OpenSSLMac.Hmac getMac(byte[] key)
            throws InvalidKeyException, NoSuchAlgorithmException {
        OpenSSLMac.Hmac mac = createMac(hmacName);
        try {
            mac.engineInit(new SecretKeySpec(key, "RAW"), null);
        } catch (InvalidAlgorithmParameterException e) {
            throw new AssertionError(e);
        }
        return mac;
    }
}
