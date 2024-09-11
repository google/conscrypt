/*
 * Copyright (C) 2015 The Android Open Source Project
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

package org.conscrypt.ct;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import org.conscrypt.Internal;

/**
 * DigitallySigned structure, as defined by RFC5246 Section 4.7.
 */
@Internal
public class DigitallySigned {
    public enum HashAlgorithm {
        NONE,
        MD5,
        SHA1,
        SHA224,
        SHA256,
        SHA384,
        SHA512;

        private static HashAlgorithm[] values = values();
        public static HashAlgorithm valueOf(int ord) {
            try {
                return values[ord];
            } catch (IndexOutOfBoundsException e) {
                throw new IllegalArgumentException("Invalid hash algorithm " + ord, e);
            }
        }
    }

    public enum SignatureAlgorithm {
        ANONYMOUS,
        RSA,
        DSA,
        ECDSA;

        private static SignatureAlgorithm[] values = values();
        public static SignatureAlgorithm valueOf(int ord) {
            try {
                return values[ord];
            } catch (IndexOutOfBoundsException e) {
                throw new IllegalArgumentException("Invalid signature algorithm " + ord, e);
            }
        }
    }

    private final HashAlgorithm hashAlgorithm;
    private final SignatureAlgorithm signatureAlgorithm;
    private final byte[] signature;

    public DigitallySigned(HashAlgorithm hashAlgorithm,
                           SignatureAlgorithm signatureAlgorithm,
                           byte[] signature) {
        this.hashAlgorithm = hashAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
    }

    public DigitallySigned(int hashAlgorithm,
                           int signatureAlgorithm,
                           byte[] signature) {
        this(
            HashAlgorithm.valueOf(hashAlgorithm),
            SignatureAlgorithm.valueOf(signatureAlgorithm),
            signature
        );
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
    public byte[] getSignature() {
        return signature;
    }

    /**
     * Get the name of the hash and signature combination.
     * The result can be used to as the argument to {@link java.security.Signature#getInstance}.
     */
    public String getAlgorithm() {
        return String.format("%swith%s", hashAlgorithm, signatureAlgorithm);
    }

    /**
     * Decode a TLS encoded DigitallySigned structure.
     */
    public static DigitallySigned decode(InputStream input)
        throws SerializationException {
        try {
            return new DigitallySigned(
                    Serialization.readNumber(input, Constants.HASH_ALGORITHM_LENGTH),
                    Serialization.readNumber(input, Constants.SIGNATURE_ALGORITHM_LENGTH),
                    Serialization.readVariableBytes(input, Constants.SIGNATURE_LENGTH_BYTES));
        } catch (IllegalArgumentException e) {
            throw new SerializationException(e);
        }
    }

    /**
     * Decode a TLS encoded DigitallySigned structure.
     */
    public static DigitallySigned decode(byte[] input)
            throws SerializationException {
        return decode(new ByteArrayInputStream(input));
    }
}


