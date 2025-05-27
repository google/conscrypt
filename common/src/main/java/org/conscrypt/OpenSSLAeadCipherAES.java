/*
 * Copyright (C) 2019 The Android Open Source Project
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

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

@Internal
public abstract class OpenSSLAeadCipherAES extends OpenSSLAeadCipher {
    private static final int AES_BLOCK_SIZE = 16;

    OpenSSLAeadCipherAES(Mode mode) {
        super(mode);
    }

    @Override
    void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
        switch (keyLength) {
            case 16: // AES 128
            case 32: // AES 256
                return;
            default:
                throw new InvalidKeyException("Unsupported key size: " + keyLength
                    + " bytes (must be 16 or 32)");
        }
    }

    @Override
    String getBaseCipherName() {
        return "AES";
    }

    @Override
    int getCipherBlockSize() {
        return AES_BLOCK_SIZE;
    }

    @Override
    protected AlgorithmParameterSpec getParameterSpec(AlgorithmParameters params)
        throws InvalidAlgorithmParameterException {
        if (params != null) {
            AlgorithmParameterSpec spec = Platform.fromGCMParameters(params);
            if (spec != null) {
                return spec;
            }
            return super.getParameterSpec(params);
        }
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        // iv will be non-null after initialization.
        if (iv == null) {
            return null;
        }

        AlgorithmParameterSpec spec = Platform.toGCMParameterSpec(
            tagLengthInBytes * 8, iv);
        if (spec == null) {
            // The platform doesn't support GCMParameterSpec. Fall back to
            // the generic AES parameters so at least the caller can get the
            // IV.
            return super.engineGetParameters();
        }

        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("GCM");
            params.init(spec);
            return params;
        } catch (NoSuchAlgorithmException e) {
            // We should not get here.
            throw (Error) new AssertionError("GCM not supported").initCause(e);
        } catch (InvalidParameterSpecException e) {
            // This may happen since Conscrypt doesn't provide this itself.
            return null;
        }
    }

    @Override
    int getOutputSizeForFinal(int inputLen) {
        // For GCM, the tag is a fixed length and there is no padding or other
        // concerns, so we can calculate the exact length required without a
        // native call
        if (isEncrypting()) {
            return bufCount + inputLen + tagLengthInBytes;
        } else {
            return Math.max(0, bufCount + inputLen - tagLengthInBytes);
        }
    }

    public static class GCM extends OpenSSLAeadCipherAES {

        public GCM() {
            super(Mode.GCM);
        }

        @Override
        void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
            if (mode != Mode.GCM) {
                throw new NoSuchAlgorithmException("Mode must be GCM");
            }
        }

        @Override
        long getEVP_AEAD(int keyLength) throws InvalidKeyException {
            if (keyLength == 16) {
                return NativeCrypto.EVP_aead_aes_128_gcm();
            } else if (keyLength == 32) {
                return NativeCrypto.EVP_aead_aes_256_gcm();
            } else {
                throw new RuntimeException("Unexpected key length: " + keyLength);
            }
        }

        public static class AES_128 extends GCM {
            public AES_128() {}

            @Override
            void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
                if (keyLength != 16) { // 128 bits
                    throw new InvalidKeyException(
                        "Unsupported key size: " + keyLength + " bytes (must be 16)");
                }
            }
        }

        public static class AES_256 extends GCM {
            public AES_256() {}

            @Override
            void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
                if (keyLength != 32) { // 256 bits
                    throw new InvalidKeyException(
                        "Unsupported key size: " + keyLength + " bytes (must be 32)");
                }
            }
        }
    }

    public static class GCM_SIV extends OpenSSLAeadCipherAES {

        public GCM_SIV() {
            super(Mode.GCM_SIV);
        }

        @Override
        void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
            if (mode != Mode.GCM_SIV) {
                throw new NoSuchAlgorithmException("Mode must be GCM-SIV");
            }
        }

        @Override
        boolean allowsNonceReuse() {
            return true;
        }

        @Override
        void checkSupportedTagLength(int tagLengthInBits)
            throws InvalidAlgorithmParameterException {
            // GCM_SIV only supports full-size tags
            if (tagLengthInBits != DEFAULT_TAG_SIZE_BITS) {
                throw new InvalidAlgorithmParameterException(
                    "Tag length must be " + DEFAULT_TAG_SIZE_BITS + " bits");
            }
        }

        @Override
        long getEVP_AEAD(int keyLength) throws InvalidKeyException {
            if (keyLength == 16) {
                return NativeCrypto.EVP_aead_aes_128_gcm_siv();
            } else if (keyLength == 32) {
                return NativeCrypto.EVP_aead_aes_256_gcm_siv();
            } else {
                throw new RuntimeException("Unexpected key length: " + keyLength);
            }
        }

        public static class AES_128 extends GCM_SIV {
            public AES_128() {}

            @Override
            void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
                if (keyLength != 16) { // 128 bits
                    throw new InvalidKeyException(
                        "Unsupported key size: " + keyLength + " bytes (must be 16)");
                }
            }
        }

        public static class AES_256 extends GCM_SIV {
            public AES_256() {}

            @Override
            void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
                if (keyLength != 32) { // 256 bits
                    throw new InvalidKeyException(
                        "Unsupported key size: " + keyLength + " bytes (must be 32)");
                }
            }
        }
    }
}
