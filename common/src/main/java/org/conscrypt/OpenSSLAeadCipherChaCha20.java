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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Internal
public class OpenSSLAeadCipherChaCha20 extends OpenSSLAeadCipher {
    public OpenSSLAeadCipherChaCha20() {
        super(Mode.POLY1305);
    }

    @Override
    void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
        if (keyLength != 32) {
            throw new InvalidKeyException("Unsupported key size: " + keyLength
                    + " bytes (must be 32)");
        }
    }

    @Override
    String getBaseCipherName() {
        return "ChaCha20";
    }

    @Override
    int getCipherBlockSize() {
        return 0;
    }

    @Override
    void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
        if (mode != Mode.POLY1305) {
            throw new NoSuchAlgorithmException("Mode must be Poly1305");
        }
    }

    @Override
    long getEVP_AEAD(int keyLength) throws InvalidKeyException {
        if (keyLength == 32) {
            return NativeCrypto.EVP_aead_chacha20_poly1305();
        } else {
            throw new RuntimeException("Unexpected key length: " + keyLength);
        }
    }

    @Override
    int getOutputSizeForFinal(int inputLen) {
        // For ChaCha20+Poly1305, the tag is always 16 bytes long and there is no
        // padding or other concerns, so we can calculate the exact length required
        // without a native call
        if (isEncrypting()) {
            return bufCount + inputLen + 16;
        } else {
            return Math.max(0, bufCount + inputLen - 16);
        }
    }
}
