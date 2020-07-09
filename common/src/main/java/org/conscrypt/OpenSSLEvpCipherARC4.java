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
import javax.crypto.NoSuchPaddingException;

@Internal
public class OpenSSLEvpCipherARC4 extends OpenSSLEvpCipher {
    public OpenSSLEvpCipherARC4() {
        // Modes and padding don't make sense for ARC4.
        super(Mode.ECB, Padding.NOPADDING);
    }

    @Override
    String getBaseCipherName() {
        return "ARCFOUR";
    }

    @Override
    String getCipherName(int keySize, Mode mode) {
        return "rc4";
    }

    @Override
    void checkSupportedKeySize(int keySize) throws InvalidKeyException {
    }

    @Override
    void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
        if (mode != Mode.NONE && mode != Mode.ECB) {
            throw new NoSuchAlgorithmException("Unsupported mode " + mode.toString());
        }
    }

    @Override
    void checkSupportedPadding(Padding padding) throws NoSuchPaddingException {
        if (padding != Padding.NOPADDING) {
            throw new NoSuchPaddingException("Unsupported padding " + padding.toString());
        }
    }

    @Override
    int getCipherBlockSize() {
        return 0;
    }

    @Override
    boolean supportsVariableSizeKey() {
        return true;
    }
}
