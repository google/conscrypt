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
import java.util.Locale;
import javax.crypto.NoSuchPaddingException;

@Internal
public abstract class OpenSSLEvpCipherDESEDE extends OpenSSLEvpCipher {
    private static final int DES_BLOCK_SIZE = 8;

    OpenSSLEvpCipherDESEDE(Mode mode, Padding padding) {
        super(mode, padding);
    }

    public static class CBC extends OpenSSLEvpCipherDESEDE {
        CBC(Padding padding) {
            super(Mode.CBC, padding);
        }

        public static class NoPadding extends CBC {
            public NoPadding() {
                super(Padding.NOPADDING);
            }
        }

        public static class PKCS5Padding extends CBC {
            public PKCS5Padding() {
                super(Padding.PKCS5PADDING);
            }
        }
    }

    @Override
    String getBaseCipherName() {
        return "DESede";
    }

    @Override
    String getCipherName(int keySize, Mode mode) {
        final String baseCipherName;
        if (keySize == 16) {
            baseCipherName = "des-ede";
        } else {
            baseCipherName = "des-ede3";
        }

        return baseCipherName + "-" + mode.toString().toLowerCase(Locale.US);
    }

    @Override
    void checkSupportedKeySize(int keySize) throws InvalidKeyException {
        if (keySize != 16 && keySize != 24) {
            throw new InvalidKeyException("key size must be 128 or 192 bits");
        }
    }

    @Override
    void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
        if (mode != Mode.CBC) {
            throw new NoSuchAlgorithmException("Unsupported mode " + mode.toString());
        }
    }

    @Override
    void checkSupportedPadding(Padding padding) throws NoSuchPaddingException {
        switch (padding) {
            case NOPADDING:
            case PKCS5PADDING:
                return;
            default:
                throw new NoSuchPaddingException("Unsupported padding "
                        + padding.toString());
        }
    }

    @Override
    int getCipherBlockSize() {
        return DES_BLOCK_SIZE;
    }
}
