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

    OpenSSLEvpCipherDESEDE(Padding padding) {
        super(padding);
    }

    public static class CBC extends OpenSSLEvpCipherDESEDE {
        CBC(Padding padding) {
            super(padding);
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
    long getCipherType(int keySize) {
        if (keySize == 16) {
            return NativeCrypto.EVP_des_ede_cbc();
        } else if (keySize == 24) {
            return NativeCrypto.EVP_des_ede3_cbc();
        }
        return 0;
    }

    @Override
    void checkSupportedKeySize(int keySize) throws InvalidKeyException {
        if (keySize != 16 && keySize != 24) {
            throw new InvalidKeyException("key size must be 128 or 192 bits");
        }
    }

    @Override
    protected void engineSetMode(String modeStr) throws NoSuchAlgorithmException {
        if (!modeStr.equalsIgnoreCase("CBC")) {
            throw new NoSuchAlgorithmException("Unsupported mode " + modeStr);
        }
    }

    @Override
    protected void engineSetPadding(String paddingStr) throws NoSuchPaddingException {
        String upperPaddingStr = paddingStr.toUpperCase(Locale.US);
        if (upperPaddingStr.equals("NOPADDING")) {
            padding = Padding.NOPADDING;
        } else if (upperPaddingStr.equals("PKCS5PADDING")
                   || upperPaddingStr.equals("PKCS7PADDING")) {
            padding = Padding.PKCS5PADDING;
        } else {
            throw new NoSuchPaddingException("No such padding: " + paddingStr);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return DES_BLOCK_SIZE;
    }
}
