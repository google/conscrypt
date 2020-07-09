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
public abstract class OpenSSLEvpCipherAES extends OpenSSLEvpCipher {
    private static final int AES_BLOCK_SIZE = 16;

    OpenSSLEvpCipherAES(Mode mode, Padding padding) {
        super(mode, padding);
    }

    @Override
    void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
        switch (mode) {
            case CBC:
            case CTR:
            case ECB:
                return;
            default:
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
                throw new NoSuchPaddingException(
                        "Unsupported padding " + padding.toString());
        }
    }

    @Override
    String getBaseCipherName() {
        return "AES";
    }

    @Override
    String getCipherName(int keyLength, Mode mode) {
        return "aes-" + (keyLength * 8) + "-" + mode.toString().toLowerCase(Locale.US);
    }

    @Override
    int getCipherBlockSize() {
        return AES_BLOCK_SIZE;
    }

    public static class AES extends OpenSSLEvpCipherAES {
        AES(Mode mode, Padding padding) {
            super(mode, padding);
        }

        public static class CBC extends AES {
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

        public static class CTR extends AES {
            public CTR() {
                super(Mode.CTR, Padding.NOPADDING);
            }
        }

        public static class ECB extends AES {
            ECB(Padding padding) {
                super(Mode.ECB, padding);
            }

            public static class NoPadding extends ECB {
                public NoPadding() {
                    super(Padding.NOPADDING);
                }
            }

            public static class PKCS5Padding extends ECB {
                public PKCS5Padding() {
                    super(Padding.PKCS5PADDING);
                }
            }
        }

        @Override
        void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
            switch (keyLength) {
                case 16: // AES 128
                case 24: // AES 192
                case 32: // AES 256
                    return;
                default:
                    throw new InvalidKeyException("Unsupported key size: " + keyLength
                        + " bytes");
            }
        }
    }

    public static class AES_128 extends OpenSSLEvpCipherAES {
        AES_128(Mode mode, Padding padding) {
            super(mode, padding);
        }

        public static class CBC extends AES_128 {
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

        public static class CTR extends AES_128 {
            public CTR() {
                super(Mode.CTR, Padding.NOPADDING);
            }
        }

        public static class ECB extends AES_128 {
            ECB(Padding padding) {
                super(Mode.ECB, padding);
            }

            public static class NoPadding extends ECB {
                public NoPadding() {
                    super(Padding.NOPADDING);
                }
            }

            public static class PKCS5Padding extends ECB {
                public PKCS5Padding() {
                    super(Padding.PKCS5PADDING);
                }
            }
        }

        @Override
        void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
            if (keyLength != 16) { // 128 bits
                throw new InvalidKeyException("Unsupported key size: " + keyLength + " bytes");
            }
        }
    }

    public static class AES_256 extends OpenSSLEvpCipherAES {
        AES_256(Mode mode, Padding padding) {
            super(mode, padding);
        }

        public static class CBC extends AES_256 {
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

        public static class CTR extends AES_256 {
            public CTR() {
                super(Mode.CTR, Padding.NOPADDING);
            }
        }

        public static class ECB extends AES_256 {
            ECB(Padding padding) {
                super(Mode.ECB, padding);
            }

            public static class NoPadding extends ECB {
                public NoPadding() {
                    super(Padding.NOPADDING);
                }
            }

            public static class PKCS5Padding extends ECB {
                public PKCS5Padding() {
                    super(Padding.PKCS5PADDING);
                }
            }
        }

        @Override
        void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
            if (keyLength != 32) { // 256 bits
                throw new InvalidKeyException("Unsupported key size: " + keyLength + " bytes");
            }
        }
    }
}
