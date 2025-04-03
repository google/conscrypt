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

import static org.conscrypt.metrics.MetricsCipher.AES;
import static org.conscrypt.metrics.MetricsMode.CBC;
import static org.conscrypt.metrics.MetricsMode.CTR;
import static org.conscrypt.metrics.MetricsMode.ECB;
import static org.conscrypt.metrics.MetricsPadding.NO_PADDING;
import static org.conscrypt.metrics.MetricsPadding.PKCS5;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

import javax.crypto.NoSuchPaddingException;

@Internal
public abstract class OpenSSLEvpCipherAES extends OpenSSLEvpCipher {
    private static final int AES_BLOCK_SIZE = 16;

    OpenSSLEvpCipherAES(Mode mode, Padding padding, int modeId, int paddingId) {
        super(mode, padding, AES.getId(), modeId, paddingId);
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
        AES(Mode mode, Padding padding, int modeId, int paddingId) {
            super(mode, padding, modeId, paddingId);
        }

        public static class CBC extends AES {
            CBC(Padding padding, int paddingId) {
                super(Mode.CBC, padding, CBC.getId(), paddingId);
            }

            public static class NoPadding extends AES.CBC {
                public NoPadding() {
                    super(Padding.NOPADDING, NO_PADDING.getId());
                }
            }

            public static class PKCS5Padding extends AES.CBC {
                public PKCS5Padding() {
                    super(Padding.PKCS5PADDING, PKCS5.getId());
                }
            }
        }

        public static class CTR extends AES {
            public CTR() {
                super(Mode.CTR, Padding.NOPADDING, CTR.getId(), NO_PADDING.getId());
            }
        }

        public static class ECB extends AES {
            ECB(Padding padding, int paddingId) {
                super(Mode.ECB, padding, ECB.getId(), paddingId);
            }

            public static class NoPadding extends AES.ECB {
                public NoPadding() {
                    super(Padding.NOPADDING, NO_PADDING.getId());
                }
            }

            public static class PKCS5Padding extends AES.ECB {
                public PKCS5Padding() {
                    super(Padding.PKCS5PADDING, PKCS5.getId());
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
        AES_128(Mode mode, Padding padding, int modeId, int paddingId) {
            super(mode, padding, modeId, paddingId);
        }

        public static class CBC extends AES_128 {
            CBC(Padding padding, int paddingId) {
                super(Mode.CBC, padding, CBC.getId(), paddingId);
            }

            public static class NoPadding extends AES_128.CBC {
                public NoPadding() {
                    super(Padding.NOPADDING, NO_PADDING.getId());
                }
            }

            public static class PKCS5Padding extends AES_128.CBC {
                public PKCS5Padding() {
                    super(Padding.PKCS5PADDING, PKCS5.getId());
                }
            }
        }

        public static class CTR extends AES_128 {
            public CTR() {
                super(Mode.CTR, Padding.NOPADDING, CTR.getId(), NO_PADDING.getId());
            }
        }

        public static class ECB extends AES_128 {
            ECB(Padding padding, int paddingId) {
                super(Mode.ECB, padding, ECB.getId(), paddingId);
            }

            public static class NoPadding extends AES_128.ECB {
                public NoPadding() {
                    super(Padding.NOPADDING, NO_PADDING.getId());
                }
            }

            public static class PKCS5Padding extends AES_128.ECB {
                public PKCS5Padding() {
                    super(Padding.PKCS5PADDING, PKCS5.getId());
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
        AES_256(Mode mode, Padding padding, int modeId, int paddingId) {
            super(mode, padding, modeId, paddingId);
        }

        public static class CBC extends AES_256 {
            CBC(Padding padding, int paddingId) {
                super(Mode.CBC, padding, CBC.getId(), paddingId);
            }

            public static class NoPadding extends AES_256.CBC {
                public NoPadding() {
                    super(Padding.NOPADDING, NO_PADDING.getId());
                }
            }

            public static class PKCS5Padding extends AES_256.CBC {
                public PKCS5Padding() {
                    super(Padding.PKCS5PADDING, PKCS5.getId());
                }
            }
        }

        public static class CTR extends AES_256 {
            public CTR() {
                super(Mode.CTR, Padding.NOPADDING, CTR.getId(), NO_PADDING.getId());
            }
        }

        public static class ECB extends AES_256 {
            ECB(Padding padding, int paddingId) {
                super(Mode.ECB, padding, ECB.getId(), paddingId);
            }

            public static class NoPadding extends AES_256.ECB {
                public NoPadding() {
                    super(Padding.NOPADDING, NO_PADDING.getId());
                }
            }

            public static class PKCS5Padding extends AES_256.ECB {
                public PKCS5Padding() {
                    super(Padding.PKCS5PADDING, PKCS5.getId());
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
