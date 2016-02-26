/*
 * Copyright (C) 2012 The Android Open Source Project
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

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.conscrypt.util.ArrayUtils;
import org.conscrypt.util.EmptyArray;
import org.conscrypt.NativeConstants;
import org.conscrypt.NativeRef.EVP_AEAD_CTX;
import org.conscrypt.NativeRef.EVP_CIPHER_CTX;

public abstract class OpenSSLCipher extends CipherSpi {

    /**
     * Modes that a block cipher may support.
     */
    protected static enum Mode {
        CBC,
        CTR,
        ECB,
        GCM,
    }

    /**
     * Paddings that a block cipher may support.
     */
    protected static enum Padding {
        NOPADDING,
        PKCS5PADDING,
        ISO10126PADDING,
    }

    /**
     * The current cipher mode.
     */
    protected Mode mode = Mode.ECB;

    /**
     * The current cipher padding.
     */
    private Padding padding = Padding.PKCS5PADDING;

    /**
     * May be used when reseting the cipher instance after calling
     * {@code doFinal}.
     */
    protected byte[] encodedKey;

    /**
     * The Initial Vector (IV) used for the current cipher.
     */
    protected byte[] iv;

    /**
     * Current cipher mode: encrypting or decrypting.
     */
    private boolean encrypting;

    /**
     * The block size of the current cipher.
     */
    private int blockSize;

    protected OpenSSLCipher() {
    }

    protected OpenSSLCipher(Mode mode, Padding padding) {
        this.mode = mode;
        this.padding = padding;
        blockSize = getCipherBlockSize();
    }

    /**
     * API-specific implementation of initializing the cipher. The
     * {@link #isEncrypting()} function will tell whether it should be
     * initialized for encryption or decryption. The {@code encodedKey} will be
     * the bytes of a supported key size.
     */
    protected abstract void engineInitInternal(byte[] encodedKey, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * API-specific implementation of updating the cipher. The
     * {@code maximumLen} will be the maximum length of the output as returned
     * by {@link #getOutputSizeForUpdate(int)}. The return value must be the
     * number of bytes processed and placed into {@code output}. On error, an
     * exception must be thrown.
     */
    protected abstract int updateInternal(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset, int maximumLen) throws ShortBufferException;

    /**
     * API-specific implementation of the final block. The {@code maximumLen}
     * will be the maximum length of the possible output as returned by
     * {@link #getOutputSizeForFinal(int)}. The return value must be the number
     * of bytes processed and placed into {@code output}. On error, an exception
     * must be thrown.
     */
    protected abstract int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
            throws IllegalBlockSizeException, BadPaddingException, ShortBufferException;

    /**
     * Returns the standard name for the particular algorithm.
     */
    protected abstract String getBaseCipherName();

    /**
     * Checks whether the cipher supports this particular {@code keySize} (in
     * bytes) and throws {@code InvalidKeyException} if it doesn't.
     */
    protected abstract void checkSupportedKeySize(int keySize) throws InvalidKeyException;

    /**
     * Checks whether the cipher supports this particular cipher {@code mode}
     * and throws {@code NoSuchAlgorithmException} if it doesn't.
     */
    protected abstract void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException;

    /**
     * Checks whether the cipher supports this particular cipher {@code padding}
     * and throws {@code NoSuchPaddingException} if it doesn't.
     */
    protected abstract void checkSupportedPadding(Padding padding) throws NoSuchPaddingException;

    protected abstract int getCipherBlockSize();

    protected boolean supportsVariableSizeKey() {
        return false;
    }

    protected boolean supportsVariableSizeIv() {
        return false;
    }

    @Override
    protected void engineSetMode(String modeStr) throws NoSuchAlgorithmException {
        final Mode mode;
        try {
            mode = Mode.valueOf(modeStr.toUpperCase(Locale.US));
        } catch (IllegalArgumentException e) {
            NoSuchAlgorithmException newE = new NoSuchAlgorithmException("No such mode: " + modeStr);
            newE.initCause(e);
            throw newE;
        }
        checkSupportedMode(mode);
        this.mode = mode;
    }

    @Override
    protected void engineSetPadding(String paddingStr) throws NoSuchPaddingException {
        final String paddingStrUpper = paddingStr.toUpperCase(Locale.US);
        final Padding padding;
        try {
            padding = Padding.valueOf(paddingStrUpper);
        } catch (IllegalArgumentException e) {
            NoSuchPaddingException newE = new NoSuchPaddingException("No such padding: "
                    + paddingStr);
            newE.initCause(e);
            throw newE;
        }
        checkSupportedPadding(padding);
        this.padding = padding;
    }

    /**
     * Returns the padding type for which this cipher is initialized.
     */
    protected Padding getPadding() {
        return padding;
    }

    @Override
    protected int engineGetBlockSize() {
        return blockSize;
    }

    /**
     * The size of output if {@code doFinal()} is called with this
     * {@code inputLen}. If padding is enabled and the size of the input puts it
     * right at the block size, it will add another block for the padding.
     */
    protected abstract int getOutputSizeForFinal(int inputLen);

    /**
     * The size of output if {@code update()} is called with this
     * {@code inputLen}. If padding is enabled and the size of the input puts it
     * right at the block size, it will add another block for the padding.
     */
    protected abstract int getOutputSizeForUpdate(int inputLen);

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return getOutputSizeForFinal(inputLen);
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (iv != null && iv.length > 0) {
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance(getBaseCipherName());
                params.init(iv);
                return params;
            } catch (NoSuchAlgorithmException e) {
                return null;
            } catch (IOException e) {
                return null;
            }
        }
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        checkAndSetEncodedKey(opmode, key);
        try {
            engineInitInternal(this.encodedKey, null, random);
        } catch (InvalidAlgorithmParameterException e) {
            // This can't actually happen since we pass in null.
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        checkAndSetEncodedKey(opmode, key);
        engineInitInternal(this.encodedKey, params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec spec;
        if (params != null) {
            try {
                spec = params.getParameterSpec(IvParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                throw new InvalidAlgorithmParameterException(
                        "Params must be convertible to IvParameterSpec", e);
            }
        } else {
            spec = null;
        }

        engineInit(opmode, key, spec, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        final int maximumLen = getOutputSizeForUpdate(inputLen);

        /* See how large our output buffer would need to be. */
        final byte[] output;
        if (maximumLen > 0) {
            output = new byte[maximumLen];
        } else {
            output = EmptyArray.BYTE;
        }

        final int bytesWritten;
        try {
            bytesWritten = updateInternal(input, inputOffset, inputLen, output, 0, maximumLen);
        } catch (ShortBufferException e) {
            /* This shouldn't happen. */
            throw new RuntimeException("calculated buffer size was wrong: " + maximumLen);
        }

        if (output.length == bytesWritten) {
            return output;
        } else if (bytesWritten == 0) {
            return EmptyArray.BYTE;
        } else {
            return Arrays.copyOfRange(output, 0, bytesWritten);
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        final int maximumLen = getOutputSizeForUpdate(inputLen);
        return updateInternal(input, inputOffset, inputLen, output, outputOffset, maximumLen);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        final int maximumLen = getOutputSizeForFinal(inputLen);
        /* Assume that we'll output exactly on a byte boundary. */
        final byte[] output = new byte[maximumLen];

        int bytesWritten;
        if (inputLen > 0) {
            try {
                bytesWritten = updateInternal(input, inputOffset, inputLen, output, 0, maximumLen);
            } catch (ShortBufferException e) {
                /* This should not happen since we sized our own buffer. */
                throw new RuntimeException("our calculated buffer was too small", e);
            }
        } else {
            bytesWritten = 0;
        }

        try {
            bytesWritten += doFinalInternal(output, bytesWritten, maximumLen - bytesWritten);
        } catch (ShortBufferException e) {
            /* This should not happen since we sized our own buffer. */
            throw new RuntimeException("our calculated buffer was too small", e);
        }

        if (bytesWritten == output.length) {
            return output;
        } else if (bytesWritten == 0) {
            return EmptyArray.BYTE;
        } else {
            return Arrays.copyOfRange(output, 0, bytesWritten);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
        if (output == null) {
            throw new NullPointerException("output == null");
        }

        int maximumLen = getOutputSizeForFinal(inputLen);

        final int bytesWritten;
        if (inputLen > 0) {
            bytesWritten = updateInternal(input, inputOffset, inputLen, output, outputOffset,
                    maximumLen);
            outputOffset += bytesWritten;
            maximumLen -= bytesWritten;
        } else {
            bytesWritten = 0;
        }

        return bytesWritten + doFinalInternal(output, outputOffset, maximumLen);
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        try {
            byte[] encoded = key.getEncoded();
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            IllegalBlockSizeException newE = new IllegalBlockSizeException();
            newE.initCause(e);
            throw newE;
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        try {
            byte[] encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            if (wrappedKeyType == Cipher.PUBLIC_KEY) {
                KeyFactory keyFactory = KeyFactory.getInstance(wrappedKeyAlgorithm);
                return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
            } else if (wrappedKeyType == Cipher.PRIVATE_KEY) {
                KeyFactory keyFactory = KeyFactory.getInstance(wrappedKeyAlgorithm);
                return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
            } else if (wrappedKeyType == Cipher.SECRET_KEY) {
                return new SecretKeySpec(encoded, wrappedKeyAlgorithm);
            } else {
                throw new UnsupportedOperationException("wrappedKeyType == " + wrappedKeyType);
            }
        } catch (IllegalBlockSizeException e) {
            throw new InvalidKeyException(e);
        } catch (BadPaddingException e) {
            throw new InvalidKeyException(e);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }
    }

    private byte[] checkAndSetEncodedKey(int opmode, Key key) throws InvalidKeyException {
        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            encrypting = true;
        } else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
            encrypting = false;
        } else {
            throw new InvalidParameterException("Unsupported opmode " + opmode);
        }

        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Only SecretKey is supported");
        }

        final byte[] encodedKey = key.getEncoded();
        if (encodedKey == null) {
            throw new InvalidKeyException("key.getEncoded() == null");
        }
        checkSupportedKeySize(encodedKey.length);
        this.encodedKey = encodedKey;
        return encodedKey;
    }

    protected boolean isEncrypting() {
        return encrypting;
    }

    public static abstract class EVP_CIPHER extends OpenSSLCipher {
        /**
         * Native pointer for the OpenSSL EVP_CIPHER context.
         */
        private final EVP_CIPHER_CTX cipherCtx = new EVP_CIPHER_CTX(
                NativeCrypto.EVP_CIPHER_CTX_new());

        /**
         * Whether the cipher has processed any data yet. EVP_CIPHER doesn't
         * like calling "doFinal()" in decryption mode without processing any
         * updates.
         */
        protected boolean calledUpdate;

        /**
         * The block size of the current mode.
         */
        private int modeBlockSize;

        public EVP_CIPHER(Mode mode, Padding padding) {
            super(mode, padding);
        }

        @Override
        protected void engineInitInternal(byte[] encodedKey, AlgorithmParameterSpec params,
                SecureRandom random) throws InvalidKeyException,
                InvalidAlgorithmParameterException {
            byte[] iv;
            if (params instanceof IvParameterSpec) {
                IvParameterSpec ivParams = (IvParameterSpec) params;
                iv = ivParams.getIV();
            } else {
                iv = null;
            }

            final long cipherType = NativeCrypto.EVP_get_cipherbyname(getCipherName(
                    encodedKey.length, mode));
            if (cipherType == 0) {
                throw new InvalidAlgorithmParameterException("Cannot find name for key length = "
                        + (encodedKey.length * 8) + " and mode = " + mode);
            }

            final boolean encrypting = isEncrypting();

            final int expectedIvLength = NativeCrypto.EVP_CIPHER_iv_length(cipherType);
            if (iv == null && expectedIvLength != 0) {
                if (!encrypting) {
                    throw new InvalidAlgorithmParameterException("IV must be specified in " + mode
                            + " mode");
                }

                iv = new byte[expectedIvLength];
                if (random == null) {
                    random = new SecureRandom();
                }
                random.nextBytes(iv);
            } else if (expectedIvLength == 0 && iv != null) {
                throw new InvalidAlgorithmParameterException("IV not used in " + mode + " mode");
            } else if (iv != null && iv.length != expectedIvLength) {
                throw new InvalidAlgorithmParameterException("expected IV length of "
                        + expectedIvLength + " but was " + iv.length);
            }

            this.iv = iv;

            if (supportsVariableSizeKey()) {
                NativeCrypto.EVP_CipherInit_ex(cipherCtx, cipherType, null, null, encrypting);
                NativeCrypto.EVP_CIPHER_CTX_set_key_length(cipherCtx, encodedKey.length);
                NativeCrypto.EVP_CipherInit_ex(cipherCtx, 0, encodedKey, iv, isEncrypting());
            } else {
                NativeCrypto.EVP_CipherInit_ex(cipherCtx, cipherType, encodedKey, iv, encrypting);
            }

            // OpenSSL only supports PKCS5 Padding.
            NativeCrypto
                    .EVP_CIPHER_CTX_set_padding(cipherCtx, getPadding() == Padding.PKCS5PADDING);
            modeBlockSize = NativeCrypto.EVP_CIPHER_CTX_block_size(cipherCtx);
            calledUpdate = false;
        }

        @Override
        protected int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output,
                int outputOffset, int maximumLen) throws ShortBufferException {
            final int intialOutputOffset = outputOffset;

            final int bytesLeft = output.length - outputOffset;
            if (bytesLeft < maximumLen) {
                throw new ShortBufferException("output buffer too small during update: "
                        + bytesLeft + " < " + maximumLen);
            }

            outputOffset += NativeCrypto.EVP_CipherUpdate(cipherCtx, output, outputOffset, input,
                    inputOffset, inputLen);

            calledUpdate = true;

            return outputOffset - intialOutputOffset;
        }

        @Override
        protected int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
                throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
            /* Remember this so we can tell how many characters were written. */
            final int initialOutputOffset = outputOffset;

            /*
             * If we're decrypting and haven't had any input, we should return
             * null. Otherwise OpenSSL will complain if we call final.
             */
            if (!isEncrypting() && !calledUpdate) {
                return 0;
            }

            /* Allow OpenSSL to pad if necessary and clean up state. */
            final int bytesLeft = output.length - outputOffset;
            final int writtenBytes;
            if (bytesLeft >= maximumLen) {
                writtenBytes = NativeCrypto.EVP_CipherFinal_ex(cipherCtx, output, outputOffset);
            } else {
                final byte[] lastBlock = new byte[maximumLen];
                writtenBytes = NativeCrypto.EVP_CipherFinal_ex(cipherCtx, lastBlock, 0);
                if (writtenBytes > bytesLeft) {
                    throw new ShortBufferException("buffer is too short: " + writtenBytes + " > "
                            + bytesLeft);
                } else if (writtenBytes > 0) {
                    System.arraycopy(lastBlock, 0, output, outputOffset, writtenBytes);
                }
            }
            outputOffset += writtenBytes;

            reset();

            return outputOffset - initialOutputOffset;
        }

        @Override
        protected int getOutputSizeForFinal(int inputLen) {
            if (modeBlockSize == 1) {
                return inputLen;
            } else {
                final int buffered = NativeCrypto.get_EVP_CIPHER_CTX_buf_len(cipherCtx);

                if (getPadding() == Padding.NOPADDING) {
                    return buffered + inputLen;
                } else {
                    final boolean finalUsed = NativeCrypto.get_EVP_CIPHER_CTX_final_used(cipherCtx);
                    // There is an additional buffer containing the possible final block.
                    int totalLen = inputLen + buffered + (finalUsed ? modeBlockSize : 0);
                    // Extra block for remainder bytes plus padding.
                    // In case it's encrypting and there are no remainder bytes, add an extra block
                    // consisting only of padding.
                    totalLen += ((totalLen % modeBlockSize != 0) || isEncrypting())
                            ? modeBlockSize : 0;
                    // The minimum multiple of {@code modeBlockSize} that can hold all the bytes.
                    return totalLen - (totalLen % modeBlockSize);
                }
            }
        }

        @Override
        protected int getOutputSizeForUpdate(int inputLen) {
            return getOutputSizeForFinal(inputLen);
        }

        /**
         * Returns the OpenSSL cipher name for the particular {@code keySize}
         * and cipher {@code mode}.
         */
        protected abstract String getCipherName(int keySize, Mode mode);

        /**
         * Reset this Cipher instance state to process a new chunk of data.
         */
        private void reset() {
            NativeCrypto.EVP_CipherInit_ex(cipherCtx, 0, encodedKey, iv, isEncrypting());
            calledUpdate = false;
        }

        public static class AES extends EVP_CIPHER {
            private static final int AES_BLOCK_SIZE = 16;

            protected AES(Mode mode, Padding padding) {
                super(mode, padding);
            }

            public static class CBC extends AES {
                public CBC(Padding padding) {
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
                public ECB(Padding padding) {
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
            protected void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
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

            @Override
            protected void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
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
            protected void checkSupportedPadding(Padding padding) throws NoSuchPaddingException {
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
            protected String getBaseCipherName() {
                return "AES";
            }

            @Override
            protected String getCipherName(int keyLength, Mode mode) {
                return "aes-" + (keyLength * 8) + "-" + mode.toString().toLowerCase(Locale.US);
            }

            @Override
            protected int getCipherBlockSize() {
                return AES_BLOCK_SIZE;
            }
        }

        public static class DESEDE extends EVP_CIPHER {
            private static int DES_BLOCK_SIZE = 8;

            public DESEDE(Mode mode, Padding padding) {
                super(mode, padding);
            }

            public static class CBC extends DESEDE {
                public CBC(Padding padding) {
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
            protected String getBaseCipherName() {
                return "DESede";
            }

            @Override
            protected String getCipherName(int keySize, Mode mode) {
                final String baseCipherName;
                if (keySize == 16) {
                    baseCipherName = "des-ede";
                } else {
                    baseCipherName = "des-ede3";
                }

                return baseCipherName + "-" + mode.toString().toLowerCase(Locale.US);
            }

            @Override
            protected void checkSupportedKeySize(int keySize) throws InvalidKeyException {
                if (keySize != 16 && keySize != 24) {
                    throw new InvalidKeyException("key size must be 128 or 192 bits");
                }
            }

            @Override
            protected void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
                if (mode != Mode.CBC) {
                    throw new NoSuchAlgorithmException("Unsupported mode " + mode.toString());
                }
            }

            @Override
            protected void checkSupportedPadding(Padding padding) throws NoSuchPaddingException {
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
            protected int getCipherBlockSize() {
                return DES_BLOCK_SIZE;
            }
        }

        public static class ARC4 extends EVP_CIPHER {
            public ARC4() {
                // Modes and padding don't make sense for ARC4.
                super(Mode.ECB, Padding.NOPADDING);
            }

            @Override
            protected String getBaseCipherName() {
                return "ARCFOUR";
            }

            @Override
            protected String getCipherName(int keySize, Mode mode) {
                return "rc4";
            }

            @Override
            protected void checkSupportedKeySize(int keySize) throws InvalidKeyException {
            }

            @Override
            protected void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
                throw new NoSuchAlgorithmException("ARC4 does not support modes");
            }

            @Override
            protected void checkSupportedPadding(Padding padding) throws NoSuchPaddingException {
                throw new NoSuchPaddingException("ARC4 does not support padding");
            }

            @Override
            protected int getCipherBlockSize() {
                return 0;
            }

            @Override
            protected boolean supportsVariableSizeKey() {
                return true;
            }
        }
    }

    public static abstract class EVP_AEAD extends OpenSSLCipher {
        /**
         * Keeps track of the last used block size.
         */
        private static int lastGlobalMessageSize = 32;

        /**
         * The byte array containing the bytes written.
         */
        protected byte[] buf;

        /**
         * The number of bytes written.
         */
        protected int bufCount;

        /**
         * AEAD cipher reference.
         */
        protected long evpAead;

        /**
         * Additional authenticated data.
         */
        private byte[] aad;

        /**
         * The length of the AEAD cipher tag in bytes.
         */
        private int tagLen;

        public EVP_AEAD(Mode mode) {
            super(mode, Padding.NOPADDING);
        }

        private void expand(int i) {
            /* Can the buffer handle i more bytes, if not expand it */
            if (bufCount + i <= buf.length) {
                return;
            }

            byte[] newbuf = new byte[(bufCount + i) * 2];
            System.arraycopy(buf, 0, newbuf, 0, bufCount);
            buf = newbuf;
        }

        private void reset() {
            final int lastBufSize = lastGlobalMessageSize;
            if (buf == null) {
                buf = new byte[lastBufSize];
            } else if (bufCount > 0 && bufCount != lastBufSize) {
                lastGlobalMessageSize = bufCount;
                if (buf.length != bufCount) {
                    buf = new byte[bufCount];
                }
            }
            bufCount = 0;
        }

        @Override
        protected void engineInitInternal(byte[] encodedKey, AlgorithmParameterSpec params,
                SecureRandom random) throws InvalidKeyException,
                InvalidAlgorithmParameterException {
            byte[] iv;
            final int tagLenBits;
            if (params == null) {
                iv = null;
                tagLenBits = 0;
            } else {
                Class<?> gcmSpecClass;
                try {
                    gcmSpecClass = Class.forName("javax.crypto.spec.GCMParameterSpec");
                } catch (ClassNotFoundException e) {
                    gcmSpecClass = null;
                }

                if (gcmSpecClass != null && gcmSpecClass.isAssignableFrom(params.getClass())) {
                    try {
                        Method getTLenMethod = gcmSpecClass.getMethod("getTLen");
                        Method getIVMethod = gcmSpecClass.getMethod("getIV");
                        tagLenBits = (int) getTLenMethod.invoke(params);
                        iv = (byte[]) getIVMethod.invoke(params);
                    } catch (NoSuchMethodException | IllegalAccessException e) {
                        throw new RuntimeException("GCMParameterSpec lacks expected methods", e);
                    } catch (InvocationTargetException e) {
                        throw new RuntimeException("Could not fetch GCM parameters",
                                e.getTargetException());
                    }
                } else if (params instanceof IvParameterSpec) {
                    IvParameterSpec ivParams = (IvParameterSpec) params;
                    iv = ivParams.getIV();
                    tagLenBits = 0;
                } else {
                    iv = null;
                    tagLenBits = 0;
                }
            }

            if (tagLenBits % 8 != 0) {
                throw new InvalidAlgorithmParameterException(
                        "Tag length must be a multiple of 8; was " + tagLen);
            }

            tagLen = tagLenBits / 8;

            final boolean encrypting = isEncrypting();

            evpAead = getEVP_AEAD(encodedKey.length);

            final int expectedIvLength = NativeCrypto.EVP_AEAD_nonce_length(evpAead);
            if (iv == null && expectedIvLength != 0) {
                if (!encrypting) {
                    throw new InvalidAlgorithmParameterException("IV must be specified in " + mode
                            + " mode");
                }

                iv = new byte[expectedIvLength];
                if (random == null) {
                    random = new SecureRandom();
                }
                random.nextBytes(iv);
            } else if (expectedIvLength == 0 && iv != null) {
                throw new InvalidAlgorithmParameterException("IV not used in " + mode + " mode");
            } else if (iv != null && iv.length != expectedIvLength) {
                throw new InvalidAlgorithmParameterException("Expected IV length of "
                        + expectedIvLength + " but was " + iv.length);
            }

            this.iv = iv;
            reset();
        }

        @Override
        protected int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output,
                int outputOffset, int maximumLen) throws ShortBufferException {
            if (buf == null) {
                throw new IllegalStateException("Cipher not initialized");
            }

            ArrayUtils.checkOffsetAndCount(input.length, inputOffset, inputLen);
            if (inputLen > 0) {
                expand(inputLen);
                System.arraycopy(input, inputOffset, buf, this.bufCount, inputLen);
                this.bufCount += inputLen;
            }
            return 0;
        }

        @Override
        protected int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
                throws IllegalBlockSizeException, BadPaddingException {
            EVP_AEAD_CTX cipherCtx = new EVP_AEAD_CTX(NativeCrypto.EVP_AEAD_CTX_init(evpAead,
                    encodedKey, tagLen));
            final int bytesWritten;
            try {
                if (isEncrypting()) {
                    bytesWritten = NativeCrypto.EVP_AEAD_CTX_seal(cipherCtx, output, outputOffset,
                            iv, buf, 0, bufCount, aad);
                } else {
                    bytesWritten = NativeCrypto.EVP_AEAD_CTX_open(cipherCtx, output, outputOffset,
                            iv, buf, 0, bufCount, aad);
                }
            } catch (BadPaddingException e) {
                Constructor<?> aeadBadTagConstructor = null;
                try {
                    aeadBadTagConstructor = Class.forName("javax.crypto.AEADBadTagException")
                            .getConstructor(String.class);
                } catch (ClassNotFoundException | NoSuchMethodException e2) {
                }

                if (aeadBadTagConstructor != null) {
                    BadPaddingException badTagException = null;
                    try {
                        badTagException = (BadPaddingException) aeadBadTagConstructor.newInstance(e
                                .getMessage());
                        badTagException.initCause(e.getCause());
                    } catch (IllegalAccessException | InstantiationException e2) {
                        // Fall through
                    } catch (InvocationTargetException e2) {
                        throw (BadPaddingException) new BadPaddingException().initCause(e2
                                .getTargetException());
                    }
                    if (badTagException != null) {
                        throw badTagException;
                    }
                }
                throw e;
            }
            reset();
            return bytesWritten;
        }

        @Override
        protected void checkSupportedPadding(Padding padding) throws NoSuchPaddingException {
            if (padding != Padding.NOPADDING) {
                throw new NoSuchPaddingException("Must be NoPadding for AEAD ciphers");
            }
        }

        @Override
        protected int getOutputSizeForFinal(int inputLen) {
            return bufCount + inputLen
                    + (isEncrypting() ? NativeCrypto.EVP_AEAD_max_overhead(evpAead) : 0);
        }

        /* @Override */
        protected void engineUpdateAAD(byte[] input, int inputOffset, int inputLen) {
            if (aad == null) {
                aad = Arrays.copyOfRange(input, inputOffset, inputLen);
            } else {
                int newSize = aad.length + inputLen;
                byte[] newaad = new byte[newSize];
                System.arraycopy(aad, 0, newaad, 0, aad.length);
                System.arraycopy(input, inputOffset, newaad, aad.length, inputLen);
                aad = newaad;
            }
        }

        protected abstract long getEVP_AEAD(int keyLength) throws InvalidKeyException;

        public abstract static class AES extends EVP_AEAD {
            private static final int AES_BLOCK_SIZE = 16;

            protected AES(Mode mode) {
                super(mode);
            }

            @Override
            protected void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
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
            protected String getBaseCipherName() {
                return "AES";
            }

            @Override
            protected int getCipherBlockSize() {
                return AES_BLOCK_SIZE;
            }

            /**
             * AEAD buffers everything until a final output.
             */
            @Override
            protected int getOutputSizeForUpdate(int inputLen) {
                return 0;
            }

            public static class GCM extends AES {
                public GCM() {
                    super(Mode.GCM);
                }

                @Override
                protected void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
                    if (mode != Mode.GCM) {
                        throw new NoSuchAlgorithmException("Mode must be GCM");
                    }
                }

                @Override
                protected long getEVP_AEAD(int keyLength) throws InvalidKeyException {
                    final long evpAead;
                    if (keyLength == 16) {
                        return NativeCrypto.EVP_aead_aes_128_gcm();
                    } else if (keyLength == 32) {
                        return NativeCrypto.EVP_aead_aes_256_gcm();
                    } else {
                        throw new RuntimeException("Unexpected key length: " + keyLength);
                    }
                }
            }
        }
    }
}
