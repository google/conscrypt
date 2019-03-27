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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
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
import org.conscrypt.NativeRef.EVP_CIPHER_CTX;

/**
 * An implementation of {@link Cipher} using BoringSSL as the backing library.
 */
@Internal
public abstract class OpenSSLCipher extends CipherSpi {

    /**
     * Modes that a block cipher may support.
     */
    enum Mode {
        NONE,
        CBC,
        CTR,
        ECB,
        GCM,
        POLY1305,
    }

    /**
     * Paddings that a block cipher may support.
     */
    enum Padding {
        NOPADDING,
        PKCS5PADDING,
        PKCS7PADDING,
        ;

        public static Padding getNormalized(String value) {
            Padding p = Padding.valueOf(value);
            if (p == PKCS7PADDING) {
                return PKCS5PADDING;
            }
            return p;
        }
    }

    /**
     * The current cipher mode.
     */
    Mode mode = Mode.ECB;

    /**
     * The current cipher padding.
     */
    private Padding padding = Padding.PKCS5PADDING;

    /**
     * May be used when reseting the cipher instance after calling
     * {@code doFinal}.
     */
    byte[] encodedKey;

    /**
     * The Initial Vector (IV) used for the current cipher.
     */
    byte[] iv;

    /**
     * Current cipher mode: encrypting or decrypting.
     */
    private boolean encrypting;

    /**
     * The block size of the current cipher.
     */
    private int blockSize;

    OpenSSLCipher() {
    }

    OpenSSLCipher(Mode mode, Padding padding) {
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
    abstract void engineInitInternal(byte[] encodedKey, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * API-specific implementation of updating the cipher. The
     * {@code maximumLen} will be the maximum length of the output as returned
     * by {@link #getOutputSizeForUpdate(int)}. The return value must be the
     * number of bytes processed and placed into {@code output}. On error, an
     * exception must be thrown.
     */
    abstract int updateInternal(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset, int maximumLen) throws ShortBufferException;

    /**
     * API-specific implementation of the final block. The {@code maximumLen}
     * will be the maximum length of the possible output as returned by
     * {@link #getOutputSizeForFinal(int)}. The return value must be the number
     * of bytes processed and placed into {@code output}. On error, an exception
     * must be thrown.
     */
    abstract int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
            throws IllegalBlockSizeException, BadPaddingException, ShortBufferException;

    /**
     * Returns the standard name for the particular algorithm.
     */
    abstract String getBaseCipherName();

    /**
     * Checks whether the cipher supports this particular {@code keySize} (in
     * bytes) and throws {@code InvalidKeyException} if it doesn't.
     */
    abstract void checkSupportedKeySize(int keySize) throws InvalidKeyException;

    /**
     * Checks whether the cipher supports this particular cipher {@code mode}
     * and throws {@code NoSuchAlgorithmException} if it doesn't.
     */
    abstract void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException;

    /**
     * Checks whether the cipher supports this particular cipher {@code padding}
     * and throws {@code NoSuchPaddingException} if it doesn't.
     */
    abstract void checkSupportedPadding(Padding padding) throws NoSuchPaddingException;

    abstract int getCipherBlockSize();

    boolean supportsVariableSizeKey() {
        return false;
    }

    boolean supportsVariableSizeIv() {
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
            padding = Padding.getNormalized(paddingStrUpper);
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
    Padding getPadding() {
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
    abstract int getOutputSizeForFinal(int inputLen);

    /**
     * The size of output if {@code update()} is called with this
     * {@code inputLen}. If padding is enabled and the size of the input puts it
     * right at the block size, it will add another block for the padding.
     */
    abstract int getOutputSizeForUpdate(int inputLen);

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return Math.max(getOutputSizeForUpdate(inputLen), getOutputSizeForFinal(inputLen));
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
                params.init(new IvParameterSpec(iv));
                return params;
            } catch (NoSuchAlgorithmException e) {
                return null;
            } catch (InvalidParameterSpecException e) {
                return null;
            }
        }
        return null;
    }

    protected AlgorithmParameterSpec getParameterSpec(AlgorithmParameters params)
            throws InvalidAlgorithmParameterException {
        if (params != null) {
            try {
                return params.getParameterSpec(IvParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                throw new InvalidAlgorithmParameterException(
                        "Params must be convertible to IvParameterSpec", e);
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
        AlgorithmParameterSpec spec = getParameterSpec(params);
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

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Only SecretKey is supported");
        }
        byte[] encodedKey = key.getEncoded();
        if (encodedKey == null) {
            throw new InvalidKeyException("key.getEncoded() == null");
        }
        checkSupportedKeySize(encodedKey.length);
        // The return value is in bits
        return encodedKey.length * 8;
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

    boolean isEncrypting() {
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
        boolean calledUpdate;

        /**
         * The block size of the current mode.
         */
        private int modeBlockSize;

        public EVP_CIPHER(Mode mode, Padding padding) {
            super(mode, padding);
        }

        @Override
        void engineInitInternal(byte[] encodedKey, AlgorithmParameterSpec params,
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
                if (random != null) {
                    random.nextBytes(iv);
                } else {
                    NativeCrypto.RAND_bytes(iv);
                }
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
        int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output,
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
        int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
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
        int getOutputSizeForFinal(int inputLen) {
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
        int getOutputSizeForUpdate(int inputLen) {
            return getOutputSizeForFinal(inputLen);
        }

        /**
         * Returns the OpenSSL cipher name for the particular {@code keySize}
         * and cipher {@code mode}.
         */
        abstract String getCipherName(int keySize, Mode mode);

        /**
         * Reset this Cipher instance state to process a new chunk of data.
         */
        private void reset() {
            NativeCrypto.EVP_CipherInit_ex(cipherCtx, 0, encodedKey, iv, isEncrypting());
            calledUpdate = false;
        }

        abstract static class AES_BASE extends EVP_CIPHER {
            private static final int AES_BLOCK_SIZE = 16;

            AES_BASE(Mode mode, Padding padding) {
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
        }

        public static class AES extends AES_BASE {
            AES(Mode mode, Padding padding) {
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

        public static class AES_128 extends AES_BASE {
            AES_128(Mode mode, Padding padding) {
                super(mode, padding);
            }

            public static class CBC extends AES_128 {
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

            public static class CTR extends AES_128 {
                public CTR() {
                    super(Mode.CTR, Padding.NOPADDING);
                }
            }

            public static class ECB extends AES_128 {
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
            void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
                if (keyLength != 16) { // 128 bits
                    throw new InvalidKeyException("Unsupported key size: " + keyLength + " bytes");
                }
            }
        }

        public static class AES_256 extends AES_BASE {
            AES_256(Mode mode, Padding padding) {
                super(mode, padding);
            }

            public static class CBC extends AES_256 {
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

            public static class CTR extends AES_256 {
                public CTR() {
                    super(Mode.CTR, Padding.NOPADDING);
                }
            }

            public static class ECB extends AES_256 {
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
            void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
                if (keyLength != 32) { // 256 bits
                    throw new InvalidKeyException("Unsupported key size: " + keyLength + " bytes");
                }
            }
        }

        public static class DESEDE extends EVP_CIPHER {
            private static final int DES_BLOCK_SIZE = 8;

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

        public static class ARC4 extends EVP_CIPHER {
            public ARC4() {
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
    }

    public static abstract class EVP_AEAD extends OpenSSLCipher {
        /**
         * The default tag size when one is not specified. Default to
         * full-length tags (128-bits or 16 octets).
         */
        private static final int DEFAULT_TAG_SIZE_BITS = 16 * 8;

        /**
         * Keeps track of the last used block size.
         */
        private static int lastGlobalMessageSize = 32;

        /**
         * The previously used key to prevent key + nonce (IV) reuse.
         */
        private byte[] previousKey;

        /**
         * The previously used nonce (IV) to prevent key + nonce reuse.
         */
        private byte[] previousIv;

        /**
         * When set this instance must be initialized before use again. This prevents key
         * and IV reuse.
         */
        private boolean mustInitialize;

        /**
         * The byte array containing the bytes written.
         */
        byte[] buf;

        /**
         * The number of bytes written.
         */
        int bufCount;

        /**
         * AEAD cipher reference.
         */
        long evpAead;

        /**
         * Additional authenticated data.
         */
        private byte[] aad;

        /**
         * The length of the AEAD cipher tag in bytes.
         */
        int tagLengthInBytes;

        public EVP_AEAD(Mode mode) {
            super(mode, Padding.NOPADDING);
        }

        private void checkInitialization() {
            if (mustInitialize) {
                throw new IllegalStateException(
                        "Cannot re-use same key and IV for multiple encryptions");
            }
        }

        /** Constant-time array comparison.  Since we are using this to compare keys, we want to
         * ensure there's no opportunity for a timing attack. */
        private boolean arraysAreEqual(byte[] a, byte[] b) {
            if (a.length != b.length) {
                return false;
            }

            int diff = 0;
            for (int i = 0; i < a.length; i++) {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
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
            aad = null;
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
        void engineInitInternal(byte[] encodedKey, AlgorithmParameterSpec params,
                SecureRandom random) throws InvalidKeyException,
                InvalidAlgorithmParameterException {
            byte[] iv;
            final int tagLenBits;
            if (params == null) {
                iv = null;
                tagLenBits = DEFAULT_TAG_SIZE_BITS;
            } else {
                GCMParameters gcmParams = Platform.fromGCMParameterSpec(params);
                if (gcmParams != null) {
                    iv = gcmParams.getIV();
                    tagLenBits = gcmParams.getTLen();
                } else if (params instanceof IvParameterSpec) {
                    IvParameterSpec ivParams = (IvParameterSpec) params;
                    iv = ivParams.getIV();
                    tagLenBits = DEFAULT_TAG_SIZE_BITS;
                } else {
                    iv = null;
                    tagLenBits = DEFAULT_TAG_SIZE_BITS;
                }
            }

            if (tagLenBits % 8 != 0) {
                throw new InvalidAlgorithmParameterException(
                        "Tag length must be a multiple of 8; was " + tagLengthInBytes);
            }

            tagLengthInBytes = tagLenBits / 8;

            final boolean encrypting = isEncrypting();

            evpAead = getEVP_AEAD(encodedKey.length);

            final int expectedIvLength = NativeCrypto.EVP_AEAD_nonce_length(evpAead);
            if (iv == null && expectedIvLength != 0) {
                if (!encrypting) {
                    throw new InvalidAlgorithmParameterException("IV must be specified in " + mode
                            + " mode");
                }

                iv = new byte[expectedIvLength];
                if (random != null) {
                    random.nextBytes(iv);
                } else {
                    NativeCrypto.RAND_bytes(iv);
                }
            } else if (expectedIvLength == 0 && iv != null) {
                throw new InvalidAlgorithmParameterException("IV not used in " + mode + " mode");
            } else if (iv != null && iv.length != expectedIvLength) {
                throw new InvalidAlgorithmParameterException("Expected IV length of "
                        + expectedIvLength + " but was " + iv.length);
            }

            if (isEncrypting() && iv != null) {
                if (previousKey != null && previousIv != null
                        && arraysAreEqual(previousKey, encodedKey)
                        && arraysAreEqual(previousIv, iv)) {
                    mustInitialize = true;
                    throw new InvalidAlgorithmParameterException(
                            "When using AEAD key and IV must not be re-used");
                }

                this.previousKey = encodedKey;
                this.previousIv = iv;
            }
            mustInitialize = false;
            this.iv = iv;
            reset();
        }

        @Override
        protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
                int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
                BadPaddingException {
            // Because the EVP_AEAD updateInternal processes input but doesn't create any output
            // (and thus can't check the output buffer), we need to add this check before the
            // superclass' processing to ensure that updateInternal is never called if the
            // output buffer isn't large enough.
            if (output != null) {
                if (getOutputSizeForFinal(inputLen) > output.length - outputOffset) {
                    throw new ShortBufferException("Insufficient output space");
                }
            }
            return super.engineDoFinal(input, inputOffset, inputLen, output, outputOffset);
        }

        @Override
        int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output,
                int outputOffset, int maximumLen) throws ShortBufferException {
            checkInitialization();
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

        @SuppressWarnings("LiteralClassName")
        private void throwAEADBadTagExceptionIfAvailable(String message, Throwable cause)
                throws BadPaddingException {
            Constructor<?> aeadBadTagConstructor;
            try {
                aeadBadTagConstructor = Class.forName("javax.crypto.AEADBadTagException")
                                                .getConstructor(String.class);
            } catch (Exception ignored) {
                return;
            }

            BadPaddingException badTagException = null;
            try {
                badTagException = (BadPaddingException) aeadBadTagConstructor.newInstance(message);
                badTagException.initCause(cause);
            } catch (IllegalAccessException e2) {
                // Fall through
            } catch (InstantiationException e2) {
                // Fall through
            } catch (InvocationTargetException e2) {
                throw(BadPaddingException) new BadPaddingException().initCause(
                        e2.getTargetException());
            }
            if (badTagException != null) {
                throw badTagException;
            }
        }

        @Override
        int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
                throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
            checkInitialization();
            final int bytesWritten;
            try {
                if (isEncrypting()) {
                    bytesWritten = NativeCrypto.EVP_AEAD_CTX_seal(evpAead, encodedKey,
                            tagLengthInBytes, output, outputOffset, iv, buf, 0, bufCount, aad);
                } else {
                    bytesWritten = NativeCrypto.EVP_AEAD_CTX_open(evpAead, encodedKey,
                            tagLengthInBytes, output, outputOffset, iv, buf, 0, bufCount, aad);
                }
            } catch (BadPaddingException e) {
                throwAEADBadTagExceptionIfAvailable(e.getMessage(), e.getCause());
                throw e;
            }
            if (isEncrypting()) {
                mustInitialize = true;
            }
            reset();
            return bytesWritten;
        }

        @Override
        void checkSupportedPadding(Padding padding) throws NoSuchPaddingException {
            if (padding != Padding.NOPADDING) {
                throw new NoSuchPaddingException("Must be NoPadding for AEAD ciphers");
            }
        }

        /**
         * AEAD buffers everything until a final output.
         */
        @Override
        int getOutputSizeForUpdate(int inputLen) {
            return 0;
        }

        @Override
        int getOutputSizeForFinal(int inputLen) {
            return bufCount + inputLen
                    + (isEncrypting() ? NativeCrypto.EVP_AEAD_max_overhead(evpAead) : 0);
        }

        // Intentionally missing Override to compile on old versions of Android
        @SuppressWarnings("MissingOverride")
        protected void engineUpdateAAD(byte[] input, int inputOffset, int inputLen) {
            checkInitialization();
            if (aad == null) {
                aad = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen);
            } else {
                int newSize = aad.length + inputLen;
                byte[] newaad = new byte[newSize];
                System.arraycopy(aad, 0, newaad, 0, aad.length);
                System.arraycopy(input, inputOffset, newaad, aad.length, inputLen);
                aad = newaad;
            }
        }

        // Intentionally missing Override to compile on old versions of Android
        @SuppressWarnings("MissingOverride")
        protected void engineUpdateAAD(ByteBuffer buf) {
            checkInitialization();
            if (aad == null) {
                aad = new byte[buf.remaining()];
                buf.get(aad);
            } else {
                int newSize = aad.length + buf.remaining();
                byte[] newaad = new byte[newSize];
                System.arraycopy(aad, 0, newaad, 0, aad.length);
                buf.get(newaad, aad.length, buf.remaining());
                aad = newaad;
            }
        }

        abstract long getEVP_AEAD(int keyLength) throws InvalidKeyException;

        public abstract static class AES extends EVP_AEAD {
            private static final int AES_BLOCK_SIZE = 16;

            AES(Mode mode) {
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

            public static class GCM extends AES {

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
                long getEVP_AEAD(int keyLength) throws InvalidKeyException {
                    if (keyLength == 16) {
                        return NativeCrypto.EVP_aead_aes_128_gcm();
                    } else if (keyLength == 32) {
                        return NativeCrypto.EVP_aead_aes_256_gcm();
                    } else {
                        throw new RuntimeException("Unexpected key length: " + keyLength);
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
        }

        public static class ChaCha20 extends EVP_AEAD {
            public ChaCha20() {
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
    }
}
