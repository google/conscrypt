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

package org.apache.harmony.xnet.provider.jsse;

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

import libcore.util.EmptyArray;

public abstract class OpenSSLCipher extends CipherSpi {

    /**
     * Modes that a block cipher may support.
     */
    protected static enum Mode {
        CBC,
        CFB, CFB1, CFB8, CFB128,
        CTR,
        CTS,
        ECB,
        OFB, OFB64, OFB128,
        PCBC,
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
     * Native pointer for the OpenSSL EVP_CIPHER context.
     */
    private OpenSSLCipherContext cipherCtx = new OpenSSLCipherContext(
            NativeCrypto.EVP_CIPHER_CTX_new());

    /**
     * The current cipher mode.
     */
    private Mode mode = Mode.ECB;

    /**
     * The current cipher padding.
     */
    private Padding padding = Padding.PKCS5PADDING;

    /**
     * The Initial Vector (IV) used for the current cipher.
     */
    private byte[] iv;

    /**
     * Current cipher mode: encrypting or decrypting.
     */
    private boolean encrypting;

    /**
     * The block size of the current cipher.
     */
    private int blockSize;

    /**
     * The block size of the current mode.
     */
    private int modeBlockSize;

    /**
     * Buffer to hold a block-sized entry before calling into OpenSSL.
     */
    private byte[] buffer;

    /**
     * Current offset in the buffer.
     */
    private int bufferOffset;

    protected OpenSSLCipher() {
    }

    protected OpenSSLCipher(Mode mode, Padding padding) {
        this.mode = mode;
        this.padding = padding;
        blockSize = getCipherBlockSize();
    }

    /**
     * Returns the OpenSSL cipher name for the particular {@code keySize} and
     * cipher {@code mode}.
     */
    protected abstract String getCipherName(int keySize, Mode mode);

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

    @Override
    protected void engineSetMode(String modeStr) throws NoSuchAlgorithmException {
        final Mode mode;
        try {
            mode = Mode.valueOf(modeStr.toUpperCase(Locale.US));
        } catch (IllegalArgumentException e) {
            NoSuchAlgorithmException newE = new NoSuchAlgorithmException("No such mode: "
                    + modeStr);
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

    @Override
    protected int engineGetBlockSize() {
        return blockSize;
    }

    /**
     * The size of output if {@code doFinal()} is called with this
     * {@code inputLen}. If padding is enabled and the size of the input puts it
     * right at the block size, it will add another block for the padding.
     */
    private final int getFinalOutputSize(int inputLen) {
        final int totalLen = bufferOffset + inputLen;
        final int overrunLen = totalLen % blockSize;

        if (overrunLen == 0) {
            if ((padding == Padding.NOPADDING) && (totalLen > 0)) {
                return totalLen;
            } else {
                return totalLen + blockSize;
            }
        } else {
            return totalLen - overrunLen + blockSize;
        }
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return getFinalOutputSize(inputLen);
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private void engineInitInternal(int opmode, Key key, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException {
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

        final int cipherType = NativeCrypto.EVP_get_cipherbyname(getCipherName(encodedKey.length,
                mode));
        if (cipherType == 0) {
            throw new InvalidAlgorithmParameterException("Cannot find name for key length = "
                    + (encodedKey.length * 8) + " and mode = " + mode);
        }

        final int ivLength = NativeCrypto.EVP_CIPHER_iv_length(cipherType);
        if (iv == null) {
            iv = new byte[ivLength];
        } else if (iv.length != ivLength) {
            throw new InvalidAlgorithmParameterException("expected IV length of " + ivLength);
        }

        this.iv = iv;

        NativeCrypto.EVP_CipherInit_ex(cipherCtx.getContext(), cipherType, encodedKey, iv,
                encrypting);

        // OpenSSL only supports PKCS5 Padding.
        NativeCrypto.EVP_CIPHER_CTX_set_padding(cipherCtx.getContext(),
                padding == Padding.PKCS5PADDING);
        modeBlockSize = NativeCrypto.EVP_CIPHER_CTX_block_size(cipherCtx.getContext());

        buffer = new byte[blockSize];
        bufferOffset = 0;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInitInternal(opmode, key, null);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        final byte[] iv;
        if (params instanceof IvParameterSpec) {
            IvParameterSpec ivParams = (IvParameterSpec) params;
            iv = ivParams.getIV();
        } else {
            iv = null;
        }

        engineInitInternal(opmode, key, iv);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        final AlgorithmParameterSpec spec;
        try {
            spec = params.getParameterSpec(IvParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException(e);
        }

        engineInit(opmode, key, spec, random);
    }

    private final int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, int totalLen, int fullBlocksSize) throws ShortBufferException {
        final int intialOutputOffset = outputOffset;

        /* Take care of existing buffered bytes. */
        final int remainingBuffer = buffer.length - bufferOffset;
        if (bufferOffset > 0 && inputLen >= remainingBuffer) {
            System.arraycopy(input, inputOffset, buffer, bufferOffset, remainingBuffer);
            final int writtenBytes = NativeCrypto.EVP_CipherUpdate(cipherCtx.getContext(), output,
                    outputOffset, buffer, 0, blockSize);
            fullBlocksSize -= writtenBytes;
            outputOffset += writtenBytes;

            inputLen -= remainingBuffer;
            inputOffset += remainingBuffer;

            bufferOffset = 0;
        }

        /* Take care of the bytes that would fill up our block-sized buffer. */
        if (fullBlocksSize > 0) {
            final int bytesLeft = output.length - outputOffset;
            if (bytesLeft < fullBlocksSize) {
                throw new ShortBufferException("output buffer too small during update: "
                        + bytesLeft + " < " + fullBlocksSize);
            }

            outputOffset += NativeCrypto.EVP_CipherUpdate(cipherCtx.getContext(), output,
                    outputOffset, input, inputOffset, fullBlocksSize);
            inputLen -= fullBlocksSize;
            inputOffset += fullBlocksSize;
        }

        /* Put the rest into the buffer for next time. */
        if (inputLen > 0) {
            System.arraycopy(input, inputOffset, buffer, bufferOffset, inputLen);
            bufferOffset += inputLen;
        }

        return outputOffset - intialOutputOffset;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        final int totalLen = bufferOffset + inputLen;
        final int fullBlocksSize = totalLen - (totalLen % blockSize);

        /* See how large our output buffer would need to be. */
        final byte[] output;
        if (fullBlocksSize > 0) {
            output = new byte[fullBlocksSize];
        } else {
            output = EmptyArray.BYTE;
        }

        try {
            updateInternal(input, inputOffset, inputLen, output, 0, totalLen, fullBlocksSize);
        } catch (ShortBufferException e) {
            /* This shouldn't happen. */
            throw new AssertionError("calculated buffer size was wrong: " + fullBlocksSize);
        }

        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        final int totalLen = bufferOffset + inputLen;
        final int fullBlocksSize = totalLen - (totalLen % modeBlockSize);
        return updateInternal(input, inputOffset, inputLen, output, outputOffset, totalLen, fullBlocksSize);
    }

    private int doFinalInternal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, int totalLen, int trailingLen, int maximumPossibleSize)
            throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
        if ((trailingLen != 0) && (padding == Padding.NOPADDING)) {
            throw new IllegalBlockSizeException("not multiple of block size " + trailingLen
                    + " != " + modeBlockSize);
        }

        /* Remember this so we can tell how many characters were written. */
        final int initialOutputOffset = outputOffset;

        if (inputLen > 0) {
            /*
             * First run update to set up our invariant that we have less than
             * {@code blockSize} worth of bytes for the next CipherUpdate call.
             */
            final int updateSize;
            if (trailingLen == 0 && maximumPossibleSize >= blockSize) {
                updateSize = maximumPossibleSize - blockSize;
            } else {
                updateSize = maximumPossibleSize - trailingLen;
            }
            final int updateBytesWritten = updateInternal(input, inputOffset, inputLen, output,
                    outputOffset, totalLen, updateSize);
            outputOffset += updateBytesWritten;
        }

        /* Take care of existing buffered bytes. */
        if (bufferOffset > 0) {
            final int bytesLeft = output.length - outputOffset;

            final int bytesNeeded = bufferOffset + modeBlockSize - 1;
            final int writtenBytes;
            if (bytesLeft < bytesNeeded) {
                final byte[] tmpBuf = new byte[bytesNeeded];
                writtenBytes = NativeCrypto.EVP_CipherUpdate(cipherCtx.getContext(), tmpBuf, 0,
                        buffer, 0, bufferOffset);
                if (writtenBytes > 0) {
                    if (writtenBytes > bytesLeft) {
                        System.arraycopy(tmpBuf, 0, output, outputOffset, bytesLeft);
                    } else {
                        System.arraycopy(tmpBuf, 0, output, outputOffset, writtenBytes);
                    }
                }
            } else {
                writtenBytes = NativeCrypto.EVP_CipherUpdate(cipherCtx.getContext(), output,
                        outputOffset, buffer, 0, bufferOffset);
            }

            outputOffset += writtenBytes;
            bufferOffset = 0;
        }

        /* Allow OpenSSL to pad if necessary and clean up state. */
        final int bytesLeft = output.length - outputOffset;
        final int writtenBytes;
        if (bytesLeft >= blockSize) {
            writtenBytes = NativeCrypto.EVP_CipherFinal_ex(cipherCtx.getContext(), output,
                    outputOffset);
        } else {
            writtenBytes = NativeCrypto.EVP_CipherFinal_ex(cipherCtx.getContext(), buffer, 0);
            if (writtenBytes > bytesLeft) {
                throw new ShortBufferException("buffer is too short: " + writtenBytes + " > "
                        + bytesLeft);
            } else if (writtenBytes > 0) {
                System.arraycopy(buffer, 0, output, outputOffset, writtenBytes);
            }
        }
        outputOffset += writtenBytes;

        /* Re-initialize the cipher for the next time. */
        NativeCrypto.EVP_CipherInit_ex(cipherCtx.getContext(), 0, null, null, encrypting);

        return outputOffset - initialOutputOffset;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        final int totalLen = bufferOffset + inputLen;
        final int trailingLen = totalLen % modeBlockSize;

        final int maximumPossibleSize = calculateMaximumPossibleSize(totalLen, trailingLen);
        /* Assume that we'll output exactly on a byte boundary. */
        byte[] output = new byte[maximumPossibleSize];
        final int bytesWritten;
        try {
            bytesWritten = doFinalInternal(input, inputOffset, inputLen, output, 0, totalLen,
                    trailingLen, maximumPossibleSize);
        } catch (ShortBufferException e) {
            /* This should not happen since we sized our own buffer. */
            throw new RuntimeException("our calculated buffer was too small", e);
        }

        if (bytesWritten == output.length) {
            return output;
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

        final int totalLen = bufferOffset + inputLen;
        final int trailingLen = totalLen % modeBlockSize;

        final int maximumPossibleSize = calculateMaximumPossibleSize(totalLen, trailingLen);

        return doFinalInternal(input, inputOffset, inputLen, output, outputOffset, totalLen,
                trailingLen, maximumPossibleSize);
    }

    private int calculateMaximumPossibleSize(final int totalLen, final int trailingLen) {
        if (encrypting && (modeBlockSize > 1) && (padding != Padding.NOPADDING)) {
            return totalLen - trailingLen + modeBlockSize;
        } else {
            return totalLen;
        }
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

    public static class AES extends OpenSSLCipher {
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

        public static class CFB extends AES {
            public CFB(Padding padding) {
                super(Mode.CFB, padding);
            }

            public static class NoPadding extends CFB {
                public NoPadding() {
                    super(Padding.NOPADDING);
                }
            }

            public static class PKCS5Padding extends CFB {
                public PKCS5Padding() {
                    super(Padding.PKCS5PADDING);
                }
            }
        }

        public static class CTR extends AES {
            public CTR(Padding padding) {
                super(Mode.CTR, padding);
            }

            public static class NoPadding extends CTR {
                public NoPadding() {
                    super(Padding.NOPADDING);
                }
            }

            public static class PKCS5Padding extends CTR {
                public PKCS5Padding() {
                    super(Padding.PKCS5PADDING);
                }
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

        public static class OFB extends AES {
            public OFB(Padding padding) {
                super(Mode.OFB, padding);
            }

            public static class NoPadding extends OFB {
                public NoPadding() {
                    super(Padding.NOPADDING);
                }
            }

            public static class PKCS5Padding extends OFB {
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
                    throw new InvalidKeyException("Unsupported key size: " + keyLength + " bytes");
            }
        }

        @Override
        protected void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
            switch (mode) {
                case CBC:
                case CFB:
                case CFB1:
                case CFB8:
                case CFB128:
                case CTR:
                case ECB:
                case OFB:
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
                    throw new NoSuchPaddingException("Unsupported padding " + padding.toString());
            }
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
}
