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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import org.conscrypt.NativeRef.EVP_CIPHER_CTX;

@Internal
public abstract class OpenSSLEvpCipher extends OpenSSLCipher {
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
    private boolean calledUpdate;

    /**
     * The block size of the current mode.
     */
    private int modeBlockSize;

    protected OpenSSLEvpCipher(Mode mode, Padding padding) {
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
            throw new ShortBufferWithoutStackTraceException("output buffer too small during update: "
                    + bytesLeft + " < " + maximumLen);
        }

        outputOffset += NativeCrypto.EVP_CipherUpdate(cipherCtx, output, outputOffset, input,
                inputOffset, inputLen);

        calledUpdate = true;

        return outputOffset - intialOutputOffset;
    }

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
                throw new ShortBufferWithoutStackTraceException("buffer is too short: " + writtenBytes + " > "
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

}
