/*
 * Copyright (C) 2017 The Android Open Source Project
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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

/**
 * Implementation of the ChaCha20 stream cipher.
 *
 * @hide
 */
@Internal
public class OpenSSLCipherChaCha20 extends OpenSSLCipher {

    private static final int BLOCK_SIZE_BYTES = 64;
    private static final int NONCE_SIZE_BYTES = 12;

    // BoringSSL's interface encrypts by the block, so we need to keep track of whether we
    // had unused keystream bytes at the end of the previous encryption operation, so that
    // we can use them before moving on to the next block.
    private int currentBlockConsumedBytes = 0;
    private int blockCounter = 0;

    public OpenSSLCipherChaCha20() {}

    @Override
    void engineInitInternal(byte[] encodedKey, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params instanceof IvParameterSpec) {
            IvParameterSpec ivParams = (IvParameterSpec) params;
            if (ivParams.getIV().length != NONCE_SIZE_BYTES) {
                throw new InvalidAlgorithmParameterException("IV must be 12 bytes long");
            }
            iv = ivParams.getIV();
        } else {
            if (!isEncrypting()) {
                throw new InvalidAlgorithmParameterException(
                        "IV must be specified when encrypting");
            }
            iv = new byte[NONCE_SIZE_BYTES];
            if (random != null) {
                random.nextBytes(iv);
            } else {
                NativeCrypto.RAND_bytes(iv);
            }
        }
    }

    @Override
    int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset,
            int maximumLen) throws ShortBufferException {
        int inputLenRemaining = inputLen;
        if (currentBlockConsumedBytes > 0) {
            // A previous operation ended with a partial block, so we need to encrypt using
            // the remainder of that block before beginning to use the next block
            int len = Math.min(BLOCK_SIZE_BYTES - currentBlockConsumedBytes, inputLenRemaining);
            byte[] singleBlock = new byte[BLOCK_SIZE_BYTES];
            byte[] singleBlockOut = new byte[BLOCK_SIZE_BYTES];
            System.arraycopy(input, inputOffset, singleBlock, currentBlockConsumedBytes, len);
            NativeCrypto.chacha20_encrypt_decrypt(singleBlock, 0, singleBlockOut, 0,
                    BLOCK_SIZE_BYTES, encodedKey, iv, blockCounter);
            System.arraycopy(singleBlockOut, currentBlockConsumedBytes, output, outputOffset, len);
            currentBlockConsumedBytes += len;
            if (currentBlockConsumedBytes < BLOCK_SIZE_BYTES) {
                // We still didn't finish this block, so we're done.
                return len;
            }
            assert currentBlockConsumedBytes == BLOCK_SIZE_BYTES;
            currentBlockConsumedBytes = 0;
            inputOffset += len;
            outputOffset += len;
            inputLenRemaining -= len;
            blockCounter++;
        }
        NativeCrypto.chacha20_encrypt_decrypt(input, inputOffset, output,
                outputOffset, inputLenRemaining, encodedKey, iv, blockCounter);
        currentBlockConsumedBytes = inputLenRemaining % BLOCK_SIZE_BYTES;
        blockCounter += inputLenRemaining / BLOCK_SIZE_BYTES;
        return inputLen;
    }

    @Override
    int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
            throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
        reset();
        return 0;
    }

    private void reset() {
        blockCounter = 0;
        currentBlockConsumedBytes = 0;
    }

    @Override
    String getBaseCipherName() {
        return "ChaCha20";
    }

    @Override
    void checkSupportedKeySize(int keySize) throws InvalidKeyException {
        if (keySize != 32) {
            throw new InvalidKeyException("Unsupported key size: " + keySize
                    + " bytes (must be 32)");
        }
    }

    @Override
    void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
        if (mode != Mode.NONE) {
            throw new NoSuchAlgorithmException("Mode must be NONE");
        }
    }

    @Override
    void checkSupportedPadding(Padding padding) throws NoSuchPaddingException {
        if (padding != Padding.NOPADDING) {
            throw new NoSuchPaddingException("Must be NoPadding");
        }
    }

    @Override
    int getCipherBlockSize() {
        return 0;
    }

    @Override
    int getOutputSizeForFinal(int inputLen) {
        return inputLen;
    }

    @Override
    int getOutputSizeForUpdate(int inputLen) {
        return inputLen;
    }

}
