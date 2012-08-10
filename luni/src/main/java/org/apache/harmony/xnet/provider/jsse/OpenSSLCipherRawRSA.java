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
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class OpenSSLCipherRawRSA extends CipherSpi {
    /**
     * An empty list that is returned from update calls.
     */
    private static final byte[] emptyList = new byte[0];

    /**
     * The current OpenSSL key we're operating on.
     */
    private OpenSSLKey key;

    /**
     * Current cipher mode: encrypting or decrypting.
     */
    private boolean usingPrivateKey;

    /**
     * Buffer for operations
     */
    private byte[] buffer;

    /**
     * Current offset in the buffer.
     */
    private int bufferOffset;

    /**
     * Flag that indicates an exception should be thrown when the input is too
     * large during doFinal.
     */
    private boolean inputTooLarge;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        final String modeUpper = mode.toUpperCase();
        if ("NONE".equals(modeUpper) || "ECB".equals(modeUpper)) {
            return;
        }

        throw new NoSuchAlgorithmException("mode not supported: " + mode);
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        final String paddingUpper = padding.toUpperCase();
        if ("NOPADDING".equals(paddingUpper)) {
            return;
        }

        throw new NoSuchPaddingException("padding not supported: " + padding);
    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (key == null) {
            throw new IllegalStateException("cipher is not initialized");
        }

        return buffer.length;
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private void engineInitInternal(int opmode, Key key) throws InvalidKeyException {
        if (key instanceof OpenSSLRSAPrivateKey) {
            OpenSSLRSAPrivateKey rsaPrivateKey = (OpenSSLRSAPrivateKey) key;
            usingPrivateKey = true;
            this.key = rsaPrivateKey.getOpenSSLKey();
        } else if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) key;
            usingPrivateKey = true;
            this.key = OpenSSLRSAPrivateCrtKey.getInstance(rsaPrivateKey);
        } else if (key instanceof RSAPrivateKey) {
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) key;
            usingPrivateKey = true;
            this.key = OpenSSLRSAPrivateKey.getInstance(rsaPrivateKey);
        } else if (key instanceof OpenSSLRSAPublicKey) {
            OpenSSLRSAPublicKey rsaPublicKey = (OpenSSLRSAPublicKey) key;
            usingPrivateKey = false;
            this.key = rsaPublicKey.getOpenSSLKey();
        } else if (key instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) key;
            usingPrivateKey = false;
            this.key = OpenSSLRSAPublicKey.getInstance(rsaPublicKey);
        } else {
            throw new InvalidKeyException("Need RSA private or public key");
        }

        buffer = new byte[NativeCrypto.RSA_size(this.key.getPkeyContext())];
        inputTooLarge = false;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        engineInitInternal(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("unknown param type: "
                    + params.getClass().getName());
        }

        engineInitInternal(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("unknown param type: "
                    + params.getClass().getName());
        }

        engineInitInternal(opmode, key);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (bufferOffset + inputLen > buffer.length) {
            inputTooLarge = true;
            return emptyList;
        }

        System.arraycopy(input, inputOffset, buffer, bufferOffset, inputLen);
        bufferOffset += inputLen;
        return emptyList;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        engineUpdate(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (input != null) {
            engineUpdate(input, inputOffset, inputLen);
        }

        if (inputTooLarge) {
            throw new IllegalBlockSizeException("input must be under " + buffer.length + " bytes");
        }

        final byte[] tmpBuf;
        if (bufferOffset != buffer.length) {
            tmpBuf = new byte[buffer.length];
            System.arraycopy(buffer, 0, tmpBuf, buffer.length - bufferOffset, bufferOffset);
        } else {
            tmpBuf = buffer;
        }

        final byte[] output = new byte[buffer.length];
        if (usingPrivateKey) {
            NativeCrypto.RSA_private_encrypt(tmpBuf.length, tmpBuf, output, key.getPkeyContext(),
                    NativeCrypto.RSA_NO_PADDING);
        } else {
            NativeCrypto.RSA_public_decrypt(tmpBuf.length, tmpBuf, output, key.getPkeyContext(),
                    NativeCrypto.RSA_NO_PADDING);
        }

        bufferOffset = 0;
        return output;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
        byte[] b = engineDoFinal(input, inputOffset, inputLen);

        final int lastOffset = outputOffset + b.length;
        if (lastOffset > output.length) {
            throw new ShortBufferException("output buffer is too small " + output.length + " < "
                    + lastOffset);
        }

        System.arraycopy(b, 0, output, outputOffset, b.length);
        return b.length;
    }
}
