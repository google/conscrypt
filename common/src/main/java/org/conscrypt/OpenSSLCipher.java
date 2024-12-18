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
        GCM_SIV,
        POLY1305,
        ;

        public static Mode getNormalized(String modeString) {
            modeString = modeString.toUpperCase(Locale.US);
            // We use GCM-SIV as the mode string, but - isn't a valid identifier character, so
            // we need to ensure GCM-SIV is recognized and GCM_SIV isn't.
            if (modeString.equals("GCM-SIV")) {
                return GCM_SIV;
            } else if (modeString.equals("GCM_SIV")) {
                throw new IllegalArgumentException("Invalid mode");
            } else {
                return Mode.valueOf(modeString);
            }
        }
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
            Padding p = Padding.valueOf(value.toUpperCase(Locale.US));
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
            mode = Mode.getNormalized(modeStr);
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
        final Padding padding;
        try {
            padding = Padding.getNormalized(paddingStr);
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

}
