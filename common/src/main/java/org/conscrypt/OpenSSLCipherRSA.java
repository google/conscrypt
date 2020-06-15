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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

@Internal
public abstract class OpenSSLCipherRSA extends CipherSpi {
    /**
     * The current OpenSSL key we're operating on.
     */
    OpenSSLKey key;

    /**
     * Current key type: private or public.
     */
    boolean usingPrivateKey;

    /**
     * Current cipher mode: encrypting or decrypting.
     */
    boolean encrypting;

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

    /**
     * Current padding mode
     */
    int padding = NativeConstants.RSA_PKCS1_PADDING;

    OpenSSLCipherRSA(int padding) {
        this.padding = padding;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        final String modeUpper = mode.toUpperCase(Locale.ROOT);
        if ("NONE".equals(modeUpper) || "ECB".equals(modeUpper)) {
            return;
        }

        throw new NoSuchAlgorithmException("mode not supported: " + mode);
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        final String paddingUpper = padding.toUpperCase(Locale.ROOT);
        if ("PKCS1PADDING".equals(paddingUpper)) {
            this.padding = NativeConstants.RSA_PKCS1_PADDING;
            return;
        }
        if ("NOPADDING".equals(paddingUpper)) {
            this.padding = NativeConstants.RSA_NO_PADDING;
            return;
        }

        throw new NoSuchPaddingException("padding not supported: " + padding);
    }

    @Override
    protected int engineGetBlockSize() {
        if (encrypting) {
            return paddedBlockSizeBytes();
        }
        return keySizeBytes();
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (encrypting) {
            return keySizeBytes();
        }
        return paddedBlockSizeBytes();
    }

    int paddedBlockSizeBytes() {
        int paddedBlockSizeBytes = keySizeBytes();
        if (padding == NativeConstants.RSA_PKCS1_PADDING) {
            paddedBlockSizeBytes--;  // for 0 prefix
            paddedBlockSizeBytes -= 10;  // PKCS1 padding header length
        }
        return paddedBlockSizeBytes;
    }

    int keySizeBytes() {
        if (!isInitialized()) {
            throw new IllegalStateException("cipher is not initialized");
        }
        return NativeCrypto.RSA_size(this.key.getNativeRef());
    }

    /**
     * Returns {@code true} if the cipher has been initialized.
     */
    boolean isInitialized() {
        return key != null;
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    void doCryptoInit(AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException {}

    void engineInitInternal(int opmode, Key key, AlgorithmParameterSpec spec)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            encrypting = true;
        } else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
            encrypting = false;
        } else {
            throw new InvalidParameterException("Unsupported opmode " + opmode);
        }

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
            if (null == key) {
                throw new InvalidKeyException("RSA private or public key is null");
            }

            throw new InvalidKeyException("Need RSA private or public key");
        }

        buffer = new byte[NativeCrypto.RSA_size(this.key.getNativeRef())];
        bufferOffset = 0;
        inputTooLarge = false;

        doCryptoInit(spec);
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key instanceof OpenSSLRSAPrivateKey) {
            return ((OpenSSLRSAPrivateKey) key).getModulus().bitLength();
        }
        if (key instanceof RSAPrivateCrtKey) {
            return ((RSAPrivateCrtKey) key).getModulus().bitLength();
        }
        if (key instanceof RSAPrivateKey) {
            return ((RSAPrivateKey) key).getModulus().bitLength();
        }
        if (key instanceof OpenSSLRSAPublicKey) {
            return ((OpenSSLRSAPublicKey) key).getModulus().bitLength();
        }
        if (key instanceof RSAPublicKey) {
            return ((RSAPublicKey) key).getModulus().bitLength();
        }
        if (null == key) {
            throw new InvalidKeyException("RSA private or public key is null");
        }
        throw new InvalidKeyException("Need RSA private or public key");
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInitInternal(opmode, key, null);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException("Algorithm parameters rejected when none supplied", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("unknown param type: "
                    + params.getClass().getName());
        }

        engineInitInternal(opmode, key, params);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("unknown param type: "
                    + params.getClass().getName());
        }

        engineInitInternal(opmode, key, null);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (bufferOffset + inputLen > buffer.length) {
            inputTooLarge = true;
            return EmptyArray.BYTE;
        }

        System.arraycopy(input, inputOffset, buffer, bufferOffset, inputLen);
        bufferOffset += inputLen;
        return EmptyArray.BYTE;
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
            if (padding == NativeConstants.RSA_NO_PADDING) {
                tmpBuf = new byte[buffer.length];
                System.arraycopy(buffer, 0, tmpBuf, buffer.length - bufferOffset, bufferOffset);
            } else {
                tmpBuf = Arrays.copyOf(buffer, bufferOffset);
            }
        } else {
            tmpBuf = buffer;
        }

        byte[] output = new byte[buffer.length];
        int resultSize = doCryptoOperation(tmpBuf, output);
        if (!encrypting && resultSize != output.length) {
            output = Arrays.copyOf(output, resultSize);
        }

        bufferOffset = 0;
        return output;
    }

    abstract int doCryptoOperation(final byte[] tmpBuf, byte[] output)
            throws BadPaddingException, IllegalBlockSizeException;

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
        byte[] b = engineDoFinal(input, inputOffset, inputLen);

        final int lastOffset = outputOffset + b.length;
        if (lastOffset > output.length) {
            throw new ShortBufferWithoutStackTraceException("output buffer is too small " + output.length + " < "
                    + lastOffset);
        }

        System.arraycopy(b, 0, output, outputOffset, b.length);
        return b.length;
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
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
            int wrappedKeyType) throws InvalidKeyException, NoSuchAlgorithmException {
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

    public abstract static class DirectRSA extends OpenSSLCipherRSA {
        public DirectRSA(int padding) {
            super(padding);
        }

        @Override
        int doCryptoOperation(final byte[] tmpBuf, byte[] output)
                throws BadPaddingException, IllegalBlockSizeException {
            int resultSize;
            if (encrypting) {
                if (usingPrivateKey) {
                    resultSize = NativeCrypto.RSA_private_encrypt(
                            tmpBuf.length, tmpBuf, output, key.getNativeRef(), padding);
                } else {
                    resultSize = NativeCrypto.RSA_public_encrypt(
                            tmpBuf.length, tmpBuf, output, key.getNativeRef(), padding);
                }
            } else {
                try {
                    if (usingPrivateKey) {
                        resultSize = NativeCrypto.RSA_private_decrypt(
                                tmpBuf.length, tmpBuf, output, key.getNativeRef(), padding);
                    } else {
                        resultSize = NativeCrypto.RSA_public_decrypt(
                                tmpBuf.length, tmpBuf, output, key.getNativeRef(), padding);
                    }
                } catch (SignatureException e) {
                    IllegalBlockSizeException newE = new IllegalBlockSizeException();
                    newE.initCause(e);
                    throw newE;
                }
            }
            return resultSize;
        }
    }

    public static final class PKCS1 extends DirectRSA {
        public PKCS1() {
            super(NativeConstants.RSA_PKCS1_PADDING);
        }
    }

    public static final class Raw extends DirectRSA {
        public Raw() {
            super(NativeConstants.RSA_NO_PADDING);
        }
    }

    public static class OAEP extends OpenSSLCipherRSA {
        private long oaepMd;
        private int oaepMdSizeBytes;

        private long mgf1Md;

        private byte[] label;

        private NativeRef.EVP_PKEY_CTX pkeyCtx;

        public OAEP(long defaultMd, int defaultMdSizeBytes) {
            super(NativeConstants.RSA_PKCS1_OAEP_PADDING);
            oaepMd = mgf1Md = defaultMd;
            oaepMdSizeBytes = defaultMdSizeBytes;
        }

        @Override
        protected AlgorithmParameters engineGetParameters() {
            if (!isInitialized()) {
                return null;
            }

            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance("OAEP");

                final PSource pSrc;
                if (label == null) {
                    pSrc = PSource.PSpecified.DEFAULT;
                } else {
                    pSrc = new PSource.PSpecified(label);
                }

                params.init(new OAEPParameterSpec(
                        EvpMdRef.getJcaDigestAlgorithmStandardNameFromEVP_MD(oaepMd),
                        EvpMdRef.MGF1_ALGORITHM_NAME,
                        new MGF1ParameterSpec(
                                EvpMdRef.getJcaDigestAlgorithmStandardNameFromEVP_MD(mgf1Md)),
                        pSrc));
                return params;
            } catch (NoSuchAlgorithmException e) {
                // We should not get here.
                throw (Error) new AssertionError("OAEP not supported").initCause(e);
            } catch (InvalidParameterSpecException e) {
                throw new RuntimeException("No providers of AlgorithmParameters.OAEP available");
            }
        }

        @Override
        protected void engineSetPadding(String padding) throws NoSuchPaddingException {
            String paddingUpper = padding.toUpperCase(Locale.US);
            if (paddingUpper.equals("OAEPPADDING")) {
                this.padding = NativeConstants.RSA_PKCS1_OAEP_PADDING;
                return;
            }

            throw new NoSuchPaddingException("Only OAEP padding is supported");
        }

        @Override
        protected void engineInit(
                int opmode, Key key, AlgorithmParameterSpec spec, SecureRandom random)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            if (spec != null && !(spec instanceof OAEPParameterSpec)) {
                throw new InvalidAlgorithmParameterException(
                        "Only OAEPParameterSpec accepted in OAEP mode");
            }

            engineInitInternal(opmode, key, spec);
        }

        @Override
        protected void engineInit(
                int opmode, Key key, AlgorithmParameters params, SecureRandom random)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            OAEPParameterSpec spec = null;
            if (params != null) {
                try {
                    spec = params.getParameterSpec(OAEPParameterSpec.class);
                } catch (InvalidParameterSpecException e) {
                    throw new InvalidAlgorithmParameterException(
                            "Only OAEP parameters are supported", e);
                }
            }

            engineInitInternal(opmode, key, spec);
        }

        @Override
        void engineInitInternal(int opmode, Key key, AlgorithmParameterSpec spec)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
                if (!(key instanceof PublicKey)) {
                    throw new InvalidKeyException("Only public keys may be used to encrypt");
                }
            } else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
                if (!(key instanceof PrivateKey)) {
                    throw new InvalidKeyException("Only private keys may be used to decrypt");
                }
            }
            super.engineInitInternal(opmode, key, spec);
        }

        @Override
        void doCryptoInit(AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
            pkeyCtx = new NativeRef.EVP_PKEY_CTX(encrypting
                            ? NativeCrypto.EVP_PKEY_encrypt_init(key.getNativeRef())
                            : NativeCrypto.EVP_PKEY_decrypt_init(key.getNativeRef()));

            if (spec instanceof OAEPParameterSpec) {
                readOAEPParameters((OAEPParameterSpec) spec);
            }

            NativeCrypto.EVP_PKEY_CTX_set_rsa_padding(
                    pkeyCtx.address, NativeConstants.RSA_PKCS1_OAEP_PADDING);
            NativeCrypto.EVP_PKEY_CTX_set_rsa_oaep_md(pkeyCtx.address, oaepMd);
            NativeCrypto.EVP_PKEY_CTX_set_rsa_mgf1_md(pkeyCtx.address, mgf1Md);
            if (label != null && label.length > 0) {
                NativeCrypto.EVP_PKEY_CTX_set_rsa_oaep_label(pkeyCtx.address, label);
            }
        }

        @Override
        int paddedBlockSizeBytes() {
            int paddedBlockSizeBytes = keySizeBytes();
            // Size described in step 2 of decoding algorithm, but extra byte
            // needed to make sure it's smaller than the RSA key modulus size.
            // https://tools.ietf.org/html/rfc2437#section-9.1.1.2
            return paddedBlockSizeBytes - (2 * oaepMdSizeBytes + 2);
        }

        private void readOAEPParameters(OAEPParameterSpec spec)
                throws InvalidAlgorithmParameterException {
            String mgfAlgUpper = spec.getMGFAlgorithm().toUpperCase(Locale.US);
            AlgorithmParameterSpec mgfSpec = spec.getMGFParameters();
            if ((!EvpMdRef.MGF1_ALGORITHM_NAME.equals(mgfAlgUpper)
                        && !EvpMdRef.MGF1_OID.equals(mgfAlgUpper))
                    || !(mgfSpec instanceof MGF1ParameterSpec)) {
                throw new InvalidAlgorithmParameterException(
                        "Only MGF1 supported as mask generation function");
            }

            MGF1ParameterSpec mgf1spec = (MGF1ParameterSpec) mgfSpec;
            String oaepAlgUpper = spec.getDigestAlgorithm().toUpperCase(Locale.US);
            try {
                oaepMd = EvpMdRef.getEVP_MDByJcaDigestAlgorithmStandardName(oaepAlgUpper);
                oaepMdSizeBytes =
                        EvpMdRef.getDigestSizeBytesByJcaDigestAlgorithmStandardName(oaepAlgUpper);
                mgf1Md = EvpMdRef.getEVP_MDByJcaDigestAlgorithmStandardName(
                        mgf1spec.getDigestAlgorithm());
            } catch (NoSuchAlgorithmException e) {
                throw new InvalidAlgorithmParameterException(e);
            }

            PSource pSource = spec.getPSource();
            if (!"PSpecified".equals(pSource.getAlgorithm())
                    || !(pSource instanceof PSource.PSpecified)) {
                throw new InvalidAlgorithmParameterException(
                        "Only PSpecified accepted for PSource");
            }
            label = ((PSource.PSpecified) pSource).getValue();
        }

        @Override
        int doCryptoOperation(byte[] tmpBuf, byte[] output)
                throws BadPaddingException, IllegalBlockSizeException {
            if (encrypting) {
                return NativeCrypto.EVP_PKEY_encrypt(pkeyCtx, output, 0, tmpBuf, 0, tmpBuf.length);
            } else {
                return NativeCrypto.EVP_PKEY_decrypt(pkeyCtx, output, 0, tmpBuf, 0, tmpBuf.length);
            }
        }

        public static final class SHA1 extends OAEP {
            public SHA1() {
                super(EvpMdRef.SHA1.EVP_MD, EvpMdRef.SHA1.SIZE_BYTES);
            }
        }

        public static final class SHA224 extends OAEP {
            public SHA224() {
                super(EvpMdRef.SHA224.EVP_MD, EvpMdRef.SHA224.SIZE_BYTES);
            }
        }

        public static final class SHA256 extends OAEP {
            public SHA256() {
                super(EvpMdRef.SHA256.EVP_MD, EvpMdRef.SHA256.SIZE_BYTES);
            }
        }

        public static final class SHA384 extends OAEP {
            public SHA384() {
                super(EvpMdRef.SHA384.EVP_MD, EvpMdRef.SHA384.SIZE_BYTES);
            }
        }

        public static final class SHA512 extends OAEP {
            public SHA512() {
                super(EvpMdRef.SHA512.EVP_MD, EvpMdRef.SHA512.SIZE_BYTES);
            }
        }
    }
}
