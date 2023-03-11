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

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import org.conscrypt.HpkeAlgorithmIdentifier.AEAD;
import org.conscrypt.HpkeAlgorithmIdentifier.KDF;
import org.conscrypt.HpkeAlgorithmIdentifier.KEM;
import org.conscrypt.HpkeParameterSpec.Mode;
import org.conscrypt.NativeRef.EVP_HPKE_CTX;
import org.conscrypt.NativeRef.EVP_HPKE_KEY;

/**
 * An HPKE implementation of {@link Cipher} using BoringSSL as the backing library.
 */
@Internal
public class OpenSSLCipherHpke extends CipherSpi {

    private static final int AES_BLOCK_SIZE_BYTES = 16;
    private static final String HPKE = "HPKE";

    private static final KEM SUPPORTED_KEM = KEM.DHKEM_X25519_HKDF_SHA256;
    private static final KDF SUPPORTED_KDF = KDF.HKDF_SHA256;
    private static final Set<AEAD> SUPPORTED_AEADS = Collections.unmodifiableSet(new HashSet<>(
        Arrays.asList(AEAD.AES_128_GCM, AEAD.AES_256_GCM, AEAD.CHACHA20POLY1305)));

    /**
     * Algorithms to be used for KEM, KDF, and AEAD.
     */
    private HpkeAlgorithmIdentifier algorithmIdentifier;

    /**
     * Determines if {@link #checkAndInitializeContext()} has been called
     */
    private boolean alreadyExecuted;

    /**
     * HPKE context.
     */
    private EVP_HPKE_CTX evpCtx;

    /**
     * HPKE key.
     */
    private EVP_HPKE_KEY evpKey;

    /**
     * KEM identifier memory address.
     */
    private long evpKem;

    /**
     * KDF identifier memory address.
     */
    private long evpKdf;

    /**
     * AEAD identifier memory address.
     */
    private long evpAead;

    /**
     * Current cipher mode: encrypt (encrypt or send secret export) or decrypt (decrypt or receive
     * secret export).
     */
    private boolean encrypting;

    /**
     * Current api: encryption/decrypting or secret export.
     */
    private boolean exporting;

    /**
     * Determines whether Cipher has been initialized.
     */
    private boolean initialized;

    /**
     * Additional authenticated data.
     */
    private byte[] aad;

    /**
     * Encapsulated key
     */
    private byte[] enc;

    /**
     * Raw value for private/public key.
     */
    private byte[] encodedKey;

    /**
     * Secret export desired output length.
     */
    private int exportLength;

    /**
     * Caller's parameter info
     */
    private byte[] info;

    /**
     * Initialization Vector provided as part of the algorithm params. These are randomly generated
     * bytes matching the private key length from the underlying KEM parameter, which can also be used
     * to make the ciphertext deterministic for testing purposes if an initial value is provided.
     */
    private byte[] iv;

    /**
     * Same value as initialization vector, but if IV is not provided, the code will create a
     * randomly generated initialization vector matching the private key length from the underlying
     * KEM parameter. This value is hidden from the caller.
     */
    private byte[] randomSk;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("Mode " + mode + " not supported");
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException("Padding " + padding + " not supported");
    }

    @Override
    protected int engineGetBlockSize() {
        checkInitialization();
        if (AEAD.AES_128_GCM.equals(algorithmIdentifier.getAead())
            || AEAD.AES_256_GCM.equals(algorithmIdentifier.getAead())) {
            return AES_BLOCK_SIZE_BYTES;
        }

        // ChaCha20 is a stream cipher that has an internal block size of 64 bytes.
        // Returning 0 as it is not a block cipher.
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        checkInitialization();
        if (exporting) {
            return exportLength + algorithmIdentifier.getKem().getEncLength();
        }

        final int maxCtxOverhead = NativeCrypto.EVP_HPKE_CTX_max_overhead(this.evpCtx);
        if (encrypting) {
            return inputLen + algorithmIdentifier.getKem().getEncLength() + maxCtxOverhead;
        }

        return inputLen <= maxCtxOverhead ? 0 : (inputLen - maxCtxOverhead);
    }


    @Override
    protected byte[] engineGetIV() {
        if (iv == null) {
            return null;
        }
        return iv.clone();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (algorithmIdentifier == null) {
            return null;
        }
        try {
            final AlgorithmParameterSpec spec = new HpkeParameterSpec.Builder(
                algorithmIdentifier, enc, info, iv, exportLength,
                /* psk= */ null, /* pskId= */ null, /* authKey= */ null, Mode.BASE, encrypting,
                exporting).build();
            final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
            params.init(spec);
            return params;
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            return null;
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (opmode != Cipher.ENCRYPT_MODE) {
            throw new IllegalStateException("Only default encryption mode supported");
        }
        final AlgorithmParameterSpec algorithmParameterSpec = HpkeParameterSpec.DEFAULT_ENCRYPTION;
        try {
            engineInit(opmode, key, algorithmParameterSpec, random);
        } catch (InvalidAlgorithmParameterException e) {
            // This shouldn't reach here, as a default spec is provided
            throw new InvalidKeyException("Invalid Algorithm Parameters", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        final HpkeParameterSpec spec;
        if (params == null && opmode == Cipher.ENCRYPT_MODE) {
            spec = HpkeParameterSpec.DEFAULT_ENCRYPTION;
        } else {
            final boolean paramsInstanceOfHpke = params instanceof HpkeParameterSpec;
            if (!paramsInstanceOfHpke) {
                throw new InvalidAlgorithmParameterException("Only HpkeParameterSpec supported");
            }
            spec = (HpkeParameterSpec) params;
        }

        checkMode(spec);
        checkAndSetOperationMode(opmode, spec);
        checkAndSetEncodedKey(key, spec);
        checkAndSetHpkeParams(spec);
        checkAndSetIv(random, spec.getIv());
        exportLength = spec.getL();

        if (encrypting) {
            enc = NativeCrypto.EVP_HPKE_CTX_setup_sender_with_seed(
                evpCtx, evpKem, evpKdf, evpAead, encodedKey, info, randomSk);
        } else {
            enc = spec.getEnc();
            evpKey = new EVP_HPKE_KEY(NativeCrypto.EVP_HPKE_KEY_new());
            NativeCrypto.EVP_HPKE_KEY_init(evpKey, evpKem, encodedKey);
            NativeCrypto.EVP_HPKE_CTX_setup_recipient(evpCtx, evpKey, evpKdf, evpAead, enc, info);
        }
        initialized = true;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params == null && opmode != Cipher.ENCRYPT_MODE) {
            throw new InvalidAlgorithmParameterException(
                "Only encrypt mode is supported when no AlgorithmParameters are provided");
        }
        final AlgorithmParameterSpec spec;
        try {
            spec = params == null ?
                HpkeParameterSpec.DEFAULT_ENCRYPTION :
                params.getParameterSpec(AlgorithmParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException(
                "AlgorithmParameters contains an invalid parameter", e);
        }

        engineInit(opmode, key, spec, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        checkInitialization();
        if (exporting) {
            final byte[] export = NativeCrypto.EVP_HPKE_CTX_export(evpCtx, input, exportLength);
            final byte[] encAndExport = new byte[enc.length + export.length];
            System.arraycopy(enc, 0, encAndExport, 0, enc.length);
            System.arraycopy(export, 0, encAndExport, enc.length, export.length);
            return encAndExport;
        }
        if (encrypting) {
            final byte[] ciphertext = NativeCrypto.EVP_HPKE_CTX_seal(evpCtx, input, aad);
            final byte[] encAndCiphertext = new byte[enc.length + ciphertext.length];
            System.arraycopy(enc, 0, encAndCiphertext, 0, enc.length);
            System.arraycopy(ciphertext, 0, encAndCiphertext, enc.length, ciphertext.length);
            aad = null;
            return encAndCiphertext;
        }
        final byte[] plaintext = NativeCrypto.EVP_HPKE_CTX_open(evpCtx, input, aad);
        aad = null;
        return plaintext;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        final byte[] result = engineUpdate(input, inputOffset, inputLen);
        if (result == null) {
            return 0;
        }
        if (output == null || output.length - outputOffset < result.length) {
            throw new ShortBufferWithoutStackTraceException("Insufficient output space");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        checkInitialization();
        checkAndInitializeContext();
        try {
            if (input == null) {
                return null;
            }
            return engineUpdate(input, inputOffset, inputLen);
        } finally {
            finish();
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        checkInitialization();
        checkAndInitializeContext();
        try {
            if (input == null) {
                return 0;
            }
            return engineUpdate(input, inputOffset, inputLen, output, outputOffset);
        } finally {
            finish();
        }
    }

    @Override
    protected void engineUpdateAAD(byte[] input, int inputOffset, int inputLen) {
        checkInitialization();
        if (aad == null) {
            aad = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen);
        } else {
            int newSize = aad.length + inputLen;
            byte[] newAad = new byte[newSize];
            System.arraycopy(aad, 0, newAad, 0, aad.length);
            System.arraycopy(input, inputOffset, newAad, aad.length, inputLen);
            aad = newAad;
        }
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer byteBuffer) {
        checkInitialization();
        if (aad == null) {
            aad = new byte[byteBuffer.remaining()];
            byteBuffer.get(aad);
        } else {
            int newSize = aad.length + byteBuffer.remaining();
            byte[] newAad = new byte[newSize];
            System.arraycopy(aad, 0, newAad, 0, aad.length);
            byteBuffer.get(newAad, aad.length, byteBuffer.remaining());
            aad = newAad;
        }
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        checkInitialization();
        checkKey(key, algorithmIdentifier.getKem());
        return key.getEncoded().length * 8;
    }

    private void checkAndSetAlgorithmIdentifier(HpkeAlgorithmIdentifier algorithmIdentifier)
            throws InvalidAlgorithmParameterException {
        if (!SUPPORTED_KEM.equals(algorithmIdentifier.getKem())) {
            throw new InvalidAlgorithmParameterException(
                "KEM " + algorithmIdentifier.getKem() + " not supported");
        }

        if (!SUPPORTED_KDF.equals(algorithmIdentifier.getKdf())) {
            throw new InvalidAlgorithmParameterException(
                "KDF " + algorithmIdentifier.getKdf() + " not supported");
        }

        if (!SUPPORTED_AEADS.contains(algorithmIdentifier.getAead())) {
            throw new InvalidAlgorithmParameterException(
                "AEAD " + algorithmIdentifier.getAead() + " not supported");
        }
        this.algorithmIdentifier = algorithmIdentifier;
    }

    private void checkAndSetEncodedKey(Key key, HpkeParameterSpec spec) throws InvalidKeyException {
        checkKey(key, spec.getAlgorithmIdentifier().getKem());
        encodedKey = key.getEncoded();
    }

    private void checkAndSetEvpAead(AEAD aeadIdentifier) throws InvalidAlgorithmParameterException {
        switch (aeadIdentifier) {
            case AES_128_GCM:
                this.evpAead = NativeCrypto.EVP_HPKE_AEAD_aes_128_gcm();
                break;
            case AES_256_GCM:
                this.evpAead = NativeCrypto.EVP_HPKE_AEAD_aes_256_gcm();
                break;
            case CHACHA20POLY1305:
                this.evpAead = NativeCrypto.EVP_HPKE_AEAD_chacha20_poly1305();
                break;
            default:
                throw new InvalidAlgorithmParameterException(
                    "AEAD " + aeadIdentifier + " not supported");
        }
    }

    private void checkAndSetEvpKem(KEM kemIdentifier) throws InvalidAlgorithmParameterException {
        if (KEM.DHKEM_X25519_HKDF_SHA256.equals(kemIdentifier)) {
            this.evpKem = NativeCrypto.EVP_HPKE_KEM_dhkem_x25519_hkdf_sha256();
            return;
        }
        throw new InvalidAlgorithmParameterException("KEM " + kemIdentifier + " not supported");
    }

    private void checkAndSetEvpKdf(KDF kdfIdentifier) throws InvalidAlgorithmParameterException {
        if (KDF.HKDF_SHA256.equals(kdfIdentifier)) {
            this.evpKdf = NativeCrypto.EVP_HPKE_KDF_hkdf_sha256();
            return;
        }
        throw new InvalidAlgorithmParameterException("KDF " + kdfIdentifier + " not supported");
    }

    private void checkAndSetHpkeParams(HpkeParameterSpec spec)
            throws InvalidAlgorithmParameterException {
        checkAndSetAlgorithmIdentifier(spec.getAlgorithmIdentifier());
        checkAndSetEvpAead(spec.getAlgorithmIdentifier().getAead());
        checkAndSetEvpKem(spec.getAlgorithmIdentifier().getKem());
        checkAndSetEvpKdf(spec.getAlgorithmIdentifier().getKdf());
        evpCtx = new EVP_HPKE_CTX(NativeCrypto.EVP_HPKE_CTX_new());
        info = spec.getInfo();
    }

    private void checkAndSetIv(SecureRandom random, byte[] iv) {
        if (encrypting) {
            if (iv == null) {
                randomSk = new byte[algorithmIdentifier.getKem().getSkLength()];
                if (random != null) {
                    random.nextBytes(randomSk);
                } else {
                    NativeCrypto.RAND_bytes(randomSk);
                }
                return;
            }

            this.iv = iv;
            randomSk = iv;
        }
    }

    private void checkAndSetOperationMode(int opmode, HpkeParameterSpec spec) {
        if (opmode < Cipher.ENCRYPT_MODE || opmode > Cipher.DECRYPT_MODE) {
            throw new IllegalArgumentException("Opmode " + opmode + " not supported");
        }
        if ((opmode == Cipher.ENCRYPT_MODE && spec.isEncrypting()) ||
                (opmode == Cipher.DECRYPT_MODE && !spec.isEncrypting())) {
            encrypting = opmode == Cipher.ENCRYPT_MODE;
            exporting = spec.isExporting();
            return;
        }
        throw new IllegalStateException("Opmode not matching AlgorithmParameterSpec mode");
    }

    private void checkAndInitializeContext() {
        if (alreadyExecuted) {
            if (encrypting) {
                enc = NativeCrypto.EVP_HPKE_CTX_setup_sender_with_seed(
                    evpCtx, evpKem, evpKdf, evpAead, encodedKey, info, randomSk);
            } else {
                NativeCrypto.EVP_HPKE_CTX_setup_recipient(evpCtx, evpKey, evpKdf, evpAead, enc,
                    info);
            }
        }
    }

    private void checkInitialization() {
        if (!initialized) {
            throw new IllegalStateException("Cipher needs to be initialized");
        }
    }

    private void checkKey(Key key, KEM kem) throws InvalidKeyException {
        final boolean instanceOfSecretKey = key instanceof SecretKey;
        if (!instanceOfSecretKey) {
            throw new InvalidKeyException("Only SecretKey is supported");
        }

        final byte[] encodedKey = key.getEncoded();
        if (encodedKey == null) {
            throw new InvalidKeyException("key.getEncoded() == null");
        }

        final int expectedKeyLength = encrypting ? kem.getPkLength() : kem.getSkLength();
        if (encodedKey.length != expectedKeyLength) {
            throw new InvalidKeyException(
                "Expected key length of " + expectedKeyLength + " but was " + encodedKey.length);
        }
    }

    private void checkMode(HpkeParameterSpec spec) {
        if (!Mode.BASE.equals(spec.getMode())) {
            throw new IllegalStateException("Mode " + spec.getMode() + " not supported");
        }
    }

    private void finish() {
        alreadyExecuted = true;
    }
}
