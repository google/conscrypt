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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

@Internal
public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
    /**
     * Controls whether no-copy optimizations for direct ByteBuffers are enabled.
     */
    private static final boolean ENABLE_BYTEBUFFER_OPTIMIZATIONS = true;

    /**
     * The default tag size when one is not specified. Default to
     * full-length tags (128-bits or 16 octets).
     */
    static final int DEFAULT_TAG_SIZE_BITS = 16 * 8;

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

    protected OpenSSLAeadCipher(Mode mode) {
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

        checkSupportedTagLength(tagLenBits);

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

        if (isEncrypting() && iv != null && !allowsNonceReuse()) {
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

    void checkSupportedTagLength(int tagLenBits)
            throws InvalidAlgorithmParameterException {
        if (tagLenBits % 8 != 0) {
            throw new InvalidAlgorithmParameterException(
                    "Tag length must be a multiple of 8; was " + tagLenBits);
        }
    }

    /**
     * Returns whether reusing nonces is allowed (aka, whether this is nonce misuse-resistant).
     * Most AEAD ciphers are not, but some are specially constructed so that reusing a key/nonce
     * pair is safe.
     */
    boolean allowsNonceReuse() {
        return false;
    }

    @Override
    protected int engineDoFinal(ByteBuffer input, ByteBuffer output) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
        if (!ENABLE_BYTEBUFFER_OPTIMIZATIONS) {
            return super.engineDoFinal(input, output);
        }
        if (input == null || output == null) {
            throw new NullPointerException("Null ByteBuffer Error");
        }
        if (getOutputSizeForFinal(input.remaining()) > output.remaining()) {
            throw new ShortBufferWithoutStackTraceException("Insufficient Bytes for Output Buffer");
        }
        if (output.isReadOnly()) {
            throw new IllegalArgumentException("Cannot write to Read Only ByteBuffer");
        }
        if (bufCount != 0) {
            return super.engineDoFinal(input, output); // traditional case
        }
        int bytesWritten;
        if (!input.isDirect()) {
            int incap = input.remaining();
            ByteBuffer inputClone = ByteBuffer.allocateDirect(incap);
            inputClone.mark();
            inputClone.put(input);
            inputClone.reset();
            input = inputClone;
        }
        if (!output.isDirect()) {
            ByteBuffer outputClone = ByteBuffer.allocateDirect(
                    getOutputSizeForFinal(input.remaining()));
            bytesWritten = doFinalInternal(input, outputClone);
            output.put(outputClone);
            input.position(input.limit()); // API reasons
        }
        else {
            bytesWritten =  doFinalInternal(input, output);
            output.position(output.position() + bytesWritten);
            input.position(input.limit()); // API reasons
        }

        return bytesWritten;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        final int maximumLen = getOutputSizeForFinal(inputLen);
        /* Assume that we'll output exactly on a byte boundary. */
        final byte[] output = new byte[maximumLen];

        int bytesWritten;
        try {
            bytesWritten = doFinalInternal(input, inputOffset, inputLen, output, 0);
        } catch (ShortBufferException e) {
            /* This should not happen since we sized our own buffer. */
            throw new RuntimeException("our calculated buffer was too small", e);
        }

        if (bytesWritten == output.length) {
            return output;
        } else if (bytesWritten == 0) {
            return EmptyArray.BYTE;
        } else {
            return Arrays.copyOf(output, bytesWritten);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
        if (output == null) {
            throw new NullPointerException("output == null");
        }
        if (getOutputSizeForFinal(inputLen) > output.length - outputOffset) {
            throw new ShortBufferWithoutStackTraceException("Insufficient output space");
        }
        return doFinalInternal(input, inputOffset, inputLen, output, outputOffset);
    }

    void appendToBuf(byte[] input, int inputOffset, int inputLen) {
        if (buf == null) {
            throw new IllegalStateException("Cipher not initialized");
        }

        ArrayUtils.checkOffsetAndCount(input.length, inputOffset, inputLen);
        if (inputLen > 0) {
            expand(inputLen);
            System.arraycopy(input, inputOffset, buf, this.bufCount, inputLen);
            this.bufCount += inputLen;
        }
    }

    @Override
    int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, int maximumLen) throws ShortBufferException {
        checkInitialization();
        appendToBuf(input, inputOffset, inputLen);
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

    int doFinalInternal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkInitialization();
        final int bytesWritten;
        try {
            if (isEncrypting()) {
                bytesWritten = NativeCrypto.EVP_AEAD_CTX_seal_buf(
                        evpAead, encodedKey, tagLengthInBytes, output, iv, input, aad);
            } else {
                bytesWritten = NativeCrypto.EVP_AEAD_CTX_open_buf(
                        evpAead, encodedKey, tagLengthInBytes, output, iv, input, aad);
            }
        } catch (BadPaddingException e) {
            throwAEADBadTagExceptionIfAvailable(e.getMessage(), e.getCause());
            throw e;
        }
        if (isEncrypting()) {
            mustInitialize = true;
        }
        return bytesWritten;
    }

    int doFinalInternal(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkInitialization();

        byte[] in;
        int inOffset;
        int inLen;
        if (bufCount > 0) {
            if (inputLen > 0) {
                appendToBuf(input, inputOffset, inputLen);
            }
            in = buf;
            inOffset = 0;
            inLen = bufCount;
        } else {
            if (inputLen == 0 && input == null) {
                in = EmptyArray.BYTE; // input can be null when inputLen == 0
            } else {
                in = input;
            }
            inOffset = inputOffset;
            inLen = inputLen;
        }

        final int bytesWritten;
        try {
            if (isEncrypting()) {
                bytesWritten = NativeCrypto.EVP_AEAD_CTX_seal(evpAead, encodedKey,
                        tagLengthInBytes, output, outputOffset, iv, in, inOffset, inLen, aad);
            } else {
                bytesWritten = NativeCrypto.EVP_AEAD_CTX_open(evpAead, encodedKey,
                        tagLengthInBytes, output, outputOffset, iv, in, inOffset, inLen, aad);
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

}

