/*
 * Copyright 2015 The Android Open Source Project
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
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * GCM parameters used during an ciphering operation with {@link OpenSSLCipher}.
 * This class is used internally for backward compatibility with Android versions
 * that did not have the {@code GCMParameterSpec} class, in addition to being the
 * implementation of the GCM AlgorithmParameters implementation.
 * <p>
 * The only supported encoding format is ASN.1, as specified in RFC 5084 section 3.2.
 */
@Internal
public final class GCMParameters extends AlgorithmParametersSpi {

    // The default value (in bits) for TLEN in the GCM ASN.1 module
    private static final int DEFAULT_TLEN = 96;

    /** The tag length in bits. */
    private int tLen;

    /** Actually the nonce value for the GCM operation. */
    private byte[] iv;

    public GCMParameters() { }

    GCMParameters(int tLen, byte[] iv) {
        this.tLen = tLen;
        this.iv = iv;
    }

    /**
     * Returns the tag length in bits.
     */
    int getTLen() {
        return tLen;
    }

    /**
     * Returns a non-cloned version of the IV.
     */
    byte[] getIV() {
        return iv;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
            throws InvalidParameterSpecException {
        GCMParameters params = Platform.fromGCMParameterSpec(algorithmParameterSpec);
        if (params == null) {
            throw new InvalidParameterSpecException("Only GCMParameterSpec is supported");
        }
        this.tLen = params.tLen;
        this.iv = params.iv;
    }

    @Override
    protected void engineInit(byte[] bytes) throws IOException {
        long readRef = 0;
        long seqRef = 0;
        try {
            readRef = NativeCrypto.asn1_read_init(bytes);
            seqRef = NativeCrypto.asn1_read_sequence(readRef);
            byte[] newIv = NativeCrypto.asn1_read_octetstring(seqRef);
            int newTlen = DEFAULT_TLEN;
            if (!NativeCrypto.asn1_read_is_empty(seqRef)) {
                newTlen = 8 * (int) NativeCrypto.asn1_read_uint64(seqRef);
            }
            if (!NativeCrypto.asn1_read_is_empty(seqRef)
                    || !NativeCrypto.asn1_read_is_empty(readRef)) {
                throw new IOException("Error reading ASN.1 encoding");
            }
            this.iv = newIv;
            this.tLen = newTlen;
        } finally {
            NativeCrypto.asn1_read_free(seqRef);
            NativeCrypto.asn1_read_free(readRef);
        }
    }

    @Override
    protected void engineInit(byte[] bytes, String format) throws IOException {
        if ((format == null) || format.equals("ASN.1")) {
            engineInit(bytes);
        } else {
            throw new IOException("Unsupported format: " + format);
        }
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> aClass)
            throws InvalidParameterSpecException {
        if ((aClass != null) && aClass.getName().equals("javax.crypto.spec.GCMParameterSpec")) {
            return aClass.cast(Platform.toGCMParameterSpec(tLen, iv));
        } else {
            throw new InvalidParameterSpecException("Unsupported class: " + aClass);
        }
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        long cbbRef = 0;
        long seqRef = 0;
        try {
            cbbRef = NativeCrypto.asn1_write_init();
            seqRef = NativeCrypto.asn1_write_sequence(cbbRef);
            NativeCrypto.asn1_write_octetstring(seqRef, this.iv);
            if (this.tLen != DEFAULT_TLEN) {
                NativeCrypto.asn1_write_uint64(seqRef, this.tLen / 8);
            }
            return NativeCrypto.asn1_write_finish(cbbRef);
        } catch (IOException e) {
            NativeCrypto.asn1_write_cleanup(cbbRef);
            throw e;
        } finally {
            NativeCrypto.asn1_write_free(seqRef);
            NativeCrypto.asn1_write_free(cbbRef);
        }
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if ((format == null) || format.equals("ASN.1")) {
            return engineGetEncoded();
        }
        throw new IOException("Unsupported format: " + format);
    }

    @Override
    protected String engineToString() {
        return "Conscrypt GCM AlgorithmParameters";
    }
}
