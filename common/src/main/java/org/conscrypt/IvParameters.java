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

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.IvParameterSpec;

/**
 * An implementation of {@link java.security.AlgorithmParameters} that contains only an IV.  The
 * supported encoding formats are ASN.1 (primary) and RAW.
 */
@Internal
public class IvParameters extends AlgorithmParametersSpi {
    private byte[] iv;

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
            throws InvalidParameterSpecException {
        if (!(algorithmParameterSpec instanceof IvParameterSpec)) {
            throw new InvalidParameterSpecException("Only IvParameterSpec is supported");
        }
        iv = ((IvParameterSpec) algorithmParameterSpec).getIV().clone();
    }

    @Override
    protected void engineInit(byte[] bytes) throws IOException {
        long readRef = 0;
        try {
            readRef = NativeCrypto.asn1_read_init(bytes);
            byte[] newIv = NativeCrypto.asn1_read_octetstring(readRef);
            if (!NativeCrypto.asn1_read_is_empty(readRef)) {
                throw new IOException("Error reading ASN.1 encoding");
            }
            this.iv = newIv;
        } finally {
            NativeCrypto.asn1_read_free(readRef);
        }
    }

    @Override
    protected void engineInit(byte[] bytes, String format) throws IOException {
        if (format == null || format.equals("ASN.1")) {
            engineInit(bytes);
        } else if (format.equals("RAW")) {
            iv = bytes.clone();
        } else {
            throw new IOException("Unsupported format: " + format);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> aClass)
            throws InvalidParameterSpecException {
        if (aClass != IvParameterSpec.class) {
            throw new InvalidParameterSpecException(
                    "Incompatible AlgorithmParametersSpec class: " + aClass);
        }
        return (T) new IvParameterSpec(iv);
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        long cbbRef = 0;
        try {
            cbbRef = NativeCrypto.asn1_write_init();
            NativeCrypto.asn1_write_octetstring(cbbRef, this.iv);
            return NativeCrypto.asn1_write_finish(cbbRef);
        } catch (IOException e) {
            NativeCrypto.asn1_write_cleanup(cbbRef);
            throw e;
        } finally {
            NativeCrypto.asn1_write_free(cbbRef);
        }
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if (format == null || format.equals("ASN.1")) {
            return engineGetEncoded();
        } else if (format.equals("RAW")) {
            return iv.clone();
        } else {
            throw new IOException("Unsupported format: " + format);
        }
    }

    @Override
    protected String engineToString() {
        return "Conscrypt IV AlgorithmParameters";
    }

    public static class AES extends IvParameters {
        public AES() {}
    }
    public static class DESEDE extends IvParameters {
        public DESEDE() {}
    }
    public static class ChaCha20 extends IvParameters {
        public ChaCha20() {}
    }
}
