/*
 * Copyright 2018 The Android Open Source Project
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
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * AlgorithmParameters implementation for PSS.  The only supported encoding format is ASN.1
 * (with X.509 accepted as an alias), as specified in RFC 4055 section 3.1.
 */
@Internal
public class PSSParameters extends AlgorithmParametersSpi {

    private PSSParameterSpec spec = PSSParameterSpec.DEFAULT;

    public PSSParameters() {}

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
            throws InvalidParameterSpecException {
        if (algorithmParameterSpec instanceof PSSParameterSpec) {
            this.spec = (PSSParameterSpec) algorithmParameterSpec;
        } else {
            throw new InvalidParameterSpecException("Only PSSParameterSpec is supported");
        }
    }

    @Override
    protected void engineInit(byte[] bytes) throws IOException {
        long readRef = 0;
        long seqRef = 0;
        try {
            readRef = NativeCrypto.asn1_read_init(bytes);
            seqRef = NativeCrypto.asn1_read_sequence(readRef);
            int saltLength = 20;
            String hash = OAEPParameters.readHash(seqRef);
            String mgfHash = OAEPParameters.readMgfHash(seqRef);
            if (NativeCrypto.asn1_read_next_tag_is(seqRef, 2)) {
                long saltRef = 0;
                try {
                    saltRef = NativeCrypto.asn1_read_tagged(seqRef);
                    saltLength = (int) NativeCrypto.asn1_read_uint64(saltRef);
                } finally {
                    NativeCrypto.asn1_read_free(saltRef);
                }
            }
            if (NativeCrypto.asn1_read_next_tag_is(seqRef, 3)) {
                long trailerField;
                long trailerRef = 0;
                try {
                    trailerRef = NativeCrypto.asn1_read_tagged(seqRef);
                    trailerField = (int) NativeCrypto.asn1_read_uint64(trailerRef);
                } finally {
                    NativeCrypto.asn1_read_free(trailerRef);
                }
                // 1 is the only legal value for trailerField
                if (trailerField != 1) {
                    throw new IOException("Error reading ASN.1 encoding");
                }
            }

            if (!NativeCrypto.asn1_read_is_empty(seqRef)
                    || !NativeCrypto.asn1_read_is_empty(readRef)) {
                throw new IOException("Error reading ASN.1 encoding");
            }
            this.spec = new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(mgfHash),
                    saltLength, 1);
        } finally {
            NativeCrypto.asn1_read_free(seqRef);
            NativeCrypto.asn1_read_free(readRef);
        }
    }

    @Override
    protected void engineInit(byte[] bytes, String format) throws IOException {
        if ((format == null) || format.equals("ASN.1") || format.equals("X.509")) {
            engineInit(bytes);
        } else {
            throw new IOException("Unsupported format: " + format);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> aClass)
            throws InvalidParameterSpecException {
        if ((aClass != null) && aClass == PSSParameterSpec.class) {
            return (T) spec;
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
            OAEPParameters.writeHashAndMgfHash(seqRef, spec.getDigestAlgorithm(),
                    (MGF1ParameterSpec) spec.getMGFParameters());
            // Implementations are prohibited from writing the default value for any of the fields
            if (spec.getSaltLength() != 20) {
                long tagRef = 0;
                try {
                    tagRef = NativeCrypto.asn1_write_tag(seqRef, 2);
                    NativeCrypto.asn1_write_uint64(tagRef, spec.getSaltLength());
                } finally {
                    NativeCrypto.asn1_write_flush(seqRef);
                    NativeCrypto.asn1_write_free(tagRef);
                }
            }
            // 1 is the only legal value for trailerField and the default, so ignore it
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
        if ((format == null) || format.equals("ASN.1") || format.equals("X.509")) {
            return engineGetEncoded();
        }
        throw new IOException("Unsupported format: " + format);
    }

    @Override
    protected String engineToString() {
        return "Conscrypt PSS AlgorithmParameters";
    }
}
