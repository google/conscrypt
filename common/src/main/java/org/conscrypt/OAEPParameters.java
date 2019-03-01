/*
 * Copyright 2017 The Android Open Source Project
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
import java.util.HashMap;
import java.util.Map;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * AlgorithmParameters implementation for OAEP.  The only supported encoding format is ASN.1,
 * as specified in RFC 4055 section 4.1.
 */
@Internal
public class OAEPParameters extends AlgorithmParametersSpi {

    private static final Map<String, String> OID_TO_NAME = new HashMap<String, String>();
    private static final Map<String, String> NAME_TO_OID = new HashMap<String, String>();
    static {
        OID_TO_NAME.put("1.3.14.3.2.26", "SHA-1");
        OID_TO_NAME.put("2.16.840.1.101.3.4.2.4", "SHA-224");
        OID_TO_NAME.put("2.16.840.1.101.3.4.2.1", "SHA-256");
        OID_TO_NAME.put("2.16.840.1.101.3.4.2.2", "SHA-384");
        OID_TO_NAME.put("2.16.840.1.101.3.4.2.3", "SHA-512");
        for (Map.Entry<String, String> entry : OID_TO_NAME.entrySet()) {
            NAME_TO_OID.put(entry.getValue(), entry.getKey());
        }
    }
    private static final String MGF1_OID = "1.2.840.113549.1.1.8";
    private static final String PSPECIFIED_OID = "1.2.840.113549.1.1.9";

    private OAEPParameterSpec spec = OAEPParameterSpec.DEFAULT;

    public OAEPParameters() {}

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
            throws InvalidParameterSpecException {
        if (algorithmParameterSpec instanceof OAEPParameterSpec) {
            this.spec = (OAEPParameterSpec) algorithmParameterSpec;
        } else {
            throw new InvalidParameterSpecException("Only OAEPParameterSpec is supported");
        }
    }

    @Override
    protected void engineInit(byte[] bytes) throws IOException {
        long readRef = 0;
        long seqRef = 0;
        try {
            readRef = NativeCrypto.asn1_read_init(bytes);
            seqRef = NativeCrypto.asn1_read_sequence(readRef);
            PSource.PSpecified pSpecified = PSource.PSpecified.DEFAULT;
            String hash = readHash(seqRef);
            String mgfHash = readMgfHash(seqRef);
            if (NativeCrypto.asn1_read_next_tag_is(seqRef, 2)) {
                long pSourceRef = 0;
                long pSourceSeqRef = 0;
                try {
                    pSourceRef = NativeCrypto.asn1_read_tagged(seqRef);
                    pSourceSeqRef = NativeCrypto.asn1_read_sequence(pSourceRef);
                    String pSourceOid = NativeCrypto.asn1_read_oid(pSourceSeqRef);
                    if (!pSourceOid.equals(PSPECIFIED_OID)) {
                        throw new IOException("Error reading ASN.1 encoding");
                    }
                    pSpecified = new PSource.PSpecified(
                            NativeCrypto.asn1_read_octetstring(pSourceSeqRef));
                    if (!NativeCrypto.asn1_read_is_empty(pSourceSeqRef)) {
                        throw new IOException("Error reading ASN.1 encoding");
                    }
                } finally {
                    NativeCrypto.asn1_read_free(pSourceSeqRef);
                    NativeCrypto.asn1_read_free(pSourceRef);
                }
            }

            if (!NativeCrypto.asn1_read_is_empty(seqRef)
                    || !NativeCrypto.asn1_read_is_empty(readRef)) {
                throw new IOException("Error reading ASN.1 encoding");
            }
            this.spec = new OAEPParameterSpec(hash, "MGF1", new MGF1ParameterSpec(mgfHash),
                    pSpecified);
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

    // Shared with PSSParameters, since they share some of their encoded form
    static String readHash(long seqRef) throws IOException {
        if (NativeCrypto.asn1_read_next_tag_is(seqRef, 0)) {
            long hashRef = 0;
            try {
                hashRef = NativeCrypto.asn1_read_tagged(seqRef);
                return getHashName(hashRef);
            } finally {
                NativeCrypto.asn1_read_free(hashRef);
            }
        }
        return "SHA-1";
    }

    // Shared with PSSParameters, since they share some of their encoded form
    static String readMgfHash(long seqRef) throws IOException {
        if (NativeCrypto.asn1_read_next_tag_is(seqRef, 1)) {
            long mgfRef = 0;
            long mgfSeqRef = 0;
            try {
                mgfRef = NativeCrypto.asn1_read_tagged(seqRef);
                mgfSeqRef = NativeCrypto.asn1_read_sequence(mgfRef);
                String mgfOid = NativeCrypto.asn1_read_oid(mgfSeqRef);
                if (!mgfOid.equals(MGF1_OID)) {
                    throw new IOException("Error reading ASN.1 encoding");
                }
                String mgfHash = getHashName(mgfSeqRef);
                if (!NativeCrypto.asn1_read_is_empty(mgfSeqRef)) {
                    throw new IOException("Error reading ASN.1 encoding");
                }
                return mgfHash;
            } finally {
                NativeCrypto.asn1_read_free(mgfSeqRef);
                NativeCrypto.asn1_read_free(mgfRef);
            }
        }
        return "SHA-1";
    }

    private static String getHashName(long hashRef) throws IOException {
        long hashSeqRef = 0;
        try {
            hashSeqRef = NativeCrypto.asn1_read_sequence(hashRef);
            String hashOid = NativeCrypto.asn1_read_oid(hashSeqRef);
            if (!NativeCrypto.asn1_read_is_empty(hashSeqRef)) {
                NativeCrypto.asn1_read_null(hashSeqRef);
            }
            if (!NativeCrypto.asn1_read_is_empty(hashSeqRef)
                    || !OID_TO_NAME.containsKey(hashOid)) {
                throw new IOException("Error reading ASN.1 encoding");
            }
            return OID_TO_NAME.get(hashOid);
        } finally {
            NativeCrypto.asn1_read_free(hashSeqRef);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> aClass)
            throws InvalidParameterSpecException {
        if ((aClass != null) && aClass == OAEPParameterSpec.class) {
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
            writeHashAndMgfHash(seqRef, spec.getDigestAlgorithm(),
                    (MGF1ParameterSpec) spec.getMGFParameters());
            PSource.PSpecified pSource = (PSource.PSpecified) spec.getPSource();
            // Implementations are prohibited from writing the default value for any of the fields
            if (pSource.getValue().length != 0) {
                long pSourceRef = 0;
                long pSourceParamsRef = 0;
                try {
                    pSourceRef = NativeCrypto.asn1_write_tag(seqRef, 2);
                    pSourceParamsRef = writeAlgorithmIdentifier(pSourceRef, PSPECIFIED_OID);
                    NativeCrypto.asn1_write_octetstring(pSourceParamsRef, pSource.getValue());
                } finally {
                    NativeCrypto.asn1_write_flush(seqRef);
                    NativeCrypto.asn1_write_free(pSourceParamsRef);
                    NativeCrypto.asn1_write_free(pSourceRef);
                }
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

    // Shared with PSSParameters, since they share some of their encoded form
    static void writeHashAndMgfHash(long seqRef, String hash, MGF1ParameterSpec mgfSpec) throws IOException {
        // Implementations are prohibited from writing the default value for any of the fields
        if (!hash.equals("SHA-1")) {
            long hashRef = 0;
            long hashParamsRef = 0;
            try {
                hashRef = NativeCrypto.asn1_write_tag(seqRef, 0);
                hashParamsRef = writeAlgorithmIdentifier(
                        hashRef, NAME_TO_OID.get(hash));
                NativeCrypto.asn1_write_null(hashParamsRef);
            } finally {
                NativeCrypto.asn1_write_flush(seqRef);
                NativeCrypto.asn1_write_free(hashParamsRef);
                NativeCrypto.asn1_write_free(hashRef);
            }
        }
        if (!mgfSpec.getDigestAlgorithm().equals("SHA-1")) {
            long mgfRef = 0;
            long mgfParamsRef = 0;
            long hashParamsRef = 0;
            try {
                mgfRef = NativeCrypto.asn1_write_tag(seqRef, 1);
                mgfParamsRef = writeAlgorithmIdentifier(mgfRef, MGF1_OID);
                hashParamsRef = writeAlgorithmIdentifier(
                        mgfParamsRef, NAME_TO_OID.get(mgfSpec.getDigestAlgorithm()));
                NativeCrypto.asn1_write_null(hashParamsRef);
            } finally {
                NativeCrypto.asn1_write_flush(seqRef);
                NativeCrypto.asn1_write_free(hashParamsRef);
                NativeCrypto.asn1_write_free(mgfParamsRef);
                NativeCrypto.asn1_write_free(mgfRef);
            }
        }
    }

    /**
     * Writes an ASN.1 AlgorithmIdentifier structure into container, which looks like
     * <pre>
     * SEQUENCE
     *   OBJECT IDENTIFIER
     *   PARAMS (based on the particular algorithm)
     * </pre>
     * This method returns a reference to the sequence such that the params may be added to it.
     * The reference needs to be freed with asn1_write_free once it's used.
     */
    private static long writeAlgorithmIdentifier(long container, String oid) throws IOException {
        long seqRef = 0;
        try {
            seqRef = NativeCrypto.asn1_write_sequence(container);
            NativeCrypto.asn1_write_oid(seqRef, oid);
        } catch (IOException e) {
            NativeCrypto.asn1_write_free(seqRef);
            throw e;
        }
        return seqRef;
    }

    @Override
    protected String engineToString() {
        return "Conscrypt OAEP AlgorithmParameters";
    }
}
