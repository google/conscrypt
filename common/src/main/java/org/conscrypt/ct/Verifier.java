/*
 * Copyright (C) 2015 The Android Open Source Project
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

package org.conscrypt.ct;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.conscrypt.Internal;
import org.conscrypt.NativeCrypto;
import org.conscrypt.OpenSSLX509Certificate;

@Internal
public class Verifier {
    private final LogStore store;

    public Verifier(LogStore store) {
        this.store = store;
    }

    public VerificationResult verifySignedCertificateTimestamps(List<X509Certificate> chain,
            byte[] tlsData, byte[] ocspData) throws CertificateEncodingException {
        OpenSSLX509Certificate[] certs = new OpenSSLX509Certificate[chain.size()];
        int i = 0;
        for (X509Certificate cert : chain) {
            certs[i++] = OpenSSLX509Certificate.fromCertificate(cert);
        }
        return verifySignedCertificateTimestamps(certs, tlsData, ocspData);
    }

    /**
     * Verify a certificate chain for transparency.
     * Signed timestamps are extracted from the leaf certificate, TLS extension, and stapled ocsp
     * response, and verified against the list of known logs.
     * @throws IllegalArgumentException if the chain is empty
     */
    public VerificationResult verifySignedCertificateTimestamps(OpenSSLX509Certificate[] chain,
            byte[] tlsData, byte[] ocspData) throws CertificateEncodingException {
        if (chain.length == 0) {
            throw new IllegalArgumentException("Chain of certificates mustn't be empty.");
        }

        OpenSSLX509Certificate leaf = chain[0];

        VerificationResult result = new VerificationResult();
        List<SignedCertificateTimestamp> tlsScts = getSCTsFromTLSExtension(tlsData);
        verifyExternalSCTs(tlsScts, leaf, result);

        List<SignedCertificateTimestamp> ocspScts = getSCTsFromOCSPResponse(ocspData, chain);
        verifyExternalSCTs(ocspScts, leaf, result);

        List<SignedCertificateTimestamp> embeddedScts = getSCTsFromX509Extension(chain[0]);
        verifyEmbeddedSCTs(embeddedScts, chain, result);
        return result;
    }

    /**
     * Verify a list of SCTs which were embedded from an X509 certificate.
     * The result of the verification for each sct is added to {@code result}.
     */
    private void verifyEmbeddedSCTs(List<SignedCertificateTimestamp> scts,
            OpenSSLX509Certificate[] chain, VerificationResult result) {
        // Avoid creating the cert entry if we don't need it
        if (scts.isEmpty()) {
            return;
        }

        CertificateEntry precertEntry = null;
        if (chain.length >= 2) {
            OpenSSLX509Certificate leaf = chain[0];
            OpenSSLX509Certificate issuer = chain[1];

            try {
                precertEntry = CertificateEntry.createForPrecertificate(leaf, issuer);
            } catch (CertificateException e) {
                // Leave precertEntry as null, we handle it just below
            }
        }

        if (precertEntry == null) {
            markSCTsAsInvalid(scts, result);
            return;
        }

        for (SignedCertificateTimestamp sct : scts) {
            VerifiedSCT.Status status = verifySingleSCT(sct, precertEntry);
            result.add(new VerifiedSCT(sct, status));
        }
    }

    /**
     * Verify a list of SCTs which were not embedded in an X509 certificate, that is received
     * through the TLS or OCSP extensions.
     * The result of the verification for each sct is added to {@code result}.
     */
    private void verifyExternalSCTs(List<SignedCertificateTimestamp> scts,
            OpenSSLX509Certificate leaf, VerificationResult result) {
        // Avoid creating the cert entry if we don't need it
        if (scts.isEmpty()) {
            return;
        }

        CertificateEntry x509Entry;
        try {
            x509Entry = CertificateEntry.createForX509Certificate(leaf);
        } catch (CertificateException e) {
            markSCTsAsInvalid(scts, result);
            return;
        }

        for (SignedCertificateTimestamp sct : scts) {
            VerifiedSCT.Status status = verifySingleSCT(sct, x509Entry);
            result.add(new VerifiedSCT(sct, status));
        }
    }

    /**
     * Verify a single SCT for the given Certificate Entry
     */
    private VerifiedSCT.Status verifySingleSCT(
            SignedCertificateTimestamp sct, CertificateEntry certEntry) {
        LogInfo log = store.getKnownLog(sct.getLogID());
        if (log == null) {
            return VerifiedSCT.Status.UNKNOWN_LOG;
        }

        return log.verifySingleSCT(sct, certEntry);
    }

    /**
     * Add every SCT in {@code scts} to {@code result} with INVALID_SCT as status
     */
    private void markSCTsAsInvalid(
            List<SignedCertificateTimestamp> scts, VerificationResult result) {
        for (SignedCertificateTimestamp sct : scts) {
            result.add(new VerifiedSCT(sct, VerifiedSCT.Status.INVALID_SCT));
        }
    }

    /**
     * Parse an encoded SignedCertificateTimestampList into a list of SignedCertificateTimestamp
     * instances, as described by RFC6962.
     * Individual SCTs which fail to be parsed are skipped. If the data is null, or the encompassing
     * list fails to be parsed, an empty list is returned.
     * @param origin used to create the SignedCertificateTimestamp instances.
     */
    @SuppressWarnings("MixedMutabilityReturnType")
    private static List<SignedCertificateTimestamp> getSCTsFromSCTList(
            byte[] data, SignedCertificateTimestamp.Origin origin) {
        if (data == null) {
            return Collections.emptyList();
        }

        byte[][] sctList;
        try {
            sctList = Serialization.readList(
                    data, Constants.SCT_LIST_LENGTH_BYTES, Constants.SERIALIZED_SCT_LENGTH_BYTES);
        } catch (SerializationException e) {
            return Collections.emptyList();
        }

        List<SignedCertificateTimestamp> scts = new ArrayList<SignedCertificateTimestamp>();
        for (byte[] encodedSCT : sctList) {
            try {
                SignedCertificateTimestamp sct =
                        SignedCertificateTimestamp.decode(encodedSCT, origin);
                scts.add(sct);
            } catch (SerializationException e) {
                // Ignore errors
            }
        }

        return scts;
    }

    /**
     * Extract a list of SignedCertificateTimestamp from a TLS "signed_certificate_timestamp"
     * extension as described by RFC6962.
     * Individual SCTs which fail to be parsed are skipped. If the data is null, or the encompassing
     * list fails to be parsed, an empty list is returned.
     * @param data contents of the TLS extension to be decoded
     */
    private List<SignedCertificateTimestamp> getSCTsFromTLSExtension(byte[] data) {
        return getSCTsFromSCTList(data, SignedCertificateTimestamp.Origin.TLS_EXTENSION);
    }

    /**
     * Extract a list of SignedCertificateTimestamp contained in an OCSP response.
     * If the data is null, or parsing the OCSP response fails, an empty list is returned.
     * Individual SCTs which fail to be parsed are skipped.
     * @param data contents of the OCSP response
     * @param chain certificate chain for which to get SCTs. Must contain at least the leaf and it's
     *              issuer in order to identify the relevant SingleResponse from the OCSP response,
     *              or an empty list is returned
     */
    private List<SignedCertificateTimestamp> getSCTsFromOCSPResponse(
            byte[] data, OpenSSLX509Certificate[] chain) {
        if (data == null || chain.length < 2) {
            return Collections.emptyList();
        }

        byte[] extData = NativeCrypto.get_ocsp_single_extension(data, Constants.OCSP_SCT_LIST_OID,
                chain[0].getContext(), chain[0], chain[1].getContext(), chain[1]);
        if (extData == null) {
            return Collections.emptyList();
        }

        try {
            return getSCTsFromSCTList(
                    Serialization.readDEROctetString(Serialization.readDEROctetString(extData)),
                    SignedCertificateTimestamp.Origin.OCSP_RESPONSE);
        } catch (SerializationException e) {
            return Collections.emptyList();
        }
    }

    /**
     * Extract a list of SignedCertificateTimestamp embedded in an X509 certificate.
     *
     * If the certificate does not contain any SCT extension, or the encompassing encoded list fails
     * to be parsed, an empty list is returned. Individual SCTs which fail to be parsed are ignored.
     */
    private List<SignedCertificateTimestamp> getSCTsFromX509Extension(OpenSSLX509Certificate leaf) {
        byte[] extData = leaf.getExtensionValue(Constants.X509_SCT_LIST_OID);
        if (extData == null) {
            return Collections.emptyList();
        }

        try {
            return getSCTsFromSCTList(
                    Serialization.readDEROctetString(Serialization.readDEROctetString(extData)),
                    SignedCertificateTimestamp.Origin.EMBEDDED);
        } catch (SerializationException e) {
            return Collections.emptyList();
        }
    }
}
