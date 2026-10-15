/*
 * Copyright 2026 The Android Open Source Project
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

package org.conscrypt.util;

import org.conscrypt.ConscryptCertStore;
import org.conscrypt.Internal;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

/**
 * Utility methods for draft-ietf-plants-merkle-tree-certs-06 (MTC) ID parsing and message
 * construction.
 */
@Internal
public final class MtcUtils {
    private static final String MTC_PROOF_SIG_ALG_OID = "1.3.6.1.4.1.44363.47.0";
    private static final String MTC_CA_ID_OID = "1.3.6.1.4.1.44363.47.3";
    private static final String MTC_CA_EXT_SHA256_OID = "1.3.6.1.4.1.44363.47.4";
    private static final String ML_DSA_44_OID = "2.16.840.1.101.3.4.3.17";
    private static final String ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18";
    private static final String ML_DSA_87_OID = "2.16.840.1.101.3.4.3.19";
    public static final int MTC_INDEX_BITS = 48;
    public static final long MTC_INDEX_MASK = (1L << MTC_INDEX_BITS) - 1;
    private static final BigInteger MIN_MTC_SERIAL = BigInteger.ONE.shiftLeft(MTC_INDEX_BITS);
    private static final BigInteger MAX_MTC_SERIAL =
            BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
    public static final byte MTC_LEAF_PREFIX = 0x00;
    public static final short ENTRY_TYPE_TBS_CERT = 0x0001;

    private static final String MTC_TAI_PREFIX = "oid/1.3.6.1.4.1.";
    private static final byte[] MTC_SUBTREE_V1_LABEL =
            new byte[] {'s', 'u', 'b', 't', 'r', 'e', 'e', '/', 'v', '1', '\n', 0};

    private MtcUtils() {}

    /**
     * Checks whether the given certificate uses the MTC proof signature algorithm per
     * {@code draft-ietf-plants-merkle-tree-certs-06 Section 6.2}.
     *
     * <p>An MTC signature is identified by having a synthesized signature algorithm indicating
     * an MTC proof (OID {@code 1.3.6.1.4.1.44363.47.0}, {@code id-alg-mtcProof}) with omitted
     * parameters.
     *
     * <p>Note: Per Section 7.2, dispatching between classic X.509 signature verification and
     * MTC verification must be determined by whether the issuer is an MTC CA
     * ({@link #isMtcCaCertificate}), not solely by the subject certificate's signature algorithm.
     */
    public static boolean hasMtcSignatureAlgorithm(X509Certificate cert) {
        if (cert == null) {
            return false;
        }
        return MTC_PROOF_SIG_ALG_OID.equals(cert.getSigAlgOID()) && cert.getSigAlgParams() == null;
    }

    /**
     * Checks whether the given certificate is an MTC CA / Trust Anchor certificate per
     * {@code draft-ietf-plants-merkle-tree-certs-06 Section 5.5}.
     *
     * <p>An MTC CA certificate is identified by the presence of the MTC CA extension
     * (OID {@code 1.3.6.1.4.1.44363.47.4}, {@code id-pe-mtcCertificationAuthority-SHA256}).
     * Structural validity of the extension (such as criticality and serial bounds) and the
     * Subject DN (Trust Anchor ID) is enforced separately during verification so that a
     * malformed MTC CA certificate never falls back to classic X.509 verification.
     */
    public static boolean isMtcCaCertificate(X509Certificate cert) {
        if (cert == null) {
            return false;
        }
        return cert.getExtensionValue(MTC_CA_EXT_SHA256_OID) != null;
    }

    /**
     * Extracts the CA Trust Anchor ID bytes (raw DER {@code RELATIVE-OID} content) from the
     * trust anchor's Subject Distinguished Name per
     * {@code draft-ietf-plants-merkle-tree-certs-06 Section 5.1}.
     *
     * <p>The Subject DN must consist of a single {@code RelativeDistinguishedName} containing a
     * single {@code AttributeTypeAndValue} with type {@code id-rdna-trustAnchorID}
     * ({@code 1.3.6.1.4.1.44363.47.3}) and value encoded as an ASN.1 {@code RELATIVE-OID}.
     */
    public static byte[] extractCaId(TrustAnchor anchor) throws CertificateException {
        X509Certificate cert = (anchor != null) ? anchor.getTrustedCert() : null;
        if (!isMtcCaCertificate(cert)) {
            throw new CertificateException("Trust anchor is not a valid MTC CA certificate");
        }
        X500Principal principal = cert.getSubjectX500Principal();
        if (principal == null) {
            throw new CertificateException("No subject principal found for MTC trust anchor");
        }
        try {
            ByteBuffer nameBuf = ByteBuffer.wrap(principal.getEncoded());
            ByteBuffer rdnSeq = DerUtils.readSequence(nameBuf);
            if (nameBuf.hasRemaining()) {
                throw new CertificateException("Trailing data outside Subject RDNSequence");
            }
            ByteBuffer rdnSet = DerUtils.readSet(rdnSeq);
            if (rdnSeq.hasRemaining()) {
                throw new CertificateException(
                        "MTC CA Subject must contain a single RelativeDistinguishedName");
            }
            ByteBuffer attrSeq = DerUtils.readSequence(rdnSet);
            if (rdnSet.hasRemaining()) {
                throw new CertificateException(
                        "MTC CA Subject RDN must contain a single AttributeTypeAndValue");
            }
            String attrOid = DerUtils.readOid(attrSeq);
            if (!MTC_CA_ID_OID.equals(attrOid)) {
                throw new CertificateException("Unexpected MTC CA Subject attribute OID: "
                                               + attrOid);
            }
            byte[] caId = DerUtils.readRelativeOidBytes(attrSeq);
            if (attrSeq.hasRemaining()) {
                throw new CertificateException(
                        "Trailing data in MTC CA Subject AttributeTypeAndValue");
            }
            return caId;
        } catch (SerializationException e) {
            throw new CertificateException("Failed to parse MTC CA Subject DN", e);
        }
    }

    /**
     * Validates that the leaf certificate's serial number falls within the allowed
     * {@code [minSerial, maxSerial]} range encoded in the trust anchor's critical
     * {@code id-pe-mtcCertificationAuthority-SHA256} extension (Section 5.5 and Section 7.2 Step
     * 4).
     */
    public static void validateSerialInCaRange(TrustAnchor anchor, BigInteger serial)
            throws CertificateException {
        try {
            ByteBuffer seqBuf = readCaExtensionSequence(anchor);
            DerUtils.skipSequence(seqBuf); // sigAlg AlgorithmIdentifier
            BigInteger minSerial = DerUtils.readBigInteger(seqBuf);
            BigInteger maxSerial = DerUtils.readBigInteger(seqBuf);
            if (seqBuf.hasRemaining()) {
                throw new CertificateException(
                        "Trailing data in mtcCertificationAuthority extension");
            }
            if (minSerial.compareTo(MIN_MTC_SERIAL) < 0 || maxSerial.compareTo(MAX_MTC_SERIAL) > 0
                || minSerial.compareTo(maxSerial) > 0) {
                throw new CertificateException("Invalid [minSerial, maxSerial] bounds in MTC CA");
            }
            if (serial.compareTo(minSerial) < 0 || serial.compareTo(maxSerial) > 0) {
                throw new CertificateException("MTC certificate serial " + serial
                                               + " is outside CA allowed range [" + minSerial
                                               + ", " + maxSerial + "]");
            }
        } catch (SerializationException e) {
            throw new CertificateException("Failed to parse mtcCertificationAuthority extension",
                                           e);
        }
    }

    /**
     * Extracts the signature algorithm OID string ({@code sigAlg.algorithm}) from the trust
     * anchor's critical {@code id-pe-mtcCertificationAuthority-SHA256} extension per
     * {@code draft-ietf-plants-merkle-tree-certs-06 Section 5.5}.
     *
     * <p>Only ML-DSA algorithms ({@code ML-DSA-44}, {@code ML-DSA-65}, {@code ML-DSA-87}) with
     * omitted {@code AlgorithmIdentifier} parameters (RFC 9881 Section 2) are supported.
     */
    public static String extractCaSigAlg(TrustAnchor anchor) throws CertificateException {
        try {
            ByteBuffer seqBuf = readCaExtensionSequence(anchor);
            ByteBuffer sigAlgSeq = DerUtils.readSequence(seqBuf);
            String sigAlgOid = DerUtils.readOid(sigAlgSeq);
            // We only support ML-DSA signature algorithms for MTC CA subtree root signatures.
            // Per RFC 9881 Section 2, the AlgorithmIdentifier parameters field MUST be absent.
            if (!isMlDsaOid(sigAlgOid)) {
                throw new CertificateException("Unsupported MTC CA signature algorithm OID: "
                                               + sigAlgOid);
            }
            if (sigAlgSeq.hasRemaining()) {
                throw new CertificateException(
                        "Unexpected parameters in MTC CA sigAlg AlgorithmIdentifier");
            }
            return sigAlgOid;
        } catch (SerializationException e) {
            throw new CertificateException("Failed to parse mtcCertificationAuthority extension",
                                           e);
        }
    }

    /**
     * Returns {@code true} if the given OID identifies a supported ML-DSA signature algorithm
     * ({@code ML-DSA-44}, {@code ML-DSA-65}, or {@code ML-DSA-87} per RFC 9881 Section 2).
     * Only ML-DSA algorithms are supported for MTC CA signatures.
     */
    private static boolean isMlDsaOid(String oid) {
        return ML_DSA_44_OID.equals(oid) || ML_DSA_65_OID.equals(oid) || ML_DSA_87_OID.equals(oid);
    }

    private static ByteBuffer readCaExtensionSequence(TrustAnchor anchor)
            throws CertificateException, SerializationException {
        X509Certificate caCert = (anchor != null) ? anchor.getTrustedCert() : null;
        if (caCert == null) {
            throw new CertificateException("No X509Certificate found in MTC trust anchor");
        }
        Set<String> criticalOids = caCert.getCriticalExtensionOIDs();
        if (criticalOids == null || !criticalOids.contains(MTC_CA_EXT_SHA256_OID)) {
            throw new CertificateException(
                    "MTC CA certificate is missing critical mtcCertificationAuthority extension");
        }
        byte[] extValue = caCert.getExtensionValue(MTC_CA_EXT_SHA256_OID);
        if (extValue == null) {
            throw new CertificateException(
                    "MTC CA certificate is missing mtcCertificationAuthority extension value");
        }
        ByteBuffer extBuf = ByteBuffer.wrap(DerUtils.readOctetString(extValue));
        ByteBuffer seqBuf = DerUtils.readSequence(extBuf);
        if (extBuf.hasRemaining()) {
            throw new CertificateException(
                    "Trailing data outside mtcCertificationAuthority SEQUENCE");
        }
        return seqBuf;
    }

    /**
     * Computes the Subtree v1 Log ID bytes ({@code <ca_id>.0.<logNumber>}) as a base-128
     * {@code RELATIVE-OID} byte array per draft-ietf-plants-merkle-tree-certs-06 Section 5.2.
     *
     * @param caId the issuing CA Trust Anchor ID bytes
     * @param logNumber the log number from the MTC proof
     * @return the encoded Log ID bytes ({@code <ca_id>.0.<logNumber>})
     */
    public static byte[] getLogId(byte[] caId, int logNumber) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(caId.length + 4);
        baos.write(caId, 0, caId.length);
        baos.write(0);
        appendBase128(baos, logNumber);
        return baos.toByteArray();
    }

    private static void appendBase128(ByteArrayOutputStream out, long val) {
        if (val < 0) {
            throw new IllegalArgumentException("Base128 value must be non-negative: " + val);
        }
        // Collect 7-bit chunks from least-significant to most-significant into buf:
        // buf[0] holds the final (least-significant) byte with continuation bit 0, and
        // buf[1..count-1] hold the preceding bytes with continuation bit 0x80 set.
        byte[] buf = new byte[10];
        int count = 0;
        buf[count++] = (byte) (val & 0x7F);
        val >>>= 7;
        while (val > 0) {
            buf[count++] = (byte) ((val & 0x7F) | 0x80);
            val >>>= 7;
        }
        // Emit the collected bytes in reverse order so the output is big-endian.
        for (int i = count - 1; i >= 0; i--) {
            out.write(buf[i]);
        }
    }

    /**
     * Constructs the CosignedMessage structure for signature verification, per
     * draft-ietf-plants-merkle-tree-certs-06 Section 5.3.1 and Section 7.2 Step 12.
     */
    private static byte[] constructCosignedMessage(byte[] cosignerId, byte[] logId, long start,
                                                   long end, byte[] expectedSubtreeHash)
            throws CertificateException {
        String cosignerIdText;
        String logIdText;
        try {
            cosignerIdText = DerUtils.formatRelativeOid(cosignerId);
            logIdText = DerUtils.formatRelativeOid(logId);
        } catch (SerializationException e) {
            throw new CertificateException("Invalid Trust Anchor or Log ID bytes", e);
        }
        byte[] cosignerName = (MTC_TAI_PREFIX + cosignerIdText).getBytes(StandardCharsets.UTF_8);
        byte[] logOrigin = (MTC_TAI_PREFIX + logIdText).getBytes(StandardCharsets.UTF_8);

        int totalLen = MTC_SUBTREE_V1_LABEL.length + 1 + cosignerName.length
                + 8 // timestamp (uint64 0)
                + 1 + logOrigin.length + 8 // start (uint64)
                + 8 // end (uint64)
                + expectedSubtreeHash.length;

        ByteBuffer buf = ByteBuffer.allocate(totalLen);
        buf.put(MTC_SUBTREE_V1_LABEL);
        buf.put((byte) cosignerName.length);
        buf.put(cosignerName);
        buf.putLong(0L); // timestamp = 0
        buf.put((byte) logOrigin.length);
        buf.put(logOrigin);
        buf.putLong(start);
        buf.putLong(end);
        buf.put(expectedSubtreeHash);
        return buf.array();
    }

    /**
     * Finds and extracts the signature bytes for the specified cosigner / issuing CA Trust Anchor
     * ID from the signatures payload, while validating that all {@code cosigner_id} entries are
     * non-empty, unique, and strictly ordered (shorter byte strings first, then lexicographically)
     * per Section 6.2.
     */
    public static byte[] findCaSignature(byte[] signatures, byte[] caId)
            throws CertificateException {
        if (caId == null || caId.length == 0) {
            throw new CertificateException("Empty CA Trust Anchor ID");
        }
        ByteBuffer sigsBuf = ByteBuffer.wrap(signatures);
        byte[] prevSignerId = null;
        byte[] matchedSig = null;
        while (sigsBuf.hasRemaining()) {
            int signerIdLen = readUint8(sigsBuf);
            if (signerIdLen == 0) {
                throw new CertificateException("Malformed MTC proof: empty cosigner_id");
            }
            byte[] signerIdBytes = readBytes(sigsBuf, signerIdLen);
            if (prevSignerId != null && compareCosignerIds(prevSignerId, signerIdBytes) >= 0) {
                throw new CertificateException(
                        "Malformed MTC proof: cosigner_id values are duplicate or out of order");
            }
            prevSignerId = signerIdBytes;

            int sigLen = readUint16(sigsBuf);
            byte[] sigBytes = readBytes(sigsBuf, sigLen);

            if (Arrays.equals(signerIdBytes, caId)) {
                matchedSig = sigBytes;
            }
        }
        return matchedSig;
    }

    /**
     * Compares two {@code cosigner_id} byte arrays per Section 6.2: shorter byte strings precede
     * longer byte strings, and equal-length byte strings are ordered lexicographically (unsigned).
     */
    private static int compareCosignerIds(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return Integer.compare(a.length, b.length);
        }
        for (int i = 0; i < a.length; i++) {
            int cmp = Integer.compare(Byte.toUnsignedInt(a[i]), Byte.toUnsignedInt(b[i]));
            if (cmp != 0) {
                return cmp;
            }
        }
        return 0;
    }

    /**
     * Verifies the issuing CA's signature over the signed tree root for the specified log ID.
     *
     * @throws CertificateException if the signature is invalid
     */
    public static void verifySignedTreeRoot(PublicKey publicKey, String sigAlg, byte[] caId,
                                            byte[] logId, long start, long end,
                                            byte[] expectedSubtreeHash, byte[] caSignature)
            throws CertificateException {
        byte[] msg = constructCosignedMessage(caId, logId, start, end, expectedSubtreeHash);
        try {
            verifySignatureWithKey(publicKey, sigAlg, msg, caSignature);
        } catch (Exception e) {
            throw new CertificateException("MTC CA signed tree root verification failed", e);
        }
    }

    /**
     * Reads an 8-bit unsigned integer from the buffer.
     */
    private static int readUint8(ByteBuffer buffer) throws CertificateException {
        if (buffer.remaining() < 1) {
            throw new CertificateException("Malformed MTC proof: unexpected end of data");
        }
        return Byte.toUnsignedInt(buffer.get());
    }

    /**
     * Reads a 16-bit unsigned integer from the buffer in big-endian order.
     */
    public static int readUint16(ByteBuffer buffer) throws CertificateException {
        if (buffer.remaining() < 2) {
            throw new CertificateException("Malformed MTC proof: unexpected end of data");
        }
        return Short.toUnsignedInt(buffer.getShort());
    }

    /**
     * Reads a 48-bit unsigned integer from the buffer in big-endian order.
     */
    public static long readUint48(ByteBuffer buffer) throws CertificateException {
        if (buffer.remaining() < 6) {
            throw new CertificateException("Malformed MTC proof: unexpected end of data");
        }
        return (Integer.toUnsignedLong(buffer.getInt()) << 16)
                | Short.toUnsignedInt(buffer.getShort());
    }

    /**
     * Reads a byte array of the specified length from the buffer.
     */
    public static byte[] readBytes(ByteBuffer buffer, int length) throws CertificateException {
        if (buffer.remaining() < length) {
            throw new CertificateException("Malformed MTC proof: unexpected end of data");
        }
        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }

    /**
     * Obtains a thread-safe / clean instance of SHA-256 {@link MessageDigest}.
     */
    public static MessageDigest getSha256Digest() throws CertificateException {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateException("SHA-256 algorithm not found", e);
        }
    }

    /**
     * Computes the SHA-256 digest of the given data.
     */
    public static byte[] sha256(byte[] data) throws CertificateException {
        return getSha256Digest().digest(data);
    }

    /**
     * Verifies a digital signature against the provided data using the specified public key and
     * signature algorithm.
     */
    private static void verifySignatureWithKey(PublicKey publicKey, String sigAlg, byte[] data,
                                               byte[] signatureBytes) throws Exception {
        Signature sig = Signature.getInstance(sigAlg);
        sig.initVerify(publicKey);
        sig.update(data);
        if (!sig.verify(signatureBytes)) {
            throw new SignatureException("Signature verification returned false for alg " + sigAlg);
        }
    }

    /**
     * Finds the trust anchor for the issuing CA of the specified MTC leaf certificate.
     *
     * @param leaf the MTC leaf certificate whose issuing CA is being looked up
     * @param acceptedIssuers array of accepted issuer certificates, or {@code null}
     * @param certStore the trusted certificate store, or {@code null}
     * @return the matching {@link TrustAnchor}, or {@code null} if not found
     */
    public static TrustAnchor findIssuingCaTrustAnchor(X509Certificate leaf,
                                                       X509Certificate[] acceptedIssuers,
                                                       ConscryptCertStore certStore) {
        X500Principal issuer = leaf.getIssuerX500Principal();
        if (issuer == null) {
            return null;
        }

        // 1. Check acceptedIssuers if available
        if (acceptedIssuers != null && acceptedIssuers.length > 0) {
            for (X509Certificate cert : acceptedIssuers) {
                if (issuer.equals(cert.getSubjectX500Principal()) && isMtcCaCertificate(cert)) {
                    return new TrustAnchor(cert, null);
                }
            }
        }

        // 2. Query certStore lazily (e.g. AndroidCAStore / NetworkSecurityConfig)
        if (certStore != null) {
            Set<X509Certificate> storeAnchors = certStore.findAllIssuers(leaf);
            if (storeAnchors != null) {
                for (X509Certificate cert : storeAnchors) {
                    if (isMtcCaCertificate(cert)) {
                        return new TrustAnchor(cert, null);
                    }
                }
            }
        }

        return null;
    }

    /**
     * Checks whether the interval {@code [start, end)} defines a valid subtree per
     * draft-ietf-plants-merkle-tree-certs-06 Section 4.1:
     * <ul>
     *   <li>{@code 0 <= start <= end <= 2^48}</li>
     *   <li>{@code start} is a multiple of {@code BIT_CEIL(end - start)}</li>
     * </ul>
     *
     * <p>In the MTC protocol, {@code start} and {@code end} are 48-bit unsigned integers
     * ({@code uint48} in {@code [0, 2^48 - 1]}), so they are always non-negative when represented
     * as signed 64-bit {@code long} values and {@code end - start} cannot overflow.
     */
    public static boolean isValidSubtree(long start, long end) {
        if (start < 0 || start > end || end > (1L << MTC_INDEX_BITS)) {
            return false;
        }
        long size = end - start;
        long bitCeil = (size <= 1) ? 1L : (1L << (64 - Long.numberOfLeadingZeros(size - 1)));
        return (start & (bitCeil - 1)) == 0;
    }
}
