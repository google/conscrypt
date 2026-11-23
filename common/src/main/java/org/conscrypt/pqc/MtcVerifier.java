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

package org.conscrypt.pqc;

import org.conscrypt.Internal;
import org.conscrypt.util.DerUtils;
import org.conscrypt.util.SerializationException;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Verifies Merkle Tree Certificates (MTC) per IETF draft
 * {@code draft-ietf-plants-merkle-tree-certs-07}
 * (https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-07).
 */
@Internal
public final class MtcVerifier {
    private MtcVerifier() {}

    /**
     * Verifies Merkle Tree Certificates (MTC) per draft-ietf-plants-merkle-tree-certs-07
     * Section 7.2
     * (https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-07#section-7.2).
     * Validates that the leaf certificate is authenticated via a Merkle inclusion proof
     * rooted at a trusted log checkpoint or cosigned subtree.
     */
    public static void verifyMTC(X509Certificate leaf, TrustAnchor anchor)
            throws CertificateException {
        if (leaf == null) {
            throw new CertificateException("MTC leaf certificate is null");
        }

        // =====================================================================
        // Step 1: Signature Algorithm Verification (Section 6.2)
        // Ensure the certificate indicates MTC proof-based authentication.
        // =====================================================================
        if (!MtcUtils.hasMtcSignatureAlgorithm(leaf)) {
            throw new CertificateException("Unacceptable signature algorithm for MTC: "
                                           + leaf.getSigAlgOID());
        }

        // =====================================================================
        // Step 2: Proof Parsing (Section 6.2)
        // Unpack the MTCProof structure (extensions, subtree interval [start, end),
        // inclusion proof, and signatures) from the signature field.
        // =====================================================================
        byte[] sigBytes = leaf.getSignature();
        if (sigBytes == null) {
            throw new CertificateException("Missing MTC proof");
        }

        ByteBuffer buffer = ByteBuffer.wrap(sigBytes);
        int extLen = MtcUtils.readUint16(buffer);
        byte[] extensions = MtcUtils.readBytes(buffer, extLen);
        MtcUtils.validateExtensions(extensions);
        long start = MtcUtils.readUint48(buffer);
        long end = MtcUtils.readUint48(buffer);
        int proofLen = MtcUtils.readUint16(buffer);
        byte[] inclusionProof = MtcUtils.readBytes(buffer, proofLen);
        int sigsLen = MtcUtils.readUint24(buffer);
        byte[] signatures = MtcUtils.readBytes(buffer, sigsLen);
        if (buffer.hasRemaining()) {
            throw new CertificateException("Trailing data in MTC proof");
        }

        // =====================================================================
        // Step 3: Serial Number Validation
        // Validate that the certificate contains a valid 64-bit positive serial number.
        // =====================================================================
        BigInteger serial = leaf.getSerialNumber();
        if (serial == null || serial.signum() <= 0 || serial.bitLength() > 64) {
            throw new CertificateException("Invalid or missing serial number in MTC certificate");
        }

        // =====================================================================
        // Step 4: Revocation Status Check (Section 7.5)
        // Check if the serial number falls within any revoked ranges.
        // =====================================================================
        if (anchor == null || anchor.getTrustedCert() == null) {
            throw new CertificateException("No issuing CA trust anchor found for MTC certificate: "
                                           + leaf.getIssuerX500Principal());
        }
        MtcUtils.validateSerialInCaRange(anchor, serial);
        // TODO: Check that the serial is not contained in out-of-band revoked ranges.

        // =====================================================================
        // Step 5: Decompose Serial & Validate Subtree Interval (Section 4.3.2)
        // Decompose serial into 16-bit log number and 48-bit index, and validate that
        // the subtree interval [start, end) is valid and contains the index.
        // =====================================================================
        int logNumber = extractLogNumber(serial);
        validateSubtreeInterval(start, end, proofLen);
        long index = extractIndex(serial, start, end);

        // =====================================================================
        // Step 6: Derive Log ID (Section 5.2)
        // Find the issuing CA trust anchor and derive the log ID from the CA ID and log number.
        // =====================================================================
        if (!Objects.equals(leaf.getIssuerX500Principal(),
                            anchor.getTrustedCert().getSubjectX500Principal())) {
            throw new CertificateException(
                    "MTC leaf issuer does not match CA trust anchor subject");
        }
        byte[] caId = MtcUtils.extractCaId(anchor);
        byte[] logId = MtcUtils.getLogId(caId, logNumber);

        // =====================================================================
        // Steps 7 to 9: Leaf Entry Construction & Leaf Hash
        // Reconstruct the MerkleTreeCertEntry payload (type 0x0001: tbs_cert_entry) wrapping the
        // proof extensions and TBSCertificate, then compute the leaf digest MTH({entry}) =
        // SHA-256(0x00 || entry).
        // =====================================================================
        byte[] tbsCertEntryData = constructTbsCertEntryData(leaf);
        byte[] entry = constructMerkleTreeCertEntry(extensions, tbsCertEntryData);
        byte[] entryHash = computeLeafHash(entry);

        // =====================================================================
        // Step 10: Merkle Tree Inclusion Proof Evaluation (Section 4.3.2)
        // Walk up the Merkle tree from the leaf hash using the sibling hashes in inclusion_proof
        // to reconstruct the expected subtree root hash.
        // =====================================================================
        byte[] expectedSubtreeHash =
                evaluateInclusionProof(inclusionProof, index, start, end, entryHash);

        // =====================================================================
        // Step 11: Trusted Subtree Verification (Section 7.4)
        // TODO: Check if the trust anchor has a pre-configured trusted subtree matching
        // (log_number, [start, end)) and verify expectedSubtreeHash against its root hash.
        // =====================================================================

        // =====================================================================
        // Step 12: Issuing CA Signed Subtree Root Signature
        // =====================================================================
        verifyMtcCaSignedSubtreeRoot(signatures, anchor, caId, logId, start, end,
                                     expectedSubtreeHash);

        // =====================================================================
        // Step 13: Cosigner Checkpoint Signatures (Section 7.3)
        // TODO: Implement third-party cosigners verification and witness quorum policy
        // per draft-ietf-plants-merkle-tree-certs Section 7.3.
        // =====================================================================

        // =====================================================================
        // Path Validation Checks (Section 5.5 & Section 7.2)
        // Verify CA and leaf certificate validity periods and CA constraints.
        // =====================================================================
        X509Certificate caCert = anchor.getTrustedCert();
        caCert.checkValidity();
        if (caCert.getBasicConstraints() == -1) {
            throw new CertificateException("MTC CA certificate missing BasicConstraints cA=TRUE");
        }
        boolean[] keyUsage = caCert.getKeyUsage();
        if (keyUsage != null && (keyUsage.length <= 5 || !keyUsage[5])) {
            throw new CertificateException("MTC CA certificate missing keyCertSign KeyUsage");
        }
        leaf.checkValidity();
    }

    /**
     * Validates that the subtree range [start, end) is a valid subtree interval
     * (either power-of-two full subtree or partial subtree) and that the proof length
     * is valid (a non-negative multiple of 32 bytes), per
     * draft-ietf-plants-merkle-tree-certs Section 4.1 and Section 4.3.2.
     */
    private static void validateSubtreeInterval(long start, long end, int proofLen)
            throws CertificateException {
        if (start >= end) {
            throw new CertificateException("Invalid MTC proof subtree interval: start >= end");
        }
        if (!MtcUtils.isValidSubtree(start, end)) {
            throw new CertificateException("Invalid MTC proof subtree interval [" + start + ", "
                                           + end + ")");
        }
        if (proofLen < 0 || (proofLen % 32) != 0) {
            throw new CertificateException("Invalid MTC inclusion proof length: " + proofLen);
        }
    }

    /**
     * Extracts and validates the 16-bit log number from an MTC serial number (upper 16 bits).
     * Spec: log_number = floor(serialNumber / 2^48) per draft-ietf-plants-merkle-tree-certs
     * Section 7.2 Step 5.
     */
    private static int extractLogNumber(BigInteger serial) throws CertificateException {
        int logNumber = (int) (serial.longValue() >>> MtcUtils.MTC_INDEX_BITS);
        if (logNumber == 0) {
            throw new CertificateException("Invalid log_number 0 in MTC serial number");
        }
        return logNumber;
    }

    /**
     * Extracts and validates the 48-bit certificate index from an MTC serial number (lower 48
     * bits), ensuring it falls within the subtree interval [start, end). Spec: index = serialNumber
     * mod 2^48 per draft-ietf-plants-merkle-tree-certs Section 7.2 Step 5.
     */
    private static long extractIndex(BigInteger serial, long start, long end)
            throws CertificateException {
        long index = serial.longValue() & MtcUtils.MTC_INDEX_MASK;
        if (index < start || index >= end) {
            throw new CertificateException("Certificate index " + index
                                           + " is outside MTC proof subtree range [" + start
                                           + ", " + end + ")");
        }
        return index;
    }

    /**
     * Constructs a MerkleTreeCertEntry of type tbs_cert_entry (0x0001) per Section 7.2 Step 8.
     * Entry format: extensions (u16 length-prefixed) || type (u16 = 0x0001) || tbs_cert_entry_data.
     */
    private static byte[] constructMerkleTreeCertEntry(byte[] extensions, byte[] tbsCertEntryData)
            throws CertificateException {
        int totalLen = 2 + extensions.length + 2 + tbsCertEntryData.length;
        if (totalLen > 65535) {
            throw new CertificateException("MTCLogEntry exceeds maximum size of 65535 bytes");
        }
        ByteBuffer buffer = ByteBuffer.allocate(totalLen);
        buffer.putShort((short) extensions.length);
        buffer.put(extensions);
        buffer.putShort(MtcUtils.ENTRY_TYPE_TBS_CERT);
        buffer.put(tbsCertEntryData);
        return buffer.array();
    }

    /**
     * Constructs the DER-encoded contents of the TBSCertificateLogEntry structure from the
     * leaf X.509 certificate's TBSCertificate, per draft-ietf-plants-merkle-tree-certs Section 7.2
     * Step 8.
     */
    private static byte[] constructTbsCertEntryData(X509Certificate leaf)
            throws CertificateException {
        try {
            ByteBuffer tbsOuter = ByteBuffer.wrap(leaf.getTBSCertificate());
            ByteBuffer tbs = DerUtils.readSequence(tbsOuter);
            if (tbsOuter.hasRemaining()) {
                throw new CertificateException("Trailing data outside TBSCertificate SEQUENCE");
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // 1. Version [0] EXPLICIT Version (tag 0xA0) - optional
            byte[] version = DerUtils.readOptionalElement(tbs, DerUtils.TAG_CONTEXT_EXPLICIT_0);
            if (version != null) {
                out.write(version, 0, version.length);
            }

            // 2. Serial Number (tag 0x02) & 3. Signature Algorithm (tag 0x30) - omitted
            DerUtils.readBigInteger(tbs);
            ByteBuffer sigAlgSeq = DerUtils.readSequence(tbs);
            String innerSigAlgOid = DerUtils.readOid(sigAlgSeq);
            if (!MtcUtils.MTC_PROOF_SIG_ALG_OID.equals(innerSigAlgOid)
                || sigAlgSeq.hasRemaining()) {
                throw new CertificateException(
                        "Invalid TBSCertificate.signature AlgorithmIdentifier");
            }

            // 4. Issuer (tag 0x30)
            byte[] issuer = DerUtils.readSequenceElement(tbs);
            out.write(issuer, 0, issuer.length);

            // 5. Validity (tag 0x30)
            byte[] validity = DerUtils.readSequenceElement(tbs);
            out.write(validity, 0, validity.length);

            // 6. Subject (tag 0x30)
            byte[] subject = DerUtils.readSequenceElement(tbs);
            out.write(subject, 0, subject.length);

            // 7. SubjectPublicKeyInfo (tag 0x30) -> extract algorithm + SHA-256 hash of SPKI
            byte[] spki = DerUtils.readSequenceElement(tbs);
            ByteBuffer spkiOuter = ByteBuffer.wrap(spki);
            ByteBuffer spkiBuf = DerUtils.readSequence(spkiOuter);
            byte[] spkiAlg = DerUtils.readSequenceElement(spkiBuf);
            out.write(spkiAlg, 0, spkiAlg.length);

            // SubjectPublicKeyInfoHash as OCTET STRING
            byte[] spkiHash = MtcUtils.sha256(spki);
            out.write(0x04);
            out.write(spkiHash.length);
            out.write(spkiHash, 0, spkiHash.length);

            // 8. Remaining elements (extensions [3] tag 0xA3, unique identifiers, etc.)
            byte[] remaining = new byte[tbs.remaining()];
            tbs.get(remaining);
            out.write(remaining, 0, remaining.length);

            return out.toByteArray();
        } catch (SerializationException e) {
            throw new CertificateException("Failed to parse TBSCertificate DER", e);
        }
    }

    /**
     * Computes the leaf node hash MTH({entry}) = SHA-256(0x00 || entry) per Section 7.2 Step 9.
     */
    private static byte[] computeLeafHash(byte[] entry) throws CertificateException {
        MessageDigest md = MtcUtils.getSha256Digest();
        md.update(MtcUtils.MTC_LEAF_PREFIX);
        return md.digest(entry);
    }

    /**
     * Evaluates a Merkle subtree inclusion proof to calculate the expected subtree root hash,
     * per draft-ietf-plants-merkle-tree-certs Section 4.3.2 and Section 7.2 Step 10.
     *
     * <p>Assumes the caller has already validated that {@code [start, end)} is a valid non-empty
     * subtree interval containing {@code index} ({@code 0 <= start <= index < end <= 2^48}) and
     * that {@code inclusionProof.length} is a multiple of 32 bytes (see
     * {@link #validateSubtreeInterval} and {@link #extractIndex}).
     */
    private static byte[] evaluateInclusionProof(byte[] inclusionProof, long index, long start,
                                                 long end, byte[] leafHash)
            throws CertificateException {
        // fn: current node index within the subtree (0-based)
        // sn: last node index in the subtree (when sn == 0, we have reached the root)
        long fn = index - start;
        long sn = end - start - 1;
        byte[] currentHash = leafHash;
        ByteBuffer buffer = ByteBuffer.wrap(inclusionProof);

        while (buffer.hasRemaining()) {
            // If sn is already 0, we have reached the root and the proof contains extra hashes.
            if (sn == 0) {
                throw new CertificateException("Inclusion proof contains too many nodes");
            }
            if (buffer.remaining() < 32) {
                throw new CertificateException("Invalid inclusion proof node length");
            }
            byte[] p = new byte[32];
            buffer.get(p);

            MessageDigest nodeDigest = MtcUtils.getSha256Digest();
            nodeDigest.update(
                    (byte) 0x01); // Domain separator for interior Merkle nodes (RFC 9162 § 2.1)

            // Determine if the adjacent hash p is on the left or right:
            // - If fn is odd (a right-hand child) or fn == sn (the rightmost node of an unbalanced
            // subtree),
            //   hash p is on the left.
            // - Otherwise, hash p is on the right.
            if ((fn & 1) != 0 || fn == sn) {
                nodeDigest.update(p);
                nodeDigest.update(currentHash);
                currentHash = nodeDigest.digest();

                // Advance past completed balanced subtrees to find the next ancestor.
                while ((fn & 1) == 0) {
                    fn >>>= 1;
                    sn >>>= 1;
                }
            } else {
                nodeDigest.update(currentHash);
                nodeDigest.update(p);
                currentHash = nodeDigest.digest();
            }

            // Move one level up the tree.
            fn >>>= 1;
            sn >>>= 1;
        }

        // If sn is not 0, the proof ended before reaching the root.
        if (sn != 0) {
            throw new CertificateException("Inclusion proof incomplete: remaining sn=" + sn);
        }

        return currentHash;
    }

    /**
     * Verifies that the signatures in an MTCProof contain a valid signature from the issuing CA
     * over the computed Merkle subtree root hash, per draft-ietf-plants-merkle-tree-certs Section
     * 7.2 Step 12.
     */
    private static void verifyMtcCaSignedSubtreeRoot(byte[] signatures, TrustAnchor anchor,
                                                     byte[] caId, byte[] logId, long start,
                                                     long end, byte[] expectedSubtreeHash)
            throws CertificateException {
        if (signatures == null || signatures.length == 0) {
            throw new CertificateException("MTC proof contains no signatures");
        }

        // 1. Resolve issuing CA public key
        PublicKey publicKey = anchor.getTrustedCert().getPublicKey();
        if (publicKey == null) {
            throw new CertificateException("No public key found for MTC trust anchor");
        }

        // 2. Extract the issuing CA signature from the signatures payload
        byte[] caSignature = MtcUtils.findCaSignature(signatures, caId);
        if (caSignature == null) {
            throw new CertificateException("No signature from issuing CA found in MTC proof");
        }

        // 3. Verify the signed subtree root signature
        String sigAlg = MtcUtils.extractCaSigAlg(anchor);
        MtcUtils.verifySignedSubtreeRoot(publicKey, sigAlg, caId, logId, start, end,
                                         expectedSubtreeHash, caSignature);
    }
}
