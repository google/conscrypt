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

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import org.conscrypt.Internal;

/**
 * Properties about a Certificate Transparency Log.
 * This object stores information about a CT log, its public key, description and URL.
 * It allows verification of SCTs against the log's public key.
 */
@Internal
public class CTLogInfo {
    public static final int STATE_PENDING = 0;
    public static final int STATE_QUALIFIED = 1;
    public static final int STATE_USABLE = 2;
    public static final int STATE_READONLY = 3;
    public static final int STATE_RETIRED = 4;
    public static final int STATE_REJECTED = 5;

    private final byte[] logId;
    private final PublicKey publicKey;
    private final int state;
    private final String description;
    private final String url;

    public CTLogInfo(PublicKey publicKey, int state, String description, String url) {
        if (publicKey == null) {
            throw new IllegalArgumentException("null publicKey");
        }
        if (description == null) {
            throw new IllegalArgumentException("null description");
        }
        if (state < 0 || state > STATE_REJECTED) {
            throw new IllegalArgumentException("invalid state value");
        }

        try {
            this.logId = MessageDigest.getInstance("SHA-256")
                .digest(publicKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available
            throw new RuntimeException(e);
        }

        this.publicKey = publicKey;
        this.state = state;
        this.description = description;
        this.url = url;
    }

    /**
     * Get the log's ID, that is the SHA-256 hash of it's public key
     */
    public byte[] getID() {
        return logId;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getDescription() {
        return description;
    }

    public String getUrl() {
        return url;
    }

    public int getState() {
        return state;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof CTLogInfo)) {
            return false;
        }

        CTLogInfo that = (CTLogInfo)other;
        return this.state == that.state && this.description.equals(that.description)
                && this.url.equals(that.url) && Arrays.equals(this.logId, that.logId);
    }

    @Override
    public int hashCode() {
        int hash = 1;
        hash = hash * 31 + Arrays.hashCode(logId);
        hash = hash * 31 + description.hashCode();
        hash = hash * 31 + url.hashCode();
        hash = hash * 31 + state;

        return hash;
    }

    /**
     * Verify the signature of a signed certificate timestamp for the given certificate entry
     * against the log's public key.
     *
     * @return the result of the verification
     */
    public VerifiedSCT.Status verifySingleSCT(SignedCertificateTimestamp sct,
                                              CertificateEntry entry) {
        if (!Arrays.equals(sct.getLogID(), getID())) {
            return VerifiedSCT.Status.UNKNOWN_LOG;
        }

        byte[] toVerify;
        try {
            toVerify = sct.encodeTBS(entry);
        } catch (SerializationException e) {
            return VerifiedSCT.Status.INVALID_SCT;
        }

        Signature signature;
        try {
            String algorithm = sct.getSignature().getAlgorithm();
            signature = Signature.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            return VerifiedSCT.Status.INVALID_SCT;
        }

        try {
            signature.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            return VerifiedSCT.Status.INVALID_SCT;
        }

        try {
            signature.update(toVerify);
            if (!signature.verify(sct.getSignature().getSignature())) {
                return VerifiedSCT.Status.INVALID_SIGNATURE;
            }
            return VerifiedSCT.Status.VALID;
        } catch (SignatureException e) {
            // This only happens if the signature is not initialized,
            // but we call initVerify just before, so it should never do
            throw new RuntimeException(e);
        }
    }
}

