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
import java.util.Objects;
import org.conscrypt.Internal;

/**
 * Properties about a Certificate Transparency Log.
 * This object stores information about a CT log, its public key, description and URL.
 * It allows verification of SCTs against the log's public key.
 */
@Internal
public class LogInfo {
    public static final int STATE_UNKNOWN = 0;
    public static final int STATE_PENDING = 1;
    public static final int STATE_QUALIFIED = 2;
    public static final int STATE_USABLE = 3;
    public static final int STATE_READONLY = 4;
    public static final int STATE_RETIRED = 5;
    public static final int STATE_REJECTED = 6;

    private final byte[] logId;
    private final PublicKey publicKey;
    private final int state;
    private final String description;
    private final String url;
    private final String operator;

    private LogInfo(Builder builder) {
        /* Based on the required fields for the log list schema v3. Notably,
         * the state may be absent. The logId must match the public key, this
         * is validated in the builder. */
        Objects.requireNonNull(builder.logId);
        Objects.requireNonNull(builder.publicKey);
        Objects.requireNonNull(builder.url);
        Objects.requireNonNull(builder.operator);

        this.logId = builder.logId;
        this.publicKey = builder.publicKey;
        this.state = builder.state;
        this.description = builder.description;
        this.url = builder.url;
        this.operator = builder.operator;
    }

    public static class Builder {
        private byte[] logId;
        private PublicKey publicKey;
        private int state;
        private String description;
        private String url;
        private String operator;

        public Builder setPublicKey(PublicKey publicKey) {
            Objects.requireNonNull(publicKey);
            this.publicKey = publicKey;
            try {
                this.logId = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
            } catch (NoSuchAlgorithmException e) {
                // SHA-256 is guaranteed to be available
                throw new RuntimeException(e);
            }
            return this;
        }

        public Builder setState(int state) {
            if (state < 0 || state > STATE_REJECTED) {
                throw new IllegalArgumentException("invalid state value");
            }
            this.state = state;
            return this;
        }

        public Builder setDescription(String description) {
            Objects.requireNonNull(description);
            this.description = description;
            return this;
        }

        public Builder setUrl(String url) {
            Objects.requireNonNull(url);
            this.url = url;
            return this;
        }

        public Builder setOperator(String operator) {
            Objects.requireNonNull(operator);
            this.operator = operator;
            return this;
        }

        public LogInfo build() {
            return new LogInfo(this);
        }
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

    public String getOperator() {
        return operator;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof LogInfo)) {
            return false;
        }

        LogInfo that = (LogInfo) other;
        return this.state == that.state && this.description.equals(that.description)
                && this.url.equals(that.url) && this.operator.equals(that.operator)
                && Arrays.equals(this.logId, that.logId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(logId), description, url, state, operator);
    }

    /**
     * Verify the signature of a signed certificate timestamp for the given certificate entry
     * against the log's public key.
     *
     * @return the result of the verification
     */
    public VerifiedSCT.Status verifySingleSCT(
            SignedCertificateTimestamp sct, CertificateEntry entry) {
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
