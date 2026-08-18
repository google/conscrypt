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

import org.conscrypt.Internal;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Properties about a Certificate Transparency Log.
 * This object stores information about a CT log, its public key and URL.
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

    public static final int TYPE_UNKNOWN = 0;
    public static final int TYPE_RFC6962 = 1;
    public static final int TYPE_STATIC_CT_API = 2;

    private final byte[] logId;
    private final PublicKey publicKey;
    private final int state;
    private final long stateTimestamp;
    private final String operator;
    private final int type;

    private LogInfo(Builder builder) {
        /* Based on the required fields for the log list schema v3. Notably,
         * the state may be absent. The logId must match the public key, this
         * is validated in the builder. */
        Objects.requireNonNull(builder.logId);
        Objects.requireNonNull(builder.publicKey);
        Objects.requireNonNull(builder.operator);

        this.logId = builder.logId;
        this.publicKey = builder.publicKey;
        this.state = builder.state;
        this.stateTimestamp = builder.stateTimestamp;
        this.operator = builder.operator;
        this.type = builder.type;
    }

    public static class Builder {
        private byte[] logId;
        private PublicKey publicKey;
        private int state;
        private long stateTimestamp;
        private String operator;
        private int type;

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

        public Builder setState(int state, long timestamp) {
            if (state < 0 || state > STATE_REJECTED) {
                throw new IllegalArgumentException("invalid state value");
            }
            this.state = state;
            this.stateTimestamp = timestamp;
            return this;
        }

        public Builder setOperator(String operator) {
            Objects.requireNonNull(operator);
            this.operator = operator;
            return this;
        }

        public Builder setType(int type) {
            if (type < 0 || type > TYPE_STATIC_CT_API) {
                throw new IllegalArgumentException("invalid type value");
            }
            this.type = type;
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

    public int getState() {
        return state;
    }

    public int getStateAt(long when) {
        if (when >= this.stateTimestamp) {
            return state;
        }
        return STATE_UNKNOWN;
    }

    public long getStateTimestamp() {
        return stateTimestamp;
    }

    public String getOperator() {
        return operator;
    }

    public int getType() {
        return type;
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
        return this.state == that.state && this.operator.equals(that.operator)
                && this.stateTimestamp == that.stateTimestamp && this.type == that.type
                && Arrays.equals(this.logId, that.logId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(logId), state, stateTimestamp, operator, type);
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
