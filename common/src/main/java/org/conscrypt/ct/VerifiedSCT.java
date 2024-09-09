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

import java.util.Objects;
import org.conscrypt.Internal;

/**
 * Verification result for a single SCT.
 */
@Internal
public final class VerifiedSCT {
    public enum Status {
        VALID,
        INVALID_SIGNATURE,
        UNKNOWN_LOG,
        INVALID_SCT
    }

    private final SignedCertificateTimestamp sct;
    private final Status status;
    private final LogInfo logInfo;

    private VerifiedSCT(Builder builder) {
        Objects.requireNonNull(builder.sct);
        Objects.requireNonNull(builder.status);
        if (builder.status == Status.VALID) {
            Objects.requireNonNull(builder.logInfo);
        }

        this.sct = builder.sct;
        this.status = builder.status;
        this.logInfo = builder.logInfo;
    }

    public SignedCertificateTimestamp getSct() {
        return sct;
    }

    public Status getStatus() {
        return status;
    }

    public boolean isValid() {
        return status == Status.VALID;
    }

    public LogInfo getLogInfo() {
        return logInfo;
    }

    public static class Builder {
        private SignedCertificateTimestamp sct;
        private Status status;
        private LogInfo logInfo;

        public Builder(SignedCertificateTimestamp sct) {
            this.sct = sct;
        }

        public Builder setStatus(Status status) {
            this.status = status;
            return this;
        }

        public Builder setLogInfo(LogInfo logInfo) {
            Objects.requireNonNull(logInfo);
            this.logInfo = logInfo;
            return this;
        }

        public VerifiedSCT build() {
            return new VerifiedSCT(this);
        }
    }
}

