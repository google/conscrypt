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

package org.conscrypt.metrics;

import org.conscrypt.DomainEncryptionMode;
import org.conscrypt.EchOptions;
import org.conscrypt.Internal;
import org.conscrypt.NetworkSecurityPolicy;

/**
 * A TLS handshake with Encrypted Client Hello attempted, for the purpose of reporting.
 */
@Internal
public class TlsEncryptedClientHelloHandshake {
    enum Result {
        UNKNOWN(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__RESULT__ECH_RESULT_UNKNOWN),
        SUCCESS(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__RESULT__ECH_RESULT_SUCCESS),
        SUCCESS_WITH_GREASE(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__RESULT__ECH_RESULT_SUCCESS_GREASE),
        FAILURE(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__RESULT__ECH_RESULT_FAILURE),
        SKIPPED(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__RESULT__ECH_RESULT_SKIPPED);

        private final int metricsValue;

        public int getMetricsValue() {
            return metricsValue;
        }

        private Result(int metricsValue) {
            this.metricsValue = metricsValue;
        }
    }

    enum UsageReason {
        UNKNOWN(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__USAGE_REASON__ECH_REASON_UNKNOWN),
        DEFAULT(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__USAGE_REASON__ECH_REASON_DEFAULT),
        SDK_TARGET(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__USAGE_REASON__ECH_REASON_SDK_TARGET),
        NSC_APP_OPT_IN(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__USAGE_REASON__ECH_REASON_NSC_APP_OPT_IN),
        NSC_DOMAIN_OPT_IN(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__USAGE_REASON__ECH_REASON_NSC_DOMAIN_OPT_IN);

        private final int metricsValue;

        public int getMetricsValue() {
            return metricsValue;
        }

        private UsageReason(int metricsValue) {
            this.metricsValue = metricsValue;
        }
    }

    enum SkipReason {
        UNKNOWN(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__SKIP_REASON__ECH_SKIP_REASON_UNKNOWN),
        SDK_TARGET(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__SKIP_REASON__ECH_SKIP_REASON_SDK_TARGET),
        NSC_APP_OPT_OUT(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__SKIP_REASON__ECH_SKIP_REASON_NSC_APP_OPT_OUT),
        NSC_DOMAIN_OPT_OUT(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__SKIP_REASON__ECH_SKIP_REASON_NSC_DOMAIN_OPT_OUT),
        NO_CONFIG(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__SKIP_REASON__ECH_SKIP_REASON_NO_CONFIG),
        SERVER_SNI_MISMATCH(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__SKIP_REASON__ECH_SKIP_REASON_SERVER_SNI_MISMATCH),
        UNSUPPORTED_TLS_VERSION(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__SKIP_REASON__ECH_SKIP_REASON_UNSUPPORTED_TLS_VERSION);

        private final int metricsValue;

        public int getMetricsValue() {
            return metricsValue;
        }

        private SkipReason(int metricsValue) {
            this.metricsValue = metricsValue;
        }
    }

    public enum FailureReason {
        UNKNOWN(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__FAILURE_REASON__ECH_FAILURE_REASON_UNKNOWN),
        SERVER_REJECTION(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__FAILURE_REASON__ECH_FAILURE_REASON_SERVER_REJECTION),
        INVALID_CONFIG(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__FAILURE_REASON__ECH_FAILURE_REASON_INVALID_CONFIG),
        INCONSISTENT_NEGOTIATION(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__FAILURE_REASON__ECH_FAILURE_REASON_INCONSISTENT_NEGOTIATION),
        NO_RETRY_CONFIG(
            ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED__FAILURE_REASON__ECH_FAILURE_REASON_NO_RETRY_CONFIGS);

        private final int metricsValue;

        public int getMetricsValue() {
            return metricsValue;
        }

        private FailureReason(int metricsValue) {
            this.metricsValue = metricsValue;
        }
    }

    private final Result result;
    private final UsageReason usageReason;
    private final SkipReason skipReason;
    private final FailureReason failureReason;
    private final int handshakeDurationMillis;

    private TlsEncryptedClientHelloHandshake(Result result, UsageReason usageReason,
            SkipReason skipReason, FailureReason failureReason, int handshakeDurationMillis) {
        this.result = result;
        this.usageReason = usageReason;
        this.skipReason = skipReason;
        this.failureReason = failureReason;
        this.handshakeDurationMillis = handshakeDurationMillis;
    }

    public static final class Builder {
        private Result result = Result.UNKNOWN;
        private EchOptions opts;
        private FailureReason failureReason = FailureReason.UNKNOWN;
        private NetworkSecurityPolicy policy;
        private String hostname;
        private byte[] retryConfigs;
        private int handshakeDurationMillis;
        private boolean handshakeSuccess;

        public Builder() {
        }

        public Builder setEchOptions(EchOptions opts) {
            this.opts = opts;
            return this;
        }

        public Builder setFailureReason(FailureReason failureReason) {
            this.failureReason = failureReason;
            return this;
        }

        public Builder setPolicy(NetworkSecurityPolicy policy) {
            this.policy = policy;
            return this;
        }

        public Builder setHostname(String hostname) {
            this.hostname = hostname;
            return this;
        }

        public Builder setRetryConfigs(byte[] retryConfigs) {
            this.retryConfigs = retryConfigs;

            this.failureReason = (this.retryConfigs == null || this.retryConfigs.length == 0)
                    ? FailureReason.NO_RETRY_CONFIG
                    : FailureReason.SERVER_REJECTION;

            return this;
        }

        public Builder setHandshakeDurationMillis(int handshakeDurationMillis) {
            this.handshakeDurationMillis = handshakeDurationMillis;
            return this;
        }

        public Builder setHandshakeSuccess(boolean handshakeSuccess) {
            this.handshakeSuccess = handshakeSuccess;
            return this;
        }

        private Result calculateResult() {
            if (!handshakeSuccess || failureReason != FailureReason.UNKNOWN) {
                return Result.FAILURE;
            }

            if (calculateSkipReason() != SkipReason.UNKNOWN) {
                return (opts != null && opts.isGreaseEnabled())
                    ? Result.SUCCESS_WITH_GREASE : Result.SKIPPED;
            }

            return Result.SUCCESS;
        }

        private UsageReason calculateUsageReason() {
            if (policy == null || opts == null) {
                // If policy is null, we can't access the NSC settings so no UsageReason can be
                // determined. This may happen if the socket closes before the policy can be set.
                // If opts is null, we aren't using ECH so no UsageReason needed.
                return UsageReason.UNKNOWN;
            }

            if (policy.getDomainEncryptionMode("") == DomainEncryptionMode.OPPORTUNISTIC ||
                policy.getDomainEncryptionMode(hostname) == DomainEncryptionMode.OPPORTUNISTIC ||
                policy.getDomainEncryptionMode("") == DomainEncryptionMode.ENABLED ||
                policy.getDomainEncryptionMode(hostname) == DomainEncryptionMode.ENABLED) {
                // ECH mode was default opportunistic for 26Q2, and default enabled for 26Q4 onwards
                return UsageReason.DEFAULT;
            }

            return policy.getDomainEncryptionMode("") == DomainEncryptionMode.REQUIRED
                    ? UsageReason.NSC_APP_OPT_IN
                    : UsageReason.NSC_DOMAIN_OPT_IN;
        }

        private SkipReason calculateSkipReason() {
            if (policy == null) {
                // If policy is null, we can't access the NSC settings so no SkipReason can be
                // determined. This may happen if the socket closes before the policy can be set.
                return SkipReason.UNKNOWN;
            }

            if (opts == null) {
                return policy.getDomainEncryptionMode("") == DomainEncryptionMode.DISABLED
                        ? SkipReason.NSC_APP_OPT_OUT
                        : SkipReason.NSC_DOMAIN_OPT_OUT;
            }

            if (opts.getConfigList() == null) {
                return SkipReason.NO_CONFIG;
            }

            return SkipReason.UNKNOWN;
        }

        public TlsEncryptedClientHelloHandshake build() {
            return new TlsEncryptedClientHelloHandshake(
                calculateResult(), calculateUsageReason(), calculateSkipReason(),
                    failureReason, handshakeDurationMillis);
        }
    }

    /**
     * Returns the result of the handshake.
     */
    public Result getResult() {
        return this.result;
    }

    /**
     * Returns the reason for trying Encrypted Client Hello.
     */
    public UsageReason getUsageReason() {
        return this.usageReason;
    }

    /**
     * Returns the reason for skipping Encrypted Client Hello.
     */
    public SkipReason getSkipReason() {
        return this.skipReason;
    }

    /**
     * Returns the reason why Encrypted Client Hello failed on the handshake.
     */
    public FailureReason getFailureReason() {
        return this.failureReason;
    }

    /**
     * Returns the duration of the whole TLS handshake in milliseconds.
     */
    public int getHandshakeDurationMillis() {
        return this.handshakeDurationMillis;
    }

    /**
     * Returns true if we should emit the ECH handshake atom or not.
     *
     * <p>The bulk of handshakes will skip ECH due to no config being provided. Use this as a
     * heuristic for whether to emit the ECH handshake atom or not.
     */
    public boolean shouldReportEchHandshake() {
        return result != Result.SKIPPED || skipReason != SkipReason.NO_CONFIG;
    }
}
