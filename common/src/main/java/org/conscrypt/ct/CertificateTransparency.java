/*
 * Copyright (C) 2024 The Android Open Source Project
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
import org.conscrypt.Platform;
import org.conscrypt.metrics.StatsLog;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * Certificate Transparency subsystem. The implementation contains references
 * to its log store, its policy and its verifier.
 */
@Internal
public class CertificateTransparency {
    private LogStore logStore;
    private Verifier verifier;
    private Policy policy;
    private StatsLog statsLog;

    public CertificateTransparency(
            LogStore logStore, Policy policy, Verifier verifier, StatsLog statsLog) {
        Objects.requireNonNull(logStore);
        Objects.requireNonNull(policy);
        Objects.requireNonNull(verifier);
        Objects.requireNonNull(statsLog);

        this.logStore = logStore;
        this.policy = policy;
        this.verifier = verifier;
        this.statsLog = statsLog;
    }

    public boolean isCTVerificationRequired(String host) {
        return Platform.isCTVerificationRequired(host);
    }

    public int reasonCTVerificationRequired(String host) {
        return Platform.reasonCTVerificationRequired(host);
    }

    public void checkCT(List<X509Certificate> chain, byte[] ocspData, byte[] tlsData, String host)
            throws CertificateException {
        if (logStore.getState() != LogStore.State.COMPLIANT) {
            /* Fail open. For some reason, the LogStore is not usable. It could
             * be because there is no log list available or that the log list
             * is too old (according to the policy). */
            statsLog.reportCTVerificationResult(logStore,
                    /* VerificationResult */ null,
                    /* PolicyCompliance */ null, reasonCTVerificationRequired(host));
            return;
        }
        VerificationResult result =
                verifier.verifySignedCertificateTimestamps(chain, tlsData, ocspData);

        X509Certificate leaf = chain.get(0);
        PolicyCompliance compliance = policy.doesResultConformToPolicy(result, leaf);
        statsLog.reportCTVerificationResult(
                logStore, result, compliance, reasonCTVerificationRequired(host));
        if (compliance != PolicyCompliance.COMPLY) {
            throw new CertificateException(
                    "Certificate chain does not conform to required transparency policy: "
                    + compliance.name());
        }
    }
}
