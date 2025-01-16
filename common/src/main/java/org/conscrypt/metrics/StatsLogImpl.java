/*
 * Copyright (C) 2020 The Android Open Source Project
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

import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_EXPIRED;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_NOT_FOUND;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_PARSING_FAILED;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_SUCCESS;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_NO_SCTS_FOUND;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_SCTS_NOT_COMPLIANT;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_SUCCESS;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_UNKNOWN;
import static org.conscrypt.metrics.ConscryptStatsLog.TLS_HANDSHAKE_REPORTED;

import org.conscrypt.Internal;
import org.conscrypt.Platform;
import org.conscrypt.ct.LogStore;
import org.conscrypt.ct.PolicyCompliance;
import org.conscrypt.ct.VerificationResult;

import java.lang.Thread.UncaughtExceptionHandler;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

@Internal
public final class StatsLogImpl implements StatsLog {
    private static final ExecutorService e = Executors.newSingleThreadExecutor(new ThreadFactory() {
        @Override
        public Thread newThread(Runnable r) {
            Thread thread = new Thread(r, "ConscryptStatsLog");
            thread.setUncaughtExceptionHandler(new UncaughtExceptionHandler() {
                @Override
                public void uncaughtException(Thread t, Throwable e) {
                    // Ignore
                }
            });
            return thread;
        }
    });

    private static final StatsLog INSTANCE = new StatsLogImpl();
    private StatsLogImpl() {}
    public static StatsLog getInstance() {
        return INSTANCE;
    }

    @Override
    public void countTlsHandshake(
            boolean success, String protocol, String cipherSuite, long duration) {
        Protocol proto = Protocol.forName(protocol);
        CipherSuite suite = CipherSuite.forName(cipherSuite);

        write(TLS_HANDSHAKE_REPORTED, success, proto.getId(), suite.getId(), (int) duration,
                Platform.getStatsSource().getId(), Platform.getUids());
    }

    private static int logStoreStateToMetricsState(LogStore.State state) {
        switch (state) {
            case UNINITIALIZED:
            case LOADED:
                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN;
            case NOT_FOUND:
                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_NOT_FOUND;
            case MALFORMED:
                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_PARSING_FAILED;
            case COMPLIANT:
                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_SUCCESS;
            case NON_COMPLIANT:
                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_EXPIRED;
        }
        return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN;
    }

    @Override
    public void updateCTLogListStatusChanged(LogStore logStore) {
        int state = logStoreStateToMetricsState(logStore.getState());
        write(CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED, state, logStore.getCompatVersion(),
                logStore.getMinCompatVersionAvailable(), logStore.getMajorVersion(),
                logStore.getMinorVersion());
    }

    private static int policyComplianceToMetrics(
            VerificationResult result, PolicyCompliance compliance) {
        if (compliance == PolicyCompliance.COMPLY) {
            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_SUCCESS;
        } else if (result.getValidSCTs().size() == 0) {
            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_NO_SCTS_FOUND;
        } else if (compliance == PolicyCompliance.NOT_ENOUGH_SCTS
                || compliance == PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS) {
            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_SCTS_NOT_COMPLIANT;
        }
        return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_UNKNOWN;
    }

    @Override
    public void reportCTVerificationResult(LogStore store, VerificationResult result,
            PolicyCompliance compliance, CertificateTransparencyVerificationReason reason) {
        if (store.getState() == LogStore.State.NOT_FOUND
                || store.getState() == LogStore.State.MALFORMED) {
            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED,
                    CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE,
                    reason.getId(), 0, 0, 0, 0, 0, 0);
        } else if (store.getState() == LogStore.State.NON_COMPLIANT) {
            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED,
                    CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT,
                    reason.getId(), 0, 0, 0, 0, 0, 0);
        } else if (store.getState() == LogStore.State.COMPLIANT) {
            int comp = policyComplianceToMetrics(result, compliance);
            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED, comp, reason.getId(),
                    store.getCompatVersion(), store.getMajorVersion(), store.getMinorVersion(),
                    result.numCertSCTs(), result.numOCSPSCTs(), result.numTlsSCTs());
        }
    }

    private void write(int atomId, boolean success, int protocol, int cipherSuite, int duration,
            int source, int[] uids) {
        e.execute(new Runnable() {
            @Override
            public void run() {
                ConscryptStatsLog.write(
                        atomId, success, protocol, cipherSuite, duration, source, uids);
            }
        });
    }

    private void write(int atomId, int status, int loadedCompatVersion,
            int minCompatVersionAvailable, int majorVersion, int minorVersion) {
        e.execute(new Runnable() {
            @Override
            public void run() {
                ConscryptStatsLog.write(atomId, status, loadedCompatVersion,
                        minCompatVersionAvailable, majorVersion, minorVersion);
            }
        });
    }

    private void write(int atomId, int verificationResult, int verificationReason,
            int policyCompatVersion, int majorVersion, int minorVersion, int numEmbeddedScts,
            int numOcspScts, int numTlsScts) {
        e.execute(new Runnable() {
            @Override
            public void run() {
                ConscryptStatsLog.write(atomId, verificationResult, verificationReason,
                        policyCompatVersion, majorVersion, minorVersion, numEmbeddedScts,
                        numOcspScts, numTlsScts);
            }
        });
    }
}
