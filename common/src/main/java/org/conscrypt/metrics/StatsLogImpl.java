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

import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_BLOCKLIST_BLOCK_REPORTED;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_SHA1_BUILT_IN;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_SHA1_FILE;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_SHA1_TEST;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_SHA256_BUILT_IN;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_SHA256_FILE;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_SHA256_TEST;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_UNKNOWN;
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
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_VALIDATION_FAILURE_REPORTED;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_VALIDATION_FAILURE_REPORTED__REASON__CERTIFICATE_VALIDATION_FAILURE_REASON_NO_TRUST_ANCHOR;
import static org.conscrypt.metrics.ConscryptStatsLog.CERTIFICATE_VALIDATION_FAILURE_REPORTED__REASON__CERTIFICATE_VALIDATION_FAILURE_REASON_UNKNOWN;
import static org.conscrypt.metrics.ConscryptStatsLog.TLS_HANDSHAKE_REPORTED;
import static org.conscrypt.metrics.ConscryptStatsLog.TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED;

import org.conscrypt.CertBlocklistEntry;
import org.conscrypt.Internal;
import org.conscrypt.Platform;
import org.conscrypt.ct.LogStore;
import org.conscrypt.ct.PolicyCompliance;
import org.conscrypt.ct.VerificationResult;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;

/**
 * Implements logging for Conscrypt metrics.
 */
@Internal
public final class StatsLogImpl implements StatsLog {
    // The queue capacity is capped to prevent memory exhaustion if logging requests
    // flood in faster than the background thread can process them.
    private static final int QUEUE_CAPACITY = 100;

    private final BlockingQueue<Runnable> logQueue;
    private final ExecutorService writerThreadExecutor;

    /**
     * Initialization-on-demand holder idiom.
     * Thread-safe and lazy. Crucial to avoid spawning the writer thread while
     * running in the Zygote process, as thread creation in Zygote is forbidden
     * and causes crashes/deadlocks after fork.
     */
    private static class Holder {
        private static final StatsLogImpl INSTANCE = new StatsLogImpl();
    }

    private StatsLogImpl() {
        this.logQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
        this.writerThreadExecutor =
                Executors.newSingleThreadExecutor(new LowPriorityThreadFactory());
        startWriterThread();
    }

    /**
     * Returns the singleton instance of StatsLogImpl.
     * Using a singleton ensures all logging requests from various connections
     * are funneled into a single shared queue and processed by a single background thread,
     * conserving system resources.
     */
    public static StatsLog getInstance() {
        return Holder.INSTANCE;
    }

    public void stop() {
        // shutdownNow() sends an interrupt to the running thread
        writerThreadExecutor.shutdownNow();
        try {
            writerThreadExecutor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void startWriterThread() {
        writerThreadExecutor.execute(() -> {
            try {
                // Loop until the thread is interrupted
                while (!Thread.currentThread().isInterrupted()) {
                    // Blocks until a log task is available.
                    // If interrupted while blocking, it throws InterruptedException.
                    Runnable logTask = logQueue.take();
                    logTask.run();
                }
            } catch (InterruptedException e) {
                // Thread was interrupted while blocking in take(). Allow it to exit the loop.
            } finally {
                // TRADEOFF: We drain the queue on shutdown to ensure best-effort delivery
                // of the remaining metrics (crucial for unit/integration test stability).
                // However, this can delay shutdown by up to the executor's termination timeout
                // (5 seconds) if the log tasks block. In production, the OS usually terminates
                // the process abruptly (SIGKILL), so this delay only affects clean teardowns.
                while (!logQueue.isEmpty()) {
                    Runnable logTask = logQueue.poll();
                    if (logTask != null) {
                        logTask.run();
                    }
                }
            }
        });
    }

    private static class LowPriorityThreadFactory implements ThreadFactory {
        @Override
        public Thread newThread(Runnable r) {
            Thread thread = new Thread(r, "ConscryptStatsLogWriter");
            thread.setPriority(Thread.MIN_PRIORITY);
            return thread;
        }
    }

    @Override
    public void countTlsHandshake(boolean success, String protocol, String cipherSuite,
                                  long duration) {
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

    private static int policyComplianceToMetrics(VerificationResult result,
                                                 PolicyCompliance compliance) {
        if (compliance == PolicyCompliance.COMPLY) {
            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_SUCCESS;
        } else if (result.getValidSCTs().size() == 0) {
            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_NO_SCTS_FOUND;
        } else if (compliance == PolicyCompliance.NOT_ENOUGH_SCTS
                   || compliance == PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS
                   || compliance == PolicyCompliance.NO_RFC6962_LOG) {
            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_SCTS_NOT_COMPLIANT;
        }
        return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_UNKNOWN;
    }

    private static int getUid() {
        int[] uids = Platform.getUids();
        if (uids != null && uids.length != 0) {
            return uids[0];
        }
        return 0;
    }

    @Override
    public void reportCTVerificationResult(LogStore store, VerificationResult result,
                                           PolicyCompliance compliance,
                                           CertificateTransparencyVerificationReason reason) {
        if (store.getState() == LogStore.State.NOT_FOUND
            || store.getState() == LogStore.State.MALFORMED) {
            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED,
                  CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE,
                  reason.getId(), store.getCompatVersion(), store.getMajorVersion(),
                  store.getMinorVersion(), 0, 0, 0, getUid(), store.getTimestamp());
        } else if (store.getState() == LogStore.State.NON_COMPLIANT) {
            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED,
                  CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT,
                  reason.getId(), store.getCompatVersion(), store.getMajorVersion(),
                  store.getMinorVersion(), 0, 0, 0, getUid(), store.getTimestamp());
        } else if (store.getState() == LogStore.State.COMPLIANT) {
            int comp = policyComplianceToMetrics(result, compliance);
            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED, comp, reason.getId(),
                  store.getCompatVersion(), store.getMajorVersion(), store.getMinorVersion(),
                  result.numCertSCTs(), result.numOCSPSCTs(), result.numTlsSCTs(), getUid(),
                  store.getTimestamp());
        }
    }

    private static int blocklistOriginToMetrics(CertBlocklistEntry.Origin origin) {
        switch (origin) {
            case SHA1_TEST:
                return CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_SHA1_TEST;
            case SHA1_BUILT_IN:
                return CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_SHA1_BUILT_IN;
            case SHA1_FILE:
                return CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_SHA1_FILE;
            case SHA256_TEST:
                return CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_SHA256_TEST;
            case SHA256_BUILT_IN:
                return CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_SHA256_BUILT_IN;
            case SHA256_FILE:
                return CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_SHA256_FILE;
        }
        return CERTIFICATE_BLOCKLIST_BLOCK_REPORTED__SOURCE__BLOCKLIST_SOURCE_UNKNOWN;
    }

    @Override
    public void reportBlocklistHit(CertBlocklistEntry entry) {
        write(CERTIFICATE_BLOCKLIST_BLOCK_REPORTED, blocklistOriginToMetrics(entry.getOrigin()),
              entry.getIndex(), getUid());
    }

    @Override
    public void reportCertificationValidationFailure(CertificateValidationFailureReason reason,
                                                     int chainLength) {
        write(CERTIFICATE_VALIDATION_FAILURE_REPORTED, reason.getId(), chainLength, getUid());
    }

    @Override
    public void reportTlsEchHandshake(TlsEncryptedClientHelloHandshake handshake) {
        write(
            TLS_ENCRYPTED_CLIENT_HELLO_HANDSHAKE_REPORTED,
            handshake.getResult().getMetricsValue(),
            handshake.getUsageReason().getMetricsValue(),
            handshake.getSkipReason().getMetricsValue(),
            handshake.getFailureReason().getMetricsValue(),
            handshake.getHandshakeDurationMillis(),
            getUid());
    }

    private static final boolean sdkVersionBiggerThan32;

    static {
        sdkVersionBiggerThan32 = Platform.isSdkGreater(32);
    }

    @SuppressWarnings("NewApi")
    private void write(int atomId, boolean success, int protocol, int cipherSuite, int duration,
                       int source, int[] uids) {
        if (!sdkVersionBiggerThan32) {
            final ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
            builder.writeInt(atomId);
            builder.writeBoolean(success);
            builder.writeInt(protocol);
            builder.writeInt(cipherSuite);
            builder.writeInt(duration);
            builder.writeInt(source);

            builder.usePooledBuffer();
            ReflexiveStatsLog.write(builder.build());
        } else {
            logQueue.offer(()
                                   -> ConscryptStatsLog.write(atomId, success, protocol,
                                                              cipherSuite, duration, source, uids));
        }
    }

    private void write(int atomId, int status, int loadedCompatVersion,
                       int minCompatVersionAvailable, int majorVersion, int minorVersion) {
        ConscryptStatsLog.write(atomId, status, loadedCompatVersion, minCompatVersionAvailable,
                                majorVersion, minorVersion);
    }

    private void write(int atomId, int verificationResult, int verificationReason,
                       int policyCompatVersion, int majorVersion, int minorVersion,
                       int numEmbeddedScts, int numOcspScts, int numTlsScts, int uid,
                       long logListTimestampMillis) {
        ConscryptStatsLog.write(atomId, verificationResult, verificationReason, policyCompatVersion,
                                majorVersion, minorVersion, numEmbeddedScts, numOcspScts,
                                numTlsScts, uid, logListTimestampMillis);
    }

    private void write(int atomId, int origin, int index, int uid) {
        ConscryptStatsLog.write(atomId, origin, index, uid);
    }

    private void write(int atomId, int result, int usageReason, int skipReason, int failureReason,
                       int handshakeDurationMillis, int uid) {
        ConscryptStatsLog.write(atomId, result, usageReason, skipReason, failureReason,
                                handshakeDurationMillis, uid);
    }
}
