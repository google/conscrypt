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
package org.conscrypt.metrics;

import org.conscrypt.Internal;
import org.conscrypt.ct.LogStore;
import org.conscrypt.ct.PolicyCompliance;
import org.conscrypt.ct.VerificationResult;

@Internal
public class NoopStatsLog implements StatsLog {
    private static final StatsLog INSTANCE = new NoopStatsLog();
    public static StatsLog getInstance() {
        return INSTANCE;
    }

    public void countTlsHandshake(
            boolean success, String protocol, String cipherSuite, long duration) {}

    public void updateCTLogListStatusChanged(LogStore logStore) {}

    public void reportCTVerificationResult(LogStore logStore, VerificationResult result,
            PolicyCompliance compliance, CertificateTransparencyVerificationReason reason) {}
}
