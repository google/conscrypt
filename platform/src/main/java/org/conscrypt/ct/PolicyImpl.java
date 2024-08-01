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

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import org.conscrypt.Internal;

@Internal
public class PolicyImpl implements Policy {
    private final LogStore logStore;
    private final int minimumLogCount;

    public PolicyImpl(LogStore logStore, int minimumLogCount) {
        this.logStore = logStore;
        this.minimumLogCount = minimumLogCount;
    }

    @Override
    public boolean doesResultConformToPolicy(
            VerificationResult result, String hostname, X509Certificate[] chain) {
        Set<LogInfo> logSet = new HashSet<>();
        for (VerifiedSCT verifiedSCT : result.getValidSCTs()) {
            LogInfo log = logStore.getKnownLog(verifiedSCT.sct.getLogID());
            if (log != null) {
                logSet.add(log);
            }
        }

        return logSet.size() >= minimumLogCount;
    }
}
