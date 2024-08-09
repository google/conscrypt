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
import java.util.concurrent.TimeUnit;
import org.conscrypt.Internal;

@Internal
public class PolicyImpl implements Policy {
    @Override
    public PolicyCompliance doesResultConformToPolicy(
            VerificationResult result, X509Certificate leaf) {
        Set<VerifiedSCT> embeddedValidSCTs = new HashSet<>();
        Set<VerifiedSCT> ocspOrTLSValidSCTs = new HashSet<>();
        for (VerifiedSCT vsct : result.getValidSCTs()) {
            if (vsct.getSct().getOrigin() == SignedCertificateTimestamp.Origin.EMBEDDED) {
                embeddedValidSCTs.add(vsct);
            } else {
                ocspOrTLSValidSCTs.add(vsct);
            }
        }
        if (embeddedValidSCTs.size() > 0) {
            return conformEmbeddedSCTs(embeddedValidSCTs, leaf);
        }
        return PolicyCompliance.NOT_ENOUGH_SCTS;
    }

    private PolicyCompliance conformEmbeddedSCTs(
            Set<VerifiedSCT> embeddedValidSCTs, X509Certificate leaf) {
        /* 1. At least one Embedded SCT from a CT Log that was Qualified,
         *    Usable, or ReadOnly at the time of check;
         */
        boolean found = false;
        for (VerifiedSCT vsct : embeddedValidSCTs) {
            LogInfo log = vsct.getLogInfo();
            switch (log.getState()) {
                case LogInfo.STATE_QUALIFIED:
                case LogInfo.STATE_USABLE:
                case LogInfo.STATE_READONLY:
                    found = true;
            }
        }
        if (!found) {
            return PolicyCompliance.NOT_ENOUGH_SCTS;
        }

        /* 2. There are Embedded SCTs from at least N distinct CT Logs that
         *    were Qualified, Usable, ReadOnly, or Retired at the time of check,
         *    where N is defined in the following table;
         *
         *    Certificate Lifetime    Number of SCTs from distinct CT Logs
         *         <= 180 days                        2
         *          > 180 days                        3
         */
        Set<LogInfo> validLogs = new HashSet<>();
        int numberSCTsRequired;
        long certLifetimeMs = leaf.getNotAfter().getTime() - leaf.getNotBefore().getTime();
        long certLifetimeDays = TimeUnit.DAYS.convert(certLifetimeMs, TimeUnit.MILLISECONDS);
        if (certLifetimeDays <= 180) {
            numberSCTsRequired = 2;
        } else {
            numberSCTsRequired = 3;
        }
        for (VerifiedSCT vsct : embeddedValidSCTs) {
            LogInfo log = vsct.getLogInfo();
            switch (log.getState()) {
                case LogInfo.STATE_QUALIFIED:
                case LogInfo.STATE_USABLE:
                case LogInfo.STATE_READONLY:
                case LogInfo.STATE_RETIRED:
                    validLogs.add(log);
            }
        }
        if (validLogs.size() < numberSCTsRequired) {
            return PolicyCompliance.NOT_ENOUGH_SCTS;
        }

        /* 3. Among the SCTs satisfying requirements 1 and 2, at least two SCTs
         *    must be issued from distinct CT Log Operators as recognized by
         *    Chrome.
         */
        Set<String> operators = new HashSet<>();
        for (LogInfo logInfo : validLogs) {
            operators.add(logInfo.getOperator());
        }
        if (operators.size() < 2) {
            return PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS;
        }

        return PolicyCompliance.COMPLY;
    }
}
