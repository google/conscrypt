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

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;

/**
 * Container for verified SignedCertificateTimestamp.
 *
 * getValidSCTs returns SCTs which were found to match a known log and for
 * which the signature has been verified. There is no guarantee on the state of
 * the log (e.g., getLogInfo.getState() may return STATE_UNKNOWN). Further
 * verification on the compliance with the policy is performed in PolicyImpl.
 */
@Internal
public class VerificationResult {
    private final List<VerifiedSCT> validSCTs = new ArrayList<>();
    private final List<VerifiedSCT> invalidSCTs = new ArrayList<>();
    private final EnumMap<SignedCertificateTimestamp.Origin, Integer> count =
            new EnumMap<>(SignedCertificateTimestamp.Origin.class);

    public void add(VerifiedSCT result) {
        if (result.isValid()) {
            validSCTs.add(result);
        } else {
            invalidSCTs.add(result);
        }
        SignedCertificateTimestamp.Origin origin = result.getSct().getOrigin();
        Integer value = count.get(origin);
        if (value == null) {
            count.put(origin, 1);
        } else {
            count.put(origin, value + 1);
        }
    }

    public List<VerifiedSCT> getValidSCTs() {
        return Collections.unmodifiableList(validSCTs);
    }

    public List<VerifiedSCT> getInvalidSCTs() {
        return Collections.unmodifiableList(invalidSCTs);
    }

    public int numCertSCTs() {
        Integer num = count.get(SignedCertificateTimestamp.Origin.EMBEDDED);
        return (num == null ? 0 : num.intValue());
    }

    public int numOCSPSCTs() {
        Integer num = count.get(SignedCertificateTimestamp.Origin.OCSP_RESPONSE);
        return (num == null ? 0 : num.intValue());
    }
    public int numTlsSCTs() {
        Integer num = count.get(SignedCertificateTimestamp.Origin.TLS_EXTENSION);
        return (num == null ? 0 : num.intValue());
    }
}
