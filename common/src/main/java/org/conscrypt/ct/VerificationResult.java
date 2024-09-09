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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.conscrypt.Internal;

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
    private final ArrayList<VerifiedSCT> validSCTs = new ArrayList<VerifiedSCT>();
    private final ArrayList<VerifiedSCT> invalidSCTs = new ArrayList<VerifiedSCT>();

    public void add(VerifiedSCT result) {
        if (result.isValid()) {
            validSCTs.add(result);
        } else {
            invalidSCTs.add(result);
        }
    }

    public List<VerifiedSCT> getValidSCTs() {
        return Collections.unmodifiableList(validSCTs);
    }

    public List<VerifiedSCT> getInvalidSCTs() {
        return Collections.unmodifiableList(invalidSCTs);
    }
}
