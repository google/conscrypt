/*
 * Copyright (C) 2012 The Android Open Source Project
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

package org.conscrypt;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for classes that implement certificate pinning for use in {@link TrustManagerImpl}.
 */
@Internal
public interface CertPinManager {
    /**
     * Given a {@code hostname} and a {@code chain} this verifies that the
     * certificate chain includes pinned certificates if pinning is requested
     * for {@code hostname}.
     */
    void checkChainPinning(String hostname, List<X509Certificate> chain)
            throws CertificateException;
}
