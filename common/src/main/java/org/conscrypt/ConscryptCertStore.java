/*
 * Copyright 2018 The Android Open Source Project
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

import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * A certificate store that supports additional operations that are used in
 * TrustManagerImpl.  This is primarily implemented by the cert store on the
 * Android platform.
 */
@Internal
public interface ConscryptCertStore {

    /**
     * Returns a stored CA certificate with the same name and public key as the
     * provided {@link X509Certificate}.
     */
    X509Certificate getTrustAnchor(X509Certificate c);

    /**
     * Returns all CA certificates with the public key that was used to sign the
     * provided {@link X509Certificate}.
     */
    Set<X509Certificate> findAllIssuers(X509Certificate c);
}
