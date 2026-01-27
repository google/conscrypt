/*
 * Copyright (C) 2025 The Android Open Source Project
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
 * Interface for TrustManager methods implemented in Conscrypt but not part of
 * the standard X509TrustManager or X509ExtendedTrustManager.
 *
 * These methods can be called by the Android framework. Extend
 * X509TrustManagerExtensions if these need to be visible to apps.
 */
@Internal
public interface ConscryptX509TrustManager {
    /**
     * Verifies the given certificate chain.
     *
     * <p>See {@link X509TrustManager#checkServerTrusted(X509Certificate[], String)} for a
     * description of the chain and authType parameters. The final parameter, host, should be the
     * hostname of the server.</p>
     *
     * @throws CertificateException if the chain does not verify correctly.
     * @return the properly ordered chain used for verification as a list of X509Certificates.
     */
    public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType,
                                                    String hostname) throws CertificateException;

    /**
     * Verifies the given certificate chain.
     *
     * <p>See {@link X509TrustManager#checkServerTrusted(X509Certificate[], String)} for a
     * description of the chain and authType parameters. The final parameter, host, should be the
     * hostname of the server.
     *
     * <p>ocspData and tlsSctData may be provided to verify any Signed Certificate Timestamp (SCT)
     * attached to the connection. These are ASN.1 octet strings (SignedCertificateTimestampList) as
     * described in RFC 6962, Section 3.3. Note that SCTs embedded in the certificate chain will
     * automatically be processed.
     *
     * @throws CertificateException if the chain does not verify correctly.
     * @return the properly ordered chain used for verification as a list of X509Certificates.
     */
    public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, byte[] ocspData,
                                                    byte[] tlsSctData, String authType,
                                                    String hostname) throws CertificateException;
}
