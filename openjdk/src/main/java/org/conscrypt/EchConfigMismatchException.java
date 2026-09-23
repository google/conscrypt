/*
 * Copyright (C) 2026 The Android Open Source Project
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

import javax.net.ssl.SSLException;

/**
 * Exception thrown when the provided ECH (Encrypted Client Hello) config does not match the server.
 *
 * <p>Before accessing the retry configuration, clients <b>must</b> call {@link #getPublicHostname()}
 * and verify that the hostname matches the connection hostname (using their preferred {@link
 * javax.net.ssl.HostnameVerifier}). If the returned hostname is {@code null}, any provided retry
 * configuration must be ignored.
 *
 * <p>Clients can then attempt to establish a new connection, using the provided retry {@link
 * EchConfigList}, if available. A retry {@link EchConfigList} may not be available if the server
 * has not provided any.
 */
public class EchConfigMismatchException extends SSLException {
    private final String publicName;
    private final EchConfigList echRetryConfigList;

    /**
     * Returns the {@link EchConfigList} provided by the server for retrying the connection, or
     * {@code null} if no retry configuration was set by the server.
     *
     * Prior to reading this value, the client <b>must</b> verify that the certificate is valid for
     * the name returned by {@link #getPublicHostname()}.
     */
    public EchConfigList getRetryConfigList() {
        if (publicName == null) {
            return null;
        }
        return echRetryConfigList;
    }

    /**
     * Returns the hostname that should be used for verification.
     *
     * This method must be called before interpreting the retry config list, returned by {@link
     * #getRetryConfigList()}.
     *
     * For more details see section 6.1.7 "Authenticating for the Public Name" in RFC TLS Encrypted
     * Client Hello (draft-ietf-tls-esni-25).
     */
    public String getPublicHostname() {
        return publicName;
    }

    /**
     * Returns {@code true} if a retry {@link EchConfigList} is available, false otherwise.
     */
    public boolean hasRetryConfigList() {
        return echRetryConfigList != null;
    }

    /**
     * Constructs a new {@code EchConfigMismatchException}.
     *
     * @param message the detail message.
     */
    public EchConfigMismatchException(String message) {
        super(message);
        this.publicName = null;
        this.echRetryConfigList = null;
    }

    /**
     * Constructs a new {@code EchConfigMismatchException}.
     *
     * @param message the detail message.
     * @param publicName the hostname that must be used for verification, or {@code null} if the
     *        server did not provide a valid public name.
     * @param echRetryConfigList the {@link EchConfigList} provided by the server for retrying the
     *        connection, or {@code null} if no retry configuration was set by the server.
     */
    public EchConfigMismatchException(String message, String publicName,
                                      EchConfigList echRetryConfigList) {
        super(message);
        this.publicName = publicName;
        this.echRetryConfigList = echRetryConfigList;
    }
}
