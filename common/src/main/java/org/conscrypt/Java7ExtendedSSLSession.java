/*
 * Copyright 2017 The Android Open Source Project
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

import java.security.Principal;
import java.security.cert.Certificate;
import java.util.List;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;

/**
 * This is an adapter that wraps the active session with {@link ExtendedSSLSession}, if running
 * on Java 7+.
 */
class Java7ExtendedSSLSession extends ExtendedSSLSession implements SessionDecorator {
    // TODO: use BoringSSL API to actually fetch the real data
    private static final String[] LOCAL_SUPPORTED_SIGNATURE_ALGORITHMS = new String[] {
            "SHA512withRSA", "SHA512withECDSA", "SHA384withRSA", "SHA384withECDSA", "SHA256withRSA",
            "SHA256withECDSA", "SHA224withRSA", "SHA224withECDSA", "SHA1withRSA", "SHA1withECDSA",
    };
    // TODO: use BoringSSL API to actually fetch the real data
    private static final String[] PEER_SUPPORTED_SIGNATURE_ALGORITHMS =
            new String[] {"SHA1withRSA", "SHA1withECDSA"};
    private final ConscryptSession delegate;

    Java7ExtendedSSLSession(ConscryptSession delegate) {
        this.delegate = delegate;
    }

    @Override
    public final ConscryptSession getDelegate() {
        return delegate;
    }

    /* @Override */
    @SuppressWarnings("MissingOverride") // For Android backward-compatibility.
    public final String[] getLocalSupportedSignatureAlgorithms() {
        return LOCAL_SUPPORTED_SIGNATURE_ALGORITHMS.clone();
    }

    /* @Override */
    @SuppressWarnings("MissingOverride") // For Android backward-compatibility.
    public final String[] getPeerSupportedSignatureAlgorithms() {
        return PEER_SUPPORTED_SIGNATURE_ALGORITHMS.clone();
    }

    @Override
    public final String getRequestedServerName() {
        return getDelegate().getRequestedServerName();
    }

    /**
     * Provides forward-compatibility with Java 9.
     */
    @Override
    public final List<byte[]> getStatusResponses() {
        return getDelegate().getStatusResponses();
    }

    @Override
    public final byte[] getPeerSignedCertificateTimestamp() {
        return getDelegate().getPeerSignedCertificateTimestamp();
    }

    @Override
    public final byte[] getId() {
        return getDelegate().getId();
    }

    @Override
    public final SSLSessionContext getSessionContext() {
        return getDelegate().getSessionContext();
    }

    @Override
    public final long getCreationTime() {
        return getDelegate().getCreationTime();
    }

    @Override
    public final long getLastAccessedTime() {
        return getDelegate().getLastAccessedTime();
    }

    @Override
    public final void invalidate() {
        getDelegate().invalidate();
    }

    @Override
    public final boolean isValid() {
        return getDelegate().isValid();
    }

    @Override
    public final void putValue(String s, Object o) {
        getDelegate().putValue(s, o);
    }

    @Override
    public final Object getValue(String s) {
        return getDelegate().getValue(s);
    }

    @Override
    public final void removeValue(String s) {
        getDelegate().removeValue(s);
    }

    @Override
    public final String[] getValueNames() {
        return getDelegate().getValueNames();
    }

    @Override
    public java.security.cert.X509Certificate[] getPeerCertificates()
        throws SSLPeerUnverifiedException {
        return getDelegate().getPeerCertificates();
    }

    @Override
    public final Certificate[] getLocalCertificates() {
        return getDelegate().getLocalCertificates();
    }

    @Override
    public final X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        return getDelegate().getPeerCertificateChain();
    }

    @Override
    public final Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return getDelegate().getPeerPrincipal();
    }

    @Override
    public final Principal getLocalPrincipal() {
        return getDelegate().getLocalPrincipal();
    }

    @Override
    public final String getCipherSuite() {
        return getDelegate().getCipherSuite();
    }

    @Override
    public final String getProtocol() {
        return getDelegate().getProtocol();
    }

    @Override
    public final String getPeerHost() {
        return getDelegate().getPeerHost();
    }

    @Override
    public final int getPeerPort() {
        return getDelegate().getPeerPort();
    }

    @Override
    public final int getPacketBufferSize() {
        return getDelegate().getPacketBufferSize();
    }

    @Override
    public final int getApplicationBufferSize() {
        return getDelegate().getApplicationBufferSize();
    }
}
