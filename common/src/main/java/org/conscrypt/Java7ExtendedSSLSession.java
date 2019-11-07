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
class Java7ExtendedSSLSession extends ExtendedSSLSession implements ConscryptSession {
    // TODO: use BoringSSL API to actually fetch the real data
    private static final String[] LOCAL_SUPPORTED_SIGNATURE_ALGORITHMS = new String[] {
            "SHA512withRSA", "SHA512withECDSA", "SHA384withRSA", "SHA384withECDSA", "SHA256withRSA",
            "SHA256withECDSA", "SHA224withRSA", "SHA224withECDSA", "SHA1withRSA", "SHA1withECDSA",
    };
    // TODO: use BoringSSL API to actually fetch the real data
    private static final String[] PEER_SUPPORTED_SIGNATURE_ALGORITHMS =
            new String[] {"SHA1withRSA", "SHA1withECDSA"};
    protected final ExternalSession delegate;

    Java7ExtendedSSLSession(ExternalSession delegate) {
        this.delegate = delegate;
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
        return delegate.getRequestedServerName();
    }

    /**
     * Provides forward-compatibility with Java 9.
     */
    @Override
    public final List<byte[]> getStatusResponses() {
        return delegate.getStatusResponses();
    }

    @Override
    public final byte[] getPeerSignedCertificateTimestamp() {
        return delegate.getPeerSignedCertificateTimestamp();
    }

    @Override
    public final byte[] getId() {
        return delegate.getId();
    }

    @Override
    public final SSLSessionContext getSessionContext() {
        return delegate.getSessionContext();
    }

    @Override
    public final long getCreationTime() {
        return delegate.getCreationTime();
    }

    @Override
    public final long getLastAccessedTime() {
        return delegate.getLastAccessedTime();
    }

    @Override
    public final void invalidate() {
        delegate.invalidate();
    }

    @Override
    public final boolean isValid() {
        return delegate.isValid();
    }

    @Override
    public final void putValue(String s, Object o) {
        delegate.putValue(this, s, o);
    }

    @Override
    public final Object getValue(String s) {
        return delegate.getValue(s);
    }

    @Override
    public final void removeValue(String s) {
        delegate.removeValue(this, s);
    }

    @Override
    public final String[] getValueNames() {
        return delegate.getValueNames();
    }

    @Override
    public java.security.cert.X509Certificate[] getPeerCertificates()
        throws SSLPeerUnverifiedException {
        return delegate.getPeerCertificates();
    }

    @Override
    public final Certificate[] getLocalCertificates() {
        return delegate.getLocalCertificates();
    }

    @Override
    public final X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        return delegate.getPeerCertificateChain();
    }

    @Override
    public final Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return delegate.getPeerPrincipal();
    }

    @Override
    public final Principal getLocalPrincipal() {
        return delegate.getLocalPrincipal();
    }

    @Override
    public final String getCipherSuite() {
        return delegate.getCipherSuite();
    }

    @Override
    public final String getProtocol() {
        return delegate.getProtocol();
    }

    @Override
    public final String getPeerHost() {
        return delegate.getPeerHost();
    }

    @Override
    public final int getPeerPort() {
        return delegate.getPeerPort();
    }

    @Override
    public final int getPacketBufferSize() {
        return delegate.getPacketBufferSize();
    }

    @Override
    public final int getApplicationBufferSize() {
        return delegate.getApplicationBufferSize();
    }

    @Override
    public String getApplicationProtocol() {
        return delegate.getApplicationProtocol();
    }
}
