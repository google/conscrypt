/*
 * Copyright 2015 The Android Open Source Project
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
import java.util.Collections;
import java.util.List;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;

/**
 * Implementation of the ExtendedSSLSession class for OpenSSL. Uses a delegate to maintain backward
 * compatibility with previous versions of Android which don't have ExtendedSSLSession.
 */
public class OpenSSLExtendedSessionImpl extends ExtendedSSLSession {
    private final OpenSSLSessionImpl delegate;

    public OpenSSLExtendedSessionImpl(OpenSSLSessionImpl delegate) {
        this.delegate = delegate;
    }

    public OpenSSLSessionImpl getDelegate() {
        return delegate;
    }

    public String[] getLocalSupportedSignatureAlgorithms() {
        // From src/ssl/t1_lib.c tls12_sigalgs
        // TODO: use BoringSSL API to actually fetch the real data
        return new String[] {
                "SHA512withRSA",
                "SHA512withECDSA",
                "SHA384withRSA",
                "SHA384withECDSA",
                "SHA256withRSA",
                "SHA256withECDSA",
                "SHA224withRSA",
                "SHA224withECDSA",
                "SHA1withRSA",
                "SHA1withECDSA",
        };
    }

    public String[] getPeerSupportedSignatureAlgorithms() {
        // TODO: use BoringSSL API to actually fetch the real data
        return new String[] {
                "SHA1withRSA",
                "SHA1withECDSA",
        };
    }

    public List<SNIServerName> getRequestedServerNames() {
        String requestedServerName = delegate.getRequestedServerName();
        if (requestedServerName == null) {
            return null;
        }

        return Collections.<SNIServerName> singletonList(new SNIHostName(requestedServerName));
    }

    @Override
    public byte[] getId() {
        return delegate.getId();
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return delegate.getSessionContext();
    }

    @Override
    public long getCreationTime() {
        return delegate.getCreationTime();
    }

    @Override
    public long getLastAccessedTime() {
        return delegate.getLastAccessedTime();
    }

    @Override
    public void invalidate() {
        delegate.invalidate();
    }

    @Override
    public boolean isValid() {
        return delegate.isValid();
    }

    @Override
    public void putValue(String name, Object value) {
        delegate.putValue(name, value);
    }

    @Override
    public Object getValue(String name) {
        return delegate.getValue(name);
    }

    @Override
    public void removeValue(String name) {
        delegate.removeValue(name);
    }

    @Override
    public String[] getValueNames() {
        return delegate.getValueNames();
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        return delegate.getPeerCertificates();
    }

    @Override
    public Certificate[] getLocalCertificates() {
        return delegate.getLocalCertificates();
    }

    @Override
    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        return delegate.getPeerCertificateChain();
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return delegate.getPeerPrincipal();
    }

    @Override
    public Principal getLocalPrincipal() {
        return delegate.getLocalPrincipal();
    }

    @Override
    public String getCipherSuite() {
        return delegate.getCipherSuite();
    }

    @Override
    public String getProtocol() {
        return delegate.getProtocol();
    }

    @Override
    public String getPeerHost() {
        return delegate.getPeerHost();
    }

    @Override
    public int getPeerPort() {
        return delegate.getPeerPort();
    }

    @Override
    public int getPacketBufferSize() {
        return delegate.getPacketBufferSize();
    }

    @Override
    public int getApplicationBufferSize() {
        return delegate.getApplicationBufferSize();
    }
}
