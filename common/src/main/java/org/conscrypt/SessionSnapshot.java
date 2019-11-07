/*
 * Copyright (C) 2017 The Android Open Source Project
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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;

/**
 * A snapshot of the content of another {@link ConscryptSession}. This copies everything over
 * except for the certificates.
 */
final class SessionSnapshot implements ConscryptSession {
    private final SSLSessionContext sessionContext;
    private final byte[] id;
    private final String requestedServerName;
    private final List<byte[]> statusResponses;
    private final byte[] peerTlsSctData;
    private final long creationTime;
    private final long lastAccessedTime;
    private final String cipherSuite;
    private final String protocol;
    private final String peerHost;
    private final String applicationProtocol;
    private final int peerPort;

    SessionSnapshot(ConscryptSession session) {
        sessionContext = session.getSessionContext();
        id = session.getId();
        requestedServerName = session.getRequestedServerName();
        statusResponses = session.getStatusResponses();
        peerTlsSctData = session.getPeerSignedCertificateTimestamp();
        creationTime = session.getCreationTime();
        lastAccessedTime = session.getLastAccessedTime();
        cipherSuite = session.getCipherSuite();
        protocol = session.getProtocol();
        peerHost = session.getPeerHost();
        peerPort = session.getPeerPort();
        applicationProtocol = session.getApplicationProtocol();
    }

    @Override
    public String getRequestedServerName() {
        return requestedServerName;
    }

    @Override
    public List<byte[]> getStatusResponses() {
        List<byte[]> ret = new ArrayList<byte[]>(statusResponses.size());
        for (byte[] resp : statusResponses) {
            ret.add(resp.clone());
        }
        return ret;
    }

    @Override
    public byte[] getPeerSignedCertificateTimestamp() {
        return peerTlsSctData != null ? peerTlsSctData.clone() : null;
    }

    @Override
    public byte[] getId() {
        return id;
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return sessionContext;
    }

    @Override
    public long getCreationTime() {
        return creationTime;
    }

    @Override
    public long getLastAccessedTime() {
        return lastAccessedTime;
    }

    @Override
    public void invalidate() {
        // Do nothing.
    }

    @Override
    public boolean isValid() {
        return false;
    }

    @Override
    public void putValue(String s, Object o) {
        throw new UnsupportedOperationException(
                "All calls to this method should be intercepted by ExternalSession.");
    }

    @Override
    public Object getValue(String s) {
        throw new UnsupportedOperationException(
                "All calls to this method should be intercepted by ExternalSession.");
    }

    @Override
    public void removeValue(String s) {
        throw new UnsupportedOperationException(
                "All calls to this method should be intercepted by ExternalSession.");
    }

    @Override
    public String[] getValueNames() {
        throw new UnsupportedOperationException(
                "All calls to this method should be intercepted by ExternalSession.");
    }

    @Override
    public X509Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        throw new SSLPeerUnverifiedException("No peer certificates");
    }

    @Override
    public Certificate[] getLocalCertificates() {
        return null;
    }

    @Override
    public javax.security.cert.X509Certificate[] getPeerCertificateChain()
        throws SSLPeerUnverifiedException {
        throw new SSLPeerUnverifiedException("No peer certificates");
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        throw new SSLPeerUnverifiedException("No peer certificates");
    }

    @Override
    public Principal getLocalPrincipal() {
        return null;
    }

    @Override
    public String getCipherSuite() {
        return cipherSuite;
    }

    @Override
    public String getProtocol() {
        return protocol;
    }

    @Override
    public String getPeerHost() {
        return peerHost;
    }

    @Override
    public int getPeerPort() {
        return peerPort;
    }

    @Override
    public int getPacketBufferSize() {
        return NativeConstants.SSL3_RT_MAX_PACKET_SIZE;
    }

    @Override
    public int getApplicationBufferSize() {
        return NativeConstants.SSL3_RT_MAX_PLAIN_LENGTH;
    }

    @Override
    public String getApplicationProtocol() {
        return applicationProtocol;
    }
}
