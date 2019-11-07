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

import static org.conscrypt.Preconditions.checkNotNull;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;

/**
 * A session that is dedicated a single connection and operates directly on the underlying
 * {@code SSL}.
 */
final class ActiveSession implements ConscryptSession {
    private final NativeSsl ssl;
    private AbstractSessionContext sessionContext;
    private byte[] id;
    private long creationTime;
    private String protocol;
    private String applicationProtocol;
    private String peerHost;
    private int peerPort = -1;
    private long lastAccessedTime = 0;
    private volatile javax.security.cert.X509Certificate[] peerCertificateChain;
    private X509Certificate[] localCertificates;
    private X509Certificate[] peerCertificates;
    private byte[] peerCertificateOcspData;
    private byte[] peerTlsSctData;

    ActiveSession(NativeSsl ssl, AbstractSessionContext sessionContext) {
        this.ssl = checkNotNull(ssl, "ssl");
        this.sessionContext = checkNotNull(sessionContext, "sessionContext");
    }

    @Override
    public byte[] getId() {
        if (id == null) {
            synchronized (ssl) {
                id = ssl.getSessionId();
            }
        }
        return id != null ? id.clone() : EmptyArray.BYTE;
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return isValid() ? sessionContext : null;
    }

    @Override
    public long getCreationTime() {
        if (creationTime == 0) {
            synchronized (ssl) {
                creationTime = ssl.getTime();
            }
        }
        return creationTime;
    }

    /**
     * Returns the last time this SSL session was accessed. Accessing
     * here is to mean that a new connection with the same SSL context data was
     * established.
     *
     * @return the session's last access time in milliseconds since the epoch
     */
    // TODO(nathanmittler): Does lastAccessedTime need to account for session reuse?
    @Override
    public long getLastAccessedTime() {
        return lastAccessedTime == 0 ? getCreationTime() : lastAccessedTime;
    }

    void setLastAccessedTime(long accessTimeMillis) {
        lastAccessedTime = accessTimeMillis;
    }

    /**
     * Returns the OCSP stapled response. Returns a copy of the internal arrays.
     *
     * The method signature matches
     * <a
     * href="http://download.java.net/java/jdk9/docs/api/javax/net/ssl/ExtendedSSLSession.html#getStatusResponses--">Java
     * 9</a>.
     *
     * @see <a href="https://tools.ietf.org/html/rfc6066">RFC 6066</a>
     * @see <a href="https://tools.ietf.org/html/rfc6961">RFC 6961</a>
     */
    @Override
    public List<byte[]> getStatusResponses() {
        if (peerCertificateOcspData == null) {
            return Collections.<byte[]>emptyList();
        }

        return Collections.singletonList(peerCertificateOcspData.clone());
    }

    /**
     * Returns the signed certificate timestamp (SCT) received from the peer. Returns a
     * copy of the internal array.
     *
     * @see <a href="https://tools.ietf.org/html/rfc6962">RFC 6962</a>
     */
    @Override
    public byte[] getPeerSignedCertificateTimestamp() {
        if (peerTlsSctData == null) {
            return null;
        }
        return peerTlsSctData.clone();
    }

    @Override
    public String getRequestedServerName() {
        synchronized (ssl) {
            return ssl.getRequestedServerName();
        }
    }

    @Override
    public void invalidate() {
        synchronized (ssl) {
            ssl.setTimeout(0L);
        }
    }

    @Override
    public boolean isValid() {
        synchronized (ssl) {
            long creationTimeMillis = ssl.getTime();
            long timeoutMillis = ssl.getTimeout();
            return (System.currentTimeMillis() - timeoutMillis) < creationTimeMillis;
        }
    }

    @Override
    public void putValue(String name, Object value) {
        throw new UnsupportedOperationException(
                "All calls to this method should be intercepted by ExternalSession.");
    }

    @Override
    public Object getValue(String name) {
        throw new UnsupportedOperationException(
                "All calls to this method should be intercepted by ExternalSession.");
    }

    @Override
    public void removeValue(String name) {
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
        checkPeerCertificatesPresent();
        return peerCertificates.clone();
    }

    @Override
    public Certificate[] getLocalCertificates() {
        // Local certificates never change, so set them locally as soon as they're available
        if (localCertificates == null) {
            synchronized (ssl) {
                localCertificates = ssl.getLocalCertificates();
            }
        }
        return localCertificates == null ? null : localCertificates.clone();
    }

    /**
     * Returns the certificate(s) of the peer in this SSL session
     * used in the handshaking phase of the connection.
     * Please notice hat this method is superseded by
     * <code>getPeerCertificates()</code>.
     * @return an array of X509 certificates (the peer's one first and then
     *         eventually that of the certification authority) or null if no
     *         certificate were used during the SSL connection.
     * @throws SSLPeerUnverifiedException if either a non-X.509 certificate
     *         was used (i.e. Kerberos certificates) or the peer could not
     *         be verified.
     */
    @Override
    public javax.security.cert.X509Certificate[] getPeerCertificateChain()
            throws SSLPeerUnverifiedException {
        checkPeerCertificatesPresent();
        // TODO(nathanmittler): Should we clone?
        javax.security.cert.X509Certificate[] result = peerCertificateChain;
        if (result == null) {
            // single-check idiom
            peerCertificateChain = result = SSLUtils.toCertificateChain(peerCertificates);
        }
        return result;
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        checkPeerCertificatesPresent();
        return peerCertificates[0].getSubjectX500Principal();
    }

    @Override
    public Principal getLocalPrincipal() {
        X509Certificate[] certs = (X509Certificate[]) getLocalCertificates();
        if (certs != null && certs.length > 0) {
            return certs[0].getSubjectX500Principal();
        } else {
            return null;
        }
    }

    @Override
    public String getCipherSuite() {
        // Always get the Cipher from the SSL directly since it may have changed during a
        // renegotiation.
        String cipher;
        synchronized (ssl) {
            cipher = ssl.getCipherSuite();
        }
        return cipher == null ? SSLNullSession.INVALID_CIPHER : cipher;
    }

    @Override
    public String getProtocol() {
        String protocol = this.protocol;
        if (protocol == null) {
            synchronized (ssl) {
                protocol = ssl.getVersion();
            }
            this.protocol = protocol;
        }
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
        String applicationProtocol = this.applicationProtocol;
        if (applicationProtocol == null) {
            synchronized (ssl) {
                applicationProtocol = SSLUtils.toProtocolString(ssl.getApplicationProtocol());
            }
            this.applicationProtocol = applicationProtocol;
        }
        return applicationProtocol;
    }

    /**
     * Configures the peer information once it has been received by the handshake.
     */
    void onPeerCertificatesReceived(
            String peerHost, int peerPort, X509Certificate[] peerCertificates) {
        configurePeer(peerHost, peerPort, peerCertificates);
    }

    private void configurePeer(String peerHost, int peerPort, X509Certificate[] peerCertificates) {
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.peerCertificates = peerCertificates;
        synchronized (ssl) {
            this.peerCertificateOcspData = ssl.getPeerCertificateOcspData();
            this.peerTlsSctData = ssl.getPeerTlsSctData();
        }
    }

    /**
     * Updates the cached peer certificate after the handshake has completed
     * (or entered False Start).
     */
    void onPeerCertificateAvailable(String peerHost, int peerPort) throws CertificateException {
        synchronized (ssl) {
            id = null;
            if (localCertificates == null) {
                this.localCertificates = ssl.getLocalCertificates();
            }
            if (this.peerCertificates == null) {
                // When resuming a session, the cert_verify_callback (which calls
                // onPeerCertificatesReceived) isn't called by BoringSSL during the handshake
                // because it presumes the certs were verified in the previous connection on that
                // session, leaving us without the peer certificates.  If that happens, fetch them
                // explicitly.
                configurePeer(peerHost, peerPort, ssl.getPeerCertificates());
            }
        }
    }

    /**
     * Throw SSLPeerUnverifiedException on null or empty peerCertificates array
     */
    private void checkPeerCertificatesPresent() throws SSLPeerUnverifiedException {
        if (peerCertificates == null || peerCertificates.length == 0) {
            throw new SSLPeerUnverifiedException("No peer certificates");
        }
    }
}
