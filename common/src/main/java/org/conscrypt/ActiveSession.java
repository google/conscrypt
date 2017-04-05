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
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;

/**
 * A session that is dedicated a single connection and operates directly on the underlying
 * {@code SSL}.
 */
final class ActiveSession implements SSLSession {
    private final SslWrapper ssl;
    private AbstractSessionContext sessionContext;
    private byte[] id;
    private long creationTime;
    private String cipherSuite;
    private String protocol;
    private String peerHost;
    private int peerPort = -1;
    private long lastAccessedTime = 0;
    private volatile javax.security.cert.X509Certificate[] peerCertificateChain;
    private X509Certificate[] localCertificates;
    private X509Certificate[] peerCertificates;
    private byte[] peerCertificateOcspData;
    private byte[] peerTlsSctData;

    // lazy init for memory reasons
    private Map<String, Object> values;

    ActiveSession(SslWrapper ssl, AbstractSessionContext sessionContext) {
        this.ssl = checkNotNull(ssl, "ssl");
        this.sessionContext = checkNotNull(sessionContext, "sessionContext");
    }

    @Override
    public byte[] getId() {
        if (id == null) {
            id = ssl.getSessionId();
        }
        return id != null ? id.clone() : EmptyArray.BYTE;
    }

    /**
     * Indicates that this session's ID may have changed and should be re-cached.
     */
    void resetId() {
        id = null;
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return isValid() ? sessionContext : null;
    }

    @Override
    public long getCreationTime() {
        if (creationTime == 0) {
            creationTime = ssl.getTime();
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
    /* @Override */
    @SuppressWarnings("MissingOverride") // For Pre-Java9 compatibility.
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
    byte[] getPeerSignedCertificateTimestamp() {
        if (peerTlsSctData == null) {
            return null;
        }
        return peerTlsSctData.clone();
    }

    String getRequestedServerName() {
        return ssl.getRequestedServerName();
    }

    @Override
    public void invalidate() {
        ssl.setTimeout(0L);
    }

    @Override
    public boolean isValid() {
        long creationTimeMillis = ssl.getTime();
        long timeoutMillis = ssl.getTimeout();
        return (System.currentTimeMillis() - timeoutMillis) < creationTimeMillis;
    }

    @Override
    public void putValue(String name, Object value) {
        if (name == null) {
            throw new NullPointerException("name");
        }
        if (value == null) {
            throw new NullPointerException("value");
        }
        Map<String, Object> values = this.values;
        if (values == null) {
            // Use size of 2 to keep the memory overhead small
            values = this.values = new HashMap<String, Object>(2);
        }
        Object old = values.put(name, value);
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(this, name));
        }
        if (old instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) old).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
        notifyUnbound(old, name);
    }

    @Override
    public Object getValue(String name) {
        if (name == null) {
            throw new NullPointerException("name");
        }
        if (values == null) {
            return null;
        }
        return values.get(name);
    }

    @Override
    public void removeValue(String name) {
        if (name == null) {
            throw new NullPointerException("name");
        }
        Map<String, Object> values = this.values;
        if (values == null) {
            return;
        }
        Object old = values.remove(name);
        notifyUnbound(old, name);
    }

    @Override
    public String[] getValueNames() {
        Map<String, Object> values = this.values;
        if (values == null || values.isEmpty()) {
            return EmptyArray.STRING;
        }
        return values.keySet().toArray(new String[values.size()]);
    }

    @Override
    public X509Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        checkPeerCertificatesPresent();
        return peerCertificates.clone();
    }

    @Override
    public Certificate[] getLocalCertificates() {
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
        if (localCertificates != null && localCertificates.length > 0) {
            return localCertificates[0].getSubjectX500Principal();
        } else {
            return null;
        }
    }

    @Override
    public String getCipherSuite() {
        if (cipherSuite == null) {
            cipherSuite = ssl.getCipherSuite();
        }
        return cipherSuite;
    }

    @Override
    public String getProtocol() {
        String protocol = this.protocol;
        if (protocol == null) {
            protocol = ssl.getVersion();
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

    /**
     * Configures the peer information once it has been received by the handshake.
     */
    void onPeerCertificatesReceived(
            String peerHost, int peerPort, OpenSSLX509Certificate[] peerCertificates) {
        configurePeer(peerHost, peerPort, peerCertificates);
    }

    /**
     * Configures the peer and local state from a newly created BoringSSL session.
     */
    void onSessionEstablished(String peerHost, int peerPort) {
        id = null;
        this.localCertificates = ssl.getLocalCertificates();
        configurePeer(peerHost, peerPort, ssl.getPeerCertificates());
    }

    private void configurePeer(
            String peerHost, int peerPort, OpenSSLX509Certificate[] peerCertificates) {
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.peerCertificates = peerCertificates;
        this.peerCertificateOcspData = ssl.getPeerCertificateOcspData();
        this.peerTlsSctData = ssl.getPeerTlsSctData();
    }

    private X509Certificate[] getX509PeerCertificates() throws SSLPeerUnverifiedException {
        if (peerCertificates == null || peerCertificates.length == 0) {
            throw new SSLPeerUnverifiedException("No peer certificates");
        }
        return peerCertificates;
    }

    /**
     * Throw SSLPeerUnverifiedException on null or empty peerCertificates array
     */
    private void checkPeerCertificatesPresent() throws SSLPeerUnverifiedException {
        if (peerCertificates == null || peerCertificates.length == 0) {
            throw new SSLPeerUnverifiedException("No peer certificates");
        }
    }

    private void notifyUnbound(Object value, String name) {
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value)
                    .valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }
}
