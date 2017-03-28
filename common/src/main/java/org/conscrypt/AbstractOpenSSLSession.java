/*
 * Copyright 2016 The Android Open Source Project
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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.CertificateException;

/**
 * Extends the base SSLSession with some methods used exclusively in Conscrypt.
 */
abstract class AbstractOpenSSLSession implements SSLSession {
    private final Map<String, Object> values = new HashMap<String, Object>();

    private volatile javax.security.cert.X509Certificate[] peerCertificateChain;

    private AbstractSessionContext sessionContext;

    private boolean isValid = true;

    /**
     * Class constructor creates an SSL session context given the appropriate
     * session context.
     */
    AbstractOpenSSLSession(AbstractSessionContext sessionContext) {
        this.sessionContext = sessionContext;
    }

    protected abstract X509Certificate[] getX509PeerCertificates()
            throws SSLPeerUnverifiedException;

    protected abstract X509Certificate[] getX509LocalCertificates();

    /**
     * Throw SSLPeerUnverifiedException on null or empty peerCertificates array
     */
    private void checkPeerCertificatesPresent() throws SSLPeerUnverifiedException {
        X509Certificate[] peerCertificates = getX509PeerCertificates();
        if (peerCertificates == null || peerCertificates.length == 0) {
            throw new SSLPeerUnverifiedException("No peer certificates");
        }
    }

    /**
     * Return the identity of the peer in this SSL session
     * determined via certificate(s).
     * @return an array of X509 certificates (the peer's one first and then
     *         eventually that of the certification authority) or null if no
     *         certificate were used during the SSL connection.
     * @throws SSLPeerUnverifiedException if either a non-X.509 certificate
     *         was used (i.e. Kerberos certificates) or the peer could not
     *         be verified.
     */
    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        return getX509PeerCertificates();
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
        javax.security.cert.X509Certificate[] result = peerCertificateChain;
        if (result == null) {
            // single-check idiom
            peerCertificateChain = result = createPeerCertificateChain();
        }
        return result;
    }

    /**
     * Provide a value to initialize the volatile peerCertificateChain
     * field based on the native SSL_SESSION
     */
    private javax.security.cert.X509Certificate[] createPeerCertificateChain()
            throws SSLPeerUnverifiedException {
        X509Certificate[] peerCertificates = getX509PeerCertificates();
        try {
            javax.security.cert.X509Certificate[] chain =
                    new javax.security.cert.X509Certificate[peerCertificates.length];

            for (int i = 0; i < peerCertificates.length; i++) {
                byte[] encoded = peerCertificates[i].getEncoded();
                chain[i] = javax.security.cert.X509Certificate.getInstance(encoded);
            }
            return chain;
        } catch (CertificateEncodingException e) {
            SSLPeerUnverifiedException exception = new SSLPeerUnverifiedException(e.getMessage());
            exception.initCause(exception);
            throw exception;
        } catch (CertificateException e) {
            SSLPeerUnverifiedException exception = new SSLPeerUnverifiedException(e.getMessage());
            exception.initCause(exception);
            throw exception;
        }
    }

    /**
     * The identity of the principal that was used by the peer during the SSL
     * handshake phase is returned by this method.
     * @return a X500Principal of the last certificate for X509-based
     *         cipher suites.
     * @throws SSLPeerUnverifiedException if either a non-X.509 certificate
     *         was used (i.e. Kerberos certificates) or the peer does not exist.
     *
     */
    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        checkPeerCertificatesPresent();
        return getX509PeerCertificates()[0].getSubjectX500Principal();
    }

    /**
     * Returns the principal (subject) of this concrete SSL session used in the
     * handshaking phase of the connection.
     * @return a X509 certificate or null if no principal was defined
     */
    @Override
    public Principal getLocalPrincipal() {
        X509Certificate[] localCertificates = getX509LocalCertificates();
        if (localCertificates != null && localCertificates.length > 0) {
            return localCertificates[0].getSubjectX500Principal();
        } else {
            return null;
        }
    }

    /**
     * Returns the certificate(s) of the principal (subject) of this concrete SSL
     * session used in the handshaking phase of the connection. The OpenSSL
     * native method supports only RSA certificates.
     * @return an array of certificates (the local one first and then eventually
     *         that of the certification authority) or null if no certificate
     *         were used during the handshaking phase.
     */
    @Override
    public Certificate[] getLocalCertificates() {
        return getX509LocalCertificates();
    }

    /**
     * Returns the largest buffer size for the application's data bound to this
     * concrete SSL session.
     * @return the largest buffer size
     */
    @Override
    public int getApplicationBufferSize() {
        return NativeConstants.SSL3_RT_MAX_PLAIN_LENGTH;
    }

    /**
     * Returns the largest SSL/TLS packet size one can expect for this concrete
     * SSL session.
     * @return the largest packet size
     */
    @Override
    public int getPacketBufferSize() {
        return NativeConstants.SSL3_RT_MAX_PACKET_SIZE;
    }

    /**
     * Returns the object which is bound to the the input parameter name.
     * This name is a sort of link to the data of the SSL session's application
     * layer, if any exists.
     *
     * @param name the name of the binding to find.
     * @return the value bound to that name, or null if the binding does not
     *         exist.
     * @throws IllegalArgumentException if the argument is null.
     */
    @Override
    public Object getValue(String name) {
        if (name == null) {
            throw new IllegalArgumentException("name == null");
        }
        return values.get(name);
    }

    /**
     * Returns an array with the names (sort of links) of all the data
     * objects of the application layer bound into the SSL session.
     *
     * @return a non-null (possibly empty) array of names of the data objects
     *         bound to this SSL session.
     */
    @Override
    public String[] getValueNames() {
        return values.keySet().toArray(new String[values.size()]);
    }

    /**
     * A link (name) with the specified value object of the SSL session's
     * application layer data is created or replaced. If the new (or existing)
     * value object implements the <code>SSLSessionBindingListener</code>
     * interface, that object will be notified in due course.
     *
     * @param name the name of the link (no null are
     *            accepted!)
     * @param value data object that shall be bound to
     *            name.
     * @throws IllegalArgumentException if one or both argument(s) is null.
     */
    @Override
    public void putValue(String name, Object value) {
        if (name == null || value == null) {
            throw new IllegalArgumentException("name == null || value == null");
        }
        Object old = values.put(name, value);
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(this, name));
        }
        if (old instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) old).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }

    /**
     * Removes a link (name) with the specified value object of the SSL
     * session's application layer data.
     *
     * <p>If the value object implements the <code>SSLSessionBindingListener</code>
     * interface, the object will receive a <code>valueUnbound</code> notification.
     *
     * @param name the name of the link (no null are
     *            accepted!)
     * @throws IllegalArgumentException if the argument is null.
     */
    @Override
    public void removeValue(String name) {
        if (name == null) {
            throw new IllegalArgumentException("name == null");
        }
        Object old = values.remove(name);
        if (old instanceof SSLSessionBindingListener) {
            SSLSessionBindingListener listener = (SSLSessionBindingListener) old;
            listener.valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }

    /**
     * Returns the context to which the actual SSL session is bound. A SSL
     * context consists of (1) a possible delegate, (2) a provider and (3) a
     * protocol.
     * @return the SSL context used for this session, or null if it is
     * unavailable.
     */
    @Override
    public SSLSessionContext getSessionContext() {
        return sessionContext;
    }

    /**
     * Returns a boolean flag signaling whether a SSL session is valid
     * and available for resuming or joining or not.
     *
     * @return true if this session may be resumed.
     */
    @Override
    public boolean isValid() {
        if (!isValid) {
            return false;
        }
        // The session has't yet been invalidated -- check whether it timed out.

        SSLSessionContext context = getSessionContext();
        if (context == null) {
            // Session not associated with a context -- no way to tell what its timeout should be.
            return true;
        }

        int timeoutSeconds = context.getSessionTimeout();
        if (timeoutSeconds == 0) {
            // Infinite timeout -- session still valid
            return true;
        }

        long creationTimestampMillis = getCreationTime();
        long ageSeconds = (System.currentTimeMillis() - creationTimestampMillis) / 1000;
        // NOTE: The age might be negative if something was/is wrong with the system clock. We time
        // out such sessions to be safe.
        if ((ageSeconds >= timeoutSeconds) || (ageSeconds < 0)) {
            // Session timed out -- no longer valid
            isValid = false;
            return false;
        }

        // Session still valid
        return true;
    }

    /**
     * It invalidates a SSL session forbidding any resumption.
     */
    @Override
    public void invalidate() {
        isValid = false;
        sessionContext = null;
    }

    /**
     * Returns the name requested by the SNI extension.
     */
    public abstract String getRequestedServerName();

    /**
     * Returns the OCSP stapled response.
     */
    public abstract List<byte[]> getStatusResponses();

    /**
     * Returns the TLS Stapled Certificate Transparency data.
     */
    public abstract byte[] getTlsSctData();

    /**
     * Sets the last accessed time for this session in milliseconds since Jan 1,
     * 1970 00:00:00 UTC.
     */
    public abstract void setLastAccessedTime(long accessTimeMillis);

    /**
     * Indicates that this session's ID may have changed and should be
     * re-cached.
     */
    abstract void resetId();
}
