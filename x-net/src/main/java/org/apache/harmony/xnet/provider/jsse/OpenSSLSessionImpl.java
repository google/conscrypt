/*
 * Copyright (C) 2007 The Android Open Source Project
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

package org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Vector;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLPermission;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.CertificateEncodingException;

import org.apache.harmony.luni.util.TwoKeyHashMap;
import org.apache.harmony.security.provider.cert.X509CertImpl;

/**
 * Implementation of the class OpenSSLSessionImpl
 * based on OpenSSL. The JNI native interface for some methods
 * of this this class are defined in the file:
 * org_apache_harmony_xnet_provider_jsse_OpenSSLSessionImpl.cpp
 */
public class OpenSSLSessionImpl implements SSLSession {

    long lastAccessedTime = 0;
    X509Certificate[] localCertificates;
    X509Certificate[] peerCertificates;

    private boolean isValid = true;
    private TwoKeyHashMap values = new TwoKeyHashMap();
    private javax.security.cert.X509Certificate[] peerCertificateChain;
    protected int session;
    private SSLParameters sslParameters;
    private String peerHost;
    private int peerPort;

    /**
     * Class constructor creates an SSL session context given the appropriate
     * SSL parameters.
     * @param sslParameters the SSL parameters like ciphers' suites etc.
     * @param ssl the Identifier for SSL session
     */
    protected OpenSSLSessionImpl(int session, SSLParameters sslParameters, String peerHost, int peerPort) {
        this.session = session;
        this.sslParameters = sslParameters;
        this.peerHost = peerHost;
        this.peerPort = peerPort;
    }

    /**
     * Returns the identifier of the actual OpenSSL session.
     */
    private native byte[] nativegetid();

    /**
     * Gets the identifier of the actual SSL session
     * @return array of sessions' identifiers.
     */
    public byte[] getId() {
        return nativegetid();
    }

    /**
     * Gets the creation time of the OpenSSL session.
     * @return the session's creation time in milli seconds since January
     * 1st, 1970
     */
    private native long nativegetcreationtime();

    /**
     * Gets the creation time of the SSL session.
     * @return the session's creation time in milli seconds since 12.00 PM,
     * January 1st, 1970
     */
    public long getCreationTime(){
        return nativegetcreationtime();
    }

    /**
     * Gives the last time this concrete SSL session was accessed. Accessing
     * here is to mean that a new connection with the same SSL context data was
     * established.
     *
     * @return the session's accessing time in milli seconds since 12.00 PM,
     * January 1st, 1970
     */
    public long getLastAccessedTime() {
        if (lastAccessedTime == 0)
            return nativegetcreationtime();
        else
            return lastAccessedTime;
    }

    /**
     * Gives the largest buffer size for the application's data bound to this
     * concrete SSL session.
     * @return the largest buffer size
     */
    public int getApplicationBufferSize() {
        return SSLRecordProtocol.MAX_DATA_LENGTH;
    }

    /**
     * Gives the largest SSL/TLS packet size one can expect for this concrete
     * SSL session.
     * @return the largest packet size
     */
    public int getPacketBufferSize() {
        return SSLRecordProtocol.MAX_SSL_PACKET_SIZE;
    }

    /**
     * Gives the principal (subject) of this concrete SSL session used in the
     * handshaking phase of the connection.
     * @return a X509 certificate or null if no principal was defined
     */
    public Principal getLocalPrincipal() {
        if (localCertificates != null && localCertificates.length > 0) {
            return localCertificates[0].getSubjectX500Principal();
        } else {
            return null;
        }
    }

    /**
     * Gives the certificate(s) of the principal (subject) of this concrete SSL
     * session used in the handshaking phase of the connection. The OpenSSL
     * native method supports only RSA certificates.
     * @return an array of certificates (the local one first and then eventually
     *         that of the certification authority) or null if no certificate
     *         were used during the handshaking phase.
     */
    public Certificate[] getLocalCertificates() {
        X509Certificate[] localCertificates = null;
        // This implementation only supports RSA certificates.
        String alias = sslParameters.getKeyManager().chooseClientAlias(new String[] { "RSA" }, null, null);
        if (alias != null) {
            localCertificates = sslParameters.getKeyManager().getCertificateChain(alias);
        }
        return localCertificates;
    }

    /**
     * Returns the X509 certificates of the peer in the PEM format.
     */
    private native byte[][] nativegetpeercertificates();

    /**
     * Gives the certificate(s) of the peer in this SSL session
     * used in the handshaking phase of the connection.
     * Please notice hat this method is superseded by
     * <code>getPeerCertificates()</code>.
     * @return an array of X509 certificates (the peer's one first and then
     *         eventually that of the certification authority) or null if no
     *         certificate were used during the SSL connection.
     * @throws <code>SSLPeerUnverifiedcertificateException</code> if either a
     *         not X509 certificate was used (i.e. Kerberos certificates) or the
     *         peer could not be verified.
     */
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        if (peerCertificateChain == null) {
            try {
                byte[][] bytes = nativegetpeercertificates();
                if (bytes == null) throw new SSLPeerUnverifiedException("No certificate available");

                peerCertificateChain = new javax.security.cert.X509Certificate[bytes.length];

                for(int i = 0; i < bytes.length; i++) {
                    peerCertificateChain[i] = javax.security.cert.X509Certificate.getInstance(bytes[i]);
                }

                return peerCertificateChain;
            } catch (javax.security.cert.CertificateException e) {
                throw new SSLPeerUnverifiedException(e.getMessage());
            }
        } else {
            return peerCertificateChain;
        }
    }

    /**
     * Gives the identitity of the peer in this SSL session
     * determined via certificate(s).
     * @return an array of X509 certificates (the peer's one first and then
     *         eventually that of the certification authority) or null if no
     *         certificate were used during the SSL connection.
     * @throws <code>SSLPeerUnverifiedException</code> if either a not X509
     *         certificate was used (i.e. Kerberos certificates) or the peer
     *         could not be verified.
     */
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        if (peerCertificates == null) {
            if (peerCertificateChain == null) getPeerCertificateChain();
            try {
                if (peerCertificateChain.length == 0) return new X509Certificate[]{};

                peerCertificates = new X509CertImpl[peerCertificateChain.length];
                for(int i = 0; i < peerCertificates.length; i++) {
                    peerCertificates[i] = new X509CertImpl(peerCertificateChain[i].getEncoded());
                }
                return peerCertificates;
            } catch (SSLPeerUnverifiedException e) {
                return new X509Certificate[]{};
            } catch (IOException e) {
                return new X509Certificate[]{};
            } catch (CertificateEncodingException e) {
                return new X509Certificate[]{};
            }
        } else {
            return peerCertificates;
        }
    }

    /**
     * The identity of the principal that was used by the peer during the SSL
     * handshake phase is returned by this method.
     * @return a X500Principal of the last certificate for X509-based
     *         cipher suites. If no principal was sent, then null is returned.
     * @throws <code>SSLPeerUnverifiedException</code> if either a not X509
     *         certificate was used (i.e. Kerberos certificates) or the
     *         peer does not exist.
     *
     */
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        if (peerCertificates == null) {
            throw new SSLPeerUnverifiedException("No peer certificate");
        }
        return peerCertificates[0].getSubjectX500Principal();
    }

    /**
     * Returns via OpenSSL call the actual peer host name.
     */
    private native String nativegetpeerhost();

    /**
     * The peer's host name used in this SSL session is returned. It is the host
     * name of the client for the server; and that of the server for the client.
     * It is not a reliable way to get a fully qualified host name: it is mainly
     * used internally to implement links for a temporary cache of SSL sessions.
     *
     * @return the host name of the peer, or null if no information is
     *         available.
     *
     */
    public String getPeerHost() {
        return peerHost;
        //return nativegetpeerhost();
    }

    /**
     * Returns via OpenSSL call the actual peer port number.
     */
    private native String nativegetpeerport();

    /**
     * Gives the peer's port number for the actual SSL session. It is the port
     * number of the client for the server; and that of the server for the
     * client. It is not a reliable way to get a peer's port number: it is
     * mainly used internally to implement links for a temporary cache of SSL
     * sessions.
     * @return the peer's port number, or -1 if no one is available.
     *
     */
    public int getPeerPort() {
        return peerPort;
        //return Integer.parseInt(nativegetpeerport());
    }

    /**
     * Returns via OpenSSL call the actual cipher suite in use.
     */
    private native String nativegetciphersuite();

    /**
     * Gives back a string identifier of the crypto tools used in the actual SSL
     * session. For example AES_256_WITH_MD5.
     *
     * @return an identifier for all the cryptographic algorithms used in the
     *         actual SSL session.
     */
    public String getCipherSuite() {
        return nativegetciphersuite();
    }

    /**
     * Returns via OpenSSL call the actual version of the SSL protocol.
     */
    private native String nativegetprotocol();

    /**
     * Gives back the standard version name of the SSL protocol used in all
     * connections pertaining to this SSL session.
     *
     * @return the standard version name of the SSL protocol used in all
     *         connections pertaining to this SSL session.
     *
     */
    public String getProtocol() {
        return nativegetprotocol();
    }

    /**
     * Gives back the context to which the actual SSL session is bound. A SSL
     * context consists of (1) a possible delegate, (2) a provider and (3) a
     * protocol. If the security manager is activated and one tries to access
     * the SSL context an exception may be thrown if a
     * <code>SSLPermission("getSSLSessionContext")</code>
     * permission is not set.
     * @return the SSL context used for this session, or null if it is
     * unavailable.
     */
    public SSLSessionContext getSessionContext() {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SSLPermission("getSSLSessionContext"));
        }
        return sslParameters.getClientSessionContext();
    }

    /**
     * Gives back a boolean flag signaling whether a SSL session is valid and
     * available
     * for resuming or joining or not.
     * @return true if this session may be resumed.
     */
    public boolean isValid() {
        SSLSessionContextImpl context = sslParameters.getClientSessionContext();
        if (isValid
                && context != null
                && context.getSessionTimeout() != 0
                && lastAccessedTime + context.getSessionTimeout() > System
                        .currentTimeMillis()) {
            isValid = false;
        }
        return isValid;
    }

    /**
     * It invalidates a SSL session forbidding any resumption.
     */
    public void invalidate() {
        isValid = false;
    }

    /**
     * Gives back the object which is bound to the the input parameter name.
     * This name is a sort of link to the data of the SSL session's application
     * layer, if any exists. The search for this link is monitored, as a matter
     * of security, by the full machinery of the <code>AccessController</code>
     * class.
     *
     * @param <code>String name</code> the name of the binding to find.
     * @return the value bound to that name, or null if the binding does not
     *         exist.
     * @throws <code>IllegalArgumentException</code> if the argument is null.
     */
    public Object getValue(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Parameter is null");
        }
        return values.get(name, AccessController.getContext());
    }

    /**
     * Gives back an array with the names (sort of links) of all the data
     * objects of the application layer bound into the SSL session. The search
     * for this link is monitored, as a matter of security, by the full
     * machinery of the <code>AccessController</code> class.
     *
     * @return a non-null (possibly empty) array of names of the data objects
     *         bound to this SSL session.
     */
    public String[] getValueNames() {
        Vector v = new Vector();
        AccessControlContext current = AccessController.getContext();
        AccessControlContext cont;
        for (Iterator it = values.entrySet().iterator(); it.hasNext();) {
            TwoKeyHashMap.Entry entry = (TwoKeyHashMap.Entry) it.next();
            cont = (AccessControlContext) entry.getKey2();
            if ((current == null && cont == null)
                    || (current != null && current.equals(cont))) {
                v.add(entry.getKey1());
            }
        }
        return (String[]) v.toArray(new String[0]);
    }

    /**
     * A link (name) with the specified value object of the SSL session's
     * application layer data is created or replaced. If the new (or existing)
     * value object implements the <code>SSLSessionBindingListener</code>
     * interface, that object will be notified in due course. These links-to
     * -data bounds are monitored, as a matter of security, by the full
     * machinery of the <code>AccessController</code> class.
     *
     * @param <code>String name</code> the name of the link (no null are
     *            accepted!)
     * @param <code>Object value</code> data object that shall be bound to
     *            name.
     * @throws <code>IllegalArgumentException</code> if one or both
     *             argument(s) is null.
     */
    public void putValue(String name, Object value) {
        if (name == null || value == null) {
            throw new IllegalArgumentException("Parameter is null");
        }
        Object old = values.put(name, AccessController.getContext(), value);
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value)
                    .valueBound(new SSLSessionBindingEvent(this, name));
        }
        if (old != null && old instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) old)
                    .valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }

    /**
     * Removes a link (name) with the specified value object of the SSL
     * session's application layer data. These links-to -data bounds are
     * monitored, as a matter of security, by the full machinery of the
     * <code>AccessController</code> class.
     *
     * @param <code>String name</code> the name of the link (no null are
     *            accepted!)
     * @throws <code>IllegalArgumentException</code> if the argument is null.
     */
    public void removeValue(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Parameter is null");
        }
        values.remove(name, AccessController.getContext());
    }

    private native void nativefree(int session);

    /**
     * Frees the OpenSSL session in the memory.
     */
    protected void finalize() {
        nativefree(session);
    }
}
