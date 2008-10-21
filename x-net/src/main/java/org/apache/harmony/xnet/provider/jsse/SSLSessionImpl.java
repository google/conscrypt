/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/**
 * @author Boris Kuznetsov
 * @version $Revision$
 */

package org.apache.harmony.xnet.provider.jsse;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Vector;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLPermission;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;

import org.apache.harmony.luni.util.TwoKeyHashMap;
import org.apache.harmony.xnet.provider.jsse.SSLSessionContextImpl;

/**
 * 
 * SSLSession implementation
 *
 * @see javax.net.ssl.SSLSession
 */
public class SSLSessionImpl implements SSLSession {

    /**
     * Session object reporting an invalid cipher suite of 
     * "SSL_NULL_WITH_NULL_NULL"
     */
    public static final SSLSessionImpl NULL_SESSION = new SSLSessionImpl(null);

    private long creationTime;
    private boolean isValid = true;
    private TwoKeyHashMap values = new TwoKeyHashMap();

    /**
     * ID of the session
     */
    byte[] id;

    /**
     * Last time the session was accessed 
     */
    long lastAccessedTime;

    /**
     * Protocol used in the session
     */
    ProtocolVersion protocol;

    /**
     * CipherSuite used in the session
     */
    CipherSuite cipherSuite;

    /**
     * Context of the session
     */
    SSLSessionContextImpl context;


    /**
     * certificates were sent to the peer 
     */
    X509Certificate[] localCertificates;

    /**
     * Peer certificates
     */
    X509Certificate[] peerCertificates;

    /**
     * Peer host name 
     */
    String peerHost;

    /**
     * Peer port number
     */
    int peerPort = -1;

    /**
     * Master secret
     */
    byte[] master_secret;


    /**
     * clientRandom
     */
    byte[] clientRandom;

    /**
     * serverRandom
     */
    byte[] serverRandom;

    /**
     * True if this entity is considered the server
     */
    boolean isServer = false;

    /**
     * Creates SSLSession implementation
     * @param cipher_suite
     * @param sr
     */
    public SSLSessionImpl(CipherSuite cipher_suite, SecureRandom sr) {
        creationTime = System.currentTimeMillis();
        lastAccessedTime = creationTime;
        if (cipher_suite == null) {
            this.cipherSuite = CipherSuite.TLS_NULL_WITH_NULL_NULL;
            id = new byte[0];
            isServer = false;
        } else {
            this.cipherSuite = cipher_suite;
            id = new byte[32];
            sr.nextBytes(id);
            long time = new java.util.Date().getTime() / 1000;
            id[28] = (byte) ((time & 0xFF000000) >>> 24);
            id[29] = (byte) ((time & 0xFF0000) >>> 16);
            id[30] = (byte) ((time & 0xFF00) >>> 8);
            id[31] = (byte) (time & 0xFF);
            isServer = true;
        }

    }

    /**
     * Creates SSLSession implementation
     * @param sr
     */
    public SSLSessionImpl(SecureRandom sr) {
        this(null, sr);
    }

    private SSLSessionImpl() {
    }

    /**
     * @see javax.net.ssl.SSLSession#getApplicationBufferSize()
     */
    public int getApplicationBufferSize() {
        return SSLRecordProtocol.MAX_DATA_LENGTH;
    }

    /**
     * @see javax.net.ssl.SSLSession#getCipherSuite()
     */
    public String getCipherSuite() {
        return cipherSuite.getName();
    }

    /**
     * @see javax.net.ssl.SSLSession#getCreationTime()
     */
    public long getCreationTime() {
        return creationTime;
    }

    /**
     * @see javax.net.ssl.SSLSession#getId()
     */
    public byte[] getId() {
        return id;
    }

    /**
     * @see javax.net.ssl.SSLSession#getLastAccessedTime()
     */
    public long getLastAccessedTime() {
        return lastAccessedTime;
    }

    /**
     * @see javax.net.ssl.SSLSession#getLocalCertificates()
     */
    public Certificate[] getLocalCertificates() {
        return localCertificates;
    }

    /**
     * @see javax.net.ssl.SSLSession#getLocalPrincipal()
     */
    public Principal getLocalPrincipal() {
        if (localCertificates != null && localCertificates.length > 0) {
            return localCertificates[0].getSubjectX500Principal();
        } else {
            return null;
        }
    }

    /**
     * @see javax.net.ssl.SSLSession#getPacketBufferSize()
     */
    public int getPacketBufferSize() {
        return SSLRecordProtocol.MAX_SSL_PACKET_SIZE;
    }

    /**
     * @see javax.net.ssl.SSLSession#getPeerCertificateChain()
     */
    public javax.security.cert.X509Certificate[] getPeerCertificateChain()
            throws SSLPeerUnverifiedException {
        if (peerCertificates == null) {
            throw new SSLPeerUnverifiedException("No peer certificate");
        }
        javax.security.cert.X509Certificate[] certs = new javax.security.cert.X509Certificate[peerCertificates.length];
        for (int i = 0; i < certs.length; i++) {
            try {
                certs[i] = javax.security.cert.X509Certificate
                        .getInstance(peerCertificates[i].getEncoded());
            } catch (javax.security.cert.CertificateException e) {
            } catch (CertificateEncodingException e) {
            }
        }
        return certs;
    }

    /**
     * @see javax.net.ssl.SSLSession#getPeerCertificates()
     */
    public Certificate[] getPeerCertificates()
            throws SSLPeerUnverifiedException {
        if (peerCertificates == null) {
            throw new SSLPeerUnverifiedException("No peer certificate");
        }
        return peerCertificates;
    }

    /**
     * @see javax.net.ssl.SSLSession#getPeerHost()
     */
    public String getPeerHost() {
        return peerHost;
    }

    /**
     * @see javax.net.ssl.SSLSession#getPeerPort()
     */
    public int getPeerPort() {
        return peerPort;
    }

    /**
     * @see javax.net.ssl.SSLSession#getPeerPrincipal()
     */
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        if (peerCertificates == null) {
            throw new SSLPeerUnverifiedException("No peer certificate");
        }
        return peerCertificates[0].getSubjectX500Principal();
    }

    /**
     * @see javax.net.ssl.SSLSession#getProtocol()
     */
    public String getProtocol() {
        return protocol.name;
    }

    /**
     * @see javax.net.ssl.SSLSession#getSessionContext()
     */
    public SSLSessionContext getSessionContext() {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SSLPermission("getSSLSessionContext"));
        }
        return context;
    }

    /**
     * @see javax.net.ssl.SSLSession#getValue(String name)
     */
    public Object getValue(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Parameter is null");
        }
        return values.get(name, AccessController.getContext());
    }

    /**
     * @see javax.net.ssl.SSLSession#getValueNames()
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
     * @see javax.net.ssl.SSLSession#invalidate()
     */
    public void invalidate() {
        isValid = false;
    }

    /**
     * @see javax.net.ssl.SSLSession#isValid()
     */
    public boolean isValid() {
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
     * @see javax.net.ssl.SSLSession#putValue(String name, Object value)
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
     * @see javax.net.ssl.SSLSession#removeValue(String name)
     */
    public void removeValue(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Parameter is null");
        }
        values.remove(name, AccessController.getContext());

    }

    public Object clone() {
        SSLSessionImpl ses = new SSLSessionImpl();
        ses.id = this.id;
        ses.creationTime = this.creationTime;
        ses.lastAccessedTime = this.lastAccessedTime;
        ses.isValid = this.isValid;
        ses.cipherSuite = this.cipherSuite;
        ses.localCertificates = this.localCertificates;
        ses.peerCertificates = this.peerCertificates;
        ses.master_secret = this.master_secret;
        ses.clientRandom = this.clientRandom;
        ses.serverRandom = this.serverRandom;
        ses.peerHost = this.peerHost;
        ses.peerPort = this.peerPort;
        ses.isServer = this.isServer;
        ses.context = this.context;
        ses.protocol = this.protocol;
        ses.values = this.values;
        return ses;
    }


    /**
     * Sets the address of the peer
     * @param peerHost
     * @param peerPort
     */
    void setPeer(String peerHost, int peerPort) {
        this.peerHost = peerHost;
        this.peerPort = peerPort;
    }
}
