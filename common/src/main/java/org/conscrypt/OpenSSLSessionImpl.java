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

package org.conscrypt;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;

/**
 * Implementation of the class OpenSSLSessionImpl
 * based on BoringSSL.
 *
 * @hide
 */
@Internal
public class OpenSSLSessionImpl extends AbstractOpenSSLSession {
    private long creationTime = 0;
    long lastAccessedTime = 0;
    final X509Certificate[] localCertificates;
    final X509Certificate[] peerCertificates;

    private final Map<String, Object> values = new HashMap<String, Object>();
    private byte[] peerCertificateOcspData;
    private byte[] peerTlsSctData;
    protected long sslSessionNativePointer;
    private String peerHost;
    private int peerPort = -1;
    private String cipherSuite;
    private String protocol;
    private byte[] id;

    /**
     * Class constructor creates an SSL session context given the appropriate
     * SSL parameters.
     */
    protected OpenSSLSessionImpl(long sslSessionNativePointer, X509Certificate[] localCertificates,
            X509Certificate[] peerCertificates, byte[] peerCertificateOcspData,
            byte[] peerTlsSctData, String peerHost, int peerPort,
            AbstractSessionContext sessionContext) {
        super(sessionContext);
        this.sslSessionNativePointer = sslSessionNativePointer;
        this.localCertificates = localCertificates;
        this.peerCertificates = peerCertificates;
        this.peerCertificateOcspData = peerCertificateOcspData;
        this.peerTlsSctData = peerTlsSctData;
        this.peerHost = peerHost;
        this.peerPort = peerPort;
    }

    /**
     * Constructs a session from a byte[] containing an SSL session serialized with DER encoding.
     * This allows loading of a previously saved OpenSSLSessionImpl.
     *
     * @throws IOException if the serialized session data can not be parsed
     */
    OpenSSLSessionImpl(byte[] derData, String peerHost, int peerPort,
            X509Certificate[] peerCertificates, byte[] peerCertificateOcspData,
            byte[] peerTlsSctData, AbstractSessionContext sessionContext)
            throws IOException {
        this(NativeCrypto.d2i_SSL_SESSION(derData), null, peerCertificates,
                peerCertificateOcspData, peerTlsSctData, peerHost, peerPort, sessionContext);
    }

    /**
     * Gets the identifier of the actual SSL session
     * @return array of sessions' identifiers.
     */
    @Override
    public byte[] getId() {
        if (id == null) {
            resetId();
        }
        return id;
    }

    /**
     * Reset the id field to the current value found in the native
     * SSL_SESSION. It can change during the lifetime of the session
     * because while a session is created during initial handshake,
     * with handshake_cutthrough, the SSL_do_handshake may return
     * before we have read the session ticket from the server side and
     * therefore have computed no id based on the SHA of the ticket.
     */
    @Override
    void resetId() {
        id = NativeCrypto.SSL_SESSION_session_id(sslSessionNativePointer);
    }

    /**
     * Get the session object in DER format. This allows saving the session
     * data or sharing it with other processes.
     */
    public byte[] getEncoded() {
        return NativeCrypto.i2d_SSL_SESSION(sslSessionNativePointer);
    }

    /**
     * Gets the creation time of the SSL session.
     * @return the session's creation time in milliseconds since the epoch
     */
    @Override
    public long getCreationTime() {
        if (creationTime == 0) {
            creationTime = NativeCrypto.SSL_SESSION_get_time(sslSessionNativePointer);
        }
        return creationTime;
    }

    /**
     * Returns the last time this concrete SSL session was accessed. Accessing
     * here is to mean that a new connection with the same SSL context data was
     * established.
     *
     * @return the session's last access time in milliseconds since the epoch
     */
    @Override
    public long getLastAccessedTime() {
        return (lastAccessedTime == 0) ? getCreationTime() : lastAccessedTime;
    }

    @Override
    public void setLastAccessedTime(long accessTimeMillis) {
        lastAccessedTime = accessTimeMillis;
    }

    @Override
    protected X509Certificate[] getX509LocalCertificates() {
        return localCertificates;
    }

    @Override
    protected X509Certificate[] getX509PeerCertificates() throws SSLPeerUnverifiedException {
        if (peerCertificates == null || peerCertificates.length == 0) {
            throw new SSLPeerUnverifiedException("No peer certificates");
        }
        return peerCertificates;
    }

    /**
     * The peer's host name used in this SSL session is returned. It is the host
     * name of the client for the server; and that of the server for the client.
     * It is not a reliable way to get a fully qualified host name: it is mainly
     * used internally to implement links for a temporary cache of SSL sessions.
     *
     * @return the host name of the peer, or {@code null} if no information is
     *         available.
     */
    @Override
    public String getPeerHost() {
        return peerHost;
    }

    /**
     * Returns the peer's port number for the actual SSL session. It is the port
     * number of the client for the server; and that of the server for the
     * client. It is not a reliable way to get a peer's port number: it is
     * mainly used internally to implement links for a temporary cache of SSL
     * sessions.
     *
     * @return the peer's port number, or {@code -1} if no one is available.
     */
    @Override
    public int getPeerPort() {
        return peerPort;
    }

    /**
     * Returns a string identifier of the crypto tools used in the actual SSL
     * session. For example AES_256_WITH_MD5.
     */
    @Override
    public String getCipherSuite() {
        if (cipherSuite == null) {
            String name = NativeCrypto.SSL_SESSION_cipher(sslSessionNativePointer);
            cipherSuite = NativeCrypto.OPENSSL_TO_STANDARD_CIPHER_SUITES.get(name);
            if (cipherSuite == null) {
                cipherSuite = name;
            }
        }
        return cipherSuite;
    }

    /**
     * Returns the standard version name of the SSL protocol used in all
     * connections pertaining to this SSL session.
     */
    @Override
    public String getProtocol() {
        if (protocol == null) {
            protocol = NativeCrypto.SSL_SESSION_get_version(sslSessionNativePointer);
        }
        return protocol;
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
            ((SSLSessionBindingListener) value)
                    .valueBound(new SSLSessionBindingEvent(this, name));
        }
        if (old instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) old)
                    .valueUnbound(new SSLSessionBindingEvent(this, name));
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
     * Returns the name requested by the SNI extension.
     */
    @Override
    public String getRequestedServerName() {
        return NativeCrypto.get_SSL_SESSION_tlsext_hostname(sslSessionNativePointer);
    }

    /**
     * Returns the OCSP stapled response.
     */
    @Override
    public List<byte[]> getStatusResponses() {
        if (peerCertificateOcspData == null) {
            return Collections.<byte[]>emptyList();
        }

        return Collections.singletonList(peerCertificateOcspData.clone());
    }

    @Override
    public byte[] getTlsSctData() {
        if (peerTlsSctData == null) {
            return null;
        }
        return peerTlsSctData.clone();
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            // The constructor can throw an exception if this object is constructed from invalid
            // saved session data.
            if (sslSessionNativePointer != 0) {
                NativeCrypto.SSL_SESSION_free(sslSessionNativePointer);
            }
        } finally {
            super.finalize();
        }
    }
}
