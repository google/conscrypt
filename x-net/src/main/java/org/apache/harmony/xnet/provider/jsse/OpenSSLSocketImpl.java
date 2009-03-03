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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;

import org.apache.harmony.security.provider.cert.X509CertImpl;
import org.bouncycastle.openssl.PEMWriter;

/**
 * Implementation of the class OpenSSLSocketImpl
 * based on OpenSSL. The JNI native interface for some methods
 * of this this class are defined in the file:
 * org_apache_harmony_xnet_provider_jsse_OpenSSLSocketImpl.cpp
 * 
 * This class only supports SSLv3 and TLSv1. This should be documented elsewhere
 * later, for example in the package.html or a separate reference document. 
 */
public class OpenSSLSocketImpl extends javax.net.ssl.SSLSocket {
    private int ssl_ctx;
    private int ssl;
    private InputStream is;
    private OutputStream os;
    private Object handshakeLock = new Object();
    private Object readLock = new Object();
    private Object writeLock = new Object();
    private SSLParameters sslParameters;
    private OpenSSLSessionImpl sslSession;
    private Socket socket;
    private boolean autoClose;
    private boolean handshakeStarted = false;
    private ArrayList listeners;
    private long ssl_op_no = 0x00000000L;
    private int timeout = 0;
    private InetSocketAddress address;

    private static final String[] supportedProtocols = new String[] {
        "SSLv3",
        "TLSv1"
        };

    private static int instanceCount = 0;

    public static int getInstanceCount() {
        synchronized (OpenSSLSocketImpl.class) {
            return instanceCount;
        }
    }

    private static void updateInstanceCount(int amount) {
        synchronized (OpenSSLSocketImpl.class) {
            instanceCount += amount;
        }
    }

    /**
     * Initialize OpenSSL library.
     */
    private native static void nativeinitstatic();

    static {
        nativeinitstatic();
    }

    private native void nativeinit(String privatekey, String certificate, byte[] seed);

    /**
     * Initialize the SSL socket and set the certificates for the
     * future handshaking.
     */
    private void init() throws IOException {
        String alias = sslParameters.getKeyManager().chooseClientAlias(new String[] { "RSA" }, null, null);
        if (alias != null) {
            PrivateKey privateKey = sslParameters.getKeyManager().getPrivateKey(alias);
            X509Certificate[] certificates = sslParameters.getKeyManager().getCertificateChain(alias);

            ByteArrayOutputStream privateKeyOS = new ByteArrayOutputStream();
            PEMWriter privateKeyPEMWriter = new PEMWriter(new OutputStreamWriter(privateKeyOS));
            privateKeyPEMWriter.writeObject(privateKey);
            privateKeyPEMWriter.close();

            ByteArrayOutputStream certificateOS = new ByteArrayOutputStream();
            PEMWriter certificateWriter = new PEMWriter(new OutputStreamWriter(certificateOS));

            for (int i = 0; i < certificates.length; i++) {
                certificateWriter.writeObject(certificates[i]);
            }
            certificateWriter.close();

            nativeinit(privateKeyOS.toString(), certificateOS.toString(),
                    sslParameters.getSecureRandomMember() != null ?
                    sslParameters.getSecureRandomMember().generateSeed(1024) : null);
        } else {
            nativeinit(null, null,
                    sslParameters.getSecureRandomMember() != null ?
                    sslParameters.getSecureRandomMember().generateSeed(1024) : null);
        }
    }

    /**
     * Class constructor with 2 parameters
     *
     * @param <code>SSLParameters sslParameters</code> Parameters for the SSL
     *            context
     * @param <code>long ssl_op_no</code> Parameter to set the enabled
     *            protocols
     * @throws <code>IOException</code> if network fails
     */
    protected OpenSSLSocketImpl(SSLParameters sslParameters, long ssl_op_no) throws IOException {
        super();
        this.sslParameters = sslParameters;
        this.ssl_op_no = ssl_op_no;
        updateInstanceCount(1);
    }

    /**
     * Class constructor with 1 parameter
     *
     * @param <code>SSLParameters sslParameters</code> Parameters for the SSL
     *            context
     * @throws <code>IOException</code> if network fails
     */
    protected OpenSSLSocketImpl(SSLParameters sslParameters) throws IOException {
        super();
        this.sslParameters = sslParameters;
        init();
        updateInstanceCount(1);
    }

    /**
     * Class constructor with 3 parameters
     *
     * @param <code> String host</code>
     * @param <code>int port</code>
     * @param <code>SSLParameters sslParameters</code>
     * @throws <code>IOException</code> if network fails
     * @throws <code>UnknownHostException</code> host not defined
     */
    protected OpenSSLSocketImpl(String host, int port,
            SSLParameters sslParameters)
        throws IOException {
        super(host, port);
        this.sslParameters = sslParameters;
        init();
        updateInstanceCount(1);
    }


    /**
     * Class constructor with 3 parameters: 1st is InetAddress
     *
     * @param <code>InetAddress address</code>
     * @param <code>int port</code>
     * @param <code>SSLParameters sslParameters</code>
     * @throws <code>IOException</code> if network fails
     * @throws <code>UnknownHostException</code> host not defined
     */
    protected OpenSSLSocketImpl(InetAddress address, int port,
            SSLParameters sslParameters)
        throws IOException {
        super(address, port);
        this.sslParameters = sslParameters;
        init();
        updateInstanceCount(1);
    }


    /**
     * Class constructor with 5 parameters: 1st is host
     *
     * @param <code>String host</code>
     * @param <code>int port</code>
     * @param <code>InetAddress localHost</code>
     * @param <code>int localPort</code>
     * @param <code>SSLParameters sslParameters</code>
     * @throws <code>IOException</code> if network fails
     * @throws <code>UnknownHostException</code> host not defined
     */
    protected OpenSSLSocketImpl(String host, int port, InetAddress clientAddress,
            int clientPort, SSLParameters sslParameters)
        throws IOException {
        super(host, port, clientAddress, clientPort);
        this.sslParameters = sslParameters;
        init();
        updateInstanceCount(1);
    }

    /**
     * Class constructor with 5 parameters: 1st is InetAddress
     *
     * @param <code>InetAddress address</code>
     * @param <code>int port</code>
     * @param <code>InetAddress localAddress</code>
     * @param <code>int localPort</code>
     * @param <code>SSLParameters sslParameters</code>
     * @throws <code>IOException</code> if network fails
     * @throws <code>UnknownHostException</code> host not defined
     */
    protected OpenSSLSocketImpl(InetAddress address, int port,
            InetAddress clientAddress, int clientPort, SSLParameters sslParameters)
        throws IOException {
        super(address, port, clientAddress, clientPort);
        this.sslParameters = sslParameters;
        init();
        updateInstanceCount(1);
    }

    /**
     * Constructor with 5 parameters: 1st is socket. Enhances an existing socket
     * with SSL functionality.
     *
     * @param <code>Socket socket</code>
     * @param <code>String host</code>
     * @param <code>int port</code>
     * @param <code>boolean autoClose</code>
     * @param <code>SSLParameters sslParameters</code>
     * @throws <code>IOException</code> if network fails
     */
    protected OpenSSLSocketImpl(Socket socket, String host, int port,
            boolean autoClose, SSLParameters sslParameters) throws IOException {
        super();
        this.socket = socket;
        this.timeout = socket.getSoTimeout();
        this.address = new InetSocketAddress(host, port);
        this.autoClose = autoClose;
        this.sslParameters = sslParameters;
        init();
        updateInstanceCount(1);
    }

    /**
     * Adds OpenSSL functionality to the existing socket and starts the SSL
     * handshaking.
     */
    private native boolean nativeconnect(int ctx, Socket sock, boolean client_mode, int sslsession) throws IOException;
    private native int nativegetsslsession(int ssl);
    private native String nativecipherauthenticationmethod();

    /**
     * Gets the suitable session reference from the session cache container.
     *
     * @return OpenSSLSessionImpl
     */
    private OpenSSLSessionImpl getOpenSSLSessionImpl() {
        try {
            byte[] id;
            SSLSession ses;
            for (Enumeration<byte[]> en = sslParameters.getClientSessionContext().getIds(); en.hasMoreElements();) {
                id = en.nextElement();
                ses = sslParameters.getClientSessionContext().getSession(id);
                if (ses instanceof OpenSSLSessionImpl && ses.isValid() &&
                        super.getInetAddress() != null &&
                        super.getInetAddress().getHostAddress() != null &&
                        super.getInetAddress().getHostName().equals(ses.getPeerHost()) &&
                        super.getPort() == ses.getPeerPort()) {
                        return (OpenSSLSessionImpl) ses;
                }
            }
        } catch (Exception ex) {
            // It's not clear to me under what circumstances the above code
            // might fail. I also can't reproduce it.
        }
        return null;
    }

    /**
     * Starts a TLS/SSL handshake on this connection using some native methods
     * from the OpenSSL library. It can negotiate new encryption keys, change
     * cipher suites, or initiate a new session. The certificate chain is
     * verified if the correspondent property in java.Security is set. All
     * listensers are notified at the end of the TLS/SSL handshake.
     *
     * @throws <code>IOException</code> if network fails
     */
    public synchronized void startHandshake() throws IOException {
        synchronized (handshakeLock) {
            if (!handshakeStarted) {
                handshakeStarted = true;
            } else {
                return;
            }
        }
        
        {
            // Debug
            int size = 0;
            for (Enumeration<byte[]> en = sslParameters.getClientSessionContext().getIds();
                    en.hasMoreElements(); en.nextElement()) { size++; };
        }
        OpenSSLSessionImpl session = getOpenSSLSessionImpl();

        // Check if it's allowed to create a new session (default is true)
        if (!sslParameters.getEnableSessionCreation() && session == null) {
            throw new SSLHandshakeException("SSL Session may not be created");
        } else {
            if (nativeconnect(ssl_ctx, this.socket != null ?
                    this.socket : this, sslParameters.getUseClientMode(), session != null ? session.session : 0)) {
                session.lastAccessedTime = System.currentTimeMillis();
                sslSession = session;
            } else {
                if (address == null) sslSession = new OpenSSLSessionImpl(nativegetsslsession(ssl),
                        sslParameters, super.getInetAddress().getHostName(), super.getPort());
                else sslSession = new OpenSSLSessionImpl(nativegetsslsession(ssl),
                        sslParameters, address.getHostName(), address.getPort());
                try {
                    X509Certificate[] peerCertificates = (X509Certificate[]) sslSession.getPeerCertificates();

                    if (peerCertificates == null || peerCertificates.length == 0) {
                        throw new SSLException("Server sends no certificate");
                    }

                    sslParameters.getTrustManager().checkServerTrusted(peerCertificates,
                                                                       nativecipherauthenticationmethod());
                    sslParameters.getClientSessionContext().putSession(sslSession);
                } catch (CertificateException e) {
                    throw new SSLException("Not trusted server certificate", e);
                }
            }
        }

        if (listeners != null) {
            // notify the listeners
            HandshakeCompletedEvent event =
                new HandshakeCompletedEvent(this, sslSession);
            int size = listeners.size();
            for (int i=0; i<size; i++) {
                ((HandshakeCompletedListener)listeners.get(i))
                    .handshakeCompleted(event);
            }
        }
    }

    // To be synchronized because of the verify_callback
    native synchronized void nativeaccept(Socket socketObject, int m_ctx, boolean client_mode);

    /**
     * Performs the first part of a SSL/TLS handshaking process with a given
     * 'host' connection and initializes the SSLSession.
     */
    protected void accept(int m_ctx, boolean client_mode) throws IOException {
        // Must be set because no handshaking is necessary
        // in this situation
        handshakeStarted = true;

        nativeaccept(this, m_ctx, client_mode);

        sslSession = new OpenSSLSessionImpl(nativegetsslsession(ssl),
                sslParameters, super.getInetAddress().getHostName(), super.getPort());
        sslSession.lastAccessedTime = System.currentTimeMillis();
    }

    /**
     * Callback methode for the OpenSSL native certificate verification process.
     *
     * @param <code>byte[][] bytes</code> Byte array containing the cert's
     *            information.
     * @return 0 if the certificate verification fails or 1 if OK
     */
    @SuppressWarnings("unused")
    private int verify_callback(byte[][] bytes) {
        try {
            X509Certificate[] peerCertificateChain = new X509Certificate[bytes.length];
            for(int i = 0; i < bytes.length; i++) {
                peerCertificateChain[i] =
                    new X509CertImpl(javax.security.cert.X509Certificate.getInstance(bytes[i]).getEncoded());
            }

            try {
                // TODO "null" String
                sslParameters.getTrustManager().checkClientTrusted(peerCertificateChain, "null");
            } catch (CertificateException e) {
                throw new AlertException(AlertProtocol.BAD_CERTIFICATE,
                        new SSLException("Not trusted server certificate", e));
            }
        } catch (javax.security.cert.CertificateException e) {
            return 0;
        } catch (IOException e) {
            return 0;
        }
        return 1;
    }

    /**
     * Returns an input stream for this SSL socket using native calls to the
     * OpenSSL library.
     *
     * @return: an input stream for reading bytes from this socket.
     * @throws: <code>IOException</code> if an I/O error occurs when creating
     *          the input stream, the socket is closed, the socket is not
     *          connected, or the socket input has been shutdown.
     */
    public InputStream getInputStream() throws IOException {
        synchronized(this) {
            if (is == null) {
                is = new SSLInputStream();
            }

            return is;
        }
    }

    /**
     * Returns an output stream for this SSL socket using native calls to the
     * OpenSSL library.
     *
     * @return an output stream for writing bytes to this socket.
     * @throws <code>IOException</code> if an I/O error occurs when creating
     *             the output stream, or no connection to the socket exists.
     */
    public OutputStream getOutputStream() throws IOException {
        synchronized(this) {
            if (os == null) {
                os = new SSLOutputStream();
            }

            return os;
        }
    }

    /**
     * This method is not supported for this SSLSocket implementation.
     */
    public void shutdownInput() throws IOException {
        throw new UnsupportedOperationException(
        "Method shutdownInput() is not supported.");
    }

    /**
     * This method is not supported for this SSLSocket implementation.
     */
    public void shutdownOutput() throws IOException {
        throw new UnsupportedOperationException(
        "Method shutdownOutput() is not supported.");
    }

    /**
     * Reads with the native SSL_read function from the encrypted data stream
     * @return -1 if error or the end of the stream is reached.
     */
    private native int nativeread(int timeout) throws IOException;
    private native int nativeread(byte[] b, int off, int len, int timeout) throws IOException;

    /**
     * This inner class provides input data stream functionality
     * for the OpenSSL native implementation. It is used to
     * read data received via SSL protocol.
     */
    private class SSLInputStream extends InputStream {
        SSLInputStream() throws IOException {
            /**
            /* Note: When startHandshake() throws an exception, no
             * SSLInputStream object will be created.
             */
            OpenSSLSocketImpl.this.startHandshake();
        }

        /**
         * Reads one byte. If there is no data in the underlying buffer,
         * this operation can block until the data will be
         * available.
         * @return read value.
         * @throws <code>IOException</code>
         */
        public int read() throws IOException {
            synchronized(readLock) {
                return OpenSSLSocketImpl.this.nativeread(timeout);
            }
        }

        /**
         * Method acts as described in spec for superclass.
         * @see java.io.InputStream#read(byte[],int,int)
         */
        public int read(byte[] b, int off, int len) throws IOException {
            synchronized(readLock) {
                return OpenSSLSocketImpl.this.nativeread(b, off, len, timeout);
            }
        }
    }

    /**
     * Writes with the native SSL_write function to the encrypted data stream.
     */
    private native void nativewrite(int b) throws IOException;
    private native void nativewrite(byte[] b, int off, int len) throws IOException;

    /**
     * This inner class provides output data stream functionality
     * for the OpenSSL native implementation. It is used to
     * write data according to the encryption parameters given in SSL context.
     */
    private class SSLOutputStream extends OutputStream {
        SSLOutputStream() throws IOException {
            /**
            /* Note: When startHandshake() throws an exception, no
             * SSLInputStream object will be created.
             */
            OpenSSLSocketImpl.this.startHandshake();
        }

        /**
         * Method acts as described in spec for superclass.
         * @see java.io.OutputStream#write(int)
         */
        public void write(int b) throws IOException {
            synchronized(writeLock) {
                OpenSSLSocketImpl.this.nativewrite(b);
            }
        }

        /**
         * Method acts as described in spec for superclass.
         * @see java.io.OutputStream#write(byte[],int,int)
         */
        public void write(byte[] b, int start, int len) throws IOException {
            synchronized(writeLock) {
                OpenSSLSocketImpl.this.nativewrite(b, start, len);
            }
        }
    }


    /**
     * The SSL session used by this connection is returned. The SSL session
     * determines which cipher suite should be used by all connections within
     * that session and which identities have the session's client and server.
     * This method starts the SSL handshake.
     * @return the SSLSession.
     * @throws <code>IOException</code> if the handshake fails
     */
    public SSLSession getSession() {
        try {
            startHandshake();
        } catch (IOException e) {
            Logger.getLogger(getClass().getName()).log(Level.WARNING,
                    "Error negotiating SSL connection.", e);

            // return an invalid session with
            // invalid cipher suite of "SSL_NULL_WITH_NULL_NULL"
            return SSLSessionImpl.NULL_SESSION;
        }
        return sslSession;
    }

    /**
     * Registers a listener to be notified that a SSL handshake
     * was successfully completed on this connection.
     * @param <code>HandShakeCompletedListener listener</code>
     * @throws <code>IllegalArgumentException</code> if listener is null.
     */
    public void addHandshakeCompletedListener(
            HandshakeCompletedListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("Provided listener is null");
        }
        if (listeners == null) {
            listeners = new ArrayList();
        }
        listeners.add(listener);
    }

    /**
     * The method removes a registered listener.
     * @param <code>HandShakeCompletedListener listener</code>
     * @throws IllegalArgumentException if listener is null or not registered
     */
    public void removeHandshakeCompletedListener(
            HandshakeCompletedListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("Provided listener is null");
        }
        if (listeners == null) {
            throw new IllegalArgumentException(
                    "Provided listener is not registered");
        }
        if (!listeners.remove(listener)) {
            throw new IllegalArgumentException(
                    "Provided listener is not registered");
        }
    }

    /**
     * Returns true if new SSL sessions may be established by this socket.
     *
     * @return true if the session may be created; false if a session already
     *         exists and must be resumed.
     */
    public boolean getEnableSessionCreation() {
        return sslParameters.getEnableSessionCreation();
    }

    /**
     * Set a flag for the socket to inhibit or to allow the creation of a new
     * SSL sessions. If the flag is set to false, and there are no actual
     * sessions to resume, then there will be no successful handshaking.
     *
     * @param <code>boolean flag</code> true if session may be created; false
     *            if a session already exists and must be resumed.
     */
    public void setEnableSessionCreation(boolean flag) {
        sslParameters.setEnableSessionCreation(flag);
    }

    /**
     * Gets all available ciphers from the current OpenSSL library.
     * Needed by OpenSSLSocketFactory too.
     */
    static native String[] nativegetsupportedciphersuites();

    /**
     * The names of the cipher suites which could be used by the SSL connection
     * are returned.
     * @return an array of cipher suite names
     */
    public String[] getSupportedCipherSuites() {
        return nativegetsupportedciphersuites();
    }

    private native String[] nativegetenabledciphersuites();

    /**
     * The names of the cipher suites that are in use in the actual the SSL
     * connection are returned.
     *
     * @return an array of cipher suite names
     */
    public String[] getEnabledCipherSuites() {
        return nativegetenabledciphersuites();
    }

    /**
     * Calls the SSL_CTX_set_cipher_list(...) OpenSSL function with the passed
     * char array.
     */
    private native void nativesetenabledciphersuites(String controlString);

    private boolean findSuite(String suite) {
        String[] supportedCipherSuites = nativegetsupportedciphersuites();
        for(int i = 0; i < supportedCipherSuites.length; i++)
            if (supportedCipherSuites[i].equals(suite)) return true;
        throw new IllegalArgumentException("Protocol " + suite +
        " is not supported.");
    }

    /**
     * This method enables the cipher suites listed by
     * getSupportedCipherSuites().
     *
     * @param <code> String[] suites</code> names of all the cipher suites to
     *            put on use
     * @throws <code>IllegalArgumentException</code> when one or more of the
     *             ciphers in array suites are not supported, or when the array
     *             is null.
     */
    public void setEnabledCipherSuites(String[] suites) {
        if (suites == null) {
            throw new IllegalArgumentException("Provided parameter is null");
        }
        String controlString = "";
        for(int i = 0; i < suites.length; i++) {
            findSuite(suites[i]);
            if (i == 0) controlString = suites[i];
            else controlString += ":" + suites[i];
        }
        nativesetenabledciphersuites(controlString);
    }

    /**
     * The names of the protocols' versions that may be used on this SSL
     * connection.
     * @return an array of protocols names
     */
    public String[] getSupportedProtocols() {
        return supportedProtocols.clone();
    }

    /**
     * SSL mode of operation with or without back compatibility. See the OpenSSL
     * ssl.h header file for more information.
     */
    static private long SSL_OP_NO_SSLv3 = 0x02000000L;
    static private long SSL_OP_NO_TLSv1 = 0x04000000L;

    /**
     * The names of the protocols' versions that are in use on this SSL
     * connection.
     * 
     * @return an array of protocols names
     */
    @Override
    public String[] getEnabledProtocols() {
        ArrayList<String> array = new ArrayList<String>();

        if ((ssl_op_no & SSL_OP_NO_SSLv3) == 0x00000000L) {
            array.add(supportedProtocols[1]);
        }
        if ((ssl_op_no & SSL_OP_NO_TLSv1) == 0x00000000L) {
            array.add(supportedProtocols[2]);
        }
        return array.toArray(new String[array.size()]);
    }

    private native void nativesetenabledprotocols(long l);

    /**
     * This method enables the protocols' versions listed by
     * getSupportedProtocols().
     * 
     * @param protocols The names of all the protocols to put on use
     * 
     * @throws IllegalArgumentException when one or more of the names in the
     *             array are not supported, or when the array is null.
     */
    @Override
    public synchronized void setEnabledProtocols(String[] protocols) {

        if (protocols == null) {
            throw new IllegalArgumentException("Provided parameter is null");
        }

        ssl_op_no  = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;

        for(int i = 0; i < protocols.length; i++) {
            if (protocols[i].equals("SSLv3"))
                ssl_op_no ^= SSL_OP_NO_SSLv3;
            else if (protocols[i].equals("TLSv1"))
                ssl_op_no ^= SSL_OP_NO_TLSv1;
            else throw new IllegalArgumentException("Protocol " + protocols[i] +
            " is not supported.");
        }

        nativesetenabledprotocols(ssl_op_no);
    }

    /**
     * This method gives true back if the SSL socket is set to client mode.
     *
     * @return true if the socket should do the handshaking as client.
     */
    public boolean getUseClientMode() {
        return sslParameters.getUseClientMode();
    }

    /**
     * This method set the actual SSL socket to client mode.
     *
     * @param <code>boolean mode</code> true if the socket starts in client
     *            mode
     * @throws <code>IllegalArgumentException</code> if mode changes during
     *             handshake.
     */
    public synchronized void setUseClientMode(boolean mode) {
        if (handshakeStarted) {
            throw new IllegalArgumentException(
            "Could not change the mode after the initial handshake has begun.");
        }
        sslParameters.setUseClientMode(mode);
    }

    /**
     * Returns true if the SSL socket requests client's authentication. Relevant
     * only for server sockets!
     *
     * @return true if client authentication is desired, false if not.
     */
    public boolean getWantClientAuth() {
        return sslParameters.getWantClientAuth();
    }

    /**
     * Returns true if the SSL socket needs client's authentication. Relevant
     * only for server sockets!
     *
     * @return true if client authentication is desired, false if not.
     */
    public boolean getNeedClientAuth() {
        return sslParameters.getNeedClientAuth();
    }

    /**
     * Sets the SSL socket to use client's authentication. Relevant only for
     * server sockets!
     *
     * @param <code>boolean need</code> true if client authentication is
     *            desired, false if not.
     */
    public void setNeedClientAuth(boolean need) {
        sslParameters.setNeedClientAuth(need);
    }

    /**
     * Sets the SSL socket to use client's authentication. Relevant only for
     * server sockets! Notice that in contrast to setNeedClientAuth(..) this
     * method will continue the negotiation if the client decide not to send
     * authentication credentials.
     *
     * @param <code>boolean want</code> true if client authentication is
     *            desired, false if not.
     */
    public void setWantClientAuth(boolean want) {
        sslParameters.setWantClientAuth(want);
    }

    /**
     * This method is not supported for SSLSocket implementation.
     */
    public void sendUrgentData(int data) throws IOException {
        throw new SocketException(
                "Method sendUrgentData() is not supported.");
    }

    /**
     * This method is not supported for SSLSocket implementation.
     */
    public void setOOBInline(boolean on) throws SocketException {
        throw new SocketException(
                "Methods sendUrgentData, setOOBInline are not supported.");
    }

    /**
     * Set the read timeout on this socket. The SO_TIMEOUT option, is specified
     * in milliseconds. The read operation will block indefinitely for a zero
     * value.
     *
     * @param timeout the read timeout value
     * @throws SocketException if an error occurs setting the option
     */
    public synchronized void setSoTimeout(int timeout) throws SocketException {
        super.setSoTimeout(timeout);
        this.timeout = timeout;
    }

    private native void nativeinterrupt() throws IOException;
    private native void nativeclose() throws IOException;

    /**
     * Closes the SSL socket. Once closed, a socket is not available for further
     * use anymore under any circumstance. A new socket must be created.
     *
     * @throws <code>IOException</code> if an I/O error happens during the
     *             socket's closure.
     */
    public void close() throws IOException {
        synchronized (handshakeLock) {
            if (!handshakeStarted) {
                handshakeStarted = true;
                
                synchronized (this) {
                    nativefree();

                    if (socket != null) {
                        if (autoClose && !socket.isClosed()) socket.close();
                    } else {
                        if (!super.isClosed()) super.close();
                    }
                }
                
                return;
            }
        }

        nativeinterrupt();

        synchronized (this) {
            synchronized (writeLock) {
                synchronized (readLock) {

                    IOException pendingException = null;

                    // Shut down the SSL connection, per se.
                    try {
                        if (handshakeStarted) {
                            nativeclose();
                        }
                    } catch (IOException ex) {
                        /*
                         * Note the exception at this point, but try to continue
                         * to clean the rest of this all up before rethrowing.
                         */
                        pendingException = ex;
                    }

                    /*
                     * Even if the above call failed, it is still safe to free
                     * the native structs, and we need to do so lest we leak
                     * memory.
                     */
                    nativefree();

                    if (socket != null) {
                        if (autoClose && !socket.isClosed())
                            socket.close();
                    } else {
                        if (!super.isClosed())
                            super.close();
                    }

                    if (pendingException != null) {
                        throw pendingException;
                    }
                }
            }
        }
    }

    private native void nativefree();

    protected void finalize() throws IOException {
        updateInstanceCount(-1);

        if (ssl == 0) {
            /*
             * It's already been closed, so there's no need to do anything
             * more at this point.
             */
            return;
        }

        // Note the underlying socket up-front, for possible later use.
        Socket underlyingSocket = socket;

        // Fire up a thread to (hopefully) do all the real work.
        Finalizer f = new Finalizer();
        f.setDaemon(true);
        f.start();

        /*
         * Give the finalizer thread one second to run. If it fails to
         * terminate in that time, interrupt it (which may help if it
         * is blocked on an interruptible I/O operation), make a note
         * in the log, and go ahead and close the underlying socket if
         * possible.
         */
        try {
            f.join(1000);
        } catch (InterruptedException ex) {
            // Reassert interrupted status.
            Thread.currentThread().interrupt();
        }

        if (f.isAlive()) {
            f.interrupt();
            Logger.global.log(Level.SEVERE,
                    "Slow finalization of SSL socket (" + this + ", for " +
                    underlyingSocket + ")");
            if ((underlyingSocket != null) && !underlyingSocket.isClosed()) {
                underlyingSocket.close();
            }
        }
    }

    /**
     * Helper class for a thread that knows how to call {@link #close} on behalf
     * of instances being finalized, since that call can take arbitrarily long
     * (e.g., due to a slow network), and an overly long-running finalizer will
     * cause the process to be totally aborted.
     */
    private class Finalizer extends Thread {
        public void run() {
            Socket underlyingSocket = socket; // for error reporting
            try {
                close();
            } catch (IOException ex) {
                /*
                 * Clear interrupted status, so that the Logger call
                 * immediately below won't get spuriously interrupted.
                 */
                Thread.interrupted();

                Logger.global.log(Level.SEVERE,
                        "Trouble finalizing SSL socket (" +
                        OpenSSLSocketImpl.this + ", for " + underlyingSocket +
                        ")",
                        ex);
            }
        }
    }

    /**
     * Verifies an RSA signature. Conceptually, this method doesn't really
     * belong here, but due to its native code being closely tied to OpenSSL
     * (just like the rest of this class), we put it here for the time being.
     * This also solves potential problems with native library initialization.
     *
     * @param message The message to verify
     * @param signature The signature to verify
     * @param algorithm The hash/sign algorithm to use, i.e. "RSA-SHA1"
     * @param key The RSA public key to use
     * @return true if the verification succeeds, false otherwise
     */
    public static boolean verifySignature(byte[] message, byte[] signature, String algorithm, RSAPublicKey key) {
        byte[] modulus = key.getModulus().toByteArray();
        byte[] exponent = key.getPublicExponent().toByteArray();

        return nativeverifysignature(message, signature, algorithm, modulus, exponent) == 1;
    }

    private static native int nativeverifysignature(byte[] message, byte[] signature,
            String algorithm, byte[] modulus, byte[] exponent);
}
