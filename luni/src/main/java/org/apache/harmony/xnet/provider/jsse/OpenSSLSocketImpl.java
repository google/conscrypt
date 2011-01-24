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

import dalvik.system.BlockGuard;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import org.apache.harmony.security.provider.cert.X509CertImpl;

/**
 * Implementation of the class OpenSSLSocketImpl based on OpenSSL.
 * <p>
 * This class only supports SSLv3 and TLSv1. This should be documented elsewhere
 * later, for example in the package.html or a separate reference document.
 * <p>
 * Extensions to SSLSocket include:
 * <ul>
 * <li>handshake timeout
 * <li>compression methods
 * <li>session tickets
 * <li>Server Name Indication
 * </ul>
 */
public class OpenSSLSocketImpl
        extends javax.net.ssl.SSLSocket
        implements NativeCrypto.SSLHandshakeCallbacks {

    private int sslNativePointer;
    private InputStream is;
    private OutputStream os;
    private final Object handshakeLock = new Object();
    private final Object readLock = new Object();
    private final Object writeLock = new Object();
    private SSLParametersImpl sslParameters;
    private String[] enabledProtocols;
    private String[] enabledCipherSuites;
    private String[] enabledCompressionMethods;
    private boolean useSessionTickets;
    private String hostname;
    private OpenSSLSessionImpl sslSession;
    private final Socket socket;
    private final FileDescriptor fd;
    private boolean autoClose;
    private boolean handshakeStarted = false;

    /**
     * Not set to true until the update from native that tells us the
     * full handshake is complete, since SSL_do_handshake can return
     * before the handshake is completely done due to
     * handshake_cutthrough support.
     */
    private boolean handshakeCompleted = false;

    private ArrayList<HandshakeCompletedListener> listeners;

    /**
     * Local cache of timeout to avoid getsockopt on every read and
     * write for non-wrapped sockets. Note that
     * OpenSSLSocketImplWrapper overrides setSoTimeout and
     * getSoTimeout to delegate to the wrapped socket.
     */
    private int timeoutMilliseconds = 0;

    // BEGIN android-added
    private int handshakeTimeoutMilliseconds = -1;  // -1 = same as timeout; 0 = infinite
    // END android-added
    private String wrappedHost;
    private int wrappedPort;

    private static final AtomicInteger instanceCount = new AtomicInteger(0);

    public static int getInstanceCount() {
        return instanceCount.get();
    }

    private static void updateInstanceCount(int amount) {
        instanceCount.addAndGet(amount);
    }

    /**
     * Class constructor with 1 parameter
     *
     * @param sslParameters Parameters for the SSL
     *            context
     * @throws IOException if network fails
     */
    protected OpenSSLSocketImpl(SSLParametersImpl sslParameters) throws IOException {
        super();
        this.socket = this;
        this.fd = NativeCrypto.getFileDescriptor(socket);
        init(sslParameters);
    }

    /**
     * Create an OpenSSLSocketImpl from an OpenSSLServerSocketImpl
     *
     * @param sslParameters Parameters for the SSL
     *            context
     * @throws IOException if network fails
     */
    protected OpenSSLSocketImpl(SSLParametersImpl sslParameters,
                                String[] enabledProtocols,
                                String[] enabledCipherSuites,
                                String[] enabledCompressionMethods) throws IOException {
        super();
        this.socket = this;
        this.fd = NativeCrypto.getFileDescriptor(socket);
        init(sslParameters, enabledProtocols, enabledCipherSuites, enabledCompressionMethods);
    }

    /**
     * Class constructor with 3 parameters
     *
     * @throws IOException if network fails
     * @throws java.net.UnknownHostException host not defined
     */
    protected OpenSSLSocketImpl(String host, int port, SSLParametersImpl sslParameters)
            throws IOException {
        super(host, port);
        this.socket = this;
        this.fd = NativeCrypto.getFileDescriptor(socket);
        init(sslParameters);
    }

    /**
     * Class constructor with 3 parameters: 1st is InetAddress
     *
     * @throws IOException if network fails
     * @throws java.net.UnknownHostException host not defined
     */
    protected OpenSSLSocketImpl(InetAddress address, int port, SSLParametersImpl sslParameters)
            throws IOException {
        super(address, port);
        this.socket = this;
        this.fd = NativeCrypto.getFileDescriptor(socket);
        init(sslParameters);
    }


    /**
     * Class constructor with 5 parameters: 1st is host
     *
     * @throws IOException if network fails
     * @throws java.net.UnknownHostException host not defined
     */
    protected OpenSSLSocketImpl(String host, int port,
                                InetAddress clientAddress, int clientPort,
                                SSLParametersImpl sslParameters)
            throws IOException {
        super(host, port, clientAddress, clientPort);
        this.socket = this;
        this.fd = NativeCrypto.getFileDescriptor(socket);
        init(sslParameters);
    }

    /**
     * Class constructor with 5 parameters: 1st is InetAddress
     *
     * @throws IOException if network fails
     * @throws java.net.UnknownHostException host not defined
     */
    protected OpenSSLSocketImpl(InetAddress address, int port,
                                InetAddress clientAddress, int clientPort,
                                SSLParametersImpl sslParameters)
            throws IOException {
        super(address, port, clientAddress, clientPort);
        this.socket = this;
        this.fd = NativeCrypto.getFileDescriptor(socket);
        init(sslParameters);
    }

    /**
     * Constructor with 5 parameters: 1st is socket. Enhances an existing socket
     * with SSL functionality. Invoked via OpenSSLSocketImplWrapper constructor.
     *
     * @throws IOException if network fails
     */
    protected OpenSSLSocketImpl(Socket socket, String host, int port,
            boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        super();
        this.socket = socket;
        this.fd = NativeCrypto.getFileDescriptor(socket);
        this.wrappedHost = host;
        this.wrappedPort = port;
        this.autoClose = autoClose;
        init(sslParameters);

        // this.timeout is not set intentionally.
        // OpenSSLSocketImplWrapper.getSoTimeout will delegate timeout
        // to wrapped socket
    }

    /**
     * Initialize the SSL socket and set the certificates for the
     * future handshaking.
     */
    private void init(SSLParametersImpl sslParameters) throws IOException {
        init(sslParameters,
             NativeCrypto.getSupportedProtocols(),
             NativeCrypto.getDefaultCipherSuites(),
             NativeCrypto.getDefaultCompressionMethods());
    }

    /**
     * Initialize the SSL socket and set the certificates for the
     * future handshaking.
     */
    private void init(SSLParametersImpl sslParameters,
                      String[] enabledProtocols,
                      String[] enabledCipherSuites,
                      String[] enabledCompressionMethods) throws IOException {
        this.sslParameters = sslParameters;
        this.enabledProtocols = enabledProtocols;
        this.enabledCipherSuites = enabledCipherSuites;
        this.enabledCompressionMethods = enabledCompressionMethods;
        updateInstanceCount(1);
    }

    /**
     * Gets the suitable session reference from the session cache container.
     *
     * @return OpenSSLSessionImpl
     */
    private OpenSSLSessionImpl getCachedClientSession(ClientSessionContext sessionContext) {
        if (super.getInetAddress() == null ||
                super.getInetAddress().getHostAddress() == null ||
                super.getInetAddress().getHostName() == null) {
            return null;
        }
        OpenSSLSessionImpl session = (OpenSSLSessionImpl) sessionContext.getSession(
                super.getInetAddress().getHostName(),
                super.getPort());
        if (session == null) {
            return null;
        }

        String protocol = session.getProtocol();
        boolean protocolFound = false;
        for (String enabledProtocol : enabledProtocols) {
            if (protocol.equals(enabledProtocol)) {
                protocolFound = true;
                break;
            }
        }
        if (!protocolFound) {
            return null;
        }

        String cipherSuite = session.getCipherSuite();
        boolean cipherSuiteFound = false;
        for (String enabledCipherSuite : enabledCipherSuites) {
            if (cipherSuite.equals(enabledCipherSuite)) {
                cipherSuiteFound = true;
                break;
            }
        }
        if (!cipherSuiteFound) {
            return null;
        }

        String compressionMethod = session.getCompressionMethod();
        boolean compressionMethodFound = false;
        for (String enabledCompressionMethod : enabledCompressionMethods) {
            if (compressionMethod.equals(enabledCompressionMethod)) {
                compressionMethodFound = true;
                break;
            }
        }
        if (!compressionMethodFound) {
            return null;
        }

        return session;
    }

    /**
     * Ensures that logger is lazily loaded. The outer class seems to load
     * before logging is ready.
     */
    static class LoggerHolder {
        static final Logger logger = Logger.getLogger(OpenSSLSocketImpl.class.getName());
    }

    /**
     * Starts a TLS/SSL handshake on this connection using some native methods
     * from the OpenSSL library. It can negotiate new encryption keys, change
     * cipher suites, or initiate a new session. The certificate chain is
     * verified if the correspondent property in java.Security is set. All
     * listeners are notified at the end of the TLS/SSL handshake.
     *
     * @throws <code>IOException</code> if network fails
     */
    @Override
    public void startHandshake() throws IOException {
        startHandshake(true);
    }

    /**
     * Checks whether the socket is closed, and throws an exception.
     *
     * @throws SocketException
     *             if the socket is closed.
     */
    private void checkOpen() throws SocketException {
        if (isClosed()) {
            throw new SocketException("Socket is closed");
        }
    }

    /**
     * Perform the handshake
     * @param full If true, disable handshake cutthrough for a fully synchronous handshake
     */
    public synchronized void startHandshake(boolean full) throws IOException {
        synchronized (handshakeLock) {
            checkOpen();
            if (!handshakeStarted) {
                handshakeStarted = true;
            } else {
                return;
            }
        }

        // note that this modifies the global seed, not something specific to the connection
        final int seedLengthInBytes = NativeCrypto.RAND_SEED_LENGTH_IN_BYTES;
        final SecureRandom secureRandom = sslParameters.getSecureRandomMember();
        if (secureRandom == null) {
            NativeCrypto.RAND_load_file("/dev/urandom", seedLengthInBytes);
        } else {
            NativeCrypto.RAND_seed(secureRandom.generateSeed(seedLengthInBytes));
        }

        final boolean client = sslParameters.getUseClientMode();

        final int sslCtxNativePointer = (client) ?
            sslParameters.getClientSessionContext().sslCtxNativePointer :
            sslParameters.getServerSessionContext().sslCtxNativePointer;

        this.sslNativePointer = NativeCrypto.SSL_new(sslCtxNativePointer);

        // setup server certificates and private keys.
        // clients will receive a call back to request certificates.
        if (!client) {
            for (String keyType : NativeCrypto.KEY_TYPES) {
                try {
                    setCertificate(sslParameters.getKeyManager().chooseServerAlias(keyType,
                                                                                   null,
                                                                                   this));
                } catch (CertificateEncodingException e) {
                    throw new IOException(e);
                }
            }
        }

        NativeCrypto.setEnabledProtocols(sslNativePointer, enabledProtocols);
        NativeCrypto.setEnabledCipherSuites(sslNativePointer, enabledCipherSuites);
        if (enabledCompressionMethods.length != 0) {
            NativeCrypto.setEnabledCompressionMethods(sslNativePointer, enabledCompressionMethods);
        }
        if (useSessionTickets) {
            NativeCrypto.SSL_clear_options(sslNativePointer, NativeCrypto.SSL_OP_NO_TICKET);
        }
        if (hostname != null) {
            NativeCrypto.SSL_set_tlsext_host_name(sslNativePointer, hostname);
        }

        boolean enableSessionCreation = sslParameters.getEnableSessionCreation();
        if (!enableSessionCreation) {
            NativeCrypto.SSL_set_session_creation_enabled(sslNativePointer,
                                                          enableSessionCreation);
        }

        AbstractSessionContext sessionContext;
        OpenSSLSessionImpl session;
        if (client) {
            // look for client session to reuse
            ClientSessionContext clientSessionContext = sslParameters.getClientSessionContext();
            sessionContext = clientSessionContext;
            session = getCachedClientSession(clientSessionContext);
            if (session != null) {
                NativeCrypto.SSL_set_session(sslNativePointer,  session.sslSessionNativePointer);
            }
        } else {
            sessionContext = sslParameters.getServerSessionContext();
            session = null;
        }

        // setup peer certificate verification
        if (client) {
            // TODO support for anonymous cipher would require us to
            // conditionally use SSL_VERIFY_NONE
        } else {
            // needing client auth takes priority...
            boolean certRequested = false;
            if (sslParameters.getNeedClientAuth()) {
                NativeCrypto.SSL_set_verify(sslNativePointer,
                                            NativeCrypto.SSL_VERIFY_PEER
                                            | NativeCrypto.SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
                certRequested = true;
            // ... over just wanting it...
            } else if (sslParameters.getWantClientAuth()) {
                NativeCrypto.SSL_set_verify(sslNativePointer,
                                            NativeCrypto.SSL_VERIFY_PEER);
                certRequested = true;
            // ... and it defaults properly so we don't need call SSL_set_verify in the common case.
            } else {
                certRequested = false;
            }

            if (certRequested) {
                X509Certificate[] issuers = sslParameters.getTrustManager().getAcceptedIssuers();
                if (issuers != null && issuers.length != 0) {
                    byte[][] issuersBytes;
                    try {
                        issuersBytes = NativeCrypto.encodeIssuerX509Principals(issuers);
                    } catch (CertificateEncodingException e) {
                        throw new IOException("Problem encoding principals", e);
                    }
                    NativeCrypto.SSL_set_client_CA_list(sslNativePointer, issuersBytes);
                }
            }
        }

        if (client && full) {
            // we want to do a full synchronous handshake, so turn off cutthrough
            NativeCrypto.SSL_clear_mode(sslNativePointer,
                                        NativeCrypto.SSL_MODE_HANDSHAKE_CUTTHROUGH);
        }

        // BEGIN android-added
        // Temporarily use a different timeout for the handshake process
        int savedTimeoutMilliseconds = getSoTimeout();
        if (handshakeTimeoutMilliseconds >= 0) {
            setSoTimeout(handshakeTimeoutMilliseconds);
        }
        // END android-added


        int sslSessionNativePointer;
        try {
            sslSessionNativePointer = NativeCrypto.SSL_do_handshake(sslNativePointer, fd, this,
                                                                    getSoTimeout(), client);
        } catch (CertificateException e) {
            SSLHandshakeException exception = new SSLHandshakeException(e.getMessage());
            exception.initCause(e);
            throw exception;
        }
        byte[] sessionId = NativeCrypto.SSL_SESSION_session_id(sslSessionNativePointer);
        sslSession = (OpenSSLSessionImpl) sessionContext.getSession(sessionId);
        if (sslSession != null) {
            sslSession.lastAccessedTime = System.currentTimeMillis();
            LoggerHolder.logger.fine("Reused cached session for "
                                     + getInetAddress() + ".");
            NativeCrypto.SSL_SESSION_free(sslSessionNativePointer);
        } else {
            if (!enableSessionCreation) {
                // Should have been prevented by NativeCrypto.SSL_set_session_creation_enabled
                throw new IllegalStateException("SSL Session may not be created");
            }
            X509Certificate[] localCertificates
                    = createCertChain(NativeCrypto.SSL_get_certificate(sslNativePointer));
            X509Certificate[] peerCertificates
                    = createCertChain(NativeCrypto.SSL_get_peer_cert_chain(sslNativePointer));
            if (wrappedHost == null) {
                sslSession = new OpenSSLSessionImpl(sslSessionNativePointer,
                                                    localCertificates, peerCertificates,
                                                    super.getInetAddress().getHostName(),
                                                    super.getPort(), sessionContext);
            } else  {
                sslSession = new OpenSSLSessionImpl(sslSessionNativePointer,
                                                    localCertificates, peerCertificates,
                                                    wrappedHost, wrappedPort,
                                                    sessionContext);
            }
            // if not, putSession later in handshakeCompleted() callback
            if (handshakeCompleted) {
                sessionContext.putSession(sslSession);
            }
            LoggerHolder.logger.fine("Created new session for "
                                     + getInetAddress().getHostName() + ".");
        }

        // BEGIN android-added
        // Restore the original timeout now that the handshake is complete
        if (handshakeTimeoutMilliseconds >= 0) {
            setSoTimeout(savedTimeoutMilliseconds);
        }
        // END android-added

        // if not, notifyHandshakeCompletedListeners later in handshakeCompleted() callback
        if (handshakeCompleted) {
            notifyHandshakeCompletedListeners();
        }
    }

    /**
     * Return a possibly null array of X509Certificates given the
     * possibly null array of DER encoded bytes.
     */
    private static X509Certificate[] createCertChain(byte[][] certificatesBytes) {
        if (certificatesBytes == null) {
            return null;
        }
        X509Certificate[] certificates = new X509Certificate[certificatesBytes.length];
        for (int i = 0; i < certificatesBytes.length; i++) {
            try {
                certificates[i] = new X509CertImpl(certificatesBytes[i]);
            } catch (IOException e) {
                return null;
            }
        }
        return certificates;
    }

    private void setCertificate(String alias) throws CertificateEncodingException, SSLException {
        if (alias == null) {
            return;
        }

        PrivateKey privateKey = sslParameters.getKeyManager().getPrivateKey(alias);
        byte[] privateKeyBytes = privateKey.getEncoded();
        NativeCrypto.SSL_use_PrivateKey(sslNativePointer, privateKeyBytes);

        X509Certificate[] certificates = sslParameters.getKeyManager().getCertificateChain(alias);
        byte[][] certificateBytes = NativeCrypto.encodeCertificates(certificates);
        NativeCrypto.SSL_use_certificate(sslNativePointer, certificateBytes);

        // checks the last installed private key and certificate,
        // so need to do this once per loop iteration
        NativeCrypto.SSL_check_private_key(sslNativePointer);
    }

    /**
     * Implementation of NativeCrypto.SSLHandshakeCallbacks
     * invoked via JNI from client_cert_cb
     */
    public void clientCertificateRequested(byte[] keyTypeBytes, byte[][] asn1DerEncodedPrincipals)
            throws CertificateEncodingException, SSLException {

        String[] keyTypes = new String[keyTypeBytes.length];
        for (int i = 0; i < keyTypeBytes.length; i++) {
            keyTypes[i] = NativeCrypto.keyType(keyTypeBytes[i]);
        }

        X500Principal[] issuers;
        if (asn1DerEncodedPrincipals == null) {
            issuers = null;
        } else {
            issuers = new X500Principal[asn1DerEncodedPrincipals.length];
            for (int i = 0; i < asn1DerEncodedPrincipals.length; i++) {
                issuers[i] = new X500Principal(asn1DerEncodedPrincipals[i]);
            }
        }
        setCertificate(sslParameters.getKeyManager().chooseClientAlias(keyTypes, issuers, this));
    }

    /**
     * Implementation of NativeCrypto.SSLHandshakeCallbacks
     * invoked via JNI from info_callback
     */
    public void handshakeCompleted() {
        handshakeCompleted = true;

        // If sslSession is null, the handshake was completed during
        // the call to NativeCrypto.SSL_do_handshake and not during a
        // later read operation. That means we do not need to fixup
        // the SSLSession and session cache or notify
        // HandshakeCompletedListeners, it will be done in
        // startHandshake.
        if (sslSession == null) {
            return;
        }

        // reset session id from the native pointer and update the
        // appropriate cache.
        sslSession.resetId();
        AbstractSessionContext sessionContext =
            (sslParameters.getUseClientMode())
            ? sslParameters.getClientSessionContext()
                : sslParameters.getServerSessionContext();
        sessionContext.putSession(sslSession);

        // let listeners know we are finally done
        notifyHandshakeCompletedListeners();
    }

    private void notifyHandshakeCompletedListeners() {
        if (listeners != null && !listeners.isEmpty()) {
            // notify the listeners
            HandshakeCompletedEvent event =
                new HandshakeCompletedEvent(this, sslSession);
            for (HandshakeCompletedListener listener : listeners) {
                try {
                    listener.handshakeCompleted(event);
                } catch (RuntimeException e) {
                    // The RI runs the handlers in a separate thread,
                    // which we do not. But we try to preserve their
                    // behavior of logging a problem and not killing
                    // the handshaking thread just because a listener
                    // has a problem.
                    Thread thread = Thread.currentThread();
                    thread.getUncaughtExceptionHandler().uncaughtException(thread, e);
                }
            }
        }
    }

    /**
     * Implementation of NativeCrypto.SSLHandshakeCallbacks
     *
     * @param bytes An array of ASN.1 DER encoded certficates
     * @param authMethod auth algorithm name
     *
     * @throws CertificateException if the certificate is untrusted
     */
    @SuppressWarnings("unused")
    public void verifyCertificateChain(byte[][] bytes, String authMethod)
            throws CertificateException {
        try {
            if (bytes == null || bytes.length == 0) {
                throw new SSLException("Peer sent no certificate");
            }
            X509Certificate[] peerCertificateChain = new X509Certificate[bytes.length];
            for (int i = 0; i < bytes.length; i++) {
                peerCertificateChain[i] =
                    new X509CertImpl(
                        javax.security.cert.X509Certificate.getInstance(bytes[i]).getEncoded());
            }
            boolean client = sslParameters.getUseClientMode();
            if (client) {
                sslParameters.getTrustManager().checkServerTrusted(peerCertificateChain,
                                                                   authMethod);
            } else {
                sslParameters.getTrustManager().checkClientTrusted(peerCertificateChain,
                                                                   authMethod);
            }

        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
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
    @Override
    public InputStream getInputStream() throws IOException {
        checkOpen();
        synchronized (this) {
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
    @Override
    public OutputStream getOutputStream() throws IOException {
        checkOpen();
        synchronized (this) {
            if (os == null) {
                os = new SSLOutputStream();
            }

            return os;
        }
    }

    /**
     * This method is not supported for this SSLSocket implementation
     * because reading from an SSLSocket may involve writing to the
     * network.
     */
    @Override
    public void shutdownInput() throws IOException {
        throw new UnsupportedOperationException();
    }

    /**
     * This method is not supported for this SSLSocket implementation
     * because writing to an SSLSocket may involve reading from the
     * network.
     */
    @Override
    public void shutdownOutput() throws IOException {
        throw new UnsupportedOperationException();
    }

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
            OpenSSLSocketImpl.this.startHandshake(false);
        }

        /**
         * Reads one byte. If there is no data in the underlying buffer,
         * this operation can block until the data will be
         * available.
         * @return read value.
         * @throws <code>IOException</code>
         */
        @Override
        public int read() throws IOException {
            BlockGuard.getThreadPolicy().onNetwork();
            synchronized (readLock) {
                checkOpen();
                return NativeCrypto.SSL_read_byte(sslNativePointer, fd, OpenSSLSocketImpl.this,
                                                  getSoTimeout());
            }
        }

        /**
         * Method acts as described in spec for superclass.
         * @see java.io.InputStream#read(byte[],int,int)
         */
        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            BlockGuard.getThreadPolicy().onNetwork();
            synchronized (readLock) {
                checkOpen();
                if (b == null) {
                    throw new NullPointerException("b == null");
                }
                if ((len | off) < 0 || len > b.length - off) {
                    throw new IndexOutOfBoundsException();
                }
                if (0 == len) {
                    return 0;
                }
                return NativeCrypto.SSL_read(sslNativePointer, fd, OpenSSLSocketImpl.this,
                                             b, off, len, getSoTimeout());
            }
        }
    }

    /**
     * This inner class provides output data stream functionality
     * for the OpenSSL native implementation. It is used to
     * write data according to the encryption parameters given in SSL context.
     */
    private class SSLOutputStream extends OutputStream {
        SSLOutputStream() throws IOException {
            /**
            /* Note: When startHandshake() throws an exception, no
             * SSLOutputStream object will be created.
             */
            OpenSSLSocketImpl.this.startHandshake(false);
        }

        /**
         * Method acts as described in spec for superclass.
         * @see java.io.OutputStream#write(int)
         */
        @Override
        public void write(int b) throws IOException {
            BlockGuard.getThreadPolicy().onNetwork();
            synchronized (writeLock) {
                checkOpen();
                NativeCrypto.SSL_write_byte(sslNativePointer, fd, OpenSSLSocketImpl.this, b);
            }
        }

        /**
         * Method acts as described in spec for superclass.
         * @see java.io.OutputStream#write(byte[],int,int)
         */
        @Override
        public void write(byte[] b, int start, int len) throws IOException {
            BlockGuard.getThreadPolicy().onNetwork();
            synchronized (writeLock) {
                checkOpen();
                if (b == null) {
                    throw new NullPointerException("b == null");
                }
                if ((len | start) < 0 || len > b.length - start) {
                    throw new IndexOutOfBoundsException();
                }
                if (len == 0) {
                    return;
                }
                NativeCrypto.SSL_write(sslNativePointer, fd, OpenSSLSocketImpl.this, b, start, len);
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
    @Override
    public SSLSession getSession() {
        if (sslSession == null) {
            try {
                startHandshake(true);
            } catch (IOException e) {

                // return an invalid session with
                // invalid cipher suite of "SSL_NULL_WITH_NULL_NULL"
                return SSLSessionImpl.NULL_SESSION;
            }
        }
        return sslSession;
    }

    /**
     * Registers a listener to be notified that a SSL handshake
     * was successfully completed on this connection.
     * @throws <code>IllegalArgumentException</code> if listener is null.
     */
    @Override
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
     * @throws IllegalArgumentException if listener is null or not registered
     */
    @Override
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
    @Override
    public boolean getEnableSessionCreation() {
        return sslParameters.getEnableSessionCreation();
    }

    /**
     * Set a flag for the socket to inhibit or to allow the creation of a new
     * SSL sessions. If the flag is set to false, and there are no actual
     * sessions to resume, then there will be no successful handshaking.
     *
     * @param flag true if session may be created; false
     *            if a session already exists and must be resumed.
     */
    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslParameters.setEnableSessionCreation(flag);
    }

    /**
     * The names of the cipher suites which could be used by the SSL connection
     * are returned.
     * @return an array of cipher suite names
     */
    @Override
    public String[] getSupportedCipherSuites() {
        return NativeCrypto.getSupportedCipherSuites();
    }

    /**
     * The names of the cipher suites that are in use in the actual the SSL
     * connection are returned.
     *
     * @return an array of cipher suite names
     */
    @Override
    public String[] getEnabledCipherSuites() {
        return enabledCipherSuites.clone();
    }

    /**
     * This method enables the cipher suites listed by
     * getSupportedCipherSuites().
     *
     * @param suites names of all the cipher suites to
     *            put on use
     * @throws IllegalArgumentException when one or more of the
     *             ciphers in array suites are not supported, or when the array
     *             is null.
     */
    @Override
    public void setEnabledCipherSuites(String[] suites) {
        enabledCipherSuites = NativeCrypto.checkEnabledCipherSuites(suites);
    }

    /**
     * The names of the protocols' versions that may be used on this SSL
     * connection.
     * @return an array of protocols names
     */
    @Override
    public String[] getSupportedProtocols() {
        return NativeCrypto.getSupportedProtocols();
    }

    /**
     * The names of the protocols' versions that are in use on this SSL
     * connection.
     *
     * @return an array of protocols names
     */
    @Override
    public String[] getEnabledProtocols() {
        return enabledProtocols.clone();
    }

    /**
     * This method enables the protocols' versions listed by
     * getSupportedProtocols().
     *
     * @param protocols The names of all the protocols to allow
     *
     * @throws IllegalArgumentException when one or more of the names in the
     *             array are not supported, or when the array is null.
     */
    @Override
    public void setEnabledProtocols(String[] protocols) {
        enabledProtocols = NativeCrypto.checkEnabledProtocols(protocols);
    }

    /**
     * The names of the compression methods that may be used on this SSL
     * connection.
     * @return an array of compression methods
     */
    public String[] getSupportedCompressionMethods() {
        return NativeCrypto.getSupportedCompressionMethods();
    }

    /**
     * The names of the compression methods versions that are in use
     * on this SSL connection.
     *
     * @return an array of compression methods
     */
    public String[] getEnabledCompressionMethods() {
        return enabledCompressionMethods.clone();
    }

    /**
     * This method enables the compression method listed by
     * getSupportedCompressionMethods().
     *
     * @param methods The names of all the compression methods to allow
     *
     * @throws IllegalArgumentException when one or more of the names in the
     *             array are not supported, or when the array is null.
     */
    public void setEnabledCompressionMethods (String[] methods) {
        enabledCompressionMethods = NativeCrypto.checkEnabledCompressionMethods(methods);
    }

    /**
     * This method enables session ticket support.
     *
     * @param useSessionTickets True to enable session tickets
     */
    public void setUseSessionTickets(boolean useSessionTickets) {
        this.useSessionTickets = useSessionTickets;
    }

    /**
     * This method gives true back if the SSL socket is set to client mode.
     *
     * @return true if the socket should do the handshaking as client.
     */
    public boolean getUseSessionTickets() {
        return useSessionTickets;
    }

    /**
     * This method enables Server Name Indication
     *
     * @param hostname the desired SNI hostname, or null to disable
     */
    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    /**
     * This method returns the current SNI hostname
     *
     * @return a host name if SNI is enabled, or null otherwise
     */
    public String getHostname() {
        return hostname;
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
     * @param mode true if the socket starts in client
     *            mode
     * @throws IllegalArgumentException if mode changes during
     *             handshake.
     */
    @Override
    public void setUseClientMode(boolean mode) {
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
    @Override
    public boolean getWantClientAuth() {
        return sslParameters.getWantClientAuth();
    }

    /**
     * Returns true if the SSL socket needs client's authentication. Relevant
     * only for server sockets!
     *
     * @return true if client authentication is desired, false if not.
     */
    @Override
    public boolean getNeedClientAuth() {
        return sslParameters.getNeedClientAuth();
    }

    /**
     * Sets the SSL socket to use client's authentication. Relevant only for
     * server sockets!
     *
     * @param need true if client authentication is
     *            desired, false if not.
     */
    @Override
    public void setNeedClientAuth(boolean need) {
        sslParameters.setNeedClientAuth(need);
    }

    /**
     * Sets the SSL socket to use client's authentication. Relevant only for
     * server sockets! Notice that in contrast to setNeedClientAuth(..) this
     * method will continue the negotiation if the client decide not to send
     * authentication credentials.
     *
     * @param want true if client authentication is
     *            desired, false if not.
     */
    @Override
    public void setWantClientAuth(boolean want) {
        sslParameters.setWantClientAuth(want);
    }

    /**
     * This method is not supported for SSLSocket implementation.
     */
    @Override
    public void sendUrgentData(int data) throws IOException {
        throw new SocketException(
                "Method sendUrgentData() is not supported.");
    }

    /**
     * This method is not supported for SSLSocket implementation.
     */
    @Override
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
    @Override
    public void setSoTimeout(int timeoutMilliseconds) throws SocketException {
        super.setSoTimeout(timeoutMilliseconds);
        this.timeoutMilliseconds = timeoutMilliseconds;
    }

    @Override
    public int getSoTimeout() throws SocketException {
        return timeoutMilliseconds;
    }

    // BEGIN android-added
    /**
     * Set the handshake timeout on this socket.  This timeout is specified in
     * milliseconds and will be used only during the handshake process.
     *
     * @param timeout the handshake timeout value
     */
    public void setHandshakeTimeout(int timeoutMilliseconds) throws SocketException {
        this.handshakeTimeoutMilliseconds = timeoutMilliseconds;
    }
    // END android-added

    /**
     * Closes the SSL socket. Once closed, a socket is not available for further
     * use anymore under any circumstance. A new socket must be created.
     *
     * @throws <code>IOException</code> if an I/O error happens during the
     *             socket's closure.
     */
    @Override
    public void close() throws IOException {
        // TODO: Close SSL sockets using a background thread so they close
        // gracefully.

        synchronized (handshakeLock) {
            if (!handshakeStarted) {
                // prevent further attemps to start handshake
                handshakeStarted = true;

                synchronized (this) {
                    free();

                    if (socket != this) {
                        if (autoClose && !socket.isClosed()) socket.close();
                    } else {
                        if (!super.isClosed()) super.close();
                    }
                }

                return;
            }
        }

        NativeCrypto.SSL_interrupt(sslNativePointer);

        synchronized (this) {
            synchronized (writeLock) {
                synchronized (readLock) {

                    // Shut down the SSL connection, per se.
                    try {
                        if (handshakeStarted) {
                            BlockGuard.getThreadPolicy().onNetwork();
                            NativeCrypto.SSL_shutdown(sslNativePointer, fd, this);
                        }
                    } catch (IOException ignored) {
                        /*
                         * Note that although close() can throw
                         * IOException, the RI does not throw if there
                         * is problem sending a "close notify" which
                         * can happen if the underlying socket is closed.
                         */
                    }

                    /*
                     * Even if the above call failed, it is still safe to free
                     * the native structs, and we need to do so lest we leak
                     * memory.
                     */
                    free();

                    if (socket != this) {
                        if (autoClose && !socket.isClosed())
                            socket.close();
                    } else {
                        if (!super.isClosed())
                            super.close();
                    }
                }
            }
        }
    }

    private void free() {
        if (sslNativePointer == 0) {
            return;
        }
        NativeCrypto.SSL_free(sslNativePointer);
        sslNativePointer = 0;
    }

    @Override protected void finalize() throws Throwable {
        try {
            /*
             * Just worry about our own state. Notably we do not try and
             * close anything. The SocketImpl, either our own
             * PlainSocketImpl, or the Socket we are wrapping, will do
             * that. This might mean we do not properly SSL_shutdown, but
             * if you want to do that, properly close the socket yourself.
             *
             * The reason why we don't try to SSL_shutdown, is that there
             * can be a race between finalizers where the PlainSocketImpl
             * finalizer runs first and closes the socket. However, in the
             * meanwhile, the underlying file descriptor could be reused
             * for another purpose. If we call SSL_shutdown, the
             * underlying socket BIOs still have the old file descriptor
             * and will write the close notify to some unsuspecting
             * reader.
             */
            updateInstanceCount(-1);
            free();
        } finally {
            super.finalize();
        }
    }
}
