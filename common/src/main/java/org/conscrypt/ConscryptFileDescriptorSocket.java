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

import static org.conscrypt.SSLUtils.EngineStates.STATE_CLOSED;
import static org.conscrypt.SSLUtils.EngineStates.STATE_HANDSHAKE_STARTED;
import static org.conscrypt.SSLUtils.EngineStates.STATE_NEW;
import static org.conscrypt.SSLUtils.EngineStates.STATE_READY;
import static org.conscrypt.SSLUtils.EngineStates.STATE_READY_HANDSHAKE_CUT_THROUGH;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import org.conscrypt.NativeRef.SSL_SESSION;

/**
 * Implementation of the class OpenSSLSocketImpl based on OpenSSL.
 * <p>
 * Extensions to SSLSocket include:
 * <ul>
 * <li>handshake timeout
 * <li>session tickets
 * <li>Server Name Indication
 * </ul>
 */
final class ConscryptFileDescriptorSocket extends OpenSSLSocketImpl
        implements NativeCrypto.SSLHandshakeCallbacks, SSLParametersImpl.AliasChooser,
                   SSLParametersImpl.PSKCallbacks {
    private static final boolean DBG_STATE = false;

    /**
     * Protects handshakeStarted and handshakeCompleted.
     */
    private final Object stateLock = new Object();

    // @GuardedBy("stateLock");
    private int state = STATE_NEW;

    /**
     * Protected by synchronizing on stateLock. Starts as 0, set by
     * startHandshake, reset to 0 on close.
     */
    // @GuardedBy("stateLock");
    private final SslWrapper ssl;

    /**
     * Protected by synchronizing on stateLock. Starts as null, set by
     * getInputStream.
     */
    // @GuardedBy("stateLock");
    private SSLInputStream is;

    /**
     * Protected by synchronizing on stateLock. Starts as null, set by
     * getInputStream.
     */
    // @GuardedBy("stateLock");
    private SSLOutputStream os;

    private final SSLParametersImpl sslParameters;

    /*
     * A CloseGuard object on Android. On other platforms, this is nothing.
     */
    private final Object guard = Platform.closeGuardGet();

    /**
     * Private key for the TLS Channel ID extension. This field is client-side
     * only. Set during startHandshake.
     */
    private OpenSSLKey channelIdPrivateKey;

    private final ActiveSession sslSession;

    private int writeTimeoutMilliseconds = 0;
    private int handshakeTimeoutMilliseconds = -1; // -1 = same as timeout; 0 = infinite

    ConscryptFileDescriptorSocket(SSLParametersImpl sslParameters) throws IOException {
        this.sslParameters = sslParameters;
        this.ssl = newSsl(sslParameters, this);
        sslSession = new ActiveSession(ssl, sslParameters.getSessionContext());
    }

    ConscryptFileDescriptorSocket(String hostname, int port, SSLParametersImpl sslParameters)
            throws IOException {
        super(hostname, port);
        this.sslParameters = sslParameters;
        this.ssl = newSsl(sslParameters, this);
        sslSession = new ActiveSession(ssl, sslParameters.getSessionContext());
    }

    ConscryptFileDescriptorSocket(InetAddress address, int port, SSLParametersImpl sslParameters)
            throws IOException {
        super(address, port);
        this.sslParameters = sslParameters;
        this.ssl = newSsl(sslParameters, this);
        sslSession = new ActiveSession(ssl, sslParameters.getSessionContext());
    }

    ConscryptFileDescriptorSocket(String hostname, int port, InetAddress clientAddress,
            int clientPort, SSLParametersImpl sslParameters) throws IOException {
        super(hostname, port, clientAddress, clientPort);
        this.sslParameters = sslParameters;
        this.ssl = newSsl(sslParameters, this);
        sslSession = new ActiveSession(ssl, sslParameters.getSessionContext());
    }

    ConscryptFileDescriptorSocket(InetAddress address, int port, InetAddress clientAddress,
            int clientPort, SSLParametersImpl sslParameters) throws IOException {
        super(address, port, clientAddress, clientPort);
        this.sslParameters = sslParameters;
        this.ssl = newSsl(sslParameters, this);
        sslSession = new ActiveSession(ssl, sslParameters.getSessionContext());
    }

    ConscryptFileDescriptorSocket(Socket socket, String hostname, int port, boolean autoClose,
            SSLParametersImpl sslParameters) throws IOException {
        super(socket, hostname, port, autoClose);
        this.sslParameters = sslParameters;
        this.ssl = newSsl(sslParameters, this);
        sslSession = new ActiveSession(ssl, sslParameters.getSessionContext());
    }

    private static SslWrapper newSsl(SSLParametersImpl sslParameters,
            ConscryptFileDescriptorSocket engine) {
        try {
            return SslWrapper.newInstance(sslParameters, engine, engine, engine);
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Starts a TLS/SSL handshake on this connection using some native methods
     * from the OpenSSL library. It can negotiate new encryption keys, change
     * cipher suites, or initiate a new session. The certificate chain is
     * verified if the correspondent property in java.Security is set. All
     * listeners are notified at the end of the TLS/SSL handshake.
     */
    @Override
    public void startHandshake() throws IOException {
        checkOpen();
        synchronized (stateLock) {
            if (state == STATE_NEW) {
                state = STATE_HANDSHAKE_STARTED;
            } else {
                // We've either started the handshake already or have been closed.
                // Do nothing in both cases.
                return;
            }
        }

        boolean releaseResources = true;
        try {
            Platform.closeGuardOpen(guard, "close");

            // Prepare the SSL object for the handshake.
            ssl.initialize(getHostname(), channelIdPrivateKey);

            // For clients, offer to resume a previously cached session to avoid the
            // full TLS handshake.
            if (getUseClientMode()) {
                SslSessionWrapper cachedSession = clientSessionContext().getCachedSession(
                        getHostnameOrIP(), getPort(), sslParameters);
                if (cachedSession != null) {
                    cachedSession.offerToResume(ssl);
                }
            }

            // Temporarily use a different timeout for the handshake process
            int savedReadTimeoutMilliseconds = getSoTimeout();
            int savedWriteTimeoutMilliseconds = getSoWriteTimeout();
            if (handshakeTimeoutMilliseconds >= 0) {
                setSoTimeout(handshakeTimeoutMilliseconds);
                setSoWriteTimeout(handshakeTimeoutMilliseconds);
            }

            synchronized (stateLock) {
                if (state == STATE_CLOSED) {
                    return;
                }
            }

            try {
                ssl.doHandshake(Platform.getFileDescriptor(socket), getSoTimeout());
            } catch (CertificateException e) {
                SSLHandshakeException wrapper = new SSLHandshakeException(e.getMessage());
                wrapper.initCause(e);
                throw wrapper;
            } catch (SSLException e) {
                // Swallow this exception if it's thrown as the result of an interruption.
                //
                // TODO: SSL_read and SSL_write return -1 when interrupted, but SSL_do_handshake
                // will throw the last sslError that it saw before sslSelect, usually SSL_WANT_READ
                // (or WANT_WRITE). Catching that exception here doesn't seem much worse than
                // changing the native code to return a "special" native pointer value when that
                // happens.
                synchronized (stateLock) {
                    if (state == STATE_CLOSED) {
                        return;
                    }
                }

                // Write CCS errors to EventLog
                String message = e.getMessage();
                // Must match error string of SSL_R_UNEXPECTED_CCS
                if (message.contains("unexpected CCS")) {
                    String logMessage =
                            String.format("ssl_unexpected_ccs: host=%s", getHostnameOrIP());
                    Platform.logEvent(logMessage);
                }

                throw e;
            }

            synchronized (stateLock) {
                if (state == STATE_CLOSED) {
                    return;
                }
            }

            // Restore the original timeout now that the handshake is complete
            if (handshakeTimeoutMilliseconds >= 0) {
                setSoTimeout(savedReadTimeoutMilliseconds);
                setSoWriteTimeout(savedWriteTimeoutMilliseconds);
            }

            synchronized (stateLock) {
                releaseResources = (state == STATE_CLOSED);

                if (state == STATE_HANDSHAKE_STARTED) {
                    state = STATE_READY_HANDSHAKE_CUT_THROUGH;
                } else {
                    state = STATE_READY;
                }

                if (!releaseResources) {
                    // Unblock threads that are waiting for our state to transition
                    // into STATE_READY or STATE_READY_HANDSHAKE_CUT_THROUGH.
                    stateLock.notifyAll();
                }
            }
        } catch (SSLProtocolException e) {
            throw(SSLHandshakeException) new SSLHandshakeException("Handshake failed").initCause(e);
        } finally {
            // on exceptional exit, treat the socket as closed
            if (releaseResources) {
                synchronized (stateLock) {
                    // Mark the socket as closed since we might have reached this as
                    // a result on an exception thrown by the handshake process.
                    //
                    // The state will already be set to closed if we reach this as a result of
                    // an early return or an interruption due to a concurrent call to close().
                    state = STATE_CLOSED;
                    stateLock.notifyAll();
                }

                try {
                    shutdownAndFreeSslNative();
                } catch (IOException ignored) {
                    // Ignored.
                }
            }
        }
    }

    @Override
    @SuppressWarnings("unused") // used by NativeCrypto.SSLHandshakeCallbacks / client_cert_cb
    public void clientCertificateRequested(byte[] keyTypeBytes, byte[][] asn1DerEncodedPrincipals)
            throws CertificateEncodingException, SSLException {
        ssl.chooseClientCertificate(keyTypeBytes, asn1DerEncodedPrincipals);
    }

    @Override
    @SuppressWarnings("unused") // used by native psk_client_callback
    public int clientPSKKeyRequested(String identityHint, byte[] identity, byte[] key) {
        return ssl.clientPSKKeyRequested(identityHint, identity, key);
    }

    @Override
    @SuppressWarnings("unused") // used by native psk_server_callback
    public int serverPSKKeyRequested(String identityHint, String identity, byte[] key) {
        return ssl.serverPSKKeyRequested(identityHint, identity, key);
    }

    @Override
    @SuppressWarnings("unused") // used by NativeCrypto.SSLHandshakeCallbacks / info_callback
    public void onSSLStateChange(int type, int val) {
        if (type != NativeConstants.SSL_CB_HANDSHAKE_DONE) {
            // We only care about successful completion.
            return;
        }

        // The handshake has completed successfully ...

        // Update the session from the current state of the SSL object.
        sslSession.onSessionEstablished(getHostnameOrIP(), getPort());

        // First, update the state.
        synchronized (stateLock) {
            if (state == STATE_CLOSED) {
                // Someone called "close" but the handshake hasn't been interrupted yet.
                return;
            }

            // Now that we've fixed up our state, we can tell waiting threads that
            // we're ready.
            state = STATE_READY;
        }

        // Let listeners know we are finally done
        notifyHandshakeCompletedListeners();

        synchronized (stateLock) {
            // Notify all threads waiting for the handshake to complete.
            stateLock.notifyAll();
        }
    }

    @Override
    @SuppressWarnings("unused") // used by NativeCrypto.SSLHandshakeCallbacks / new_session_callback
    public void onNewSessionEstablished(long sslSessionNativePtr) {
        try {
            // Increment the reference count to "take ownership" of the session resource.
            NativeCrypto.SSL_SESSION_up_ref(sslSessionNativePtr);

            // Create a native reference which will release the SSL_SESSION in its finalizer.
            // This constructor will only throw if the native pointer passed in is NULL, which
            // BoringSSL guarantees will not happen.
            NativeRef.SSL_SESSION ref = new SSL_SESSION(sslSessionNativePtr);

            SslSessionWrapper sessionWrapper = SslSessionWrapper.newInstance(ref, sslSession);

            // Cache the newly established session.
            AbstractSessionContext ctx = sessionContext();
            ctx.cacheSession(sessionWrapper);
        } catch (Exception ignored) {
            // Ignore.
        }
    }

    @Override
    public long serverSessionRequested(byte[] id) {
        // TODO(nathanmittler): Implement server-side caching for TLS < 1.3
        return 0;
    }

    @SuppressWarnings("unused") // used by NativeCrypto.SSLHandshakeCallbacks
    @Override
    public void verifyCertificateChain(long[] certRefs, String authMethod)
            throws CertificateException {
        try {
            X509TrustManager x509tm = sslParameters.getX509TrustManager();
            if (x509tm == null) {
                throw new CertificateException("No X.509 TrustManager");
            }
            if (certRefs == null || certRefs.length == 0) {
                throw new SSLException("Peer sent no certificate");
            }
            OpenSSLX509Certificate[] peerCertChain =
                    OpenSSLX509Certificate.createCertChain(certRefs);

            // Update the peer information on the session.
            sslSession.onPeerCertificatesReceived(getHostnameOrIP(), getPort(), peerCertChain);

            if (getUseClientMode()) {
                Platform.checkServerTrusted(x509tm, peerCertChain, authMethod, this);
            } else {
                String authType = peerCertChain[0].getPublicKey().getAlgorithm();
                Platform.checkClientTrusted(x509tm, peerCertChain, authType, this);
            }
        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException(e);
        }
    }

    @Override
    public InputStream getInputStream() throws IOException {
        checkOpen();

        InputStream returnVal;
        synchronized (stateLock) {
            if (state == STATE_CLOSED) {
                throw new SocketException("Socket is closed.");
            }

            if (is == null) {
                is = new SSLInputStream();
            }

            returnVal = is;
        }

        // Block waiting for a handshake without a lock held. It's possible that the socket
        // is closed at this point. If that happens, we'll still return the input stream but
        // all reads on it will throw.
        waitForHandshake();
        return returnVal;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        checkOpen();

        OutputStream returnVal;
        synchronized (stateLock) {
            if (state == STATE_CLOSED) {
                throw new SocketException("Socket is closed.");
            }

            if (os == null) {
                os = new SSLOutputStream();
            }

            returnVal = os;
        }

        // Block waiting for a handshake without a lock held. It's possible that the socket
        // is closed at this point. If that happens, we'll still return the output stream but
        // all writes on it will throw.
        waitForHandshake();
        return returnVal;
    }

    private void assertReadableOrWriteableState() {
        if (state == STATE_READY || state == STATE_READY_HANDSHAKE_CUT_THROUGH) {
            return;
        }

        throw new AssertionError("Invalid state: " + state);
    }

    private void waitForHandshake() throws IOException {
        startHandshake();

        synchronized (stateLock) {
            while (state != STATE_READY &&
                    state != STATE_READY_HANDSHAKE_CUT_THROUGH &&
                    state != STATE_CLOSED) {
                try {
                    stateLock.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted waiting for handshake", e);
                }
            }

            if (state == STATE_CLOSED) {
                throw new SocketException("Socket is closed");
            }
        }
    }

    /**
     * This inner class provides input data stream functionality
     * for the OpenSSL native implementation. It is used to
     * read data received via SSL protocol.
     */
    private class SSLInputStream extends InputStream {
        /**
         * OpenSSL only lets one thread read at a time, so this is used to
         * make sure we serialize callers of SSL_read. Thread is already
         * expected to have completed handshaking.
         */
        private final Object readLock = new Object();

        SSLInputStream() {
        }

        /**
         * Reads one byte. If there is no data in the underlying buffer,
         * this operation can block until the data will be
         * available.
         */
        @Override
        public int read() throws IOException {
            byte[] buffer = new byte[1];
            int result = read(buffer, 0, 1);
            return (result != -1) ? buffer[0] & 0xff : -1;
        }

        /**
         * Method acts as described in spec for superclass.
         * @see java.io.InputStream#read(byte[],int,int)
         */
        @Override
        public int read(byte[] buf, int offset, int byteCount) throws IOException {
            Platform.blockGuardOnNetwork();

            checkOpen();
            ArrayUtils.checkOffsetAndCount(buf.length, offset, byteCount);
            if (byteCount == 0) {
                return 0;
            }

            synchronized (readLock) {
                synchronized (stateLock) {
                    if (state == STATE_CLOSED) {
                        throw new SocketException("socket is closed");
                    }

                    if (DBG_STATE) {
                        assertReadableOrWriteableState();
                    }
                }

                int ret =  ssl.read(
                        Platform.getFileDescriptor(socket), buf, offset, byteCount, getSoTimeout());
                if (ret == -1) {
                    synchronized (stateLock) {
                        if (state == STATE_CLOSED) {
                            throw new SocketException("socket is closed");
                        }
                    }
                }
                return ret;
            }
        }

        void awaitPendingOps() {
            if (DBG_STATE) {
                synchronized (stateLock) {
                    if (state != STATE_CLOSED) {
                        throw new AssertionError("State is: " + state);
                    }
                }
            }

            synchronized (readLock) {}
        }
    }

    /**
     * This inner class provides output data stream functionality
     * for the OpenSSL native implementation. It is used to
     * write data according to the encryption parameters given in SSL context.
     */
    private class SSLOutputStream extends OutputStream {
        /**
         * OpenSSL only lets one thread write at a time, so this is used
         * to make sure we serialize callers of SSL_write. Thread is
         * already expected to have completed handshaking.
         */
        private final Object writeLock = new Object();

        SSLOutputStream() {
        }

        /**
         * Method acts as described in spec for superclass.
         * @see java.io.OutputStream#write(int)
         */
        @Override
        public void write(int oneByte) throws IOException {
            byte[] buffer = new byte[1];
            buffer[0] = (byte) (oneByte & 0xff);
            write(buffer);
        }

        /**
         * Method acts as described in spec for superclass.
         * @see java.io.OutputStream#write(byte[],int,int)
         */
        @Override
        public void write(byte[] buf, int offset, int byteCount) throws IOException {
            Platform.blockGuardOnNetwork();
            checkOpen();
            ArrayUtils.checkOffsetAndCount(buf.length, offset, byteCount);
            if (byteCount == 0) {
                return;
            }

            synchronized (writeLock) {
                synchronized (stateLock) {
                    if (state == STATE_CLOSED) {
                        throw new SocketException("socket is closed");
                    }

                    if (DBG_STATE) {
                        assertReadableOrWriteableState();
                    }
                }

                ssl.write(Platform.getFileDescriptor(socket), buf, offset, byteCount,
                        writeTimeoutMilliseconds);

                synchronized (stateLock) {
                    if (state == STATE_CLOSED) {
                        throw new SocketException("socket is closed");
                    }
                }
            }
        }

        void awaitPendingOps() {
            if (DBG_STATE) {
                synchronized (stateLock) {
                    if (state != STATE_CLOSED) {
                        throw new AssertionError("State is: " + state);
                    }
                }
            }

            synchronized (writeLock) {}
        }
    }

    @Override
    public SSLSession getSession() {
        boolean handshakeCompleted = false;
        synchronized (stateLock) {
            try {
                handshakeCompleted = state >= STATE_READY;
                if (!handshakeCompleted && isConnected()) {
                    waitForHandshake();
                    handshakeCompleted = true;
                }
            } catch (IOException e) {
                // Fall through.
            }
        }

        if (!handshakeCompleted) {
            // return an invalid session with
            // invalid cipher suite of "SSL_NULL_WITH_NULL_NULL"
            return SSLNullSession.getNullSession();
        }

        return Platform.wrapSSLSession(sslSession);
    }

    @Override
    SSLSession getActiveSession() {
        return sslSession;
    }

    @Override
    public SSLSession getHandshakeSession() {
        synchronized (stateLock) {
            return state >= STATE_HANDSHAKE_STARTED && state < STATE_READY ? sslSession : null;
        }
    }

    @Override
    public boolean getEnableSessionCreation() {
        return sslParameters.getEnableSessionCreation();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslParameters.setEnableSessionCreation(flag);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return NativeCrypto.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return sslParameters.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        sslParameters.setEnabledCipherSuites(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return NativeCrypto.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return sslParameters.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        sslParameters.setEnabledProtocols(protocols);
    }

    /**
     * This method enables session ticket support.
     *
     * @param useSessionTickets True to enable session tickets
     */
    @Override
    public void setUseSessionTickets(boolean useSessionTickets) {
        sslParameters.setUseSessionTickets(useSessionTickets);
    }

    /**
     * This method enables Server Name Indication
     *
     * @param hostname the desired SNI hostname, or null to disable
     */
    @Override
    public void setHostname(String hostname) {
        sslParameters.setUseSni(hostname != null);
        super.setHostname(hostname);
    }

    /**
     * Enables/disables TLS Channel ID for this server socket.
     *
     * <p>This method needs to be invoked before the handshake starts.
     *
     * @throws IllegalStateException if this is a client socket or if the handshake has already
     *         started.
     */
    @Override
    public void setChannelIdEnabled(boolean enabled) {
        if (getUseClientMode()) {
            throw new IllegalStateException("Client mode");
        }

        synchronized (stateLock) {
            if (state != STATE_NEW) {
                throw new IllegalStateException(
                        "Could not enable/disable Channel ID after the initial handshake has"
                                + " begun.");
            }
        }
        sslParameters.channelIdEnabled = enabled;
    }

    /**
     * Gets the TLS Channel ID for this server socket. Channel ID is only available once the
     * handshake completes.
     *
     * @return channel ID or {@code null} if not available.
     *
     * @throws IllegalStateException if this is a client socket or if the handshake has not yet
     *         completed.
     * @throws SSLException if channel ID is available but could not be obtained.
     */
    @Override
    public byte[] getChannelId() throws SSLException {
        if (getUseClientMode()) {
            throw new IllegalStateException("Client mode");
        }

        synchronized (stateLock) {
            if (state != STATE_READY) {
                throw new IllegalStateException(
                        "Channel ID is only available after handshake completes");
            }
        }
        return ssl.getTlsChannelId();
    }

    /**
     * Sets the {@link PrivateKey} to be used for TLS Channel ID by this client socket.
     *
     * <p>This method needs to be invoked before the handshake starts.
     *
     * @param privateKey private key (enables TLS Channel ID) or {@code null} for no key (disables
     *        TLS Channel ID). The private key must be an Elliptic Curve (EC) key based on the NIST
     *        P-256 curve (aka SECG secp256r1 or ANSI X9.62 prime256v1).
     *
     * @throws IllegalStateException if this is a server socket or if the handshake has already
     *         started.
     */
    @Override
    public void setChannelIdPrivateKey(PrivateKey privateKey) {
        if (!getUseClientMode()) {
            throw new IllegalStateException("Server mode");
        }

        synchronized (stateLock) {
            if (state != STATE_NEW) {
                throw new IllegalStateException(
                        "Could not change Channel ID private key after the initial handshake has"
                                + " begun.");
            }
        }

        if (privateKey == null) {
            sslParameters.channelIdEnabled = false;
            channelIdPrivateKey = null;
        } else {
            sslParameters.channelIdEnabled = true;
            try {
                ECParameterSpec ecParams = null;
                if (privateKey instanceof ECKey) {
                    ecParams = ((ECKey) privateKey).getParams();
                }
                if (ecParams == null) {
                    // Assume this is a P-256 key, as specified in the contract of this method.
                    ecParams =
                            OpenSSLECGroupContext.getCurveByName("prime256v1").getECParameterSpec();
                }
                channelIdPrivateKey =
                        OpenSSLKey.fromECPrivateKeyForTLSStackOnly(privateKey, ecParams);
            } catch (InvalidKeyException e) {
                // Will have error in startHandshake
            }
        }
    }

    @Override
    public boolean getUseClientMode() {
        return sslParameters.getUseClientMode();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        synchronized (stateLock) {
            if (state != STATE_NEW) {
                throw new IllegalArgumentException(
                        "Could not change the mode after the initial handshake has begun.");
            }
        }
        sslParameters.setUseClientMode(mode);
    }

    @Override
    public boolean getWantClientAuth() {
        return sslParameters.getWantClientAuth();
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        sslParameters.setNeedClientAuth(need);
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslParameters.setWantClientAuth(want);
    }

    /**
     * Note write timeouts are not part of the javax.net.ssl.SSLSocket API
     */
    @Override
    public void setSoWriteTimeout(int writeTimeoutMilliseconds) throws SocketException {
        this.writeTimeoutMilliseconds = writeTimeoutMilliseconds;

        Platform.setSocketWriteTimeout(this, writeTimeoutMilliseconds);
    }

    /**
     * Note write timeouts are not part of the javax.net.ssl.SSLSocket API
     */
    @Override
    public int getSoWriteTimeout() throws SocketException {
        return writeTimeoutMilliseconds;
    }

    /**
     * Set the handshake timeout on this socket.  This timeout is specified in
     * milliseconds and will be used only during the handshake process.
     */
    @Override
    public void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException {
        this.handshakeTimeoutMilliseconds = handshakeTimeoutMilliseconds;
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void close() throws IOException {
        // TODO: Close SSL sockets using a background thread so they close gracefully.

        SSLInputStream sslInputStream;
        SSLOutputStream sslOutputStream;

        synchronized (stateLock) {
            if (state == STATE_CLOSED) {
                // close() has already been called, so do nothing and return.
                return;
            }

            int oldState = state;
            state = STATE_CLOSED;

            if (oldState == STATE_NEW) {
                // The handshake hasn't been started yet, so there's no OpenSSL related
                // state to clean up. We still need to close the underlying socket if
                // we're wrapping it and were asked to autoClose.
                free();
                closeUnderlyingSocket();

                stateLock.notifyAll();
                return;
            }

            if (oldState != STATE_READY && oldState != STATE_READY_HANDSHAKE_CUT_THROUGH) {
                // If we're in these states, we still haven't returned from startHandshake.
                // We call SSL_interrupt so that we can interrupt SSL_do_handshake and then
                // set the state to STATE_CLOSED. startHandshake will handle all cleanup
                // after SSL_do_handshake returns, so we don't have anything to do here.
                ssl.interrupt();

                stateLock.notifyAll();
                return;
            }

            stateLock.notifyAll();
            // We've already returned from startHandshake, so we potentially have
            // input and output streams to clean up.
            sslInputStream = is;
            sslOutputStream = os;
        }

        // Don't bother interrupting unless we have something to interrupt.
        if (sslInputStream != null || sslOutputStream != null) {
            ssl.interrupt();
        }

        // Wait for the input and output streams to finish any reads they have in
        // progress. If there are no reads in progress at this point, future reads will
        // throw because state == STATE_CLOSED
        if (sslInputStream != null) {
            sslInputStream.awaitPendingOps();
        }
        if (sslOutputStream != null) {
            sslOutputStream.awaitPendingOps();
        }

        shutdownAndFreeSslNative();
    }

    private void shutdownAndFreeSslNative() throws IOException {
        try {
            Platform.blockGuardOnNetwork();
            ssl.shutdown(Platform.getFileDescriptor(socket));
        } catch (IOException ignored) {
            /*
             * Note that although close() can throw
             * IOException, the RI does not throw if there
             * is problem sending a "close notify" which
             * can happen if the underlying socket is closed.
             */
        } finally {
            free();
            closeUnderlyingSocket();
        }
    }

    private void closeUnderlyingSocket() throws IOException {
        super.close();
    }

    private void free() {
        if (!ssl.isClosed()) {
            ssl.close();
            Platform.closeGuardClose(guard);
        }
    }

    @Override
    protected void finalize() throws Throwable {
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
            if (guard != null) {
                Platform.closeGuardWarnIfOpen(guard);
            }
            free();
        } finally {
            super.finalize();
        }
    }

    /**
     * Returns the protocol agreed upon by client and server, or {@code null} if
     * no protocol was agreed upon.
     */
    @Override
    public byte[] getAlpnSelectedProtocol() {
        return ssl.getAlpnSelectedProtocol();
    }

    /**
     * Sets the list of ALPN protocols. This method internally converts the protocols to their
     * wire-format form.
     *
     * @param alpnProtocols the list of ALPN protocols
     * @see #setAlpnProtocols(byte[])
     */
    @Override
    public void setAlpnProtocols(String[] alpnProtocols) {
        sslParameters.setAlpnProtocols(alpnProtocols);
    }

    /**
     * Alternate version of {@link #setAlpnProtocols(String[])} that directly sets the list of
     * ALPN in the wire-format form used by BoringSSL (length-prefixed 8-bit strings).
     * Requires that all strings be encoded with US-ASCII.
     *
     * @param alpnProtocols the encoded form of the ALPN protocol list
     * @see #setAlpnProtocols(String[])
     */
    @Override
    public void setAlpnProtocols(byte[] alpnProtocols) {
        sslParameters.setAlpnProtocols(alpnProtocols);
    }

    @Override
    public SSLParameters getSSLParameters() {
        SSLParameters params = super.getSSLParameters();
        Platform.getSSLParameters(params, sslParameters, this);
        return params;
    }

    @Override
    public void setSSLParameters(SSLParameters p) {
        super.setSSLParameters(p);
        Platform.setSSLParameters(p, sslParameters, this);
    }

    @Override
    public String chooseServerAlias(X509KeyManager keyManager, String keyType) {
        return keyManager.chooseServerAlias(keyType, null, this);
    }

    @Override
    public String chooseClientAlias(X509KeyManager keyManager, X500Principal[] issuers,
            String[] keyTypes) {
        return keyManager.chooseClientAlias(keyTypes, null, this);
    }

    @Override
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    public String chooseServerPSKIdentityHint(PSKKeyManager keyManager) {
        return keyManager.chooseServerKeyIdentityHint(this);
    }

    @Override
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    public String chooseClientPSKIdentity(PSKKeyManager keyManager, String identityHint) {
        return keyManager.chooseClientKeyIdentity(identityHint, this);
    }

    @Override
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    public SecretKey getPSKKey(PSKKeyManager keyManager, String identityHint, String identity) {
        return keyManager.getKey(identityHint, identity, this);
    }

    private ClientSessionContext clientSessionContext() {
        return sslParameters.getClientSessionContext();
    }

    private AbstractSessionContext sessionContext() {
        return sslParameters.getSessionContext();
    }
}
