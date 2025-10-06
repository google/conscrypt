/*
 * Copyright 2013 The Android Open Source Project
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

/*
 * Copyright 2016 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.conscrypt;

import static java.lang.Math.max;
import static java.lang.Math.min;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.FINISHED;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NEED_WRAP;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
import static javax.net.ssl.SSLEngineResult.Status.BUFFER_OVERFLOW;
import static javax.net.ssl.SSLEngineResult.Status.BUFFER_UNDERFLOW;
import static javax.net.ssl.SSLEngineResult.Status.CLOSED;
import static javax.net.ssl.SSLEngineResult.Status.OK;
import static org.conscrypt.NativeConstants.SSL3_RT_HEADER_LENGTH;
import static org.conscrypt.NativeConstants.SSL3_RT_MAX_PACKET_SIZE;
import static org.conscrypt.NativeConstants.SSL3_RT_MAX_PLAIN_LENGTH;
import static org.conscrypt.NativeConstants.SSL_CB_HANDSHAKE_DONE;
import static org.conscrypt.NativeConstants.SSL_CB_HANDSHAKE_START;
import static org.conscrypt.NativeConstants.SSL_ERROR_WANT_READ;
import static org.conscrypt.NativeConstants.SSL_ERROR_WANT_WRITE;
import static org.conscrypt.NativeConstants.SSL_ERROR_ZERO_RETURN;
import static org.conscrypt.Preconditions.checkArgument;
import static org.conscrypt.Preconditions.checkNotNull;
import static org.conscrypt.Preconditions.checkPositionIndexes;
import static org.conscrypt.SSLUtils.EngineStates.STATE_CLOSED;
import static org.conscrypt.SSLUtils.EngineStates.STATE_CLOSED_INBOUND;
import static org.conscrypt.SSLUtils.EngineStates.STATE_CLOSED_OUTBOUND;
import static org.conscrypt.SSLUtils.EngineStates.STATE_HANDSHAKE_COMPLETED;
import static org.conscrypt.SSLUtils.EngineStates.STATE_HANDSHAKE_STARTED;
import static org.conscrypt.SSLUtils.EngineStates.STATE_MODE_SET;
import static org.conscrypt.SSLUtils.EngineStates.STATE_NEW;
import static org.conscrypt.SSLUtils.EngineStates.STATE_READY;
import static org.conscrypt.SSLUtils.EngineStates.STATE_READY_HANDSHAKE_CUT_THROUGH;
import static org.conscrypt.SSLUtils.calculateOutNetBufSize;
import static org.conscrypt.SSLUtils.toSSLHandshakeException;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import org.conscrypt.NativeRef.SSL_SESSION;
import org.conscrypt.NativeSsl.BioWrapper;
import org.conscrypt.SSLParametersImpl.AliasChooser;

/**
 * Implements the {@link SSLEngine} API using OpenSSL's non-blocking interfaces.
 */
final class ConscryptEngine extends AbstractConscryptEngine implements NativeCrypto.SSLHandshakeCallbacks,
                                                         SSLParametersImpl.AliasChooser,
                                                         SSLParametersImpl.PSKCallbacks {

    private static final SSLEngineResult NEED_UNWRAP_OK =
            new SSLEngineResult(OK, NEED_UNWRAP, 0, 0);
    private static final SSLEngineResult NEED_UNWRAP_CLOSED =
            new SSLEngineResult(CLOSED, NEED_UNWRAP, 0, 0);
    private static final SSLEngineResult NEED_WRAP_OK = new SSLEngineResult(OK, NEED_WRAP, 0, 0);
    private static final SSLEngineResult NEED_WRAP_CLOSED =
            new SSLEngineResult(CLOSED, NEED_WRAP, 0, 0);
    private static final SSLEngineResult CLOSED_NOT_HANDSHAKING =
            new SSLEngineResult(CLOSED, NOT_HANDSHAKING, 0, 0);

    private static BufferAllocator defaultBufferAllocator = null;

    private final SSLParametersImpl sslParameters;
    private BufferAllocator bufferAllocator = defaultBufferAllocator;

    /**
     * A lazy-created direct buffer used as a bridge between heap buffers provided by the
     * application and JNI. This avoids the overhead of calling JNI with heap buffers.
     * Used only when no {@link #bufferAllocator} has been provided.
     */
    private ByteBuffer lazyDirectBuffer;

    /**
     * Hostname used with the TLS extension SNI hostname.
     */
    private String peerHostname;

    // @GuardedBy("ssl");
    private int state = STATE_NEW;
    private boolean handshakeFinished;

    /**
     * Wrapper around the underlying SSL object.
     */
    private final NativeSsl ssl;

    /**
     * The BIO used for reading/writing encrypted bytes.
     */
    // @GuardedBy("ssl");
    private final BioWrapper networkBio;

    /**
     * Set during startHandshake.
     */
    private ActiveSession activeSession;

    /**
     * A snapshot of the active session when the engine was closed.
     */
    private SessionSnapshot closedSession;

    /**
     * The session object exposed externally from this class.
     */
    private final SSLSession externalSession =
        Platform.wrapSSLSession(new ExternalSession(new ExternalSession.Provider() {
            @Override
            public ConscryptSession provideSession() {
                return ConscryptEngine.this.provideSession();
            }
        }));

    /**
     * Private key for the TLS Channel ID extension. This field is client-side only. Set during
     * startHandshake.
     */
    private OpenSSLKey channelIdPrivateKey;

    private int maxSealOverhead;

    private HandshakeListener handshakeListener;

    private final ByteBuffer[] singleSrcBuffer = new ByteBuffer[1];
    private final ByteBuffer[] singleDstBuffer = new ByteBuffer[1];
    private final PeerInfoProvider peerInfoProvider;

    ConscryptEngine(SSLParametersImpl sslParameters) {
        this.sslParameters = sslParameters;
        peerInfoProvider = PeerInfoProvider.nullProvider();
        this.ssl = newSsl(sslParameters, this, this);
        this.networkBio = ssl.newBio();
    }

    ConscryptEngine(String host, int port, SSLParametersImpl sslParameters) {
        this.sslParameters = sslParameters;
        this.peerInfoProvider = PeerInfoProvider.forHostAndPort(host, port);
        this.ssl = newSsl(sslParameters, this, this);
        this.networkBio = ssl.newBio();
    }

    ConscryptEngine(SSLParametersImpl sslParameters, PeerInfoProvider peerInfoProvider,
        AliasChooser aliasChooser) {
        this.sslParameters = sslParameters;
        this.peerInfoProvider = checkNotNull(peerInfoProvider, "peerInfoProvider");
        this.ssl = newSsl(sslParameters, this, aliasChooser);
        this.networkBio = ssl.newBio();
    }

    private static NativeSsl newSsl(SSLParametersImpl sslParameters, ConscryptEngine engine,
        AliasChooser aliasChooser) {
        try {
            return NativeSsl.newInstance(sslParameters, engine, aliasChooser, engine);
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Configures the default {@link BufferAllocator} to be used by all future
     * {@link SSLEngine} and {@link ConscryptEngineSocket} instances from this provider.
     */
    static void setDefaultBufferAllocator(BufferAllocator bufferAllocator) {
        defaultBufferAllocator = bufferAllocator;
    }

    /**
     * Returns the default {@link BufferAllocator}, which may be {@code null} if no default
     * has been explicitly set.
     */
    static BufferAllocator getDefaultBufferAllocator() {
        return defaultBufferAllocator;
    }

    @Override
    void setBufferAllocator(BufferAllocator bufferAllocator) {
        synchronized (ssl) {
            if (isHandshakeStarted()) {
                throw new IllegalStateException(
                        "Could not set buffer allocator after the initial handshake has begun.");
            }
            this.bufferAllocator = bufferAllocator;
        }
    }

    /**
     * Returns the maximum overhead, in bytes, of sealing a record with SSL.
     */
    @Override
    int maxSealOverhead() {
        return maxSealOverhead;
    }

    /**
     * Enables/disables TLS Channel ID for this server engine.
     *
     * <p>This method needs to be invoked before the handshake starts.
     *
     * @throws IllegalStateException if this is a client engine or if the handshake has already
     *         started.
     */
    @Override
    void setChannelIdEnabled(boolean enabled) {
        synchronized (ssl) {
            if (getUseClientMode()) {
                throw new IllegalStateException("Not allowed in client mode");
            }
            if (isHandshakeStarted()) {
                throw new IllegalStateException(
                        "Could not enable/disable Channel ID after the initial handshake has begun.");
            }
            sslParameters.channelIdEnabled = enabled;
        }
    }

    /**
     * Gets the TLS Channel ID for this server engine. Channel ID is only available once the
     * handshake completes.
     *
     * @return channel ID or {@code null} if not available.
     *
     * @throws IllegalStateException if this is a client engine or if the handshake has not yet
     * completed.
     * @throws SSLException if channel ID is available but could not be obtained.
     */
    @Override
    byte[] getChannelId() throws SSLException {
        synchronized (ssl) {
            if (getUseClientMode()) {
                throw new IllegalStateException("Not allowed in client mode");
            }

            if (isHandshakeStarted()) {
                throw new IllegalStateException(
                        "Channel ID is only available after handshake completes");
            }
            return ssl.getTlsChannelId();
        }
    }

    /**
     * Sets the {@link PrivateKey} to be used for TLS Channel ID by this client engine.
     *
     * <p>This method needs to be invoked before the handshake starts.
     *
     * @param privateKey private key (enables TLS Channel ID) or {@code null} for no key (disables
     *        TLS Channel ID). The private key must be an Elliptic Curve (EC) key based on the NIST
     *        P-256 curve (aka SECG secp256r1 or ANSI X9.62 prime256v1).
     *
     * @throws IllegalStateException if this is a server engine or if the handshake has already
     *         started.
     */
    @Override
    void setChannelIdPrivateKey(PrivateKey privateKey) {
        if (!getUseClientMode()) {
            throw new IllegalStateException("Not allowed in server mode");
        }

        synchronized (ssl) {
            if (isHandshakeStarted()) {
                throw new IllegalStateException("Could not change Channel ID private key "
                        + "after the initial handshake has begun.");
            }

            if (privateKey == null) {
                sslParameters.channelIdEnabled = false;
                channelIdPrivateKey = null;
                return;
            }

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

    /**
     * Sets the listener for the completion of the TLS handshake.
     */
    @Override
    void setHandshakeListener(HandshakeListener handshakeListener) {
        synchronized (ssl) {
            if (isHandshakeStarted()) {
                throw new IllegalStateException(
                        "Handshake listener must be set before starting the handshake.");
            }
            this.handshakeListener = handshakeListener;
        }
    }

    private boolean isHandshakeStarted() {
        switch (state) {
            case STATE_NEW:
            case STATE_MODE_SET:
                return false;
            default:
                return true;
        }
    }

    /**
     * This method enables Server Name Indication (SNI) and overrides the {@link PeerInfoProvider}
     * supplied during engine creation.  If the hostname is not a valid SNI hostname, the SNI
     * extension will be omitted from the handshake.
     */
    @Override
    void setHostname(String hostname) {
        sslParameters.setUseSni(hostname != null);
        this.peerHostname = hostname;
    }

    /**
     * Returns the hostname from {@link #setHostname(String)} or supplied by the
     * {@link PeerInfoProvider} upon creation. No DNS resolution is attempted before
     * returning the hostname.
     */
    @Override
    String getHostname() {
        return peerHostname != null ? peerHostname : peerInfoProvider.getHostname();
    }

    @Override
    public String getPeerHost() {
        return peerHostname != null ? peerHostname : peerInfoProvider.getHostnameOrIP();
    }

    @Override
    public int getPeerPort() {
        return peerInfoProvider.getPort();
    }

    @Override
    public void beginHandshake() throws SSLException {
        synchronized (ssl) {
            beginHandshakeInternal();
        }
    }

    private void beginHandshakeInternal() throws SSLException {
        switch (state) {
            case STATE_NEW: {
                throw new IllegalStateException("Client/server mode must be set before handshake");
            }
            case STATE_MODE_SET: {
                // We know what mode to handshake in but have not started the handshake, proceed
                break;
            }
            case STATE_CLOSED_INBOUND:
            case STATE_CLOSED_OUTBOUND:
            case STATE_CLOSED:
                throw new SSLHandshakeException("Engine has already been closed");
            default:
                // We've already started the handshake, just return
                return;
        }

        transitionTo(STATE_HANDSHAKE_STARTED);

        boolean releaseResources = true;
        try {
            // Prepare the SSL object for the handshake.
            ssl.initialize(getHostname(), channelIdPrivateKey);

            // For clients, offer to resume a previously cached session to avoid the
            // full TLS handshake.
            if (getUseClientMode()) {
                NativeSslSession cachedSession = clientSessionContext().getCachedSession(
                        getHostname(), getPeerPort(), sslParameters);
                if (cachedSession != null) {
                    cachedSession.offerToResume(ssl);
                }
            }

            maxSealOverhead = ssl.getMaxSealOverhead();
            handshake();
            releaseResources = false;
        } catch (IOException e) {
            closeAll();
            throw SSLUtils.toSSLHandshakeException(e);
        } finally {
            if (releaseResources) {
                closeAndFreeResources();
            }
        }
    }

    @Override
    public void closeInbound() {
        synchronized (ssl) {
            if (state == STATE_CLOSED || state == STATE_CLOSED_INBOUND) {
                return;
            }
            if (isHandshakeStarted()) {
                if (state == STATE_CLOSED_OUTBOUND) {
                    transitionTo(STATE_CLOSED);
                } else {
                    transitionTo(STATE_CLOSED_INBOUND);
                }
                freeIfDone();
            } else {
                // Never started the handshake. Just close now.
                closeAndFreeResources();
            }
        }
    }

    @Override
    public void closeOutbound() {
        synchronized (ssl) {
            if (state == STATE_CLOSED || state == STATE_CLOSED_OUTBOUND) {
                return;
            }
            if (isHandshakeStarted()) {
                if (state == STATE_CLOSED_INBOUND) {
                    transitionTo(STATE_CLOSED);
                } else {
                    transitionTo(STATE_CLOSED_OUTBOUND);
                }
                sendSSLShutdown();
                freeIfDone();
            } else {
                // Never started the handshake. Just close now.
                closeAndFreeResources();
            }
        }
    }

    @Override
    public Runnable getDelegatedTask() {
        // This implementation doesn't use any delegated tasks.
        return null;
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return sslParameters.getEnabledCipherSuites();
    }

    @Override
    public String[] getEnabledProtocols() {
        return sslParameters.getEnabledProtocols();
    }

    @Override
    public boolean getEnableSessionCreation() {
        return sslParameters.getEnableSessionCreation();
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
    public HandshakeStatus getHandshakeStatus() {
        synchronized (ssl) {
            return getHandshakeStatusInternal();
        }
    }

    private HandshakeStatus getHandshakeStatusInternal() {
        if (handshakeFinished) {
            return HandshakeStatus.NOT_HANDSHAKING;
        }
        switch (state) {
            case STATE_HANDSHAKE_STARTED:
                return pendingStatus(pendingOutboundEncryptedBytes());
            case STATE_HANDSHAKE_COMPLETED:
                return HandshakeStatus.NEED_WRAP;
            case STATE_NEW:
            case STATE_MODE_SET:
            case STATE_CLOSED:
            case STATE_CLOSED_INBOUND:
            case STATE_CLOSED_OUTBOUND:
            case STATE_READY:
            case STATE_READY_HANDSHAKE_CUT_THROUGH:
                return HandshakeStatus.NOT_HANDSHAKING;
            default:
                break;
        }
        throw new IllegalStateException("Unexpected engine state: " + state);
    }

    int pendingOutboundEncryptedBytes() {
        return networkBio.getPendingWrittenBytes();
    }

    private int pendingInboundCleartextBytes() {
        return ssl.getPendingReadableBytes();
    }

    private static SSLEngineResult.HandshakeStatus pendingStatus(int pendingOutboundBytes) {
        // Depending on if there is something left in the BIO we need to WRAP or UNWRAP
        return pendingOutboundBytes > 0 ? NEED_WRAP : NEED_UNWRAP;
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslParameters.getNeedClientAuth();
    }

    /**
     * Work-around to allow this method to be called on older versions of Android.
     */
    @Override
    SSLSession handshakeSession() {
        synchronized (ssl) {
            if (state == STATE_HANDSHAKE_STARTED) {
                return Platform.wrapSSLSession(new ExternalSession(new ExternalSession.Provider() {
                    @Override
                    public ConscryptSession provideSession() {
                        return ConscryptEngine.this.provideHandshakeSession();
                    }
                }));
            }
            return null;
        }
    }

    @Override
    public SSLSession getSession() {
        return externalSession;
    }

    private ConscryptSession provideSession() {
        synchronized (ssl) {
            if (state == STATE_CLOSED) {
                return closedSession != null ? closedSession : SSLNullSession.getNullSession();
            }
            if (state < STATE_HANDSHAKE_COMPLETED) {
                // Return an invalid session with invalid cipher suite of "SSL_NULL_WITH_NULL_NULL"
                return SSLNullSession.getNullSession();
            }
            return activeSession;
        }
    }

    private ConscryptSession provideHandshakeSession() {
        synchronized (ssl) {
            return state == STATE_HANDSHAKE_STARTED ? activeSession
                : SSLNullSession.getNullSession();
        }
    }

    // After handshake has started, provide active session otherwise a null session,
    // for code which needs to read session attributes without triggering the handshake.
    private ConscryptSession provideAfterHandshakeSession() {
        return (state < STATE_HANDSHAKE_STARTED)
                ? SSLNullSession.getNullSession()
                : provideSession();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return NativeCrypto.getSupportedCipherSuites();
    }

    @Override
    public String[] getSupportedProtocols() {
        return NativeCrypto.getSupportedProtocols();
    }

    @Override
    public boolean getUseClientMode() {
        return sslParameters.getUseClientMode();
    }

    @Override
    public boolean getWantClientAuth() {
        return sslParameters.getWantClientAuth();
    }

    @Override
    public boolean isInboundDone() {
        synchronized (ssl) {
            return (state == STATE_CLOSED
                    || state == STATE_CLOSED_INBOUND
                    || ssl.wasShutdownReceived())
                && (pendingInboundCleartextBytes() == 0);
        }
    }

    @Override
    public boolean isOutboundDone() {
        synchronized (ssl) {
            return (state == STATE_CLOSED
                    || state == STATE_CLOSED_OUTBOUND
                    || ssl.wasShutdownSent())
                && (pendingOutboundEncryptedBytes() == 0);
        }
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        sslParameters.setEnabledCipherSuites(suites);
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        sslParameters.setEnabledProtocols(protocols);
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslParameters.setEnableSessionCreation(flag);
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        sslParameters.setNeedClientAuth(need);
    }

    @Override
    public void setUseClientMode(boolean mode) {
        synchronized (ssl) {
            if (isHandshakeStarted()) {
                throw new IllegalArgumentException(
                        "Can not change mode after handshake: state == " + state);
            }
            transitionTo(STATE_MODE_SET);
            sslParameters.setUseClientMode(mode);
        }
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslParameters.setWantClientAuth(want);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        synchronized (ssl) {
            try {
                return unwrap(singleSrcBuffer(src), singleDstBuffer(dst));
            } finally {
                resetSingleSrcBuffer();
                resetSingleDstBuffer();
            }
        }
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException {
        synchronized (ssl) {
            try {
                return unwrap(singleSrcBuffer(src), dsts);
            } finally {
                resetSingleSrcBuffer();
            }
        }
    }

    @Override
    public SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer[] dsts, final int offset,
            final int length) throws SSLException {
        synchronized (ssl) {
            try {
                return unwrap(singleSrcBuffer(src), 0, 1, dsts, offset, length);
            } finally {
                resetSingleSrcBuffer();
            }
        }
    }

    @Override
    SSLEngineResult unwrap(final ByteBuffer[] srcs, final ByteBuffer[] dsts) throws SSLException {
        checkArgument(srcs != null, "srcs is null");
        checkArgument(dsts != null, "dsts is null");
        return unwrap(srcs, 0, srcs.length, dsts, 0, dsts.length);
    }

    @Override
    SSLEngineResult unwrap(final ByteBuffer[] srcs, int srcsOffset, final int srcsLength,
            final ByteBuffer[] dsts, final int dstsOffset, final int dstsLength)
            throws SSLException {
        checkArgument(srcs != null, "srcs is null");
        checkArgument(dsts != null, "dsts is null");
        checkPositionIndexes(srcsOffset, srcsOffset + srcsLength, srcs.length);
        checkPositionIndexes(dstsOffset, dstsOffset + dstsLength, dsts.length);

        // Determine the output capacity.
        final int dstLength = calcDstsLength(dsts, dstsOffset, dstsLength);
        final int endOffset = dstsOffset + dstsLength;

        final int srcsEndOffset = srcsOffset + srcsLength;
        final long srcLength = calcSrcsLength(srcs, srcsOffset, srcsEndOffset);

        synchronized (ssl) {
            switch (state) {
                case STATE_MODE_SET:
                    // Begin the handshake implicitly.
                    beginHandshakeInternal();
                    break;
                case STATE_CLOSED_INBOUND:
                case STATE_CLOSED:
                    freeIfDone();
                    // If the inbound direction is closed. we can't send anymore.
                    return new SSLEngineResult(Status.CLOSED, getHandshakeStatusInternal(), 0, 0);
                case STATE_NEW:
                    throw new IllegalStateException(
                            "Client/server mode must be set before calling unwrap");
                default:
                    break;
            }

            HandshakeStatus handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
            if (!handshakeFinished) {
                handshakeStatus = handshake();
                if (handshakeStatus == NEED_WRAP) {
                    return NEED_WRAP_OK;
                }
                if (state == STATE_CLOSED) {
                    return NEED_WRAP_CLOSED;
                }
                // NEED_UNWRAP - just fall through to perform the unwrap.
            }

            // Consume any source data. Skip this if there are unread cleartext data.
            boolean noCleartextDataAvailable = pendingInboundCleartextBytes() <= 0;
            int lenRemaining = 0;
            if (srcLength > 0 && noCleartextDataAvailable) {
                if (srcLength < SSL3_RT_HEADER_LENGTH) {
                    // Need to be able to read a full TLS header.
                    return new SSLEngineResult(BUFFER_UNDERFLOW, getHandshakeStatus(), 0, 0);
                }

                int packetLength = SSLUtils.getEncryptedPacketLength(srcs, srcsOffset);
                if (packetLength < 0) {
                    throw new SSLException("Unable to parse TLS packet header");
                }

                if (srcLength < packetLength) {
                    // We either have not enough data to read the packet header or not enough for
                    // reading the whole packet.
                    return new SSLEngineResult(BUFFER_UNDERFLOW, getHandshakeStatus(), 0, 0);
                }

                // Limit the amount of data to be read to a single packet.
                lenRemaining = packetLength;
            } else if (noCleartextDataAvailable) {
                // No pending data and nothing provided as input.  Need more data.
                return new SSLEngineResult(BUFFER_UNDERFLOW, getHandshakeStatus(), 0, 0);
            }

            // Write all of the encrypted source data to the networkBio
            int bytesConsumed = 0;
            if (lenRemaining > 0 && srcsOffset < srcsEndOffset) {
                do {
                    ByteBuffer src = srcs[srcsOffset];
                    int remaining = src.remaining();
                    if (remaining == 0) {
                        // We must skip empty buffers as BIO_write will return 0 if asked to
                        // write something with length 0.
                        srcsOffset++;
                        continue;
                    }
                    // Write the source encrypted data to the networkBio.
                    int written = writeEncryptedData(src, min(lenRemaining, remaining));
                    if (written > 0) {
                        bytesConsumed += written;
                        lenRemaining -= written;
                        if (lenRemaining == 0) {
                            // A whole packet has been consumed.
                            break;
                        }

                        if (written == remaining) {
                            srcsOffset++;
                        } else {
                            // We were not able to write everything into the BIO so break the
                            // write loop as otherwise we will produce an error on the next
                            // write attempt, which will trigger a SSL.clearError() later.
                            break;
                        }
                    } else {
                        // BIO_write returned a negative or zero number, this means we could not
                        // complete the write operation and should retry later.
                        // We ignore BIO_* errors here as we use in memory BIO anyway and will
                        // do another SSL_* call later on in which we will produce an exception
                        // in case of an error
                        NativeCrypto.SSL_clear_error();
                        break;
                    }
                } while (srcsOffset < srcsEndOffset);
            }

            // Now read any available plaintext data.
            int bytesProduced = 0;
            try {
                if (dstLength > 0) {
                    // Write decrypted data to dsts buffers
                    for (int idx = dstsOffset; idx < endOffset; ++idx) {
                        ByteBuffer dst = dsts[idx];
                        if (!dst.hasRemaining()) {
                            continue;
                        }

                        int bytesRead = readPlaintextData(dst);
                        if (bytesRead > 0) {
                            bytesProduced += bytesRead;
                            if (dst.hasRemaining()) {
                                // We haven't filled this buffer fully, break out of the loop
                                // and determine the correct response status below.
                                break;
                            }
                        } else {
                            switch (bytesRead) {
                                case -SSL_ERROR_WANT_READ:
                                case -SSL_ERROR_WANT_WRITE: {
                                    return newResult(bytesConsumed, bytesProduced, handshakeStatus);
                                }
                                case -SSL_ERROR_ZERO_RETURN: {
                                    // We received a close_notify from the peer, so mark the
                                    // inbound direction as closed and shut down the SSL object
                                    closeAll();
                                    return new SSLEngineResult(Status.CLOSED,
                                            pendingOutboundEncryptedBytes() > 0
                                                    ? NEED_WRAP : NOT_HANDSHAKING,
                                            bytesConsumed, bytesProduced);
                                }
                                default: {
                                    // Should never get here.
                                    closeAll();
                                    throw newSslExceptionWithMessage("SSL_read");
                                }
                            }
                        }
                    }
                } else {
                    // If the capacity of all destination buffers is 0 we need to trigger a SSL_read
                    // anyway to ensure everything is flushed in the BIO pair and so we can detect
                    // it in the pendingInboundCleartextBytes() call.
                    ssl.forceRead();
                }
            } catch (InterruptedIOException e) {
                return newResult(bytesConsumed, bytesProduced, handshakeStatus);
            } catch (IOException e) {
                // Shut down the SSL and rethrow the exception.  Users will need to drain any alerts
                // from the SSL before closing.
                closeAll();
                throw convertException(e);
            }

            // There won't be any application data until we're done handshaking.
            // We first check handshakeFinished to eliminate the overhead of extra JNI call if
            // possible.
            int pendingCleartextBytes = handshakeFinished ? pendingInboundCleartextBytes() : 0;
            if (pendingCleartextBytes > 0) {
                // We filled all buffers but there is still some data pending in the BIO buffer,
                // return BUFFER_OVERFLOW.
                return new SSLEngineResult(BUFFER_OVERFLOW,
                        mayFinishHandshake(handshakeStatus == FINISHED
                                        ? handshakeStatus
                                        : getHandshakeStatusInternal()),
                        bytesConsumed, bytesProduced);
            }

            return newResult(bytesConsumed, bytesProduced, handshakeStatus);
        }
    }

    private static int calcDstsLength(ByteBuffer[] dsts, int dstsOffset, int dstsLength) {
        int capacity = 0;
        for (int i = 0; i < dsts.length; i++) {
            ByteBuffer dst = dsts[i];
            checkArgument(dst != null, "dsts[%d] is null", i);
            if (dst.isReadOnly()) {
                throw new ReadOnlyBufferException();
            }
            if (i >= dstsOffset && i < dstsOffset + dstsLength) {
                capacity += dst.remaining();
            }
        }
        return capacity;
    }

    private static long calcSrcsLength(ByteBuffer[] srcs, int srcsOffset, int srcsEndOffset) {
        long len = 0;
        for (int i = srcsOffset; i < srcsEndOffset; i++) {
            ByteBuffer src = srcs[i];
            if (src == null) {
                throw new IllegalArgumentException("srcs[" + i + "] is null");
            }
            len += src.remaining();
        }
        return len;
    }

    private SSLEngineResult.HandshakeStatus handshake() throws SSLException {
        try {
            // Only actually perform the handshake if we haven't already just completed it
            // via BIO operations.
            try {
                int ssl_error_code = ssl.doHandshake();
                switch (ssl_error_code) {
                    case SSL_ERROR_WANT_READ:
                        return pendingStatus(pendingOutboundEncryptedBytes());
                    case SSL_ERROR_WANT_WRITE: {
                        return NEED_WRAP;
                    }
                    default: {
                        // SSL_ERROR_NONE.
                    }
                }
            } catch (IOException e) {
                // Shut down the SSL and rethrow the exception.  Users will need to drain any alerts
                // from the SSL before closing.
                closeAll();
                throw e;
            }

            // The handshake has completed successfully...

            // Update the session from the current state of the SSL object.
            activeSession.onPeerCertificateAvailable(getPeerHost(), getPeerPort());

            finishHandshake();
            return FINISHED;
        } catch (Exception e) {
            throw toSSLHandshakeException(e);
        }
    }

    private void finishHandshake() throws SSLException {
        handshakeFinished = true;
        // Notify the listener, if provided.
        if (handshakeListener != null) {
            handshakeListener.onHandshakeFinished();
        }
    }

    /**
     * Write plaintext data to the OpenSSL internal BIO
     *
     * Calling this function with src.remaining == 0 is undefined.
     */
    private int writePlaintextData(final ByteBuffer src, int len) throws SSLException {
        try {
            final int pos = src.position();
            final int sslWrote;
            if (src.isDirect()) {
                sslWrote = writePlaintextDataDirect(src, pos, len);
            } else {
                sslWrote = writePlaintextDataHeap(src, pos, len);
            }
            if (sslWrote > 0) {
                src.position(pos + sslWrote);
            }
            return sslWrote;
        } catch (Exception e) {
            throw convertException(e);
        }
    }

    private int writePlaintextDataDirect(ByteBuffer src, int pos, int len) throws IOException {
        return ssl.writeDirectByteBuffer(directByteBufferAddress(src, pos), len);
    }

    private int writePlaintextDataHeap(ByteBuffer src, int pos, int len) throws IOException {
        AllocatedBuffer allocatedBuffer = null;
        try {
            final ByteBuffer buffer;
            if (bufferAllocator != null) {
                allocatedBuffer = bufferAllocator.allocateDirectBuffer(len);
                buffer = allocatedBuffer.nioBuffer();
            } else {
                // We don't have a buffer allocator, but we don't want to send a heap
                // buffer to JNI. So lazy-create a direct buffer that we will use from now
                // on to copy plaintext data.
                buffer = getOrCreateLazyDirectBuffer();
            }

            // Copy the data to the direct buffer.
            int limit = src.limit();
            int bytesToWrite = min(len, buffer.remaining());
            src.limit(pos + bytesToWrite);
            buffer.put(src);
            buffer.flip();
            // Restore the original position and limit.
            src.limit(limit);
            src.position(pos);

            return writePlaintextDataDirect(buffer, 0, bytesToWrite);
        } finally {
            if (allocatedBuffer != null) {
                // Release the buffer back to the pool.
                allocatedBuffer.release();
            }
        }
    }

    /**
     * Read plaintext data from the OpenSSL internal BIO
     */
    private int readPlaintextData(final ByteBuffer dst) throws IOException {
        try {
            final int pos = dst.position();
            final int limit = dst.limit();
            final int len = min(SSL3_RT_MAX_PACKET_SIZE, limit - pos);
            if (dst.isDirect()) {
                int bytesRead = readPlaintextDataDirect(dst, pos, len);
                if (bytesRead > 0) {
                    dst.position(pos + bytesRead);
                }
                return bytesRead;
            }

            // The heap method updates the dst position automatically.
            return readPlaintextDataHeap(dst, len);
        } catch (CertificateException e) {
            throw convertException(e);
        }
    }

    private int readPlaintextDataDirect(ByteBuffer dst, int pos, int len)
            throws IOException, CertificateException {
        return ssl.readDirectByteBuffer(directByteBufferAddress(dst, pos), len);
    }

    private int readPlaintextDataHeap(ByteBuffer dst, int len)
            throws IOException, CertificateException {
        AllocatedBuffer allocatedBuffer = null;
        try {
            final ByteBuffer buffer;
            if (bufferAllocator != null) {
                allocatedBuffer = bufferAllocator.allocateDirectBuffer(len);
                buffer = allocatedBuffer.nioBuffer();
            } else {
                // We don't have a buffer allocator, but we don't want to send a heap
                // buffer to JNI. So lazy-create a direct buffer that we will use from now
                // on to copy plaintext data.
                buffer = getOrCreateLazyDirectBuffer();
            }

            // Read the data to the direct buffer.
            int bytesToRead = min(len, buffer.remaining());
            int bytesRead = readPlaintextDataDirect(buffer, 0, bytesToRead);
            if (bytesRead > 0) {
                // Copy the data to the heap buffer.
                buffer.position(bytesRead);
                buffer.flip();
                dst.put(buffer);
            }

            return bytesRead;
        } finally {
            if (allocatedBuffer != null) {
                // Release the buffer back to the pool.
                allocatedBuffer.release();
            }
        }
    }

    private SSLException convertException(Throwable e) {
        if (e instanceof SSLHandshakeException || !handshakeFinished) {
            return SSLUtils.toSSLHandshakeException(e);
        }
        return SSLUtils.toSSLException(e);
    }

    /**
     * Write encrypted data to the OpenSSL network BIO.
     */
    private int writeEncryptedData(final ByteBuffer src, int len) throws SSLException {
        try {
            final int pos = src.position();
            final int bytesWritten;
            if (src.isDirect()) {
                bytesWritten = writeEncryptedDataDirect(src, pos, len);
            } else {
                bytesWritten = writeEncryptedDataHeap(src, pos, len);
            }

            if (bytesWritten > 0) {
                src.position(pos + bytesWritten);
            }

            return bytesWritten;
        } catch (IOException e) {
            closeAll();
            throw new SSLException(e);
        }
    }

    private int writeEncryptedDataDirect(ByteBuffer src, int pos, int len) throws IOException {
        return networkBio.writeDirectByteBuffer(directByteBufferAddress(src, pos), len);
    }

    private int writeEncryptedDataHeap(ByteBuffer src, int pos, int len) throws IOException {
        AllocatedBuffer allocatedBuffer = null;
        try {
            final ByteBuffer buffer;
            if (bufferAllocator != null) {
                allocatedBuffer = bufferAllocator.allocateDirectBuffer(len);
                buffer = allocatedBuffer.nioBuffer();
            } else {
                // We don't have a buffer allocator, but we don't want to send a heap
                // buffer to JNI. So lazy-create a direct buffer that we will use from now
                // on to copy encrypted packets.
                buffer = getOrCreateLazyDirectBuffer();
            }

            int limit = src.limit();
            int bytesToCopy = min(min(limit - pos, len), buffer.remaining());
            src.limit(pos + bytesToCopy);
            buffer.put(src);
            // Restore the original limit.
            src.limit(limit);

            // Reset the original position on the source buffer.
            src.position(pos);

            int bytesWritten = writeEncryptedDataDirect(buffer, 0, bytesToCopy);

            // Restore the original position.
            src.position(pos);

            return bytesWritten;
        } finally {
            if (allocatedBuffer != null) {
                // Release the buffer back to the pool.
                allocatedBuffer.release();
            }
        }
    }

    private ByteBuffer getOrCreateLazyDirectBuffer() {
        if (lazyDirectBuffer == null) {
            lazyDirectBuffer = ByteBuffer.allocateDirect(
                    max(SSL3_RT_MAX_PLAIN_LENGTH, SSL3_RT_MAX_PACKET_SIZE));
        }
        lazyDirectBuffer.clear();
        return lazyDirectBuffer;
    }

    private long directByteBufferAddress(ByteBuffer directBuffer, int pos) {
        return NativeCrypto.getDirectBufferAddress(directBuffer) + pos;
    }

    private SSLEngineResult readPendingBytesFromBIO(ByteBuffer dst, int bytesConsumed,
            int bytesProduced, SSLEngineResult.HandshakeStatus status) throws SSLException {
        try {
            // Check to see if the engine wrote data into the network BIO
            int pendingNet = pendingOutboundEncryptedBytes();
            if (pendingNet > 0) {
                // Do we have enough room in dst to write encrypted data?
                int capacity = dst.remaining();
                if (capacity < pendingNet) {
                    return new SSLEngineResult(BUFFER_OVERFLOW,
                            mayFinishHandshake(
                                    status == FINISHED ? status : getHandshakeStatus(pendingNet)),
                            bytesConsumed, bytesProduced);
                }

                // Write the pending data from the network BIO into the dst buffer
                int produced = readEncryptedData(dst, pendingNet);

                if (produced <= 0) {
                    // We ignore BIO_* errors here as we use in memory BIO anyway and will do
                    // another SSL_* call later on in which we will produce an exception in
                    // case of an error
                    NativeCrypto.SSL_clear_error();
                } else {
                    bytesProduced += produced;
                    pendingNet -= produced;
                }

                return new SSLEngineResult(getEngineStatus(),
                        mayFinishHandshake(
                                status == FINISHED ? status : getHandshakeStatus(pendingNet)),
                        bytesConsumed, bytesProduced);
            }
            return null;
        } catch (Exception e) {
            throw convertException(e);
        }
    }

    /**
     * Read encrypted data from the OpenSSL network BIO
     */
    private int readEncryptedData(final ByteBuffer dst, final int pending) throws SSLException {
        try {
            int bytesRead = 0;
            final int pos = dst.position();
            if (dst.remaining() >= pending) {
                final int limit = dst.limit();
                final int len = min(pending, limit - pos);
                if (dst.isDirect()) {
                    bytesRead = readEncryptedDataDirect(dst, pos, len);
                    // Need to update the position on the dst buffer.
                    if (bytesRead > 0) {
                        dst.position(pos + bytesRead);
                    }
                } else {
                    // The heap method will update the position on the dst buffer automatically.
                    bytesRead = readEncryptedDataHeap(dst, len);
                }
            }

            return bytesRead;
        } catch (Exception e) {
            throw convertException(e);
        }
    }

    private int readEncryptedDataDirect(ByteBuffer dst, int pos, int len) throws IOException {
        return networkBio.readDirectByteBuffer(directByteBufferAddress(dst, pos), len);
    }

    private int readEncryptedDataHeap(ByteBuffer dst, int len) throws IOException {
        AllocatedBuffer allocatedBuffer = null;
        try {
            final ByteBuffer buffer;
            if (bufferAllocator != null) {
                allocatedBuffer = bufferAllocator.allocateDirectBuffer(len);
                buffer = allocatedBuffer.nioBuffer();
            } else {
                // We don't have a buffer allocator, but we don't want to send a heap
                // buffer to JNI. So lazy-create a direct buffer that we will use from now
                // on to copy encrypted packets.
                buffer = getOrCreateLazyDirectBuffer();
            }

            int bytesToRead = min(len, buffer.remaining());
            int bytesRead = readEncryptedDataDirect(buffer, 0, bytesToRead);
            if (bytesRead > 0) {
                buffer.position(bytesRead);
                buffer.flip();
                dst.put(buffer);
            }

            return bytesRead;
        } finally {
            if (allocatedBuffer != null) {
                // Release the buffer back to the pool.
                allocatedBuffer.release();
            }
        }
    }

    private SSLEngineResult.HandshakeStatus mayFinishHandshake(
            SSLEngineResult.HandshakeStatus status) throws SSLException {
        if (!handshakeFinished && status == NOT_HANDSHAKING) {
            // If the status was NOT_HANDSHAKING and we not finished the handshake we need to call
            // SSL_do_handshake() again
            return handshake();
        }
        return status;
    }

    private SSLEngineResult.HandshakeStatus getHandshakeStatus(int pending) {
        // Check if we are in the initial handshake phase or shutdown phase
        return !handshakeFinished ? pendingStatus(pending) : NOT_HANDSHAKING;
    }

    private SSLEngineResult.Status getEngineStatus() {
        switch (state) {
            case STATE_CLOSED_INBOUND:
            case STATE_CLOSED_OUTBOUND:
            case STATE_CLOSED:
                return CLOSED;
            default:
                return OK;
        }
    }

    private void closeAll() {
        closeOutbound();
        closeInbound();
    }

    private void freeIfDone() {
        if (isInboundDone() && isOutboundDone()) {
            closeAndFreeResources();
        }
    }

    private SSLException newSslExceptionWithMessage(String err) {
        if (!handshakeFinished) {
            return new SSLException(err);
        }
        return new SSLHandshakeException(err);
    }

    private SSLEngineResult newResult(int bytesConsumed, int bytesProduced,
            SSLEngineResult.HandshakeStatus status) throws SSLException {
        return new SSLEngineResult(getEngineStatus(),
                mayFinishHandshake(status == FINISHED ? status : getHandshakeStatusInternal()),
                bytesConsumed, bytesProduced);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        synchronized (ssl) {
            try {
                return wrap(singleSrcBuffer(src), dst);
            } finally {
                resetSingleSrcBuffer();
            }
        }
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer dst)
            throws SSLException {
        checkArgument(srcs != null, "srcs is null");
        checkArgument(dst != null, "dst is null");
        checkPositionIndexes(srcsOffset, srcsOffset + srcsLength, srcs.length);
        if (dst.isReadOnly()) {
            throw new ReadOnlyBufferException();
        }

        if ((srcsOffset != 0) || (srcsLength != srcs.length)) {
            srcs = Arrays.copyOfRange(srcs, srcsOffset, srcsOffset + srcsLength);
        }
        BufferUtils.checkNotNull(srcs);

        synchronized (ssl) {
            switch (state) {
                case STATE_MODE_SET:
                    // Begin the handshake implicitly.
                    beginHandshakeInternal();
                    break;
                case STATE_CLOSED_OUTBOUND:
                case STATE_CLOSED:
                    // We may have pending encrypted bytes from a close_notify alert, so
                    // try to read them out
                    SSLEngineResult pendingNetResult =
                            readPendingBytesFromBIO(dst, 0, 0, HandshakeStatus.NOT_HANDSHAKING);
                    if (pendingNetResult != null) {
                        freeIfDone();
                        return pendingNetResult;
                    }
                    return new SSLEngineResult(Status.CLOSED, getHandshakeStatusInternal(), 0, 0);
                case STATE_NEW:
                    throw new IllegalStateException(
                            "Client/server mode must be set before calling wrap");
                default:
                    break;
            }

            // If we haven't completed the handshake yet, just let the caller know.
            HandshakeStatus handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
            // Prepare OpenSSL to work in server mode and receive handshake
            if (!handshakeFinished) {
                handshakeStatus = handshake();
                if (handshakeStatus == NEED_UNWRAP) {
                    return NEED_UNWRAP_OK;
                }

                if (state == STATE_CLOSED) {
                    return NEED_UNWRAP_CLOSED;
                }
                // NEED_WRAP - just fall through to perform the wrap.
            }

            int dataLength = (int) min(BufferUtils.remaining(srcs), SSL3_RT_MAX_PLAIN_LENGTH);
            if (dst.remaining() < calculateOutNetBufSize(dataLength)) {
                return new SSLEngineResult(
                    Status.BUFFER_OVERFLOW, getHandshakeStatusInternal(), 0, 0);
            }

            int bytesProduced = 0;
            int bytesConsumed = 0;
            if (dataLength > 0) {
                // Try and find a single buffer to send, e.g. the first non-empty buffer has
                // more than enough data remaining to fill a TLS record. Otherwise copy as much
                // data as possible from the source buffers to fill a record. Note the we can't
                // mark the data as consumed until we see how much the TLS layer actually consumes.
                boolean isCopy = false;
                ByteBuffer outputBuffer
                        = BufferUtils.getBufferLargerThan(srcs, SSL3_RT_MAX_PLAIN_LENGTH);
                if (outputBuffer == null) {
                    // The buffer by getOrCreateLazyDirectBuffer() is also used by
                    // writePlainTextDataHeap(), but by filling it here the write path will go via
                    // writePlainTextDataDirect() and the cost will be approximately the same,
                    // especially if compacting multiple non-direct buffers into a single
                    // direct one.
                    // TODO(): use bufferAllocator if set.
                    // https://github.com/google/conscrypt/issues/974
                    outputBuffer = BufferUtils.copyNoConsume(
                            srcs, getOrCreateLazyDirectBuffer(), SSL3_RT_MAX_PLAIN_LENGTH);
                    isCopy = true;
                }
                final SSLEngineResult pendingNetResult;
                // Write plaintext application data to the SSL engine
                int result = writePlaintextData(outputBuffer,
                        min(SSL3_RT_MAX_PLAIN_LENGTH, outputBuffer.remaining()));
                if (result > 0) {
                    bytesConsumed = result;
                    if (isCopy) {
                        // Data was a copy, so mark it as consumed in the original buffers.
                        BufferUtils.consume(srcs, bytesConsumed);
                    }

                    pendingNetResult = readPendingBytesFromBIO(
                            dst, bytesConsumed, bytesProduced, handshakeStatus);
                    if (pendingNetResult != null) {
                        if (pendingNetResult.getStatus() != OK) {
                            return pendingNetResult;
                        }
                        bytesProduced = pendingNetResult.bytesProduced();
                    }
                } else {
                    int sslError = ssl.getError(result);
                    switch (sslError) {
                        case SSL_ERROR_ZERO_RETURN:
                            // This means the connection was shutdown correctly, close inbound
                            // and outbound
                            closeAll();
                            pendingNetResult = readPendingBytesFromBIO(
                                    dst, bytesConsumed, bytesProduced, handshakeStatus);
                            return pendingNetResult != null ? pendingNetResult
                                    : CLOSED_NOT_HANDSHAKING;
                        case SSL_ERROR_WANT_READ:
                            // If there is no pending data to read from BIO we should go back to
                            // event loop and try
                            // to read more data [1]. It is also possible that event loop will
                            // detect the socket
                            // has been closed. [1]
                            // https://www.openssl.org/docs/manmaster/man3/SSL_write.html
                            pendingNetResult = readPendingBytesFromBIO(
                                    dst, bytesConsumed, bytesProduced, handshakeStatus);
                            return pendingNetResult != null
                                    ? pendingNetResult
                                    : new SSLEngineResult(getEngineStatus(), NEED_UNWRAP,
                                    bytesConsumed, bytesProduced);
                        case SSL_ERROR_WANT_WRITE:
                            // SSL_ERROR_WANT_WRITE typically means that the underlying
                            // transport is not writable
                            // and we should set the "want write" flag on the selector and try
                            // again when the
                            // underlying transport is writable [1]. However we are not directly
                            // writing to the
                            // underlying transport and instead writing to a BIO buffer. The
                            // OpenSsl documentation
                            // says we should do the following [1]:
                            //
                            // "When using a buffering BIO, like a BIO pair, data must be
                            // written into or retrieved
                            // out of the BIO before being able to continue."
                            //
                            // So we attempt to drain the BIO buffer below, but if there is no
                            // data this condition
                            // is undefined and we assume their is a fatal error with the
                            // openssl engine and close.
                            // [1] https://www.openssl.org/docs/manmaster/man3/SSL_write.html
                            pendingNetResult = readPendingBytesFromBIO(
                                    dst, bytesConsumed, bytesProduced, handshakeStatus);
                            return pendingNetResult != null ? pendingNetResult
                                    : NEED_WRAP_CLOSED;
                        default:
                            // Everything else is considered as error
                            closeAll();
                            throw newSslExceptionWithMessage("SSL_write: error " + sslError);
                    }
                }
            }

            // We need to check if pendingWrittenBytesInBIO was checked yet, as we may not have
            // checked if the srcs was empty, or only contained empty buffers.
            if (bytesConsumed == 0) {
                SSLEngineResult pendingNetResult =
                        readPendingBytesFromBIO(dst, 0, bytesProduced, handshakeStatus);
                if (pendingNetResult != null) {
                    return pendingNetResult;
                }
            }
            return newResult(bytesConsumed, bytesProduced, handshakeStatus);
        }
    }

    @Override
    public int clientPSKKeyRequested(String identityHint, byte[] identity, byte[] key) {
        return ssl.clientPSKKeyRequested(identityHint, identity, key);
    }

    @Override
    public int serverPSKKeyRequested(String identityHint, String identity, byte[] key) {
        return ssl.serverPSKKeyRequested(identityHint, identity, key);
    }

    @Override
    public void onSSLStateChange(int type, int val) {
        synchronized (ssl) {
            switch (type) {
                case SSL_CB_HANDSHAKE_START: {
                    // For clients, this will allow the NEED_UNWRAP status to be
                    // returned.
                    transitionTo(STATE_HANDSHAKE_STARTED);
                    break;
                }
                case SSL_CB_HANDSHAKE_DONE: {
                    if (state != STATE_HANDSHAKE_STARTED
                            && state != STATE_READY_HANDSHAKE_CUT_THROUGH) {
                        throw new IllegalStateException(
                                "Completed handshake while in mode " + state);
                    }
                    transitionTo(STATE_HANDSHAKE_COMPLETED);
                    break;
                }
                default:
                    // Ignore
            }
        }
    }

    @Override
    public void serverCertificateRequested() throws IOException {
        synchronized (ssl) {
            ssl.configureServerCertificate();
        }
    }

    @Override
    public void onNewSessionEstablished(long sslSessionNativePtr) {
        try {
            // Increment the reference count to "take ownership" of the session resource.
            NativeCrypto.SSL_SESSION_up_ref(sslSessionNativePtr);

            // Create a native reference which will release the SSL_SESSION in its finalizer.
            // This constructor will only throw if the native pointer passed in is NULL, which
            // BoringSSL guarantees will not happen.
            NativeRef.SSL_SESSION ref = new SSL_SESSION(sslSessionNativePtr);

            NativeSslSession nativeSession = NativeSslSession.newInstance(ref, activeSession);

            // Cache the newly established session.
            AbstractSessionContext ctx = sessionContext();
            ctx.cacheSession(nativeSession);
        } catch (Exception ignored) {
            // Ignore.
        }
    }

    @Override
    public long serverSessionRequested(byte[] id) {
        // TODO(nathanmittler): Implement server-side caching for TLS < 1.3
        return 0;
    }

    @Override
    public void verifyCertificateChain(byte[][] certChain, String authMethod)
            throws CertificateException {
        try {
            if (certChain == null || certChain.length == 0) {
                throw new CertificateException("Peer sent no certificate");
            }
            X509Certificate[] peerCertChain = SSLUtils.decodeX509CertificateChain(certChain);

            X509TrustManager x509tm = sslParameters.getX509TrustManager();
            if (x509tm == null) {
                throw new CertificateException("No X.509 TrustManager");
            }

            // Update the peer information on the session.
            activeSession.onPeerCertificatesReceived(getPeerHost(), getPeerPort(), peerCertChain);

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
    public void clientCertificateRequested(byte[] keyTypeBytes, int[] signatureAlgs,
            byte[][] asn1DerEncodedPrincipals)
            throws CertificateEncodingException, SSLException {
        ssl.chooseClientCertificate(keyTypeBytes, signatureAlgs, asn1DerEncodedPrincipals);
    }

    private void sendSSLShutdown() {
        try {
            ssl.shutdown();
        } catch (IOException ignored) {
            // TODO: The RI ignores close failures in SSLSocket, but need to
            // investigate whether it does for SSLEngine.
        }
    }

    private void closeAndFreeResources() {
        transitionTo(STATE_CLOSED);
        if (ssl != null) {
            ssl.close();
        }
        if (networkBio != null) {
            networkBio.close();
        }
    }

    @Override
    @SuppressWarnings("Finalize")
    protected void finalize() throws Throwable {
        try {
            // If ssl is null, object must not be fully constructed so nothing for us to do here.
            if (ssl != null) {
                // Otherwise closeAndFreeResources() and callees expect to synchronize on ssl.
                synchronized (ssl) {
                    closeAndFreeResources();
                }
            }
        } finally {
            super.finalize();
        }
    }

    @Override
    public String chooseServerAlias(X509KeyManager keyManager, String keyType) {
        if (keyManager instanceof X509ExtendedKeyManager) {
            X509ExtendedKeyManager ekm = (X509ExtendedKeyManager) keyManager;
            return ekm.chooseEngineServerAlias(keyType, null, this);
        } else {
            return keyManager.chooseServerAlias(keyType, null, null);
        }
    }

    @Override
    public String chooseClientAlias(
            X509KeyManager keyManager, X500Principal[] issuers, String[] keyTypes) {
        if (keyManager instanceof X509ExtendedKeyManager) {
            X509ExtendedKeyManager ekm = (X509ExtendedKeyManager) keyManager;
            return ekm.chooseEngineClientAlias(keyTypes, issuers, this);
        } else {
            return keyManager.chooseClientAlias(keyTypes, issuers, null);
        }
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

    /**
     * This method enables session ticket support.
     *
     * @param useSessionTickets True to enable session tickets
     */
    @Override
    void setUseSessionTickets(boolean useSessionTickets) {
        sslParameters.setUseSessionTickets(useSessionTickets);
    }

    @Override
    String[] getApplicationProtocols() {
        return sslParameters.getApplicationProtocols();
    }

    @Override
    void setApplicationProtocols(String[] protocols) {
        sslParameters.setApplicationProtocols(protocols);
    }

    @Override
    void setApplicationProtocolSelector(ApplicationProtocolSelector selector) {
        setApplicationProtocolSelector(
                selector == null ? null : new ApplicationProtocolSelectorAdapter(this, selector));
    }

    @Override
    byte[] getTlsUnique() {
        return ssl.getTlsUnique();
    }

    @Override
    byte[] exportKeyingMaterial(String label, byte[] context, int length) throws SSLException {
        synchronized (ssl) {
            if (state < STATE_HANDSHAKE_COMPLETED || state == STATE_CLOSED) {
                return null;
            }
        }
        return ssl.exportKeyingMaterial(label, context, length);
    }

    void setApplicationProtocolSelector(ApplicationProtocolSelectorAdapter adapter) {
        sslParameters.setApplicationProtocolSelector(adapter);
    }

    @Override
    public int selectApplicationProtocol(byte[] protocols) {
        ApplicationProtocolSelectorAdapter adapter = sslParameters.getApplicationProtocolSelector();
        if (adapter == null) {
            return NativeConstants.SSL_TLSEXT_ERR_NOACK;
        }
        return adapter.selectApplicationProtocol(protocols);
    }

    @Override
    public String getApplicationProtocol() {
        return provideAfterHandshakeSession().getApplicationProtocol();
    }

    @Override
    public String getHandshakeApplicationProtocol() {
        synchronized (ssl) {
            return state >= STATE_HANDSHAKE_STARTED ? getApplicationProtocol() : null;
        }
    }

    private ByteBuffer[] singleSrcBuffer(ByteBuffer src) {
        singleSrcBuffer[0] = src;
        return singleSrcBuffer;
    }

    private void resetSingleSrcBuffer() {
        singleSrcBuffer[0] = null;
    }

    private ByteBuffer[] singleDstBuffer(ByteBuffer src) {
        singleDstBuffer[0] = src;
        return singleDstBuffer;
    }

    private void resetSingleDstBuffer() {
        singleDstBuffer[0] = null;
    }

    private ClientSessionContext clientSessionContext() {
        return sslParameters.getClientSessionContext();
    }

    private AbstractSessionContext sessionContext() {
        return sslParameters.getSessionContext();
    }

    private void transitionTo(int newState) {
        switch (newState) {
            case STATE_HANDSHAKE_STARTED: {
                handshakeFinished = false;
                activeSession = new ActiveSession(ssl, sslParameters.getSessionContext());
                break;
            }
            case STATE_CLOSED: {
                if (!ssl.isClosed() && state >= STATE_HANDSHAKE_STARTED && state < STATE_CLOSED) {
                    closedSession = new SessionSnapshot(activeSession);
                }
                break;
            }
            default: {
                break;
            }
        }

        // Update the state
        this.state = newState;
    }
}
