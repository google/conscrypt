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
import static org.conscrypt.NativeConstants.SSL_ERROR_NONE;
import static org.conscrypt.NativeConstants.SSL_ERROR_WANT_READ;
import static org.conscrypt.NativeConstants.SSL_ERROR_WANT_WRITE;
import static org.conscrypt.NativeConstants.SSL_ERROR_ZERO_RETURN;
import static org.conscrypt.NativeConstants.SSL_RECEIVED_SHUTDOWN;
import static org.conscrypt.NativeConstants.SSL_SENT_SHUTDOWN;
import static org.conscrypt.SSLUtils.calculateOutNetBufSize;
import static org.conscrypt.SSLUtils.toSSLHandshakeException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;
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

/**
 * Implements the {@link SSLEngine} API using OpenSSL's non-blocking interfaces.
 *
 * @hide
 */
final class OpenSSLEngineImpl extends SSLEngine implements NativeCrypto.SSLHandshakeCallbacks,
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
    private static final ByteBuffer EMPTY = ByteBuffer.allocateDirect(0);
    private static final long EMPTY_ADDR = NativeCrypto.getDirectBufferAddress(EMPTY);

    /**
     * Hostname used with the TLS extension SNI hostname. {@link #getPeerHost()} is used if this is
     * not set.
     */
    private String sniHostname;

    private final SSLParametersImpl sslParameters;

    /**
     * Protects {@link #engineState} and {@link #handshakeFinished}.
     */
    private final Object stateLock = new Object();

    private enum EngineState {
        /**
         * The {@link OpenSSLSocketImpl} object is constructed, but {@link #beginHandshake()} has
         * not yet been called.
         */
        NEW,
        /**
         * {@link #setUseClientMode(boolean)} has been called at least once.
         */
        MODE_SET,
        /**
         * Handshake task has been started.
         */
        HANDSHAKE_STARTED,
        /**
         * Handshake has been completed, but {@link #beginHandshake()} hasn't returned yet.
         */
        HANDSHAKE_COMPLETED,
        /**
         * {@link #beginHandshake()} has completed but the task hasn't been called. This is expected
         * behaviour in cut-through mode, where SSL_do_handshake returns before the handshake is
         * complete. We can now start writing data to the socket.
         */
        READY_HANDSHAKE_CUT_THROUGH,
        /**
         * {@link #beginHandshake()} has completed and socket is ready to go.
         */
        READY,
        CLOSED_INBOUND,
        CLOSED_OUTBOUND,
        /**
         * Inbound and outbound has been called.
         */
        CLOSED,
    }

    // @GuardedBy("stateLock");
    private EngineState engineState = EngineState.NEW;
    private boolean handshakeFinished;

    /**
     * Protected by synchronizing on stateLock. Starts as 0, set by startHandshake, reset to 0 on
     * close.
     */
    // @GuardedBy("stateLock");
    private long sslNativePointer;

    /**
     * Protected by synchronizing on stateLock. Starts as 0, set by startHandshake, reset to 0 on
     * close.
     */
    // @GuardedBy("stateLock");
    private long networkBio;

    /**
     * Set during startHandshake.
     */
    private AbstractOpenSSLSession sslSession;

    /**
     * Used during handshake callbacks.
     */
    private AbstractOpenSSLSession handshakeSession;

    /**
     * Private key for the TLS Channel ID extension. This field is client-side only. Set during
     * startHandshake.
     */
    private OpenSSLKey channelIdPrivateKey;

    private int maxSealOverhead;

    private HandshakeListener handshakeListener;

    private final ByteBuffer[] singleSrcBuffer = new ByteBuffer[1];
    private final ByteBuffer[] singleDstBuffer = new ByteBuffer[1];

    OpenSSLEngineImpl(SSLParametersImpl sslParameters) {
        this.sslParameters = sslParameters;
    }

    OpenSSLEngineImpl(String host, int port, SSLParametersImpl sslParameters) {
        super(host, port);
        this.sslParameters = sslParameters;
    }

    /**
     * Returns the maximum overhead, in bytes, of sealing a record with SSL.
     */
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
    void setChannelIdEnabled(boolean enabled) {
        synchronized (stateLock) {
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
    byte[] getChannelId() throws SSLException {
        synchronized (stateLock) {
            if (getUseClientMode()) {
                throw new IllegalStateException("Not allowed in client mode");
            }

            if (isHandshakeStarted()) {
                throw new IllegalStateException(
                        "Channel ID is only available after handshake completes");
            }
            return NativeCrypto.SSL_get_tls_channel_id(sslNativePointer);
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
    void setChannelIdPrivateKey(PrivateKey privateKey) {
        if (!getUseClientMode()) {
            throw new IllegalStateException("Not allowed in server mode");
        }

        synchronized (stateLock) {
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
    void setHandshakeListener(HandshakeListener handshakeListener) {
        synchronized (stateLock) {
            if (isHandshakeStarted()) {
                throw new IllegalStateException(
                        "Handshake listener must be set before starting the handshake.");
            }
            this.handshakeListener = handshakeListener;
        }
    }

    private boolean isHandshakeStarted() {
        switch (engineState) {
            case NEW:
            case MODE_SET:
                return false;
            default:
                return true;
        }
    }

    @Override
    public void beginHandshake() throws SSLException {
        synchronized (stateLock) {
            beginHandshakeInternal();
        }
    }

    private void beginHandshakeInternal() throws SSLException {
        switch (engineState) {
            case MODE_SET:
                // This is the only allowed state.
                break;
            case HANDSHAKE_STARTED:
                throw new IllegalStateException("Handshake has already been started");
            case CLOSED_INBOUND:
            case CLOSED_OUTBOUND:
            case CLOSED:
                throw new IllegalStateException("Engine has already been closed");
            default:
                throw new IllegalStateException("Client/server mode must be set before handshake");
        }

        engineState = EngineState.HANDSHAKE_STARTED;

        boolean releaseResources = true;
        try {
            final AbstractSessionContext sessionContext = sslParameters.getSessionContext();
            sslNativePointer = NativeCrypto.SSL_new(sessionContext.sslCtxNativePointer);
            networkBio = NativeCrypto.SSL_BIO_new(sslNativePointer);
            sslSession = sslParameters.getSessionToReuse(
                    sslNativePointer, getSniHostname(), getPeerPort());
            sslParameters.setSSLParameters(sslNativePointer, this, this, getSniHostname());
            sslParameters.setCertificateValidation(sslNativePointer);
            sslParameters.setTlsChannelId(sslNativePointer, channelIdPrivateKey);
            if (getUseClientMode()) {
                NativeCrypto.SSL_set_connect_state(sslNativePointer);
            } else {
                NativeCrypto.SSL_set_accept_state(sslNativePointer);
            }
            maxSealOverhead = NativeCrypto.SSL_max_seal_overhead(sslNativePointer);
            handshake();
            releaseResources = false;
        } catch (IOException e) {
            // Write CCS errors to EventLog
            String message = e.getMessage();
            // Must match error reason string of SSL_R_UNEXPECTED_CCS (in ssl/ssl_err.c)
            if (message.contains("unexpected CCS")) {
                String logMessage = String.format("ssl_unexpected_ccs: host=%s", getSniHostname());
                Platform.logEvent(logMessage);
            }
            throw SSLUtils.toSSLHandshakeException(e);
        } finally {
            if (releaseResources) {
                engineState = EngineState.CLOSED;
                shutdownAndFreeSslNative();
            }
        }
    }

    @Override
    public void closeInbound() throws SSLException {
        synchronized (stateLock) {
            if (engineState == EngineState.CLOSED) {
                return;
            }
            if (engineState == EngineState.CLOSED_OUTBOUND) {
                engineState = EngineState.CLOSED;
            } else {
                engineState = EngineState.CLOSED_INBOUND;
            }
        }
        // TODO anything else to notify OpenSSL layer?
    }

    @Override
    public void closeOutbound() {
        synchronized (stateLock) {
            if (engineState == EngineState.CLOSED || engineState == EngineState.CLOSED_OUTBOUND) {
                return;
            }
            if (isHandshakeStarted()) {
                shutdownAndFreeSslNative();
            }
            if (engineState == EngineState.CLOSED_INBOUND) {
                engineState = EngineState.CLOSED;
            } else {
                engineState = EngineState.CLOSED_OUTBOUND;
            }
        }
        shutdown();
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

    public void setSniHostname(String sniHostname) {
        this.sniHostname = sniHostname;
    }

    public String getSniHostname() {
        return sniHostname != null ? sniHostname : getPeerHost();
    }

    @Override
    public void setSSLParameters(SSLParameters p) {
        super.setSSLParameters(p);
        Platform.setSSLParameters(p, sslParameters, this);
    }

    @Override
    public HandshakeStatus getHandshakeStatus() {
        synchronized (stateLock) {
            return getHandshakeStatusInternal();
        }
    }

    private HandshakeStatus getHandshakeStatusInternal() {
        if (handshakeFinished) {
            return HandshakeStatus.NOT_HANDSHAKING;
        }
        switch (engineState) {
            case HANDSHAKE_STARTED:
                return pendingStatus(pendingOutboundEncryptedBytes());
            case HANDSHAKE_COMPLETED:
                return HandshakeStatus.NEED_WRAP;
            case NEW:
            case MODE_SET:
            case CLOSED:
            case CLOSED_INBOUND:
            case CLOSED_OUTBOUND:
            case READY:
            case READY_HANDSHAKE_CUT_THROUGH:
                return HandshakeStatus.NOT_HANDSHAKING;
            default:
                break;
        }
        throw new IllegalStateException("Unexpected engine state: " + engineState);
    }

    private int pendingOutboundEncryptedBytes() {
        return NativeCrypto.SSL_pending_written_bytes_in_BIO(networkBio);
    }

    private int pendingInboundCleartextBytes() {
        return NativeCrypto.SSL_pending_readable_bytes(sslNativePointer);
    }

    private static SSLEngineResult.HandshakeStatus pendingStatus(int pendingOutboundBytes) {
        // Depending on if there is something left in the BIO we need to WRAP or UNWRAP
        return pendingOutboundBytes > 0 ? NEED_WRAP : NEED_UNWRAP;
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public SSLSession getSession() {
        if (sslSession == null) {
            return handshakeSession != null ? Platform.wrapSSLSession(handshakeSession)
                                            : SSLNullSession.getNullSession();
        }
        return Platform.wrapSSLSession(sslSession);
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
        if (sslNativePointer == 0) {
            synchronized (stateLock) {
                return engineState == EngineState.CLOSED
                        || engineState == EngineState.CLOSED_INBOUND;
            }
        }
        return (NativeCrypto.SSL_get_shutdown(sslNativePointer) & SSL_RECEIVED_SHUTDOWN) != 0;
    }

    @Override
    public boolean isOutboundDone() {
        if (sslNativePointer == 0) {
            synchronized (stateLock) {
                return engineState == EngineState.CLOSED
                        || engineState == EngineState.CLOSED_OUTBOUND;
            }
        }
        return (NativeCrypto.SSL_get_shutdown(sslNativePointer) & SSL_SENT_SHUTDOWN) != 0;
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
        synchronized (stateLock) {
            if (isHandshakeStarted()) {
                throw new IllegalArgumentException(
                        "Can not change mode after handshake: engineState == " + engineState);
            }
            engineState = EngineState.MODE_SET;
        }
        sslParameters.setUseClientMode(mode);
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslParameters.setWantClientAuth(want);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        synchronized (stateLock) {
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
        synchronized (stateLock) {
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
        synchronized (stateLock) {
            try {
                return unwrap(singleSrcBuffer(src), 0, 1, dsts, offset, length);
            } finally {
                resetSingleSrcBuffer();
            }
        }
    }

    SSLEngineResult unwrap(final ByteBuffer[] srcs, final ByteBuffer[] dsts) throws SSLException {
        checkNotNull(srcs, "srcs");
        checkNotNull(dsts, "dsts");
        return unwrap(srcs, 0, srcs.length, dsts, 0, dsts.length);
    }

    SSLEngineResult unwrap(final ByteBuffer[] srcs, int srcsOffset, final int srcsLength,
            final ByteBuffer[] dsts, final int dstsOffset, final int dstsLength)
            throws SSLException {
        checkNotNull(srcs, "srcs");
        checkNotNull(dsts, "dsts");

        checkIndex(srcs.length, srcsOffset, srcsLength, "srcs");
        checkIndex(dsts.length, dstsOffset, dstsLength, "dsts");

        // Determine the output capacity.
        final int dstLength = calcDstsLength(dsts, dstsOffset, dstsLength);
        final int endOffset = dstsOffset + dstsLength;

        final int srcsEndOffset = srcsOffset + srcsLength;
        final long srcLength = calcSrcsLength(srcs, srcsOffset, srcsEndOffset);

        synchronized (stateLock) {
            switch (engineState) {
                case MODE_SET:
                    // Begin the handshake implicitly.
                    beginHandshakeInternal();
                    break;
                case CLOSED_INBOUND:
                case CLOSED:
                    // If the inbound direction is closed. we can't send anymore.
                    return new SSLEngineResult(Status.CLOSED, getHandshakeStatusInternal(), 0, 0);
                case NEW:
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
                if (engineState == EngineState.CLOSED) {
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
                    int written = writeEncryptedData(src, Math.min(lenRemaining, remaining));
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
                        // Return an appropriate result based on the error code.
                        int sslError = NativeCrypto.SSL_get_error(sslNativePointer, bytesRead);
                        switch (sslError) {
                            case SSL_ERROR_ZERO_RETURN:
                                // This means the connection was shutdown correctly, close inbound
                                // and outbound
                                closeAll();
                                return newResult(bytesConsumed, bytesProduced, handshakeStatus);
                            case SSL_ERROR_WANT_READ:
                            case SSL_ERROR_WANT_WRITE:
                                return newResult(bytesConsumed, bytesProduced, handshakeStatus);
                            default:
                                return sslReadErrorResult(NativeCrypto.SSL_get_last_error_number(),
                                        bytesConsumed, bytesProduced);
                        }
                    }
                }
            } else {
                // If the capacity of all destination buffers is 0 we need to trigger a SSL_read
                // anyway to ensure everything is flushed in the BIO pair and so we can detect it
                // in the pendingInboundCleartextBytes() call.
                try {
                    if (NativeCrypto.ENGINE_SSL_read_direct(sslNativePointer, EMPTY_ADDR, 0, this)
                            <= 0) {
                        // We do not check SSL_get_error as we are not interested in any error that
                        // is not fatal.
                        int err = NativeCrypto.SSL_get_last_error_number();
                        if (err != SSL_ERROR_NONE) {
                            return sslReadErrorResult(err, bytesConsumed, bytesProduced);
                        }
                    }
                } catch (IOException e) {
                    throw new SSLException(e);
                }
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
            checkNotNull(dst, "one of the dst");
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
        long sslSessionCtx = 0L;
        try {
            // Only actually perform the handshake if we haven't already just completed it
            // via BIO operations.
            int code = NativeCrypto.ENGINE_SSL_do_handshake(sslNativePointer, this);
            if (code <= 0) {
                int sslError = NativeCrypto.SSL_get_error(sslNativePointer, code);
                switch (sslError) {
                    case SSL_ERROR_WANT_READ:
                    case SSL_ERROR_WANT_WRITE:
                        return pendingStatus(pendingOutboundEncryptedBytes());
                    default:
                        // Everything else is considered as error
                        throw shutdownWithError("SSL_do_handshake");
                }
            }

            // Handshake is finished!
            sslSessionCtx = NativeCrypto.SSL_get1_session(sslNativePointer);
            if (sslSessionCtx == 0) {
                // TODO(nathanmittler): Should we throw here?
                // return pendingStatus(pendingOutboundBytes());
                throw shutdownWithError("Failed to obtain session after handshake completed");
            }
            sslSession = sslParameters.setupSession(sslSessionCtx, sslNativePointer, sslSession,
                    getSniHostname(), getPeerPort(), true);
            if (sslSession != null && engineState == EngineState.HANDSHAKE_STARTED) {
                engineState = EngineState.READY_HANDSHAKE_CUT_THROUGH;
            } else {
                engineState = EngineState.READY;
            }
            finishHandshake();
            return FINISHED;
        } catch (Exception e) {
            throw toSSLHandshakeException(e);
        } finally {
            if (sslSession == null && sslSessionCtx != 0) {
                NativeCrypto.SSL_SESSION_free(sslSessionCtx);
            }
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
                long addr = NativeCrypto.getDirectBufferAddress(src) + pos;
                sslWrote = NativeCrypto.ENGINE_SSL_write_direct(sslNativePointer, addr, len, this);
            } else {
                ByteBuffer heapSrc = toHeapBuffer(src, len);
                sslWrote = NativeCrypto.ENGINE_SSL_write_heap(sslNativePointer, heapSrc.array(),
                        heapSrc.arrayOffset() + heapSrc.position(), len, this);
            }
            if (sslWrote > 0) {
                src.position(pos + sslWrote);
            }
            return sslWrote;
        } catch (Exception e) {
            throw convertException(e);
        }
    }

    /**
     * Read plaintext data from the OpenSSL internal BIO
     */
    private int readPlaintextData(final ByteBuffer dst) throws SSLException {
        try {
            final int sslRead;
            final int pos = dst.position();
            final int limit = dst.limit();
            final int len = Math.min(SSL3_RT_MAX_PACKET_SIZE, limit - pos);
            if (dst.isDirect()) {
                long addr = NativeCrypto.getDirectBufferAddress(dst) + pos;
                sslRead = NativeCrypto.ENGINE_SSL_read_direct(sslNativePointer, addr, len, this);
                if (sslRead > 0) {
                    dst.position(pos + sslRead);
                }
            } else if (dst.hasArray()) {
                sslRead = NativeCrypto.ENGINE_SSL_read_heap(
                        sslNativePointer, dst.array(), dst.arrayOffset() + pos, len, this);
                if (sslRead > 0) {
                    dst.position(pos + sslRead);
                }
            } else {
                byte[] data = new byte[len];
                sslRead = NativeCrypto.ENGINE_SSL_read_heap(sslNativePointer, data, 0, len, this);
                if (sslRead > 0) {
                    dst.put(data, 0, sslRead);
                }
            }
            return sslRead;
        } catch (Exception e) {
            throw convertException(e);
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
            final int netWrote;
            if (src.isDirect()) {
                long addr = NativeCrypto.getDirectBufferAddress(src) + pos;
                netWrote = NativeCrypto.ENGINE_SSL_write_BIO_direct(
                        sslNativePointer, networkBio, addr, len, this);
            } else {
                ByteBuffer heapSrc = toHeapBuffer(src, len);
                netWrote = NativeCrypto.ENGINE_SSL_write_BIO_heap(sslNativePointer, networkBio,
                        heapSrc.array(), heapSrc.arrayOffset() + heapSrc.position(), len, this);
            }

            if (netWrote >= 0) {
                src.position(pos + netWrote);
            }

            return netWrote;
        } catch (IOException e) {
            throw new SSLException(e);
        }
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
            int bioRead = 0;
            if (dst.remaining() >= pending) {
                final int pos = dst.position();
                final int limit = dst.limit();
                final int len = Math.min(pending, limit - pos);
                if (dst.isDirect()) {
                    long addr = NativeCrypto.getDirectBufferAddress(dst) + pos;
                    bioRead = NativeCrypto.ENGINE_SSL_read_BIO_direct(
                            sslNativePointer, networkBio, addr, len, this);
                    if (bioRead > 0) {
                        dst.position(pos + bioRead);
                        return bioRead;
                    }
                } else if (dst.hasArray()) {
                    bioRead = NativeCrypto.ENGINE_SSL_read_BIO_heap(sslNativePointer, networkBio,
                            dst.array(), dst.arrayOffset() + pos, pending, this);
                    if (bioRead > 0) {
                        dst.position(pos + bioRead);
                        return bioRead;
                    }
                } else {
                    byte[] data = new byte[len];
                    bioRead = NativeCrypto.ENGINE_SSL_read_BIO_heap(
                            sslNativePointer, networkBio, data, 0, pending, this);
                    if (bioRead > 0) {
                        dst.put(data, 0, bioRead);
                        return bioRead;
                    }
                }
            }
            return bioRead;
        } catch (Exception e) {
            throw convertException(e);
        }
    }

    private SSLEngineResult.HandshakeStatus mayFinishHandshake(
            SSLEngineResult.HandshakeStatus status) throws SSLException {
        if (!handshakeFinished
                && status
                        == NOT_HANDSHAKING /*|| engineState == EngineState.HANDSHAKE_COMPLETED)*/) {
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
        switch (engineState) {
            case CLOSED_INBOUND:
            case CLOSED_OUTBOUND:
            case CLOSED:
                return CLOSED;
            default:
                return OK;
        }
    }

    private void closeAll() throws SSLException {
        closeOutbound();
        closeInbound();
    }

    private SSLEngineResult sslReadErrorResult(int err, int bytesConsumed, int bytesProduced)
            throws SSLException {
        if (!handshakeFinished && pendingOutboundEncryptedBytes() > 0) {
            return new SSLEngineResult(OK, NEED_WRAP, bytesConsumed, bytesProduced);
        }
        throw shutdownWithError(NativeCrypto.SSL_get_error_string(err));
    }

    private SSLException shutdownWithError(String err) {
        // There was an internal error -- shutdown
        shutdown();
        if (getHandshakeStatusInternal() == HandshakeStatus.FINISHED) {
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
    public final SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        synchronized (stateLock) {
            try {
                return wrap(singleSrcBuffer(src), dst);
            } finally {
                resetSingleSrcBuffer();
            }
        }
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
            throws SSLException {
        checkNotNull(srcs, "srcs");
        checkNotNull(dst, "dst");
        checkIndex(srcs.length, offset, length, "srcs");
        if (dst.isReadOnly()) {
            throw new ReadOnlyBufferException();
        }

        synchronized (stateLock) {
            switch (engineState) {
                case MODE_SET:
                    // Begin the handshake implicitly.
                    beginHandshakeInternal();
                    break;
                case CLOSED_OUTBOUND:
                case CLOSED:
                    return new SSLEngineResult(Status.CLOSED, getHandshakeStatusInternal(), 0, 0);
                case NEW:
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

                if (engineState == EngineState.CLOSED) {
                    return NEED_UNWRAP_CLOSED;
                }
                // NEED_WRAP - just fall through to perform the wrap.
            }

            int srcsLen = 0;
            final int endOffset = offset + length;
            for (int i = offset; i < endOffset; ++i) {
                final ByteBuffer src = srcs[i];
                if (src == null) {
                    throw new IllegalArgumentException("srcs[" + i + "] is null");
                }
                if (srcsLen == SSL3_RT_MAX_PLAIN_LENGTH) {
                    continue;
                }

                srcsLen += src.remaining();
                if (srcsLen > SSL3_RT_MAX_PLAIN_LENGTH || srcsLen < 0) {
                    // If srcLen > MAX_PLAINTEXT_LENGTH or secLen < 0 just set it to
                    // MAX_PLAINTEXT_LENGTH.
                    // This also help us to guard against overflow.
                    // We not break out here as we still need to check for null entries in srcs[].
                    srcsLen = SSL3_RT_MAX_PLAIN_LENGTH;
                }
            }

            if (dst.remaining() < calculateOutNetBufSize(srcsLen)) {
                return new SSLEngineResult(
                        Status.BUFFER_OVERFLOW, getHandshakeStatusInternal(), 0, 0);
            }

            int bytesProduced = 0;
            int bytesConsumed = 0;
        loop:
            for (int i = offset; i < endOffset; ++i) {
                final ByteBuffer src = srcs[i];
                checkNotNull(src, "srcs[%d] is null", i);
                while (src.hasRemaining()) {
                    final SSLEngineResult pendingNetResult;
                    // Write plaintext application data to the SSL engine
                    int result = writePlaintextData(src,
                            Math.min(src.remaining(), SSL3_RT_MAX_PLAIN_LENGTH - bytesConsumed));
                    if (result > 0) {
                        bytesConsumed += result;

                        pendingNetResult = readPendingBytesFromBIO(
                                dst, bytesConsumed, bytesProduced, handshakeStatus);
                        if (pendingNetResult != null) {
                            if (pendingNetResult.getStatus() != OK) {
                                return pendingNetResult;
                            }
                            bytesProduced = pendingNetResult.bytesProduced();
                        }
                        if (bytesConsumed == SSL3_RT_MAX_PLAIN_LENGTH) {
                            // If we consumed the maximum amount of bytes for the plaintext length
                            // break out of the loop and start to fill the dst buffer.
                            break loop;
                        }
                    } else {
                        int sslError = NativeCrypto.SSL_get_error(sslNativePointer, result);
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
                                // https://www.openssl.org/docs/manmaster/ssl/SSL_write.html
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
                                // [1] https://www.openssl.org/docs/manmaster/ssl/SSL_write.html
                                pendingNetResult = readPendingBytesFromBIO(
                                        dst, bytesConsumed, bytesProduced, handshakeStatus);
                                return pendingNetResult != null ? pendingNetResult
                                                                : NEED_WRAP_CLOSED;
                            default:
                                // Everything else is considered as error
                                throw shutdownWithError("SSL_write");
                        }
                    }
                }
            }
            // We need to check if pendingWrittenBytesInBIO was checked yet, as we may not checked
            // if the srcs was
            // empty, or only contained empty buffers.
            if (bytesConsumed == 0) {
                SSLEngineResult pendingNetResult =
                        readPendingBytesFromBIO(dst, 0, bytesProduced, handshakeStatus);
                if (pendingNetResult != null) {
                    return pendingNetResult;
                }
            }

            // return new SSLEngineResult(OK, getHandshakeStatusInternal(), bytesConsumed,
            // bytesProduced);
            return newResult(bytesConsumed, bytesProduced, handshakeStatus);
        }
    }

    @Override
    public int clientPSKKeyRequested(String identityHint, byte[] identity, byte[] key) {
        return sslParameters.clientPSKKeyRequested(identityHint, identity, key, this);
    }

    @Override
    public int serverPSKKeyRequested(String identityHint, String identity, byte[] key) {
        return sslParameters.serverPSKKeyRequested(identityHint, identity, key, this);
    }

    @Override
    public void onSSLStateChange(int type, int val) {
        synchronized (stateLock) {
            switch (type) {
                case SSL_CB_HANDSHAKE_START:
                    // For clients, this will allow the NEED_UNWRAP status to be
                    // returned.
                    engineState = EngineState.HANDSHAKE_STARTED;
                    break;
                case SSL_CB_HANDSHAKE_DONE:
                    if (engineState != EngineState.HANDSHAKE_STARTED
                            && engineState != EngineState.READY_HANDSHAKE_CUT_THROUGH) {
                        throw new IllegalStateException(
                                "Completed handshake while in mode " + engineState);
                    }
                    engineState = EngineState.HANDSHAKE_COMPLETED;
                    break;

            }
        }
    }

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

            byte[] ocspData = NativeCrypto.SSL_get_ocsp_response(sslNativePointer);
            byte[] tlsSctData = NativeCrypto.SSL_get_signed_cert_timestamp_list(sslNativePointer);

            // Used for verifyCertificateChain callback
            handshakeSession = new OpenSSLSessionImpl(
                    NativeCrypto.SSL_get1_session(sslNativePointer), null, peerCertChain, ocspData,
                    tlsSctData, getSniHostname(), getPeerPort(), null);

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
        } finally {
            handshakeSession = null;
        }
    }

    @Override
    public void clientCertificateRequested(byte[] keyTypeBytes, byte[][] asn1DerEncodedPrincipals)
            throws CertificateEncodingException, SSLException {
        sslParameters.chooseClientCertificate(
                keyTypeBytes, asn1DerEncodedPrincipals, sslNativePointer, this);
    }

    private void shutdown() {
        try {
            NativeCrypto.ENGINE_SSL_shutdown(sslNativePointer, this);
        } catch (IOException ignored) {
            // TODO: The RI ignores close failures in SSLSocket, but need to
            // investigate whether it does for SSLEngine.
        }
    }

    private void shutdownAndFreeSslNative() {
        try {
            shutdown();
        } finally {
            free();
        }
    }

    private void free() {
        if (sslNativePointer == 0) {
            return;
        }
        NativeCrypto.SSL_free(sslNativePointer);
        NativeCrypto.BIO_free_all(networkBio);
        sslNativePointer = 0;
        networkBio = 0;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            free();
        } finally {
            super.finalize();
        }
    }

    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java 6.
    public SSLSession getHandshakeSession() {
        return handshakeSession;
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
    void setUseSessionTickets(boolean useSessionTickets) {
        sslParameters.setUseSessionTickets(useSessionTickets);
    }

    /**
     * Sets the list of ALPN protocols.
     *
     * @param alpnProtocols the list of ALPN protocols
     */
    void setAlpnProtocols(String[] alpnProtocols) {
        sslParameters.setAlpnProtocols(alpnProtocols);
    }

    /**
     * Returns the protocol agreed upon by client and server, or {@code null} if no protocol was
     * agreed upon.
     */
    byte[] getAlpnSelectedProtocol() {
        return NativeCrypto.SSL_get0_alpn_selected(sslNativePointer);
    }

    private ByteBuffer toHeapBuffer(ByteBuffer buffer, int len) {
        if (buffer.hasArray()) {
            return buffer;
        }

        // Need to copy to a heap buffer.
        final ByteBuffer heapBuffer = ByteBuffer.allocate(len);
        final int pos = buffer.position();
        final int limit = buffer.limit();
        buffer.limit(pos + len);
        try {
            heapBuffer.put(buffer);
            heapBuffer.flip();
            return heapBuffer;
        } finally {
            buffer.limit(limit);
            buffer.position(pos);
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

    private static void checkIndex(int arrayLength, int offset, int length, String arrayName) {
        if ((offset | length) < 0 || offset + length > arrayLength) {
            throw new IndexOutOfBoundsException("offset: " + offset + ", length: " + length
                    + " (expected: offset <= offset + length <= " + arrayName + ".length ("
                    + arrayLength + "))");
        }
    }

    private static <T> T checkNotNull(T obj, String fmt, Object... args) {
        if (obj == null) {
            throw new IllegalArgumentException(String.format(fmt, args));
        }
        return obj;
    }
}
