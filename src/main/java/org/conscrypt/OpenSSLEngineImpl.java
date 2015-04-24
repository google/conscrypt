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

package org.conscrypt;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

/**
 * Implements the {@link SSLEngine} API using OpenSSL's non-blocking interfaces.
 */
public class OpenSSLEngineImpl extends SSLEngine implements NativeCrypto.SSLHandshakeCallbacks,
        SSLParametersImpl.AliasChooser, SSLParametersImpl.PSKCallbacks {
    private final SSLParametersImpl sslParameters;

    /**
     * Protects handshakeStarted and handshakeCompleted.
     */
    private final Object stateLock = new Object();

    private static enum EngineState {
        /**
         * The {@link OpenSSLSocketImpl} object is constructed, but {@link #beginHandshake()}
         * has not yet been called.
         */
        NEW,
        /**
         * {@link #setUseClientMode(boolean)} has been called at least once.
         */
        MODE_SET,
        /**
         * {@link #beginHandshake()} has been called at least once.
         */
        HANDSHAKE_WANTED,
        /**
         * Handshake task has been started.
         */
        HANDSHAKE_STARTED,
        /**
         * Handshake has been completed, but {@link #beginHandshake()} hasn't returned yet.
         */
        HANDSHAKE_COMPLETED,
        /**
         * {@link #beginHandshake()} has completed but the task hasn't
         * been called. This is expected behaviour in cut-through mode, where SSL_do_handshake
         * returns before the handshake is complete. We can now start writing data to the socket.
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

    /**
     * Protected by synchronizing on stateLock. Starts as 0, set by
     * startHandshake, reset to 0 on close.
     */
    // @GuardedBy("stateLock");
    private long sslNativePointer;

    /** Used during handshake when {@link #wrap(ByteBuffer, ByteBuffer)} is called. */
    // TODO: make this use something similar to BIO_s_null() in native code
    private static OpenSSLBIOSource nullSource = OpenSSLBIOSource.wrap(ByteBuffer.allocate(0));

    /** A BIO sink written to only during handshakes. */
    private OpenSSLBIOSink handshakeSink;

    /** A BIO sink written to during regular operation. */
    private final OpenSSLBIOSink localToRemoteSink = OpenSSLBIOSink.create();

    /** Set during startHandshake. */
    private OpenSSLSessionImpl sslSession;

    /** Used during handshake callbacks. */
    private OpenSSLSessionImpl handshakeSession;

    /**
     * Private key for the TLS Channel ID extension. This field is client-side
     * only. Set during startHandshake.
     */
    OpenSSLKey channelIdPrivateKey;

    public OpenSSLEngineImpl(SSLParametersImpl sslParameters) {
        this.sslParameters = sslParameters;
    }

    public OpenSSLEngineImpl(String host, int port, SSLParametersImpl sslParameters) {
        super(host, port);
        this.sslParameters = sslParameters;
    }

    @Override
    public void beginHandshake() throws SSLException {
        synchronized (stateLock) {
            if (engineState == EngineState.CLOSED || engineState == EngineState.CLOSED_OUTBOUND
                    || engineState == EngineState.CLOSED_INBOUND) {
                throw new IllegalStateException("Engine has already been closed");
            }
            if (engineState == EngineState.HANDSHAKE_STARTED) {
                throw new IllegalStateException("Handshake has already been started");
            }
            if (engineState != EngineState.MODE_SET) {
                throw new IllegalStateException("Client/server mode must be set before handshake");
            }
            if (getUseClientMode()) {
                engineState = EngineState.HANDSHAKE_WANTED;
            } else {
                engineState = EngineState.HANDSHAKE_STARTED;
            }
        }

        boolean releaseResources = true;
        try {
            final AbstractSessionContext sessionContext = sslParameters.getSessionContext();
            final long sslCtxNativePointer = sessionContext.sslCtxNativePointer;
            sslNativePointer = NativeCrypto.SSL_new(sslCtxNativePointer);
            sslSession = sslParameters.getSessionToReuse(
                    sslNativePointer, getPeerHost(), getPeerPort());
            sslParameters.setSSLParameters(sslCtxNativePointer, sslNativePointer, this, this,
                    getPeerHost());
            sslParameters.setCertificateValidation(sslNativePointer);
            sslParameters.setTlsChannelId(sslNativePointer, channelIdPrivateKey);
            if (getUseClientMode()) {
                NativeCrypto.SSL_set_connect_state(sslNativePointer);
            } else {
                NativeCrypto.SSL_set_accept_state(sslNativePointer);
            }
            handshakeSink = OpenSSLBIOSink.create();
            releaseResources = false;
        } catch (IOException e) {
            // Write CCS errors to EventLog
            String message = e.getMessage();
            // Must match error reason string of SSL_R_UNEXPECTED_CCS (in ssl/ssl_err.c)
            if (message.contains("unexpected CCS")) {
                String logMessage = String.format("ssl_unexpected_ccs: host=%s", getPeerHost());
                Platform.logEvent(logMessage);
            }
            throw new SSLException(e);
        } finally {
            if (releaseResources) {
                synchronized (stateLock) {
                    engineState = EngineState.CLOSED;
                }
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
            if (engineState != EngineState.MODE_SET && engineState != EngineState.NEW) {
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
        /* This implementation doesn't use any delegated tasks. */
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
    public HandshakeStatus getHandshakeStatus() {
        synchronized (stateLock) {
            switch (engineState) {
                case HANDSHAKE_WANTED:
                    if (getUseClientMode()) {
                        return HandshakeStatus.NEED_WRAP;
                    } else {
                        return HandshakeStatus.NEED_UNWRAP;
                    }
                case HANDSHAKE_STARTED:
                    if (handshakeSink.available() > 0) {
                        return HandshakeStatus.NEED_WRAP;
                    } else {
                        return HandshakeStatus.NEED_UNWRAP;
                    }
                case HANDSHAKE_COMPLETED:
                    if (handshakeSink.available() == 0) {
                        handshakeSink = null;
                        engineState = EngineState.READY;
                        return HandshakeStatus.FINISHED;
                    } else {
                        return HandshakeStatus.NEED_WRAP;
                    }
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
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public SSLSession getSession() {
        if (sslSession == null) {
            return SSLNullSession.getNullSession();
        }
        return sslSession;
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
        return (NativeCrypto.SSL_get_shutdown(sslNativePointer)
                & NativeConstants.SSL_RECEIVED_SHUTDOWN) != 0;
    }

    @Override
    public boolean isOutboundDone() {
        if (sslNativePointer == 0) {
            synchronized (stateLock) {
                return engineState == EngineState.CLOSED
                        || engineState == EngineState.CLOSED_OUTBOUND;
            }
        }
        return (NativeCrypto.SSL_get_shutdown(sslNativePointer)
                & NativeConstants.SSL_SENT_SHUTDOWN) != 0;
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
            if (engineState != EngineState.MODE_SET && engineState != EngineState.NEW) {
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

    private static void checkIndex(int length, int offset, int count) {
        if (offset < 0) {
            throw new IndexOutOfBoundsException("offset < 0");
        } else if (count < 0) {
            throw new IndexOutOfBoundsException("count < 0");
        } else if (offset > length) {
            throw new IndexOutOfBoundsException("offset > length");
        } else if (offset > length - count) {
            throw new IndexOutOfBoundsException("offset + count > length");
        }
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
            throws SSLException {
        if (src == null) {
            throw new IllegalArgumentException("src == null");
        } else if (dsts == null) {
            throw new IllegalArgumentException("dsts == null");
        }
        checkIndex(dsts.length, offset, length);
        int dstRemaining = 0;
        for (int i = 0; i < dsts.length; i++) {
            ByteBuffer dst = dsts[i];
            if (dst == null) {
                throw new IllegalArgumentException("one of the dst == null");
            } else if (dst.isReadOnly()) {
                throw new ReadOnlyBufferException();
            }
            if (i >= offset && i < offset + length) {
                dstRemaining += dst.remaining();
            }
        }

        synchronized (stateLock) {
            // If the inbound direction is closed. we can't send anymore.
            if (engineState == EngineState.CLOSED || engineState == EngineState.CLOSED_INBOUND) {
                return new SSLEngineResult(Status.CLOSED, getHandshakeStatus(), 0, 0);
            }
            if (engineState == EngineState.NEW || engineState == EngineState.MODE_SET) {
                beginHandshake();
            }
        }

        // If we haven't completed the handshake yet, just let the caller know.
        HandshakeStatus handshakeStatus = getHandshakeStatus();
        if (handshakeStatus == HandshakeStatus.NEED_UNWRAP) {
            int positionBeforeHandshake = src.position();
            OpenSSLBIOSource source = OpenSSLBIOSource.wrap(src);
            long sslSessionCtx = 0L;
            try {
                sslSessionCtx = NativeCrypto.SSL_do_handshake_bio(sslNativePointer,
                        source.getContext(), handshakeSink.getContext(), this, getUseClientMode(),
                        sslParameters.npnProtocols, sslParameters.alpnProtocols);
                if (sslSessionCtx != 0) {
                    if (sslSession != null && engineState == EngineState.HANDSHAKE_STARTED) {
                        engineState = EngineState.READY_HANDSHAKE_CUT_THROUGH;
                    }
                    sslSession = sslParameters.setupSession(sslSessionCtx, sslNativePointer, sslSession,
                            getPeerHost(), getPeerPort(), true);
                }
                int bytesWritten = handshakeSink.position();
                int bytesConsumed = (src.position() - positionBeforeHandshake);
                return new SSLEngineResult((bytesConsumed > 0) ? Status.OK : Status.BUFFER_UNDERFLOW,
                        getHandshakeStatus(), bytesConsumed, bytesWritten);
            } catch (Exception e) {
                throw (SSLHandshakeException) new SSLHandshakeException("Handshake failed")
                        .initCause(e);
            } finally {
                if (sslSession == null && sslSessionCtx != 0) {
                    NativeCrypto.SSL_SESSION_free(sslSessionCtx);
                }
                source.release();
            }
        } else if (handshakeStatus != HandshakeStatus.NOT_HANDSHAKING) {
            return new SSLEngineResult(Status.OK, handshakeStatus, 0, 0);
        }

        if (dstRemaining == 0) {
            return new SSLEngineResult(Status.BUFFER_OVERFLOW, getHandshakeStatus(), 0, 0);
        }

        ByteBuffer srcDuplicate = src.duplicate();
        OpenSSLBIOSource source = OpenSSLBIOSource.wrap(srcDuplicate);
        try {
            int positionBeforeRead = srcDuplicate.position();
            int produced = 0;
            boolean shouldStop = false;

            while (!shouldStop) {
                ByteBuffer dst = getNextAvailableByteBuffer(dsts, offset, length);
                if (dst == null) {
                    shouldStop = true;
                    continue;
                }
                ByteBuffer arrayDst = dst;
                if (dst.isDirect()) {
                    arrayDst = ByteBuffer.allocate(dst.remaining());
                }

                int dstOffset = arrayDst.arrayOffset() + arrayDst.position();

                int internalProduced = NativeCrypto.SSL_read_BIO(sslNativePointer,
                        arrayDst.array(), dstOffset, dst.remaining(), source.getContext(),
                        localToRemoteSink.getContext(), this);
                if (internalProduced <= 0) {
                    shouldStop = true;
                    continue;
                }
                arrayDst.position(arrayDst.position() + internalProduced);
                produced += internalProduced;
                if (dst != arrayDst) {
                    arrayDst.flip();
                    dst.put(arrayDst);
                }
            }

            int consumed = srcDuplicate.position() - positionBeforeRead;
            src.position(srcDuplicate.position());
            return new SSLEngineResult((consumed > 0) ? Status.OK : Status.BUFFER_UNDERFLOW,
                    getHandshakeStatus(), consumed, produced);
        } catch (IOException e) {
            throw new SSLException(e);
        } finally {
            source.release();
        }
    }

    /** Returns the next non-empty ByteBuffer. */
    private ByteBuffer getNextAvailableByteBuffer(ByteBuffer[] buffers, int offset, int length) {
        for (int i = offset; i < length; ++i) {
            if (buffers[i].remaining() > 0) {
                return buffers[i];
            }
        }
        return null;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
            throws SSLException {
        if (srcs == null) {
            throw new IllegalArgumentException("srcs == null");
        } else if (dst == null) {
            throw new IllegalArgumentException("dst == null");
        } else if (dst.isReadOnly()) {
            throw new ReadOnlyBufferException();
        }
        for (ByteBuffer src : srcs) {
            if (src == null) {
                throw new IllegalArgumentException("one of the src == null");
            }
        }
        checkIndex(srcs.length, offset, length);

        if (dst.remaining() < NativeConstants.SSL3_RT_MAX_PACKET_SIZE) {
            return new SSLEngineResult(Status.BUFFER_OVERFLOW, getHandshakeStatus(), 0, 0);
        }

        synchronized (stateLock) {
            // If the outbound direction is closed. we can't send anymore.
            if (engineState == EngineState.CLOSED || engineState == EngineState.CLOSED_OUTBOUND) {
                return new SSLEngineResult(Status.CLOSED, getHandshakeStatus(), 0, 0);
            }
            if (engineState == EngineState.NEW || engineState == EngineState.MODE_SET) {
                beginHandshake();
            }
        }

        // If we haven't completed the handshake yet, just let the caller know.
        HandshakeStatus handshakeStatus = getHandshakeStatus();
        if (handshakeStatus == HandshakeStatus.NEED_WRAP) {
            if (handshakeSink.available() == 0) {
                long sslSessionCtx = 0L;
                try {
                    sslSessionCtx = NativeCrypto.SSL_do_handshake_bio(sslNativePointer,
                            nullSource.getContext(), handshakeSink.getContext(), this,
                            getUseClientMode(), sslParameters.npnProtocols,
                            sslParameters.alpnProtocols);
                    if (sslSessionCtx != 0) {
                        if (sslSession != null && engineState == EngineState.HANDSHAKE_STARTED) {
                            engineState = EngineState.READY_HANDSHAKE_CUT_THROUGH;
                        }
                        sslSession = sslParameters.setupSession(sslSessionCtx, sslNativePointer, sslSession,
                                getPeerHost(), getPeerPort(), true);
                    }
                } catch (Exception e) {
                    throw (SSLHandshakeException) new SSLHandshakeException("Handshake failed")
                            .initCause(e);
                } finally {
                    if (sslSession == null && sslSessionCtx != 0) {
                        NativeCrypto.SSL_SESSION_free(sslSessionCtx);
                    }
                }
            }
            int bytesWritten = writeSinkToByteBuffer(handshakeSink, dst);
            return new SSLEngineResult(Status.OK, getHandshakeStatus(), 0, bytesWritten);
        } else if (handshakeStatus != HandshakeStatus.NOT_HANDSHAKING) {
            return new SSLEngineResult(Status.OK, handshakeStatus, 0, 0);
        }

        try {
            int totalRead = 0;
            byte[] buffer = null;

            for (ByteBuffer src : srcs) {
                int toRead = src.remaining();
                if (buffer == null || toRead > buffer.length) {
                    buffer = new byte[toRead];
                }
                /*
                 * We can't just use .mark() here because the caller might be
                 * using it.
                 */
                src.duplicate().get(buffer, 0, toRead);
                int numRead = NativeCrypto.SSL_write_BIO(sslNativePointer, buffer, toRead,
                        localToRemoteSink.getContext(), this);
                if (numRead > 0) {
                    src.position(src.position() + numRead);
                    totalRead += numRead;
                }
            }

            return new SSLEngineResult(Status.OK, getHandshakeStatus(), totalRead,
                    writeSinkToByteBuffer(localToRemoteSink, dst));
        } catch (IOException e) {
            throw new SSLException(e);
        }
    }

    /** Writes data available in a BIO sink to a ByteBuffer. */
    private static int writeSinkToByteBuffer(OpenSSLBIOSink sink, ByteBuffer dst) {
        int toWrite = Math.min(sink.available(), dst.remaining());
        dst.put(sink.toByteArray(), sink.position(), toWrite);
        sink.skip(toWrite);
        return toWrite;
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
    public void onSSLStateChange(long sslSessionNativePtr, int type, int val) {
        synchronized (stateLock) {
            switch (type) {
                case NativeConstants.SSL_CB_HANDSHAKE_DONE:
                    if (engineState != EngineState.HANDSHAKE_STARTED &&
                        engineState != EngineState.READY_HANDSHAKE_CUT_THROUGH) {
                        throw new IllegalStateException("Completed handshake while in mode "
                                + engineState);
                    }
                    engineState = EngineState.HANDSHAKE_COMPLETED;
                    break;
                case NativeConstants.SSL_CB_HANDSHAKE_START:
                    // For clients, this will allow the NEED_UNWRAP status to be
                    // returned.
                    engineState = EngineState.HANDSHAKE_STARTED;
                    break;
            }
        }
    }

    @Override
    public void verifyCertificateChain(long sslSessionNativePtr, long[] certRefs,
            String authMethod) throws CertificateException {
        try {
            X509TrustManager x509tm = sslParameters.getX509TrustManager();
            if (x509tm == null) {
                throw new CertificateException("No X.509 TrustManager");
            }
            if (certRefs == null || certRefs.length == 0) {
                throw new SSLException("Peer sent no certificate");
            }
            OpenSSLX509Certificate[] peerCertChain = new OpenSSLX509Certificate[certRefs.length];
            for (int i = 0; i < certRefs.length; i++) {
                peerCertChain[i] = new OpenSSLX509Certificate(certRefs[i]);
            }

            // Used for verifyCertificateChain callback
            handshakeSession = new OpenSSLSessionImpl(sslSessionNativePtr, null, peerCertChain,
                    getPeerHost(), getPeerPort(), null);

            boolean client = sslParameters.getUseClientMode();
            if (client) {
                Platform.checkServerTrusted(x509tm, peerCertChain, authMethod, getPeerHost());
            } else {
                String authType = peerCertChain[0].getPublicKey().getAlgorithm();
                x509tm.checkClientTrusted(peerCertChain, authType);
            }
        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException(e);
        } finally {
            // Clear this before notifying handshake completed listeners
            handshakeSession = null;
        }
    }

    @Override
    public void clientCertificateRequested(byte[] keyTypeBytes, byte[][] asn1DerEncodedPrincipals)
            throws CertificateEncodingException, SSLException {
        sslParameters.chooseClientCertificate(keyTypeBytes, asn1DerEncodedPrincipals,
                sslNativePointer, this);
    }

    private void shutdown() {
        try {
            NativeCrypto.SSL_shutdown_BIO(sslNativePointer, nullSource.getContext(),
                    localToRemoteSink.getContext(), this);
        } catch (IOException ignored) {
            /*
             * TODO: The RI ignores close failures in SSLSocket, but need to
             * investigate whether it does for SSLEngine.
             */
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
        sslNativePointer = 0;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            free();
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
    public String chooseClientAlias(X509KeyManager keyManager, X500Principal[] issuers,
            String[] keyTypes) {
        if (keyManager instanceof X509ExtendedKeyManager) {
            X509ExtendedKeyManager ekm = (X509ExtendedKeyManager) keyManager;
            return ekm.chooseEngineClientAlias(keyTypes, issuers, this);
        } else {
            return keyManager.chooseClientAlias(keyTypes, issuers, null);
        }
    }

    @Override
    public String chooseServerPSKIdentityHint(PSKKeyManager keyManager) {
        return keyManager.chooseServerKeyIdentityHint(this);
    }

    @Override
    public String chooseClientPSKIdentity(PSKKeyManager keyManager, String identityHint) {
        return keyManager.chooseClientKeyIdentity(identityHint, this);
    }

    @Override
    public SecretKey getPSKKey(PSKKeyManager keyManager, String identityHint, String identity) {
        return keyManager.getKey(identityHint, identity, this);
    }
}
