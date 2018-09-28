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

import static org.conscrypt.Preconditions.checkNotNull;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * A wrapper around {@link ConscryptEngine} that adapts to the new Java 9 (and potentially later
 * patches of 8) {@code setHandshakeApplicationProtocolSelector} API (which requires Java 8 for
 * compilation, due to the use of {@link BiFunction}).
 */
final class Java8EngineWrapper extends AbstractConscryptEngine {
    private final ConscryptEngine delegate;
    private BiFunction<SSLEngine, List<String>, String> selector;

    Java8EngineWrapper(ConscryptEngine delegate) {
        this.delegate = checkNotNull(delegate, "delegate");
    }

    static SSLEngine getDelegate(SSLEngine engine) {
        if (engine instanceof Java8EngineWrapper) {
            return ((Java8EngineWrapper) engine).delegate;
        }
        return engine;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] byteBuffers, ByteBuffer byteBuffer)
            throws SSLException {
        return delegate.wrap(byteBuffers, byteBuffer);
    }

    @Override
    public SSLParameters getSSLParameters() {
        return delegate.getSSLParameters();
    }

    @Override
    public void setSSLParameters(SSLParameters sslParameters) {
        delegate.setSSLParameters(sslParameters);
    }

    @Override
    void setBufferAllocator(BufferAllocator bufferAllocator) {
        delegate.setBufferAllocator(bufferAllocator);
    }

    @Override
    int maxSealOverhead() {
        return delegate.maxSealOverhead();
    }

    @Override
    void setChannelIdEnabled(boolean enabled) {
        delegate.setChannelIdEnabled(enabled);
    }

    @Override
    byte[] getChannelId() throws SSLException {
        return delegate.getChannelId();
    }

    @Override
    void setChannelIdPrivateKey(PrivateKey privateKey) {
        delegate.setChannelIdPrivateKey(privateKey);
    }

    @Override
    void setHandshakeListener(HandshakeListener handshakeListener) {
        delegate.setHandshakeListener(handshakeListener);
    }

    @Override
    void setHostname(String hostname) {
        delegate.setHostname(hostname);
    }

    @Override
    String getHostname() {
        return delegate.getHostname();
    }

    @Override
    public String getPeerHost() {
        return delegate.getPeerHost();
    }

    @Override
    public int getPeerPort() {
        return delegate.getPeerPort();
    }

    @Override
    public void beginHandshake() throws SSLException {
        delegate.beginHandshake();
    }

    @Override
    public void closeInbound() throws SSLException {
        delegate.closeInbound();
    }

    @Override
    public void closeOutbound() {
        delegate.closeOutbound();
    }

    @Override
    public Runnable getDelegatedTask() {
        return delegate.getDelegatedTask();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return delegate.getEnabledCipherSuites();
    }

    @Override
    public String[] getEnabledProtocols() {
        return delegate.getEnabledProtocols();
    }

    @Override
    public boolean getEnableSessionCreation() {
        return delegate.getEnableSessionCreation();
    }

    @Override
    public HandshakeStatus getHandshakeStatus() {
        return delegate.getHandshakeStatus();
    }

    @Override
    public boolean getNeedClientAuth() {
        return delegate.getNeedClientAuth();
    }

    @Override
    SSLSession handshakeSession() {
        return delegate.handshakeSession();
    }

    @Override
    public SSLSession getSession() {
        return delegate.getSession();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public String[] getSupportedProtocols() {
        return delegate.getSupportedProtocols();
    }

    @Override
    public boolean getUseClientMode() {
        return delegate.getUseClientMode();
    }

    @Override
    public boolean getWantClientAuth() {
        return delegate.getWantClientAuth();
    }

    @Override
    public boolean isInboundDone() {
        return delegate.isInboundDone();
    }

    @Override
    public boolean isOutboundDone() {
        return delegate.isOutboundDone();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        delegate.setEnabledCipherSuites(suites);
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        delegate.setEnabledProtocols(protocols);
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        delegate.setEnableSessionCreation(flag);
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        delegate.setNeedClientAuth(need);
    }

    @Override
    public void setUseClientMode(boolean mode) {
        delegate.setUseClientMode(mode);
    }

    @Override
    public void setWantClientAuth(boolean want) {
        delegate.setWantClientAuth(want);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return delegate.unwrap(src, dst);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException {
        return delegate.unwrap(src, dsts);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
            throws SSLException {
        return delegate.unwrap(src, dsts, offset, length);
    }

    @Override
    SSLEngineResult unwrap(ByteBuffer[] srcs, ByteBuffer[] dsts) throws SSLException {
        return delegate.unwrap(srcs, dsts);
    }

    @Override
    SSLEngineResult unwrap(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts,
            int dstsOffset, int dstsLength) throws SSLException {
        return delegate.unwrap(srcs, srcsOffset, srcsLength, dsts, dstsOffset, dstsLength);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return delegate.wrap(src, dst);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer dst)
            throws SSLException {
        return delegate.wrap(srcs, srcsOffset, srcsLength, dst);
    }

    @Override
    void setUseSessionTickets(boolean useSessionTickets) {
        delegate.setUseSessionTickets(useSessionTickets);
    }

    @Override
    void setApplicationProtocols(String[] protocols) {
        delegate.setApplicationProtocols(protocols);
    }

    @Override
    String[] getApplicationProtocols() {
        return delegate.getApplicationProtocols();
    }

    @Override
    public String getApplicationProtocol() {
        return delegate.getApplicationProtocol();
    }

    @Override
    void setApplicationProtocolSelector(ApplicationProtocolSelector selector) {
        delegate.setApplicationProtocolSelector(
                selector == null ? null : new ApplicationProtocolSelectorAdapter(this, selector));
    }

    @Override
    byte[] getTlsUnique() {
        return delegate.getTlsUnique();
    }

    @Override
    byte[] exportKeyingMaterial(String label, byte[] context, int length) throws SSLException {
        return delegate.exportKeyingMaterial(label, context, length);
    }

    @Override
    public String getHandshakeApplicationProtocol() {
        return delegate.getHandshakeApplicationProtocol();
    }

    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java < 9.
    public void setHandshakeApplicationProtocolSelector(
            final BiFunction<SSLEngine, List<String>, String> selector) {
        this.selector = selector;
        setApplicationProtocolSelector(toApplicationProtocolSelector(selector));
    }

    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java < 9.
    public BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return selector;
    }

    private static ApplicationProtocolSelector toApplicationProtocolSelector(
            final BiFunction<SSLEngine, List<String>, String> selector) {
        return selector == null ? null : new ApplicationProtocolSelector() {
            @Override
            public String selectApplicationProtocol(SSLEngine engine, List<String> protocols) {
                return selector.apply(engine, protocols);
            }

            @Override
            public String selectApplicationProtocol(SSLSocket socket, List<String> protocols) {
                throw new UnsupportedOperationException();
            }
        };
    }
}
