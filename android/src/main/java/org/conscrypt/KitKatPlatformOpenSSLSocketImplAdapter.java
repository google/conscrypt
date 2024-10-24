/*
 * Copyright (C) 2015 The Android Open Source Project
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

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/**
 * This class delegates all calls to an {@code org.conscrypt.OpenSSLSocketImpl}.
 * This is to work around code that checks that the socket is an
 * {@code org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl} before
 * calling methods, such as setting SNI. This is only for KitKat.
 *
 * It delegates all public methods in Socket, SSLSocket, and OpenSSLSocket from
 * KK.
 */
@Internal
public class KitKatPlatformOpenSSLSocketImplAdapter
        extends com.android.org.conscrypt.OpenSSLSocketImpl {


    private final AbstractConscryptSocket delegate;

    public KitKatPlatformOpenSSLSocketImplAdapter(AbstractConscryptSocket delegate)
            throws IOException {
        super(null);
        this.delegate = delegate;
    }

    // Socket methods.

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void close() throws IOException {
        delegate.close();
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return delegate.getInputStream();
    }

    @Override
    public int getLocalPort() {
        return delegate.getLocalPort();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return delegate.getOutputStream();
    }

    @Override
    public int getPort() {
        return delegate.getPort();
    }

    @Override
    public void connect(SocketAddress sockaddr, int timeout) throws IOException {
        delegate.connect(sockaddr, timeout);
    }

    @Override
    public void connect(SocketAddress sockaddr) throws IOException {
        delegate.connect(sockaddr);
    }

    @Override
    public void bind(SocketAddress sockaddr) throws IOException {
        delegate.bind(sockaddr);
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return delegate.getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return delegate.getLocalSocketAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return delegate.getLocalAddress();
    }

    @Override
    public InetAddress getInetAddress() {
        return delegate.getInetAddress();
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        delegate.setSoLinger(on, linger);
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        delegate.setTcpNoDelay(on);
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        delegate.setReuseAddress(on);
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        delegate.setKeepAlive(on);
    }

    @Override
    public void setTrafficClass(int tos) throws SocketException {
        delegate.setTrafficClass(tos);
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void setSoTimeout(int to) throws SocketException {
        delegate.setSoTimeout(to);
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void setSendBufferSize(int size) throws SocketException {
        delegate.setSendBufferSize(size);
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void setReceiveBufferSize(int size) throws SocketException {
        delegate.setReceiveBufferSize(size);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return delegate.getTcpNoDelay();
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        return delegate.getReuseAddress();
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return delegate.getKeepAlive();
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public int getSoTimeout() throws SocketException {
        return delegate.getSoTimeout();
    }

    @Override
    public int getSoLinger() throws SocketException {
        return delegate.getSoLinger();
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public int getSendBufferSize() throws SocketException {
        return delegate.getSendBufferSize();
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public int getReceiveBufferSize() throws SocketException {
        return delegate.getReceiveBufferSize();
    }

    @Override
    public boolean isConnected() {
        return delegate.isConnected();
    }

    @Override
    public boolean isClosed() {
        return delegate.isClosed();
    }

    @Override
    public boolean isBound() {
        return delegate.isBound();
    }

    @Override
    public boolean isOutputShutdown() {
        return delegate.isOutputShutdown();
    }

    @Override
    public boolean isInputShutdown() {
        return delegate.isInputShutdown();
    }

    @Override
    public void shutdownInput() throws IOException {
        delegate.shutdownInput();
    }

    @Override
    public void shutdownOutput() throws IOException {
        delegate.shutdownOutput();
    }

    @Override
    public void setOOBInline(boolean oobinline) throws SocketException {
        delegate.setOOBInline(oobinline);
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return delegate.getOOBInline();
    }

    @Override
    public int getTrafficClass() throws SocketException {
        return delegate.getTrafficClass();
    }

    @Override
    public void sendUrgentData(int value) throws IOException {
        delegate.sendUrgentData(value);
    }

    @Override
    public SocketChannel getChannel() {
        return delegate.getChannel();
    }

    @Override
    public FileDescriptor getFileDescriptor$() {
        return delegate.getFileDescriptor$();
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        delegate.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    // SSLSocket methods.

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return delegate.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        delegate.setEnabledCipherSuites(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return delegate.getSupportedProtocols();
    }
    @Override
    public String[] getEnabledProtocols() {
        return delegate.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        delegate.setEnabledProtocols(protocols);
    }

    @Override
    public SSLSession getSession() {
        return delegate.getSession();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        delegate.addHandshakeCompletedListener(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        delegate.removeHandshakeCompletedListener(listener);
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void startHandshake() throws IOException {
        delegate.startHandshake();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        delegate.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return delegate.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        delegate.setNeedClientAuth(need);
    }

    @Override
    public void setWantClientAuth(boolean want) {
        delegate.setWantClientAuth(want);
    }

    @Override
    public boolean getNeedClientAuth() {
        return delegate.getNeedClientAuth();
    }

    @Override
    public boolean getWantClientAuth() {
        return delegate.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        delegate.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return delegate.getEnableSessionCreation();
    }

    @Override
    public SSLParameters getSSLParameters() {
        return delegate.getSSLParameters();
    }

    @Override
    public void setSSLParameters(SSLParameters p) {
        delegate.setSSLParameters(p);
    }

    // OpenSSLSocket methods.
    @Override
    public void clientCertificateRequested(byte[] keyTypeBytes, byte[][] asn1DerEncodedPrincipals)
            throws CertificateEncodingException, SSLException {
        throw new RuntimeException("Shouldn't be here!");
    }

    @Override
    public void handshakeCompleted() {
        throw new RuntimeException("Shouldn't be here!");
    }

    @Override
    public void verifyCertificateChain(byte[][] bytes, String authMethod)
            throws CertificateException {
        throw new RuntimeException("Shouldn't be here!");
    }

    @Override
    public void setUseSessionTickets(boolean useSessionTickets) {
        delegate.setUseSessionTickets(useSessionTickets);
    }

    @Override
    public void setHostname(String hostname) {
        delegate.setHostname(hostname);
    }

    @Override
    public void setChannelIdEnabled(boolean enabled) {
        delegate.setChannelIdEnabled(enabled);
    }

    @Override
    public byte[] getChannelId() throws SSLException {
        return delegate.getChannelId();
    }

    @Override
    public void setChannelIdPrivateKey(PrivateKey privateKey) {
        delegate.setChannelIdPrivateKey(privateKey);
    }

    @Override
    public void setSoWriteTimeout(int writeTimeoutMilliseconds) throws SocketException {
        delegate.setSoWriteTimeout(writeTimeoutMilliseconds);
    }

    @Override
    public int getSoWriteTimeout() throws SocketException {
        return delegate.getSoWriteTimeout();
    }

    @Override
    public void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException {
        delegate.setHandshakeTimeout(handshakeTimeoutMilliseconds);
    }

    // These aren't in the Platform's OpenSSLSocketImpl but we have them to support duck typing.
    @SuppressWarnings("deprecation")
    public byte[] getAlpnSelectedProtocol() {
        return delegate.getAlpnSelectedProtocol();
    }

    @SuppressWarnings("deprecation")
    public void setAlpnProtocols(byte[] alpnProtocols) {
        delegate.setAlpnProtocols(alpnProtocols);
    }
}
