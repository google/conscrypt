package org.conscrypt;

import static org.conscrypt.Preconditions.checkNotNull;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.security.PrivateKey;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * A wrapper around a Conscrypt socket that adapts to the new Java 9 (and potentially later
 * patches of 8) {@code setHandshakeApplicationProtocolSelector​} API (which requires Java 8 for
 * compilation, due to the use of {@link BiFunction}).
 */
public final class Java8SocketWrapper extends AbstractConscryptSocket {
    private final ConscryptSocketBase delegate;
    private BiFunction<SSLSocket, List<String>, String> selector;

    Java8SocketWrapper(ConscryptSocketBase delegate) {
        this.delegate = checkNotNull(delegate, "delegate");
    }

    static SSLSocket getDelegate(SSLSocket socket) {
        if (socket instanceof Java8SocketWrapper) {
            return ((Java8SocketWrapper) socket).delegate;
        }
        return socket;
    }

    @Override
    @SuppressWarnings("deprecation")
    byte[] getNpnSelectedProtocol() {
        return delegate.getNpnSelectedProtocol();
    }

    @Override
    @SuppressWarnings("deprecation")
    void setNpnProtocols(byte[] npnProtocols) {
        delegate.setNpnProtocols(npnProtocols);
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
    public void connect(SocketAddress endpoint) throws IOException {
        delegate.connect(endpoint);
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        delegate.connect(endpoint, timeout);
    }

    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        delegate.bind(bindpoint);
    }

    @Override
    public InetAddress getInetAddress() {
        return delegate.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return delegate.getLocalAddress();
    }

    @Override
    public int getPort() {
        return delegate.getPort();
    }

    @Override
    public int getLocalPort() {
        return delegate.getLocalPort();
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
    public SocketChannel getChannel() {
        return delegate.getChannel();
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return delegate.getInputStream();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return delegate.getOutputStream();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        delegate.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return delegate.getTcpNoDelay();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        delegate.setSoLinger(on, linger);
    }

    @Override
    public int getSoLinger() throws SocketException {
        return delegate.getSoLinger();
    }

    @Override
    public void sendUrgentData(int data) throws IOException {
        delegate.sendUrgentData(data);
    }

    @Override
    public void setOOBInline(boolean on) throws SocketException {
        delegate.setOOBInline(on);
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return delegate.getOOBInline();
    }

    @Override
    public synchronized void setSoTimeout(int timeout) throws SocketException {
        delegate.setSoTimeout(timeout);
    }

    @Override
    public synchronized int getSoTimeout() throws SocketException {
        return delegate.getSoTimeout();
    }

    @Override
    public synchronized void setSendBufferSize(int size) throws SocketException {
        delegate.setSendBufferSize(size);
    }

    @Override
    public synchronized int getSendBufferSize() throws SocketException {
        return delegate.getSendBufferSize();
    }

    @Override
    public synchronized void setReceiveBufferSize(int size) throws SocketException {
        delegate.setReceiveBufferSize(size);
    }

    @Override
    public synchronized int getReceiveBufferSize() throws SocketException {
        return delegate.getReceiveBufferSize();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        delegate.setKeepAlive(on);
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return delegate.getKeepAlive();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        delegate.setTrafficClass(tc);
    }

    @Override
    public int getTrafficClass() throws SocketException {
        return delegate.getTrafficClass();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        delegate.setReuseAddress(on);
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        return delegate.getReuseAddress();
    }

    @Override
    public synchronized void close() throws IOException {
        delegate.close();
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
    public String toString() {
        return delegate.toString();
    }

    @Override
    public boolean isConnected() {
        return delegate.isConnected();
    }

    @Override
    public boolean isBound() {
        return delegate.isBound();
    }

    @Override
    public boolean isClosed() {
        return delegate.isClosed();
    }

    @Override
    public boolean isInputShutdown() {
        return delegate.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown() {
        return delegate.isOutputShutdown();
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        delegate.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return delegate.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] strings) {
        delegate.setEnabledCipherSuites(strings);
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
    public void setEnabledProtocols(String[] strings) {
        delegate.setEnabledProtocols(strings);
    }

    @Override
    public SSLSession getSession() {
        return delegate.getSession();
    }

    @Override
    public SSLSession getHandshakeSession() {
        return delegate.getHandshakeSession();
    }

    @Override
    public void addHandshakeCompletedListener(
            HandshakeCompletedListener handshakeCompletedListener) {
        delegate.addHandshakeCompletedListener(handshakeCompletedListener);
    }

    @Override
    public void removeHandshakeCompletedListener(
            HandshakeCompletedListener handshakeCompletedListener) {
        delegate.removeHandshakeCompletedListener(handshakeCompletedListener);
    }

    @Override
    public void startHandshake() throws IOException {
        delegate.startHandshake();
    }

    @Override
    public void setUseClientMode(boolean b) {
        delegate.setUseClientMode(b);
    }

    @Override
    public boolean getUseClientMode() {
        return delegate.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean b) {
        delegate.setNeedClientAuth(b);
    }

    @Override
    public boolean getNeedClientAuth() {
        return delegate.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean b) {
        delegate.setWantClientAuth(b);
    }

    @Override
    public boolean getWantClientAuth() {
        return delegate.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean b) {
        delegate.setEnableSessionCreation(b);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return delegate.getEnableSessionCreation();
    }

    @Override
    public FileDescriptor getFileDescriptor$() {
        return delegate.getFileDescriptor$();
    }

    @Override
    String getHostname() {
        return delegate.getHostname();
    }

    @Override
    void setHostname(String hostname) {
        delegate.setHostname(hostname);
    }

    @Override
    String getHostnameOrIP() {
        return delegate.getHostnameOrIP();
    }

    @Override
    void setSoWriteTimeout(int writeTimeoutMilliseconds) throws SocketException {
        delegate.setSoWriteTimeout(writeTimeoutMilliseconds);
    }

    @Override
    int getSoWriteTimeout() throws SocketException {
        return delegate.getSoWriteTimeout();
    }

    @Override
    void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException {
        delegate.setHandshakeTimeout(handshakeTimeoutMilliseconds);
    }

    @Override
    void setUseSessionTickets(boolean useSessionTickets) {
        delegate.setUseSessionTickets(useSessionTickets);
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
    @Deprecated
    @SuppressWarnings("deprecation")
    public byte[] getAlpnSelectedProtocol() {
        return delegate.getAlpnSelectedProtocol();
    }

    @Override
    @Deprecated
    @SuppressWarnings("deprecation")
    public void setAlpnProtocols(String[] alpnProtocols) {
        delegate.setAlpnProtocols(alpnProtocols);
    }

    @Override
    @Deprecated
    @SuppressWarnings("deprecation")
    public void setAlpnProtocols(byte[] alpnProtocols) {
        delegate.setAlpnProtocols(alpnProtocols);
    }

    @Override
    void setApplicationProtocolSelector(ApplicationProtocolSelector selector) {
        delegate.setApplicationProtocolSelector(
                selector == null ? null : new ApplicationProtocolSelectorAdapter(this, selector));
    }

    @Override
    PeerInfoProvider peerInfoProvider() {
        return delegate.peerInfoProvider();
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
    public String getApplicationProtocol​() {
        return delegate.getApplicationProtocol​();
    }

    @Override
    public String getHandshakeApplicationProtocol​() {
        return delegate.getHandshakeApplicationProtocol​();
    }

    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java < 9.
    public void setHandshakeApplicationProtocolSelector​(
            final BiFunction<SSLSocket, List<String>, String> selector) {
        this.selector = selector;
        setApplicationProtocolSelector(toApplicationProtocolSelector(selector));
    }

    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java < 9.
    public BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector​() {
        return selector;
    }

    private static ApplicationProtocolSelector toApplicationProtocolSelector(
        final BiFunction<SSLSocket, List<String>, String> selector) {
        return selector == null ? null : new ApplicationProtocolSelector() {
            @Override
            public String selectApplicationProtocol(SSLEngine socket, List<String> protocols) {
                throw new UnsupportedOperationException();
            }

            @Override
            public String selectApplicationProtocol(SSLSocket socket, List<String> protocols) {
                return selector.apply(socket, protocols);
            }
        };
    }
}
