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

import static org.conscrypt.Preconditions.checkArgument;
import static org.conscrypt.Preconditions.checkNotNull;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Abstract base class for all Conscrypt {@link SSLSocket} classes.
 */
abstract class AbstractConscryptSocket extends SSLSocket {
    final Socket socket;
    private final boolean autoClose;

    /**
     * The peer's DNS hostname if it was supplied during creation. Note that
     * this may be a raw IP address, so it should be checked before use with
     * extensions that don't use it like Server Name Indication (SNI).
     */
    private String peerHostname;

    /**
     * The peer's port if it was supplied during creation. Should only be set if
     * {@link #peerHostname} is also set.
     */
    private final int peerPort;

    private final PeerInfoProvider peerInfoProvider = new PeerInfoProvider() {
        @Override
        String getHostname() {
            return AbstractConscryptSocket.this.getHostname();
        }

        @Override
        String getHostnameOrIP() {
            return AbstractConscryptSocket.this.getHostnameOrIP();
        }

        @Override
        int getPort() {
            return AbstractConscryptSocket.this.getPort();
        }
    };

    private final List<HandshakeCompletedListener> listeners =
            new ArrayList<HandshakeCompletedListener>(2);

    /**
     * Local cache of timeout to avoid getsockopt on every read and
     * write for non-wrapped sockets. Note that this is not used when delegating
     * to another socket.
     */
    private int readTimeoutMilliseconds;

    AbstractConscryptSocket() throws IOException {
        this.socket = this;
        this.peerHostname = null;
        this.peerPort = -1;
        this.autoClose = false;
    }

    AbstractConscryptSocket(String hostname, int port) throws IOException {
        super(hostname, port);
        this.socket = this;
        this.peerHostname = hostname;
        this.peerPort = port;
        this.autoClose = false;
    }

    AbstractConscryptSocket(InetAddress address, int port) throws IOException {
        super(address, port);
        this.socket = this;
        this.peerHostname = null;
        this.peerPort = -1;
        this.autoClose = false;
    }

    AbstractConscryptSocket(String hostname, int port, InetAddress clientAddress, int clientPort)
            throws IOException {
        super(hostname, port, clientAddress, clientPort);
        this.socket = this;
        this.peerHostname = hostname;
        this.peerPort = port;
        this.autoClose = false;
    }

    AbstractConscryptSocket(InetAddress address, int port, InetAddress clientAddress,
            int clientPort) throws IOException {
        super(address, port, clientAddress, clientPort);
        this.socket = this;
        this.peerHostname = null;
        this.peerPort = -1;
        this.autoClose = false;
    }

    AbstractConscryptSocket(Socket socket, String hostname, int port, boolean autoClose)
            throws IOException {
        this.socket = checkNotNull(socket, "socket");
        this.peerHostname = hostname;
        this.peerPort = port;
        this.autoClose = autoClose;
    }

    @Override
    public final void connect(SocketAddress endpoint) throws IOException {
        connect(endpoint, 0);
    }

    /**
     * Try to extract the peer's hostname if it's available from the endpoint address.
     */
    @Override
    public final void connect(SocketAddress endpoint, int timeout) throws IOException {
        if (peerHostname == null && endpoint instanceof InetSocketAddress) {
            peerHostname =
                    Platform.getHostStringFromInetSocketAddress((InetSocketAddress) endpoint);
        }

        if (isDelegating()) {
            socket.connect(endpoint, timeout);
        } else {
            super.connect(endpoint, timeout);
        }
    }

    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        if (isDelegating()) {
            socket.bind(bindpoint);
        } else {
            super.bind(bindpoint);
        }
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void close() throws IOException {
        if (isDelegating()) {
            if (autoClose && !socket.isClosed()) {
                socket.close();
            }
        } else {
            if (!super.isClosed()) {
                super.close();
            }
        }
    }

    @Override
    public InetAddress getInetAddress() {
        if (isDelegating()) {
            return socket.getInetAddress();
        }
        return super.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        if (isDelegating()) {
            return socket.getLocalAddress();
        }
        return super.getLocalAddress();
    }

    @Override
    public int getLocalPort() {
        if (isDelegating()) {
            return socket.getLocalPort();
        }
        return super.getLocalPort();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        if (isDelegating()) {
            return socket.getRemoteSocketAddress();
        }
        return super.getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        if (isDelegating()) {
            return socket.getLocalSocketAddress();
        }
        return super.getLocalSocketAddress();
    }

    @Override
    public final int getPort() {
        if (isDelegating()) {
            return socket.getPort();
        }

        if (peerPort != -1) {
            // Return the port that has been explicitly set in the constructor.
            return peerPort;
        }
        return super.getPort();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        checkArgument(listener != null, "Provided listener is null");
        listeners.add(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        checkArgument(listener != null, "Provided listener is null");
        if (!listeners.remove(listener)) {
            throw new IllegalArgumentException("Provided listener is not registered");
        }
    }

    /* @Override */
    public FileDescriptor getFileDescriptor$() {
        if (isDelegating()) {
            return Platform.getFileDescriptor(socket);
        }
        return Platform.getFileDescriptorFromSSLSocket(this);
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public final void setSoTimeout(int readTimeoutMilliseconds) throws SocketException {
        if (isDelegating()) {
            socket.setSoTimeout(readTimeoutMilliseconds);
        } else {
            super.setSoTimeout(readTimeoutMilliseconds);
            this.readTimeoutMilliseconds = readTimeoutMilliseconds;
        }
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public final int getSoTimeout() throws SocketException {
        if (isDelegating()) {
            return socket.getSoTimeout();
        }
        return readTimeoutMilliseconds;
    }

    @Override
    public final void sendUrgentData(int data) throws IOException {
        throw new SocketException("Method sendUrgentData() is not supported.");
    }

    @Override
    public final void setOOBInline(boolean on) throws SocketException {
        throw new SocketException("Method setOOBInline() is not supported.");
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return false;
    }

    @Override
    public SocketChannel getChannel() {
        // TODO(nmittler): Support channels?
        return null;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        if (isDelegating()) {
            return socket.getInputStream();
        }
        return super.getInputStream();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        if (isDelegating()) {
            return socket.getOutputStream();
        }
        return super.getOutputStream();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        if (isDelegating()) {
            socket.setTcpNoDelay(on);
        } else {
            super.setTcpNoDelay(on);
        }
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        if (isDelegating()) {
            return socket.getTcpNoDelay();
        }
        return super.getTcpNoDelay();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        if (isDelegating()) {
            socket.setSoLinger(on, linger);
        } else {
            super.setSoLinger(on, linger);
        }
    }

    @Override
    public int getSoLinger() throws SocketException {
        if (isDelegating()) {
            return socket.getSoLinger();
        }
        return super.getSoLinger();
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void setSendBufferSize(int size) throws SocketException {
        if (isDelegating()) {
            socket.setSendBufferSize(size);
        } else {
            super.setSendBufferSize(size);
        }
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public int getSendBufferSize() throws SocketException {
        if (isDelegating()) {
            return socket.getSendBufferSize();
        }
        return super.getSendBufferSize();
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void setReceiveBufferSize(int size) throws SocketException {
        if (isDelegating()) {
            socket.setReceiveBufferSize(size);
        } else {
            super.setReceiveBufferSize(size);
        }
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public int getReceiveBufferSize() throws SocketException {
        if (isDelegating()) {
            return socket.getReceiveBufferSize();
        }
        return super.getReceiveBufferSize();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        if (isDelegating()) {
            socket.setKeepAlive(on);
        } else {
            super.setKeepAlive(on);
        }
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        if (isDelegating()) {
            return socket.getKeepAlive();
        }
        return super.getKeepAlive();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        if (isDelegating()) {
            socket.setTrafficClass(tc);
        } else {
            super.setTrafficClass(tc);
        }
    }

    @Override
    public int getTrafficClass() throws SocketException {
        if (isDelegating()) {
            return socket.getTrafficClass();
        }
        return super.getTrafficClass();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        if (isDelegating()) {
            socket.setReuseAddress(on);
        } else {
            super.setReuseAddress(on);
        }
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        if (isDelegating()) {
            return socket.getReuseAddress();
        }
        return super.getReuseAddress();
    }

    @Override
    public void shutdownInput() throws IOException {
        if (isDelegating()) {
            socket.shutdownInput();
        } else {
            super.shutdownInput();
        }
    }

    @Override
    public void shutdownOutput() throws IOException {
        if (isDelegating()) {
            socket.shutdownOutput();
        } else {
            super.shutdownOutput();
        }
    }

    @Override
    public boolean isConnected() {
        if (isDelegating()) {
            return socket.isConnected();
        }
        return super.isConnected();
    }

    @Override
    public boolean isBound() {
        if (isDelegating()) {
            return socket.isBound();
        }
        return super.isBound();
    }

    @Override
    public boolean isClosed() {
        if (isDelegating()) {
            return socket.isClosed();
        }
        return super.isClosed();
    }

    @Override
    public boolean isInputShutdown() {
        if (isDelegating()) {
            return socket.isInputShutdown();
        }
        return super.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown() {
        if (isDelegating()) {
            return socket.isOutputShutdown();
        }
        return super.isOutputShutdown();
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        if (isDelegating()) {
            socket.setPerformancePreferences(connectionTime, latency, bandwidth);
        } else {
            super.setPerformancePreferences(connectionTime, latency, bandwidth);
        }
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder("SSL socket over ");
        if (isDelegating()) {
            builder.append(socket.toString());
        } else {
            builder.append(super.toString());
        }
        return builder.toString();
    }

    /**
     * Returns the hostname that was supplied during socket creation. No DNS resolution is
     * attempted before returning the hostname.
     */
    String getHostname() {
        return peerHostname;
    }

    /**
     * This method enables Server Name Indication
     *
     * @param hostname the desired SNI hostname, or null to disable
     */
    void setHostname(String hostname) {
        peerHostname = hostname;
    }

    /**
     * For the purposes of an SSLSession, we want a way to represent the supplied hostname
     * or the IP address in a textual representation. We do not want to perform reverse DNS
     * lookups on this address.
     */
    String getHostnameOrIP() {
        if (peerHostname != null) {
            return peerHostname;
        }

        InetAddress peerAddress = getInetAddress();
        if (peerAddress != null) {
            return Platform.getOriginalHostNameFromInetAddress(peerAddress);
        }

        return null;
    }

    /**
     * Note write timeouts are not part of the javax.net.ssl.SSLSocket API
     */
    void setSoWriteTimeout(int writeTimeoutMilliseconds) throws SocketException {
        throw new SocketException("Method setSoWriteTimeout() is not supported.");
    }

    /**
     * Note write timeouts are not part of the javax.net.ssl.SSLSocket API
     */
    int getSoWriteTimeout() throws SocketException {
        return 0;
    }

    /**
     * Set the handshake timeout on this socket.  This timeout is specified in
     * milliseconds and will be used only during the handshake process.
     */
    void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException {
        throw new SocketException("Method setHandshakeTimeout() is not supported.");
    }

    final void checkOpen() throws SocketException {
        if (isClosed()) {
            throw new SocketException("Socket is closed");
        }
    }

    final PeerInfoProvider peerInfoProvider() {
        return peerInfoProvider;
    }

    /**
     * Called by {@link #notifyHandshakeCompletedListeners()} to get the currently active session.
     * Unlike {@link #getSession()}, this method must not block.
     */
    abstract SSLSession getActiveSession();

    abstract void setApplicationProtocolSelector(ApplicationProtocolSelectorAdapter selector);

    final void notifyHandshakeCompletedListeners() {
        List<HandshakeCompletedListener> listenersCopy = new ArrayList<>(listeners);
        if (!listenersCopy.isEmpty()) {
            // notify the listeners
            HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, getActiveSession());
            for (HandshakeCompletedListener listener : listenersCopy) {
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

    private boolean isDelegating() {
        // Checking for null to handle the case of calling virtual methods in the super class
        // constructor.
        return socket != null && socket != this;
    }
    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java 6.
    public abstract SSLSession getHandshakeSession();

    /**
     * This method enables session ticket support.
     *
     * @param useSessionTickets True to enable session tickets
     */
    abstract void setUseSessionTickets(boolean useSessionTickets);

    /**
     * Enables/disables TLS Channel ID for this server socket.
     *
     * <p>This method needs to be invoked before the handshake starts.
     *
     * @throws IllegalStateException if this is a client socket or if the handshake has already
     *         started.
     */
    abstract void setChannelIdEnabled(boolean enabled);

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
    abstract byte[] getChannelId() throws SSLException;

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
    abstract void setChannelIdPrivateKey(PrivateKey privateKey);

    /**
     * Returns the protocol agreed upon by client and server, or {@code null} if
     * no protocol was agreed upon.
     *
     * @deprecated use {@link #getApplicationProtocol()} instead.
     */
    @Deprecated
    abstract byte[] getAlpnSelectedProtocol();

    /**
     * Sets the list of ALPN protocols. This method internally converts the protocols to their
     * wire-format form.
     *
     * @param alpnProtocols the list of ALPN protocols
     * @deprecated use {@link #setApplicationProtocols(String[])} instead.
     */
    @Deprecated
    abstract void setAlpnProtocols(String[] alpnProtocols);

    /**
     * Alternate version of {@link #setAlpnProtocols(String[])} that directly sets the list of
     * ALPN in the wire-format form used by BoringSSL (length-prefixed 8-bit strings).
     * Requires that all strings be encoded with US-ASCII.
     *
     * @param alpnProtocols the encoded form of the ALPN protocol list
     * @deprecated Use {@link #setApplicationProtocols(String[])} instead.
     */
    @Deprecated
    abstract void setAlpnProtocols(byte[] alpnProtocols);

    /**
     * Sets the list of ALPN protocols.
     *
     * @param protocols the list of ALPN protocols
     */
    @SuppressWarnings("MissingOverride") // For compiling pre Java 9.
    abstract void setApplicationProtocols(String[] protocols);

    /**
     * Returns the list of supported ALPN protocols.
     */
    @SuppressWarnings("MissingOverride") // For compiling pre Java 9.
    abstract String[] getApplicationProtocols();

    @SuppressWarnings("MissingOverride") // For compiling pre Java 9.
    public abstract String getApplicationProtocol();

    @SuppressWarnings("MissingOverride") // For compiling pre Java 9.
    public abstract String getHandshakeApplicationProtocol();

    /**
     * Sets an application-provided ALPN protocol selector. If provided, this will override
     * the list of protocols set by {@link #setApplicationProtocols(String[])}.
     */
    abstract void setApplicationProtocolSelector(ApplicationProtocolSelector selector);

    /**
     * Returns the tls-unique channel binding value for this connection, per RFC 5929.  This
     * will return {@code null} if there is no such value available, such as if the handshake
     * has not yet completed or this connection is closed.
     */
    abstract byte[] getTlsUnique();

    /**
     * Exports a value derived from the TLS master secret as described in RFC 5705.
     *
     * @param label the label to use in calculating the exported value.  This must be
     * an ASCII-only string.
     * @param context the application-specific context value to use in calculating the
     * exported value.  This may be {@code null} to use no application context, which is
     * treated differently than an empty byte array.
     * @param length the number of bytes of keying material to return.
     * @return a value of the specified length, or {@code null} if the handshake has not yet
     * completed or the connection has been closed.
     * @throws SSLException if the value could not be exported.
     */
    abstract byte[] exportKeyingMaterial(String label, byte[] context, int length)
            throws SSLException;
}
