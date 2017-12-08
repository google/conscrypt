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

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.PrivateKey;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Abstract base class for all Conscrypt sockets that extends the basic {@link SSLSocket} API.
 */
abstract class AbstractConscryptSocket extends SSLSocket {

    AbstractConscryptSocket() {
    }

    AbstractConscryptSocket(String hostname, int port) throws IOException {
        super(hostname, port);
    }

    AbstractConscryptSocket(InetAddress address, int port) throws IOException {
        super(address, port);
    }

    AbstractConscryptSocket(String hostname, int port, InetAddress clientAddress, int clientPort)
            throws IOException {
        super(hostname, port, clientAddress, clientPort);
    }

    AbstractConscryptSocket(InetAddress address, int port, InetAddress clientAddress,
            int clientPort) throws IOException {
        super(address, port, clientAddress, clientPort);
    }

    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java 6.
    public abstract SSLSession getHandshakeSession();

    /* @Override */
    public abstract FileDescriptor getFileDescriptor$();

    /**
     * Returns the hostname that was supplied during socket creation. No DNS resolution is
     * attempted before returning the hostname.
     */
    abstract String getHostname();

    /**
     * This method enables Server Name Indication
     *
     * @param hostname the desired SNI hostname, or null to disable
     */
    abstract void setHostname(String hostname);

    /**
     * For the purposes of an SSLSession, we want a way to represent the supplied hostname
     * or the IP address in a textual representation. We do not want to perform reverse DNS
     * lookups on this address.
     */
    abstract String getHostnameOrIP();

    /**
     * Note write timeouts are not part of the javax.net.ssl.SSLSocket API
     */
    abstract void setSoWriteTimeout(int writeTimeoutMilliseconds) throws SocketException;

    /**
     * Note write timeouts are not part of the javax.net.ssl.SSLSocket API
     */
    abstract int getSoWriteTimeout() throws SocketException;

    /**
     * Set the handshake timeout on this socket.  This timeout is specified in
     * milliseconds and will be used only during the handshake process.
     */
    abstract void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException;

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
     * Returns null always for backward compatibility.
     * @deprecated NPN is not supported
     */
    @Deprecated
    byte[] getNpnSelectedProtocol() {
        return null;
    }

    /**
     * This method does nothing and is kept for backward compatibility.
     * @deprecated NPN is not supported
     */
    @Deprecated
    void setNpnProtocols(byte[] npnProtocols) {}

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

    abstract PeerInfoProvider peerInfoProvider();

    /**
     * Returns the tls-unique channel binding value for this connection, per RFC 5929.  This
     * will return {@code null} if there is no such value available, such as if the handshake
     * has not yet completed or this connection is closed.
     */
    abstract byte[] getTlsUnique();
}
