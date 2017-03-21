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
import java.io.UnsupportedEncodingException;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.Provider;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Core API for creating and configuring all Conscrypt types.
 */
public final class Conscrypt {
    private Conscrypt() {}

    /**
     * Constructs a new {@link Provider} with the default name.
     */
    public static Provider newProvider() {
        return new OpenSSLProvider();
    }

    /**
     * Constructs a new {@link Provider} with the given name.
     */
    public static Provider newProvider(String providerName) {
        return new OpenSSLProvider(providerName);
    }

    /**
     * Utility methods for configuring Conscrypt socket factories.
     */
    public static final class SocketFactories {
        private SocketFactories() {}

        /**
         * Indicates whether the given object is a Conscrypt socket factory.
         */
        public static boolean isConscrypt(SSLSocketFactory factory) {
            return factory instanceof OpenSSLSocketFactoryImpl;
        }

        private static OpenSSLSocketFactoryImpl toConscrypt(SSLSocketFactory factory) {
            if (!isConscrypt(factory)) {
                throw new IllegalArgumentException(
                        "Not a conscrypt socket factory: " + factory.getClass().getName());
            }
            return (OpenSSLSocketFactoryImpl) factory;
        }

        /**
         * Configures the default socket to be created for all socket factory instances.
         */
        @ExperimentalApi
        public static void setUseEngineSocketByDefault(boolean useEngineSocket) {
            OpenSSLSocketFactoryImpl.setUseEngineSocketByDefault(useEngineSocket);
        }

        /**
         * Configures the socket to be created for the given socket factory instance.
         */
        @ExperimentalApi
        public static void setUseEngineSocket(SSLSocketFactory factory, boolean useEngineSocket) {
            toConscrypt(factory).setUseEngineSocket(useEngineSocket);
        }
    }

    /**
     * Utility methods for configuring Conscrypt server socket factories.
     */
    public static final class ServerSocketFactories {
        private ServerSocketFactories() {}

        /**
         * Indicates whether the given object is a Conscrypt socket factory.
         */
        public static boolean isConscrypt(SSLServerSocketFactory factory) {
            return factory instanceof OpenSSLServerSocketFactoryImpl;
        }

        private static OpenSSLServerSocketFactoryImpl toConscrypt(SSLServerSocketFactory factory) {
            if (!isConscrypt(factory)) {
                throw new IllegalArgumentException(
                        "Not a conscrypt server socket factory: " + factory.getClass().getName());
            }
            return (OpenSSLServerSocketFactoryImpl) factory;
        }

        /**
         * Configures the default socket to be created for all server socket factory instances.
         */
        @ExperimentalApi
        public static void setUseEngineSocketByDefault(boolean useEngineSocket) {
            OpenSSLServerSocketFactoryImpl.setUseEngineSocketByDefault(useEngineSocket);
        }

        /**
         * Configures the socket to be created for the given server socket factory instance.
         */
        @ExperimentalApi
        public static void setUseEngineSocket(
                SSLServerSocketFactory factory, boolean useEngineSocket) {
            toConscrypt(factory).setUseEngineSocket(useEngineSocket);
        }
    }

    /**
     * Utility methods for configuring Conscrypt sockets.
     */
    public static final class Sockets {
        private Sockets() {}

        /**
         * Indicates whether the given socket is a Conscrypt socket.
         */
        public static boolean isConscrypt(SSLSocket socket) {
            return socket instanceof OpenSSLSocketImpl;
        }

        private static OpenSSLSocketImpl toConscrypt(SSLSocket socket) {
            if (!isConscrypt(socket)) {
                throw new IllegalArgumentException(
                        "Not a conscrypt socket: " + socket.getClass().getName());
            }
            return (OpenSSLSocketImpl) socket;
        }

        /**
         * This method enables session ticket support.
         *
         * @param socket the socket
         * @param useSessionTickets True to enable session tickets
         */
        public static void setUseSessionTickets(SSLSocket socket, boolean useSessionTickets) {
            toConscrypt(socket).setUseSessionTickets(useSessionTickets);
        }

        /**
         * This method enables Server Name Indication
         *
         * @param socket the socket
         * @param hostname the desired SNI hostname, or null to disable
         */
        public static void setHostname(SSLSocket socket, String hostname) {
            toConscrypt(socket).setHostname(hostname);
        }

        /**
         * Returns the hostname that was supplied during socket creation. No DNS resolution is
         * attempted before returning the hostname.
         */
        public static String getHostname(SSLSocket socket) {
            return toConscrypt(socket).getHostname();
        }

        /**
         * For the purposes of an SSLSession, we want a way to represent the supplied hostname
         * or the IP address in a textual representation. We do not want to perform reverse DNS
         * lookups on this address.
         */
        public static String getHostnameOrIP(SSLSocket socket) {
            return toConscrypt(socket).getHostnameOrIP();
        }

        /**
         * Note write timeouts are not part of the javax.net.ssl.SSLSocket API
         */
        public static void setSoWriteTimeout(SSLSocket socket, int writeTimeoutMilliseconds)
                throws SocketException {
            toConscrypt(socket).setSoWriteTimeout(writeTimeoutMilliseconds);
        }

        /**
         * Note write timeouts are not part of the javax.net.ssl.SSLSocket API
         */
        public static int getSoWriteTimeout(SSLSocket socket) throws SocketException {
            return toConscrypt(socket).getSoWriteTimeout();
        }

        /**
         * Set the handshake timeout on this socket.  This timeout is specified in
         * milliseconds and will be used only during the handshake process.
         */
        public static void setHandshakeTimeout(SSLSocket socket, int handshakeTimeoutMilliseconds)
                throws SocketException {
            toConscrypt(socket).setHandshakeTimeout(handshakeTimeoutMilliseconds);
        }

        /**
         * Gets the underlying file descriptor for the given socket.
         */
        public static FileDescriptor getFileDescriptor(SSLSocket socket) {
            return toConscrypt(socket).getFileDescriptor$();
        }

        /**
         * Enables/disables TLS Channel ID for the given server-side socket.
         *
         * <p>This method needs to be invoked before the handshake starts.
         *
         * @param socket the socket
         * @param enabled Whether to enable channel ID.
         * @throws IllegalStateException if this is a client socket or if the handshake has already
         * started.
         */
        public static void setChannelIdEnabled(SSLSocket socket, boolean enabled) {
            toConscrypt(socket).setChannelIdEnabled(enabled);
        }

        /**
         * Gets the TLS Channel ID for the given server-side socket. Channel ID is only available
         * once the handshake completes.
         *
         * @param socket the socket
         * @return channel ID or {@code null} if not available.
         * @throws IllegalStateException if this is a client socket or if the handshake has not yet
         * completed.
         * @throws SSLException if channel ID is available but could not be obtained.
         */
        public static byte[] getChannelId(SSLSocket socket) throws SSLException {
            return toConscrypt(socket).getChannelId();
        }

        /**
         * Sets the {@link PrivateKey} to be used for TLS Channel ID by this client socket.
         *
         * <p>This method needs to be invoked before the handshake starts.
         *
         * @param socket the socket
         * @param privateKey private key (enables TLS Channel ID) or {@code null} for no key
         * (disables TLS Channel ID).
         * The private key must be an Elliptic Curve (EC) key based on the NIST P-256 curve (aka
         * SECG secp256r1 or ANSI
         * X9.62 prime256v1).
         * @throws IllegalStateException if this is a server socket or if the handshake has already
         * started.
         */
        public static void setChannelIdPrivateKey(SSLSocket socket, PrivateKey privateKey) {
            toConscrypt(socket).setChannelIdPrivateKey(privateKey);
        }

        /**
         * Returns the ALPN protocol agreed upon by client and server.
         *
         * @param socket the socket
         * @return the selected protocol or {@code null} if no protocol was agreed upon.
         */
        public static String getAlpnSelectedProtocol(SSLSocket socket) {
            return toProtocolString(toConscrypt(socket).getAlpnSelectedProtocol());
        }

        /**
         * Sets the list of ALPN protocols supported by the socket.
         *
         * @param socket the socket
         * @param alpnProtocols the list of ALPN protocols
         */
        public static void setAlpnProtocols(SSLSocket socket, String[] alpnProtocols) {
            toConscrypt(socket).setAlpnProtocols(alpnProtocols);
        }
    }

    /**
     * Utility methods for configuring Conscrypt engines.
     */
    public static final class Engines {
        private Engines() {}

        /**
         * Indicates whether the given engine is a Conscrypt engine.
         */
        public static boolean isConscrypt(SSLEngine engine) {
            return engine instanceof OpenSSLEngineImpl;
        }

        private static OpenSSLEngineImpl toConscrypt(SSLEngine engine) {
            if (!isConscrypt(engine)) {
                throw new IllegalArgumentException(
                        "Not a conscrypt engine: " + engine.getClass().getName());
            }
            return (OpenSSLEngineImpl) engine;
        }

        /**
         * This method enables Server Name Indication (SNI) and sets the host name used for
         * SNI.
         *
         * @param engine the engine
         * @param hostname the desired SNI hostname, or {@code null} to disable
         */
        public static void setHostname(SSLEngine engine, String hostname) {
            toConscrypt(engine).setSniHostname(hostname);
        }

        /**
         * Returns the SNI hostname that was set for the {@code engine}. If no SNI hostname
         * was set, it will return the hostname supplied during creation of the {@code engine}.
         */
        public static String getHostname(SSLEngine engine) {
            return toConscrypt(engine).getSniHostname();
        }

        /**
         * Returns the maximum overhead, in bytes, of sealing a record with SSL.
         */
        public static int maxSealOverhead(SSLEngine engine) {
            return toConscrypt(engine).maxSealOverhead();
        }

        /**
         * Sets a listener on the given engine for completion of the TLS handshake
         */
        public static void setHandshakeListener(
                SSLEngine engine, HandshakeListener handshakeListener) {
            toConscrypt(engine).setHandshakeListener(handshakeListener);
        }

        /**
         * Enables/disables TLS Channel ID for the given server-side engine.
         *
         * <p>This method needs to be invoked before the handshake starts.
         *
         * @param engine the engine
         * @param enabled Whether to enable channel ID.
         * @throws IllegalStateException if this is a client engine or if the handshake has already
         * started.
         */
        public static void setChannelIdEnabled(SSLEngine engine, boolean enabled) {
            toConscrypt(engine).setChannelIdEnabled(enabled);
        }

        /**
         * Gets the TLS Channel ID for the given server-side engine. Channel ID is only available
         * once the handshake completes.
         *
         * @param engine the engine
         * @return channel ID or {@code null} if not available.
         * @throws IllegalStateException if this is a client engine or if the handshake has not yet
         * completed.
         * @throws SSLException if channel ID is available but could not be obtained.
         */
        public static byte[] getChannelId(SSLEngine engine) throws SSLException {
            return toConscrypt(engine).getChannelId();
        }

        /**
         * Sets the {@link PrivateKey} to be used for TLS Channel ID by this client engine.
         *
         * <p>This method needs to be invoked before the handshake starts.
         *
         * @param engine the engine
         * @param privateKey private key (enables TLS Channel ID) or {@code null} for no key
         * (disables TLS Channel ID).
         * The private key must be an Elliptic Curve (EC) key based on the NIST P-256 curve (aka
         * SECG secp256r1 or ANSI X9.62 prime256v1).
         * @throws IllegalStateException if this is a server engine or if the handshake has already
         * started.
         */
        public static void setChannelIdPrivateKey(SSLEngine engine, PrivateKey privateKey) {
            toConscrypt(engine).setChannelIdPrivateKey(privateKey);
        }

        /**
         * Extended unwrap method for multiple source and destination buffers.
         *
         * @param engine the target engine for the unwrap
         * @param srcs the source buffers
         * @param dsts the destination buffers
         * @return the result of the unwrap operation
         * @throws SSLException thrown if an SSL error occurred
         */
        public static SSLEngineResult unwrap(SSLEngine engine, final ByteBuffer[] srcs,
                final ByteBuffer[] dsts) throws SSLException {
            return toConscrypt(engine).unwrap(srcs, dsts);
        }

        /**
         * Exteneded unwrap method for multiple source and destination buffers.
         *
         * @param engine the target engine for the unwrap.
         * @param srcs the source buffers
         * @param srcsOffset the offset in the {@code srcs} array of the first source buffer
         * @param srcsLength the number of source buffers starting at {@code srcsOffset}
         * @param dsts the destination buffers
         * @param dstsOffset the offset in the {@code dsts} array of the first destination buffer
         * @param dstsLength the number of destination buffers starting at {@code dstsOffset}
         * @return the result of the unwrap operation
         * @throws SSLException thrown if an SSL error occurred
         */
        public static SSLEngineResult unwrap(SSLEngine engine, final ByteBuffer[] srcs,
                int srcsOffset, final int srcsLength, final ByteBuffer[] dsts, final int dstsOffset,
                final int dstsLength) throws SSLException {
            return toConscrypt(engine).unwrap(
                    srcs, srcsOffset, srcsLength, dsts, dstsOffset, dstsLength);
        }

        /**
         * This method enables session ticket support.
         *
         * @param engine the engine
         * @param useSessionTickets True to enable session tickets
         */
        public static void setUseSessionTickets(SSLEngine engine, boolean useSessionTickets) {
            toConscrypt(engine).setUseSessionTickets(useSessionTickets);
        }

        /**
         * Sets the list of ALPN protocols supported by the engine.
         *
         * @param engine the engine
         * @param alpnProtocols the list of ALPN protocols
         */
        public static void setAlpnProtocols(SSLEngine engine, String[] alpnProtocols) {
            toConscrypt(engine).setAlpnProtocols(alpnProtocols);
        }

        /**
         * Returns the ALPN protocol agreed upon by client and server.
         *
         * @param engine the engine
         * @return the selected protocol or {@code null} if no protocol was agreed upon.
         */
        public static String getAlpnSelectedProtocol(SSLEngine engine) {
            return toProtocolString(toConscrypt(engine).getAlpnSelectedProtocol());
        }
    }

    private static String toProtocolString(byte[] bytes) {
        try {
            if (bytes == null) {
                return null;
            }
            return new String(bytes, "US-ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
}
