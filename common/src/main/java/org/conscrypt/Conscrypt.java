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

import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.PrivateKey;
import java.security.Provider;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Core API for creating and configuring all Conscrypt types.
 */
@SuppressWarnings("unused")
public final class Conscrypt {
    private Conscrypt() {}

    /**
     * Returns {@code true} if the Conscrypt native library has been successfully loaded.
     */
    public static boolean isAvailable() {
        try {
            checkAvailability();
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    /**
     * Checks that the Conscrypt support is available for the system.
     *
     * @throws UnsatisfiedLinkError if unavailable
     */
    public static void checkAvailability() {
        NativeCrypto.checkAvailability();
    }

    /**
     * Indicates whether the given {@link Provider} was created by this distribution of Conscrypt.
     */
    public static boolean isConscrypt(Provider provider) {
        return provider instanceof OpenSSLProvider;
    }

    /**
     * Constructs a new {@link Provider} with the default name.
     */
    public static Provider newProvider() {
        checkAvailability();
        return new OpenSSLProvider();
    }

    /**
     * Constructs a new {@link Provider} with the given name.
     */
    public static Provider newProvider(String providerName) {
        checkAvailability();
        return new OpenSSLProvider(providerName);
    }

    /**
     * Returns the maximum length (in bytes) of an encrypted packet.
     */
    public static int maxEncryptedPacketLength() {
        return NativeConstants.SSL3_RT_MAX_PACKET_SIZE;
    }

    /**
     * Gets the default X.509 trust manager.
     */
    @ExperimentalApi
    public static X509TrustManager getDefaultX509TrustManager() throws KeyManagementException {
        checkAvailability();
        return SSLParametersImpl.getDefaultX509TrustManager();
    }

    /**
     * Indicates whether the given {@link SSLContext} was created by this distribution of Conscrypt.
     */
    public static boolean isConscrypt(SSLContext context) {
        return context.getProvider() instanceof OpenSSLProvider;
    }

    /**
     * Constructs a new instance of the preferred {@link SSLContextSpi}.
     */
    public static SSLContextSpi newPreferredSSLContextSpi() {
        checkAvailability();
        return OpenSSLContextImpl.getPreferred();
    }

    /**
     * Sets the client-side persistent cache to be used by the context.
     */
    public static void setClientSessionCache(SSLContext context, SSLClientSessionCache cache) {
        SSLSessionContext clientContext = context.getClientSessionContext();
        if (!(clientContext instanceof ClientSessionContext)) {
            throw new IllegalArgumentException(
                    "Not a conscrypt client context: " + clientContext.getClass().getName());
        }
        ((ClientSessionContext) clientContext).setPersistentCache(cache);
    }

    /**
     * Sets the server-side persistent cache to be used by the context.
     */
    public static void setServerSessionCache(SSLContext context, SSLServerSessionCache cache) {
        SSLSessionContext serverContext = context.getServerSessionContext();
        if (!(serverContext instanceof ServerSessionContext)) {
            throw new IllegalArgumentException(
                    "Not a conscrypt client context: " + serverContext.getClass().getName());
        }
        ((ServerSessionContext) serverContext).setPersistentCache(cache);
    }

    /**
     * Indicates whether the given {@link SSLSocketFactory} was created by this distribution of
     * Conscrypt.
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
        OpenSSLServerSocketFactoryImpl.setUseEngineSocketByDefault(useEngineSocket);
    }

    /**
     * Configures the socket to be created for the given socket factory instance.
     */
    @ExperimentalApi
    public static void setUseEngineSocket(SSLSocketFactory factory, boolean useEngineSocket) {
        toConscrypt(factory).setUseEngineSocket(useEngineSocket);
    }

    /**
     * Indicates whether the given {@link SSLServerSocketFactory} was created by this distribution
     * of Conscrypt.
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
     * Configures the socket to be created for the given server socket factory instance.
     */
    @ExperimentalApi
    public static void setUseEngineSocket(SSLServerSocketFactory factory, boolean useEngineSocket) {
        toConscrypt(factory).setUseEngineSocket(useEngineSocket);
    }

    /**
     * Indicates whether the given {@link SSLSocket} was created by this distribution of Conscrypt.
     */
    public static boolean isConscrypt(SSLSocket socket) {
        return socket instanceof AbstractConscryptSocket;
    }

    private static AbstractConscryptSocket toConscrypt(SSLSocket socket) {
        if (!isConscrypt(socket)) {
            throw new IllegalArgumentException(
                    "Not a conscrypt socket: " + socket.getClass().getName());
        }
        return (AbstractConscryptSocket) socket;
    }

    /**
     * This method enables Server Name Indication (SNI) and overrides the hostname supplied
     * during socket creation.
     *
     * @param socket the socket
     * @param hostname the desired SNI hostname, or null to disable
     */
    public static void setHostname(SSLSocket socket, String hostname) {
        toConscrypt(socket).setHostname(hostname);
    }

    /**
     * Returns either the hostname supplied during socket creation or via
     * {@link #setHostname(SSLSocket, String)}. No DNS resolution is attempted before
     * returning the hostname.
     */
    public static String getHostname(SSLSocket socket) {
        return toConscrypt(socket).getHostname();
    }

    /**
     * This method attempts to create a textual representation of the peer host or IP. Does
     * not perform a reverse DNS lookup. This is typically used during session creation.
     */
    public static String getHostnameOrIP(SSLSocket socket) {
        return toConscrypt(socket).getHostnameOrIP();
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
    public static String getApplicationProtocol(SSLSocket socket) {
        return toConscrypt(socket).getApplicationProtocol();
    }

    /**
     * Sets an application-provided ALPN protocol selector. If provided, this will override
     * the list of protocols set by {@link #setApplicationProtocols(SSLSocket, String[])}.
     *
     * @param socket the socket
     * @param selector the ALPN protocol selector
     */
    public static void setApplicationProtocolSelector(SSLSocket socket,
        ApplicationProtocolSelector selector) {
        toConscrypt(socket).setApplicationProtocolSelector(selector);
    }

    /**
     * Sets the application-layer protocols (ALPN) in prioritization order.
     *
     * @param socket the socket being configured
     * @param protocols the protocols in descending order of preference. If empty, no protocol
     * indications will be used. This array will be copied.
     * @throws IllegalArgumentException - if protocols is null, or if any element in a non-empty
     * array is null or an empty (zero-length) string
     */
    public static void setApplicationProtocols(SSLSocket socket, String[] protocols) {
        toConscrypt(socket).setApplicationProtocols(protocols);
    }

    /**
     * Gets the application-layer protocols (ALPN) in prioritization order.
     *
     * @param socket the socket
     * @return the protocols in descending order of preference, or an empty array if protocol
     * indications are not being used. Always returns a new array.
     */
    public static String[] getApplicationProtocols(SSLSocket socket) {
        return toConscrypt(socket).getApplicationProtocols();
    }

    /**
     * Indicates whether the given {@link SSLEngine} was created by this distribution of Conscrypt.
     */
    public static boolean isConscrypt(SSLEngine engine) {
        return engine instanceof AbstractConscryptEngine;
    }

    private static AbstractConscryptEngine toConscrypt(SSLEngine engine) {
        if (!isConscrypt(engine)) {
            throw new IllegalArgumentException(
                    "Not a conscrypt engine: " + engine.getClass().getName());
        }
        return (AbstractConscryptEngine) engine;
    }

    /**
     * Provides the given engine with the provided bufferAllocator.
     */
    @ExperimentalApi
    public static void setBufferAllocator(SSLEngine engine, BufferAllocator bufferAllocator) {
        toConscrypt(engine).setBufferAllocator(bufferAllocator);
    }

    /**
     * This method enables Server Name Indication (SNI) and overrides the hostname supplied
     * during engine creation.
     *
     * @param engine the engine
     * @param hostname the desired SNI hostname, or {@code null} to disable
     */
    public static void setHostname(SSLEngine engine, String hostname) {
        toConscrypt(engine).setHostname(hostname);
    }

    /**
     * Returns either the hostname supplied during socket creation or via
     * {@link #setHostname(SSLEngine, String)}. No DNS resolution is attempted before
     * returning the hostname.
     */
    public static String getHostname(SSLEngine engine) {
        return toConscrypt(engine).getHostname();
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
    public static void setHandshakeListener(SSLEngine engine, HandshakeListener handshakeListener) {
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
    public static SSLEngineResult unwrap(SSLEngine engine, final ByteBuffer[] srcs, int srcsOffset,
            final int srcsLength, final ByteBuffer[] dsts, final int dstsOffset,
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
     * Sets the application-layer protocols (ALPN) in prioritization order.
     *
     * @param engine the engine being configured
     * @param protocols the protocols in descending order of preference. If empty, no protocol
     * indications will be used.  This array will be copied.
     * @throws IllegalArgumentException - if protocols is null, or if any element in a non-empty
     * array is null or an empty (zero-length) string
     */
    public static void setApplicationProtocols(SSLEngine engine, String[] protocols) {
        toConscrypt(engine).setApplicationProtocols(protocols);
    }

    /**
     * Gets the application-layer protocols (ALPN) in prioritization order.
     *
     * @param engine the engine
     * @return the protocols in descending order of preference, or an empty array if protocol
     * indications are not being used. Always returns a new array.
     */
    public static String[] getApplicationProtocols(SSLEngine engine) {
        return toConscrypt(engine).getApplicationProtocols();
    }

    /**
     * Sets an application-provided ALPN protocol selector. If provided, this will override
     * the list of protocols set by {@link #setApplicationProtocols(SSLEngine, String[])}.
     *
     * @param engine the engine
     * @param selector the ALPN protocol selector
     */
    public static void setApplicationProtocolSelector(SSLEngine engine,
        ApplicationProtocolSelector selector) {
        toConscrypt(engine).setApplicationProtocolSelector(selector);
    }

    /**
     * Returns the ALPN protocol agreed upon by client and server.
     *
     * @param engine the engine
     * @return the selected protocol or {@code null} if no protocol was agreed upon.
     */
    public static String getApplicationProtocol(SSLEngine engine) {
        return toConscrypt(engine).getApplicationProtocol();
    }
}
