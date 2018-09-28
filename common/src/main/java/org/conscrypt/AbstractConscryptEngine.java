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
import java.security.PrivateKey;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/**
 * Abstract base class for all Conscrypt {@link SSLEngine} classes.
 */
abstract class AbstractConscryptEngine extends SSLEngine {
    abstract void setBufferAllocator(BufferAllocator bufferAllocator);

    /**
     * Returns the maximum overhead, in bytes, of sealing a record with SSL.
     */
    abstract int maxSealOverhead();

    /**
     * Enables/disables TLS Channel ID for this server engine.
     *
     * <p>This method needs to be invoked before the handshake starts.
     *
     * @throws IllegalStateException if this is a client engine or if the handshake has already
     *         started.
     */
    abstract void setChannelIdEnabled(boolean enabled);

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
    abstract byte[] getChannelId() throws SSLException;

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
    abstract void setChannelIdPrivateKey(PrivateKey privateKey);

    /**
     * Sets the listener for the completion of the TLS handshake.
     */
    abstract void setHandshakeListener(HandshakeListener handshakeListener);

    /**
     * This method enables Server Name Indication (SNI) and overrides the {@link PeerInfoProvider}
     * supplied during engine creation.
     */
    abstract void setHostname(String hostname);

    /**
     * Returns the hostname from {@link #setHostname(String)} or supplied by the
     * {@link PeerInfoProvider} upon creation. No DNS resolution is attempted before
     * returning the hostname.
     */
    abstract String getHostname();

    @Override public abstract String getPeerHost();

    @Override public abstract int getPeerPort();

    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java 6.
    public final SSLSession getHandshakeSession() {
        return handshakeSession();
    }

    /**
     * Work-around to allow this method to be called on older versions of Android.
     */
    abstract SSLSession handshakeSession();

    @Override
    public abstract SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException;

    @Override
    public abstract SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException;

    @Override
    public abstract SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer[] dsts,
            final int offset, final int length) throws SSLException;

    abstract SSLEngineResult unwrap(final ByteBuffer[] srcs, final ByteBuffer[] dsts)
            throws SSLException;

    abstract SSLEngineResult unwrap(final ByteBuffer[] srcs, int srcsOffset, final int srcsLength,
            final ByteBuffer[] dsts, final int dstsOffset, final int dstsLength)
            throws SSLException;

    @Override
    public abstract SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException;

    @Override
    public abstract SSLEngineResult wrap(
            ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer dst) throws SSLException;

    /**
     * This method enables session ticket support.
     *
     * @param useSessionTickets True to enable session tickets
     */
    abstract void setUseSessionTickets(boolean useSessionTickets);

    /**
     * Sets the list of ALPN protocols.
     *
     * @param protocols the list of ALPN protocols
     */
    abstract void setApplicationProtocols(String[] protocols);

    /**
     * Returns the list of supported ALPN protocols.
     */
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
