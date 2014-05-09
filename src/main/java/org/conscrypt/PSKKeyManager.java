/*
 * Copyright 2014 The Android Open Source Project
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

import java.net.Socket;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;

/**
 * Pre-Shared Key (PSK) key manager for TLS/SSL.
 *
 * <p>In a PSK key exchange, a Pre-Shared Key (PSK) for mutual authentication and for securing the
 * TLS/SSL connection. Both peers have to use the same key for the TLS/SSL handshake to succeed. The
 * key is not transmitted over the network.
 *
 * <p>To help the peers choose the right key, the server can provide a <em>PSK identity hint</em> to
 * the client, and the client can provide a <em>PSK identity</em> to the server. The contents of
 * these two pieces of information are specific to application-level protocols.
 *
 * <p><em>NOTE: Both the PSK identity hint and the PSK identity are transmitted in cleartext.
 * Moreover, these data are received and processed prior to peer having been authenticated. Thus,
 * they must not contain or leak key material or other sensitive information, and should be
 * treated (e.g., parsed) with caution, as untrusted data.</em>
 *
 * <p>The high-level flow leading to peers choosing a key for a connection is as follows:
 * <ol>
 * <li>The server receives a TLS/SSL handshake request from client.
 * <li>The server, optionally, sends a PSK identity hint to the client.</li>
 * <li>The client chooses the key to be used for the connection.</li>
 * <li>The client sends a PSK identity (may be empty) of the chosen key to the server.</li>
 * <li>The server chooses the key to be used for the connection.</li>
 * </ol>
 *
 * <p>In the flow above, both the client and the server can signal that they do not have a suitable
 * key, in which case the the handshake will be aborted immediately. This may enable an attacker who
 * does not know the key to learn which PSK identity hints and/or PSK identities are supported. If
 * this is a concern then a randomly generated key should be used in the scenario where no key is
 * available. This will lead to the handshake aborting later, due to key mismatch -- exactly as in
 * the scenario where a key is available but is not known to the attacker.
 *
 * <p>The maximum supported sizes are as follows:
 * <ul>
 * <li>256 bytes for keys (see {@link #MAX_KEY_LENGTH_BYTES}),</li>
 * <li>128 bytes for identity and identity hint (in modified UTF-8 representation) (see
 * {@link #MAX_IDENTITY_LENGTH_BYTES} and {@link #MAX_IDENTITY_HINT_LENGTH_BYTES}).</li>
 * </ul>
 *
 * @hide
 */
public interface PSKKeyManager extends KeyManager {

    /**
     * Maximum supported length (in bytes) for PSK identity hint (in modified UTF-8 representation).
     */
    int MAX_IDENTITY_HINT_LENGTH_BYTES = 128;

    /** Maximum supported length (in bytes) for PSK identity (in modified UTF-8 representation). */
    int MAX_IDENTITY_LENGTH_BYTES = 128;

    /** Maximum supported length (in bytes) for PSK key. */
    int MAX_KEY_LENGTH_BYTES = 256;

    /**
     * Gets the Pre-Shared Key (PSK) identity hint to report to the client at the other end of the
     * provided connection to help agree on the PSK for this socket.
     *
     * @return PSK identity hint to be provided to the client or {@code null} to provide no hint.
     */
    String chooseServerKeyIdentityHint(Socket socket);

    /**
     * Gets the Pre-Shared Key (PSK) identity hint to report to the client at the other end of the
     * provided connection to help agree on the PSK for this engine.
     *
     * @return PSK identity hint to be provided to the client or {@code null} to provide no hint.
     */
    String chooseServerKeyIdentityHint(SSLEngine engine);

    /**
     * Gets the Pre-Shared Key (PSK) identity to report to the server at the other end of the
     * provided connection to help agree on the PSK for this socket.
     *
     * @param identityHint identity hint provided by the server or {@code null} if none provided.
     *
     * @return PSK identity to provide to the server. {@code null} is permitted but will be
     *         converted into an empty string.
     */
    String chooseClientKeyIdentity(String identityHint, Socket socket);

    /**
     * Gets the Pre-Shared Key (PSK) identity to report to the server at the other end of the
     * provided connection to help agree on the PSK for this engine.
     *
     * @param identityHint identity hint provided by the server or {@code null} if none provided.
     *
     * @return PSK identity to provide to the server. {@code null} is permitted but will be
     *         converted into an empty string.
     */
    String chooseClientKeyIdentity(String identityHint, SSLEngine engine);

    /**
     * Gets the Pre-Shared Key (PSK) to use for the provided connection.
     *
     * @param identityHint identity hint provided by the server to help select the key or
     *        {@code null} if none provided.
     * @param identity identity provided by the client to help select the key.
     *
     * @return key or {@code null} to signal to peer that no suitable key is available and to abort
     *         the handshake.
     */
    SecretKey getKey(String identityHint, String identity, Socket socket);

    /**
     * Gets the Pre-Shared Key (PSK) to use for the provided connection.
     *
     * @param identityHint identity hint provided by the server to help select the key or
     *        {@code null} if none provided.
     * @param identity identity provided by the client to help select the key.
     *
     * @return key or {@code null} to signal to peer that no suitable key is available and to abort
     *         the handshake.
     */
    SecretKey getKey(String identityHint, String identity, SSLEngine engine);
}