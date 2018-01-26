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

import static org.conscrypt.NativeConstants.SSL_MODE_CBC_RECORD_SPLITTING;
import static org.conscrypt.NativeConstants.SSL_OP_CIPHER_SERVER_PREFERENCE;
import static org.conscrypt.NativeConstants.SSL_OP_NO_TICKET;
import static org.conscrypt.NativeConstants.SSL_RECEIVED_SHUTDOWN;
import static org.conscrypt.NativeConstants.SSL_SENT_SHUTDOWN;
import static org.conscrypt.NativeConstants.SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
import static org.conscrypt.NativeConstants.SSL_VERIFY_NONE;
import static org.conscrypt.NativeConstants.SSL_VERIFY_PEER;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import org.conscrypt.NativeCrypto.SSLHandshakeCallbacks;
import org.conscrypt.SSLParametersImpl.AliasChooser;
import org.conscrypt.SSLParametersImpl.PSKCallbacks;

/**
 * A utility wrapper that abstracts operations on the underlying native SSL instance.
 */
final class NativeSsl {
    private final SSLParametersImpl parameters;
    private final SSLHandshakeCallbacks handshakeCallbacks;
    private final AliasChooser aliasChooser;
    private final PSKCallbacks pskCallbacks;
    private X509Certificate[] localCertificates;
    private volatile long ssl;

    private NativeSsl(long ssl, SSLParametersImpl parameters,
            SSLHandshakeCallbacks handshakeCallbacks, AliasChooser aliasChooser,
            PSKCallbacks pskCallbacks) {
        this.ssl = ssl;
        this.parameters = parameters;
        this.handshakeCallbacks = handshakeCallbacks;
        this.aliasChooser = aliasChooser;
        this.pskCallbacks = pskCallbacks;
    }

    static NativeSsl newInstanceForTesting(long ssl) {
        return new NativeSsl(ssl, null, null, null, null);
    }

    static NativeSsl newInstance(SSLParametersImpl parameters,
            SSLHandshakeCallbacks handshakeCallbacks, AliasChooser chooser,
            PSKCallbacks pskCallbacks) throws SSLException {
        long ctx = parameters.getSessionContext().sslCtxNativePointer;
        long ssl = NativeCrypto.SSL_new(ctx);
        return new NativeSsl(ssl, parameters, handshakeCallbacks, chooser, pskCallbacks);
    }

    BioWrapper newBio() {
        try {
            return new BioWrapper();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    void offerToResumeSession(long sslSessionNativePointer) throws SSLException {
        NativeCrypto.SSL_set_session(this, sslSessionNativePointer);
    }

    byte[] getSessionId() {
        return NativeCrypto.SSL_session_id(this);
    }

    long getTime() {
        return NativeCrypto.SSL_get_time(this);
    }

    long getTimeout() {
        return NativeCrypto.SSL_get_timeout(this);
    }

    void setTimeout(long millis) {
        NativeCrypto.SSL_set_timeout(this, millis);
    }

    String getCipherSuite() {
        return NativeCrypto.cipherSuiteToJava(NativeCrypto.SSL_get_current_cipher(this));
    }

    X509Certificate[] getPeerCertificates() throws CertificateException {
        byte[][] encoded = NativeCrypto.SSL_get0_peer_certificates(this);
        return encoded == null ? null : SSLUtils.decodeX509CertificateChain(encoded);
    }

    X509Certificate[] getLocalCertificates() {
        return localCertificates;
    }

    byte[] getPeerCertificateOcspData() {
        return NativeCrypto.SSL_get_ocsp_response(this);
    }

    byte[] getTlsUnique() {
        return NativeCrypto.SSL_get_tls_unique(this);
    }

    byte[] getPeerTlsSctData() {
        return NativeCrypto.SSL_get_signed_cert_timestamp_list(this);
    }

    /**
     * @see NativeCrypto.SSLHandshakeCallbacks#clientPSKKeyRequested(String, byte[], byte[])
     */
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    int clientPSKKeyRequested(String identityHint, byte[] identityBytesOut, byte[] key) {
        PSKKeyManager pskKeyManager = parameters.getPSKKeyManager();
        if (pskKeyManager == null) {
            return 0;
        }

        String identity = pskCallbacks.chooseClientPSKIdentity(pskKeyManager, identityHint);
        // Store identity in NULL-terminated modified UTF-8 representation into ientityBytesOut
        byte[] identityBytes;
        if (identity == null) {
            identity = "";
            identityBytes = EmptyArray.BYTE;
        } else if (identity.isEmpty()) {
            identityBytes = EmptyArray.BYTE;
        } else {
            try {
                identityBytes = identity.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException("UTF-8 encoding not supported", e);
            }
        }
        if (identityBytes.length + 1 > identityBytesOut.length) {
            // Insufficient space in the output buffer
            return 0;
        }
        if (identityBytes.length > 0) {
            System.arraycopy(identityBytes, 0, identityBytesOut, 0, identityBytes.length);
        }
        identityBytesOut[identityBytes.length] = 0;

        SecretKey secretKey = pskCallbacks.getPSKKey(pskKeyManager, identityHint, identity);
        byte[] secretKeyBytes = secretKey.getEncoded();
        if (secretKeyBytes == null) {
            return 0;
        } else if (secretKeyBytes.length > key.length) {
            // Insufficient space in the output buffer
            return 0;
        }
        System.arraycopy(secretKeyBytes, 0, key, 0, secretKeyBytes.length);
        return secretKeyBytes.length;
    }

    /**
     * @see NativeCrypto.SSLHandshakeCallbacks#serverPSKKeyRequested(String, String, byte[])
     */
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    int serverPSKKeyRequested(String identityHint, String identity, byte[] key) {
        PSKKeyManager pskKeyManager = parameters.getPSKKeyManager();
        if (pskKeyManager == null) {
            return 0;
        }
        SecretKey secretKey = pskCallbacks.getPSKKey(pskKeyManager, identityHint, identity);
        byte[] secretKeyBytes = secretKey.getEncoded();
        if (secretKeyBytes == null) {
            return 0;
        } else if (secretKeyBytes.length > key.length) {
            return 0;
        }
        System.arraycopy(secretKeyBytes, 0, key, 0, secretKeyBytes.length);
        return secretKeyBytes.length;
    }

    void chooseClientCertificate(byte[] keyTypeBytes, byte[][] asn1DerEncodedPrincipals)
            throws SSLException, CertificateEncodingException {
        Set<String> keyTypesSet = SSLUtils.getSupportedClientKeyTypes(keyTypeBytes);
        String[] keyTypes = keyTypesSet.toArray(new String[keyTypesSet.size()]);

        X500Principal[] issuers;
        if (asn1DerEncodedPrincipals == null) {
            issuers = null;
        } else {
            issuers = new X500Principal[asn1DerEncodedPrincipals.length];
            for (int i = 0; i < asn1DerEncodedPrincipals.length; i++) {
                issuers[i] = new X500Principal(asn1DerEncodedPrincipals[i]);
            }
        }
        X509KeyManager keyManager = parameters.getX509KeyManager();
        String alias = (keyManager != null)
                ? aliasChooser.chooseClientAlias(keyManager, issuers, keyTypes)
                : null;
        setCertificate(alias);
    }

    void setCertificate(String alias) throws CertificateEncodingException, SSLException {
        if (alias == null) {
            return;
        }
        X509KeyManager keyManager = parameters.getX509KeyManager();
        if (keyManager == null) {
            return;
        }
        PrivateKey privateKey = keyManager.getPrivateKey(alias);
        if (privateKey == null) {
            return;
        }
        localCertificates = keyManager.getCertificateChain(alias);
        if (localCertificates == null) {
            return;
        }
        int numLocalCerts = localCertificates.length;
        PublicKey publicKey = (numLocalCerts > 0) ? localCertificates[0].getPublicKey() : null;

        // Encode the local certificates.
        byte[][] encodedLocalCerts = new byte[numLocalCerts][];
        for (int i = 0; i < numLocalCerts; ++i) {
            encodedLocalCerts[i] = localCertificates[i].getEncoded();
        }

        // Convert the key so we can access a native reference.
        final OpenSSLKey key;
        try {
            key = OpenSSLKey.fromPrivateKeyForTLSStackOnly(privateKey, publicKey);
        } catch (InvalidKeyException e) {
            throw new SSLException(e);
        }

        // Set the local certs and private key.
        NativeCrypto.setLocalCertsAndPrivateKey(this, encodedLocalCerts, key.getNativeRef());
    }

    String getVersion() {
        return NativeCrypto.SSL_get_version(this);
    }

    String getRequestedServerName() {
        return NativeCrypto.SSL_get_servername(this);
    }

    byte[] getTlsChannelId() throws SSLException {
        return NativeCrypto.SSL_get_tls_channel_id(this);
    }

    void initialize(String hostname, OpenSSLKey channelIdPrivateKey) throws IOException {
        boolean enableSessionCreation = parameters.getEnableSessionCreation();
        if (!enableSessionCreation) {
            NativeCrypto.SSL_set_session_creation_enabled(this, false);
        }

        // Allow servers to trigger renegotiation. Some inadvisable server
        // configurations cause them to attempt to renegotiate during
        // certain protocols.
        NativeCrypto.SSL_accept_renegotiations(this);

        if (isClient()) {
            NativeCrypto.SSL_set_connect_state(this);

            // Configure OCSP and CT extensions for client
            NativeCrypto.SSL_enable_ocsp_stapling(this);
            if (parameters.isCTVerificationEnabled(hostname)) {
                NativeCrypto.SSL_enable_signed_cert_timestamps(this);
            }
        } else {
            NativeCrypto.SSL_set_accept_state(this);

            // Configure OCSP for server
            if (parameters.getOCSPResponse() != null) {
                NativeCrypto.SSL_enable_ocsp_stapling(this);
            }
        }

        if (parameters.getEnabledProtocols().length == 0 && parameters.isEnabledProtocolsFiltered) {
            throw new SSLHandshakeException("No enabled protocols; "
                    + NativeCrypto.OBSOLETE_PROTOCOL_SSLV3
                    + " is no longer supported and was filtered from the list");
        }
        NativeCrypto.setEnabledProtocols(this, parameters.enabledProtocols);
        NativeCrypto.setEnabledCipherSuites(this, parameters.enabledCipherSuites);

        if (parameters.applicationProtocols.length > 0) {
            NativeCrypto.setApplicationProtocols(this, isClient(), parameters.applicationProtocols);
        }
        if (!isClient() && parameters.applicationProtocolSelector != null) {
            NativeCrypto.setApplicationProtocolSelector(this, parameters.applicationProtocolSelector);
        }

        // setup server certificates and private keys.
        // clients will receive a call back to request certificates.
        if (!isClient()) {
            Set<String> keyTypes = new HashSet<String>();
            for (long sslCipherNativePointer : NativeCrypto.SSL_get_ciphers(this)) {
                String keyType = SSLUtils.getServerX509KeyType(sslCipherNativePointer);
                if (keyType != null) {
                    keyTypes.add(keyType);
                }
            }
            X509KeyManager keyManager = parameters.getX509KeyManager();
            if (keyManager != null) {
                for (String keyType : keyTypes) {
                    try {
                        setCertificate(aliasChooser.chooseServerAlias(keyManager, keyType));
                    } catch (CertificateEncodingException e) {
                        throw new IOException(e);
                    }
                }
            }

            NativeCrypto.SSL_set_options(this, SSL_OP_CIPHER_SERVER_PREFERENCE);

            if (parameters.sctExtension != null) {
                NativeCrypto.SSL_set_signed_cert_timestamp_list(this, parameters.sctExtension);
            }

            if (parameters.ocspResponse != null) {
                NativeCrypto.SSL_set_ocsp_response(this, parameters.ocspResponse);
            }
        }

        enablePSKKeyManagerIfRequested();

        if (parameters.useSessionTickets) {
            NativeCrypto.SSL_clear_options(this, SSL_OP_NO_TICKET);
        } else {
            NativeCrypto.SSL_set_options(
                    this, NativeCrypto.SSL_get_options(this) | SSL_OP_NO_TICKET);
        }

        if (parameters.getUseSni() && AddressUtils.isValidSniHostname(hostname)) {
            NativeCrypto.SSL_set_tlsext_host_name(this, hostname);
        }

        // BEAST attack mitigation (1/n-1 record splitting for CBC cipher suites
        // with TLSv1 and SSLv3).
        NativeCrypto.SSL_set_mode(this, SSL_MODE_CBC_RECORD_SPLITTING);

        setCertificateValidation();
        setTlsChannelId(channelIdPrivateKey);
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    void doHandshake(FileDescriptor fd, int timeoutMillis)
            throws CertificateException, IOException {
        if (isClosed() || fd == null || !fd.valid()) {
            throw new SocketException("Socket is closed");
        }
        NativeCrypto.SSL_do_handshake(this, fd, handshakeCallbacks, timeoutMillis);
    }

    int doHandshake() throws IOException {
        return NativeCrypto.ENGINE_SSL_do_handshake(this, handshakeCallbacks);
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    int read(FileDescriptor fd, byte[] buf, int offset, int len, int timeoutMillis)
            throws IOException {
        if (isClosed() || fd == null || !fd.valid()) {
            throw new SocketException("Socket is closed");
        }
        return NativeCrypto.SSL_read(this, fd, handshakeCallbacks, buf, offset, len, timeoutMillis);
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    void write(FileDescriptor fd, byte[] buf, int offset, int len, int timeoutMillis)
            throws IOException {
        if (isClosed() || fd == null || !fd.valid()) {
            throw new SocketException("Socket is closed");
        }
        NativeCrypto.SSL_write(this, fd, handshakeCallbacks, buf, offset, len, timeoutMillis);
    }

    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    private void enablePSKKeyManagerIfRequested() throws SSLException {
        // Enable Pre-Shared Key (PSK) key exchange if requested
        PSKKeyManager pskKeyManager = parameters.getPSKKeyManager();
        if (pskKeyManager != null) {
            boolean pskEnabled = false;
            for (String enabledCipherSuite : parameters.enabledCipherSuites) {
                if ((enabledCipherSuite != null) && (enabledCipherSuite.contains("PSK"))) {
                    pskEnabled = true;
                    break;
                }
            }
            if (pskEnabled) {
                if (isClient()) {
                    NativeCrypto.set_SSL_psk_client_callback_enabled(this, true);
                } else {
                    NativeCrypto.set_SSL_psk_server_callback_enabled(this, true);
                    String identityHint = pskCallbacks.chooseServerPSKIdentityHint(pskKeyManager);
                    NativeCrypto.SSL_use_psk_identity_hint(this, identityHint);
                }
            }
        }
    }

    private void setTlsChannelId(OpenSSLKey channelIdPrivateKey) throws SSLException {
        if (!parameters.channelIdEnabled) {
            return;
        }

        if (parameters.getUseClientMode()) {
            // Client-side TLS Channel ID
            if (channelIdPrivateKey == null) {
                throw new SSLHandshakeException("Invalid TLS channel ID key specified");
            }
            NativeCrypto.SSL_set1_tls_channel_id(this, channelIdPrivateKey.getNativeRef());
        } else {
            // Server-side TLS Channel ID
            NativeCrypto.SSL_enable_tls_channel_id(this);
        }
    }

    private void setCertificateValidation() throws SSLException {
        // setup peer certificate verification
        if (!isClient()) {
            // needing client auth takes priority...
            boolean certRequested;
            if (parameters.getNeedClientAuth()) {
                NativeCrypto.SSL_set_verify(this, SSL_VERIFY_PEER
                                | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
                certRequested = true;
                // ... over just wanting it...
            } else if (parameters.getWantClientAuth()) {
                NativeCrypto.SSL_set_verify(this, SSL_VERIFY_PEER);
                certRequested = true;
                // ... and we must disable verification if we don't want client auth.
            } else {
                NativeCrypto.SSL_set_verify(this, SSL_VERIFY_NONE);
                certRequested = false;
            }

            if (certRequested) {
                X509TrustManager trustManager = parameters.getX509TrustManager();
                X509Certificate[] issuers = trustManager.getAcceptedIssuers();
                if (issuers != null && issuers.length != 0) {
                    byte[][] issuersBytes;
                    try {
                        issuersBytes = SSLUtils.encodeIssuerX509Principals(issuers);
                    } catch (CertificateEncodingException e) {
                        throw new SSLException("Problem encoding principals", e);
                    }
                    NativeCrypto.SSL_set_client_CA_list(this, issuersBytes);
                }
            }
        }
    }

    void interrupt() {
        NativeCrypto.SSL_interrupt(this);
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    void shutdown(FileDescriptor fd) throws IOException {
        NativeCrypto.SSL_shutdown(this, fd, handshakeCallbacks);
    }

    void shutdown() throws IOException {
        NativeCrypto.ENGINE_SSL_shutdown(this, handshakeCallbacks);
    }

    boolean wasShutdownReceived() {
        return (NativeCrypto.SSL_get_shutdown(this) & SSL_RECEIVED_SHUTDOWN) != 0;
    }

    boolean wasShutdownSent() {
        return (NativeCrypto.SSL_get_shutdown(this) & SSL_SENT_SHUTDOWN) != 0;
    }

    int readDirectByteBuffer(long destAddress, int destLength)
            throws IOException, CertificateException {
        return NativeCrypto.ENGINE_SSL_read_direct(
                this, destAddress, destLength, handshakeCallbacks);
    }

    int writeDirectByteBuffer(long sourceAddress, int sourceLength) throws IOException {
        return NativeCrypto.ENGINE_SSL_write_direct(
                this, sourceAddress, sourceLength, handshakeCallbacks);
    }

    int getPendingReadableBytes() {
        return NativeCrypto.SSL_pending_readable_bytes(this);
    }

    int getMaxSealOverhead() {
        return NativeCrypto.SSL_max_seal_overhead(this);
    }

    void close() {
        NativeCrypto.SSL_free(this);
        ssl = 0L;
    }

    boolean isClosed() {
        return ssl == 0L;
    }

    int getError(int result) {
        return NativeCrypto.SSL_get_error(this, result);
    }

    byte[] getApplicationProtocol() {
        return NativeCrypto.getApplicationProtocol(this);
    }

    private boolean isClient() {
        return parameters.getUseClientMode();
    }

    @Override
    protected final void finalize() throws Throwable {
        try {
            if (!isClosed()) {
                close();
            }
        } finally {
            super.finalize();
        }
    }

    /**
     * A utility wrapper that abstracts operations on the underlying native BIO instance.
     */
    final class BioWrapper {
        private long bio;

        private BioWrapper() throws SSLException {
            this.bio = NativeCrypto.SSL_BIO_new(NativeSsl.this);
        }

        int getPendingWrittenBytes() {
            return NativeCrypto.SSL_pending_written_bytes_in_BIO(bio);
        }

        int writeDirectByteBuffer(long address, int length) throws IOException {
            return NativeCrypto.ENGINE_SSL_write_BIO_direct(
                    NativeSsl.this, bio, address, length, handshakeCallbacks);
        }

        int readDirectByteBuffer(long destAddress, int destLength) throws IOException {
            return NativeCrypto.ENGINE_SSL_read_BIO_direct(
                    NativeSsl.this, bio, destAddress, destLength, handshakeCallbacks);
        }

        void close() {
            NativeCrypto.BIO_free_all(bio);
            bio = 0L;
        }
    }
}
