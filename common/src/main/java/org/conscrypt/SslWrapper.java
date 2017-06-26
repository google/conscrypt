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

import static org.conscrypt.NativeConstants.SSL_RECEIVED_SHUTDOWN;
import static org.conscrypt.NativeConstants.SSL_SENT_SHUTDOWN;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.SocketTimeoutException;
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
final class SslWrapper {
    private final SSLParametersImpl parameters;
    private final SSLHandshakeCallbacks handshakeCallbacks;
    private final AliasChooser aliasChooser;
    private final PSKCallbacks pskCallbacks;
    private long ssl;

    static SslWrapper newInstance(SSLParametersImpl parameters,
            SSLHandshakeCallbacks handshakeCallbacks, AliasChooser chooser,
            PSKCallbacks pskCallbacks) throws SSLException {
        long ctx = parameters.getSessionContext().sslCtxNativePointer;
        long ssl = NativeCrypto.SSL_new(ctx);
        return new SslWrapper(ssl, parameters, handshakeCallbacks, chooser, pskCallbacks);
    }

    private SslWrapper(long ssl, SSLParametersImpl parameters,
            SSLHandshakeCallbacks handshakeCallbacks, AliasChooser aliasChooser,
            PSKCallbacks pskCallbacks) {
        this.ssl = ssl;
        this.parameters = parameters;
        this.handshakeCallbacks = handshakeCallbacks;
        this.aliasChooser = aliasChooser;
        this.pskCallbacks = pskCallbacks;
    }

    long ssl() {
        return ssl;
    }

    BioWrapper newBio() {
        try {
            return new BioWrapper();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    void offerToResumeSession(long sslSessionNativePointer) throws SSLException {
        NativeCrypto.SSL_set_session(ssl, sslSessionNativePointer);
    }

    byte[] getSessionId() {
        return NativeCrypto.SSL_session_id(ssl);
    }

    long getTime() {
        return NativeCrypto.SSL_get_time(ssl);
    }

    long getTimeout() {
        return NativeCrypto.SSL_get_timeout(ssl);
    }

    void setTimeout(long millis) {
        NativeCrypto.SSL_set_timeout(ssl, millis);
    }

    String getCipherSuite() {
        return NativeCrypto.cipherSuiteToJava(NativeCrypto.SSL_get_current_cipher(ssl));
    }

    OpenSSLX509Certificate[] getLocalCertificates() {
        return OpenSSLX509Certificate.createCertChain(NativeCrypto.SSL_get_certificate(ssl));
    }

    OpenSSLX509Certificate[] getPeerCertificates() {
        return OpenSSLX509Certificate.createCertChain(NativeCrypto.SSL_get_peer_cert_chain(ssl));
    }

    byte[] getPeerCertificateOcspData() {
        return NativeCrypto.SSL_get_ocsp_response(ssl);
    }

    byte[] getPeerTlsSctData() {
        return NativeCrypto.SSL_get_signed_cert_timestamp_list(ssl);
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
        X509Certificate[] certificates = keyManager.getCertificateChain(alias);
        if (certificates == null) {
            return;
        }
        PublicKey publicKey = (certificates.length > 0) ? certificates[0].getPublicKey() : null;

        /*
         * Make sure we keep a reference to the OpenSSLX509Certificate by using
         * this array. Otherwise, if they're not OpenSSLX509Certificate
         * instances originally, they may be garbage collected before we
         * complete our JNI calls.
         */
        OpenSSLX509Certificate[] openSslCerts = new OpenSSLX509Certificate[certificates.length];
        long[] x509refs = new long[certificates.length];
        for (int i = 0; i < certificates.length; i++) {
            OpenSSLX509Certificate openSslCert =
                    OpenSSLX509Certificate.fromCertificate(certificates[i]);
            openSslCerts[i] = openSslCert;
            x509refs[i] = openSslCert.getContext();
        }

        // Note that OpenSSL says to use SSL_use_certificate before
        // SSL_use_PrivateKey.
        NativeCrypto.SSL_use_certificate(ssl, x509refs);

        final OpenSSLKey key;
        try {
            key = OpenSSLKey.fromPrivateKeyForTLSStackOnly(privateKey, publicKey);
            NativeCrypto.SSL_use_PrivateKey(ssl, key.getNativeRef());
        } catch (InvalidKeyException e) {
            throw new SSLException(e);
        }

        // We may not have access to all the information to check the private key
        // if it's a wrapped platform key, so skip this check.
        if (!key.isWrapped()) {
            // Makes sure the set PrivateKey and X509Certificate refer to the same
            // key by comparing the public values.
            NativeCrypto.SSL_check_private_key(ssl);
        }
    }

    String getVersion() {
        return NativeCrypto.SSL_get_version(ssl);
    }

    boolean isReused() {
        return NativeCrypto.SSL_session_reused(ssl);
    }

    String getRequestedServerName() {
        return NativeCrypto.SSL_get_servername(ssl);
    }

    byte[] getTlsChannelId() throws SSLException {
        return NativeCrypto.SSL_get_tls_channel_id(ssl);
    }

    void initialize(String hostname, OpenSSLKey channelIdPrivateKey) throws IOException {
        boolean enableSessionCreation = parameters.getEnableSessionCreation();
        if (!enableSessionCreation) {
            NativeCrypto.SSL_set_session_creation_enabled(ssl, false);
        }

        // Allow servers to trigger renegotiation. Some inadvisable server
        // configurations cause them to attempt to renegotiate during
        // certain protocols.
        NativeCrypto.SSL_accept_renegotiations(ssl);

        if (isClient()) {
            NativeCrypto.SSL_set_connect_state(ssl);

            // Configure OCSP and CT extensions for client
            NativeCrypto.SSL_enable_ocsp_stapling(ssl);
            if (parameters.isCTVerificationEnabled(hostname)) {
                NativeCrypto.SSL_enable_signed_cert_timestamps(ssl);
            }
        } else {
            NativeCrypto.SSL_set_accept_state(ssl);

            // Configure OCSP for server
            if (parameters.getOCSPResponse() != null) {
                NativeCrypto.SSL_enable_ocsp_stapling(ssl);
            }
        }

        if (parameters.getEnabledProtocols().length == 0 && parameters.isEnabledProtocolsFiltered) {
            throw new SSLHandshakeException("No enabled protocols; "
                    + NativeCrypto.OBSOLETE_PROTOCOL_SSLV3
                    + " is no longer supported and was filtered from the list");
        }
        NativeCrypto.SSL_configure_alpn(ssl, isClient(), parameters.alpnProtocols);
        NativeCrypto.setEnabledProtocols(ssl, parameters.enabledProtocols);
        NativeCrypto.setEnabledCipherSuites(ssl, parameters.enabledCipherSuites);

        // setup server certificates and private keys.
        // clients will receive a call back to request certificates.
        if (!isClient()) {
            Set<String> keyTypes = new HashSet<String>();
            for (long sslCipherNativePointer : NativeCrypto.SSL_get_ciphers(ssl)) {
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

            NativeCrypto.SSL_set_options(ssl, NativeConstants.SSL_OP_CIPHER_SERVER_PREFERENCE);

            if (parameters.sctExtension != null) {
                NativeCrypto.SSL_set_signed_cert_timestamp_list(ssl, parameters.sctExtension);
            }

            if (parameters.ocspResponse != null) {
                NativeCrypto.SSL_set_ocsp_response(ssl, parameters.ocspResponse);
            }
        }

        enablePSKKeyManagerIfRequested();

        if (parameters.useSessionTickets) {
            NativeCrypto.SSL_clear_options(ssl, NativeConstants.SSL_OP_NO_TICKET);
        } else {
            NativeCrypto.SSL_set_options(
                    ssl, NativeCrypto.SSL_get_options(ssl) | NativeConstants.SSL_OP_NO_TICKET);
        }

        if (parameters.getUseSni() && AddressUtils.isValidSniHostname(hostname)) {
            NativeCrypto.SSL_set_tlsext_host_name(ssl, hostname);
        }

        // BEAST attack mitigation (1/n-1 record splitting for CBC cipher suites
        // with TLSv1 and SSLv3).
        NativeCrypto.SSL_set_mode(ssl, NativeConstants.SSL_MODE_CBC_RECORD_SPLITTING);

        setCertificateValidation(ssl);
        setTlsChannelId(channelIdPrivateKey);
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    void doHandshake(FileDescriptor fd, int timeoutMillis)
            throws CertificateException, SocketTimeoutException, SSLException {
        NativeCrypto.SSL_do_handshake(ssl, fd, handshakeCallbacks, timeoutMillis);
    }

    int doHandshake() throws IOException {
        return NativeCrypto.ENGINE_SSL_do_handshake(ssl, handshakeCallbacks);
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    int read(FileDescriptor fd, byte[] buf, int offset, int len, int timeoutMillis)
            throws IOException {
        return NativeCrypto.SSL_read(ssl, fd, handshakeCallbacks, buf, offset, len, timeoutMillis);
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    void write(FileDescriptor fd, byte[] buf, int offset, int len, int timeoutMillis)
            throws IOException {
        NativeCrypto.SSL_write(ssl, fd, handshakeCallbacks, buf, offset, len, timeoutMillis);
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
                    NativeCrypto.set_SSL_psk_client_callback_enabled(ssl, true);
                } else {
                    NativeCrypto.set_SSL_psk_server_callback_enabled(ssl, true);
                    String identityHint = pskCallbacks.chooseServerPSKIdentityHint(pskKeyManager);
                    NativeCrypto.SSL_use_psk_identity_hint(ssl, identityHint);
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
            NativeCrypto.SSL_set1_tls_channel_id(ssl, channelIdPrivateKey.getNativeRef());
        } else {
            // Server-side TLS Channel ID
            NativeCrypto.SSL_enable_tls_channel_id(ssl);
        }
    }

    private void setCertificateValidation(long sslNativePointer) throws SSLException {
        // setup peer certificate verification
        if (!isClient()) {
            // needing client auth takes priority...
            boolean certRequested;
            if (parameters.getNeedClientAuth()) {
                NativeCrypto.SSL_set_verify(sslNativePointer, NativeCrypto.SSL_VERIFY_PEER
                                | NativeCrypto.SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
                certRequested = true;
                // ... over just wanting it...
            } else if (parameters.getWantClientAuth()) {
                NativeCrypto.SSL_set_verify(sslNativePointer, NativeCrypto.SSL_VERIFY_PEER);
                certRequested = true;
                // ... and we must disable verification if we don't want client auth.
            } else {
                NativeCrypto.SSL_set_verify(sslNativePointer, NativeCrypto.SSL_VERIFY_NONE);
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
                    NativeCrypto.SSL_set_client_CA_list(sslNativePointer, issuersBytes);
                }
            }
        }
    }

    void interrupt() {
        NativeCrypto.SSL_interrupt(ssl);
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    void shutdown(FileDescriptor fd) throws IOException {
        NativeCrypto.SSL_shutdown(ssl, fd, handshakeCallbacks);
    }

    void shutdown() throws IOException {
        NativeCrypto.ENGINE_SSL_shutdown(ssl, handshakeCallbacks);
    }

    boolean wasShutdownReceived() {
        return (NativeCrypto.SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) != 0;
    }

    boolean wasShutdownSent() {
        return (NativeCrypto.SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN) != 0;
    }

    int readDirectByteBuffer(long destAddress, int destLength)
            throws IOException, CertificateException {
        return NativeCrypto.ENGINE_SSL_read_direct(
                ssl, destAddress, destLength, handshakeCallbacks);
    }

    int readArray(byte[] destJava, int destOffset, int destLength)
            throws IOException, CertificateException {
        return NativeCrypto.ENGINE_SSL_read_heap(
                ssl, destJava, destOffset, destLength, handshakeCallbacks);
    }

    int writeDirectByteBuffer(long sourceAddress, int sourceLength) throws IOException {
        return NativeCrypto.ENGINE_SSL_write_direct(
                ssl, sourceAddress, sourceLength, handshakeCallbacks);
    }

    int writeArray(byte[] sourceJava, int sourceOffset, int sourceLength) throws IOException {
        return NativeCrypto.ENGINE_SSL_write_heap(
                ssl, sourceJava, sourceOffset, sourceLength, handshakeCallbacks);
    }

    int getPendingReadableBytes() {
        return NativeCrypto.SSL_pending_readable_bytes(ssl);
    }

    int getMaxSealOverhead() {
        return NativeCrypto.SSL_max_seal_overhead(ssl);
    }

    void close() {
        NativeCrypto.SSL_free(ssl);
        ssl = 0L;
    }

    boolean isClosed() {
        return ssl == 0L;
    }

    int getError(int result) {
        return NativeCrypto.SSL_get_error(ssl, result);
    }

    byte[] getAlpnSelectedProtocol() {
        return NativeCrypto.SSL_get0_alpn_selected(ssl);
    }

    private boolean isClient() {
        return parameters.getUseClientMode();
    }

    /**
     * A utility wrapper that abstracts operations on the underlying native BIO instance.
     */
    final class BioWrapper {
        private long bio;

        private BioWrapper() throws SSLException {
            this.bio = NativeCrypto.SSL_BIO_new(ssl);
        }

        int getPendingWrittenBytes() {
            return NativeCrypto.SSL_pending_written_bytes_in_BIO(bio);
        }

        int writeDirectByteBuffer(long address, int length) throws IOException {
            return NativeCrypto.ENGINE_SSL_write_BIO_direct(
                    ssl, bio, address, length, handshakeCallbacks);
        }

        int writeArray(byte[] sourceJava, int sourceOffset, int sourceLength) throws IOException {
            return NativeCrypto.ENGINE_SSL_write_BIO_heap(
                    ssl, bio, sourceJava, sourceOffset, sourceLength, handshakeCallbacks);
        }

        int readDirectByteBuffer(long destAddress, int destLength) throws IOException {
            return NativeCrypto.ENGINE_SSL_read_BIO_direct(
                    ssl, bio, destAddress, destLength, handshakeCallbacks);
        }

        int readArray(byte[] destJava, int destOffset, int destLength) throws IOException {
            return NativeCrypto.ENGINE_SSL_read_BIO_heap(
                    ssl, bio, destJava, destOffset, destLength, handshakeCallbacks);
        }

        void close() {
            NativeCrypto.BIO_free_all(bio);
            bio = 0L;
        }
    }
}
