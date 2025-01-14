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
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
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
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
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

    static NativeSsl newInstance(SSLParametersImpl parameters,
            SSLHandshakeCallbacks handshakeCallbacks, AliasChooser chooser,
            PSKCallbacks pskCallbacks) throws SSLException {
        long ssl = parameters.getSessionContext().newSsl();
        return new NativeSsl(ssl, parameters, handshakeCallbacks, chooser, pskCallbacks);
    }

    BioWrapper newBio() {
        try {
            return new BioWrapper();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    void initSpake() throws SSLException, InvalidAlgorithmParameterException {
        Spake2PlusKeyManager spakeKeyManager = parameters.getSpake2PlusKeyManager();
        byte[] context =
                spakeKeyManager.getContext() == null
                        ? "spake2+".getBytes()
                        : spakeKeyManager.getContext();
        byte[] idProverArray = spakeKeyManager.getIdProver();
        byte[] idVerifierArray = spakeKeyManager.getIdVerifier();
        byte[] pwArray = spakeKeyManager.getPassword();
        byte[] w0Array = spakeKeyManager.getw0();
        byte[] w1Array = spakeKeyManager.getw1();
        byte[] registrationRecordArray = spakeKeyManager.getRegistrationRecord();
        boolean isClient = spakeKeyManager.isClient();

        // TODO: uncomment this once the native code is ready.
        /*
        if (pwArray != null) {
            NativeCrypto.SSL_CTX_set_spake_credential(
                context, pwArray, idProverArray,
                idVerifierArray, isClient, this);
        } else if (isClient && w0Array != null && w1Array != null) {
            NativeCrypto.SSL_CTX_set_spake_credential_client(
                context, w0Array, w1Array,
                idProverArray, idVerifierArray, this);
        } else if (!isClient && w0Array != null && registrationRecordArray != null) {
            NativeCrypto.SSL_CTX_set_spake_credential_server(
                context, w0Array, registrationRecordArray,
                idProverArray, idVerifierArray, this);
        }
        */
    }

    void offerToResumeSession(long sslSessionNativePointer) throws SSLException {
        NativeCrypto.SSL_set_session(ssl, this, sslSessionNativePointer);
    }

    byte[] getSessionId() {
        return NativeCrypto.SSL_session_id(ssl, this);
    }

    long getTime() {
        return NativeCrypto.SSL_get_time(ssl, this);
    }

    long getTimeout() {
        return NativeCrypto.SSL_get_timeout(ssl, this);
    }

    void setTimeout(long millis) {
        NativeCrypto.SSL_set_timeout(ssl, this, millis);
    }

    String getCipherSuite() {
        return NativeCrypto.cipherSuiteToJava(NativeCrypto.SSL_get_current_cipher(ssl, this));
    }

    X509Certificate[] getPeerCertificates() throws CertificateException {
        byte[][] encoded = NativeCrypto.SSL_get0_peer_certificates(ssl, this);
        return encoded == null ? null : SSLUtils.decodeX509CertificateChain(encoded);
    }

    X509Certificate[] getLocalCertificates() {
        return localCertificates;
    }

    byte[] getPeerCertificateOcspData() {
        return NativeCrypto.SSL_get_ocsp_response(ssl, this);
    }

    byte[] getTlsUnique() {
        return NativeCrypto.SSL_get_tls_unique(ssl, this);
    }

    byte[] exportKeyingMaterial(String label, byte[] context, int length) throws SSLException {
        if (label == null) {
            throw new NullPointerException("Label is null");
        }
        byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
        return NativeCrypto.SSL_export_keying_material(ssl, this, labelBytes, context, length);
    }

    byte[] getPeerTlsSctData() {
        return NativeCrypto.SSL_get_signed_cert_timestamp_list(ssl, this);
    }

    /*
     * See NativeCrypto.SSLHandshakeCallbacks#clientPSKKeyRequested(String, byte[], byte[]).
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
            identityBytes = identity.getBytes(StandardCharsets.UTF_8);
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

    /*
     * See NativeCrypto.SSLHandshakeCallbacks#serverPSKKeyRequested(String, String, byte[]).
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

    void chooseClientCertificate(byte[] keyTypeBytes, int[] signatureAlgs,
            byte[][] asn1DerEncodedPrincipals)
            throws SSLException, CertificateEncodingException {
        Set<String> keyTypesSet = SSLUtils.getSupportedClientKeyTypes(keyTypeBytes, signatureAlgs);
        String[] keyTypes = keyTypesSet.toArray(new String[0]);

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

    private void setCertificate(String alias) throws CertificateEncodingException, SSLException {
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
        NativeCrypto.setLocalCertsAndPrivateKey(ssl, this, encodedLocalCerts, key.getNativeRef());
    }

    String getVersion() {
        return NativeCrypto.SSL_get_version(ssl, this);
    }

    String getRequestedServerName() {
        return NativeCrypto.SSL_get_servername(ssl, this);
    }

    byte[] getTlsChannelId() throws SSLException {
        return NativeCrypto.SSL_get_tls_channel_id(ssl, this);
    }

    void initialize(String hostname, OpenSSLKey channelIdPrivateKey) throws IOException {
        if (parameters.isSpake()) {
            try {
                initSpake();
            } catch (Exception e) {
                throw new SSLHandshakeException("Spake initialization failed " + e.getMessage());
            }
        }

        boolean enableSessionCreation = parameters.getEnableSessionCreation();
        if (!enableSessionCreation) {
            NativeCrypto.SSL_set_session_creation_enabled(ssl, this, false);
        }

        // Allow servers to trigger renegotiation. Some inadvisable server
        // configurations cause them to attempt to renegotiate during
        // certain protocols.
        NativeCrypto.SSL_accept_renegotiations(ssl, this);

        if (isClient()) {
            NativeCrypto.SSL_set_connect_state(ssl, this);

            // Configure OCSP and CT extensions for client
            NativeCrypto.SSL_enable_ocsp_stapling(ssl, this);
            if (parameters.isCTVerificationEnabled(hostname)) {
                NativeCrypto.SSL_enable_signed_cert_timestamps(ssl, this);
            }
        } else {
            NativeCrypto.SSL_set_accept_state(ssl, this);

            // Configure OCSP for server
            if (parameters.getOCSPResponse() != null) {
                NativeCrypto.SSL_enable_ocsp_stapling(ssl, this);
            }
        }

        if (parameters.getEnabledProtocols().length == 0 && parameters.isEnabledProtocolsFiltered) {
            throw new SSLHandshakeException("No enabled protocols; "
                    + NativeCrypto.OBSOLETE_PROTOCOL_SSLV3 + ", "
                    + NativeCrypto.DEPRECATED_PROTOCOL_TLSV1
                    + " and " + NativeCrypto.DEPRECATED_PROTOCOL_TLSV1_1
                    + " are no longer supported and were filtered from the list");
        }
        NativeCrypto.setEnabledProtocols(ssl, this, parameters.enabledProtocols);
        // Not sure if we need to do this for SPAKE, but the SPAKE cipher suite
        // not registered at the moment.
        if (!parameters.isSpake()) {
            NativeCrypto.setEnabledCipherSuites(
                ssl, this, parameters.enabledCipherSuites, parameters.enabledProtocols);
        }

        if (parameters.applicationProtocols.length > 0) {
            NativeCrypto.setApplicationProtocols(ssl, this, isClient(), parameters.applicationProtocols);
        }
        if (!isClient() && parameters.applicationProtocolSelector != null) {
            NativeCrypto.setHasApplicationProtocolSelector(ssl, this, true);
        }

        // setup server certificates and private keys.
        // clients will receive a call back to request certificates.
        if (!isClient()) {
            NativeCrypto.SSL_set_options(ssl, this, SSL_OP_CIPHER_SERVER_PREFERENCE);

            if (parameters.sctExtension != null) {
                NativeCrypto.SSL_set_signed_cert_timestamp_list(ssl, this, parameters.sctExtension);
            }

            if (parameters.ocspResponse != null) {
                NativeCrypto.SSL_set_ocsp_response(ssl, this, parameters.ocspResponse);
            }
        }

        enablePSKKeyManagerIfRequested();

        if (parameters.useSessionTickets) {
            NativeCrypto.SSL_clear_options(ssl, this, SSL_OP_NO_TICKET);
        } else {
            NativeCrypto.SSL_set_options(
                    ssl, this, NativeCrypto.SSL_get_options(ssl, this) | SSL_OP_NO_TICKET);
        }

        if (parameters.getUseSni() && AddressUtils.isValidSniHostname(hostname)) {
            NativeCrypto.SSL_set_tlsext_host_name(ssl, this, hostname);
        }

        // BEAST attack mitigation (1/n-1 record splitting for CBC cipher suites
        // with TLSv1 and SSLv3).
        NativeCrypto.SSL_set_mode(ssl, this, SSL_MODE_CBC_RECORD_SPLITTING);

        if (!parameters.isSpake()) {
          setCertificateValidation();
        }
        setTlsChannelId(channelIdPrivateKey);
    }

    void configureServerCertificate() throws IOException {
        verifyWithSniMatchers(getRequestedServerName());
        if (isClient()) {
            return;
        }
        X509KeyManager keyManager = parameters.getX509KeyManager();
        if (keyManager != null) {
            for (String keyType : getCipherKeyTypes()) {
                try {
                    setCertificate(aliasChooser.chooseServerAlias(keyManager, keyType));
                } catch (CertificateEncodingException e) {
                    throw new IOException(e);
                }
            }
        }
    }

    private void verifyWithSniMatchers(String serverName) throws SSLHandshakeException {
        if (!AddressUtils.isValidSniHostname(serverName)) {
            return;
        }

        if (!Platform.serverNamePermitted(parameters, serverName)) {
            throw new SSLHandshakeException("SNI match failed: " + serverName);
        }
    }

    private Set<String> getCipherKeyTypes() {
        Set<String> keyTypes = new HashSet<>();
        for (long sslCipherNativePointer : NativeCrypto.SSL_get_ciphers(ssl, this)) {
            String keyType = SSLUtils.getServerX509KeyType(sslCipherNativePointer);
            if (keyType != null) {
                keyTypes.add(keyType);
            }
        }
        return keyTypes;
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    void doHandshake(FileDescriptor fd, int timeoutMillis)
            throws CertificateException, IOException {
        lock.readLock().lock();
        try {
            if (isClosed() || fd == null || !fd.valid()) {
                throw new SocketException("Socket is closed");
            }
            NativeCrypto.SSL_do_handshake(ssl, this, fd, handshakeCallbacks, timeoutMillis);
        } finally {
            lock.readLock().unlock();
        }
    }

    int doHandshake() throws IOException {
        lock.readLock().lock();
        try {
            return NativeCrypto.ENGINE_SSL_do_handshake(ssl, this, handshakeCallbacks);
        } finally {
            lock.readLock().unlock();
        }
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    int read(FileDescriptor fd, byte[] buf, int offset, int len, int timeoutMillis)
            throws IOException {
        lock.readLock().lock();
        try {
            if (isClosed() || fd == null || !fd.valid()) {
                throw new SocketException("Socket is closed");
            }
            return NativeCrypto
                    .SSL_read(ssl, this, fd, handshakeCallbacks, buf, offset, len, timeoutMillis);
        } finally {
            lock.readLock().unlock();
        }
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    void write(FileDescriptor fd, byte[] buf, int offset, int len, int timeoutMillis)
            throws IOException {
        lock.readLock().lock();
        try {
            if (isClosed() || fd == null || !fd.valid()) {
                throw new SocketException("Socket is closed");
            }
            NativeCrypto
                    .SSL_write(ssl, this, fd, handshakeCallbacks, buf, offset, len, timeoutMillis);
        } finally {
            lock.readLock().unlock();
        }
    }

    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    private void enablePSKKeyManagerIfRequested() throws SSLException {
        // Enable Pre-Shared Key (PSK) key exchange if requested
        PSKKeyManager pskKeyManager = parameters.getPSKKeyManager();
        if (pskKeyManager != null) {
            boolean pskEnabled = false;
            for (String enabledCipherSuite : parameters.enabledCipherSuites) {
                if ((enabledCipherSuite != null) && enabledCipherSuite.contains("PSK")) {
                    pskEnabled = true;
                    break;
                }
            }
            if (pskEnabled) {
                if (isClient()) {
                    NativeCrypto.set_SSL_psk_client_callback_enabled(ssl, this, true);
                } else {
                    NativeCrypto.set_SSL_psk_server_callback_enabled(ssl, this, true);
                    String identityHint = pskCallbacks.chooseServerPSKIdentityHint(pskKeyManager);
                    NativeCrypto.SSL_use_psk_identity_hint(ssl, this, identityHint);
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
            NativeCrypto.SSL_set1_tls_channel_id(ssl, this, channelIdPrivateKey.getNativeRef());
        } else {
            // Server-side TLS Channel ID
            NativeCrypto.SSL_enable_tls_channel_id(ssl, this);
        }
    }

    private void setCertificateValidation() throws SSLException {
        // setup peer certificate verification
        if (!isClient()) {
            // needing client auth takes priority...
            boolean certRequested;
            if (parameters.getNeedClientAuth()) {
                NativeCrypto.SSL_set_verify(ssl, this, SSL_VERIFY_PEER
                                | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
                certRequested = true;
                // ... over just wanting it...
            } else if (parameters.getWantClientAuth()) {
                NativeCrypto.SSL_set_verify(ssl, this, SSL_VERIFY_PEER);
                certRequested = true;
                // ... and we must disable verification if we don't want client auth.
            } else {
                NativeCrypto.SSL_set_verify(ssl, this, SSL_VERIFY_NONE);
                certRequested = false;
            }

            if (certRequested) {
                X509TrustManager trustManager = parameters.getX509TrustManager();
                X509Certificate[] issuers = trustManager.getAcceptedIssuers();
                if (issuers != null && issuers.length != 0) {
                    byte[][] issuersBytes;
                    try {
                        issuersBytes = SSLUtils.encodeSubjectX509Principals(issuers);
                    } catch (CertificateEncodingException e) {
                        throw new SSLException("Problem encoding principals", e);
                    }
                    NativeCrypto.SSL_set_client_CA_list(ssl, this, issuersBytes);
                }
            }
        }
    }

    void interrupt() {
        NativeCrypto.SSL_interrupt(ssl, this);
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    void shutdown(FileDescriptor fd) throws IOException {
        NativeCrypto.SSL_shutdown(ssl, this, fd, handshakeCallbacks);
    }

    void shutdown() throws IOException {
        lock.readLock().lock();
        try {
            NativeCrypto.ENGINE_SSL_shutdown(ssl, this, handshakeCallbacks);
        } finally {
            lock.readLock().unlock();
        }
    }

    boolean wasShutdownReceived() {
        lock.readLock().lock();
        try {
            return (NativeCrypto.SSL_get_shutdown(ssl, this) & SSL_RECEIVED_SHUTDOWN) != 0;
        } finally {
            lock.readLock().unlock();
        }
    }

    boolean wasShutdownSent() {
        lock.readLock().lock();
        try {
            return (NativeCrypto.SSL_get_shutdown(ssl, this) & SSL_SENT_SHUTDOWN) != 0;
        } finally {
            lock.readLock().unlock();
        }
    }

    int readDirectByteBuffer(long destAddress, int destLength)
            throws IOException, CertificateException {
        lock.readLock().lock();
        try {
            return NativeCrypto.ENGINE_SSL_read_direct(
                    ssl, this, destAddress, destLength, handshakeCallbacks);
        } finally {
            lock.readLock().unlock();
        }
    }

    int writeDirectByteBuffer(long sourceAddress, int sourceLength) throws IOException {
        lock.readLock().lock();
        try {
            return NativeCrypto.ENGINE_SSL_write_direct(
                    ssl, this, sourceAddress, sourceLength, handshakeCallbacks);
        } finally {
            lock.readLock().unlock();
        }
    }

    void forceRead() throws IOException {
        lock.readLock().lock();
        try {
            NativeCrypto.ENGINE_SSL_force_read(ssl, this, handshakeCallbacks);
        } finally {
            lock.readLock().unlock();
        }
    }

    int getPendingReadableBytes() {
        lock.readLock().lock();
        try {
            if (!isClosed()) {
                return NativeCrypto.SSL_pending_readable_bytes(ssl, this);
            }
            return 0;
        } finally {
            lock.readLock().unlock();
        }
    }

    int getMaxSealOverhead() {
        return NativeCrypto.SSL_max_seal_overhead(ssl, this);
    }

    void close() {
        lock.writeLock().lock();
        try {
            if (!isClosed()) {
                long toFree = ssl;
                ssl = 0L;
                NativeCrypto.SSL_free(toFree, this);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    boolean isClosed() {
        return ssl == 0L;
    }

    int getError(int result) {
        return NativeCrypto.SSL_get_error(ssl, this, result);
    }

    byte[] getApplicationProtocol() {
        return NativeCrypto.getApplicationProtocol(ssl, this);
    }

    private boolean isClient() {
        return parameters.getUseClientMode();
    }

    @Override
    @SuppressWarnings("Finalize")
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }

    /**
     * A utility wrapper that abstracts operations on the underlying native BIO instance.
     */
    final class BioWrapper {
        private volatile long bio;

        private BioWrapper() throws SSLException {
            this.bio = NativeCrypto.SSL_BIO_new(ssl, NativeSsl.this);
        }

        int getPendingWrittenBytes() {
            lock.readLock().lock();
            try {
                return (bio == 0L) ? 0 : NativeCrypto.SSL_pending_written_bytes_in_BIO(bio);
            } finally {
                lock.readLock().unlock();
            }
        }

        int writeDirectByteBuffer(long address, int length) throws IOException {
            lock.readLock().lock();
            try {
                if (isClosed()) {
                    throw new SSLException("Connection closed");
                }
                return NativeCrypto.ENGINE_SSL_write_BIO_direct(
                        ssl, NativeSsl.this, bio, address, length, handshakeCallbacks);
            } finally {
                lock.readLock().unlock();
            }
        }

        int readDirectByteBuffer(long destAddress, int destLength) throws IOException {
            lock.readLock().lock();
            try {
                if (isClosed()) {
                    throw new SSLException("Connection closed");
                }
                return NativeCrypto.ENGINE_SSL_read_BIO_direct(
                        ssl, NativeSsl.this, bio, destAddress, destLength, handshakeCallbacks);
            } finally {
                lock.readLock().unlock();
            }
        }

        void close() {
            lock.writeLock().lock();
            try {
                long toFree = bio;
                bio = 0L;
                if (toFree != 0L) {
                    NativeCrypto.BIO_free_all(toFree);
                }
            } finally {
                lock.writeLock().unlock();
            }
        }
    }
}
