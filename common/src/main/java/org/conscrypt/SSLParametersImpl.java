/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.conscrypt;

import java.security.AlgorithmConstraints;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

/**
 * The instances of this class encapsulate all the info
 * about enabled cipher suites and protocols,
 * as well as the information about client/server mode of
 * ssl socket, whether it require/want client authentication or not,
 * and controls whether new SSL sessions may be established by this
 * socket or not.
 */
final class SSLParametersImpl implements Cloneable {

    // default source of X.509 certificate based authentication keys
    private static volatile X509KeyManager defaultX509KeyManager;
    // default source of X.509 certificate based authentication trust decisions
    private static volatile X509TrustManager defaultX509TrustManager;
    // default SSL parameters
    private static volatile SSLParametersImpl defaultParameters;

    // client session context contains the set of reusable
    // client-side SSL sessions
    private final ClientSessionContext clientSessionContext;
    // server session context contains the set of reusable
    // server-side SSL sessions
    private final ServerSessionContext serverSessionContext;
    // source of X.509 certificate based authentication keys or null if not provided
    private final X509KeyManager x509KeyManager;
    // source of Pre-Shared Key (PSK) authentication keys or null if not provided.
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    private final PSKKeyManager pskKeyManager;
    // source of X.509 certificate based authentication trust decisions or null if not provided
    private final X509TrustManager x509TrustManager;

    // protocols enabled for SSL connection
    String[] enabledProtocols;
    // set to indicate when obsolete protocols are filtered
    boolean isEnabledProtocolsFiltered;
    // The TLS 1.0-1.2 cipher suites enabled for the SSL connection.  TLS 1.3 cipher suites
    // cannot be customized, so for simplicity this field never contains any TLS 1.3 suites.
    String[] enabledCipherSuites;

    // if the peer with this parameters tuned to work in client mode
    private boolean client_mode = true;
    // if the peer with this parameters tuned to require client authentication
    private boolean need_client_auth = false;
    // if the peer with this parameters tuned to request client authentication
    private boolean want_client_auth = false;
    // if the peer with this parameters allowed to cteate new SSL session
    private boolean enable_session_creation = true;
    // Endpoint identification algorithm (e.g., HTTPS)
    private String endpointIdentificationAlgorithm;
    // Whether to use the local cipher suites order
    private boolean useCipherSuitesOrder;
    private Collection<SNIMatcher> sniMatchers;
    private AlgorithmConstraints algorithmConstraints;

    // client-side only, bypasses the property based configuration, used for tests
    private boolean ctVerificationEnabled;

    // server-side only. SCT and OCSP data to send to clients which request it
    byte[] sctExtension;
    byte[] ocspResponse;

    byte[] applicationProtocols = EmptyArray.BYTE;
    ApplicationProtocolSelectorAdapter applicationProtocolSelector;
    boolean useSessionTickets;
    private Boolean useSni;

    /**
     * Whether the TLS Channel ID extension is enabled. This field is
     * server-side only.
     */
    boolean channelIdEnabled;

    /**
     * Initializes the parameters. Naturally this constructor is used
     * in SSLContextImpl.engineInit method which directly passes its
     * parameters. In other words this constructor holds all
     * the functionality provided by SSLContext.init method.
     * See {@link javax.net.ssl.SSLContext#init(KeyManager[],TrustManager[],
     * SecureRandom)} for more information
     */
    SSLParametersImpl(KeyManager[] kms, TrustManager[] tms,
            SecureRandom sr, ClientSessionContext clientSessionContext,
            ServerSessionContext serverSessionContext, String[] protocols)
            throws KeyManagementException {
        this.serverSessionContext = serverSessionContext;
        this.clientSessionContext = clientSessionContext;

        // initialize key managers
        if (kms == null) {
            x509KeyManager = getDefaultX509KeyManager();
            // There's no default PSK key manager
            pskKeyManager = null;
        } else {
            x509KeyManager = findFirstX509KeyManager(kms);
            pskKeyManager = findFirstPSKKeyManager(kms);
        }

        // initialize x509TrustManager
        if (tms == null) {
            x509TrustManager = getDefaultX509TrustManager();
        } else {
            x509TrustManager = findFirstX509TrustManager(tms);
        }

        // initialize the list of cipher suites and protocols enabled by default
        enabledProtocols = NativeCrypto.checkEnabledProtocols(
                protocols == null ? NativeCrypto.DEFAULT_PROTOCOLS : protocols).clone();
        boolean x509CipherSuitesNeeded = (x509KeyManager != null) || (x509TrustManager != null);
        boolean pskCipherSuitesNeeded = pskKeyManager != null;
        enabledCipherSuites = getDefaultCipherSuites(
                x509CipherSuitesNeeded, pskCipherSuitesNeeded);

        // We ignore the SecureRandom passed in by the caller. The native code below
        // directly accesses /dev/urandom, which makes it irrelevant.
    }

    // Copy constructor for the purposes of changing the final fields
    @SuppressWarnings("deprecation")  // for PSKKeyManager
    private SSLParametersImpl(ClientSessionContext clientSessionContext,
        ServerSessionContext serverSessionContext,
        X509KeyManager x509KeyManager,
        PSKKeyManager pskKeyManager,
        X509TrustManager x509TrustManager,
        SSLParametersImpl sslParams) {
        this.clientSessionContext = clientSessionContext;
        this.serverSessionContext = serverSessionContext;
        this.x509KeyManager = x509KeyManager;
        this.pskKeyManager = pskKeyManager;
        this.x509TrustManager = x509TrustManager;

        this.enabledProtocols =
            (sslParams.enabledProtocols == null) ? null : sslParams.enabledProtocols.clone();
        this.isEnabledProtocolsFiltered = sslParams.isEnabledProtocolsFiltered;
        this.enabledCipherSuites =
            (sslParams.enabledCipherSuites == null) ? null : sslParams.enabledCipherSuites.clone();
        this.client_mode = sslParams.client_mode;
        this.need_client_auth = sslParams.need_client_auth;
        this.want_client_auth = sslParams.want_client_auth;
        this.enable_session_creation = sslParams.enable_session_creation;
        this.endpointIdentificationAlgorithm = sslParams.endpointIdentificationAlgorithm;
        this.useCipherSuitesOrder = sslParams.useCipherSuitesOrder;
        this.ctVerificationEnabled = sslParams.ctVerificationEnabled;
        this.sctExtension =
            (sslParams.sctExtension == null) ? null : sslParams.sctExtension.clone();
        this.ocspResponse =
            (sslParams.ocspResponse == null) ? null : sslParams.ocspResponse.clone();
        this.applicationProtocols =
            (sslParams.applicationProtocols == null) ? null : sslParams.applicationProtocols.clone();
        this.applicationProtocolSelector = sslParams.applicationProtocolSelector;
        this.useSessionTickets = sslParams.useSessionTickets;
        this.useSni = sslParams.useSni;
        this.channelIdEnabled = sslParams.channelIdEnabled;
    }

    static SSLParametersImpl getDefault() throws KeyManagementException {
        SSLParametersImpl result = defaultParameters;
        if (result == null) {
            // single-check idiom
            defaultParameters = result = new SSLParametersImpl(null,
                                                               null,
                                                               null,
                                                               new ClientSessionContext(),
                                                               new ServerSessionContext(),
                                                               null);
        }
        return (SSLParametersImpl) result.clone();
    }

    /**
     * Returns the appropriate session context.
     */
    AbstractSessionContext getSessionContext() {
        return client_mode ? clientSessionContext : serverSessionContext;
    }

    /**
     * @return client session context
     */
    ClientSessionContext getClientSessionContext() {
        return clientSessionContext;
    }

    /**
     * @return X.509 key manager or {@code null} for none.
     */
    X509KeyManager getX509KeyManager() {
        return x509KeyManager;
    }

    /**
     * @return Pre-Shared Key (PSK) key manager or {@code null} for none.
     */
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    PSKKeyManager getPSKKeyManager() {
        return pskKeyManager;
    }

    /**
     * @return X.509 trust manager or {@code null} for none.
     */
    X509TrustManager getX509TrustManager() {
        return x509TrustManager;
    }

    /**
     * @return the names of enabled cipher suites
     */
    String[] getEnabledCipherSuites() {
        if (Arrays.asList(enabledProtocols).contains(NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3)) {
            return SSLUtils.concat(
                    NativeCrypto.SUPPORTED_TLS_1_3_CIPHER_SUITES, enabledCipherSuites);
        }
        return enabledCipherSuites.clone();
    }

    /**
     * Sets the enabled cipher suites after filtering through OpenSSL.
     */
    void setEnabledCipherSuites(String[] cipherSuites) {
        // Filter out any TLS 1.3 cipher suites the user may have passed.  Our TLS 1.3 suites
        // are always enabled, no matter what the user requests, so we only store the 1.0-1.2
        // suites in enabledCipherSuites.
        enabledCipherSuites = NativeCrypto.checkEnabledCipherSuites(
                filterFromCipherSuites(cipherSuites,
                        NativeCrypto.SUPPORTED_TLS_1_3_CIPHER_SUITES_SET));
    }

    /**
     * @return the set of enabled protocols
     */
    String[] getEnabledProtocols() {
        return enabledProtocols.clone();
    }

    /**
     * Sets the list of available protocols for use in SSL connection.
     * @throws IllegalArgumentException if {@code protocols == null}
     */
    void setEnabledProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("protocols == null");
        }
        String[] filteredProtocols =
                filterFromProtocols(protocols, NativeCrypto.OBSOLETE_PROTOCOL_SSLV3);
        isEnabledProtocolsFiltered = protocols.length != filteredProtocols.length;
        enabledProtocols = NativeCrypto.checkEnabledProtocols(filteredProtocols).clone();
    }

    /**
     * Sets the list of ALPN protocols.
     *
     * @param protocols the list of ALPN protocols
     */
    void setApplicationProtocols(String[] protocols) {
        this.applicationProtocols = SSLUtils.encodeProtocols(protocols);
    }

    String[] getApplicationProtocols() {
        return SSLUtils.decodeProtocols(applicationProtocols);
    }

    /**
     * Used for server-mode only. Sets or clears the application-provided ALPN protocol selector.
     * If set, will override the protocol list provided by {@link #setApplicationProtocols(String[])}.
     */
    void setApplicationProtocolSelector(ApplicationProtocolSelectorAdapter applicationProtocolSelector) {
        this.applicationProtocolSelector = applicationProtocolSelector;
    }

    /**
     * Returns the application protocol (ALPN) selector for this socket.
     */
    ApplicationProtocolSelectorAdapter getApplicationProtocolSelector() {
        return applicationProtocolSelector;
    }

    /**
     * Tunes the peer holding this parameters to work in client mode.
     * @param   mode if the peer is configured to work in client mode
     */
    void setUseClientMode(boolean mode) {
        client_mode = mode;
    }

    /**
     * Returns the value indicating if the parameters configured to work
     * in client mode.
     */
    boolean getUseClientMode() {
        return client_mode;
    }

    /**
     * Tunes the peer holding this parameters to require client authentication
     */
    void setNeedClientAuth(boolean need) {
        need_client_auth = need;
        // reset the want_client_auth setting
        want_client_auth = false;
    }

    /**
     * Returns the value indicating if the peer with this parameters tuned
     * to require client authentication
     */
    boolean getNeedClientAuth() {
        return need_client_auth;
    }

    /**
     * Tunes the peer holding this parameters to request client authentication
     */
    void setWantClientAuth(boolean want) {
        want_client_auth = want;
        // reset the need_client_auth setting
        need_client_auth = false;
    }

    /**
     * Returns the value indicating if the peer with this parameters
     * tuned to request client authentication
     */
    boolean getWantClientAuth() {
        return want_client_auth;
    }

    /**
     * Allows/disallows the peer holding this parameters to
     * create new SSL session
     */
    void setEnableSessionCreation(boolean flag) {
        enable_session_creation = flag;
    }

    /**
     * Returns the value indicating if the peer with this parameters
     * allowed to cteate new SSL session
     */
    boolean getEnableSessionCreation() {
        return enable_session_creation;
    }

    void setUseSessionTickets(boolean useSessionTickets) {
        this.useSessionTickets = useSessionTickets;
    }

    /**
     * Whether connections using this SSL connection should use the TLS
     * extension Server Name Indication (SNI).
     */
    void setUseSni(boolean flag) {
        useSni = flag;
    }

    /**
     * Returns whether connections using this SSL connection should use the TLS
     * extension Server Name Indication (SNI).
     */
    boolean getUseSni() {
        return useSni != null ? useSni : isSniEnabledByDefault();
    }

    /**
     * For testing only.
     */
    void setCTVerificationEnabled(boolean enabled) {
        ctVerificationEnabled = enabled;
    }

    /**
     * For testing only.
     */
    void setSCTExtension(byte[] extension) {
        sctExtension = extension;
    }

    /**
     * For testing only.
     */
    void setOCSPResponse(byte[] response) {
        ocspResponse = response;
    }

    byte[] getOCSPResponse() {
        return ocspResponse;
    }

    /**
     * This filters {@code obsoleteProtocol} from the list of {@code protocols}
     * down to help with app compatibility.
     */
    private static String[] filterFromProtocols(String[] protocols, String obsoleteProtocol) {
        if (protocols.length == 1 && obsoleteProtocol.equals(protocols[0])) {
            return EMPTY_STRING_ARRAY;
        }

        ArrayList<String> newProtocols = new ArrayList<String>();
        for (String protocol : protocols) {
            if (!obsoleteProtocol.equals(protocol)) {
                newProtocols.add(protocol);
            }
        }
        return newProtocols.toArray(EMPTY_STRING_ARRAY);
    }

    private static String[] filterFromCipherSuites(String[] cipherSuites, Set<String> toRemove) {
        if (cipherSuites == null || cipherSuites.length == 0) {
            return cipherSuites;
        }
        ArrayList<String> newCipherSuites = new ArrayList<String>(cipherSuites.length);
        for (String cipherSuite : cipherSuites) {
            if (!toRemove.contains(cipherSuite)) {
                newCipherSuites.add(cipherSuite);
            }
        }
        return newCipherSuites.toArray(EMPTY_STRING_ARRAY);
    }

    private static final String[] EMPTY_STRING_ARRAY = new String[0];

    /**
     * Returns whether Server Name Indication (SNI) is enabled by default for
     * sockets. For more information on SNI, see RFC 6066 section 3.
     */
    private boolean isSniEnabledByDefault() {
        try {
            String enableSNI = System.getProperty("jsse.enableSNIExtension", "true");
            if ("true".equalsIgnoreCase(enableSNI)) {
                return true;
            } else if ("false".equalsIgnoreCase(enableSNI)) {
                return false;
            } else {
                throw new RuntimeException(
                        "Can only set \"jsse.enableSNIExtension\" to \"true\" or \"false\"");
            }
        } catch (SecurityException e) {
            return true;
        }
    }

    /**
     * For abstracting the X509KeyManager calls between
     * {@link X509KeyManager#chooseClientAlias(String[], java.security.Principal[], java.net.Socket)}
     * and
     * {@link X509ExtendedKeyManager#chooseEngineClientAlias(String[], java.security.Principal[], javax.net.ssl.SSLEngine)}
     */
    interface AliasChooser {
        String chooseClientAlias(X509KeyManager keyManager, X500Principal[] issuers,
                String[] keyTypes);

        String chooseServerAlias(X509KeyManager keyManager, String keyType);
    }

    /**
     * For abstracting the {@code PSKKeyManager} calls between those taking an {@code SSLSocket} and
     * those taking an {@code SSLEngine}.
     */
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    interface PSKCallbacks {
        String chooseServerPSKIdentityHint(PSKKeyManager keyManager);
        String chooseClientPSKIdentity(PSKKeyManager keyManager, String identityHint);
        SecretKey getPSKKey(PSKKeyManager keyManager, String identityHint, String identity);
    }

    /**
     * Returns the clone of this object.
     * @return the clone.
     */
    @Override
    protected Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }

    SSLParametersImpl cloneWithTrustManager(X509TrustManager newTrustManager) {
        return new SSLParametersImpl(clientSessionContext, serverSessionContext,
            x509KeyManager, pskKeyManager, newTrustManager, this);
    }

    private static X509KeyManager getDefaultX509KeyManager() throws KeyManagementException {
        X509KeyManager result = defaultX509KeyManager;
        if (result == null) {
            // single-check idiom
            defaultX509KeyManager = result = createDefaultX509KeyManager();
        }
        return result;
    }
    private static X509KeyManager createDefaultX509KeyManager() throws KeyManagementException {
        try {
            String algorithm = KeyManagerFactory.getDefaultAlgorithm();
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
            kmf.init(null, null);
            KeyManager[] kms = kmf.getKeyManagers();
            X509KeyManager result = findFirstX509KeyManager(kms);
            if (result == null) {
                throw new KeyManagementException("No X509KeyManager among default KeyManagers: "
                        + Arrays.toString(kms));
            }
            return result;
        } catch (NoSuchAlgorithmException e) {
            throw new KeyManagementException(e);
        } catch (KeyStoreException e) {
            throw new KeyManagementException(e);
        } catch (UnrecoverableKeyException e) {
            throw new KeyManagementException(e);
        }
    }

    /**
     * Finds the first {@link X509KeyManager} element in the provided array.
     *
     * @return the first {@code X509KeyManager} or {@code null} if not found.
     */
    private static X509KeyManager findFirstX509KeyManager(KeyManager[] kms) {
        for (KeyManager km : kms) {
            if (km instanceof X509KeyManager) {
                return (X509KeyManager)km;
            }
        }
        return null;
    }

    /**
     * Finds the first {@link PSKKeyManager} element in the provided array.
     *
     * @return the first {@code PSKKeyManager} or {@code null} if not found.
     */
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    private static PSKKeyManager findFirstPSKKeyManager(KeyManager[] kms) {
        for (KeyManager km : kms) {
            if (km instanceof PSKKeyManager) {
                return (PSKKeyManager)km;
            } else if (km != null) {
                try {
                    return DuckTypedPSKKeyManager.getInstance(km);
                } catch (NoSuchMethodException ignored) {}
            }
        }
        return null;
    }

    /**
     * Gets the default X.509 trust manager.
     */
    static X509TrustManager getDefaultX509TrustManager()
            throws KeyManagementException {
        X509TrustManager result = defaultX509TrustManager;
        if (result == null) {
            // single-check idiom
            defaultX509TrustManager = result = createDefaultX509TrustManager();
        }
        return result;
    }

    private static X509TrustManager createDefaultX509TrustManager()
            throws KeyManagementException {
        try {
            String algorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
            tmf.init((KeyStore) null);
            TrustManager[] tms = tmf.getTrustManagers();
            X509TrustManager trustManager = findFirstX509TrustManager(tms);
            if (trustManager == null) {
                throw new KeyManagementException(
                        "No X509TrustManager in among default TrustManagers: "
                                + Arrays.toString(tms));
            }
            return trustManager;
        } catch (NoSuchAlgorithmException e) {
            throw new KeyManagementException(e);
        } catch (KeyStoreException e) {
            throw new KeyManagementException(e);
        }
    }

    /**
     * Finds the first {@link X509TrustManager} element in the provided array.
     *
     * @return the first {@code X509ExtendedTrustManager} or
     *         {@code X509TrustManager} or {@code null} if not found.
     */
    private static X509TrustManager findFirstX509TrustManager(TrustManager[] tms) {
        for (TrustManager tm : tms) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }
        return null;
    }

    String getEndpointIdentificationAlgorithm() {
        return endpointIdentificationAlgorithm;
    }

    void setEndpointIdentificationAlgorithm(String endpointIdentificationAlgorithm) {
        this.endpointIdentificationAlgorithm = endpointIdentificationAlgorithm;
    }

    boolean getUseCipherSuitesOrder() {
        return useCipherSuitesOrder;
    }

    Collection<SNIMatcher> getSNIMatchers() {
        if (sniMatchers == null) {
            return null;
        }
        return new ArrayList<>(sniMatchers);
    }

    void setSNIMatchers(Collection<SNIMatcher> sniMatchers) {
        this.sniMatchers = sniMatchers != null ? new ArrayList<>(sniMatchers) : null;
    }

    AlgorithmConstraints getAlgorithmConstraints() {
        return algorithmConstraints;
    }

    void setAlgorithmConstraints(AlgorithmConstraints algorithmConstraints) {
        this.algorithmConstraints = algorithmConstraints;
    }

    void setUseCipherSuitesOrder(boolean useCipherSuitesOrder) {
        this.useCipherSuitesOrder = useCipherSuitesOrder;
    }

    private static String[] getDefaultCipherSuites(
            boolean x509CipherSuitesNeeded,
            boolean pskCipherSuitesNeeded) {
        if (x509CipherSuitesNeeded) {
            // X.509 based cipher suites need to be listed.
            if (pskCipherSuitesNeeded) {
                // Both X.509 and PSK based cipher suites need to be listed. Because TLS-PSK is not
                // normally used, we assume that when PSK cipher suites are requested here they
                // should be preferred over other cipher suites. Thus, we give PSK cipher suites
                // higher priority than X.509 cipher suites.
                // NOTE: There are cipher suites that use both X.509 and PSK (e.g., those based on
                // RSA_PSK key exchange). However, these cipher suites are not currently supported.
                return SSLUtils.concat(
                        NativeCrypto.DEFAULT_PSK_CIPHER_SUITES,
                        NativeCrypto.DEFAULT_X509_CIPHER_SUITES,
                        new String[] {NativeCrypto.TLS_EMPTY_RENEGOTIATION_INFO_SCSV});
            } else {
                // Only X.509 cipher suites need to be listed.
                return SSLUtils.concat(
                        NativeCrypto.DEFAULT_X509_CIPHER_SUITES,
                        new String[] {NativeCrypto.TLS_EMPTY_RENEGOTIATION_INFO_SCSV});
            }
        } else if (pskCipherSuitesNeeded) {
            // Only PSK cipher suites need to be listed.
            return SSLUtils.concat(
                    NativeCrypto.DEFAULT_PSK_CIPHER_SUITES,
                    new String[] {NativeCrypto.TLS_EMPTY_RENEGOTIATION_INFO_SCSV});
        } else {
            // Neither X.509 nor PSK cipher suites need to be listed.
            return new String[] {NativeCrypto.TLS_EMPTY_RENEGOTIATION_INFO_SCSV};
        }
    }

    /**
     * Check if SCT verification is enforced for a given hostname.
     */
    boolean isCTVerificationEnabled(String hostname) {
        if (hostname == null) {
            return false;
        }

        // Bypass the check. This is used for testing only
        if (ctVerificationEnabled) {
            return true;
        }
        return Platform.isCTVerificationRequired(hostname);
    }
}
