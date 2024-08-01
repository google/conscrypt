/*
 * Copyright (C) 2016 The Android Open Source Project
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

// License from Apache Harmony:
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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.PKIXRevocationChecker.Option;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;
import org.conscrypt.ct.LogStore;
import org.conscrypt.ct.Policy;
import org.conscrypt.ct.VerificationResult;
import org.conscrypt.ct.Verifier;

/**
 *
 * TrustManager implementation. The implementation is based on CertPathValidator
 * PKIX and CertificateFactory X509 implementations. This implementations should
 * be provided by some certification provider.
 *
 * @see javax.net.ssl.X509ExtendedTrustManager
 */
@Internal
public final class TrustManagerImpl extends X509ExtendedTrustManager {

    private static final Logger logger = Logger.getLogger(TrustManagerImpl.class.getName());

    /**
     * Comparator used for ordering trust anchors during certificate path building.
     */
    private static final TrustAnchorComparator TRUST_ANCHOR_COMPARATOR =
            new TrustAnchorComparator();

    private static final Set<Option> REVOCATION_CHECK_OPTIONS =
            revocationOptions();

    private static ConscryptHostnameVerifier defaultHostnameVerifier;

    /**
     * The AndroidCAStore if non-null, null otherwise.
     */
    private final KeyStore rootKeyStore;

    /**
     * The CertPinManager, which validates the chain against a host-to-pin mapping
     */
    private CertPinManager pinManager;

    /**
     * The backing store for the AndroidCAStore if non-null. This will
     * be null when the rootKeyStore is null, implying we are not
     * using the AndroidCAStore.
     */
    private final ConscryptCertStore trustedCertificateStore;

    private final CertPathValidator validator;

    /**
     * An index of TrustAnchor instances that we've seen.
     */
    private final TrustedCertificateIndex trustedCertificateIndex;

    /**
     * An index of intermediate certificates that we've seen. These certificates are NOT implicitly
     * trusted and must still form a valid chain to an anchor.
     */
    private final TrustedCertificateIndex intermediateIndex;

    /**
     * This is lazily initialized in the AndroidCAStore case since it
     * forces us to bring all the CAs into memory. In the
     * non-AndroidCAStore, we initialize this as part of the
     * constructor.
     */
    private final X509Certificate[] acceptedIssuers;

    private final Exception err;
    private final CertificateFactory factory;
    private final CertBlocklist blocklist;
    private Verifier ctVerifier;
    private Policy ctPolicy;

    private ConscryptHostnameVerifier hostnameVerifier;

    // Forces CT verification to always to done. For tests.
    private boolean ctEnabledOverride;

    /**
     * Creates X509TrustManager based on a keystore
     */
    public TrustManagerImpl(KeyStore keyStore) {
        this(keyStore, null);
    }

    public TrustManagerImpl(KeyStore keyStore, CertPinManager manager) {
        this(keyStore, manager, null);
    }

    public TrustManagerImpl(KeyStore keyStore, CertPinManager manager,
            ConscryptCertStore certStore) {
        this(keyStore, manager, certStore, null);
    }

    public TrustManagerImpl(KeyStore keyStore, CertPinManager manager, ConscryptCertStore certStore,
            CertBlocklist blocklist) {
        this(keyStore, manager, certStore, blocklist, null, null, null);
    }

    /**
     * For testing only.
     */
    public TrustManagerImpl(KeyStore keyStore, CertPinManager manager, ConscryptCertStore certStore,
            CertBlocklist blocklist, LogStore ctLogStore, Verifier ctVerifier, Policy ctPolicy) {
        CertPathValidator validatorLocal = null;
        CertificateFactory factoryLocal = null;
        KeyStore rootKeyStoreLocal = null;
        ConscryptCertStore trustedCertificateStoreLocal = null;
        TrustedCertificateIndex trustedCertificateIndexLocal = null;
        X509Certificate[] acceptedIssuersLocal = null;
        Exception errLocal = null;
        try {
            validatorLocal = CertPathValidator.getInstance("PKIX");
            factoryLocal = CertificateFactory.getInstance("X509");

            // if we have an AndroidCAStore, we will lazily load CAs
            if ("AndroidCAStore".equals(keyStore.getType())
                    && Platform.supportsConscryptCertStore()) {
                rootKeyStoreLocal = keyStore;
                trustedCertificateStoreLocal =
                    (certStore != null) ? certStore : Platform.newDefaultCertStore();
                acceptedIssuersLocal = null;
                trustedCertificateIndexLocal = new TrustedCertificateIndex();
            } else {
                rootKeyStoreLocal = null;
                trustedCertificateStoreLocal = certStore;
                acceptedIssuersLocal = acceptedIssuers(keyStore);
                trustedCertificateIndexLocal
                        = new TrustedCertificateIndex(trustAnchors(acceptedIssuersLocal));
            }

        } catch (Exception e) {
            errLocal = e;
        }

        if (blocklist == null) {
            blocklist = Platform.newDefaultBlocklist();
        }
        if (ctLogStore == null) {
            ctLogStore = Platform.newDefaultLogStore();
        }

        if (ctPolicy == null) {
            ctPolicy = Platform.newDefaultPolicy(ctLogStore);
        }

        this.pinManager = manager;
        this.rootKeyStore = rootKeyStoreLocal;
        this.trustedCertificateStore = trustedCertificateStoreLocal;
        this.validator = validatorLocal;
        this.factory = factoryLocal;
        this.trustedCertificateIndex = trustedCertificateIndexLocal;
        this.intermediateIndex = new TrustedCertificateIndex();
        this.acceptedIssuers = acceptedIssuersLocal;
        this.err = errLocal;
        this.blocklist = blocklist;
        this.ctVerifier = new Verifier(ctLogStore);
        this.ctPolicy = ctPolicy;
    }

    @SuppressWarnings("JdkObsolete")  // KeyStore#aliases is the only API available
    private static X509Certificate[] acceptedIssuers(KeyStore ks) {
        try {
            // Note that unlike the PKIXParameters code to create a Set of
            // TrustAnchors from a KeyStore, this version takes from both
            // TrustedCertificateEntry and PrivateKeyEntry, not just
            // TrustedCertificateEntry, which is why TrustManagerImpl
            // cannot just use an PKIXParameters(KeyStore)
            // constructor.

            // TODO remove duplicates if same cert is found in both a
            // PrivateKeyEntry and TrustedCertificateEntry
            List<X509Certificate> trusted = new ArrayList<X509Certificate>();
            for (Enumeration<String> en = ks.aliases(); en.hasMoreElements();) {
                final String alias = en.nextElement();
                final X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                if (cert != null) {
                    trusted.add(cert);
                }
            }
            return trusted.toArray(new X509Certificate[trusted.size()]);
        } catch (KeyStoreException e) {
            return new X509Certificate[0];
        }
    }

    private static Set<TrustAnchor> trustAnchors(X509Certificate[] certs) {
        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>(certs.length);
        for (X509Certificate cert : certs) {
            trustAnchors.add(new TrustAnchor(cert, null));
        }
        return trustAnchors;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        checkTrusted(chain, authType, null, null, true /* client auth */);
    }

    /**
     * For backward compatibility with older Android API that used String for the hostname only.
     */
    public List<X509Certificate> checkClientTrusted(X509Certificate[] chain, String authType,
            String hostname) throws CertificateException {
        return checkTrusted(chain, null /* ocspData */, null /* tlsSctData */, authType, hostname,
                true);
    }

    private static SSLSession getHandshakeSessionOrThrow(SSLSocket sslSocket)
            throws CertificateException {
        SSLSession session = sslSocket.getHandshakeSession();
        if (session == null) {
            throw new CertificateException("Not in handshake; no session available");
        }
        return session;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        SSLSession session = null;
        SSLParameters parameters = null;
        if (socket instanceof SSLSocket) {
            SSLSocket sslSocket = (SSLSocket) socket;
            session = getHandshakeSessionOrThrow(sslSocket);
            parameters = sslSocket.getSSLParameters();
        }
        checkTrusted(chain, authType, session, parameters, true /* client auth */);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        SSLSession session = engine.getHandshakeSession();
        if (session == null) {
            throw new CertificateException("Not in handshake; no session available");
        }
        checkTrusted(chain, authType, session, engine.getSSLParameters(), true /* client auth */);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        checkTrusted(chain, authType, null, null, false /* client auth */);
    }

    /**
     * For backward compatibility with older Android API that used String for the hostname only.
     */
    public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType,
            String hostname) throws CertificateException {
        return checkTrusted(chain, null /* ocspData */, null /* tlsSctData */, authType, hostname,
                false);
    }

    /**
     * Returns the full trusted certificate chain found from {@code certs}.
     *
     * Throws {@link CertificateException} when no trusted chain can be found from {@code certs}.
     */
    public List<X509Certificate> getTrustedChainForServer(X509Certificate[] certs,
            String authType, Socket socket) throws CertificateException {
        SSLSession session = null;
        SSLParameters parameters = null;
        if (socket instanceof SSLSocket) {
            SSLSocket sslSocket = (SSLSocket) socket;
            session = getHandshakeSessionOrThrow(sslSocket);
            parameters = sslSocket.getSSLParameters();
        }
        return checkTrusted(certs, authType, session, parameters, false /* client auth */);
    }

    /**
     * Returns the full trusted certificate chain found from {@code certs}.
     *
     * Throws {@link CertificateException} when no trusted chain can be found from {@code certs}.
     */
    public List<X509Certificate> getTrustedChainForServer(X509Certificate[] certs,
            String authType, SSLEngine engine) throws CertificateException {
        SSLSession session = engine.getHandshakeSession();
        if (session == null) {
            throw new CertificateException("Not in handshake; no session available");
        }
        return checkTrusted(certs, authType, session, engine.getSSLParameters(),
                false /* client auth */);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        getTrustedChainForServer(chain, authType, socket);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        getTrustedChainForServer(chain, authType, engine);
    }

    /**
     * Validates whether a server is trusted. If session is given and non-null
     * it also checks if chain is pinned appropriately for that peer host. If
     * null, it does not check for pinned certs. The return value is a list of
     * the certificates used for making the trust decision.
     */
    public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType,
            SSLSession session) throws CertificateException {
        return checkTrusted(chain, authType, session, null, false /* client auth */);
    }

    public void handleTrustStorageUpdate() {
        if (acceptedIssuers == null) {
            trustedCertificateIndex.reset();
        } else {
            trustedCertificateIndex.reset(trustAnchors(acceptedIssuers));
        }
    }

    private List<X509Certificate> checkTrusted(X509Certificate[] certs, String authType,
            SSLSession session, SSLParameters parameters, boolean clientAuth)
                    throws CertificateException {
        byte[] ocspData = null;
        byte[] tlsSctData = null;
        String hostname = null;
        if (session != null) {
            hostname = session.getPeerHost();
            ocspData = getOcspDataFromSession(session);
            tlsSctData = getTlsSctDataFromSession(session);
        }

        if (session != null && parameters != null) {
            String identificationAlgorithm = parameters.getEndpointIdentificationAlgorithm();
            if ("HTTPS".equalsIgnoreCase(identificationAlgorithm)) {
                ConscryptHostnameVerifier verifier = getHttpsVerifier();
                if (!verifier.verify(certs, hostname, session)) {
                    throw new CertificateException("No subjectAltNames on the certificate match");
                }
            }
        }
        return checkTrusted(certs, ocspData, tlsSctData, authType, hostname, clientAuth);
    }

    @SuppressWarnings("unchecked")
    private static byte[] getOcspDataFromSession(SSLSession session) {
        List<byte[]> ocspResponses = null;
        if (session instanceof ConscryptSession) {
            ConscryptSession opensslSession = (ConscryptSession) session;
            ocspResponses = opensslSession.getStatusResponses();
        } else {
            Method m_getResponses;
            try {
                m_getResponses = session.getClass().getDeclaredMethod("getStatusResponses");
                m_getResponses.setAccessible(true);
                Object rawResponses = m_getResponses.invoke(session);
                if (rawResponses instanceof List) {
                    ocspResponses = (List<byte[]>) rawResponses;
                }
            } catch (NoSuchMethodException | SecurityException
                    | IllegalAccessException | IllegalArgumentException ignored) {
                // Method not available, fall through and return null
            } catch (InvocationTargetException e) {
                throw new RuntimeException(e.getCause());
            }
        }

        if (ocspResponses == null || ocspResponses.isEmpty()) {
            return null;
        }

        return ocspResponses.get(0);
    }

    private byte[] getTlsSctDataFromSession(SSLSession session) {
        if (session instanceof ConscryptSession) {
            ConscryptSession opensslSession = (ConscryptSession) session;
            return opensslSession.getPeerSignedCertificateTimestamp();
        }

        byte[] data = null;
        try {
            Method m_getTlsSctData = session.getClass().getDeclaredMethod("getPeerSignedCertificateTimestamp");
            m_getTlsSctData.setAccessible(true);
            Object rawData = m_getTlsSctData.invoke(session);
            if (rawData instanceof byte[]) {
                data = (byte[]) rawData;
            }
        } catch (NoSuchMethodException | SecurityException
                | IllegalAccessException | IllegalArgumentException ignored) {
            // Method not available, fall through and return null
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e.getCause());
        }
        return data;
    }

    private List<X509Certificate> checkTrusted(X509Certificate[] certs, byte[] ocspData,
            byte[] tlsSctData, String authType, String host, boolean clientAuth)
            throws CertificateException {
        if (certs == null || certs.length == 0 || authType == null || authType.length() == 0) {
            throw new IllegalArgumentException("null or zero-length parameter");
        }
        if (err != null) {
            throw new CertificateException(err);
        }
        Set<X509Certificate> used = new HashSet<X509Certificate>();
        ArrayList<X509Certificate> untrustedChain = new ArrayList<X509Certificate>();
        ArrayList<TrustAnchor> trustedChain = new ArrayList<TrustAnchor>();
        // Initialize the chain to contain the leaf certificate. This potentially could be a trust
        // anchor. If the leaf is a trust anchor we still continue with path building to build the
        // complete trusted chain for additional validation such as certificate pinning.
        X509Certificate leaf = certs[0];
        TrustAnchor leafAsAnchor = findTrustAnchorBySubjectAndPublicKey(leaf);
        if (leafAsAnchor != null) {
            trustedChain.add(leafAsAnchor);
            used.add(leafAsAnchor.getTrustedCert());
        } else {
            untrustedChain.add(leaf);
        }
        used.add(leaf);
        return checkTrustedRecursive(certs, ocspData, tlsSctData, host, clientAuth,
                untrustedChain, trustedChain, used);
    }

    /**
     * Recursively build certificate chains until a valid chain is found or all possible paths are
     * exhausted.
     *
     * The chain is built in two sections, the complete trusted path is the the combination of
     * {@code untrustedChain} and {@code trustAnchorChain}. The chain begins at the leaf
     * certificate and ends in the final trusted root certificate.
     *
     * @param certs the bag of certs provided by the peer. No order is assumed.
     * @param host the host being connected to.
     * @param clientAuth if a client is being authorized instead of a server.
     * @param untrustedChain the untrusted section of the chain built so far. Must be mutable.
     * @param trustAnchorChain the trusted section of the chain built so far. Must be mutable.
     * @param used the set certificates used so far in path building. Must be mutable.
     *
     * @return The entire valid chain starting with the leaf certificate. This is the
     * concatenation of untrustedChain and trustAnchorChain.
     *
     * @throws CertificateException If no valid chain could be constructed. Note that there may be
     * multiple reasons why no valid chain exists and there is no guarantee that the most severe is
     * reported in this exception. As such applications MUST NOT use the specifics of this error
     * for trust decisions (e.g. showing the user a click through page based on the specific error).
     */
    private List<X509Certificate> checkTrustedRecursive(X509Certificate[] certs, byte[] ocspData,
            byte[] tlsSctData, String host, boolean clientAuth,
            ArrayList<X509Certificate> untrustedChain, ArrayList<TrustAnchor> trustAnchorChain,
            Set<X509Certificate> used) throws CertificateException {
        CertificateException lastException = null;
        X509Certificate current;
        if (trustAnchorChain.isEmpty()) {
            current = untrustedChain.get(untrustedChain.size() - 1);
        } else {
            current = trustAnchorChain.get(trustAnchorChain.size() - 1).getTrustedCert();
        }

        // Check that the certificate isn't blocklisted.
        checkBlocklist(current);

        // 1. If the current certificate in the chain is self-signed verify the chain as is.
        if (current.getIssuerDN().equals(current.getSubjectDN())) {
            return verifyChain(untrustedChain, trustAnchorChain, host, clientAuth, ocspData,
                    tlsSctData);
        }

        // 2. Try building a chain via any trust anchors that issued the current certificate.
        // Note that we do not stop at the first trust anchor since it is possible that the trust
        // anchor is not self-signed and its issuer may be needed for additional validation such as
        // certificate pinning. In the common case the first trust anchor will be self-signed or
        // its issuer's certificate will be missing.
        Set<TrustAnchor> anchors = findAllTrustAnchorsByIssuerAndSignature(current);
        boolean seenIssuer = false;
        for (TrustAnchor anchor : sortPotentialAnchors(anchors)) {
            X509Certificate anchorCert = anchor.getTrustedCert();
            // Avoid using certificates that have already been used.
            if (used.contains(anchorCert)) {
                continue;
            }
            seenIssuer = true;
            used.add(anchorCert);
            trustAnchorChain.add(anchor);
            try {
                return checkTrustedRecursive(certs, ocspData, tlsSctData, host, clientAuth,
                        untrustedChain, trustAnchorChain, used);
            } catch (CertificateException ex) {
                lastException = ex;
            }
            // Could not form a valid chain via this certificate, remove it from this chain.
            trustAnchorChain.remove(trustAnchorChain.size() - 1);
            used.remove(anchorCert);
        }

        // 3. If we were unable to find additional trusted issuers, verify the current chain.
        // This may happen if the root of trust is not self-signed and the issuer is not
        // present in the trusted set.
        if (!trustAnchorChain.isEmpty()) {
            if (!seenIssuer) {
                return verifyChain(untrustedChain, trustAnchorChain, host, clientAuth, ocspData,
                        tlsSctData);
            }

            // Otherwise all chains based on the current trust anchor were rejected, fail.
            throw lastException;
        }

        // 4. Use the certificates provided by the peer to grow the chain.
        // Ignore the first certificate, as that is the leaf certificate.
        for (int i = 1; i < certs.length; i++) {
            X509Certificate candidateIssuer = certs[i];
            // Avoid using certificates that have already been used.
            if (used.contains(candidateIssuer)) {
                continue;
            }
            if (current.getIssuerDN().equals(candidateIssuer.getSubjectDN())) {
                // Check the strength and validity of the certificate to prune bad certificates
                // early.
                try {
                    candidateIssuer.checkValidity();
                    ChainStrengthAnalyzer.checkCert(candidateIssuer);
                } catch (CertificateException ex) {
                    lastException = new CertificateException("Unacceptable certificate: "
                            + candidateIssuer.getSubjectX500Principal(), ex);
                    continue;
                }
                used.add(candidateIssuer);
                untrustedChain.add(candidateIssuer);
                try {
                    return checkTrustedRecursive(certs, ocspData, tlsSctData, host, clientAuth,
                            untrustedChain, trustAnchorChain, used);
                } catch (CertificateException ex) {
                    lastException = ex;
                }
                // Could not form a valid chain via this certificate, remove it from this chain.
                used.remove(candidateIssuer);
                untrustedChain.remove(untrustedChain.size() - 1);
            }
        }

        // 5. Finally try the cached intermediates to handle server that failed to send them.
        Set<TrustAnchor> intermediateAnchors =
                intermediateIndex.findAllByIssuerAndSignature(current);
        for (TrustAnchor intermediate : sortPotentialAnchors(intermediateAnchors)) {
            X509Certificate intermediateCert = intermediate.getTrustedCert();
            // Avoid using certificates that have already been used.
            if (used.contains(intermediateCert)) {
                continue;
            }
            used.add(intermediateCert);
            untrustedChain.add(intermediateCert);
            try {
                return checkTrustedRecursive(certs, ocspData, tlsSctData, host, clientAuth,
                        untrustedChain, trustAnchorChain, used);
            } catch (CertificateException ex) {
                lastException = ex;
            }
            // Could not form a valid chain via this certificate, remove it from this chain.
            untrustedChain.remove(untrustedChain.size() - 1);
            used.remove(intermediateCert);
        }

        // 6. We were unable to build a valid chain, throw the last error encountered.
        if (lastException != null) {
            throw lastException;
        }

        // 7. If no errors were encountered above then verifyChain was never called because it was
        // not possible to build a valid chain to a trusted certificate.
        CertPath certPath = factory.generateCertPath(untrustedChain);
        throw new CertificateException(new CertPathValidatorException(
                "Trust anchor for certification path not found.", null, certPath, -1));
    }

    private List<X509Certificate> verifyChain(List<X509Certificate> untrustedChain,
            List<TrustAnchor> trustAnchorChain, String host, boolean clientAuth, byte[] ocspData,
            byte[] tlsSctData)
            throws CertificateException {
        try {
            // build the cert path from the list of certs sans trust anchors
            // TODO: check whether this is slow and should be replaced by a minimalistic CertPath impl
            // since we already have built the path.
            CertPath certPath = factory.generateCertPath(untrustedChain);

            // Check that there are at least some trust anchors
            if (trustAnchorChain.isEmpty()) {
                throw new CertificateException(new CertPathValidatorException(
                        "Trust anchor for certification path not found.", null, certPath, -1));
            }

            List<X509Certificate> wholeChain = new ArrayList<X509Certificate>();
            wholeChain.addAll(untrustedChain);
            for (TrustAnchor anchor : trustAnchorChain) {
                wholeChain.add(anchor.getTrustedCert());
            }

            if (pinManager != null) {
                pinManager.checkChainPinning(host, wholeChain);
            }
            // Check whole chain against the blocklist
            for (X509Certificate cert : wholeChain) {
                checkBlocklist(cert);
            }

            // Check CT (if required).
            if (!clientAuth &&
                    (ctEnabledOverride || (host != null && Platform
                            .isCTVerificationRequired(host)))) {
                checkCT(host, wholeChain, ocspData, tlsSctData);
            }

            if (untrustedChain.isEmpty()) {
                // The chain consists of only trust anchors, skip the validator
                return wholeChain;
            }

            ChainStrengthAnalyzer.check(untrustedChain);

            // Validate the untrusted part of the chain
            try {
                Set<TrustAnchor> anchorSet = new HashSet<TrustAnchor>();
                // We know that untrusted chains to the first trust anchor, only add that.
                anchorSet.add(trustAnchorChain.get(0));
                PKIXParameters params = new PKIXParameters(anchorSet);
                params.setRevocationEnabled(false);
                X509Certificate endPointCert = untrustedChain.get(0);
                setOcspResponses(params, endPointCert, ocspData);
                params.addCertPathChecker(
                        new ExtendedKeyUsagePKIXCertPathChecker(clientAuth, endPointCert));
                validator.validate(certPath, params);
            } catch (InvalidAlgorithmParameterException e) {
                throw new CertificateException("Chain validation failed", e);
            } catch (CertPathValidatorException e) {
                throw new CertificateException("Chain validation failed", e);
            }
            // Add intermediate CAs to the index to tolerate sites
            // that assume that the browser will have cached these.
            // http://b/3404902
            for (int i = 1; i < untrustedChain.size(); i++) {
                intermediateIndex.index(untrustedChain.get(i));
            }
            return wholeChain;
        } catch (CertificateException e) {
            logger.fine("Rejected candidate cert chain due to error: " + e.getMessage());
            throw e;
        }
    }

    private void checkBlocklist(X509Certificate cert) throws CertificateException {
        if (blocklist != null && blocklist.isPublicKeyBlockListed(cert.getPublicKey())) {
            throw new CertificateException("Certificate blocklisted by public key: " + cert);
        }
    }

    private void checkCT(String host, List<X509Certificate> chain, byte[] ocspData, byte[] tlsData)
            throws CertificateException {
        VerificationResult result =
                ctVerifier.verifySignedCertificateTimestamps(chain, tlsData, ocspData);

        if (!ctPolicy.doesResultConformToPolicy(result, host,
                    chain.toArray(new X509Certificate[chain.size()]))) {
            throw new CertificateException(
                    "Certificate chain does not conform to required transparency policy.");
        }
    }

    /**
     * Sets the OCSP response data that was possibly stapled to the TLS response.
     */
    private void setOcspResponses(PKIXParameters params, X509Certificate cert, byte[] ocspData) {
        if (ocspData == null) {
            return;
        }

        PKIXRevocationChecker revChecker = null;
        List<PKIXCertPathChecker> checkers =
                new ArrayList<PKIXCertPathChecker>(params.getCertPathCheckers());
        for (PKIXCertPathChecker checker : checkers) {
            if (checker instanceof PKIXRevocationChecker) {
                revChecker = (PKIXRevocationChecker) checker;
                break;
            }
        }

        if (revChecker == null) {
            // Only new CertPathValidatorSpi instances will support the
            // revocation checker API.
            try {
                revChecker = (PKIXRevocationChecker) validator.getRevocationChecker();
            } catch (UnsupportedOperationException e) {
                return;
            }

            checkers.add(revChecker);

            /*
             * If we add a new revocation checker, we should set the option for
             * end-entity verification only. Otherwise the CertPathValidator will
             * throw an exception when it can't verify the entire chain. We
             * also set the option to prevent falling back from OCSP to CRL download.
             */
            revChecker.setOptions(REVOCATION_CHECK_OPTIONS);
        }

        revChecker.setOcspResponses(Collections.singletonMap(cert, ocspData));
        params.setCertPathCheckers(checkers);
    }

    /**
     * Sort potential anchors so that the most preferred for use come first.
     *
     * @see CertificatePriorityComparator
     */
    private static Collection<TrustAnchor> sortPotentialAnchors(Set<TrustAnchor> anchors) {
        if (anchors.size() <= 1) {
            return anchors;
        }
        List<TrustAnchor> sortedAnchors = new ArrayList<TrustAnchor>(anchors);
        Collections.sort(sortedAnchors, TRUST_ANCHOR_COMPARATOR);
        return sortedAnchors;
    }


    /**
     * Comparator for sorting {@link TrustAnchor}s using a {@link CertificatePriorityComparator}.
     */
    private static class TrustAnchorComparator implements Comparator<TrustAnchor> {
        private static final CertificatePriorityComparator CERT_COMPARATOR =
                new CertificatePriorityComparator();
        @Override
        public int compare(TrustAnchor lhs, TrustAnchor rhs) {
            X509Certificate lhsCert = lhs.getTrustedCert();
            X509Certificate rhsCert = rhs.getTrustedCert();
            return CERT_COMPARATOR.compare(lhsCert, rhsCert);
        }
    }

    private static Set<Option> revocationOptions() {
        Set<Option> options = new HashSet<>();
        options.add(Option.ONLY_END_ENTITY); // Only check end entity
        options.add(Option.NO_FALLBACK);     // Don't fall back from OCSP to CRL download
        return Collections.unmodifiableSet(options);
    }

    /**
     * If an EKU extension is present in the end-entity certificate,
     * it MUST contain an appropriate key usage. For servers, this
     * includes anyExtendedKeyUsage, serverAuth, or the historical
     * Server Gated Cryptography options of nsSGC or msSGC.  For
     * clients, this includes anyExtendedKeyUsage and clientAuth.
     */
    private static class ExtendedKeyUsagePKIXCertPathChecker extends PKIXCertPathChecker {

        private static final String EKU_OID = "2.5.29.37";

        private static final String EKU_anyExtendedKeyUsage = "2.5.29.37.0";
        private static final String EKU_clientAuth = "1.3.6.1.5.5.7.3.2";
        private static final String EKU_serverAuth = "1.3.6.1.5.5.7.3.1";
        private static final String EKU_nsSGC = "2.16.840.1.113730.4.1";
        private static final String EKU_msSGC = "1.3.6.1.4.1.311.10.3.3";

        private static final Set<String> SUPPORTED_EXTENSIONS
                = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(EKU_OID)));

        private final boolean clientAuth;
        private final X509Certificate leaf;

        private ExtendedKeyUsagePKIXCertPathChecker(boolean clientAuth, X509Certificate leaf) {
            this.clientAuth = clientAuth;
            this.leaf = leaf;
        }

        @Override
        public void init(boolean forward) throws CertPathValidatorException {
        }

        @Override
        public boolean isForwardCheckingSupported() {
            return true;
        }

        @Override
        public Set<String> getSupportedExtensions() {
            return SUPPORTED_EXTENSIONS;
        }

        @SuppressWarnings("ReferenceEquality")
        @Override
        public void check(Certificate c, Collection<String> unresolvedCritExts)
                throws CertPathValidatorException {
            // We only want to validate the EKU on the leaf certificate.
            if (c != leaf) {
                return;
            }
            List<String> ekuOids;
            try {
                ekuOids = leaf.getExtendedKeyUsage();
            } catch (CertificateParsingException e) {
                // A malformed EKU is bad news, consider it fatal.
                throw new CertPathValidatorException(e);
            }
            // We are here to check EKU, but there is none.
            if (ekuOids == null) {
                return;
            }

            boolean goodExtendedKeyUsage = false;
            for (String ekuOid : ekuOids) {
                // anyExtendedKeyUsage for clients and servers
                if (ekuOid.equals(EKU_anyExtendedKeyUsage)) {
                    goodExtendedKeyUsage = true;
                    break;
                }

                // clients
                if (clientAuth) {
                    if (ekuOid.equals(EKU_clientAuth)) {
                        goodExtendedKeyUsage = true;
                        break;
                    }
                    continue;
                }

                // servers
                if (ekuOid.equals(EKU_serverAuth)) {
                    goodExtendedKeyUsage = true;
                    break;
                }
                if (ekuOid.equals(EKU_nsSGC)) {
                    goodExtendedKeyUsage = true;
                    break;
                }
                if (ekuOid.equals(EKU_msSGC)) {
                    goodExtendedKeyUsage = true;
                    break;
                }
            }
            if (goodExtendedKeyUsage) {
                // Mark extendedKeyUsage as resolved if present.
                unresolvedCritExts.remove(EKU_OID);
            } else {
                throw new CertPathValidatorException("End-entity certificate does not have a valid "
                                                     + "extendedKeyUsage.");
            }
        }
    }

    /**
     * Find all possible issuing trust anchors of {@code cert}.
     */
    private Set<TrustAnchor> findAllTrustAnchorsByIssuerAndSignature(X509Certificate cert) {
        Set<TrustAnchor> indexedAnchors =
                trustedCertificateIndex.findAllByIssuerAndSignature(cert);
        if (!indexedAnchors.isEmpty() || trustedCertificateStore == null) {
            return indexedAnchors;
        }
        Set<X509Certificate> storeAnchors = trustedCertificateStore.findAllIssuers(cert);
        if (storeAnchors.isEmpty()) {
            return indexedAnchors;
        }
        Set<TrustAnchor> result = new HashSet<TrustAnchor>(storeAnchors.size());
        for (X509Certificate storeCert : storeAnchors) {
            result.add(trustedCertificateIndex.index(storeCert));
        }
        return result;
    }

    /**
     * Check the trustedCertificateIndex for the cert to see if it is
     * already trusted and failing that check the KeyStore if it is
     * available.
     */
    private TrustAnchor findTrustAnchorBySubjectAndPublicKey(X509Certificate cert) {
        TrustAnchor trustAnchor = trustedCertificateIndex.findBySubjectAndPublicKey(cert);
        if (trustAnchor != null) {
            return trustAnchor;
        }
        if (trustedCertificateStore == null) {
            // not trusted and no TrustedCertificateStore to check.
            return null;
        }
        // probe KeyStore for a cert. AndroidCAStore stores its
        // contents hashed by cert subject on the filesystem to make
        // this faster than scanning all key store entries.
        X509Certificate systemCert = trustedCertificateStore.getTrustAnchor(cert);
        if (systemCert != null) {
            // Don't index the system certificate here, that way the only place that adds anchors to
            // the index are findAllTrustAnchorsByIssuerAndSignature.
            // This allows findAllTrustAnchorsByIssuerAndSignature to avoid checking the
            // TrustedCertificateStore if the TrustedCertificateIndex contains any issuers for the
            // certificate because it will have cached all certificates contained in the
            // TrustedCertificateStore.
            return new TrustAnchor(systemCert, null);
        }
        return null;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return (acceptedIssuers != null) ? acceptedIssuers.clone() : acceptedIssuers(rootKeyStore);
    }

    /**
     * Set the default hostname verifier that will be used for HTTPS endpoint identification.  If
     * {@code null} (the default), endpoint identification will use the default hostname verifier
     * set in {@link HttpsURLConnection#setDefaultHostnameVerifier(javax.net.ssl.HostnameVerifier)}.
     */
    synchronized static void setDefaultHostnameVerifier(ConscryptHostnameVerifier verifier) {
        defaultHostnameVerifier = verifier;
    }

    /**
     * Returns the currently-set default hostname verifier.
     *
     * @see #setDefaultHostnameVerifier(ConscryptHostnameVerifier)
     */
    synchronized static ConscryptHostnameVerifier getDefaultHostnameVerifier() {
        return defaultHostnameVerifier;
    }

    /**
     * Set the hostname verifier that will be used for HTTPS endpoint identification.  If
     * {@code null} (the default), endpoint identification will use the default hostname verifier
     * set in {@link #setDefaultHostnameVerifier(ConscryptHostnameVerifier)}.
     */
    void setHostnameVerifier(ConscryptHostnameVerifier verifier) {
        this.hostnameVerifier = verifier;
    }

    /**
     * Returns the currently-set hostname verifier for this instance.
     *
     * @see #setHostnameVerifier(ConscryptHostnameVerifier)
     */
    ConscryptHostnameVerifier getHostnameVerifier() {
        return hostnameVerifier;
    }

    private ConscryptHostnameVerifier getHttpsVerifier() {
        if (hostnameVerifier != null) {
            return hostnameVerifier;
        }
        if (defaultHostnameVerifier != null) {
            return defaultHostnameVerifier;
        }
        return Platform.getDefaultHostnameVerifier();
    }

    public void setCTEnabledOverride(boolean enabled) {
        this.ctEnabledOverride = enabled;
    }

    // Replace the CTVerifier. For testing only.
    public void setCTVerifier(Verifier verifier) {
        this.ctVerifier = verifier;
    }

    // Replace the CTPolicy. For testing only.
    public void setCTPolicy(Policy policy) {
        this.ctPolicy = policy;
    }
}
