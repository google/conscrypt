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

package org.apache.harmony.xnet.provider.jsse;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.net.ssl.X509TrustManager;

/**
 *
 * TrustManager implementation. The implementation is based on CertPathValidator
 * PKIX and CertificateFactory X509 implementations. This implementations should
 * be provided by some certification provider.
 *
 * @see javax.net.ssl.X509TrustManager
 */
public final class TrustManagerImpl implements X509TrustManager {

    /**
     * The AndroidCAStore if non-null, null otherwise
     */
    private final KeyStore rootKeyStore;

    private final CertPathValidator validator;

    private final IndexedPKIXParameters params;

    /**
     * This is lazily initialized in the AndroidCAStore case since it
     * forces us to bring all the CAs into memory. In the
     * non-AndroidCAStore, we initialize this as part of the
     * constructor.
     */
    private volatile X509Certificate[] acceptedIssuers;

    private final Exception err;
    private final CertificateFactory factory;

    public final IndexedPKIXParameters getIndexedPKIXParameters() {
        return params;
    }

    /**
     * Creates X509TrustManager based on a keystore
     *
     * @param ks
     */
    public TrustManagerImpl(KeyStore keyStore) {
        CertPathValidator validatorLocal = null;
        CertificateFactory factoryLocal = null;
        KeyStore rootKeyStoreLocal = null;
        IndexedPKIXParameters paramsLocal = null;
        X509Certificate[] acceptedIssuersLocal = null;
        Exception errLocal = null;
        try {
            validatorLocal = CertPathValidator.getInstance("PKIX");
            factoryLocal = CertificateFactory.getInstance("X509");

            Set<TrustAnchor> trustAnchors;
            // if we have an AndroidCAStore, we will lazily load CAs
            if ("AndroidCAStore".equals(keyStore.getType())) {
                rootKeyStoreLocal = keyStore;
                acceptedIssuersLocal = null;
                // Note we need to include at least one TrustAnchor
                // for the IndexedPKIXParameters super class to be happy.
                trustAnchors = trustAnchors(acceptedIssuers(keyStore, true));
            } else {
                rootKeyStoreLocal = null;
                acceptedIssuersLocal = acceptedIssuers(keyStore, false);
                trustAnchors = trustAnchors(acceptedIssuersLocal);
            }

            paramsLocal = new IndexedPKIXParameters(trustAnchors);
            paramsLocal.setRevocationEnabled(false);
        } catch (Exception e) {
            errLocal = e;
        }
        this.rootKeyStore = rootKeyStoreLocal;
        this.validator = validatorLocal;
        this.factory = factoryLocal;
        this.params = paramsLocal;
        this.acceptedIssuers = acceptedIssuersLocal;
        this.err = errLocal;
    }

    private static X509Certificate[] acceptedIssuers(KeyStore ks, boolean onlyOne)
            throws KeyStoreException {
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
                if (onlyOne) {
                    break;
                }
            }
        }
        return trusted.toArray(new X509Certificate[trusted.size()]);
    }

    private static Set<TrustAnchor> trustAnchors(X509Certificate[] certs) {
        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>(certs.length);
        for (X509Certificate cert : certs) {
            trustAnchors.add(new TrustAnchor(cert, null));
        }
        return trustAnchors;
    }

    @Override public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        checkTrusted(chain, authType);
    }

    @Override public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        checkTrusted(chain, authType);
    }

    private void checkTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        if (chain == null || chain.length == 0 || authType == null || authType.length() == 0) {
            throw new IllegalArgumentException("null or zero-length parameter");
        }
        if (err != null) {
            throw new CertificateException(err);
        }

        X509Certificate[] newChain = cleanupCertChain(chain);
        if (newChain.length == 0) {
            // chain was entirely trusted, skip the validator
            return;
        }

        if (rootKeyStore != null) {
            // check if we need to add a missing TrustAnchor value to
            // the IndexedPKIXParameters from the KeyStore
            optionallyAddTrustAnchorFromKeyStore(newChain[newChain.length-1]);
        }

        CertPath certPath = factory.generateCertPath(Arrays.asList(newChain));
        if (!Arrays.equals(chain[0].getEncoded(),
                           certPath.getCertificates().get(0).getEncoded())) {
            // Sanity check failed (shouldn't ever happen, but we
            // are using pretty remote code)
            throw new CertificateException("Certificate chain error");
        }
        try {
            validator.validate(certPath, params);
            // Add intermediate CAs to the index to tolerate sites
            // that assume that the browser will have cached these.
            // The server certificate is skipped by skipping the
            // zeroth element of new chain and note that the root CA
            // will have been removed in cleanupCertChain.
            // http://b/3404902
            for (int i = 1; i < newChain.length; i++) {
                index(newChain[i]);
            }
        } catch (InvalidAlgorithmParameterException e) {
            throw new CertificateException(e);
        } catch (CertPathValidatorException e) {
            throw new CertificateException(e);
        }
    }

    /**
     * Clean up the certificate chain, returning a cleaned up chain,
     * which may be a new array instance if elements were removed.
     * Theoretically, we shouldn't have to do this, but various web
     * servers in practice are mis-configured to have out-of-order
     * certificates, expired self-issued root certificate, or CAs with
     * unsupported signature algorithms such as
     * md2WithRSAEncryption. This also handles removing old certs
     * after bridge CA certs.
     */
    private X509Certificate[] cleanupCertChain(X509Certificate[] chain) {
        X509Certificate[] original = chain;

        // 1. Clean the received certificates chain.
        int currIndex;
        // Start with the first certificate in the chain, assuming it
        // is the leaf certificate (server or client cert).
        for (currIndex = 0; currIndex < chain.length; currIndex++) {
            // If the current cert is a TrustAnchor, we can ignore the rest of the chain.
            // This avoids including "bridge" CA certs that added for legacy compatability.
            if (isTrustAnchor(chain[currIndex])) {
                currIndex--;
                break;
            }
            // Walk the rest of the chain to find a "subject" matching
            // the "issuer" of the current certificate. In a properly
            // order chain this should be the next cert and be fast.
            // If not, we reorder things to be as the validator will
            // expect.
            boolean foundNext = false;
            for (int nextIndex = currIndex + 1; nextIndex < chain.length; nextIndex++) {
                if (chain[currIndex].getIssuerDN().equals(chain[nextIndex].getSubjectDN())) {
                    foundNext = true;
                    // Exchange certificates so that 0 through currIndex + 1 are in proper order
                    if (nextIndex != currIndex + 1) {
                        // don't mutuate original chain, which may be directly from an SSLSession
                        if (chain == original) {
                            chain = original.clone();
                        }
                        X509Certificate tempCertificate = chain[nextIndex];
                        chain[nextIndex] = chain[currIndex + 1];
                        chain[currIndex + 1] = tempCertificate;
                    }
                    break;
                }
            }
            // If we can't find the next in the chain, just give up
            // and use what we found so far. This drops unrelated
            // certificates that have nothing to do with the cert
            // chain.
            if (!foundNext) {
                break;
            }
        }

        // 2. If the chain is now shorter, copy to an appropriately sized array.
        int chainLength = currIndex + 1;
        if (chainLength == chain.length) {
            return chain;
        }
        return Arrays.copyOf(chain, chainLength);
    }

    private void optionallyAddTrustAnchorFromKeyStore(X509Certificate lastCert) {
        TrustAnchor trustAnchor;
        try {
            // returns null if no match based on issuer
            trustAnchor = params.findTrustAnchor(lastCert);
        } catch (CertPathValidatorException e) {
            // set to null if there seemed to be a match but
            // failed verification, we might have another CA to
            // discover with the same subject as one already known
            // to the IndexedPKIXParameters.
            trustAnchor = null;
        }
        if (trustAnchor == null) {
            // we have a KeyStore and the issuer of the last cert in
            // the chain seems to be missing from the
            // IndexedPKIXParameters, check the KeyStore for a hit
            X509Certificate issuer = RootKeyStoreSpi.findIssuer(lastCert);
            if (issuer != null) {
                index(issuer);
            }
        }
    }

    /**
     * Check the IndexedPKIXParameters for the cert to see if it is
     * already trusted and failing that check the KeyStore if it is
     * available.
     */
    private boolean isTrustAnchor(X509Certificate cert) {
        boolean isTrustAnchor = params.isTrustAnchor(cert);
        if (isTrustAnchor) {
            return true;
        }
        if (rootKeyStore == null) {
            // not trusted and no KeyStore to check
            return false;
        }
        // probe KeyStore for a cert. AndroidCAStore stores its
        // contents hashed by cert subject on the filesystem to make
        // this faster than scanning all key store entries.
        if (RootKeyStoreSpi.isTrustAnchor(cert)) {
            // add new TrustAnchor to params index to avoid
            // checking filesystem next time around.
            index(cert);
            return true;
        }
        return false;
    }

    /**
     * Add a new TrustAnchor to the IndexedPKIXParameters
     */
    private void index(X509Certificate cert) {
        params.index(new TrustAnchor(cert, null));
    }

    @Override public X509Certificate[] getAcceptedIssuers() {
        X509Certificate[] result = acceptedIssuers;
        if (result == null) {
            // single-check idiom
            try {
                acceptedIssuers = result = acceptedIssuers(rootKeyStore, false);
            } catch (KeyStoreException e) {
                acceptedIssuers = result = new X509Certificate[0];
            }
        }
        return acceptedIssuers.clone();
    }
}
