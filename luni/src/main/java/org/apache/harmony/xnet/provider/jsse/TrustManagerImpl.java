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
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
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
public class TrustManagerImpl implements X509TrustManager {

    private final CertPathValidator validator;

    private final PKIXParameters params;

    private final Exception err;

    private final CertificateFactory factory;

    /**
     * Creates trust manager implementation
     *
     * @param ks
     */
    public TrustManagerImpl(KeyStore ks) {
        CertPathValidator validatorLocal = null;
        CertificateFactory factoryLocal = null;
        PKIXParameters paramsLocal = null;
        Exception errLocal = null;
        try {
            validatorLocal = CertPathValidator.getInstance("PKIX");
            factoryLocal = CertificateFactory.getInstance("X509");
            paramsLocal = new IndexedPKIXParameters(ks);
            paramsLocal.setRevocationEnabled(false);
        } catch (Exception e) {
            errLocal = e;
        }
        this.validator = validatorLocal;
        this.factory = factoryLocal;
        this.params = paramsLocal;
        this.err = errLocal;
    }

    /**
     * @see javax.net.ssl.X509TrustManager#checkClientTrusted(X509Certificate[],
     *      String)
     */
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        checkTrusted(chain, authType);
    }

    /**
     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(X509Certificate[],
     *      String)
     */
    public void checkServerTrusted(X509Certificate[] chain, String authType)
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
        CertPath certPath = factory.generateCertPath(Arrays.asList(newChain));
        if (!Arrays.equals(chain[0].getEncoded(),
                           certPath.getCertificates().get(0).getEncoded())) {
            // Sanity check failed (shouldn't ever happen, but we
            // are using pretty remote code)
            throw new CertificateException("Certificate chain error");
        }
        try {
            validator.validate(certPath, params);
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

    /**
     * Checks whether the given certificate is found in our trust store.
     */
    private boolean isTrustAnchor(X509Certificate cert) {
        if (params instanceof IndexedPKIXParameters) {
            IndexedPKIXParameters index = (IndexedPKIXParameters) params;
            return index.isTrustAnchor(cert);
        }
        return IndexedPKIXParameters.isTrustAnchor(cert, params.getTrustAnchors());
    }

    /**
     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
     */
    public X509Certificate[] getAcceptedIssuers() {
        if (params == null) {
            return new X509Certificate[0];
        }
        Set<TrustAnchor> anchors = params.getTrustAnchors();
        List<X509Certificate> certs = new ArrayList<X509Certificate>(anchors.size());
        for (TrustAnchor trustAnchor : anchors) {
            X509Certificate cert = trustAnchor.getTrustedCert();
            if (cert != null) {
                certs.add(cert);
            }
        }
        return certs.toArray(new X509Certificate[certs.size()]);
    }

}
