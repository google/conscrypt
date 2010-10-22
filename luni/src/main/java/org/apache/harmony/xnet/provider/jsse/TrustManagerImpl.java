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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
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

    private PKIXParameters params;

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
        Exception errLocal = null;
        try {
            validatorLocal = CertPathValidator.getInstance("PKIX");
            factoryLocal = CertificateFactory.getInstance("X509");
            byte[] nameConstrains = null;
            Set<TrustAnchor> trusted = new HashSet<TrustAnchor>();
            for (Enumeration<String> en = ks.aliases(); en.hasMoreElements();) {
                final String alias = en.nextElement();
                final X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                if (cert != null) {
                    trusted.add(new TrustAnchor(cert, nameConstrains));
                }
            }
            params = new PKIXParameters(trusted);
            params.setRevocationEnabled(false);
        } catch (Exception e) {
            errLocal = e;
        }
        this.validator = validatorLocal;
        this.factory = factoryLocal;
        this.err = errLocal;
    }

    // BEGIN android-added
    /**
     * Indexes trust anchors so they can be found in O(1) instead of O(N) time.
     */
    public void indexTrustAnchors() throws CertificateEncodingException,
            InvalidAlgorithmParameterException, KeyStoreException {
        params = new IndexedPKIXParameters(params.getTrustAnchors());
        params.setRevocationEnabled(false);
    }
    // END android-added

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
        // BEGIN android-changed
        CertificateException ce = null;
        try {
            CertPath certPath = factory.generateCertPath(Arrays.asList(cleanupCertChain(chain)));
            if (!Arrays.equals(chain[0].getEncoded(),
                    certPath.getCertificates().get(0).getEncoded())) {
                // Sanity check failed (shouldn't ever happen, but we
                // are using pretty remote code)
                throw new CertificateException("Certificate chain error");
            }
            validator.validate(certPath, params);
            // END android-changed
        } catch (InvalidAlgorithmParameterException e) {
            ce = new CertificateException(e);
        } catch (CertPathValidatorException e) {
            ce = new CertificateException(e);
        }
        // BEGIN android-added
        if (ce != null) {
            // Caters to degenerate special case where we can't
            // establish an actual certificate chain the usual way
            // but have the peer certificate in our trust store.
            if (!isDirectlyTrustedCert(chain)) {
                throw ce;
            }
        } // END android-added
    }

    /**
     * Clean up the certificate chain, returning a cleaned up chain,
     * which may be a new array instance if elements were removed.
     * Theoretically, we shouldn't have to do this, but various web
     * servers in practice are mis-configured to have out-of-order
     * certificates, expired self-issued root certificate, or CAs with
     * unsupported signature algorithms such as md2WithRSAEncryption.
     */
    private X509Certificate[] cleanupCertChain(X509Certificate[] chain) {
        if (chain.length <= 1) {
            return chain;
        }

        // 1. Clean the received certificates chain.
        int currIndex;
        // Start with the first certificate in the chain, assuming it
        // is the leaf certificate (server or client cert).
        for (currIndex = 0; currIndex < chain.length; currIndex++) {
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

        // 2. drop the last certificate if it is self signed
        X509Certificate lastCertificate = chain[currIndex];
        if (lastCertificate.getSubjectDN().equals(lastCertificate.getIssuerDN())) {
            --currIndex;
        }

        // 3. If the chain is now shorter, copy to an appropriately sized array.
        int chainLength = currIndex + 1;
        if (chainLength == chain.length) {
            return chain;
        }
        return Arrays.copyOf(chain, chainLength);
    }

    /**
     * Checks whether the given chain is just a certificate
     * that we have in our trust store.
     *
     * @param chain The certificate chain.
     *
     * @return True if the certificate is in our trust store, false otherwise.
     */
    private boolean isDirectlyTrustedCert(X509Certificate[] chain) {
        byte[] questionable;

        if (chain.length == 1) {
            if (params instanceof IndexedPKIXParameters) {
                IndexedPKIXParameters index = (IndexedPKIXParameters) params;
                return index.isDirectlyTrusted(chain[0]);
            } else {
                try {
                    questionable = chain[0].getEncoded();
                    Set<TrustAnchor> anchors = params.getTrustAnchors();

                    for (TrustAnchor trustAnchor : anchors) {
                        byte[] trusted = trustAnchor.getTrustedCert()
                                .getEncoded();
                        if (Arrays.equals(questionable, trusted)) {
                            return true;
                        }
                    }
                } catch (CertificateEncodingException e) {
                    // Ignore.
                }
            }

        }

        return false;
    }
// END android-changed

    /**
     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
     */
    public X509Certificate[] getAcceptedIssuers() {
        if (params == null) {
            return new X509Certificate[0];
        }
        Set<TrustAnchor> anchors = params.getTrustAnchors();
        X509Certificate[] certs = new X509Certificate[anchors.size()];
        int i = 0;
        for (Iterator<TrustAnchor> it = anchors.iterator(); it.hasNext();) {
            certs[i++] = it.next().getTrustedCert();
        }
        return certs;
    }

}
