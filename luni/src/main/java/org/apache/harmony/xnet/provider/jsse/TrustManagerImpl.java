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

    private CertPathValidator validator;

    private PKIXParameters params;

    private Exception err = null;

    private CertificateFactory factory;

    /**
     * Creates trust manager implementation
     *
     * @param ks
     */
    public TrustManagerImpl(KeyStore ks) {
        try {
            validator = CertPathValidator.getInstance("PKIX");
            factory = CertificateFactory.getInstance("X509");
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
            err = e;
        }
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
        if (chain == null || chain.length == 0 || authType == null
                || authType.length() == 0) {
            throw new IllegalArgumentException("null or zero-length parameter");
        }
        if (err != null) {
            throw new CertificateException(err);
        }
        // BEGIN android-added
        // Caters to degenerate special case where we can't
        // establish an actual certificate chain the usual way,
        // but have the peer certificate in our trust store.
        if (isDirectlyTrustedCert(chain)) {
            return;
        }
        // END android-added
        try {
            // BEGIN android-changed
            CertPath certPath = factory.generateCertPath(Arrays.asList(chain));
            if (!Arrays.equals(chain[0].getEncoded(),
                    ((X509Certificate)certPath.getCertificates().get(0))
                    .getEncoded())) {
                // Sanity check failed (shouldn't ever happen, but we
                // are using pretty remote code)
                throw new CertificateException("Certificate chain error");
            }
            validator.validate(certPath, params);
            // END android-changed
        } catch (InvalidAlgorithmParameterException e) {
            throw new CertificateException(e);
        } catch (CertPathValidatorException e) {
            throw new CertificateException(e);
        }
    }

    /**
     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(X509Certificate[],
     *      String)
     */
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        if (chain == null || chain.length == 0 || authType == null
                || authType.length() == 0) {
            throw new IllegalArgumentException("null or zero-length parameter");
        }
        if (err != null) {
            throw new CertificateException(err);
        }
        // BEGIN android-changed
        CertificateException ce = null;
        try {
            CertPath certPath = factory.generateCertPath(Arrays.asList(chain));
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
        }
        // END android-added
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
