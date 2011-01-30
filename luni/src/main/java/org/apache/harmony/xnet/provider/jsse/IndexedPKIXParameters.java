/*
 * Copyright (C) 2009 The Android Open Source Project
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

package org.apache.harmony.xnet.provider.jsse;

import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

/**
 * Indexes trust anchors so they can be found in O(1) time instead of O(N).
 */
public final class IndexedPKIXParameters extends PKIXParameters {

    private final Map<X500Principal, List<TrustAnchor>> subjectToTrustAnchors
            = new HashMap<X500Principal, List<TrustAnchor>>();

    public IndexedPKIXParameters(Set<TrustAnchor> anchors)
            throws InvalidAlgorithmParameterException {
        super(anchors);
        index();
    }

    private void index() {
        for (TrustAnchor anchor : getTrustAnchors()) {
            index(anchor);
        }
    }

    public void index(TrustAnchor anchor) {
        X500Principal subject;
        X509Certificate cert = anchor.getTrustedCert();
        if (cert != null) {
            subject = cert.getSubjectX500Principal();
        } else {
            subject = anchor.getCA();
        }

        synchronized (subjectToTrustAnchors) {
            List<TrustAnchor> anchors = subjectToTrustAnchors.get(subject);
            if (anchors == null) {
                anchors = new ArrayList<TrustAnchor>();
                subjectToTrustAnchors.put(subject, anchors);
            }
            anchors.add(anchor);
        }
    }

    public TrustAnchor findTrustAnchor(X509Certificate cert)
            throws CertPathValidatorException {
        X500Principal issuer = cert.getIssuerX500Principal();
        Exception verificationException = null;
        synchronized (subjectToTrustAnchors) {
            List<TrustAnchor> anchors = subjectToTrustAnchors.get(issuer);
            if (anchors == null) {
                return null;
            }

            for (TrustAnchor anchor : anchors) {
                PublicKey publicKey;
                try {
                    X509Certificate caCert = anchor.getTrustedCert();
                    if (caCert != null) {
                        publicKey = caCert.getPublicKey();
                    } else {
                        publicKey = anchor.getCAPublicKey();
                    }
                    cert.verify(publicKey);
                    return anchor;
                } catch (Exception e) {
                    verificationException = e;
                }
            }
        }

        // Throw last verification exception.
        if (verificationException != null) {
            throw new CertPathValidatorException("TrustAnchor found but"
                    + " certificate verification failed.",
                    verificationException);
        }

        return null;
    }

    public boolean isTrustAnchor(X509Certificate cert) {
        X500Principal subject = cert.getSubjectX500Principal();
        synchronized (subjectToTrustAnchors) {
            List<TrustAnchor> anchors = subjectToTrustAnchors.get(subject);
            if (anchors == null) {
                return false;
            }
            return isTrustAnchor(cert, anchors);
        }
    }

    private static boolean isTrustAnchor(X509Certificate cert, Collection<TrustAnchor> anchors) {
        PublicKey certPublicKey = cert.getPublicKey();
        for (TrustAnchor anchor : anchors) {
            PublicKey caPublicKey;
            try {
                X509Certificate caCert = anchor.getTrustedCert();
                if (caCert != null) {
                    caPublicKey = caCert.getPublicKey();
                } else {
                    caPublicKey = anchor.getCAPublicKey();
                }
                if (caPublicKey.equals(certPublicKey)) {
                    return true;
                }
            } catch (Exception e) {
                // can happen with unsupported public key types
            }
        }
        return false;
    }

    /**
     * Wraps a byte[] and adds equals() and hashCode() support.
     */
    static class Bytes {
        final byte[] bytes;
        final int hash;
        Bytes(byte[] bytes) {
            this.bytes = bytes;
            this.hash = Arrays.hashCode(bytes);
        }
        @Override public int hashCode() {
            return hash;
        }
        @Override public boolean equals(Object o) {
            return Arrays.equals(bytes, ((Bytes) o).bytes);
        }
    }
}
