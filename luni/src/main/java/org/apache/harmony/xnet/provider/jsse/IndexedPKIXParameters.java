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
import java.security.KeyStoreException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;

/**
 * Indexes trust anchors so they can be found in O(1) time instead of O(N).
 */
public class IndexedPKIXParameters extends PKIXParameters {

    final Map<Bytes, TrustAnchor> encodings
            = new HashMap<Bytes, TrustAnchor>();
    final Map<X500Principal, TrustAnchor> bySubject
            = new HashMap<X500Principal, TrustAnchor>();
    final Map<X500Principal, List<TrustAnchor>> byCA
            = new HashMap<X500Principal, List<TrustAnchor>>();

    public IndexedPKIXParameters(Set<TrustAnchor> anchors)
            throws KeyStoreException, InvalidAlgorithmParameterException,
            CertificateEncodingException {
        super(anchors);

        for (TrustAnchor anchor : anchors) {
            X509Certificate cert = anchor.getTrustedCert();

            Bytes encoded = new Bytes(cert.getEncoded());
            encodings.put(encoded, anchor);

            X500Principal subject = cert.getSubjectX500Principal();
            if (bySubject.put(subject, anchor) != null) {
                // TODO: Should we allow this?
                throw new KeyStoreException("Two certs have the same subject: "
                        + subject);
            }

            X500Principal ca = anchor.getCA();
            List<TrustAnchor> caAnchors = byCA.get(ca);
            if (caAnchors == null) {
                caAnchors = new ArrayList<TrustAnchor>();
                byCA.put(ca, caAnchors);
            }
            caAnchors.add(anchor);
        }
    }

    public TrustAnchor findTrustAnchor(X509Certificate cert)
            throws CertPathValidatorException {
        // Mimic the alg in CertPathValidatorUtilities.findTrustAnchor().
        Exception verificationException = null;
        X500Principal issuer = cert.getIssuerX500Principal();

        List<TrustAnchor> anchors = byCA.get(issuer);
        if (anchors != null) {
            for (TrustAnchor caAnchor : anchors) {
                try {
                    cert.verify(caAnchor.getCAPublicKey());
                    return caAnchor;
                } catch (Exception e) {
                    verificationException = e;
                }
            }
        }

        TrustAnchor anchor = bySubject.get(issuer);
        if (anchor != null) {
            try {
                cert.verify(anchor.getTrustedCert().getPublicKey());
                return anchor;
            } catch (Exception e) {
                verificationException = e;
            }
        }

        try {
            Bytes encoded = new Bytes(cert.getEncoded());
            anchor = encodings.get(encoded);
            if (anchor != null) {
                return anchor;
            }
        } catch (Exception e) {
            Logger.getLogger(IndexedPKIXParameters.class.getName()).log(
                    Level.WARNING, "Error encoding cert.", e);
        }

        // Throw last verification exception.
        if (verificationException != null) {
            throw new CertPathValidatorException("TrustAnchor found but"
                    + " certificate verification failed.",
                    verificationException);
        }

        return null;
    }

    /**
     * Returns true if the given certificate is found in the trusted key
     * store.
     */
    public boolean isDirectlyTrusted(X509Certificate cert) {
        try {
            Bytes encoded = new Bytes(cert.getEncoded());
            return encodings.containsKey(encoded);
        } catch (Exception e) {
            Logger.getLogger(IndexedPKIXParameters.class.getName()).log(
                    Level.WARNING, "Error encoding cert.", e);
            return false;
        }
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
