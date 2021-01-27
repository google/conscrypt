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

package org.conscrypt;

import java.security.PublicKey;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

/**
 * Indexes {@code TrustAnchor} instances so they can be found in O(1)
 * time instead of O(N).
 */
@Internal
public final class TrustedCertificateIndex {

    private final Map<X500Principal, List<TrustAnchor>> subjectToTrustAnchors
            = new HashMap<X500Principal, List<TrustAnchor>>();

    public TrustedCertificateIndex() {}

    public TrustedCertificateIndex(Set<TrustAnchor> anchors) {
        index(anchors);
    }

    private void index(Set<TrustAnchor> anchors) {
        for (TrustAnchor anchor : anchors) {
            index(anchor);
        }
    }

    public TrustAnchor index(X509Certificate cert) {
        TrustAnchor anchor = new TrustAnchor(cert, null);
        index(anchor);
        return anchor;
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
                anchors = new ArrayList<TrustAnchor>(1);
                subjectToTrustAnchors.put(subject, anchors);
            } else {
                // Avoid indexing the same certificate multiple times
                if (cert != null) {
                    for (TrustAnchor entry : anchors) {
                        if (cert.equals(entry.getTrustedCert())) {
                            return;
                        }
                    }
                }
            }
            anchors.add(anchor);
        }
    }

    public void reset() {
        synchronized (subjectToTrustAnchors) {
            subjectToTrustAnchors.clear();
        }
    }

    public void reset(Set<TrustAnchor> anchors) {
        synchronized (subjectToTrustAnchors) {
            reset();
            index(anchors);
        }
    }

    public TrustAnchor findByIssuerAndSignature(X509Certificate cert) {
        X500Principal issuer = cert.getIssuerX500Principal();
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
                } catch (Exception ignored) {
                    // Ignored
                }
            }
        }
        return null;
    }

    public TrustAnchor findBySubjectAndPublicKey(X509Certificate cert) {
        X500Principal subject = cert.getSubjectX500Principal();
        synchronized (subjectToTrustAnchors) {
            List<TrustAnchor> anchors = subjectToTrustAnchors.get(subject);
            if (anchors == null) {
                return null;
            }
            return findBySubjectAndPublicKey(cert, anchors);
        }
    }

    private static TrustAnchor findBySubjectAndPublicKey(X509Certificate cert,
                                                         Collection<TrustAnchor> anchors) {
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
                    return anchor;
                } else {
                    // PublicKey.equals is not required to compare keys across providers. Fall back
                    // to checking using the encoded form.
                    if ("X.509".equals(caPublicKey.getFormat())
                            && "X.509".equals(certPublicKey.getFormat())) {
                        byte[] caPublicKeyEncoded = caPublicKey.getEncoded();
                        byte[] certPublicKeyEncoded = certPublicKey.getEncoded();
                        if (certPublicKeyEncoded != null
                                && caPublicKeyEncoded != null
                                && Arrays.equals(caPublicKeyEncoded, certPublicKeyEncoded)) {
                            return anchor;
                        }
                    }
                }
            } catch (Exception e) {
                // can happen with unsupported public key types
            }
        }
        return null;
    }

    public Set<TrustAnchor> findAllByIssuerAndSignature(X509Certificate cert) {
        X500Principal issuer = cert.getIssuerX500Principal();
        synchronized (subjectToTrustAnchors) {
            List<TrustAnchor> anchors = subjectToTrustAnchors.get(issuer);
            if (anchors == null) {
                return Collections.<TrustAnchor>emptySet();
            }

            Set<TrustAnchor> result = new HashSet<TrustAnchor>();
            for (TrustAnchor anchor : anchors) {
                try {
                    PublicKey publicKey;
                    X509Certificate caCert = anchor.getTrustedCert();
                    if (caCert != null) {
                        publicKey = caCert.getPublicKey();
                    } else {
                        publicKey = anchor.getCAPublicKey();
                    }
                    if (publicKey == null) {
                        continue;
                    }
                    cert.verify(publicKey);
                    result.add(anchor);
                } catch (Exception ignored) {
                    // Ignored
                }
            }
            return result;
        }
    }

}
