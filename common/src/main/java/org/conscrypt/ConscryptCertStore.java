package org.conscrypt;

import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * A certificate store that supports additional operations that are used in
 * TrustManagerImpl.  This is primarily implemented by the cert store on the
 * Android platform.
 */
@Internal
public interface ConscryptCertStore {

    /**
     * Returns a stored CA certificate with the same name and public key as the
     * provided {@link X509Certificate}.
     */
    X509Certificate getTrustAnchor(X509Certificate c);

    /**
     * Returns all CA certificates with the public key that was used to sign the
     * provided {@link X509Certificate}.
     */
    Set<X509Certificate> findAllIssuers(X509Certificate c);
}
