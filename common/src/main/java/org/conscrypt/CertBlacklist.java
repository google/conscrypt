package org.conscrypt;

import java.math.BigInteger;
import java.security.PublicKey;

/**
 * A set of certificates that are blacklisted from trust.
 */
public interface CertBlacklist {

    /**
     * Returns whether the given public key is in the blacklist.
     */
    boolean isPublicKeyBlackListed(PublicKey publicKey);

    /**
     * Returns whether the given serial number is in the blacklist.
     */
    boolean isSerialNumberBlackListed(BigInteger serial);
}
