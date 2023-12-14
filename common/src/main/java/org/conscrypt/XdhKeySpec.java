package org.conscrypt;

import java.security.spec.EncodedKeySpec;

/**
 * External Diffie–Hellman key spec holding a key which could be either a public or private key.
 *
 * Subclasses {@code EncodedKeySpec} using the non-Standard "raw" format.  The XdhKeyFactory
 * class utilises this in order to create XDH keys from raw bytes and to return them
 * as an XdhKeySpec allowing the raw key material to be extracted from an XDH key.
 *
 */
public final class XdhKeySpec extends EncodedKeySpec {
    /**
     * Creates an instance of {@link XdhKeySpec} by passing a public or private key in its raw
     * format.
     */
    public XdhKeySpec(byte[] encoded) {
        super(encoded);
    }

    @Override
    public String getFormat() {
        return "raw";
    }

    /**
     * Returns the public or private key in its raw format.
     *
     * @return key in its raw format.
     */
    public byte[] getKey() {
        return getEncoded();
    }
}
