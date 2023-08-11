package org.conscrypt;

import java.security.spec.KeySpec;

/**
 * External Diffie–Hellman key spec holding a key which could be either a public or private key.
 */
public final class XdhKeySpec implements KeySpec {
    private final byte[] key;

    /**
     * Creates an instance of {@link XdhKeySpec} by passing a public or private key in its raw
     * format.
     */
    public XdhKeySpec(byte[] key) {
        this.key = key;
    }

    /**
     * Returns the public or private key in its raw format.
     *
     * @return key in its raw format.
     */
    public byte[] getKey() {
        return key;
    }
}
