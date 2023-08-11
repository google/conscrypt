package org.conscrypt;

import java.security.spec.KeySpec;

/**
 * External Diffie–Hellman key spec holding the public or private key in its raw format.
 */
public final class XdhKeySpec implements KeySpec {
    private final byte[] key;

    public XdhKeySpec(byte[] key) {
        this.key = key;
    }

    public byte[] getKey() {
        return key;
    }
}
