package org.conscrypt;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Parameter markers to assist in future compatibility should other XEC curves be supported.
 */
@Internal
class OpenSSLXECParameterSpec implements AlgorithmParameterSpec {
    public static final String X25519 = "1.3.101.110";

    private final String oid;

    public OpenSSLXECParameterSpec(String oid) {
        this.oid = oid;
    }

    public String getOid() {
        return oid;
    }
}
