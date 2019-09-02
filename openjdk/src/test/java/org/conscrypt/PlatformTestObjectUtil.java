package org.conscrypt;

import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.util.Set;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;

final class PlatformTestObjectUtil {
    static SNIMatcher newSniMatcher() {
        return new SNIMatcher(0) {
            @Override
            public boolean matches(SNIServerName sniServerName) {
                return false;
            }
        };
    }

    static AlgorithmConstraints newAlgorithmConstraints() {
        return new AlgorithmConstraints() {
            @Override
            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm,
                    AlgorithmParameters parameters) {
                return false;
            }

            @Override
            public boolean permits(Set<CryptoPrimitive> primitives, Key key) {
                return false;
            }

            @Override
            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key,
                    AlgorithmParameters parameters) {
                return false;
            }
        };
    }
}
