package org.conscrypt.testing;

import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.util.Set;

public class RestrictedAlgorithmConstraints implements AlgorithmConstraints {
    @Override
    public boolean permits(
            Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) {
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
}
