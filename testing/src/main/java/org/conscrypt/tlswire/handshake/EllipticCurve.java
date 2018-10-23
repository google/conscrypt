/*
 * Copyright (C) 2016 The Android Open Source Project
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
package org.conscrypt.tlswire.handshake;
/**
 * {@code EllipticCurve} enum from RFC 4492 section 5.1.1. Curves are assigned
 * via the
 * <a href="https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8">IANA registry</a>.
 */
public enum EllipticCurve {
    SECT163K1(1, "sect163k1"),
    SECT163R1(2, "sect163r1"),
    SECT163R2(3, "sect163r2"),
    SECT193R1(4, "sect193r1"),
    SECT193R2(5, "sect193r2"),
    SECT233K1(6, "sect233k1"),
    SECT233R1(7, "sect233r1"),
    SECT239K1(8, "sect239k1"),
    SECT283K1(9, "sect283k1"),
    SECT283R1(10, "sect283r1"),
    SECT409K1(11, "sect409k1"),
    SECT409R1(12, "sect409r1"),
    SECT571K1(13, "sect571k1"),
    SECT571R1(14, "sect571r1"),
    SECP160K1(15, "secp160k1"),
    SECP160R1(16, "secp160r1"),
    SECP160R2(17, "secp160r2"),
    SECP192K1(18, "secp192k1"),
    SECP192R1(19, "secp192r1"),
    SECP224K1(20, "secp224k1"),
    SECP224R1(21, "secp224r1"),
    SECP256K1(22, "secp256k1"),
    SECP256R1(23, "secp256r1"),
    SECP384R1(24, "secp384r1"),
    SECP521R1(25, "secp521r1"),
    BRAINPOOLP256R1(26, "brainpoolP256r1"),
    BRAINPOOLP384R1(27, "brainpoolP384r1"),
    BRAINPOOLP521R1(28, "brainpoolP521r1"),
    X25519(29, "x25519"),
    X448(30, "x448"),
    ARBITRARY_PRIME(0xFF01, "arbitrary_explicit_prime_curves"),
    ARBITRARY_CHAR2(0xFF02, "arbitrary_explicit_char2_curves");
    public final int identifier;
    public final String name;
    private EllipticCurve(int identifier, String name) {
        this.identifier = identifier;
        this.name = name;
    }
    public static EllipticCurve fromIdentifier(int identifier) {
        for (EllipticCurve curve : values()) {
            if (curve.identifier == identifier) {
                return curve;
            }
        }
        throw new AssertionError("Unknown curve identifier " + identifier);
    }
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(name);
        sb.append(" (");
        sb.append(identifier);
        sb.append(')');
        return sb.toString();
    }
}
