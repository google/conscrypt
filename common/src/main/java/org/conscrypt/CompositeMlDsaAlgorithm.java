/*
 * Copyright (C) 2026 The Android Open Source Project
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

/**
 * Composite ML-DSA algorithm. Values from
 * https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html#name-algorithm-identifiers-and-p.
 */
@Internal
public enum CompositeMlDsaAlgorithm {
    MLDSA44_RSA2048_PSS_SHA256("MLDSA44-RSA2048-PSS-SHA256", "1.3.6.1.5.5.7.6.37",
                               new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                           (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                           (byte) 0x06, (byte) 0x25},
                               "COMPSIG-MLDSA44-RSA2048-PSS-SHA256", "SHA-256",
                               MlDsaAlgorithm.ML_DSA_44, "RSA", 2048, "SHA-256", true, null),
    MLDSA44_RSA2048_PKCS15_SHA256("MLDSA44-RSA2048-PKCS15-SHA256", "1.3.6.1.5.5.7.6.38",
                                  new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                              (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                              (byte) 0x06, (byte) 0x26},
                                  "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", "SHA-256",
                                  MlDsaAlgorithm.ML_DSA_44, "RSA", 2048, "SHA-256", false, null),
    MLDSA44_ED25519_SHA512("MLDSA44-Ed25519-SHA512", "1.3.6.1.5.5.7.6.39",
                           new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                       (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                       (byte) 0x06, (byte) 0x27},
                           "COMPSIG-MLDSA44-Ed25519-SHA512", "SHA-512", MlDsaAlgorithm.ML_DSA_44,
                           "Ed25519", null, null, null, null),
    MLDSA44_ECDSA_P256_SHA256("MLDSA44-ECDSA-P256-SHA256", "1.3.6.1.5.5.7.6.40",
                              new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                          (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                          (byte) 0x06, (byte) 0x28},
                              "COMPSIG-MLDSA44-ECDSA-P256-SHA256", "SHA-256",
                              MlDsaAlgorithm.ML_DSA_44, "EC", 256, "SHA-256", null, "prime256v1"),

    MLDSA65_RSA3072_PSS_SHA512("MLDSA65-RSA3072-PSS-SHA512", "1.3.6.1.5.5.7.6.41",
                               new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                           (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                           (byte) 0x06, (byte) 0x29},
                               "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", "SHA-512",
                               MlDsaAlgorithm.ML_DSA_65, "RSA", 3072, "SHA-256", true, null),
    MLDSA65_RSA3072_PKCS15_SHA512("MLDSA65-RSA3072-PKCS15-SHA512", "1.3.6.1.5.5.7.6.42",
                                  new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                              (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                              (byte) 0x06, (byte) 0x2a},
                                  "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", "SHA-512",
                                  MlDsaAlgorithm.ML_DSA_65, "RSA", 3072, "SHA-256", false, null),
    MLDSA65_RSA4096_PSS_SHA512("MLDSA65-RSA4096-PSS-SHA512", "1.3.6.1.5.5.7.6.43",
                               new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                           (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                           (byte) 0x06, (byte) 0x2b},
                               "COMPSIG-MLDSA65-RSA4096-PSS-SHA512", "SHA-512",
                               MlDsaAlgorithm.ML_DSA_65, "RSA", 4096, "SHA-384", true, null),
    MLDSA65_RSA4096_PKCS15_SHA512("MLDSA65-RSA4096-PKCS15-SHA512", "1.3.6.1.5.5.7.6.44",
                                  new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                              (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                              (byte) 0x06, (byte) 0x2c},
                                  "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", "SHA-512",
                                  MlDsaAlgorithm.ML_DSA_65, "RSA", 4096, "SHA-384", false, null),
    MLDSA65_ECDSA_P256_SHA512("MLDSA65-ECDSA-P256-SHA512", "1.3.6.1.5.5.7.6.45",
                              new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                          (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                          (byte) 0x06, (byte) 0x2d},
                              "COMPSIG-MLDSA65-ECDSA-P256-SHA512", "SHA-512",
                              MlDsaAlgorithm.ML_DSA_65, "EC", 256, "SHA-256", null, "prime256v1"),
    MLDSA65_ECDSA_P384_SHA512("MLDSA65-ECDSA-P384-SHA512", "1.3.6.1.5.5.7.6.46",
                              new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                          (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                          (byte) 0x06, (byte) 0x2e},
                              "COMPSIG-MLDSA65-ECDSA-P384-SHA512", "SHA-512",
                              MlDsaAlgorithm.ML_DSA_65, "EC", 384, "SHA-384", null, "secp384r1"),
    MLDSA65_ED25519_SHA512("MLDSA65-Ed25519-SHA512", "1.3.6.1.5.5.7.6.48",
                           new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                       (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                       (byte) 0x06, (byte) 0x30},
                           "COMPSIG-MLDSA65-Ed25519-SHA512", "SHA-512", MlDsaAlgorithm.ML_DSA_65,
                           "Ed25519", null, null, null, null),

    MLDSA87_ECDSA_P384_SHA512("MLDSA87-ECDSA-P384-SHA512", "1.3.6.1.5.5.7.6.49",
                              new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                          (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                          (byte) 0x06, (byte) 0x31},
                              "COMPSIG-MLDSA87-ECDSA-P384-SHA512", "SHA-512",
                              MlDsaAlgorithm.ML_DSA_87, "EC", 384, "SHA-384", null, "secp384r1"),
    MLDSA87_RSA3072_PSS_SHA512("MLDSA87-RSA3072-PSS-SHA512", "1.3.6.1.5.5.7.6.52",
                               new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                           (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                           (byte) 0x06, (byte) 0x34},
                               "COMPSIG-MLDSA87-RSA3072-PSS-SHA512", "SHA-512",
                               MlDsaAlgorithm.ML_DSA_87, "RSA", 3072, "SHA-256", true, null),
    MLDSA87_RSA4096_PSS_SHA512("MLDSA87-RSA4096-PSS-SHA512", "1.3.6.1.5.5.7.6.53",
                               new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                           (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                           (byte) 0x06, (byte) 0x35},
                               "COMPSIG-MLDSA87-RSA4096-PSS-SHA512", "SHA-512",
                               MlDsaAlgorithm.ML_DSA_87, "RSA", 4096, "SHA-384", true, null),
    MLDSA87_ECDSA_P521_SHA512("MLDSA87-ECDSA-P521-SHA512", "1.3.6.1.5.5.7.6.54",
                              new byte[] {(byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06,
                                          (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
                                          (byte) 0x06, (byte) 0x36},
                              "COMPSIG-MLDSA87-ECDSA-P521-SHA512", "SHA-512",
                              MlDsaAlgorithm.ML_DSA_87, "EC", 521, "SHA-512", null, "secp521r1");

    private final String name;
    private final String oid;
    @SuppressWarnings("Immutable") // We never change this byte array.
    private final byte[] oidBytes;
    private final String label;
    private final String preHashAlgorithm;
    private final MlDsaAlgorithm mlDsaAlgorithm;
    private final String classicAlgorithm;
    private final Integer classicRsaKeySize;
    private final String classicSignatureDigest;
    private final Boolean isRsaPss;
    private final String ecCurve;

    private CompositeMlDsaAlgorithm(String name, String oid, byte[] oidBytes, String label,
                                    String preHashAlgorithm, MlDsaAlgorithm mlDsaAlgorithm,
                                    String classicAlgorithm, Integer classicKeySize,
                                    String classicSignatureDigest, Boolean isRsaPss,
                                    String ecCurve) {
        this.name = name;
        this.oid = oid;
        this.oidBytes = oidBytes;
        this.label = label;
        this.preHashAlgorithm = preHashAlgorithm;
        this.mlDsaAlgorithm = mlDsaAlgorithm;
        this.classicAlgorithm = classicAlgorithm;
        this.classicRsaKeySize = classicKeySize;
        this.classicSignatureDigest = classicSignatureDigest;
        this.isRsaPss = isRsaPss;
        this.ecCurve = ecCurve;
    }

    public String getName() {
        return name;
    }

    public String getOid() {
        return oid;
    }

    public byte[] getOidBytes() {
        return oidBytes.clone();
    }

    public String getLabel() {
        return label;
    }

    public String getPreHashAlgorithm() {
        return preHashAlgorithm;
    }

    public MlDsaAlgorithm getMlDsaAlgorithm() {
        return mlDsaAlgorithm;
    }

    public String getClassicAlgorithm() {
        return classicAlgorithm;
    }

    public Integer getClassicKeySize() {
        return classicRsaKeySize;
    }

    public String getClassicSignatureDigest() {
        return classicSignatureDigest;
    }

    public boolean isPss() {
        return isRsaPss != null && isRsaPss;
    }

    public String getEcCurve() {
        return ecCurve;
    }

    @Override
    public String toString() {
        return name;
    }

    public static CompositeMlDsaAlgorithm fromName(String name) {
        for (CompositeMlDsaAlgorithm alg : values()) {
            if (alg.getName().equals(name)) {
                return alg;
            }
        }
        throw new IllegalArgumentException("Unsupported algorithm: " + name);
    }

    public static CompositeMlDsaAlgorithm fromOid(String oid) {
        for (CompositeMlDsaAlgorithm alg : values()) {
            if (alg.getOid().equals(oid)) {
                return alg;
            }
        }
        throw new IllegalArgumentException("Unsupported algorithm OID: " + oid);
    }
}
