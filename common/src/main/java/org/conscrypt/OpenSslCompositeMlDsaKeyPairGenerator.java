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

import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;

/** An implementation of a {@link KeyPairGenerator} for composite MLDSA keys. */
@Internal
public abstract class OpenSslCompositeMlDsaKeyPairGenerator extends KeyPairGenerator {
    private final CompositeMlDsaAlgorithm fullAlgorithm;

    private OpenSslCompositeMlDsaKeyPairGenerator(CompositeMlDsaAlgorithm algorithm) {
        super(algorithm.getName());
        this.fullAlgorithm = algorithm;
    }

    /** Key pair generator for MLDSA44-RSA2048-PSS-SHA256. */
    public static class Mldsa44Rsa2048PssSha256 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa44Rsa2048PssSha256() {
            super(CompositeMlDsaAlgorithm.MLDSA44_RSA2048_PSS_SHA256);
        }
    }

    /** Key pair generator for MLDSA44-RSA2048-PKCS15-SHA256. */
    public static class Mldsa44Rsa2048Pkcs15Sha256 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa44Rsa2048Pkcs15Sha256() {
            super(CompositeMlDsaAlgorithm.MLDSA44_RSA2048_PKCS15_SHA256);
        }
    }

    /** Key pair generator for MLDSA44-Ed25519-SHA512. */
    public static class Mldsa44Ed25519Sha512 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa44Ed25519Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA44_ED25519_SHA512);
        }
    }

    /** Key pair generator for MLDSA44-ECDSA-P256-SHA256. */
    public static class Mldsa44EcdsaP256Sha256 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa44EcdsaP256Sha256() {
            super(CompositeMlDsaAlgorithm.MLDSA44_ECDSA_P256_SHA256);
        }
    }

    /** Key pair generator for MLDSA65-RSA3072-PSS-SHA512. */
    public static class Mldsa65Rsa3072PssSha512 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa65Rsa3072PssSha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_RSA3072_PSS_SHA512);
        }
    }

    /** Key pair generator for MLDSA65-RSA3072-PKCS15-SHA512. */
    public static class Mldsa65Rsa3072Pkcs15Sha512 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa65Rsa3072Pkcs15Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_RSA3072_PKCS15_SHA512);
        }
    }

    /** Key pair generator for MLDSA65-RSA4096-PSS-SHA512. */
    public static class Mldsa65Rsa4096PssSha512 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa65Rsa4096PssSha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_RSA4096_PSS_SHA512);
        }
    }

    /** Key pair generator for MLDSA65-RSA4096-PKCS15-SHA512. */
    public static class Mldsa65Rsa4096Pkcs15Sha512 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa65Rsa4096Pkcs15Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_RSA4096_PKCS15_SHA512);
        }
    }

    /** Key pair generator for MLDSA65-Ed25519-SHA512. */
    public static class Mldsa65Ed25519Sha512 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa65Ed25519Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_ED25519_SHA512);
        }
    }

    /** Key pair generator for MLDSA65-ECDSA-P256-SHA512. */
    public static class Mldsa65EcdsaP256Sha512 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa65EcdsaP256Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_ECDSA_P256_SHA512);
        }
    }

    /** Key pair generator for MLDSA65-ECDSA-P384-SHA512. */
    public static class Mldsa65EcdsaP384Sha512 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa65EcdsaP384Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_ECDSA_P384_SHA512);
        }
    }

    /** Key pair generator for MLDSA87-RSA3072-PSS-SHA512. */
    public static class Mldsa87Rsa3072PssSha512 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa87Rsa3072PssSha512() {
            super(CompositeMlDsaAlgorithm.MLDSA87_RSA3072_PSS_SHA512);
        }
    }

    /** Key pair generator for MLDSA87-RSA4096-PSS-SHA512. */
    public static class Mldsa87Rsa4096PssSha512 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa87Rsa4096PssSha512() {
            super(CompositeMlDsaAlgorithm.MLDSA87_RSA4096_PSS_SHA512);
        }
    }

    /** Key pair generator for MLDSA87-ECDSA-P384-SHA512. */
    public static class Mldsa87EcdsaP384Sha512 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa87EcdsaP384Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA87_ECDSA_P384_SHA512);
        }
    }

    /** Key pair generator for MLDSA87-ECDSA-P521-SHA512. */
    public static class Mldsa87EcdsaP521Sha512 extends OpenSslCompositeMlDsaKeyPairGenerator {
        public Mldsa87EcdsaP521Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA87_ECDSA_P521_SHA512);
        }
    }

    @Override
    public void initialize(int bits) {
        if (bits != -1) {
            throw new InvalidParameterException("Composite ML-DSA only supports -1 for bits");
        }
    }

    /**
     * Following
     * https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html#name-key-generation
     */
    @Override
    public KeyPair generateKeyPair() {
        try {
            // Generate ML-DSA key pair.
            byte[] seed = new byte[32];
            NativeCrypto.RAND_bytes(seed);
            byte[] pqRawPublicKeyBytes;
            if (fullAlgorithm.getMlDsaAlgorithm().equals(MlDsaAlgorithm.ML_DSA_44)) {
                pqRawPublicKeyBytes = NativeCrypto.MLDSA44_public_key_from_seed(seed);
            } else if (fullAlgorithm.getMlDsaAlgorithm().equals(MlDsaAlgorithm.ML_DSA_65)) {
                pqRawPublicKeyBytes = NativeCrypto.MLDSA65_public_key_from_seed(seed);
            } else if (fullAlgorithm.getMlDsaAlgorithm().equals(MlDsaAlgorithm.ML_DSA_87)) {
                pqRawPublicKeyBytes = NativeCrypto.MLDSA87_public_key_from_seed(seed);
            } else {
                // Should never happen.
                throw new IllegalStateException("Unsupported ML-DSA algorithm: "
                                                + fullAlgorithm.getMlDsaAlgorithm());
            }

            // Generate classic key pair.
            KeyPairGeneratorSpi kpg;
            if (fullAlgorithm.getClassicAlgorithm().equals("Ed25519")) {
                kpg = new OpenSslEdDsaKeyPairGenerator();
            } else if (fullAlgorithm.getClassicAlgorithm().equals("RSA")) {
                kpg = new OpenSSLRSAKeyPairGenerator();
            } else if (fullAlgorithm.getClassicAlgorithm().equals("EC")) {
                kpg = new OpenSSLECKeyPairGenerator();
            } else {
                throw new IllegalStateException("Unsupported classic algorithm: "
                                                + fullAlgorithm.getClassicAlgorithm());
            }

            if (fullAlgorithm.getClassicKeySize() != null
                && fullAlgorithm.getClassicKeySize() > 0) {
                kpg.initialize(fullAlgorithm.getClassicKeySize(), null);
            }
            KeyPair classicKeyPair = kpg.generateKeyPair();

            // Get classic public key bytes.
            OpenSSLKey classicPublicKey =
                    ((OpenSSLKeyHolder) classicKeyPair.getPublic()).getOpenSSLKey();
            byte[] classicRawPublicKeyBytes;
            if (fullAlgorithm.getClassicAlgorithm().equals("Ed25519")) {
                classicRawPublicKeyBytes =
                        NativeCrypto.EVP_PKEY_get_raw_public_key(classicPublicKey.getNativeRef());
            } else if (fullAlgorithm.getClassicAlgorithm().equals("RSA")) {
                classicRawPublicKeyBytes = NativeCrypto.unwrap_RSA_public_key_x509(
                        NativeCrypto.EVP_marshal_public_key(classicPublicKey.getNativeRef()));
            } else if (fullAlgorithm.getClassicAlgorithm().equals("EC")) {
                classicRawPublicKeyBytes = NativeCrypto.unwrap_EC_public_key_x509(
                        NativeCrypto.EVP_marshal_public_key(classicPublicKey.getNativeRef()));
            } else {
                throw new IllegalStateException("Unsupported classic algorithm: "
                                                + fullAlgorithm.getClassicAlgorithm());
            }

            // Assemble composite public key bytes.
            byte[] compositeRawPublicKeyBytes =
                    ArrayUtils.concat(pqRawPublicKeyBytes, classicRawPublicKeyBytes);

            // Get classic private key bytes.
            OpenSSLKey classicPrivateKey =
                    ((OpenSSLKeyHolder) classicKeyPair.getPrivate()).getOpenSSLKey();
            byte[] classicRawSecretKeyBytes;
            if (fullAlgorithm.getClassicAlgorithm().equals("Ed25519")) {
                classicRawSecretKeyBytes =
                        NativeCrypto.EVP_PKEY_get_raw_private_key(classicPrivateKey.getNativeRef());
            } else if (fullAlgorithm.getClassicAlgorithm().equals("RSA")) {
                classicRawSecretKeyBytes = NativeCrypto.unwrap_RSA_private_key_pkcs8(
                        NativeCrypto.EVP_marshal_private_key(classicPrivateKey.getNativeRef()));
            } else if (fullAlgorithm.getClassicAlgorithm().equals("EC")) {
                classicRawSecretKeyBytes = NativeCrypto.unwrap_EC_private_key_pkcs8(
                        NativeCrypto.EVP_marshal_private_key(classicPrivateKey.getNativeRef()));
            } else {
                throw new IllegalStateException("Unsupported classic algorithm: "
                                                + fullAlgorithm.getClassicAlgorithm());
            }

            // Assemble composite private key bytes.
            byte[] compositeRawSecretKeyBytes = ArrayUtils.concat(seed, classicRawSecretKeyBytes);

            // Assemble composite key pair.
            return new KeyPair(
                    new OpenSslCompositeMlDsaPublicKey(compositeRawPublicKeyBytes, fullAlgorithm),
                    new OpenSslCompositeMlDsaPrivateKey(compositeRawSecretKeyBytes, fullAlgorithm));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
