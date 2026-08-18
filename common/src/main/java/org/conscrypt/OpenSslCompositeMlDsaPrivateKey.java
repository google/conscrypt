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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

/** An implementation of a composite ML-DSA private key. */
@Internal
public class OpenSslCompositeMlDsaPrivateKey implements PrivateKey {
    private static final int ML_DSA_SEED_LENGTH = 32;

    private final CompositeMlDsaAlgorithm algorithm;
    private final OpenSslMlDsaPrivateKey mlDsaPrivateKey;
    private final PrivateKey classicPrivateKey;
    // Needed to avoid re-creating the classic private key on every getRaw() call, since some of the
    // classic PrivateKey implementations (like OpenSSLRSAPrivateKey) don't support unencoded keys
    // (that is, to get raw bytes back from the PrivateKey object, we'd need to decode it from the
    // PKCS#8 format first).
    private final byte[] classicRawKey;

    public OpenSslCompositeMlDsaPrivateKey(byte[] rawKey, CompositeMlDsaAlgorithm algorithm)
            throws InvalidKeySpecException {
        this.algorithm = algorithm;
        byte[] seed = Arrays.copyOf(rawKey, ML_DSA_SEED_LENGTH);
        byte[] classicRaw = Arrays.copyOfRange(rawKey, ML_DSA_SEED_LENGTH, rawKey.length);
        this.mlDsaPrivateKey = new OpenSslMlDsaPrivateKey(seed, algorithm.getMlDsaAlgorithm());
        this.classicPrivateKey = createClassicPrivateKey(this.algorithm, classicRaw);
        this.classicRawKey = classicRaw;
    }

    private static PrivateKey createClassicPrivateKey(CompositeMlDsaAlgorithm algorithm,
                                                      byte[] rawClassicKey)
            throws InvalidKeySpecException {
        if (algorithm.getClassicAlgorithm().equals("Ed25519")) {
            if (rawClassicKey.length != 32) {
                throw new InvalidKeySpecException("Invalid Ed25519 private key length: "
                                                  + rawClassicKey.length);
            }
            return new OpenSslEdDsaPrivateKey(rawClassicKey);
        }
        if (algorithm.getClassicAlgorithm().equals("RSA")) {
            return OpenSSLKey.getPrivateKey(
                    new PKCS8EncodedKeySpec(NativeCrypto.wrap_RSA_private_key_pkcs8(rawClassicKey)),
                    NativeConstants.EVP_PKEY_RSA);
        }
        if (algorithm.getClassicAlgorithm().equals("EC")) {
            return OpenSSLKey.getPrivateKey(
                    new PKCS8EncodedKeySpec(NativeCrypto.wrap_EC_private_key_pkcs8(rawClassicKey)),
                    NativeConstants.EVP_PKEY_EC);
        }
        throw new InvalidKeySpecException("Unsupported classic algorithm: "
                                          + algorithm.getClassicAlgorithm());
    }

    public CompositeMlDsaAlgorithm getCompositeMlDsaAlgorithm() {
        return algorithm;
    }

    public OpenSslMlDsaPrivateKey getMlDsaPrivateKey() {
        return mlDsaPrivateKey;
    }

    public PrivateKey getClassicPrivateKey() {
        return classicPrivateKey;
    }

    public byte[] getRaw() {
        byte[] seed = mlDsaPrivateKey.getSeed();
        byte[] result = new byte[seed.length + classicRawKey.length];
        System.arraycopy(seed, 0, result, 0, seed.length);
        System.arraycopy(classicRawKey, 0, result, seed.length, classicRawKey.length);
        return result;
    }

    @Override
    public String getAlgorithm() {
        return algorithm.getName();
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        long cbb = 0;
        long seqRef = 0;
        long algRef = 0;
        try {
            cbb = NativeCrypto.asn1_write_init();
            seqRef = NativeCrypto.asn1_write_sequence(cbb);
            NativeCrypto.asn1_write_uint64(seqRef, 0); // version
            algRef = NativeCrypto.asn1_write_sequence(seqRef);
            NativeCrypto.asn1_write_oid_raw(algRef, algorithm.getOid());
            NativeCrypto.asn1_write_flush(seqRef);
            NativeCrypto.asn1_write_octetstring(seqRef, getRaw());
            return NativeCrypto.asn1_write_finish(cbb);
        } catch (IOException e) {
            NativeCrypto.asn1_write_cleanup(cbb);
            throw new IllegalStateException("Failed to encode composite ML-DSA private key", e);
        } finally {
            NativeCrypto.asn1_write_free(algRef);
            NativeCrypto.asn1_write_free(seqRef);
            NativeCrypto.asn1_write_free(cbb);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof OpenSslCompositeMlDsaPrivateKey)) {
            return false;
        }
        OpenSslCompositeMlDsaPrivateKey other = (OpenSslCompositeMlDsaPrivateKey) o;
        return algorithm == other.algorithm && MessageDigest.isEqual(getRaw(), other.getRaw());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getRaw());
    }

    private void readObject(ObjectInputStream in) {
        throw new UnsupportedOperationException("serialization not supported");
    }

    private void writeObject(ObjectOutputStream out) {
        throw new UnsupportedOperationException("serialization not supported");
    }
}
