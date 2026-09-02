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
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/** An implementation of a composite MLDSA public key. */
@Internal
public class OpenSslCompositeMlDsaPublicKey implements PublicKey {
    private static final long serialVersionUID = 9131812741197458311L;

    private final CompositeMlDsaAlgorithm algorithm;
    private final OpenSslMlDsaPublicKey mlDsaPublicKey;
    private final PublicKey classicPublicKey;
    // Needed to avoid re-creating the classic public key on every getRaw() call, since some of the
    // classic PublicKey implementations (like OpenSSLRSAPublicKey) don't support unencoded keys
    // (that is, to get raw bytes back from the PublicKey object, we'd need to decode it from the
    // X509 format first).
    private final byte[] classicRawKey;

    public OpenSslCompositeMlDsaPublicKey(byte[] rawKey, CompositeMlDsaAlgorithm algorithm)
            throws IllegalArgumentException, InvalidKeySpecException {
        this.algorithm = algorithm;
        int mlLen = algorithm.getMlDsaAlgorithm().publicKeySize();
        byte[] mlDsaRaw = Arrays.copyOf(rawKey, mlLen);
        byte[] classicRaw = Arrays.copyOfRange(rawKey, mlLen, rawKey.length);
        this.mlDsaPublicKey = new OpenSslMlDsaPublicKey(mlDsaRaw, algorithm.getMlDsaAlgorithm());
        this.classicPublicKey = createClassicPublicKey(this.algorithm, classicRaw);
        this.classicRawKey = classicRaw;
    }

    private static PublicKey createClassicPublicKey(CompositeMlDsaAlgorithm algorithm,
                                                    byte[] rawClassicKey)
            throws IllegalArgumentException, InvalidKeySpecException {
        if (algorithm.getClassicAlgorithm().equals("Ed25519")) {
            if (rawClassicKey.length != 32) {
                throw new IllegalArgumentException("Invalid Ed25519 public key length: "
                                                   + rawClassicKey.length);
            }
            return new OpenSslEdDsaPublicKey(rawClassicKey);
        } else if (algorithm.getClassicAlgorithm().equals("RSA")) {
            try {
                return OpenSSLKey.getPublicKey(
                        new X509EncodedKeySpec(
                                NativeCrypto.wrap_RSA_public_key_x509(rawClassicKey)),
                        NativeConstants.EVP_PKEY_RSA);
            } catch (InvalidKeySpecException e) {
                throw new IllegalArgumentException(e);
            }
        } else if (algorithm.getClassicAlgorithm().equals("EC")) {
            return OpenSSLKey.getPublicKey(
                    new X509EncodedKeySpec(NativeCrypto.wrap_EC_public_key_x509(
                            rawClassicKey, algorithm.getEcCurve())),
                    NativeConstants.EVP_PKEY_EC);
        } else {
            throw new IllegalArgumentException("Unsupported classic algorithm: "
                                               + algorithm.getClassicAlgorithm());
        }
    }

    public CompositeMlDsaAlgorithm getCompositeMlDsaAlgorithm() {
        return algorithm;
    }

    public OpenSslMlDsaPublicKey getMlDsaPublicKey() {
        return mlDsaPublicKey;
    }

    public PublicKey getClassicPublicKey() {
        return classicPublicKey;
    }

    public byte[] getRaw() {
        byte[] mlDsaRaw = mlDsaPublicKey.getRaw();
        byte[] result = new byte[mlDsaRaw.length + classicRawKey.length];
        System.arraycopy(mlDsaRaw, 0, result, 0, mlDsaRaw.length);
        System.arraycopy(classicRawKey, 0, result, mlDsaRaw.length, classicRawKey.length);
        return result;
    }

    @Override
    public String getAlgorithm() {
        return algorithm.getName();
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        long cbb = 0;
        long seqRef = 0;
        long algRef = 0;
        try {
            cbb = NativeCrypto.asn1_write_init();
            seqRef = NativeCrypto.asn1_write_sequence(cbb);
            algRef = NativeCrypto.asn1_write_sequence(seqRef);
            NativeCrypto.asn1_write_oid_raw(algRef, algorithm.getOid());
            NativeCrypto.asn1_write_flush(seqRef);
            NativeCrypto.asn1_write_bitstring(seqRef, getRaw());
            return NativeCrypto.asn1_write_finish(cbb);
        } catch (IOException e) {
            NativeCrypto.asn1_write_cleanup(cbb);
            throw new IllegalStateException("Failed to encode public key", e);
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
        if (!(o instanceof OpenSslCompositeMlDsaPublicKey)) {
            return false;
        }
        OpenSslCompositeMlDsaPublicKey other = (OpenSslCompositeMlDsaPublicKey) o;
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
