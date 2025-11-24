/*
 * Copyright 2025 The Android Open Source Project
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

import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.util.Arrays;

/** An OpenSSL ML-DSA private key. */
public class OpenSslMlDsaPrivateKey implements PrivateKey {
    private static final long serialVersionUID = 0x3bacc385e8e106a3L;

    // To preserve the serialization format, "seed" is the only variable that gets
    // serialized. To be able to distinguish between ML-DSA-65 and ML-DSA-87, we add
    // and additional byte to the end of the seed if the algorithm is ML-DSA-87. So:
    // - for ML-DSA-65, "seed" has length 32 and is equal to the seed.
    // - for ML-DSA-87, "seed" has length 33, where the first 32 bytes are the seed, and
    //   the last byte has value 87 = 0x57.
    private byte[] seed = null; // only set when the key is serialized or deserialized.
    private transient MlDsaAlgorithm algorithm;
    private transient OpenSSLKey key;

    private static OpenSSLKey getOpenSslKeyFromSeed(byte[] seed, MlDsaAlgorithm algorithm)
            throws ParsingException {
        if (seed.length != 32) {
            throw new IllegalArgumentException("Invalid key size");
        }
        return new OpenSSLKey(NativeCrypto.EVP_PKEY_from_private_seed(
                OpenSslMlDsaKeyFactory.getPKeyType(algorithm), seed));
    }

    private static boolean isValid(byte[] encodedSeed, MlDsaAlgorithm algorithm) {
        if (algorithm == MlDsaAlgorithm.ML_DSA_65) {
            return encodedSeed.length == 32;
        }
        if (algorithm == MlDsaAlgorithm.ML_DSA_87) {
            return encodedSeed.length == 33 && encodedSeed[32] == 87;
        }
        return false;
    }

    private static MlDsaAlgorithm getAlgorithmFromEncodedSeed(byte[] encodedSeed) {
        if (encodedSeed.length == 32) {
            return MlDsaAlgorithm.ML_DSA_65;
        }
        if (encodedSeed.length == 33 && encodedSeed[32] == 87) {
            return MlDsaAlgorithm.ML_DSA_87;
        }
        throw new IllegalArgumentException("Invalid encoded seed");
    }

    private static byte[] encodeSeed(byte[] unencodedSeed, MlDsaAlgorithm algorithm) {
        if (unencodedSeed.length != 32) {
            throw new IllegalArgumentException("Invalid seed");
        }
        if (algorithm == MlDsaAlgorithm.ML_DSA_65) {
            return unencodedSeed.clone();
        } else {
            // add the suffix 87 to the end of the seed.
            byte[] encodedSeed = Arrays.copyOf(unencodedSeed, 33);
            encodedSeed[32] = 87;
            return encodedSeed;
        }
    }

    OpenSslMlDsaPrivateKey(OpenSSLKey key, MlDsaAlgorithm algorithm) {
        if (NativeCrypto.EVP_PKEY_type(key.getNativeRef())
                != OpenSslMlDsaKeyFactory.getPKeyType(algorithm)) {
            throw new IllegalArgumentException("Invalid key type");
        }
        this.algorithm = algorithm;
        this.key = key;
    }

    public OpenSslMlDsaPrivateKey(byte[] seed, MlDsaAlgorithm algorithm) {
        this.algorithm = algorithm;
        try {
            this.key = getOpenSslKeyFromSeed(seed, algorithm);
        } catch (ParsingException e) {
            throw new IllegalArgumentException("Invalid key", e);
        }
    }

    @Override
    public String getAlgorithm() {
        return "ML-DSA";
    }

    public MlDsaAlgorithm getMlDsaAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        if (key == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return NativeCrypto.EVP_marshal_private_key(key.getNativeRef());
    }

    byte[] getSeed() {
        if (key == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return NativeCrypto.EVP_PKEY_get_private_seed(key.getNativeRef());
    }

    @Override
    public OpenSSLKey getOpenSSLKey() {
        return key;
    }

    @Override
    public void destroy() {
        key = null;
    }

    @Override
    public boolean isDestroyed() {
        return key == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof OpenSslMlDsaPrivateKey)) {
            return false;
        }
        OpenSslMlDsaPrivateKey that = (OpenSslMlDsaPrivateKey) o;
        return Arrays.equals(getEncoded(), that.getEncoded());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getEncoded());
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject(); // reads "seed"
        this.algorithm = getAlgorithmFromEncodedSeed(this.seed);
        if (!isValid(this.seed, this.algorithm)) {
            throw new IOException("Invalid key");
        }
        // The unencoded seed is always the first 32 bytes of the encoded seed.
        byte[] unencodedSeed = Arrays.copyOf(seed, 32);
        try {
            this.key = getOpenSslKeyFromSeed(unencodedSeed, this.algorithm);
        } catch (ParsingException e) {
            throw new IOException("Invalid key", e);
        }
        this.seed = null;
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        synchronized (this) {
            this.seed = encodeSeed(getSeed(), this.algorithm);
            stream.defaultWriteObject(); // writes "seed"
            this.seed = null;
        }
    }
}
