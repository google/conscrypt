/*
 * Copyright (C) 2012 The Android Open Source Project
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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.DHParameterSpec;

public class OpenSSLDHKeyPairGenerator extends KeyPairGeneratorSpi {

    /** The safe prime to use for the generated DH key pair. */
    private BigInteger prime;

    /** If {@code prime} is unspecified, this is the size of the generated prime. */
    private int primeBits = 1024;

    private static final BigInteger DEFAULT_GENERATOR = BigInteger.valueOf(2);

    private BigInteger generator = DEFAULT_GENERATOR;

    @Override
    public KeyPair generateKeyPair() {
        final OpenSSLKey key;
        if (prime != null) {
            key = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_DH(prime.toByteArray(),
                    generator.toByteArray(), null, null));
        } else {
            key = new OpenSSLKey(NativeCrypto.DH_generate_parameters_ex(primeBits,
                    generator.longValue()));
        }

        NativeCrypto.DH_generate_key(key.getPkeyContext());

        final OpenSSLDHPrivateKey privKey = new OpenSSLDHPrivateKey(key);
        final OpenSSLDHPublicKey pubKey = new OpenSSLDHPublicKey(key);

        return new KeyPair(pubKey, privKey);
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        prime = null;
        primeBits = keysize;
        generator = DEFAULT_GENERATOR;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        prime = null;
        primeBits = 1024;
        generator = DEFAULT_GENERATOR;

        if (params instanceof DHParameterSpec) {
            DHParameterSpec dhParams = (DHParameterSpec) params;

            prime = dhParams.getP();
            BigInteger gen = dhParams.getG();
            if (gen != null) {
                generator = gen;
            }
        } else if (params != null) {
            throw new InvalidAlgorithmParameterException("Params must be DHParameterSpec");
        }
    }
}
