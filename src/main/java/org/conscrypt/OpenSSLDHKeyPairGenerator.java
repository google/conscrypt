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

    private int primeBits = 1024;

    private int generator = 2;

    @Override
    public KeyPair generateKeyPair() {
        final OpenSSLKey key = new OpenSSLKey(NativeCrypto.DH_generate_key(primeBits, generator));

        final OpenSSLDHPrivateKey privKey = new OpenSSLDHPrivateKey(key);
        final OpenSSLDHPublicKey pubKey = new OpenSSLDHPublicKey(key);

        return new KeyPair(pubKey, privKey);
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        primeBits = keysize;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof DHParameterSpec) {
            DHParameterSpec dhParams = (DHParameterSpec) params;

            BigInteger pInt = dhParams.getP();
            if (pInt != null) {
                primeBits = pInt.bitLength();
            }
        } else if (params != null) {
            throw new InvalidAlgorithmParameterException("Params must be DHParameterSpec");
        }
    }
}
