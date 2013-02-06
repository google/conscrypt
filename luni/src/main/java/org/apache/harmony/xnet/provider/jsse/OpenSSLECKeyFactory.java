/*
 * Copyright (C) 2013 The Android Open Source Project
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

package org.apache.harmony.xnet.provider.jsse;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class OpenSSLECKeyFactory extends KeyFactorySpi {

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof ECPublicKeySpec) {
            ECPublicKeySpec ecKeySpec = (ECPublicKeySpec) keySpec;

            return new OpenSSLECPublicKey(ecKeySpec);
        } else if (keySpec instanceof X509EncodedKeySpec) {
            X509EncodedKeySpec x509KeySpec = (X509EncodedKeySpec) keySpec;

            try {
                final OpenSSLKey key = new OpenSSLKey(
                        NativeCrypto.d2i_PUBKEY(x509KeySpec.getEncoded()));
                return new OpenSSLECPublicKey(key);
            } catch (Exception e) {
                throw new InvalidKeySpecException(e);
            }
        }
        throw new InvalidKeySpecException("Must use ECPublicKeySpec or X509EncodedKeySpec; was "
                + keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof ECPrivateKeySpec) {
            ECPrivateKeySpec ecKeySpec = (ECPrivateKeySpec) keySpec;

            return new OpenSSLECPrivateKey(ecKeySpec);
        } else if (keySpec instanceof PKCS8EncodedKeySpec) {
            PKCS8EncodedKeySpec pkcs8KeySpec = (PKCS8EncodedKeySpec) keySpec;

            try {
                final OpenSSLKey key = new OpenSSLKey(
                        NativeCrypto.d2i_PKCS8_PRIV_KEY_INFO(pkcs8KeySpec.getEncoded()));
                return new OpenSSLECPrivateKey(key);
            } catch (Exception e) {
                throw new InvalidKeySpecException(e);
            }
        }
        throw new InvalidKeySpecException("Must use ECPrivateKeySpec or PKCS8EncodedKeySpec; was "
                + keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("key == null");
        }

        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }

        if (key instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey) key;

            if (ECPublicKeySpec.class.equals(keySpec)) {
                ECParameterSpec params = ecKey.getParams();

                ECPoint w = ecKey.getW();

                return (T) new ECPublicKeySpec(w, params);
            } else if (X509EncodedKeySpec.class.equals(keySpec)) {
                return (T) new X509EncodedKeySpec(key.getEncoded());
            } else {
                throw new InvalidKeySpecException(
                        "Must be ECPublicKeySpec or X509EncodedKeySpec; was " + keySpec.getName());
            }
        } else if (key instanceof ECPrivateKey) {
            ECPrivateKey ecKey = (ECPrivateKey) key;

            if (ECPrivateKeySpec.class.equals(keySpec)) {
                ECParameterSpec params = ecKey.getParams();

                BigInteger s = ecKey.getS();

                return (T) new ECPrivateKeySpec(s, params);
            } else if (PKCS8EncodedKeySpec.class.equals(keySpec)) {
                return (T) new PKCS8EncodedKeySpec(ecKey.getEncoded());
            } else {
                throw new InvalidKeySpecException(
                        "Must be ECPrivateKeySpec or PKCS8EncodedKeySpec; was " + keySpec.getName());
            }
        } else {
            throw new InvalidKeySpecException("Must be ECPublicKey or ECPrivateKey; was "
                    + key.getClass().getName());
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("key == null");
        }

        if (key instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey) key;

            ECPoint w = ecKey.getW();

            ECParameterSpec params = ecKey.getParams();

            try {
                return engineGeneratePublic(new ECPublicKeySpec(w, params));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        } else if (key instanceof ECPrivateKey) {
            ECPrivateKey ecKey = (ECPrivateKey) key;

            BigInteger s = ecKey.getS();

            ECParameterSpec params = ecKey.getParams();

            try {
                return engineGeneratePrivate(new ECPrivateKeySpec(s, params));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        } else {
            throw new InvalidKeyException("Key must be ECPublicKey or ECPrivateKey; was "
                    + key.getClass().getName());
        }
    }

}
