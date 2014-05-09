/*
 * Copyright (C) 2014 The Android Open Source Project
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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

public class OpenSSLDHKeyFactory extends KeyFactorySpi {

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }

        if (keySpec instanceof DHPublicKeySpec) {
            return new OpenSSLDHPublicKey((DHPublicKeySpec) keySpec);
        } else if (keySpec instanceof X509EncodedKeySpec) {
            return OpenSSLKey.getPublicKey((X509EncodedKeySpec) keySpec, NativeCrypto.EVP_PKEY_DH);
        }
        throw new InvalidKeySpecException("Must use DHPublicKeySpec or X509EncodedKeySpec; was "
                + keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }

        if (keySpec instanceof DHPrivateKeySpec) {
            return new OpenSSLDHPrivateKey((DHPrivateKeySpec) keySpec);
        } else if (keySpec instanceof PKCS8EncodedKeySpec) {
            return OpenSSLKey.getPrivateKey((PKCS8EncodedKeySpec) keySpec,
                    NativeCrypto.EVP_PKEY_DH);
        }
        throw new InvalidKeySpecException("Must use DHPrivateKeySpec or PKCS8EncodedKeySpec; was "
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

        if (!"DH".equals(key.getAlgorithm())) {
            throw new InvalidKeySpecException("Key must be a DH key");
        }

        if (key instanceof DHPublicKey && DHPublicKeySpec.class.isAssignableFrom(keySpec)) {
            DHPublicKey dhKey = (DHPublicKey) key;
            DHParameterSpec params = dhKey.getParams();
            return (T) new DHPublicKeySpec(dhKey.getY(), params.getP(), params.getG());
        } else if (key instanceof PublicKey && DHPublicKeySpec.class.isAssignableFrom(keySpec)) {
            final byte[] encoded = key.getEncoded();
            if (!"X.509".equals(key.getFormat()) || encoded == null) {
                throw new InvalidKeySpecException("Not a valid X.509 encoding");
            }
            DHPublicKey dhKey = (DHPublicKey) engineGeneratePublic(new X509EncodedKeySpec(encoded));
            DHParameterSpec params = dhKey.getParams();
            return (T) new DHPublicKeySpec(dhKey.getY(), params.getP(), params.getG());
        } else if (key instanceof DHPrivateKey && DHPrivateKeySpec.class.isAssignableFrom(keySpec)) {
            DHPrivateKey dhKey = (DHPrivateKey) key;
            DHParameterSpec params = dhKey.getParams();
            return (T) new DHPrivateKeySpec(dhKey.getX(), params.getP(), params.getG());
        } else if (key instanceof PrivateKey && DHPrivateKeySpec.class.isAssignableFrom(keySpec)) {
            final byte[] encoded = key.getEncoded();
            if (!"PKCS#8".equals(key.getFormat()) || encoded == null) {
                throw new InvalidKeySpecException("Not a valid PKCS#8 encoding");
            }
            DHPrivateKey dhKey = (DHPrivateKey) engineGeneratePrivate(new PKCS8EncodedKeySpec(
                    encoded));
            DHParameterSpec params = dhKey.getParams();
            return (T) new DHPrivateKeySpec(dhKey.getX(), params.getP(), params.getG());
        } else if (key instanceof PrivateKey
                && PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
            final byte[] encoded = key.getEncoded();
            if (!"PKCS#8".equals(key.getFormat())) {
                throw new InvalidKeySpecException("Encoding type must be PKCS#8; was "
                        + key.getFormat());
            } else if (encoded == null) {
                throw new InvalidKeySpecException("Key is not encodable");
            }
            return (T) new PKCS8EncodedKeySpec(encoded);
        } else if (key instanceof PublicKey && X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
            final byte[] encoded = key.getEncoded();
            if (!"X.509".equals(key.getFormat())) {
                throw new InvalidKeySpecException("Encoding type must be X.509; was "
                        + key.getFormat());
            } else if (encoded == null) {
                throw new InvalidKeySpecException("Key is not encodable");
            }
            return (T) new X509EncodedKeySpec(encoded);
        } else {
            throw new InvalidKeySpecException("Unsupported key type and key spec combination; key="
                    + key.getClass().getName() + ", keySpec=" + keySpec.getName());
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("key == null");
        }
        if ((key instanceof OpenSSLDHPublicKey) || (key instanceof OpenSSLDHPrivateKey)) {
            return key;
        } else if (key instanceof DHPublicKey) {
            DHPublicKey dhKey = (DHPublicKey) key;

            BigInteger y = dhKey.getY();

            DHParameterSpec params = dhKey.getParams();
            BigInteger p = params.getP();
            BigInteger g = params.getG();

            try {
                return engineGeneratePublic(new DHPublicKeySpec(y, p, g));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        } else if (key instanceof DHPrivateKey) {
            DHPrivateKey dhKey = (DHPrivateKey) key;

            BigInteger x = dhKey.getX();

            DHParameterSpec params = dhKey.getParams();
            BigInteger p = params.getP();
            BigInteger g = params.getG();

            try {
                return engineGeneratePrivate(new DHPrivateKeySpec(x, p, g));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        } else if ((key instanceof PrivateKey) && ("PKCS#8".equals(key.getFormat()))) {
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException("Key does not support encoding");
            }
            try {
                return engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        } else if ((key instanceof PublicKey) && ("X.509".equals(key.getFormat()))) {
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException("Key does not support encoding");
            }
            try {
                return engineGeneratePublic(new X509EncodedKeySpec(encoded));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        } else {
            throw new InvalidKeyException("Key must be DH public or private key; was "
                    + key.getClass().getName());
        }
    }
}
