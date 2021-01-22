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

package org.conscrypt;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * An implementation of a {@link KeyFactorySpi} for EC keys based on BoringSSL.
 */
@Internal
public final class OpenSSLXDHKeyFactory extends KeyFactorySpi {

    public OpenSSLXDHKeyFactory() {}

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }

        if (keySpec instanceof X509EncodedKeySpec) {
            return new OpenSSLX25519PublicKey((X509EncodedKeySpec) keySpec);
        }
        throw new InvalidKeySpecException("Must use ECPublicKeySpec or X509EncodedKeySpec; was "
                + keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }

        if (keySpec instanceof PKCS8EncodedKeySpec) {
            return new OpenSSLX25519PrivateKey((PKCS8EncodedKeySpec) keySpec);
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

        if (!"XDH".equals(key.getAlgorithm())) {
            throw new InvalidKeySpecException("Key must be an XDH key");
        }

        Class<?> publicKeySpec = getJavaPublicKeySpec();
        Class<?> privateKeySpec = getJavaPrivateKeySpec();

        if (publicKeySpec != null && key instanceof PublicKey && publicKeySpec.isAssignableFrom(keySpec)) {
            final byte[] encoded = key.getEncoded();
            if (!"X.509".equals(key.getFormat()) || encoded == null) {
                throw new InvalidKeySpecException("Not a valid X.509 encoding");
            }
            OpenSSLX25519PublicKey publicKey = (OpenSSLX25519PublicKey) engineGeneratePublic(new X509EncodedKeySpec(encoded));
            @SuppressWarnings("unchecked")
            T result = (T) constructJavaPublicKeySpec(publicKeySpec, publicKey);
            return result;
        } else if (privateKeySpec != null && key instanceof PrivateKey && privateKeySpec.isAssignableFrom(keySpec)) {
            final byte[] encoded = key.getEncoded();
            if (!"PKCS#8".equals(key.getFormat()) || encoded == null) {
                throw new InvalidKeySpecException("Not a valid PKCS#8 encoding");
            }
            OpenSSLX25519PrivateKey privateKey = (OpenSSLX25519PrivateKey) engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded));
            @SuppressWarnings("unchecked")
            T result = (T) constructJavaPrivateKeySpec(privateKeySpec, privateKey);
            return result;
        } else if (key instanceof PrivateKey && PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
            final byte[] encoded = key.getEncoded();
            if (!"PKCS#8".equals(key.getFormat())) {
                throw new InvalidKeySpecException("Encoding type must be PKCS#8; was "
                        + key.getFormat());
            } else if (encoded == null) {
                throw new InvalidKeySpecException("Key is not encodable");
            }
            @SuppressWarnings("unchecked") T result = (T) new PKCS8EncodedKeySpec(encoded);
            return result;
        } else if (key instanceof PublicKey && X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
            final byte[] encoded = key.getEncoded();
            if (!"X.509".equals(key.getFormat())) {
                throw new InvalidKeySpecException("Encoding type must be X.509; was "
                        + key.getFormat());
            } else if (encoded == null) {
                throw new InvalidKeySpecException("Key is not encodable");
            }
            @SuppressWarnings("unchecked") T result = (T) new X509EncodedKeySpec(encoded);
            return result;
        }

        throw new InvalidKeySpecException("Unsupported key type and key spec combination; key="
                + key.getClass().getName() + ", keySpec=" + keySpec.getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("key == null");
        }
        if ((key instanceof OpenSSLX25519PublicKey) || (key instanceof OpenSSLX25519PrivateKey)) {
            return key;
        } else if ((key instanceof PrivateKey) && "PKCS#8".equals(key.getFormat())) {
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException("Key does not support encoding");
            }
            try {
                return engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        } else if ((key instanceof PublicKey) && "X.509".equals(key.getFormat())) {
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
            throw new InvalidKeyException("Key must be EC public or private key; was "
                    + key.getClass().getName());
        }
    }

    private static Class<?> getJavaPrivateKeySpec() {
        try {
            return Class.forName("java.security.spec.XECPrivateKeySpec");
        } catch (ClassNotFoundException ignored) {
            return null;
        }
    }

    private static Class<?> getJavaPublicKeySpec() {
        try {
            return Class.forName("java.security.spec.XECPublicKeySpec");
        } catch (ClassNotFoundException ignored) {
            return null;
        }
    }

    private KeySpec constructJavaPrivateKeySpec(Class<?> privateKeySpec, OpenSSLX25519PrivateKey privateKey) throws InvalidKeySpecException {
        if (privateKeySpec == null) {
            throw new InvalidKeySpecException("Could not find java.security.spec.XECPrivateKeySpec");
        }

        try {
            Constructor<?> c = privateKeySpec.getConstructor(AlgorithmParameterSpec.class, byte[].class);
            @SuppressWarnings("unchecked")
            KeySpec result = (KeySpec) c.newInstance(new OpenSSLXECParameterSpec(OpenSSLXECParameterSpec.X25519), privateKey.getU());
            return result;
        } catch (NoSuchMethodException e) {
            throw new InvalidKeySpecException("Could not find java.security.spec.XECPrivateKeySpec", e);
        } catch (InstantiationException e) {
            throw new InvalidKeySpecException("Could not find java.security.spec.XECPrivateKeySpec", e);
        } catch (IllegalAccessException e) {
            throw new InvalidKeySpecException("Could not find java.security.spec.XECPrivateKeySpec", e);
        } catch (InvocationTargetException e) {
            throw new InvalidKeySpecException("Could not find java.security.spec.XECPrivateKeySpec", e);
        }
    }

    private KeySpec constructJavaPublicKeySpec(Class<?> publicKeySpec, OpenSSLX25519PublicKey publicKey) throws InvalidKeySpecException {
        try {
            Constructor<?> c = publicKeySpec.getConstructor(AlgorithmParameterSpec.class, BigInteger.class);
            @SuppressWarnings("unchecked")
            KeySpec result = (KeySpec) c.newInstance(new OpenSSLXECParameterSpec(OpenSSLXECParameterSpec.X25519), new BigInteger(1, publicKey.getU()));
            return result;
        } catch (NoSuchMethodException e) {
            throw new InvalidKeySpecException("Could not find java.security.spec.XECPublicKeySpec", e);
        } catch (InstantiationException e) {
            throw new InvalidKeySpecException("Could not find java.security.spec.XECPublicKeySpec", e);
        } catch (IllegalAccessException e) {
            throw new InvalidKeySpecException("Could not find java.security.spec.XECPublicKeySpec", e);
        } catch (InvocationTargetException e) {
            throw new InvalidKeySpecException("Could not find java.security.spec.XECPublicKeySpec", e);
        }
    }
}
