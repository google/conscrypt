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
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * An implementation of a {@link KeyFactorySpi} for XEC keys based on BoringSSL.
 */
@Internal
public final class OpenSSLXDHKeyFactory extends KeyFactorySpi {
    private static final Class<?> javaXecPublicKeySpec = getJavaXECPublicKeySpec();
    private static final Class<?> javaXecPrivateKeySpec = getJavaXECPrivateKeySpec();
    private static final AlgorithmParameterSpec javaX25519AlgorithmSpec
            = getJavaX25519ParameterSpec();

    public OpenSSLXDHKeyFactory() {}

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }
        if (keySpec instanceof EncodedKeySpec) {
            return new OpenSSLX25519PublicKey((EncodedKeySpec) keySpec);
        }
        throw new InvalidKeySpecException(
                "Must use XECPublicKeySpec, X509EncodedKeySpec or Raw EncodedKeySpec; was "
                + keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }
        if (keySpec instanceof EncodedKeySpec) {
            return new OpenSSLX25519PrivateKey((EncodedKeySpec) keySpec);
        }
        throw new InvalidKeySpecException(
                "Must use XECPrivateKeySpec, PKCS8EncodedKeySpec or Raw EncodedKeySpec; was "
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
        // Support XDH or X25519 algorithm names per JEP 324
        if (!"XDH".equals(key.getAlgorithm()) && !"X25519".equals(key.getAlgorithm()) ) {
            throw new InvalidKeySpecException("Key must be an XDH or X25519 key");
        }
        if (key.getEncoded() == null) {
            throw new InvalidKeySpecException("Key is destroyed");
        }
        // Convert any "foreign" keys to our own type, this has the same requirements as
        // converting to a KeySpec below, and is a no-op for our own keys.
        try {
            key = engineTranslateKey(key);
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Unsupported key class: " + key.getClass(), e);
        }

        if (key instanceof OpenSSLX25519PublicKey) {
            OpenSSLX25519PublicKey conscryptKey = (OpenSSLX25519PublicKey) key;
            if (javaXecPublicKeySpec != null && javaXecPublicKeySpec.isAssignableFrom(keySpec)) {
                @SuppressWarnings("unchecked")
                T result = (T) constructJavaXecPublicKeySpec(conscryptKey);
                return result;
            } else if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                @SuppressWarnings("unchecked")
                T result = (T) new X509EncodedKeySpec(key.getEncoded());
                return result;
            } else if (keySpec == XdhKeySpec.class) {
                @SuppressWarnings("unchecked")
                T result = (T) new XdhKeySpec(conscryptKey.getU());
                return result;
            } else if (EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return makeRawKeySpec(conscryptKey.getU(), keySpec);
            }
        } else if (key instanceof OpenSSLX25519PrivateKey) {
            OpenSSLX25519PrivateKey conscryptKey = (OpenSSLX25519PrivateKey) key;
            if (javaXecPrivateKeySpec != null && javaXecPrivateKeySpec.isAssignableFrom(keySpec)) {
                @SuppressWarnings("unchecked")
                T result = (T) constructJavaPrivateKeySpec(conscryptKey);
                return result;
            } else if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                @SuppressWarnings("unchecked")
                T result = (T) new PKCS8EncodedKeySpec(key.getEncoded());
                return result;
            } else if (keySpec == XdhKeySpec.class) {
                @SuppressWarnings("unchecked")
                T result = (T) new XdhKeySpec(conscryptKey.getU());
                return result;
            } else if (EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return makeRawKeySpec(conscryptKey.getU(), keySpec);
            }
        }
        throw new InvalidKeySpecException("Unsupported key type and key spec combination; key="
                + key.getClass().getName() + ", keySpec=" + keySpec.getName());
    }

    private <T extends KeySpec> T makeRawKeySpec(byte[] bytes, Class<T> keySpecClass)
            throws InvalidKeySpecException {
        try {
            Constructor<T> constructor = keySpecClass.getConstructor(byte[].class);
            T instance = constructor.newInstance((Object) bytes);
            EncodedKeySpec spec = (EncodedKeySpec) instance;
            if (!spec.getFormat().equalsIgnoreCase("raw")) {
                throw new InvalidKeySpecException("EncodedKeySpec class must be raw format");
            }
            return instance;
        } catch (NoSuchMethodException | InvocationTargetException | InstantiationException |
                 IllegalAccessException e) {
            throw new InvalidKeySpecException(
                    "Can't process KeySpec class " + keySpecClass.getName(), e);
        }
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
            throw new InvalidKeyException("Key must be XEC public or private key; was "
                    + key.getClass().getName());
        }
    }

    private static Class<?> getJavaXECPrivateKeySpec() {
        try {
            return Class.forName("java.security.spec.XECPrivateKeySpec");
        } catch (ClassNotFoundException ignored) {
            return null;
        }
    }

  private static Class<?> getJavaXECPublicKeySpec() {
    try {
      return Class.forName("java.security.spec.XECPublicKeySpec");
    } catch (ClassNotFoundException ignored) {
      return null;
    }
  }

  private static AlgorithmParameterSpec getJavaX25519ParameterSpec() {
    try {
      Class<?> cls = Class.forName("java.security.spec.NamedParameterSpec");
      Field field = cls.getDeclaredField("X25519");
      Object result = field.get(null);
      return (AlgorithmParameterSpec) result;
    } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException ignored) {
      return null;
    }
  }

  private KeySpec constructJavaPrivateKeySpec(OpenSSLX25519PrivateKey privateKey)
            throws InvalidKeySpecException {
      if (OpenSSLXDHKeyFactory.javaXecPrivateKeySpec == null) {
          throw new InvalidKeySpecException("Could not find java.security.spec.XECPrivateKeySpec");
      }
      try {
            Constructor<?> c = OpenSSLXDHKeyFactory.javaXecPrivateKeySpec.getConstructor(
                    AlgorithmParameterSpec.class, byte[].class);
            @SuppressWarnings("unchecked")
            KeySpec result = (KeySpec) c.newInstance(javaX25519AlgorithmSpec, privateKey.getU());
            return result;
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException |
                 InvocationTargetException e) {
          throw new InvalidKeySpecException(
                    "Could not find java.security.spec.XECPrivateKeySpec", e);
        }
    }

    private KeySpec constructJavaXecPublicKeySpec(OpenSSLX25519PublicKey publicKey)
            throws InvalidKeySpecException {
        if (OpenSSLXDHKeyFactory.javaXecPublicKeySpec == null) {
            throw new InvalidKeySpecException("Could not find java.security.spec.XECPublicKeySpec");
        }
        try {
            Constructor<?> c = OpenSSLXDHKeyFactory.javaXecPublicKeySpec.getConstructor(
                    AlgorithmParameterSpec.class, BigInteger.class);
            @SuppressWarnings("unchecked")
            KeySpec result = (KeySpec) c.newInstance(javaX25519AlgorithmSpec,
                    new BigInteger(1, ArrayUtils.reverse(publicKey.getU())));
            return result;
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException |
                 InvocationTargetException e) {
            throw new InvalidKeySpecException(
                    "Could not find java.security.spec.XECPublicKeySpec", e);
        }
    }
}
