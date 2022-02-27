/*
 * Copyright (C) 2022 The Android Open Source Project
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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;

@Internal
public class ScryptSecretKeyFactory extends SecretKeyFactorySpi {


    @Override
    protected SecretKey engineGenerateSecret(KeySpec inKeySpec) throws InvalidKeySpecException {
        byte[] keyBytes;

        if (inKeySpec instanceof ScryptKeySpec) {
            ScryptKeySpec spec = (ScryptKeySpec) inKeySpec;
            keyBytes = NativeCrypto.Scrypt_generate_key(
                    spec.getPassword(),
                    spec.getSalt(),
                    spec.getN(),
                    spec.getR(),
                    spec.getP(),
                    spec.getKeyLength());
        } else {
            byte[] password, salt;
            long n, r, p;
            int keyLen;
            try {
                // Duck typing by reflection
                password = getBytes(inKeySpec, "getPassword");
                salt = getBytes(inKeySpec, "getSalt");
                n = getLong(inKeySpec, "getN");
                r = getLong(inKeySpec, "getR");
                p = getLong(inKeySpec, "getP");
                keyLen = getInt(inKeySpec, "getKeyLength");
            } catch (Exception e) {
                throw new InvalidKeySpecException("Quack", e);
            }

            keyBytes = NativeCrypto.Scrypt_generate_key(password, salt, n, r, p, keyLen);
        }

        return new ScryptKey(keyBytes);
    }

    // Should be able to generify these methods, but mañana
    private byte[] getBytes(KeySpec spec, String methodName)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        return (byte[]) getValue(spec, methodName);
    }

    private long getLong(KeySpec spec, String methodName)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        return (long) getValue(spec, methodName);
    }

    private int getInt(KeySpec spec, String methodName)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        return (int) getValue(spec, methodName);
    }

    private Object getValue(KeySpec spec, String methodName) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Method method = spec.getClass().getMethod(methodName, (Class<?>[]) null);
        return method.invoke(spec);
    }


    @Override
    protected KeySpec engineGetKeySpec(SecretKey secretKey,
            @SuppressWarnings("rawtypes") Class aClass) throws InvalidKeySpecException {
        if (secretKey == null) {
            throw new InvalidKeySpecException("Null KeySpec");
        }
        throw new NotImplementedException();
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey secretKey) throws InvalidKeyException {
        if (secretKey == null) {
            throw new InvalidKeyException("Null SecretKey");
        }
        throw new NotImplementedException();
    }

    private static class ScryptKey implements SecretKey {
        private static final long serialVersionUID = 8773369892581634608L;
        private final byte[] key;

        public ScryptKey(byte[] key) {
            this.key = key;
        }

        @Override
        public String getAlgorithm() {
            return "Scrypt";
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            return key;
        }
    }

    private static class NotImplementedException extends RuntimeException {
        NotImplementedException() {
            super("Not implemented");
        }
    }
}
