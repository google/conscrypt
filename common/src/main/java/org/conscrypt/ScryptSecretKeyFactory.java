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
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;

@Internal
public class ScryptSecretKeyFactory extends SecretKeyFactorySpi {

    @Override
    protected SecretKey engineGenerateSecret(KeySpec inKeySpec) throws InvalidKeySpecException {

        char[] password;
        byte[] salt;
        int n, r, p, keyOutputBits;

        if (inKeySpec instanceof ScryptKeySpec) {
            ScryptKeySpec spec = (ScryptKeySpec) inKeySpec;
            password = spec.getPassword();
            salt = spec.getSalt();
            n = spec.getCostParameter();
            r = spec.getBlockSize();
            p = spec.getParallelizationParameter();
            keyOutputBits = spec.getKeyLength();
        } else {
            // Extract parameters from any `KeySpec` that has getters with the correct name. This
            // allows, for example, code to use BouncyCastle's KeySpec with the Conscrypt provider.
            try {
                password = (char[]) getValue(inKeySpec, "getPassword");
                salt = (byte[]) getValue(inKeySpec, "getSalt");
                n = (int) getValue(inKeySpec, "getCostParameter");
                r = (int) getValue(inKeySpec, "getBlockSize");
                p = (int) getValue(inKeySpec, "getParallelizationParameter");
                keyOutputBits = (int) getValue(inKeySpec, "getKeyLength");
            } catch (Exception e) {
                throw new InvalidKeySpecException("Not a valid scrypt KeySpec", e);
            }
        }

        if (keyOutputBits % 8 != 0) {
            throw new InvalidKeySpecException("Cannot produce fractional-byte outputs");
        }

        return new ScryptKey(
                NativeCrypto.Scrypt_generate_key(
                        new String(password).getBytes(StandardCharsets.UTF_8),
                        salt, n, r, p, keyOutputBits / 8));
    }

    private Object getValue(KeySpec spec, String methodName)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Method method = spec.getClass().getMethod(methodName, (Class<?>[]) null);
        return method.invoke(spec);
    }

    @Override
    protected KeySpec engineGetKeySpec(
            SecretKey secretKey, @SuppressWarnings("rawtypes") Class aClass)
            throws InvalidKeySpecException {
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
        private static final long serialVersionUID = 2024924811854189128L;
        private final byte[] key;

        public ScryptKey(byte[] key) {
            this.key = key;
        }

        @Override
        public String getAlgorithm() {
            // Capitalised because BouncyCastle does it.
            return "SCRYPT";
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
        private static final long serialVersionUID = -7755435858585859108L;

        NotImplementedException() {
            super("Not implemented");
        }
    }
}
