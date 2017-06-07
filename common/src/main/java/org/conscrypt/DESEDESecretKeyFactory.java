/*
 * Copyright (C) 2017 The Android Open Source Project
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

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * An implementation of {@link javax.crypto.SecretKeyFactory} for use with DESEDE keys.  This
 * class supports {@link SecretKeySpec} and {@link DESedeKeySpec} for key specs.
 *
 * @hide
 */
@Internal
public class DESEDESecretKeyFactory extends SecretKeyFactorySpi {
    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("Null KeySpec");
        }
        if (keySpec instanceof SecretKeySpec) {
            return (SecretKey) keySpec;
        } else if (keySpec instanceof DESedeKeySpec) {
            DESedeKeySpec desKeySpec = (DESedeKeySpec) keySpec;
            return new SecretKeySpec(desKeySpec.getKey(), "DESEDE");
        } else {
            throw new InvalidKeySpecException(
                    "Unsupported KeySpec class: " + keySpec.getClass().getName());
        }
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey secretKey, Class<?> aClass)
            throws InvalidKeySpecException {
        if (secretKey == null) {
            throw new InvalidKeySpecException("Null SecretKey");
        }
        if (aClass == SecretKeySpec.class) {
            if (secretKey instanceof SecretKeySpec) {
                return (KeySpec) secretKey;
            } else {
                return new SecretKeySpec(secretKey.getEncoded(), "DESEDE");
            }
        } else if (aClass == DESedeKeySpec.class) {
            try {
                return new DESedeKeySpec(secretKey.getEncoded());
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException(e);
            }
        } else {
            throw new InvalidKeySpecException("Unsupported KeySpec class: " + aClass);
        }
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey secretKey) throws InvalidKeyException {
        if (secretKey == null) {
            throw new InvalidKeyException("Null SecretKey");
        }
        return new SecretKeySpec(secretKey.getEncoded(), secretKey.getAlgorithm());
    }
}
