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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/** A utility class for working with KeySpecs. */
public final class KeySpecUtil {
    private KeySpecUtil() {}

    /**
     * Creates a KeySpec object for the provided keySpecClass. The KeySpec must be a subclass of
     * EncodedKeySpec and its getFormat() method must return "raw".
     */
    public static <T extends KeySpec> T makeRawKeySpec(byte[] bytes, Class<T> keySpecClass)
            throws InvalidKeySpecException {
        try {
            Constructor<T> constructor = keySpecClass.getConstructor(byte[].class);
            T instance = constructor.newInstance((Object) bytes);
            EncodedKeySpec spec = (EncodedKeySpec) instance;
            if (!spec.getFormat().equalsIgnoreCase("raw")) {
                throw new InvalidKeySpecException("EncodedKeySpec class must be raw format");
            }
            return instance;
        } catch (NoSuchMethodException | InvocationTargetException | InstantiationException
                | IllegalAccessException e) {
            throw new InvalidKeySpecException(
                    "Can't process KeySpec class " + keySpecClass.getName(), e);
        }
    }
}
