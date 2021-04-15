/*
 * Copyright (C) 2020 The Android Open Source Project
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
package org.conscrypt.metrics;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.conscrypt.Internal;

/**
 * Helper class to handle reflexive loading and invocation of methods which may be absent.
 *
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public final class OptionalMethod {
    private final Method cachedMethod;

    /**
     * Instantiates a new OptionalMethod.
     * <p>Does not throw any exceptions if the class or method can't be loaded, or if any parameter
     * classes are {@code null} and instead behaves as a no-op, always returning {@code null}.
     *
     * @param clazz the Class to search for methods on
     * @param methodName the name of the {@code Method} on {@code clazz}
     * @param methodParams list of {@code Classes} of the {@code Method's} parameters
     *
     * @throws NullPointerException if the method name is {@code null}
     */
    public OptionalMethod(Class<?> clazz, String methodName, Class<?>... methodParams) {
        this.cachedMethod = initializeMethod(clazz, methodName, methodParams);
    }

    private static Method initializeMethod(
            Class<?> clazz, String methodName, Class<?>... methodParams) {
        try {
            for (Class<?> paramClass : methodParams) {
                if (paramClass == null) {
                    return null;
                }
            }
            if (clazz != null) {
                return clazz.getMethod(checkNotNull(methodName), methodParams);
            }
        } catch (NoSuchMethodException ignored) {
            // Ignored
        }
        return null;
    }

    public Object invoke(Object target, Object... args) {
        // no-op if failed to load method in constructor
        if (cachedMethod == null) {
            return null;
        }
        try {
            return cachedMethod.invoke(target, args);
        } catch (IllegalAccessException ignored) {
            // Ignored
        } catch (InvocationTargetException ignored) {
            // Ignored
        }
        return null;
    }

    private static <T> T checkNotNull(T reference) {
        if (reference == null) {
            throw new NullPointerException();
        }
        return reference;
    }
}
