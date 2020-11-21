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
 * Helper class to handle reflection methods loading and invoking.
 * Does not throw any exceptions and instead behaves as a no-op
 * in case method (or class) couldn't be loaded.
 */
@Internal
final class OptionalMethod {
    private final Method cachedMethod;

    public OptionalMethod(Class<?> clazz, String methodName, Class... methodParams) {
        this.cachedMethod = initializeMethod(clazz, methodName, methodParams);
    }

    private static Method initializeMethod(
            Class<?> clazz, String methodName, Class... methodParams) {
        try {
            return clazz.getMethod(methodName, methodParams);
        } catch (NoSuchMethodException ignored) {
            return null;
        }
    }

    public Object invoke(Object target, Object... args) {
        // no-op if failed to load method in constructor
        if (cachedMethod == null) {
            return null;
        }
        try {
            return cachedMethod.invoke(target, args);
        } catch (IllegalAccessException ignored) {
        } catch (InvocationTargetException ignored) {
        }
        return null;
    }
}
