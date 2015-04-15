/*
 * Copyright 2014 The Android Open Source Project
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

import java.lang.reflect.Method;
import java.net.Socket;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLEngine;

/**
 * Reflection-based {@link PSKKeyManager} adaptor for objects which expose all the methods of the
 * {@code PSKKeyManager} interface but do not implement the interface.
 *
 * <p>This is expected to be useful on platforms where there are multiple instances of the
 * {@code PSKKeyManager} interface.
 *
 * @VisibleForTesting
 */
public class DuckTypedPSKKeyManager implements PSKKeyManager {

    private final Object mDelegate;

    private DuckTypedPSKKeyManager(Object delegate) {
        mDelegate = delegate;
    }

    /**
     * Gets an instance of {@code DuckTypedPSKKeyManager} which delegates all invocations of methods
     * of the {@link PSKKeyManager} interface to the same methods of the provided object.
     *
     * @throws NoSuchMethodException if {@code obj} does not implement a method of the
     *         {@code PSKKeyManager} interface.
     */
    public static DuckTypedPSKKeyManager getInstance(Object obj) throws NoSuchMethodException {
        Class<?> sourceClass = obj.getClass();
        for (Method targetMethod : PSKKeyManager.class.getMethods()) {
            if (targetMethod.isSynthetic()) {
                continue;
            }
            // Check that obj exposes the target method (same name and parameter types)
            Method sourceMethod =
                    sourceClass.getMethod(targetMethod.getName(), targetMethod.getParameterTypes());
            // Check that the return type of obj's method matches the target method.
            Class<?> sourceReturnType = sourceMethod.getReturnType();
            Class<?> targetReturnType = targetMethod.getReturnType();
            if (!targetReturnType.isAssignableFrom(sourceReturnType)) {
                throw new NoSuchMethodException(sourceMethod + " return value (" + sourceReturnType
                        + ") incompatible with target return value (" + targetReturnType + ")");
            }
        }

        return new DuckTypedPSKKeyManager(obj);
    }

    @Override
    public String chooseServerKeyIdentityHint(Socket socket) {
        try {
            return (String) mDelegate.getClass()
                    .getMethod("chooseServerKeyIdentityHint", Socket.class)
                    .invoke(mDelegate, socket);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke chooseServerKeyIdentityHint", e);
        }
    }

    @Override
    public String chooseServerKeyIdentityHint(SSLEngine engine) {
        try {
            return (String) mDelegate.getClass()
                    .getMethod("chooseServerKeyIdentityHint", SSLEngine.class)
                    .invoke(mDelegate, engine);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke chooseServerKeyIdentityHint", e);
        }
    }

    @Override
    public String chooseClientKeyIdentity(String identityHint, Socket socket) {
        try {
            return (String) mDelegate.getClass()
                    .getMethod("chooseClientKeyIdentity", String.class, Socket.class)
                    .invoke(mDelegate, identityHint, socket);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke chooseClientKeyIdentity", e);
        }
    }

    @Override
    public String chooseClientKeyIdentity(String identityHint, SSLEngine engine) {
        try {
            return (String) mDelegate.getClass()
                    .getMethod("chooseClientKeyIdentity", String.class, SSLEngine.class)
                    .invoke(mDelegate, identityHint, engine);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke chooseClientKeyIdentity", e);
        }
    }

    @Override
    public SecretKey getKey(String identityHint, String identity, Socket socket) {
        try {
            return (SecretKey) mDelegate.getClass()
                    .getMethod("getKey", String.class, String.class, Socket.class)
                    .invoke(mDelegate, identityHint, identity, socket);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke getKey", e);
        }
    }

    @Override
    public SecretKey getKey(String identityHint, String identity, SSLEngine engine) {
        try {
            return (SecretKey) mDelegate.getClass()
                    .getMethod("getKey", String.class, String.class, SSLEngine.class)
                    .invoke(mDelegate, identityHint, identity, engine);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke getKey", e);
        }
    }
}
