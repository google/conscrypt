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
package org.conscrypt.javax.net.ssl;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.Socket;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import org.conscrypt.TestUtils;

/**
 * Reflection-based implementation of {@code PSKKeyManager} from Conscrypt on which these tests
 * cannot depend directly.
 */
class PSKKeyManagerProxy implements InvocationHandler {
    static KeyManager getConscryptPSKKeyManager(PSKKeyManagerProxy delegate) {
        Class<?> pskKeyManagerInterface;
        try {
            pskKeyManagerInterface = TestUtils.conscryptClass("PSKKeyManager");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        return (KeyManager) Proxy.newProxyInstance(
                PSKKeyManagerProxy.class.getClassLoader(),
                new Class<?>[] {pskKeyManagerInterface},
                delegate);
    }
    @SuppressWarnings("unused")
    protected SecretKey getKey(String identityHint, String identity, Socket socket) {
        return null;
    }
    @SuppressWarnings("unused")
    protected SecretKey getKey(String identityHint, String identity, SSLEngine engine) {
        return null;
    }
    @SuppressWarnings("unused")
    protected String chooseServerKeyIdentityHint(Socket socket) {
        return null;
    }
    @SuppressWarnings("unused")
    protected String chooseServerKeyIdentityHint(SSLEngine engine) {
        return null;
    }
    @SuppressWarnings("unused")
    protected String chooseClientKeyIdentity(String identityHint, Socket socket) {
        return null;
    }
    @SuppressWarnings("unused")
    protected String chooseClientKeyIdentity(String identityHint, SSLEngine engine) {
        return null;
    }
    @Override
    public final Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        String methodName = method.getName();
        Class<?>[] parameterTypes = method.getParameterTypes();
        boolean sslEngineVariant = (parameterTypes.length > 0)
                && SSLEngine.class.equals(parameterTypes[parameterTypes.length - 1]);
        if ("getKey".equals(methodName)) {
            if (sslEngineVariant) {
                return getKey((String) args[0], (String) args[1], (SSLEngine) args[2]);
            } else {
                return getKey((String) args[0], (String) args[1], (Socket) args[2]);
            }
        } else if ("chooseServerKeyIdentityHint".equals(methodName)) {
            if (sslEngineVariant) {
                return chooseServerKeyIdentityHint((SSLEngine) args[0]);
            } else {
                return chooseServerKeyIdentityHint((Socket) args[0]);
            }
        } else if ("chooseClientKeyIdentity".equals(methodName)) {
            if (sslEngineVariant) {
                return chooseClientKeyIdentity((String) args[0], (SSLEngine) args[1]);
            } else {
                return chooseClientKeyIdentity((String) args[0], (Socket) args[1]);
            }
        } else {
            throw new IllegalArgumentException("Unexpected method: " + method);
        }
    }
}
