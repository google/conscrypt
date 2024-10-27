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

package org.conscrypt;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import junit.framework.TestCase;

public class DuckTypedPSKKeyManagerTest extends TestCase {
    private SSLSocket mSSLSocket;
    private SSLEngine mSSLEngine;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SSLContext sslContext = SSLContext.getDefault();
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        mSSLSocket = (SSLSocket) sslSocketFactory.createSocket();
        mSSLEngine = sslContext.createSSLEngine();
    }

    @Override
    protected void tearDown() throws Exception {
        try {
            if (mSSLSocket != null) {
                try {
                    mSSLSocket.close();
                } catch (Exception ignored) {}
            }
        } finally {
            super.tearDown();
        }
    }

    @SuppressWarnings("deprecation")
    public void testDuckTypingFailsWhenOneMethodMissing() throws Exception {
        try {
            DuckTypedPSKKeyManager.getInstance(new AlmostPSKKeyManager());
            fail();
        } catch (NoSuchMethodException expected) {}
    }

    @SuppressWarnings("deprecation")
    public void testDuckTypingFailsWhenOneMethodReturnTypeIncompatible() throws Exception {
        try {
            assertNotNull(DuckTypedPSKKeyManager.getInstance(
                    new KeyManagerOfferingAllPSKKeyManagerMethodsWithIncompatibleReturnTypes()));
        fail();
        } catch (NoSuchMethodException expected) {}
    }

    @SuppressWarnings("deprecation")
    public void testDuckTypingSucceedsWhenAllMethodsPresentWithExactReturnTypes() throws Exception {
        assertNotNull(DuckTypedPSKKeyManager.getInstance(
                new KeyManagerOfferingAllPSKKeyManagerMethodsWithExactReturnTypes()));
    }

    @SuppressWarnings("deprecation")
    public void testDuckTypingSucceedsWhenAllMethodsPresentWithDifferentButCompatibleReturnTypes()
            throws Exception {
        assertNotNull(DuckTypedPSKKeyManager.getInstance(
                new KeyManagerOfferingAllPSKKeyManagerMethodsWithCompatibleReturnTypes()));
    }

    public void testMethodInvocationDelegation() throws Exception {
        // IMPLEMENTATION NOTE: We create a DuckTypedPSKKeyManager wrapping a Reflection Proxy,
        // invoke each method of the PSKKeyManager interface on the DuckTypedPSKKeyManager instance,
        // and assert that invocations on the Proxy are as expected and that values returned by the
        // Proxy are returned to us.

        MockInvocationHandler mockInvocationHandler = new MockInvocationHandler();
        @SuppressWarnings("deprecation")
        PSKKeyManager delegate = (PSKKeyManager) Proxy.newProxyInstance(
                DuckTypedPSKKeyManager.class.getClassLoader(), new Class<?>[] {PSKKeyManager.class},
                mockInvocationHandler);
        @SuppressWarnings("deprecation")
        PSKKeyManager pskKeyManager = DuckTypedPSKKeyManager.getInstance(delegate);
        String identityHint = "hint";
        String identity = "identity";

        mockInvocationHandler.returnValue = identityHint;
        assertSame(identityHint, pskKeyManager.chooseServerKeyIdentityHint(mSSLSocket));
        assertEquals("chooseServerKeyIdentityHint",
                mockInvocationHandler.lastInvokedMethod.getName());
        assertEquals(Arrays.asList(new Class<?>[] {Socket.class}),
                Arrays.asList(mockInvocationHandler.lastInvokedMethod.getParameterTypes()));
        assertEquals(1, mockInvocationHandler.lastInvokedMethodArgs.length);
        assertSame(mSSLSocket, mockInvocationHandler.lastInvokedMethodArgs[0]);

        mockInvocationHandler.returnValue = identityHint;
        assertSame(identityHint, pskKeyManager.chooseServerKeyIdentityHint(mSSLEngine));
        assertEquals("chooseServerKeyIdentityHint",
                mockInvocationHandler.lastInvokedMethod.getName());
        assertEquals(Arrays.asList(new Class<?>[] {SSLEngine.class}),
                Arrays.asList(mockInvocationHandler.lastInvokedMethod.getParameterTypes()));
        assertEquals(1, mockInvocationHandler.lastInvokedMethodArgs.length);
        assertSame(mSSLEngine, mockInvocationHandler.lastInvokedMethodArgs[0]);

        mockInvocationHandler.returnValue = identity;
        assertSame(identity, pskKeyManager.chooseClientKeyIdentity(identityHint, mSSLSocket));
        assertEquals("chooseClientKeyIdentity", mockInvocationHandler.lastInvokedMethod.getName());
        assertEquals(Arrays.asList(new Class<?>[] {String.class, Socket.class}),
                Arrays.asList(mockInvocationHandler.lastInvokedMethod.getParameterTypes()));
        assertEquals(2, mockInvocationHandler.lastInvokedMethodArgs.length);
        assertSame(identityHint, mockInvocationHandler.lastInvokedMethodArgs[0]);
        assertSame(mSSLSocket, mockInvocationHandler.lastInvokedMethodArgs[1]);

        mockInvocationHandler.returnValue = identity;
        assertSame(identity, pskKeyManager.chooseClientKeyIdentity(identityHint, mSSLEngine));
        assertEquals("chooseClientKeyIdentity", mockInvocationHandler.lastInvokedMethod.getName());
        assertEquals(Arrays.asList(new Class<?>[] {String.class, SSLEngine.class}),
                Arrays.asList(mockInvocationHandler.lastInvokedMethod.getParameterTypes()));
        assertEquals(2, mockInvocationHandler.lastInvokedMethodArgs.length);
        assertSame(identityHint, mockInvocationHandler.lastInvokedMethodArgs[0]);
        assertSame(mSSLEngine, mockInvocationHandler.lastInvokedMethodArgs[1]);

        SecretKey key = new SecretKeySpec("arbitrary".getBytes(StandardCharsets.UTF_8), "RAW");
        mockInvocationHandler.returnValue = key;
        assertSame(key, pskKeyManager.getKey(identityHint, identity, mSSLSocket));
        assertEquals("getKey", mockInvocationHandler.lastInvokedMethod.getName());
        assertEquals(Arrays.asList(new Class<?>[] {String.class, String.class, Socket.class}),
                Arrays.asList(mockInvocationHandler.lastInvokedMethod.getParameterTypes()));
        assertEquals(3, mockInvocationHandler.lastInvokedMethodArgs.length);
        assertSame(identityHint, mockInvocationHandler.lastInvokedMethodArgs[0]);
        assertSame(identity, mockInvocationHandler.lastInvokedMethodArgs[1]);
        assertSame(mSSLSocket, mockInvocationHandler.lastInvokedMethodArgs[2]);

        mockInvocationHandler.returnValue = key;
        assertSame(key, pskKeyManager.getKey(identityHint, identity, mSSLEngine));
        assertEquals("getKey", mockInvocationHandler.lastInvokedMethod.getName());
        assertEquals(Arrays.asList(new Class<?>[] {String.class, String.class, SSLEngine.class}),
                Arrays.asList(mockInvocationHandler.lastInvokedMethod.getParameterTypes()));
        assertEquals(3, mockInvocationHandler.lastInvokedMethodArgs.length);
        assertSame(identityHint, mockInvocationHandler.lastInvokedMethodArgs[0]);
        assertSame(identity, mockInvocationHandler.lastInvokedMethodArgs[1]);
        assertSame(mSSLEngine, mockInvocationHandler.lastInvokedMethodArgs[2]);
    }

    public void testMethodInvocationDelegationWithDifferentButCompatibleReturnType()
            throws Exception {
        // Check that nothing blows up when we invoke getKey which is declared to return
        // SecretKeySpec rather than SecretKey as declared in the PSKKeyManager interface.
        @SuppressWarnings("deprecation")
        PSKKeyManager pskKeyManager = DuckTypedPSKKeyManager.getInstance(
                new KeyManagerOfferingAllPSKKeyManagerMethodsWithCompatibleReturnTypes());
        pskKeyManager.getKey(null, "", mSSLSocket);
        pskKeyManager.getKey(null, "", mSSLEngine);
    }

    /**
     * {@link KeyManager} which implements all methods of {@link PSKKeyManager} except for one.
     */
    @SuppressWarnings("unused")
    private static class AlmostPSKKeyManager implements KeyManager {
        public String chooseServerKeyIdentityHint(Socket socket) {
            return null;
        }

        public String chooseServerKeyIdentityHint(SSLEngine engine) {
            return null;
        }

        public String chooseClientKeyIdentity(String identityHint, Socket socket) {
            return null;
        }

        public String chooseClientKeyIdentity(String identityHint, SSLEngine engine) {
            return null;
        }

        public SecretKey getKey(String identityHint, String identity, Socket socket) {
            return null;
        }

        // Missing method from the PSKKeyManager interface:
        // SecretKey getKey(String identityHint, String identity, SSLEngine engine);
    }

    /**
     * {@link KeyManager} which exposes all methods of the {@link PSKKeyManager} interface but does
     * not implement the interface.
     */
    @SuppressWarnings("unused")
    private static class KeyManagerOfferingAllPSKKeyManagerMethodsWithExactReturnTypes
            implements KeyManager {
        public String chooseServerKeyIdentityHint(Socket socket) {
            return null;
        }

        public String chooseServerKeyIdentityHint(SSLEngine engine) {
            return null;
        }

        public String chooseClientKeyIdentity(String identityHint, Socket socket) {
            return null;
        }

        public String chooseClientKeyIdentity(String identityHint, SSLEngine engine) {
            return null;
        }

        public SecretKey getKey(String identityHint, String identity, Socket socket) {
            return null;
        }

        public SecretKey getKey(String identityHint, String identity, SSLEngine engine) {
            return null;
        }
    }

    /**
     * {@link KeyManager} which exposes all methods of the {@link PSKKeyManager} interface but does
     * not implement the interface. Additionally, the return types of some methods are different
     * but compatible with the {@code PSKKeyManager} interface.
     */
    @SuppressWarnings("unused")
    private static class KeyManagerOfferingAllPSKKeyManagerMethodsWithCompatibleReturnTypes
            implements KeyManager {
        public String chooseServerKeyIdentityHint(Socket socket) {
            return null;
        }

        public String chooseServerKeyIdentityHint(SSLEngine engine) {
            return null;
        }

        public String chooseClientKeyIdentity(String identityHint, Socket socket) {
            return null;
        }

        public String chooseClientKeyIdentity(String identityHint, SSLEngine engine) {
            return null;
        }

        // PSKKeyManager's return type: SecretKey
        public SecretKeySpec getKey(String identityHint, String identity, Socket socket) {
            return null;
        }

        // PSKKeyManager's return type: SecretKey
        public SecretKeySpec getKey(String identityHint, String identity, SSLEngine engine) {
            return null;
        }
    }

    /**
     * {@link KeyManager} which exposes all methods of the {@link PSKKeyManager} interface but does
     * not implement the interface. Additionally, the return types of some methods are incompatible
     * with the {@code PSKKeyManager} interface.
     */
    @SuppressWarnings("unused")
    private static class KeyManagerOfferingAllPSKKeyManagerMethodsWithIncompatibleReturnTypes
            implements KeyManager {
        public String chooseServerKeyIdentityHint(Socket socket) {
            return null;
        }

        public String chooseServerKeyIdentityHint(SSLEngine engine) {
            return null;
        }

        public String chooseClientKeyIdentity(String identityHint, Socket socket) {
            return null;
        }

        public String chooseClientKeyIdentity(String identityHint, SSLEngine engine) {
            return null;
        }

        public SecretKey getKey(String identityHint, String identity, Socket socket) {
            return null;
        }

        // PSKKeyManager's return type: SecretKey
        public Key getKey(String identityHint, String identity, SSLEngine engine) {
            return null;
        }
    }

    static class MockInvocationHandler implements InvocationHandler {
        Object returnValue;
        Method lastInvokedMethod;
        Object[] lastInvokedMethodArgs;

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            lastInvokedMethod = method;
            lastInvokedMethodArgs = args;
            return returnValue;
        }
    }
}
