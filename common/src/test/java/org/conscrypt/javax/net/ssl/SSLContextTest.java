/*
 * Copyright (C) 2010 The Android Open Source Project
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

import static org.conscrypt.TestUtils.isTlsV1Supported;
import static org.conscrypt.TestUtils.isWindows;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509KeyManager;
import junit.framework.AssertionFailedError;
import org.conscrypt.TestUtils;
import org.conscrypt.java.security.StandardNames;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SSLContextTest {

    @Test
    public void test_SSLContext_getDefault() throws Exception {
        SSLContext sslContext = SSLContext.getDefault();
        assertNotNull(sslContext);
        try {
            sslContext.init(null, null, null);
            fail();
        } catch (KeyManagementException expected) {
            // Ignored.
        }
    }

    @Test
    public void test_SSLContext_setDefault() throws Exception {
        try {
            SSLContext.setDefault(null);
            fail();
        } catch (NullPointerException expected) {
            // Ignored.
        }

        SSLContext defaultContext = SSLContext.getDefault();
        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            SSLContext oldContext = SSLContext.getDefault();
            assertNotNull(oldContext);
            SSLContext newContext = SSLContext.getInstance(protocol);
            assertNotNull(newContext);
            assertNotSame(oldContext, newContext);
            SSLContext.setDefault(newContext);
            assertSame(newContext, SSLContext.getDefault());
        }
        SSLContext.setDefault(defaultContext);
    }

    @Test
    public void test_SSLContext_defaultConfiguration() throws Exception {
        SSLConfigurationAsserts.assertSSLContextDefaultConfiguration(SSLContext.getDefault());

        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS_WITH_DEFAULT_CONFIG) {
            SSLContext sslContext = SSLContext.getInstance(protocol);
            if (!protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                sslContext.init(null, null, null);
            }
            SSLConfigurationAsserts.assertSSLContextDefaultConfiguration(sslContext);
        }
    }

    @Test
    public void test_SSLContext_allProtocols() throws Exception {
        SSLConfigurationAsserts.assertSSLContextDefaultConfiguration(SSLContext.getDefault());

        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            SSLContext sslContext = SSLContext.getInstance(protocol);
            if (!protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                sslContext.init(null, null, null);
            }
        }
    }

    @Test
    public void test_SSLContext_pskOnlyConfiguration_defaultProviderOnly() throws Exception {
        // Test the scenario where only a PSKKeyManager is provided and no TrustManagers are
        // provided.
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(new KeyManager[] { PSKKeyManagerProxy.getConscryptPSKKeyManager(
                                new PSKKeyManagerProxy())},
                new TrustManager[0], null);
        List<String> expectedCipherSuites =
                new ArrayList<String>(StandardNames.CIPHER_SUITES_TLS13);
        expectedCipherSuites.addAll(StandardNames.CIPHER_SUITES_DEFAULT_PSK);
        expectedCipherSuites.add(StandardNames.CIPHER_SUITE_SECURE_RENEGOTIATION);
        assertEnabledCipherSuites(expectedCipherSuites, sslContext);
    }

    @Test
    public void test_SSLContext_x509AndPskConfiguration_defaultProviderOnly() throws Exception {
        // Test the scenario where an X509TrustManager and PSKKeyManager are provided.
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(new KeyManager[] {PSKKeyManagerProxy.getConscryptPSKKeyManager(
                                new PSKKeyManagerProxy())},
                null, // Use default trust managers, one of which is an X.509 one.
                null);
        // The TLS 1.3 cipher suites appear before the PSK ones, so we need to dedup them
        Set<String> expectedCipherSuiteSet = new LinkedHashSet<String>();
        expectedCipherSuiteSet.addAll(StandardNames.CIPHER_SUITES_TLS13);
        expectedCipherSuiteSet.addAll(StandardNames.CIPHER_SUITES_DEFAULT_PSK);
        expectedCipherSuiteSet.addAll(StandardNames.CIPHER_SUITES_DEFAULT);
        List<String> expectedCipherSuites = new ArrayList<String>(expectedCipherSuiteSet);
        assertEnabledCipherSuites(expectedCipherSuites, sslContext);

        // Test the scenario where an X509KeyManager and PSKKeyManager are provided.
        sslContext = SSLContext.getInstance("TLS");
        // Just an arbitrary X509KeyManager -- it won't be invoked in this test.
        X509KeyManager x509KeyManager = new RandomPrivateKeyX509ExtendedKeyManager(null);
        sslContext.init(
                new KeyManager[] {x509KeyManager,
                        PSKKeyManagerProxy.getConscryptPSKKeyManager(new PSKKeyManagerProxy())},
                new TrustManager[0], null);
        assertEnabledCipherSuites(expectedCipherSuites, sslContext);
    }

    @Test
    public void test_SSLContext_emptyConfiguration_defaultProviderOnly() throws Exception {
        // Test the scenario where neither X.509 nor PSK KeyManagers or TrustManagers are provided.
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(new KeyManager[0], new TrustManager[0], null);
        // No TLS 1.2 cipher suites should be enabled, since neither PSK nor X.509 key exchange
        // can be done.  The TLS 1.3 cipher suites should be there, since key exchange isn't
        // part of the cipher suite in 1.3.
        List<String> expected = new ArrayList<String>(StandardNames.CIPHER_SUITES_TLS13);
        expected.add(StandardNames.CIPHER_SUITE_SECURE_RENEGOTIATION);
        assertEnabledCipherSuites(expected, sslContext);
    }

    @Test
    public void test_SSLContext_init_correctProtocolVersionsEnabled() throws Exception {
        for (String tlsVersion : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            // Don't test the "Default" instance.
            if (StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT.equals(tlsVersion)) {
                continue;
            }

            SSLContext context = SSLContext.getInstance(tlsVersion);
            context.init(null, null, null);

            StandardNames.assertSSLContextEnabledProtocols(
                    tlsVersion, ((SSLSocket) context.getSocketFactory().createSocket())
                                        .getEnabledProtocols());
            StandardNames.assertSSLContextEnabledProtocols(tlsVersion,
                    ((SSLServerSocket) context.getServerSocketFactory().createServerSocket())
                            .getEnabledProtocols());
            StandardNames.assertSSLContextEnabledProtocols(
                    tlsVersion, context.getDefaultSSLParameters().getProtocols());
            StandardNames.assertSSLContextEnabledProtocols(
                    tlsVersion, context.createSSLEngine().getEnabledProtocols());
        }
    }

    private static void assertEnabledCipherSuites(
            List<String> expectedCipherSuites, SSLContext sslContext) throws Exception {
        TestUtils.assumeSetEndpointIdentificationAlgorithmAvailable();
        assertContentsInOrder(
                expectedCipherSuites, sslContext.createSSLEngine().getEnabledCipherSuites());
        assertContentsInOrder(expectedCipherSuites,
                sslContext.createSSLEngine().getSSLParameters().getCipherSuites());
        assertContentsInOrder(
                expectedCipherSuites, sslContext.getSocketFactory().getDefaultCipherSuites());
        assertContentsInOrder(
                expectedCipherSuites, sslContext.getServerSocketFactory().getDefaultCipherSuites());

        SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        try {
            assertContentsInOrder(expectedCipherSuites, sslSocket.getEnabledCipherSuites());
            assertContentsInOrder(
                    expectedCipherSuites, sslSocket.getSSLParameters().getCipherSuites());
        } finally {
            try {
                sslSocket.close();
            } catch (IOException ignored) {
            }
        }

        SSLServerSocket sslServerSocket =
                (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket();
        try {
            assertContentsInOrder(expectedCipherSuites, sslServerSocket.getEnabledCipherSuites());
        } finally {
            try {
                sslSocket.close();
            } catch (IOException ignored) {
            }
        }
    }

    @Test
    public void test_SSLContext_getInstance() throws Exception {
        try {
            SSLContext.getInstance(null);
            fail();
        } catch (NullPointerException expected) {
            // Ignored.
        }
        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            assertNotNull(SSLContext.getInstance(protocol));
            assertNotSame(SSLContext.getInstance(protocol), SSLContext.getInstance(protocol));
        }

        try {
            SSLContext.getInstance(null, (String) null);
            fail();
        } catch (Exception expected) {
            if (javaVersion() >= 9) {
                assertTrue("Expected NullPointerException on Java 9, was "
                                + expected.getClass().getName(),
                        expected instanceof NullPointerException);
            } else {
                assertTrue(
                        "Expected IllegalArgumentException, was " + expected.getClass().getName(),
                        expected instanceof IllegalArgumentException);
            }
        }
        try {
            SSLContext.getInstance(null, "");
            fail();
        } catch (Exception expected) {
            if (javaVersion() >= 9) {
                assertTrue("Expected NullPointerException on Java 9, was "
                        + expected.getClass().getName(),
                    expected instanceof NullPointerException);
            } else {
                assertTrue(
                    "Expected IllegalArgumentException, was " + expected.getClass().getName(),
                    expected instanceof IllegalArgumentException);
            }
        }
        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            try {
                SSLContext.getInstance(protocol, (String) null);
                fail();
            } catch (IllegalArgumentException expected) {
                // Ignored.
            }
        }
        try {
            SSLContext.getInstance(null, StandardNames.JSSE_PROVIDER_NAME);
            fail();
        } catch (NullPointerException expected) {
            // Ignored.
        }
    }

    @Test
    public void test_SSLContext_getProtocol() throws Exception {
        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            String protocolName = SSLContext.getInstance(protocol).getProtocol();
            assertNotNull(protocolName);
            assertTrue(protocol.startsWith(protocolName));
        }
    }

    @Test
    public void test_SSLContext_getProvider() throws Exception {
        Provider provider = SSLContext.getDefault().getProvider();
        assertNotNull(provider);
        assertEquals(StandardNames.JSSE_PROVIDER_NAME, provider.getName());
    }

    @Test
    public void test_SSLContext_init_Default() throws Exception {
        // Assert that initializing a default SSLContext fails because it's supposed to be
        // initialized already.
        SSLContext sslContext = SSLContext.getInstance(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT);
        try {
            sslContext.init(null, null, null);
            fail();
        } catch (KeyManagementException expected) {
            // Ignored.
        }
        try {
            sslContext.init(new KeyManager[0], new TrustManager[0], null);
            fail();
        } catch (KeyManagementException expected) {
            // Ignored.
        }
        try {
            sslContext.init(new KeyManager[] {new KeyManager(){}},
                    new TrustManager[] {new TrustManager(){}}, null);
            fail();
        } catch (KeyManagementException expected) {
            // Ignored.
        }
    }

    @Test
    public void test_SSLContext_init_withNullManagerArrays() throws Exception {
        // Assert that SSLContext.init works fine even when provided with null arrays of
        // KeyManagers and TrustManagers.
        // The contract of SSLContext.init is that it will for default X.509 KeyManager and
        // TrustManager from the highest priority KeyManagerFactory and TrustManagerFactory.
        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            if (protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                // Default SSLContext is provided in an already initialized state
                continue;
            }
            SSLContext sslContext = SSLContext.getInstance(protocol);
            sslContext.init(null, null, null);
        }
    }

    @Test
    public void test_SSLContext_init_withEmptyManagerArrays() throws Exception {
        // Assert that SSLContext.init works fine even when provided with empty arrays of
        // KeyManagers and TrustManagers.
        // The contract of SSLContext.init is that it will not look for default X.509 KeyManager and
        // TrustManager.
        // This test thus installs a Provider of KeyManagerFactory and TrustManagerFactory whose
        // factories throw exceptions which will make this test fail if the factories are used.
        Provider provider = new ThrowExceptionKeyAndTrustManagerFactoryProvider();
        invokeWithHighestPrioritySecurityProvider(provider, new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                assertEquals(ThrowExceptionKeyAndTrustManagerFactoryProvider.class,
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                        .getProvider()
                        .getClass());
                assertEquals(ThrowExceptionKeyAndTrustManagerFactoryProvider.class,
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
                        .getProvider()
                        .getClass());

                KeyManager[] keyManagers = new KeyManager[0];
                TrustManager[] trustManagers = new TrustManager[0];
                for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
                    if (protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                        // Default SSLContext is provided in an already initialized state
                        continue;
                    }
                    SSLContext sslContext = SSLContext.getInstance(protocol);
                    sslContext.init(keyManagers, trustManagers, null);
                }

                return null;
            }
        });
    }

    @Test
    public void test_SSLContext_init_withoutX509() throws Exception {
        // Assert that SSLContext.init works fine even when provided with KeyManagers and
        // TrustManagers which don't include the X.509 ones.
        // The contract of SSLContext.init is that it will not look for default X.509 KeyManager and
        // TrustManager.
        // This test thus installs a Provider of KeyManagerFactory and TrustManagerFactory whose
        // factories throw exceptions which will make this test fail if the factories are used.
        Provider provider = new ThrowExceptionKeyAndTrustManagerFactoryProvider();
        invokeWithHighestPrioritySecurityProvider(provider, new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                assertEquals(ThrowExceptionKeyAndTrustManagerFactoryProvider.class,
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                        .getProvider()
                        .getClass());
                assertEquals(ThrowExceptionKeyAndTrustManagerFactoryProvider.class,
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
                        .getProvider()
                        .getClass());

                KeyManager[] keyManagers = new KeyManager[]{new KeyManager() {
                }};
                TrustManager[] trustManagers = new TrustManager[]{new TrustManager() {
                }};
                for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
                    if (protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                        // Default SSLContext is provided in an already initialized state
                        continue;
                    }
                    SSLContext sslContext = SSLContext.getInstance(protocol);
                    sslContext.init(keyManagers, trustManagers, null);
                }

                return null;
            }
        });
    }

    public static class ThrowExceptionKeyAndTrustManagerFactoryProvider extends Provider {
        public ThrowExceptionKeyAndTrustManagerFactoryProvider() {
            super("ThrowExceptionKeyAndTrustManagerProvider", 1.0,
                    "SSLContextTest fake KeyManagerFactory  and TrustManagerFactory provider");

            put("TrustManagerFactory." + TrustManagerFactory.getDefaultAlgorithm(),
                    ThrowExceptionTrustManagagerFactorySpi.class.getName());
            put("TrustManagerFactory.PKIX", ThrowExceptionTrustManagagerFactorySpi.class.getName());

            put("KeyManagerFactory." + KeyManagerFactory.getDefaultAlgorithm(),
                    ThrowExceptionKeyManagagerFactorySpi.class.getName());
            put("KeyManagerFactory.PKIX", ThrowExceptionKeyManagagerFactorySpi.class.getName());
        }
    }

    public static class ThrowExceptionTrustManagagerFactorySpi extends TrustManagerFactorySpi {
        @Override
        protected void engineInit(KeyStore ks) throws KeyStoreException {
            fail();
        }

        @Override
        protected void engineInit(ManagerFactoryParameters spec)
                throws InvalidAlgorithmParameterException {
            fail();
        }

        @Override
        protected TrustManager[] engineGetTrustManagers() {
            throw new AssertionFailedError();
        }
    }

    public static class ThrowExceptionKeyManagagerFactorySpi extends KeyManagerFactorySpi {
        @Override
        protected void engineInit(KeyStore ks, char[] password)
                throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
            fail();
        }

        @Override
        protected void engineInit(ManagerFactoryParameters spec)
                throws InvalidAlgorithmParameterException {
            fail();
        }

        @Override
        protected KeyManager[] engineGetKeyManagers() {
            throw new AssertionFailedError();
        }
    }

    /**
     * Installs the specified security provider as the highest provider, invokes the provided
     * {@link Callable}, and removes the provider.
     *
     * @return result returned by the {@code callable}.
     */
    private static <T> T invokeWithHighestPrioritySecurityProvider(
            Provider provider, Callable<T> callable) throws Exception {
        int providerPosition = -1;
        try {
            providerPosition = Security.insertProviderAt(provider, 1);
            assertEquals(1, providerPosition);
            return callable.call();
        } finally {
            if (providerPosition != -1) {
                Security.removeProvider(provider.getName());
            }
        }
    }

    @Test
    public void test_SSLContext_getSocketFactory() throws Exception {
        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            if (protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                SSLContext.getInstance(protocol).getSocketFactory();
            } else {
                try {
                    SSLContext.getInstance(protocol).getSocketFactory();
                    fail();
                } catch (IllegalStateException expected) {
                    // Ignored.
                }
            }

            SSLContext sslContext = SSLContext.getInstance(protocol);
            if (!protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                sslContext.init(null, null, null);
            }
            SocketFactory sf = sslContext.getSocketFactory();
            assertNotNull(sf);
            assertTrue(SSLSocketFactory.class.isAssignableFrom(sf.getClass()));
        }
    }

    @Test
    public void test_SSLContext_getServerSocketFactory() throws Exception {
        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            if (protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                SSLContext.getInstance(protocol).getServerSocketFactory();
            } else {
                try {
                    SSLContext.getInstance(protocol).getServerSocketFactory();
                    fail();
                } catch (IllegalStateException expected) {
                    // Ignored.
                }
            }

            SSLContext sslContext = SSLContext.getInstance(protocol);
            if (!protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                sslContext.init(null, null, null);
            }
            ServerSocketFactory ssf = sslContext.getServerSocketFactory();
            assertNotNull(ssf);
            assertTrue(SSLServerSocketFactory.class.isAssignableFrom(ssf.getClass()));
        }
    }

    @Test
    public void test_SSLContext_createSSLEngine() throws Exception {
        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            if (protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                SSLContext.getInstance(protocol).createSSLEngine();
            } else {
                try {
                    SSLContext.getInstance(protocol).createSSLEngine();
                    fail();
                } catch (IllegalStateException expected) {
                    // Ignored.
                }
            }

            if (protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                SSLContext.getInstance(protocol).createSSLEngine(null, -1);
            } else {
                try {
                    SSLContext.getInstance(protocol).createSSLEngine(null, -1);
                    fail();
                } catch (IllegalStateException expected) {
                    // Ignored.
                }
            }

            {
                SSLContext sslContext = SSLContext.getInstance(protocol);
                if (!protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                    sslContext.init(null, null, null);
                }
                SSLEngine se = sslContext.createSSLEngine();
                assertNotNull(se);
            }

            {
                SSLContext sslContext = SSLContext.getInstance(protocol);
                if (!protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                    sslContext.init(null, null, null);
                }
                SSLEngine se = sslContext.createSSLEngine(null, -1);
                assertNotNull(se);
            }
        }
    }

    @Test
    public void test_SSLContext_getServerSessionContext() throws Exception {
        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            SSLContext sslContext = SSLContext.getInstance(protocol);
            SSLSessionContext sessionContext = sslContext.getServerSessionContext();
            assertNotNull(sessionContext);

            if (protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                assertSame(
                        SSLContext.getInstance(protocol).getServerSessionContext(), sessionContext);
            } else {
                assertNotSame(
                        SSLContext.getInstance(protocol).getServerSessionContext(), sessionContext);
            }
        }
    }

    @Test
    public void test_SSLContext_getClientSessionContext() throws Exception {
        for (String protocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
            SSLContext sslContext = SSLContext.getInstance(protocol);
            SSLSessionContext sessionContext = sslContext.getClientSessionContext();
            assertNotNull(sessionContext);

            if (protocol.equals(StandardNames.SSL_CONTEXT_PROTOCOLS_DEFAULT)) {
                assertSame(
                        SSLContext.getInstance(protocol).getClientSessionContext(), sessionContext);
            } else {
                assertNotSame(
                        SSLContext.getInstance(protocol).getClientSessionContext(), sessionContext);
            }
        }
    }

    @Test
    public void test_SSLContextTest_TestSSLContext_create() {
        TestSSLContext testContext = TestSSLContext.create();
        assertNotNull(testContext);
        assertNotNull(testContext.clientKeyStore);
        assertNull(testContext.clientStorePassword);
        assertNotNull(testContext.serverKeyStore);
        assertNotNull(testContext.clientKeyManagers);
        assertNotNull(testContext.serverKeyManagers);
        if (testContext.clientKeyManagers.length == 0) {
            fail("No client KeyManagers");
        }
        if (testContext.serverKeyManagers.length == 0) {
            fail("No server KeyManagers");
        }
        assertNotNull(testContext.clientKeyManagers[0]);
        assertNotNull(testContext.serverKeyManagers[0]);
        assertNotNull(testContext.clientTrustManager);
        assertNotNull(testContext.serverTrustManager);
        assertNotNull(testContext.clientContext);
        assertNotNull(testContext.serverContext);
        assertNotNull(testContext.serverSocket);
        assertNotNull(testContext.host);
        assertTrue(testContext.port != 0);
        testContext.close();
    }

    @Test
    public void test_SSLContext_SSLv3Unsupported() throws Exception {
        // Find the default provider for TLS and verify that it does NOT support SSLv3.
        Provider defaultTlsProvider = null;
        for (String protocol : new String[] {"SSLContext.TLSv1.2", "SSLContext.TLSv1"}) {
            for (Provider p : Security.getProviders()) {
                if (p.get(protocol) != null) {
                    defaultTlsProvider = p;
                    break;
                }
            }
        }
        assertNotNull(defaultTlsProvider);
        Provider finalDefaultTlsProvider = defaultTlsProvider;
        assertThrows(
            NoSuchAlgorithmException.class,
            () -> SSLContext.getInstance("SSLv3", finalDefaultTlsProvider));
    }

    private static void assertContentsInOrder(List<String> expected, String... actual) {
        List<String> actualList = Arrays.asList(actual);
        if (expected.size() != actual.length) {
            fail("Unexpected length. Expected len <" + expected.size() + ">, actual len <"
                    + actual.length + ">, expected <" + expected + ">, actual <"
                    + actualList + ">");
        }

        if (isWindows()) {
            // TODO(prbprbprb): CpuFeatures.isAESHardwareAccelerated is not reliable on windows
            Collections.sort(actualList);
            Collections.sort(expected);
        }

        if (!expected.equals(actualList)) {
            fail("Unexpected element(s). Expected <" + expected + ">, actual <" + actualList + ">");
        }
    }

    private static boolean isAndroid() {
        boolean android;
        try {
            Class.forName("android.app.Application", false, getSystemClassLoader());
            android = true;
        } catch (Throwable ignored) {
            // Failed to load the class uniquely available in Android.
            android = false;
        }
        return android;
    }

    private static int javaVersion() {
        final int majorVersion;

        if (isAndroid()) {
            majorVersion = 6;
        } else {
            majorVersion = majorVersionFromJavaSpecificationVersion();
        }

        return majorVersion;
    }

    private static int majorVersionFromJavaSpecificationVersion() {
        return majorVersion(System.getProperty("java.specification.version", "1.6"));
    }

    private static int majorVersion(final String javaSpecVersion) {
        final String[] components = javaSpecVersion.split("\\.", -1);
        final int[] version = new int[components.length];
        for (int i = 0; i < components.length; i++) {
            version[i] = Integer.parseInt(components[i]);
        }

        if (version[0] == 1) {
            assertTrue(version[1] >= 6);
            return version[1];
        } else {
            return version[0];
        }
    }

    private static ClassLoader getSystemClassLoader() {
        if (System.getSecurityManager() == null) {
            return ClassLoader.getSystemClassLoader();
        } else {
            return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
                @Override
                public ClassLoader run() {
                    return ClassLoader.getSystemClassLoader();
                }
            });
        }
    }
}
