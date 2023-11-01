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

import static org.conscrypt.TestUtils.assumeJava8;
import static org.conscrypt.TestUtils.isJavaVersion;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.lang.reflect.Method;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLParameters;
import org.conscrypt.testing.FailingSniMatcher;
import org.conscrypt.testing.RestrictedAlgorithmConstraints;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test for Platform
 */
@RunWith(JUnit4.class)
public class PlatformTest {
    private static final Method SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD;
    private static final Method SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD;

    static {
        Class<?> sslParameters = SSLParameters.class;
        Method getApplicationProtocolsMethod;
        Method setApplicationProtocolsMethod;
        try {
            getApplicationProtocolsMethod = sslParameters.getMethod("getApplicationProtocols");
            setApplicationProtocolsMethod =
                sslParameters.getMethod("setApplicationProtocols", String[].class);
        } catch (NoSuchMethodException e) {
            getApplicationProtocolsMethod = null;
            setApplicationProtocolsMethod = null;
        }

        SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD = getApplicationProtocolsMethod;
        SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD = setApplicationProtocolsMethod;
    }

    @Test
    public void test_setSSLParameters_Socket() throws Exception {
        assumeJava8();
        Socket socket = new OpenSSLSocketFactoryImpl().createSocket();
        SSLParametersImpl impl = SSLParametersImpl.getDefault();
        SSLParameters params = new SSLParameters();
        List<SNIServerName> names = new ArrayList<SNIServerName>();
        names.add(new SNIHostName("some.host"));
        params.setServerNames(names);
        params.setUseCipherSuitesOrder(false);
        params.setEndpointIdentificationAlgorithm("ABC");
        String[] applicationProtocols = new String[] {"foo", "bar"};
        if (isJavaVersion(9)) {
            setApplicationProtocols(params, applicationProtocols);
        }
        Platform.setSSLParameters(params, impl, (AbstractConscryptSocket) socket);
        assertEquals("some.host", ((AbstractConscryptSocket) socket).getHostname());
        assertFalse(impl.getUseCipherSuitesOrder());
        assertEquals("ABC", impl.getEndpointIdentificationAlgorithm());
        if (isJavaVersion(9)) {
            assertArrayEquals(applicationProtocols, impl.getApplicationProtocols());
        }
    }

    @Test
    public void test_getSSLParameters_Socket() throws Exception {
        assumeJava8();
        Socket socket = new OpenSSLSocketFactoryImpl().createSocket();
        SSLParametersImpl impl = SSLParametersImpl.getDefault();
        SSLParameters params = new SSLParameters();
        impl.setUseCipherSuitesOrder(false);
        impl.setEndpointIdentificationAlgorithm("ABC");
        String[] applicationProtocols = new String[] {"foo", "bar"};
        if (isJavaVersion(9)) {
            impl.setApplicationProtocols(applicationProtocols);
        }
        ((AbstractConscryptSocket) socket).setHostname("some.host");
        Platform.getSSLParameters(params, impl, (AbstractConscryptSocket) socket);
        assertEquals("some.host", ((SNIHostName) params.getServerNames().get(0)).getAsciiName());
        assertFalse(params.getUseCipherSuitesOrder());
        assertEquals("ABC", params.getEndpointIdentificationAlgorithm());
        if (isJavaVersion(9)) {
            assertArrayEquals(applicationProtocols, getApplicationProtocols(params));
        }
    }

    @Test
    public void test_setSSLParameters_Engine() throws Exception {
        assumeJava8();
        SSLParametersImpl impl = SSLParametersImpl.getDefault();
        SSLParameters params = new SSLParameters();
        ConscryptEngine engine = new ConscryptEngine(impl);
        List<SNIServerName> names = new ArrayList<SNIServerName>();
        names.add(new SNIHostName("some.host"));
        params.setServerNames(names);
        params.setUseCipherSuitesOrder(false);
        params.setEndpointIdentificationAlgorithm("ABC");
        String[] applicationProtocols = new String[] {"foo", "bar"};
        if (isJavaVersion(9)) {
            setApplicationProtocols(params, applicationProtocols);
        }
        Platform.setSSLParameters(params, impl, engine);
        assertEquals("some.host", engine.getHostname());
        assertFalse(impl.getUseCipherSuitesOrder());
        assertEquals("ABC", impl.getEndpointIdentificationAlgorithm());
        if (isJavaVersion(9)) {
            assertArrayEquals(applicationProtocols, impl.getApplicationProtocols());
        }
    }

    @Test
    public void test_getSSLParameters_Engine() throws Exception {
        assumeJava8();
        SSLParametersImpl impl = SSLParametersImpl.getDefault();
        SSLParameters params = new SSLParameters();
        ConscryptEngine engine = new ConscryptEngine(impl);
        impl.setUseCipherSuitesOrder(false);
        impl.setEndpointIdentificationAlgorithm("ABC");
        engine.setHostname("some.host");
        String[] applicationProtocols = new String[] {"foo", "bar"};
        if (isJavaVersion(9)) {
            impl.setApplicationProtocols(applicationProtocols);
        }
        Platform.getSSLParameters(params, impl, engine);
        assertEquals("some.host", ((SNIHostName) params.getServerNames().get(0)).getAsciiName());
        assertFalse(params.getUseCipherSuitesOrder());
        assertEquals("ABC", params.getEndpointIdentificationAlgorithm());
        if (isJavaVersion(9)) {
            assertArrayEquals(applicationProtocols, getApplicationProtocols(params));
        }
    }

    @Test
    public void test_setAndGetSSLParameters() throws Exception {
        assumeJava8();
        ConscryptEngine engine = new ConscryptEngine(SSLParametersImpl.getDefault());
        SSLParameters paramsIn = new SSLParameters();

        List<SNIServerName> names = new ArrayList<>();
        names.add(new SNIHostName("some.host"));
        paramsIn.setServerNames(names);
        paramsIn.setUseCipherSuitesOrder(true);
        paramsIn.setEndpointIdentificationAlgorithm("ABC");
        paramsIn.setWantClientAuth(true);
        paramsIn.setSNIMatchers(Collections.singleton(FailingSniMatcher.create()));
        paramsIn.setAlgorithmConstraints(new RestrictedAlgorithmConstraints());

        engine.setSSLParameters(paramsIn);
        SSLParameters paramsOut = engine.getSSLParameters();

        assertEquals(paramsIn.getServerNames(), paramsOut.getServerNames());
        assertEquals(paramsIn.getUseCipherSuitesOrder(), paramsOut.getUseCipherSuitesOrder());
        assertEquals(paramsIn.getEndpointIdentificationAlgorithm(),
                paramsOut.getEndpointIdentificationAlgorithm());
        assertEquals(paramsIn.getWantClientAuth(), paramsOut.getWantClientAuth());
        assertEquals(paramsIn.getNeedClientAuth(), paramsOut.getNeedClientAuth());
        assertSNIMatchersEqual(paramsIn.getSNIMatchers(), paramsOut.getSNIMatchers());
        assertEquals(paramsIn.getAlgorithmConstraints(), paramsOut.getAlgorithmConstraints());
    }

    private static void assertSNIMatchersEqual(Collection<SNIMatcher> a, Collection<SNIMatcher> b) {
        assertEquals(a.size(), b.size());

        HashSet<SNIMatcher> aSet = new HashSet<>(a);
        aSet.removeAll(b);
        assertEquals(0, aSet.size());
    }

    private static String[] getApplicationProtocols(SSLParameters params) {
        if (SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD != null) {
            try {
                return (String[]) SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD.invoke(params);
            } catch (Exception ignored) {
                // TODO(nmittler): Should we throw here?
            }
        }
        return EmptyArray.STRING;
    }

    private static void setApplicationProtocols(SSLParameters params, String[] protocols) {
        if (SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD != null) {
            try {
                SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD.invoke(params, (Object) protocols);
            } catch (Exception ignored) {
                // TODO(nmittler): Should we throw here?
            }
        }
    }
}
