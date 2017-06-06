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

import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLParameters;
import junit.framework.TestCase;

/**
 * Test for Platform
 */
public class PlatformTest extends TestCase {
    public void test_setSSLParameters_Socket() throws Exception {
        Socket socket = new OpenSSLSocketFactoryImpl().createSocket();
        SSLParametersImpl impl = SSLParametersImpl.getDefault();
        SSLParameters params = new SSLParameters();
        List<SNIServerName> names = new ArrayList<SNIServerName>();
        names.add(new SNIHostName("some.host"));
        params.setServerNames(names);
        params.setUseCipherSuitesOrder(false);
        params.setEndpointIdentificationAlgorithm("ABC");
        Platform.setSSLParameters(params, impl, (AbstractConscryptSocket)socket);
        assertEquals("some.host", ((AbstractConscryptSocket)socket).getHostname());
        assertFalse(impl.getUseCipherSuitesOrder());
        assertEquals("ABC", impl.getEndpointIdentificationAlgorithm());
    }

    public void test_getSSLParameters_Socket() throws Exception {
        Socket socket = new OpenSSLSocketFactoryImpl().createSocket();
        SSLParametersImpl impl = SSLParametersImpl.getDefault();
        SSLParameters params = new SSLParameters();
        impl.setUseCipherSuitesOrder(false);
        impl.setEndpointIdentificationAlgorithm("ABC");
        ((AbstractConscryptSocket)socket).setHostname("some.host");
        Platform.getSSLParameters(params, impl, (AbstractConscryptSocket)socket);
        assertEquals("some.host", ((SNIHostName)params.getServerNames().get(0)).getAsciiName());
        assertFalse(params.getUseCipherSuitesOrder());
        assertEquals("ABC", params.getEndpointIdentificationAlgorithm());
    }

    public void test_setSSLParameters_Engine() throws Exception {
        SSLParametersImpl impl = SSLParametersImpl.getDefault();
        SSLParameters params = new SSLParameters();
        ConscryptEngine engine = new ConscryptEngine(impl);
        List<SNIServerName> names = new ArrayList<SNIServerName>();
        names.add(new SNIHostName("some.host"));
        params.setServerNames(names);
        params.setUseCipherSuitesOrder(false);
        params.setEndpointIdentificationAlgorithm("ABC");
        Platform.setSSLParameters(params, impl, engine);
        assertEquals("some.host", engine.getHostname());
        assertFalse(impl.getUseCipherSuitesOrder());
        assertEquals("ABC", impl.getEndpointIdentificationAlgorithm());
    }

    public void test_getSSLParameters_Engine() throws Exception {
        SSLParametersImpl impl = SSLParametersImpl.getDefault();
        SSLParameters params = new SSLParameters();
        ConscryptEngine engine = new ConscryptEngine(impl);
        impl.setUseCipherSuitesOrder(false);
        impl.setEndpointIdentificationAlgorithm("ABC");
        engine.setHostname("some.host");
        Platform.getSSLParameters(params, impl, engine);
        assertEquals("some.host", ((SNIHostName)params.getServerNames().get(0)).getAsciiName());
        assertFalse(params.getUseCipherSuitesOrder());
        assertEquals("ABC", params.getEndpointIdentificationAlgorithm());
    }
}
