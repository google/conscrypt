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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SSLSocketFactoryTest {

    @Test
    public void test_SSLSocketFactory_getDefault() {
        SocketFactory sf = SSLSocketFactory.getDefault();
        assertNotNull(sf);
        assertTrue(SSLSocketFactory.class.isAssignableFrom(sf.getClass()));
    }

    @Test
    public void test_SSLSocketFactory_defaultConfiguration() throws Exception {
        SSLConfigurationAsserts.assertSSLSocketFactoryDefaultConfiguration(
                (SSLSocketFactory) SSLSocketFactory.getDefault());
    }

    @Test
    public void test_SSLSocketFactory_getDefaultCipherSuitesReturnsCopies() {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        assertNotSame(sf.getDefaultCipherSuites(), sf.getDefaultCipherSuites());
    }

    @Test
    public void test_SSLSocketFactory_getSupportedCipherSuitesReturnsCopies() {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        assertNotSame(sf.getSupportedCipherSuites(), sf.getSupportedCipherSuites());
    }

    @Test
    public void test_SSLSocketFactory_createSocket() throws Exception {
        try {
            SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
            sf.createSocket(null, null, -1, false);
            fail();
        } catch (NullPointerException expected) {
            // Ignored.
        }

        try {
            SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
            sf.createSocket(new Socket(), null, -1, false);
            fail();
        } catch (SocketException expected) {
            // Ignored.
        }

        ServerSocket ss = ServerSocketFactory.getDefault().createServerSocket(0);
        InetSocketAddress sa = (InetSocketAddress) ss.getLocalSocketAddress();
        InetAddress host = sa.getAddress();
        int port = sa.getPort();
        Socket s = new Socket(host, port);
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        Socket ssl = sf.createSocket(s, null, -1, false);
        assertNotNull(ssl);
        assertTrue(SSLSocket.class.isAssignableFrom(ssl.getClass()));
    }
}
