/*
 * Copyright (C) 2013 The Android Open Source Project
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

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SSLServerSocketTest {

    @Test
    public void testDefaultConfiguration() throws Exception {
        SSLConfigurationAsserts.assertSSLServerSocketDefaultConfiguration(
                (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket());
    }

    @Test
    public void testSetEnabledCipherSuitesAffectsGetter() throws Exception {
        SSLServerSocket socket =
                (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket();
        String[] cipherSuites = new String[] {socket.getSupportedCipherSuites()[0]};
        socket.setEnabledCipherSuites(cipherSuites);
        assertEquals(Arrays.asList(cipherSuites), Arrays.asList(socket.getEnabledCipherSuites()));
    }

    @Test
    public void testSetEnabledCipherSuitesStoresCopy() throws Exception {
        SSLServerSocket socket =
                (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket();
        String[] array = new String[] {socket.getEnabledCipherSuites()[0]};
        String originalFirstElement = array[0];
        socket.setEnabledCipherSuites(array);
        array[0] = "Modified after having been set";
        assertEquals(originalFirstElement, socket.getEnabledCipherSuites()[0]);
    }

    @Test
    public void testSetEnabledProtocolsAffectsGetter() throws Exception {
        SSLServerSocket socket =
                (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket();
        String[] protocols = new String[] {socket.getSupportedProtocols()[0]};
        socket.setEnabledProtocols(protocols);
        assertEquals(Arrays.asList(protocols), Arrays.asList(socket.getEnabledProtocols()));
    }

    @Test
    public void testSetEnabledProtocolsStoresCopy() throws Exception {
        SSLServerSocket socket =
                (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket();
        String[] array = new String[] {socket.getEnabledProtocols()[0]};
        String originalFirstElement = array[0];
        socket.setEnabledProtocols(array);
        array[0] = "Modified after having been set";
        assertEquals(originalFirstElement, socket.getEnabledProtocols()[0]);
    }
}
