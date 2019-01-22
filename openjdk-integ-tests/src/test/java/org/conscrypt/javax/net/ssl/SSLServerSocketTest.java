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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import org.conscrypt.TestUtils;
import org.conscrypt.java.security.StandardNames;
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
    public void testSetEnabledCipherSuitesAffectsGetter_TLS12() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(null, null, null);
        SSLServerSocket socket =
                (SSLServerSocket) context.getServerSocketFactory().createServerSocket();
        String[] cipherSuites = new String[] {
                TestUtils.pickArbitraryNonTls13Suite(socket.getSupportedCipherSuites())
        };
        socket.setEnabledCipherSuites(cipherSuites);
        assertEquals(Arrays.asList(cipherSuites), Arrays.asList(socket.getEnabledCipherSuites()));
    }

    @Test
    public void testSetEnabledCipherSuitesAffectsGetter_TLS13() throws Exception {
        SSLServerSocket socket =
            (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket();
        String[] cipherSuites = new String[] {
            TestUtils.pickArbitraryNonTls13Suite(socket.getSupportedCipherSuites())
        };
        socket.setEnabledCipherSuites(cipherSuites);
        List<String> expected = new ArrayList<String>(StandardNames.CIPHER_SUITES_TLS13);
        expected.addAll(Arrays.asList(cipherSuites));
        assertEquals(expected, Arrays.asList(socket.getEnabledCipherSuites()));
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

    @Test
    public void test_SSLSocket_setEnabledCipherSuites_TLS13() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(null, null, null);
        SSLServerSocketFactory sf = context.getServerSocketFactory();
        SSLServerSocket ssl = (SSLServerSocket) sf.createServerSocket();
        // The TLS 1.3 cipher suites should be enabled by default
        assertTrue(new HashSet<String>(Arrays.asList(ssl.getEnabledCipherSuites()))
                .containsAll(StandardNames.CIPHER_SUITES_TLS13));
        // Disabling them should be ignored
        ssl.setEnabledCipherSuites(new String[0]);
        assertTrue(new HashSet<String>(Arrays.asList(ssl.getEnabledCipherSuites()))
                .containsAll(StandardNames.CIPHER_SUITES_TLS13));

        ssl.setEnabledCipherSuites(new String[] {
                TestUtils.pickArbitraryNonTls13Suite(ssl.getSupportedCipherSuites())
        });
        assertTrue(new HashSet<String>(Arrays.asList(ssl.getEnabledCipherSuites()))
                .containsAll(StandardNames.CIPHER_SUITES_TLS13));

        // Disabling TLS 1.3 should disable 1.3 cipher suites
        ssl.setEnabledProtocols(new String[] { "TLSv1.2" });
        assertFalse(new HashSet<String>(Arrays.asList(ssl.getEnabledCipherSuites()))
                .containsAll(StandardNames.CIPHER_SUITES_TLS13));
    }
}
