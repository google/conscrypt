/*
 * Copyright (C) 2012 The Android Open Source Project
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

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import junit.framework.TestCase;
import libcore.java.security.TestKeyStore;

public class CertPinManagerTest extends TestCase {
    private List<X509Certificate> expectedFullChain;
    private X509Certificate[] chain;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        KeyStore.PrivateKeyEntry pke = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
        X509Certificate[] certs = (X509Certificate[]) pke.getCertificateChain();
        expectedFullChain = Arrays.asList(certs);
        // Leave the root out of the chain
        chain = new X509Certificate[2];
        chain[0] = certs[0];
        chain[1] = certs[1];
    }

    public void testCertPinManagerCalled() throws Exception {
        class TestCertPinManager implements CertPinManager {
            public boolean called = false;
            @Override
            public void checkChainPinning(String hostname, List<X509Certificate> chain)
                    throws CertificateException {
                called = true;
            }
        }
        TestCertPinManager manager = new TestCertPinManager();
        callCheckServerTrusted(null, manager);
        assertTrue(manager.called);
    }

    public void testNullPinManager() throws Exception {
        callCheckServerTrusted(null, null);
    }

    public void testFailure() throws Exception {
        CertPinManager manager = new CertPinManager() {
            @Override
            public void checkChainPinning(String hostname, List<X509Certificate> chain)
                    throws CertificateException {
                throw new CertificateException("pin failure");
            }
        };
        try {
            callCheckServerTrusted(null, manager);
            fail("Invalid chain was trusted");
        } catch (CertificateException expected) {
            assertEquals("pin failure", expected.getMessage());
        }
    }

    public void testHostnameProvided() throws Exception {
        final String expectedHostname = "example.com";
        class TestCertPinManager implements CertPinManager {
            public boolean hostnameMatched = false;
            @Override
            public void checkChainPinning(String hostname, List<X509Certificate> chain)
                    throws CertificateException {
                hostnameMatched = expectedHostname.equals(hostname);
            }
        }
        TestCertPinManager manager = new TestCertPinManager();
        callCheckServerTrusted(expectedHostname, manager);
        assertTrue(manager.hostnameMatched);
    }

    public void testFullChainProvided() throws Exception {
        class TestCertPinManager implements CertPinManager {
            public boolean fullChainProvided = false;
            @Override
            public void checkChainPinning(String hostname, List<X509Certificate> chain)
                    throws CertificateException {
                fullChainProvided = expectedFullChain.equals(chain);
            }
        }
        TestCertPinManager manager = new TestCertPinManager();
        callCheckServerTrusted(null, manager);
        assertTrue(manager.fullChainProvided);
    }

    private void callCheckServerTrusted(String hostname, CertPinManager manager)
            throws CertificateException {
        TrustManagerImpl tm = new TrustManagerImpl(TestKeyStore.getClient().keyStore, manager);
        tm.checkServerTrusted(chain, "RSA", hostname);
    }
}
