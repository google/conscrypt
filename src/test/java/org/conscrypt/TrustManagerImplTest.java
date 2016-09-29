/*
 * Copyright (C) 2011 The Android Open Source Project
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
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.X509TrustManager;
import junit.framework.TestCase;
import libcore.java.security.TestKeyStore;

public class TrustManagerImplTest extends TestCase {

    /**
     * Ensure that our non-standard behavior of learning to trust new
     * intermediate CAs does not regress. http://b/3404902
     */
    public void testLearnIntermediate() throws Exception {
        // chain3 should be server/intermediate/root
        KeyStore.PrivateKeyEntry pke = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
        X509Certificate[] chain3 = (X509Certificate[])pke.getCertificateChain();
        X509Certificate root = chain3[2];
        X509Certificate intermediate = chain3[1];
        X509Certificate server = chain3[0];
        X509Certificate[] chain2 =  new X509Certificate[] { server, intermediate };
        X509Certificate[] chain1 =  new X509Certificate[] { server };

        // Normal behavior
        assertValid(chain3,   trustManager(root));
        assertValid(chain2,   trustManager(root));
        assertInvalid(chain1, trustManager(root));
        assertValid(chain3,   trustManager(intermediate));
        assertValid(chain2,   trustManager(intermediate));
        assertValid(chain1,   trustManager(intermediate));
        assertValid(chain3,   trustManager(server));
        assertValid(chain2,   trustManager(server));
        assertValid(chain1,   trustManager(server));

        // non-standard behavior
        X509TrustManager tm = trustManager(root);
        // fail on short chain with only root trusted
        assertInvalid(chain1, tm);
        // succeed on longer chain, learn intermediate
        assertValid(chain2, tm);
        // now we can validate the short chain
        assertValid(chain1, tm);
    }

    // We should ignore duplicate cruft in the certificate chain
    // See https://code.google.com/p/android/issues/detail?id=52295 http://b/8313312
    public void testDuplicateInChain() throws Exception {
        // chain3 should be server/intermediate/root
        KeyStore.PrivateKeyEntry pke = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
        X509Certificate[] chain3 = (X509Certificate[])pke.getCertificateChain();
        X509Certificate root = chain3[2];
        X509Certificate intermediate = chain3[1];
        X509Certificate server = chain3[0];

        X509Certificate[] chain4 = new X509Certificate[] { server, intermediate,
                                                           server, intermediate
        };
        assertValid(chain4, trustManager(root));
    }

    public void testGetFullChain() throws Exception {
        // build the trust manager
        KeyStore.PrivateKeyEntry pke = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
        X509Certificate[] chain3 = (X509Certificate[])pke.getCertificateChain();
        X509Certificate root = chain3[2];
        X509TrustManager tm = trustManager(root);

        // build the chains we'll use for testing
        X509Certificate intermediate = chain3[1];
        X509Certificate server = chain3[0];
        X509Certificate[] chain2 =  new X509Certificate[] { server, intermediate };
        X509Certificate[] chain1 =  new X509Certificate[] { server };

        assertTrue(tm instanceof TrustManagerImpl);
        TrustManagerImpl tmi = (TrustManagerImpl) tm;
        List<X509Certificate> certs = tmi.checkServerTrusted(chain2, "RSA", new MySSLSession(
                "purple.com"));
        assertEquals(Arrays.asList(chain3), certs);
        certs = tmi.checkServerTrusted(chain1, "RSA", new MySSLSession("purple.com"));
        assertEquals(Arrays.asList(chain3), certs);
    }


    private X509TrustManager trustManager(X509Certificate ca) throws Exception {
        KeyStore keyStore = TestKeyStore.createKeyStore();
        keyStore.setCertificateEntry("alias", ca);

        return new TrustManagerImpl(keyStore);
    }

    private void assertValid(X509Certificate[] chain, X509TrustManager tm) throws Exception {
        if (tm instanceof TrustManagerImpl) {
            TrustManagerImpl tmi = (TrustManagerImpl) tm;
            tmi.checkServerTrusted(chain, "RSA");
        }
        tm.checkServerTrusted(chain, "RSA");
    }

    private void assertInvalid(X509Certificate[] chain, X509TrustManager tm) {
        try {
            tm.checkClientTrusted(chain, "RSA");
            fail();
        } catch (CertificateException expected) {
        }
        try {
            tm.checkServerTrusted(chain, "RSA");
            fail();
        } catch (CertificateException expected) {
        }
    }

    private class MySSLSession implements SSLSession {
        private final String hostname;

        public MySSLSession(String hostname) {
            this.hostname = hostname;
        }

        @Override
        public int getApplicationBufferSize() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getCipherSuite() {
            throw new UnsupportedOperationException();
        }

        @Override
        public long getCreationTime() {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] getId() {
            throw new UnsupportedOperationException();
        }

        @Override
        public long getLastAccessedTime() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Certificate[] getLocalCertificates() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Principal getLocalPrincipal() {
            throw new UnsupportedOperationException();
        }

        @Override
        public int getPacketBufferSize() {
            throw new UnsupportedOperationException();
        }

        @Override
        public javax.security.cert.X509Certificate[] getPeerCertificateChain()
                throws SSLPeerUnverifiedException {
            throw new UnsupportedOperationException();
        }

        @Override
        public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getPeerHost() {
            return hostname;
        }

        @Override
        public int getPeerPort() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getProtocol() {
            throw new UnsupportedOperationException();
        }

        @Override
        public SSLSessionContext getSessionContext() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Object getValue(String name) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String[] getValueNames() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void invalidate() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isValid() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void putValue(String name, Object value) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void removeValue(String name) {
            throw new UnsupportedOperationException();
        }
    }
}
