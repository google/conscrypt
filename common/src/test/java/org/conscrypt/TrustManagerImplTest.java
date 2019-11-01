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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;
import org.conscrypt.java.security.TestKeyStore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class TrustManagerImplTest {

    /**
     * Ensure that our non-standard behavior of learning to trust new
     * intermediate CAs does not regress. http://b/3404902
     */
    @Test
    public void testLearnIntermediate() throws Exception {
        TestUtils.assumeExtendedTrustManagerAvailable();
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
    @Test
    public void testDuplicateInChain() throws Exception {
        TestUtils.assumeExtendedTrustManagerAvailable();
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

    @Test
    public void testGetFullChain() throws Exception {
        TestUtils.assumeExtendedTrustManagerAvailable();
        // build the trust manager
        KeyStore.PrivateKeyEntry pke = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
        X509Certificate[] chain3 = (X509Certificate[]) pke.getCertificateChain();
        X509Certificate root = chain3[2];
        X509TrustManager tm = trustManager(root);

        // build the chains we'll use for testing
        X509Certificate intermediate = chain3[1];
        X509Certificate server = chain3[0];
        X509Certificate[] chain2 =  new X509Certificate[] { server, intermediate };
        X509Certificate[] chain1 =  new X509Certificate[] { server };

        assertTrue(tm instanceof TrustManagerImpl);
        TrustManagerImpl tmi = (TrustManagerImpl) tm;
        List<X509Certificate> certs = tmi.checkServerTrusted(chain2, "RSA", new FakeSSLSession(
                "purple.com"));
        assertEquals(Arrays.asList(chain3), certs);
        certs = tmi.checkServerTrusted(chain1, "RSA", new FakeSSLSession("purple.com"));
        assertEquals(Arrays.asList(chain3), certs);
    }

    @Test
    public void testHttpsEndpointIdentification() throws Exception {
        TestUtils.assumeExtendedTrustManagerAvailable();

        KeyStore.PrivateKeyEntry pke = TestKeyStore.getServerHostname().getPrivateKey("RSA", "RSA");
        X509Certificate[] chain = (X509Certificate[]) pke.getCertificateChain();
        X509Certificate root = chain[2];
        TrustManagerImpl tmi = (TrustManagerImpl) trustManager(root);

        String goodHostname = TestKeyStore.CERT_HOSTNAME;
        String badHostname = "definitelywrong.nopenopenope";

        // The default hostname verifier on OpenJDK rejects all hostnames, so use our own
        javax.net.ssl.HostnameVerifier oldDefault = HttpsURLConnection.getDefaultHostnameVerifier();
        try {
            HttpsURLConnection.setDefaultHostnameVerifier(new TestHostnameVerifier());

            SSLParameters params = new SSLParameters();

            // Without endpoint identification this should pass despite the mismatched hostname
            params.setEndpointIdentificationAlgorithm(null);

            List<X509Certificate> certs = tmi.getTrustedChainForServer(chain, "RSA",
                new FakeSSLSocket(new FakeSSLSession(badHostname, chain), params));
            assertEquals(Arrays.asList(chain), certs);

            // Turn on endpoint identification
            params.setEndpointIdentificationAlgorithm("HTTPS");

            try {
                tmi.getTrustedChainForServer(chain, "RSA",
                    new FakeSSLSocket(new FakeSSLSession(badHostname, chain), params));
                fail();
            } catch (CertificateException expected) {
            }

            certs = tmi.getTrustedChainForServer(chain, "RSA",
                new FakeSSLSocket(new FakeSSLSession(goodHostname, chain), params));
            assertEquals(Arrays.asList(chain), certs);

            // Override the global default hostname verifier with a Conscrypt-specific one that
            // always passes.  Both scenarios should pass.
            Conscrypt.setDefaultHostnameVerifier(new ConscryptHostnameVerifier() {
                @Override public boolean verify(String s, SSLSession sslSession) { return true; }
            });

            certs = tmi.getTrustedChainForServer(chain, "RSA",
                new FakeSSLSocket(new FakeSSLSession(badHostname, chain), params));
            assertEquals(Arrays.asList(chain), certs);

            certs = tmi.getTrustedChainForServer(chain, "RSA",
                new FakeSSLSocket(new FakeSSLSession(goodHostname, chain), params));
            assertEquals(Arrays.asList(chain), certs);

            // Now set an instance-specific verifier on the trust manager.  The bad hostname should
            // fail again.
            Conscrypt.setHostnameVerifier(tmi, new TestHostnameVerifier());

            try {
                tmi.getTrustedChainForServer(chain, "RSA",
                    new FakeSSLSocket(new FakeSSLSession(badHostname, chain), params));
                fail();
            } catch (CertificateException expected) {
            }

            certs = tmi.getTrustedChainForServer(chain, "RSA",
                new FakeSSLSocket(new FakeSSLSession(goodHostname, chain), params));
            assertEquals(Arrays.asList(chain), certs);

            // Remove the instance-specific verifier, and both should pass again.
            Conscrypt.setHostnameVerifier(tmi, null);

            certs = tmi.getTrustedChainForServer(chain, "RSA",
                new FakeSSLSocket(new FakeSSLSession(badHostname, chain), params));
            assertEquals(Arrays.asList(chain), certs);

            certs = tmi.getTrustedChainForServer(chain, "RSA",
                new FakeSSLSocket(new FakeSSLSession(goodHostname, chain), params));
            assertEquals(Arrays.asList(chain), certs);
        } finally {
            Conscrypt.setDefaultHostnameVerifier(null);
            HttpsURLConnection.setDefaultHostnameVerifier(oldDefault);
        }
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
            // Expected.
        }
        try {
            tm.checkServerTrusted(chain, "RSA");
            fail();
        } catch (CertificateException expected) {
            // Expected.
        }
    }

    private static class FakeSSLSession implements SSLSession {
        private final String hostname;
        private final X509Certificate[] peerCerts;

        FakeSSLSession(String hostname) {
            this.hostname = hostname;
            peerCerts = null;
        }

        FakeSSLSession(String hostname, X509Certificate[] peerCerts) {
            this.hostname = hostname;
            this.peerCerts = peerCerts.clone();
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
            if (peerCerts == null) {
                throw new SSLPeerUnverifiedException("Null peerCerts");
            } else {
                return peerCerts.clone();
            }
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

    private static class FakeSSLSocket extends SSLSocket {

        private final SSLSession session;
        private final SSLParameters parameters;

        public FakeSSLSocket(SSLSession session, SSLParameters parameters) {
            this.session = session;
            this.parameters = parameters;
        }

        @Override
        public SSLParameters getSSLParameters() {
            return parameters;
        }

        @Override
        public String[] getSupportedCipherSuites() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String[] getEnabledCipherSuites() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setEnabledCipherSuites(String[] strings) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String[] getSupportedProtocols() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String[] getEnabledProtocols() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setEnabledProtocols(String[] strings) {
            throw new UnsupportedOperationException();
        }

        @Override
        public SSLSession getSession() {
            return session;
        }

        @Override
        public SSLSession getHandshakeSession() {
            return session;
        }

        @Override
        public void addHandshakeCompletedListener(
            HandshakeCompletedListener handshakeCompletedListener) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void removeHandshakeCompletedListener(
            HandshakeCompletedListener handshakeCompletedListener) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void startHandshake() throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setUseClientMode(boolean b) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean getUseClientMode() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setNeedClientAuth(boolean b) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean getNeedClientAuth() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setWantClientAuth(boolean b) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean getWantClientAuth() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setEnableSessionCreation(boolean b) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean getEnableSessionCreation() {
            throw new UnsupportedOperationException();
        }
    }

    private static class TestHostnameVerifier
        extends org.conscrypt.javax.net.ssl.TestHostnameVerifier
        implements ConscryptHostnameVerifier {}
}
