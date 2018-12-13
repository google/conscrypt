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

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.conscrypt.TestUtils;
import org.conscrypt.java.security.TestKeyStore;

/**
 * TestSSLContext is a convenience class for other tests that
 * want a canned SSLContext and related state for testing so they
 * don't have to duplicate the logic.
 */
public final class TestSSLContext {
    /**
     * The Android SSLSocket and SSLServerSocket implementations are
     * based on a version of OpenSSL which includes support for RFC
     * 4507 session tickets. When using session tickets, the server
     * does not need to keep a cache mapping session IDs to SSL
     * sessions for reuse. Instead, the client presents the server
     * with a session ticket it received from the server earlier,
     * which is an SSL session encrypted by the server's secret
     * key. Since in this case the server does not need to keep a
     * cache, some tests may find different results depending on
     * whether or not the session tickets are in use. These tests can
     * use this function to determine if loopback SSL connections are
     * expected to use session tickets and conditionalize their
     * results appropriately.
     */
    public static boolean sslServerSocketSupportsSessionTickets() {
        // Disabled session tickets for better compatability b/2682876
        // return !IS_RI;
        return true;
    }
    public final KeyStore clientKeyStore;
    public final char[] clientStorePassword;
    public final KeyStore serverKeyStore;
    public final char[] serverStorePassword;
    public final KeyManager[] clientKeyManagers;
    public final KeyManager[] serverKeyManagers;
    public final X509TrustManager clientTrustManager;
    public final X509TrustManager serverTrustManager;
    public final SSLContext clientContext;
    public final SSLContext serverContext;
    public final SSLServerSocket serverSocket;
    public final InetAddress host;
    public final int port;
    /**
     * Used for replacing the hostname in an InetSocketAddress object during
     * serialization.
     */
    private static class HostnameRewritingObjectOutputStream extends ObjectOutputStream {
        private final String hostname;
        public HostnameRewritingObjectOutputStream(OutputStream out, String hostname)
                throws IOException {
            super(out);
            this.hostname = hostname;
        }
        @Override
        public PutField putFields() throws IOException {
            return new PutFieldProxy(super.putFields(), hostname);
        }
        private static class PutFieldProxy extends ObjectOutputStream.PutField {
            private final PutField delegate;
            private final String hostname;
            public PutFieldProxy(ObjectOutputStream.PutField delegate, String hostname) {
                this.delegate = delegate;
                this.hostname = hostname;
            }
            @Override
            public void put(String name, boolean val) {
                delegate.put(name, val);
            }
            @Override
            public void put(String name, byte val) {
                delegate.put(name, val);
            }
            @Override
            public void put(String name, char val) {
                delegate.put(name, val);
            }
            @Override
            public void put(String name, short val) {
                delegate.put(name, val);
            }
            @Override
            public void put(String name, int val) {
                delegate.put(name, val);
            }
            @Override
            public void put(String name, long val) {
                delegate.put(name, val);
            }
            @Override
            public void put(String name, float val) {
                delegate.put(name, val);
            }
            @Override
            public void put(String name, double val) {
                delegate.put(name, val);
            }
            @Override
            public void put(String name, Object val) {
                if ("hostname".equals(name)) {
                    delegate.put(name, hostname);
                } else {
                    delegate.put(name, val);
                }
            }
            @SuppressWarnings("deprecation")
            @Override
            public void write(ObjectOutput out) throws IOException {
                delegate.write(out);
            }
        }
    }
    /**
     * Creates an InetSocketAddress where the hostname points to an arbitrary
     * hostname, but the address points to the loopback address. Useful for
     * testing SNI where both "localhost" and IP addresses are not allowed.
     */
    public InetSocketAddress getLoopbackAsHostname(String hostname, int port)
            throws IOException, ClassNotFoundException {
        InetSocketAddress addr = new InetSocketAddress(TestUtils.getLoopbackAddress(), port);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        HostnameRewritingObjectOutputStream oos =
                new HostnameRewritingObjectOutputStream(baos, hostname);
        oos.writeObject(addr);
        oos.close();
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));
        return (InetSocketAddress) ois.readObject();
    }
    private TestSSLContext(KeyStore clientKeyStore, char[] clientStorePassword,
            KeyStore serverKeyStore, char[] serverStorePassword, KeyManager[] clientKeyManagers,
            KeyManager[] serverKeyManagers, X509TrustManager clientTrustManager,
            X509TrustManager serverTrustManager, SSLContext clientContext,
            SSLContext serverContext, SSLServerSocket serverSocket, InetAddress host, int port) {
        this.clientKeyStore = clientKeyStore;
        this.clientStorePassword = clientStorePassword;
        this.serverKeyStore = serverKeyStore;
        this.serverStorePassword = serverStorePassword;
        this.clientKeyManagers = clientKeyManagers;
        this.serverKeyManagers = serverKeyManagers;
        this.clientTrustManager = clientTrustManager;
        this.serverTrustManager = serverTrustManager;
        this.clientContext = clientContext;
        this.serverContext = serverContext;
        this.serverSocket = serverSocket;
        this.host = host;
        this.port = port;
    }
    public void close() {
        try {
            serverSocket.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public static final class Builder {
        private TestKeyStore client;
        private char[] clientStorePassword;
        private TestKeyStore server;
        private char[] serverStorePassword;
        private KeyManager[] additionalClientKeyManagers;
        private KeyManager[] additionalServerKeyManagers;
        private TrustManager clientTrustManager;
        private TrustManager serverTrustManager;
        private SSLContext clientContext;
        private SSLContext serverContext;
        private String clientProtocol = "TLS";
        private String serverProtocol = "TLS";
        private int serverReceiveBufferSize;
        private boolean useDefaults = true;

        public Builder useDefaults(boolean useDefaults) {
            this.useDefaults = useDefaults;
            return this;
        }

        public Builder client(TestKeyStore client) {
            this.client = client;
            return this;
        }

        public Builder clientStorePassword(char[] clientStorePassword) {
            this.clientStorePassword = clientStorePassword;
            return this;
        }

        public Builder server(TestKeyStore server) {
            this.server = server;
            return this;
        }

        public Builder serverStorePassword(char[] serverStorePassword) {
            this.serverStorePassword = serverStorePassword;
            return this;
        }

        public Builder additionalClientKeyManagers(KeyManager[] additionalClientKeyManagers) {
            this.additionalClientKeyManagers = additionalClientKeyManagers;
            return this;
        }

        public Builder additionalServerKeyManagers(KeyManager[] additionalServerKeyManagers) {
            this.additionalServerKeyManagers = additionalServerKeyManagers;
            return this;
        }

        public Builder clientTrustManager(TrustManager clientTrustManager) {
            this.clientTrustManager = clientTrustManager;
            return this;
        }

        public Builder serverTrustManager(TrustManager serverTrustManager) {
            this.serverTrustManager = serverTrustManager;
            return this;
        }

        public Builder clientContext(SSLContext clientContext) {
            this.clientContext = clientContext;
            return this;
        }

        public Builder serverContext(SSLContext serverContext) {
            this.serverContext = serverContext;
            return this;
        }

        public Builder clientProtocol(String clientProtocol) {
            this.clientProtocol = clientProtocol;
            return this;
        }

        public Builder serverProtocol(String serverProtocol) {
            this.serverProtocol = serverProtocol;
            return this;
        }

        public Builder serverReceiveBufferSize(int serverReceiveBufferSize) {
            this.serverReceiveBufferSize = serverReceiveBufferSize;
            return this;
        }

        TestSSLContext build() {
            // Get the current values for all the things.
            TestKeyStore client = this.client;
            TestKeyStore server = this.server;
            char[] clientStorePassword = this.clientStorePassword;
            char[] serverStorePassword = this.serverStorePassword;
            KeyManager[] clientKeyManagers = client != null ? client.keyManagers : null;
            KeyManager[] serverKeyManagers = server != null ? server.keyManagers : null;
            TrustManager clientTrustManager = this.clientTrustManager;
            TrustManager serverTrustManager = this.serverTrustManager;
            SSLContext clientContext = this.clientContext;
            SSLContext serverContext = this.serverContext;

            // Apply default values if configured to do so.
            if (useDefaults) {
                client = client != null ? client : TestKeyStore.getClient();
                server = server != null ? server : TestKeyStore.getServer();
                clientStorePassword =
                        clientStorePassword != null ? clientStorePassword : client.storePassword;
                serverStorePassword =
                        serverStorePassword != null ? serverStorePassword : server.storePassword;
                clientKeyManagers =
                        clientKeyManagers != null ? clientKeyManagers : client.keyManagers;
                serverKeyManagers =
                        serverKeyManagers != null ? serverKeyManagers : server.keyManagers;
                clientKeyManagers = concat(clientKeyManagers, additionalClientKeyManagers);
                serverKeyManagers = concat(serverKeyManagers, additionalServerKeyManagers);
                clientTrustManager =
                        clientTrustManager != null ? clientTrustManager : client.trustManagers[0];
                serverTrustManager =
                        serverTrustManager != null ? serverTrustManager : server.trustManagers[0];

                clientContext = clientContext != null
                        ? clientContext
                        : createSSLContext(clientProtocol, clientKeyManagers,
                                  new TrustManager[] {clientTrustManager});
                serverContext = serverContext != null
                        ? serverContext
                        : createSSLContext(serverProtocol, serverKeyManagers,
                                  new TrustManager[] {serverTrustManager});
            }

            // Create the context.
            try {
                SSLServerSocket serverSocket =
                        (SSLServerSocket) serverContext.getServerSocketFactory()
                                .createServerSocket();
                if (serverReceiveBufferSize > 0) {
                    // The TCP spec says that this should occur before listen.
                    serverSocket.setReceiveBufferSize(serverReceiveBufferSize);
                }
                InetAddress host = TestUtils.getLoopbackAddress();
                serverSocket.bind(new InetSocketAddress(host, 0));
                int port = serverSocket.getLocalPort();
                return new TestSSLContext(client != null ? client.keyStore : null,
                        clientStorePassword, server != null ? server.keyStore : null,
                        serverStorePassword, clientKeyManagers, serverKeyManagers,
                        (X509TrustManager) clientTrustManager,
                        (X509TrustManager) serverTrustManager, clientContext, serverContext,
                        serverSocket, host, port);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Usual TestSSLContext creation method, creates underlying
     * SSLContext with certificate and key as well as SSLServerSocket
     * listening provided host and port.
     */
    public static TestSSLContext create() {
        return new Builder().build();
    }

    /**
     * TestSSLContext creation method that allows separate creation of server key store
     */
    public static TestSSLContext create(TestKeyStore client, TestKeyStore server) {
        return new Builder().client(client).server(server).build();
    }
    /**
     * Create a SSLContext with a KeyManager using the private key and
     * certificate chain from the given KeyStore and a TrustManager
     * using the certificates authorities from the same KeyStore.
     */
    public static SSLContext createSSLContext(final String protocol, final KeyManager[] keyManagers,
            final TrustManager[] trustManagers) {
        try {
            SSLContext context = SSLContext.getInstance(protocol);
            context.init(keyManagers, trustManagers, new SecureRandom());
            return context;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public static void assertCertificateInKeyStore(Principal principal, KeyStore keyStore)
            throws Exception {
        String subjectName = principal.getName();
        boolean found = false;
        for (String alias : Collections.list(keyStore.aliases())) {
            if (!keyStore.isCertificateEntry(alias)) {
                continue;
            }
            X509Certificate keyStoreCertificate = (X509Certificate) keyStore.getCertificate(alias);
            if (subjectName.equals(keyStoreCertificate.getSubjectDN().getName())) {
                found = true;
                break;
            }
        }
        assertTrue(found);
    }
    public static void assertCertificateInKeyStore(Certificate certificate, KeyStore keyStore)
            throws Exception {
        boolean found = false;
        for (String alias : Collections.list(keyStore.aliases())) {
            if (!keyStore.isCertificateEntry(alias)) {
                continue;
            }
            Certificate keyStoreCertificate = keyStore.getCertificate(alias);
            if (certificate.equals(keyStoreCertificate)) {
                found = true;
                break;
            }
        }
        assertTrue(found);
    }
    public static void assertServerCertificateChain(
            X509TrustManager trustManager, Certificate[] serverChain) throws CertificateException {
        X509Certificate[] chain = (X509Certificate[]) serverChain;
        trustManager.checkServerTrusted(chain, chain[0].getPublicKey().getAlgorithm());
    }
    public static void assertClientCertificateChain(
            X509TrustManager trustManager, Certificate[] clientChain) throws CertificateException {
        X509Certificate[] chain = (X509Certificate[]) clientChain;
        trustManager.checkClientTrusted(chain, chain[0].getPublicKey().getAlgorithm());
    }
    /**
     * Returns an SSLSocketFactory that calls setWantClientAuth and
     * setNeedClientAuth as specified on all returned sockets.
     */
    public static SSLSocketFactory clientAuth(
            final SSLSocketFactory sf, final boolean want, final boolean need) {
        return new SSLSocketFactory() {
            private SSLSocket set(Socket socket) {
                SSLSocket s = (SSLSocket) socket;
                s.setWantClientAuth(want);
                s.setNeedClientAuth(need);
                return s;
            }
            @Override
            public Socket createSocket(String host, int port) throws IOException {
                return set(sf.createSocket(host, port));
            }
            @Override
            public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
                    throws IOException {
                return set(sf.createSocket(host, port, localHost, localPort));
            }
            @Override
            public Socket createSocket(InetAddress host, int port) throws IOException {
                return set(sf.createSocket(host, port));
            }
            @Override
            public Socket createSocket(InetAddress address, int port, InetAddress localAddress,
                    int localPort) throws IOException {
                return set(sf.createSocket(address, port));
            }
            @Override
            public String[] getDefaultCipherSuites() {
                return sf.getDefaultCipherSuites();
            }
            @Override
            public String[] getSupportedCipherSuites() {
                return sf.getSupportedCipherSuites();
            }
            @Override
            public Socket createSocket(Socket s, String host, int port, boolean autoClose)
                    throws IOException {
                return set(sf.createSocket(s, host, port, autoClose));
            }
        };
    }
    private static KeyManager[] concat(KeyManager[] a, KeyManager[] b) {
        if ((a == null) || (a.length == 0)) {
            return b;
        }
        if ((b == null) || (b.length == 0)) {
            return a;
        }
        KeyManager[] result = new KeyManager[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
