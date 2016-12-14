/*
 * Copyright (C) 2015 The Android Open Source Project
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

import static org.conscrypt.TestUtils.openTestFile;
import static org.conscrypt.TestUtils.readTestFile;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class OpenSSLSocketImplTest {
    private static final long TIMEOUT_SECONDS = 5;
    private static final char[] EMPTY_PASSWORD = new char[0];

    private X509Certificate ca;
    private X509Certificate cert;
    private X509Certificate certEmbedded;
    private PrivateKey certKey;

    private Field contextSSLParameters;
    private Field sslParametersTrustManager;

    @Before
    public void setUp() throws Exception {
        contextSSLParameters = OpenSSLContextImpl.class.getDeclaredField("sslParameters");
        contextSSLParameters.setAccessible(true);

        sslParametersTrustManager = SSLParametersImpl.class.getDeclaredField("x509TrustManager");
        sslParametersTrustManager.setAccessible(true);

        ca = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem"));
        cert = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert.pem"));
        certEmbedded =
                OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert-ct-embedded.pem"));
        certKey = OpenSSLKey.fromPrivateKeyPemInputStream(openTestFile("cert-key.pem"))
                          .getPrivateKey();
    }

    abstract class Hooks implements HandshakeCompletedListener {
        KeyManager[] keyManagers;
        TrustManager[] trustManagers;

        abstract OpenSSLSocketImpl createSocket(SSLSocketFactory factory, ServerSocket listener)
                throws IOException;

        public OpenSSLContextImpl createContext() throws Exception {
            OpenSSLContextImpl context = OpenSSLContextImpl.getPreferred();
            context.engineInit(keyManagers, trustManagers, null);
            return context;
        }

        boolean isHandshakeCompleted = false;
        @Override
        public void handshakeCompleted(HandshakeCompletedEvent event) {
            isHandshakeCompleted = true;
        }

        protected SSLParametersImpl getContextSSLParameters(OpenSSLContextImpl context)
                throws IllegalAccessException {
            return (SSLParametersImpl) contextSSLParameters.get(context);
        }

        protected TrustManager getSSLParametersTrustManager(SSLParametersImpl params)
                throws IllegalAccessException {
            return (TrustManager) sslParametersTrustManager.get(params);
        }
    }

    class ClientHooks extends Hooks {
        boolean ctVerificationEnabled;
        String hostname = "example.com";

        @Override
        public OpenSSLContextImpl createContext() throws Exception {
            OpenSSLContextImpl context = super.createContext();
            SSLParametersImpl sslParameters = getContextSSLParameters(context);
            if (ctVerificationEnabled) {
                sslParameters.setCTVerificationEnabled(ctVerificationEnabled);
            }
            return context;
        }

        @Override
        public OpenSSLSocketImpl createSocket(SSLSocketFactory factory, ServerSocket listener)
                throws IOException {
            OpenSSLSocketImpl socket = (OpenSSLSocketImpl) factory.createSocket(
                    listener.getInetAddress(), listener.getLocalPort());
            socket.setUseClientMode(true);
            socket.setHostname(hostname);

            return socket;
        }
    }

    class ServerHooks extends Hooks {
        byte[] sctTLSExtension;
        byte[] ocspResponse;

        @Override
        public OpenSSLContextImpl createContext() throws Exception {
            OpenSSLContextImpl context = super.createContext();
            SSLParametersImpl sslParameters = getContextSSLParameters(context);
            sslParameters.setSCTExtension(sctTLSExtension);
            sslParameters.setOCSPResponse(ocspResponse);
            return context;
        }

        @Override
        public OpenSSLSocketImpl createSocket(SSLSocketFactory factory, ServerSocket listener)
                throws IOException {
            OpenSSLSocketImpl socket = (OpenSSLSocketImpl) factory.createSocket(listener.accept(),
                    null, -1, // hostname, port
                    true); // autoclose
            socket.setUseClientMode(false);
            return socket;
        }
    }

    class TestConnection {
        ServerHooks serverHooks;
        ClientHooks clientHooks;

        OpenSSLSocketImpl client;
        OpenSSLSocketImpl server;

        Exception clientException;
        Exception serverException;

        public TestConnection(X509Certificate[] chain, PrivateKey key) throws Exception {
            clientHooks = new ClientHooks();
            serverHooks = new ServerHooks();
            setCertificates(chain, key);
        }

        private void setCertificates(X509Certificate[] chain, PrivateKey key) throws Exception {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setKeyEntry("default", key, EMPTY_PASSWORD, chain);
            ks.setCertificateEntry("CA", chain[chain.length - 1]);

            TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            TrustManager[] tms = tmf.getTrustManagers();

            KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, EMPTY_PASSWORD);
            KeyManager[] kms = kmf.getKeyManagers();

            clientHooks.trustManagers = tms;
            serverHooks.keyManagers = kms;
            serverHooks.trustManagers = tms;
        }

        private <T> T getOrThrowCause(Future<T> future, long timeout, TimeUnit timeUnit)
                throws Exception {
            try {
                return future.get(timeout, timeUnit);
            } catch (ExecutionException e) {
                if (e.getCause() instanceof Exception) {
                    throw(Exception) e.getCause();
                } else {
                    throw e;
                }
            }
        }

        public void doHandshake() throws Exception {
            ServerSocket listener = new ServerSocket(0);
            Future<OpenSSLSocketImpl> clientFuture = handshake(listener, clientHooks);
            Future<OpenSSLSocketImpl> serverFuture = handshake(listener, serverHooks);

            Exception cause = null;
            try {
                client = getOrThrowCause(clientFuture, TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (Exception e) {
                clientException = e;
            }
            try {
                server = getOrThrowCause(serverFuture, TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (Exception e) {
                serverException = e;
            }
        }

        Future<OpenSSLSocketImpl> handshake(final ServerSocket listener, final Hooks hooks) {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            Future<OpenSSLSocketImpl> future = executor.submit(new Callable<OpenSSLSocketImpl>() {
                @Override
                public OpenSSLSocketImpl call() throws Exception {
                    OpenSSLContextImpl context = hooks.createContext();
                    SSLSocketFactory factory = context.engineGetSocketFactory();
                    OpenSSLSocketImpl socket = hooks.createSocket(factory, listener);
                    socket.addHandshakeCompletedListener(hooks);

                    socket.startHandshake();

                    return socket;
                }
            });

            executor.shutdown();

            return future;
        }
    }

    @Test
    public void test_handshake() throws Exception {
        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);
        connection.doHandshake();

        assertTrue(connection.clientHooks.isHandshakeCompleted);
        assertTrue(connection.serverHooks.isHandshakeCompleted);
    }

    @Test
    public void test_handshakeWithEmbeddedSCT() throws Exception {
        TestConnection connection =
                new TestConnection(new X509Certificate[] {certEmbedded, ca}, certKey);

        connection.clientHooks.ctVerificationEnabled = true;

        connection.doHandshake();

        assertTrue(connection.clientHooks.isHandshakeCompleted);
        assertTrue(connection.serverHooks.isHandshakeCompleted);
    }

    @Test
    public void test_handshakeWithSCTFromOCSPResponse() throws Exception {
        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);

        connection.clientHooks.ctVerificationEnabled = true;
        connection.serverHooks.ocspResponse = readTestFile("ocsp-response.der");

        connection.doHandshake();

        assertTrue(connection.clientHooks.isHandshakeCompleted);
        assertTrue(connection.serverHooks.isHandshakeCompleted);
    }

    @Test
    public void test_handshakeWithSCTFromTLSExtension() throws Exception {
        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);

        connection.clientHooks.ctVerificationEnabled = true;
        connection.serverHooks.sctTLSExtension = readTestFile("ct-signed-timestamp-list");

        connection.doHandshake();

        assertTrue(connection.clientHooks.isHandshakeCompleted);
        assertTrue(connection.serverHooks.isHandshakeCompleted);
    }

    @Ignore("TODO(nathanmittler): Fix or remove")
    @Test
    public void test_handshake_failsWithMissingSCT() throws Exception {
        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);

        connection.clientHooks.ctVerificationEnabled = true;

        connection.doHandshake();
        assertThat(connection.clientException, instanceOf(SSLHandshakeException.class));
        assertThat(connection.clientException.getCause(), instanceOf(CertificateException.class));
    }

    @Ignore("TODO(nathanmittler): Fix or remove")
    @Test
    public void test_handshake_failsWithInvalidSCT() throws Exception {
        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);

        connection.clientHooks.ctVerificationEnabled = true;
        connection.serverHooks.sctTLSExtension = readTestFile("ct-signed-timestamp-list-invalid");

        connection.doHandshake();
        assertThat(connection.clientException, instanceOf(SSLHandshakeException.class));
        assertThat(connection.clientException.getCause(), instanceOf(CertificateException.class));
    }

    // http://b/27250522
    @Test
    public void test_setSoTimeout_doesNotCreateSocketImpl() throws Exception {
        ServerSocket listening = new ServerSocket(0);
        Socket underlying = new Socket(listening.getInetAddress(), listening.getLocalPort());

        Constructor<OpenSSLSocketImpl> cons = OpenSSLSocketImpl.class.getDeclaredConstructor(
                Socket.class, String.class, Integer.TYPE, Boolean.TYPE, SSLParametersImpl.class);
        cons.setAccessible(true);
        OpenSSLSocketImpl simpl =
                cons.newInstance(underlying, null, listening.getLocalPort(), false, null);
        simpl.setSoTimeout(1000);
        simpl.close();

        Field f = Socket.class.getDeclaredField("created");
        f.setAccessible(true);
        assertFalse(f.getBoolean(simpl));
    }

    @Test
    public void test_setEnabledProtocols_FiltersSSLv3_HandshakeException() throws Exception {
        TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);

        connection.clientHooks = new ClientHooks() {
            @Override
            public OpenSSLSocketImpl createSocket(SSLSocketFactory factory, ServerSocket listener)
                    throws IOException {
                OpenSSLSocketImpl socket = super.createSocket(factory, listener);
                socket.setEnabledProtocols(new String[] {"SSLv3"});
                assertEquals(
                        "SSLv3 should be filtered out", 0, socket.getEnabledProtocols().length);
                return socket;
            }
        };

        connection.doHandshake();
        assertThat(connection.clientException, instanceOf(SSLHandshakeException.class));
        assertTrue(
                connection.clientException.getMessage().contains("SSLv3 is no longer supported"));
        assertThat(connection.serverException, instanceOf(SSLHandshakeException.class));

        assertFalse(connection.clientHooks.isHandshakeCompleted);
        assertFalse(connection.serverHooks.isHandshakeCompleted);
    }
}
