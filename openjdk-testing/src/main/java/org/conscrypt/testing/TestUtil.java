/*
 * Copyright 2017 The Android Open Source Project
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

package org.conscrypt.testing;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import com.google.common.base.Charsets;
import com.google.common.io.BaseEncoding;
import com.google.common.io.CharStreams;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

/**
 * Utility methods to support testing.
 */
public final class TestUtil {
    private static final Provider JDK_PROVIDER = getDefaultTlsProvider();
    private static final Provider CONSCRYPT_PROVIDER = getConscryptProvider();
    private static final byte[] CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".getBytes();
    private static final Pattern KEY_PATTERN =
            Pattern.compile("-+BEGIN\\s+.*PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+" + // Header
                            "([a-z0-9+/=\\r\\n]+)" + // Base64 text
                            "-+END\\s+.*PRIVATE\\s+KEY[^-]*-+", // Footer
                    Pattern.CASE_INSENSITIVE);

    public static final String PROTOCOL_TLS_V1_2 = "TLSv1.2";
    public static final String PROVIDER_PROPERTY = "SSLContext.TLSv1.2";
    public static final String LOCALHOST = "localhost";

    private TestUtil() {}

    /**
     * Returns an array containing only {@link #PROTOCOL_TLS_V1_2}.
     */
    public static String[] getProtocols() {
        return new String[] {PROTOCOL_TLS_V1_2};
    }

    public static SSLSocketFactory getJdkSocketFactory() {
        return getSocketFactory(JDK_PROVIDER);
    }

    public static SSLServerSocketFactory getJdkServerSocketFactory() {
        return getServerSocketFactory(JDK_PROVIDER);
    }

    public static SSLSocketFactory getConscryptSocketFactory(boolean useEngineSocket) {
        try {
            Class<?> clazz = Class.forName("org.conscrypt.OpenSSLSocketFactoryImpl");
            Method method = clazz.getMethod("setUseEngineSocket", boolean.class);
            SSLSocketFactory socketFactory = getSocketFactory(CONSCRYPT_PROVIDER);
            method.invoke(socketFactory, useEngineSocket);
            return socketFactory;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static SSLServerSocketFactory getConscryptServerSocketFactory() {
        return getServerSocketFactory(CONSCRYPT_PROVIDER);
    }

    private static SSLSocketFactory getSocketFactory(Provider provider) {
        SSLContext clientContext = initClientSslContext(newContext(provider));
        return clientContext.getSocketFactory();
    }

    private static SSLServerSocketFactory getServerSocketFactory(Provider provider) {
        SSLContext serverContext = initServerContext(newContext(provider));
        return serverContext.getServerSocketFactory();
    }

    public static SSLContext newContext(Provider provider) {
        try {
            return SSLContext.getInstance("TLS", provider);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static SslContext newNettyClientContext(String cipher) {
        try {
            File clientCert = loadCert("ca.pem");
            SslContextBuilder ctx = SslContextBuilder.forClient()
                                            .sslProvider(io.netty.handler.ssl.SslProvider.OPENSSL)
                                            .trustManager(clientCert);
            if (cipher != null) {
                ctx.ciphers(Collections.singletonList(cipher));
            }
            return ctx.build();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    public static SslContext newNettyServerContext(String cipher) {
        try {
            File serverCert = loadCert("server1.pem");
            File serverKey = loadCert("server1.key");
            SslContextBuilder ctx = SslContextBuilder.forServer(serverCert, serverKey)
                                            .sslProvider(io.netty.handler.ssl.SslProvider.OPENSSL);
            if (cipher != null) {
                ctx.ciphers(Collections.singletonList(cipher));
            }
            return ctx.build();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Picks a port that is not used right at this moment.
     * Warning: Not thread safe. May see "BindException: Address already in use: bind" if using the
     * returned port to create a new server socket when other threads/processes are concurrently
     * creating new sockets without a specific port.
     */
    public static int pickUnusedPort() {
        try {
            ServerSocket serverSocket = new ServerSocket(0);
            int port = serverSocket.getLocalPort();
            serverSocket.close();
            return port;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Creates a text message of the given length.
     */
    public static byte[] newTextMessage(int length) {
        byte[] msg = new byte[length];
        for (int msgIndex = 0; msgIndex < length;) {
            int remaining = length - msgIndex;
            int numChars = Math.min(remaining, CHARS.length);
            System.arraycopy(CHARS, 0, msg, msgIndex, numChars);
            msgIndex += numChars;
        }
        return msg;
    }

    /**
     * Initializes the given engine with the cipher and client mode.
     */
    public static SSLEngine initEngine(SSLEngine engine, String cipher, boolean client) {
        engine.setEnabledProtocols(getProtocols());
        engine.setEnabledCipherSuites(new String[] {cipher});
        engine.setUseClientMode(client);
        return engine;
    }

    /**
     * Load a file from the resources folder.
     *
     * @param name  name of a file in src/main/resources/certs.
     */
    public static File loadCert(String name) {
        try {
            InputStream in =
                    TestUtil.class.getResourceAsStream("/org/conscrypt/testing/certs/" + name);
            File tmpFile = File.createTempFile(name, "");
            tmpFile.deleteOnExit();

            BufferedWriter writer = new BufferedWriter(new FileWriter(tmpFile));
            try {
                int b;
                while ((b = in.read()) != -1) {
                    writer.write(b);
                }
            } finally {
                writer.close();
            }

            return tmpFile;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Initializes the given client-side {@code context} with a default cert.
     */
    public static SSLContext initClientSslContext(SSLContext context) {
        File cert = loadCert("ca.pem");
        return initClientSslContext(context, cert);
    }

    /**
     * Initializes the given client-side {@code context} with an appropriate trust manager based on
     * the {@code certChainFile} as its only root certificate.
     */
    public static SSLContext initClientSslContext(SSLContext context, File certChainFile) {
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new BufferedInputStream(new FileInputStream(certChainFile)));
            X500Principal principal = cert.getSubjectX500Principal();
            ks.setCertificateEntry(principal.getName("RFC2253"), cert);

            // Set up trust manager factory to use our key store.
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(ks);
            context.init(null, trustManagerFactory.getTrustManagers(), null);
            return context;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Initializes the given server-side {@code context} with the default cert chain and key.
     */
    public static SSLContext initServerContext(SSLContext context) {
        File cert = loadCert("server1.pem");
        File key = loadCert("server1.key");
        return initServerContext(context, cert, key);
    }

    /**
     * Initializes the given server-side {@code context} with the given cert chain and private key.
     */
    public static SSLContext initServerContext(
            SSLContext context, File certChainFile, File keyFile) {
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);

            // Read the cert.
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new BufferedInputStream(new FileInputStream(certChainFile)));

            // Read the private key.
            byte[] keyData = readPrivateKey(keyFile);
            KeySpec keySpec = new PKCS8EncodedKeySpec(keyData);
            PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(keySpec);

            ks.setKeyEntry("key", key, new char[0], new Certificate[] {cert});
            KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, new char[0]);

            // Set up trust manager factory to use our key store.
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(ks);
            context.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            return context;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Performs the intial TLS handshake between the two {@link SSLEngine} instances.
     */
    public static void doEngineHandshake(SSLEngine clientEngine, SSLEngine serverEngine)
            throws SSLException {
        ByteBuffer cTOs = ByteBuffer.allocate(clientEngine.getSession().getPacketBufferSize());
        ByteBuffer sTOc = ByteBuffer.allocate(serverEngine.getSession().getPacketBufferSize());

        ByteBuffer serverAppReadBuffer =
                ByteBuffer.allocate(serverEngine.getSession().getApplicationBufferSize());
        ByteBuffer clientAppReadBuffer =
                ByteBuffer.allocate(clientEngine.getSession().getApplicationBufferSize());

        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        ByteBuffer empty = ByteBuffer.allocate(0);

        SSLEngineResult clientResult;
        SSLEngineResult serverResult;

        boolean clientHandshakeFinished = false;
        boolean serverHandshakeFinished = false;

        do {
            int cTOsPos = cTOs.position();
            int sTOcPos = sTOc.position();

            clientResult = clientEngine.wrap(empty, cTOs);
            runDelegatedTasks(clientResult, clientEngine);
            serverResult = serverEngine.wrap(empty, sTOc);
            runDelegatedTasks(serverResult, serverEngine);

            // Verify that the consumed and produced number match what is in the buffers now.
            assertEquals(empty.remaining(), clientResult.bytesConsumed());
            assertEquals(empty.remaining(), serverResult.bytesConsumed());
            assertEquals(cTOs.position() - cTOsPos, clientResult.bytesProduced());
            assertEquals(sTOc.position() - sTOcPos, serverResult.bytesProduced());

            cTOs.flip();
            sTOc.flip();

            // Verify that we only had one SSLEngineResult.HandshakeStatus.FINISHED
            if (isHandshakeFinished(clientResult)) {
                assertFalse(clientHandshakeFinished);
                clientHandshakeFinished = true;
            }
            if (isHandshakeFinished(serverResult)) {
                assertFalse(serverHandshakeFinished);
                serverHandshakeFinished = true;
            }

            cTOsPos = cTOs.position();
            sTOcPos = sTOc.position();

            int clientAppReadBufferPos = clientAppReadBuffer.position();
            int serverAppReadBufferPos = serverAppReadBuffer.position();

            clientResult = clientEngine.unwrap(sTOc, clientAppReadBuffer);
            runDelegatedTasks(clientResult, clientEngine);
            serverResult = serverEngine.unwrap(cTOs, serverAppReadBuffer);
            runDelegatedTasks(serverResult, serverEngine);

            // Verify that the consumed and produced number match what is in the buffers now.
            assertEquals(sTOc.position() - sTOcPos, clientResult.bytesConsumed());
            assertEquals(cTOs.position() - cTOsPos, serverResult.bytesConsumed());
            assertEquals(clientAppReadBuffer.position() - clientAppReadBufferPos,
                    clientResult.bytesProduced());
            assertEquals(serverAppReadBuffer.position() - serverAppReadBufferPos,
                    serverResult.bytesProduced());

            cTOs.compact();
            sTOc.compact();

            // Verify that we only had one SSLEngineResult.HandshakeStatus.FINISHED
            if (isHandshakeFinished(clientResult)) {
                assertFalse(clientHandshakeFinished);
                clientHandshakeFinished = true;
            }
            if (isHandshakeFinished(serverResult)) {
                assertFalse(serverHandshakeFinished);
                serverHandshakeFinished = true;
            }
        } while (!clientHandshakeFinished || !serverHandshakeFinished);
    }

    private static boolean isHandshakeFinished(SSLEngineResult result) {
        return result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED;
    }

    private static void runDelegatedTasks(SSLEngineResult result, SSLEngine engine) {
        if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            for (;;) {
                Runnable task = engine.getDelegatedTask();
                if (task == null) {
                    break;
                }
                task.run();
            }
        }
    }

    private static byte[] readPrivateKey(File file) throws KeyException {
        String content = readPemFileContent(file);

        Matcher m = KEY_PATTERN.matcher(content);
        if (!m.find()) {
            throw new KeyException("could not find a PKCS #8 private key in input stream"
                    + " (see http://netty.io/wiki/sslcontextbuilder-and-private-key.html for more information)");
        }

        String data = m.group(1).replace("\n", "");
        return BaseEncoding.base64().decode(data);
    }

    private static String readPemFileContent(File file) {
        InputStream in = null;
        Reader reader = null;
        try {
            in = new FileInputStream(file);
            reader = new InputStreamReader(in, Charsets.US_ASCII);
            return CharStreams.toString(reader);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
                if (reader != null) {
                    reader.close();
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static Provider getDefaultTlsProvider() {
        for (Provider p : Security.getProviders()) {
            if (p.get(PROVIDER_PROPERTY) != null) {
                return p;
            }
        }
        throw new RuntimeException("Unable to find a default provider for " + PROVIDER_PROPERTY);
    }

    private static final Provider getConscryptProvider() {
        try {
            return (Provider) Class.forName("org.conscrypt.OpenSSLProvider")
                    .getConstructor()
                    .newInstance();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
