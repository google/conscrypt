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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import libcore.io.Streams;
import libcore.java.security.TestKeyStore;

/**
 * Utility methods to support testing.
 */
public final class TestUtils {
    static final Charset UTF_8 = Charset.forName("UTF-8");

    private static final Provider JDK_PROVIDER = getDefaultTlsProvider();
    private static final Provider CONSCRYPT_PROVIDER = getConscryptProvider();
    private static final byte[] CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".getBytes(UTF_8);

    public static final String PROTOCOL_TLS_V1_2 = "TLSv1.2";
    private static final String PROVIDER_PROPERTY = "SSLContext.TLSv1.2";
    public static final String LOCALHOST = "localhost";

    private TestUtils() {}

    public static InputStream openTestFile(String name) throws FileNotFoundException {
        InputStream is = TestUtils.class.getResourceAsStream("/" + name);
        if (is == null) {
            throw new FileNotFoundException(name);
        }
        return is;
    }

    public static byte[] readTestFile(String name) throws IOException {
        return Streams.readFully(openTestFile(name));
    }

    /**
     * Returns an array containing only {@link #PROTOCOL_TLS_V1_2}.
     */
    static String[] getProtocols() {
        return new String[] {PROTOCOL_TLS_V1_2};
    }

    static SSLSocketFactory getJdkSocketFactory() {
        return getSocketFactory(JDK_PROVIDER);
    }

    static SSLServerSocketFactory getJdkServerSocketFactory() {
        return getServerSocketFactory(JDK_PROVIDER);
    }

    static SSLSocketFactory getConscryptSocketFactory(boolean useEngineSocket) {
        try {
            Class<?> clazz = Class.forName("org.conscrypt.Conscrypt$SocketFactories");
            Method method = clazz.getMethod("setUseEngineSocket", SSLSocketFactory.class, boolean.class);

            SSLSocketFactory socketFactory = getSocketFactory(CONSCRYPT_PROVIDER);
            method.invoke(null, socketFactory, useEngineSocket);
            return socketFactory;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static SSLServerSocketFactory getConscryptServerSocketFactory(boolean useEngineSocket) {
        try {
            Class<?> clazz = Class.forName("org.conscrypt.Conscrypt$ServerSocketFactories");
            Method method = clazz.getMethod("setUseEngineSocket", SSLServerSocketFactory.class, boolean.class);

            SSLServerSocketFactory socketFactory = getServerSocketFactory(CONSCRYPT_PROVIDER);
            method.invoke(null, socketFactory, useEngineSocket);
            return socketFactory;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static SSLSocketFactory getSocketFactory(Provider provider) {
        SSLContext clientContext = initClientSslContext(newContext(provider));
        return clientContext.getSocketFactory();
    }

    private static SSLServerSocketFactory getServerSocketFactory(Provider provider) {
        SSLContext serverContext = initServerSslContext(newContext(provider));
        return serverContext.getServerSocketFactory();
    }

    private static SSLContext newContext(Provider provider) {
        try {
            return SSLContext.getInstance("TLS", provider);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Picks a port that is not used right at this moment.
     * Warning: Not thread safe. May see "BindException: Address already in use: bind" if using the
     * returned port to create a new server socket when other threads/processes are concurrently
     * creating new sockets without a specific port.
     */
    static int pickUnusedPort() {
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
    static byte[] newTextMessage(int length) {
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
    static SSLEngine initEngine(SSLEngine engine, String cipher, boolean client) {
        engine.setEnabledProtocols(getProtocols());
        engine.setEnabledCipherSuites(new String[] {cipher});
        engine.setUseClientMode(client);
        return engine;
    }

    /**
     * Initializes the given client-side {@code context} with a default cert.
     */
    private static SSLContext initClientSslContext(SSLContext context) {
        return initSslContext(context, TestKeyStore.getClient());
    }

    /**
     * Initializes the given server-side {@code context} with the given cert chain and private key.
     */
    private static SSLContext initServerSslContext(SSLContext context) {
        return initSslContext(context, TestKeyStore.getServer());
    }

    /**
     * Initializes the given {@code context} from the {@code keyStore}.
     */
    static SSLContext initSslContext(SSLContext context, TestKeyStore keyStore) {
        try {
            context.init(keyStore.keyManagers, keyStore.trustManagers, null);
            return context;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Performs the intial TLS handshake between the two {@link SSLEngine} instances.
     */
    static void doEngineHandshake(SSLEngine clientEngine, SSLEngine serverEngine)
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

    private static Provider getDefaultTlsProvider() {
        for (Provider p : Security.getProviders()) {
            if (p.get(PROVIDER_PROPERTY) != null) {
                return p;
            }
        }
        throw new RuntimeException("Unable to find a default provider for " + PROVIDER_PROPERTY);
    }

    private static Provider getConscryptProvider() {
        try {
            return (Provider) Class.forName("org.conscrypt.OpenSSLProvider")
                    .getConstructor()
                    .newInstance();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
