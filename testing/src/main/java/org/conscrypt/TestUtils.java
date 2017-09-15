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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import libcore.io.Streams;
import libcore.java.security.TestKeyStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assume;

/**
 * Utility methods to support testing.
 */
public final class TestUtils {
    public static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final String PROTOCOL_TLS_V1_2 = "TLSv1.2";
    private static final String PROTOCOL_TLS_V1 = "TLSv1";
    private static final String[] DESIRED_PROTOCOLS =
        new String[] {PROTOCOL_TLS_V1_2, /* For Java 6 */ PROTOCOL_TLS_V1};
    private static final Provider JDK_PROVIDER = getDefaultTlsProvider();
    private static final byte[] CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".getBytes(UTF_8);
    private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocateDirect(0);
    private static final String[] PROTOCOLS = getProtocolsInternal();

    static final String TEST_CIPHER = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";

    private TestUtils() {}

    private static Provider getDefaultTlsProvider() {
        for (String protocol : DESIRED_PROTOCOLS) {
            for (Provider p : Security.getProviders()) {
                if (hasProtocol(p, protocol)) {
                    return p;
                }
            }
        }
        // For Java 1.6 testing
        return new BouncyCastleProvider();
    }

    private static boolean hasProtocol(Provider p, String protocol) {
        return p.get("SSLContext." + protocol) != null;
    }

    static Provider getJdkProvider() {
        return JDK_PROVIDER;
    }

    public static void assumeSNIHostnameAvailable() {
        boolean available = false;
        try {
            Class.forName("javax.net.ssl.SNIHostName");
            available = true;
        } catch (ClassNotFoundException ignore) {
            // Ignored
        }
        Assume.assumeTrue("Skipping test: SNIHostName unavailable", available);
    }

    public static void assumeSetEndpointIdentificationAlgorithmAvailable() {
        boolean supported = false;
        try {
            SSLParameters.class.getMethod("Skipping test: "
                            + "SSLParameters.setEndpointIdentificationAlgorithm unavailable",
                    String.class);
            supported = true;
        } catch (NoSuchMethodException ignore) {
            // Ignored
        }
        Assume.assumeTrue(supported);
    }

    public static InetAddress getLoopbackAddress() {
        try {
            Method method = InetAddress.class.getMethod("getLoopbackAddress");
            return (InetAddress) method.invoke(null);
        } catch (Exception ignore) {
            // Ignored.
        }
        try {
            return InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    public static Provider getConscryptProvider() {
        try {
            return (Provider) conscryptClass("OpenSSLProvider").getConstructor().newInstance();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void installConscryptAsDefaultProvider() {
        final Provider conscryptProvider = getConscryptProvider();
        synchronized (getConscryptProvider()) {
            Provider[] providers = Security.getProviders();
            if (providers.length == 0 || !providers[0].equals(conscryptProvider)) {
                Security.insertProviderAt(conscryptProvider, 1);
            }
        }
    }

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
     * Looks up the conscrypt class for the given simple name (i.e. no package prefix).
     */
    public static Class<?> conscryptClass(String simpleName) throws ClassNotFoundException {
        ClassNotFoundException ex = null;
        for (String packageName : new String[] {"org.conscrypt", "com.android.org.conscrypt"}) {
            String name = packageName + "." + simpleName;
            try {
                return Class.forName(name);
            } catch (ClassNotFoundException e) {
                ex = e;
            }
        }
        throw ex;
    }

    /**
     * Returns an array containing only {@link #PROTOCOL_TLS_V1_2}.
     */
    public static String[] getProtocols() {
        return PROTOCOLS;
    }

    private static String[] getProtocolsInternal() {
        List<String> protocols = new ArrayList<String>();
        for (String protocol : DESIRED_PROTOCOLS) {
            if (hasProtocol(getJdkProvider(), protocol)) {
                protocols.add(protocol);
            }
        }
        return protocols.toArray(new String[protocols.size()]);
    }

    public static SSLSocketFactory getJdkSocketFactory() {
        return getSocketFactory(JDK_PROVIDER);
    }

    public static SSLServerSocketFactory getJdkServerSocketFactory() {
        return getServerSocketFactory(JDK_PROVIDER);
    }

    static SSLSocketFactory setUseEngineSocket(
            SSLSocketFactory conscryptFactory, boolean useEngineSocket) {
        try {
            Class<?> clazz = conscryptClass("Conscrypt");
            Method method =
                    clazz.getMethod("setUseEngineSocket", SSLSocketFactory.class, boolean.class);
            method.invoke(null, conscryptFactory, useEngineSocket);
            return conscryptFactory;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static SSLServerSocketFactory setUseEngineSocket(
            SSLServerSocketFactory conscryptFactory, boolean useEngineSocket) {
        try {
            Class<?> clazz = conscryptClass("Conscrypt");
            Method method = clazz.getMethod(
                    "setUseEngineSocket", SSLServerSocketFactory.class, boolean.class);
            method.invoke(null, conscryptFactory, useEngineSocket);
            return conscryptFactory;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static SSLSocketFactory getConscryptSocketFactory(boolean useEngineSocket) {
        return setUseEngineSocket(getSocketFactory(getConscryptProvider()), useEngineSocket);
    }

    public static SSLServerSocketFactory getConscryptServerSocketFactory(boolean useEngineSocket) {
        return setUseEngineSocket(getServerSocketFactory(getConscryptProvider()), useEngineSocket);
    }

    private static SSLSocketFactory getSocketFactory(Provider provider) {
        SSLContext clientContext = initClientSslContext(newContext(provider));
        return clientContext.getSocketFactory();
    }

    private static SSLServerSocketFactory getServerSocketFactory(Provider provider) {
        SSLContext serverContext = initServerSslContext(newContext(provider));
        return serverContext.getServerSocketFactory();
    }

    static SSLContext newContext(Provider provider) {
        try {
            return SSLContext.getInstance("TLS", provider);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static String[] getCommonCipherSuites() {
        SSLContext jdkContext =
                TestUtils.initSslContext(newContext(getJdkProvider()), TestKeyStore.getClient());
        SSLContext conscryptContext = TestUtils.initSslContext(
                newContext(getConscryptProvider()), TestKeyStore.getClient());
        Set<String> supported = new LinkedHashSet<String>();
        supported.addAll(supportedCiphers(jdkContext));
        supported.retainAll(supportedCiphers(conscryptContext));
        filterCiphers(supported);

        return supported.toArray(new String[supported.size()]);
    }

    private static List<String> supportedCiphers(SSLContext ctx) {
        return Arrays.asList(ctx.getDefaultSSLParameters().getCipherSuites());
    }

    private static void filterCiphers(Iterable<String> ciphers) {
        // Filter all non-TLS ciphers.
        Iterator<String> iter = ciphers.iterator();
        while (iter.hasNext()) {
            String cipher = iter.next();
            if (cipher.startsWith("SSL_") || cipher.startsWith("TLS_EMPTY")
                    || cipher.contains("_RC4_")) {
                iter.remove();
            }
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

    static SSLContext newClientSslContext(Provider provider) {
        SSLContext context = newContext(provider);
        return initClientSslContext(context);
    }

    static SSLContext newServerSslContext(Provider provider) {
        SSLContext context = newContext(provider);
        return initServerSslContext(context);
    }

    /**
     * Initializes the given client-side {@code context} with a default cert.
     */
    public static SSLContext initClientSslContext(SSLContext context) {
        return initSslContext(context, TestKeyStore.getClient());
    }

    /**
     * Initializes the given server-side {@code context} with the given cert chain and private key.
     */
    public static SSLContext initServerSslContext(SSLContext context) {
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
    public static void doEngineHandshake(SSLEngine clientEngine, SSLEngine serverEngine,
        ByteBuffer clientAppBuffer, ByteBuffer clientPacketBuffer, ByteBuffer serverAppBuffer,
        ByteBuffer serverPacketBuffer, boolean beginHandshake) throws SSLException {
        if (beginHandshake) {
            clientEngine.beginHandshake();
            serverEngine.beginHandshake();
        }

        SSLEngineResult clientResult;
        SSLEngineResult serverResult;

        boolean clientHandshakeFinished = false;
        boolean serverHandshakeFinished = false;

        do {
            int cTOsPos = clientPacketBuffer.position();
            int sTOcPos = serverPacketBuffer.position();

            clientResult = clientEngine.wrap(EMPTY_BUFFER, clientPacketBuffer);
            runDelegatedTasks(clientResult, clientEngine);
            serverResult = serverEngine.wrap(EMPTY_BUFFER, serverPacketBuffer);
            runDelegatedTasks(serverResult, serverEngine);

            // Verify that the consumed and produced number match what is in the buffers now.
            assertEquals(0, clientResult.bytesConsumed());
            assertEquals(0, serverResult.bytesConsumed());
            assertEquals(clientPacketBuffer.position() - cTOsPos, clientResult.bytesProduced());
            assertEquals(serverPacketBuffer.position() - sTOcPos, serverResult.bytesProduced());

            clientPacketBuffer.flip();
            serverPacketBuffer.flip();

            // Verify that we only had one SSLEngineResult.HandshakeStatus.FINISHED
            if (isHandshakeFinished(clientResult)) {
                assertFalse(clientHandshakeFinished);
                clientHandshakeFinished = true;
            }
            if (isHandshakeFinished(serverResult)) {
                assertFalse(serverHandshakeFinished);
                serverHandshakeFinished = true;
            }

            cTOsPos = clientPacketBuffer.position();
            sTOcPos = serverPacketBuffer.position();

            int clientAppReadBufferPos = clientAppBuffer.position();
            int serverAppReadBufferPos = serverAppBuffer.position();

            clientResult = clientEngine.unwrap(serverPacketBuffer, clientAppBuffer);
            runDelegatedTasks(clientResult, clientEngine);
            serverResult = serverEngine.unwrap(clientPacketBuffer, serverAppBuffer);
            runDelegatedTasks(serverResult, serverEngine);

            // Verify that the consumed and produced number match what is in the buffers now.
            assertEquals(serverPacketBuffer.position() - sTOcPos, clientResult.bytesConsumed());
            assertEquals(clientPacketBuffer.position() - cTOsPos, serverResult.bytesConsumed());
            assertEquals(clientAppBuffer.position() - clientAppReadBufferPos,
                clientResult.bytesProduced());
            assertEquals(serverAppBuffer.position() - serverAppReadBufferPos,
                serverResult.bytesProduced());

            clientPacketBuffer.compact();
            serverPacketBuffer.compact();

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
}
