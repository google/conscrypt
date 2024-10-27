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
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.Set;
import java.util.function.Predicate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.conscrypt.java.security.StandardNames;
import org.conscrypt.java.security.TestKeyStore;
import org.conscrypt.testing.Streams;
import org.junit.Assume;

/**
 * Utility methods to support testing.
 */
public final class TestUtils {
    public static final Charset UTF_8 = StandardCharsets.UTF_8;
    private static final String PROTOCOL_TLS_V1_3 = "TLSv1.3";
    private static final String PROTOCOL_TLS_V1_2 = "TLSv1.2";
    private static final String PROTOCOL_TLS_V1_1 = "TLSv1.1";
    // For interop testing we need a JDK Provider that can do TLS 1.2 as 1.x may be disabled
    // in Conscrypt and 1.3 does not (yet) handle interoperability with the JDK Provider.
    private static final String[] DESIRED_JDK_PROTOCOLS = new String[] { PROTOCOL_TLS_V1_2 };
    private static final Provider JDK_PROVIDER = getNonConscryptTlsProvider();
    private static final byte[] CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".getBytes(UTF_8);
    private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocateDirect(0);

    static final String TEST_CIPHER = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";

    public enum BufferType {
        HEAP {
            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocate(size);
            }
        },
        DIRECT {
            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocateDirect(size);
            }
        };
        private static final Random random = new Random(System.currentTimeMillis());
        abstract ByteBuffer newBuffer(int size);

        public ByteBuffer[] newRandomBuffers(int... sizes) {
            int numBuffers = sizes.length;
            ByteBuffer[] result = new ByteBuffer[numBuffers];
            for (int i = 0; i < numBuffers; i++) {
                result[i] = newRandomBuffer(sizes[i]);
            }
            return result;
        }

        public ByteBuffer newRandomBuffer(int size) {
            byte[] data = new byte[size];
            random.nextBytes(data);
            ByteBuffer buffer = newBuffer(size);
            buffer.put(data);
            buffer.flip();
            return buffer;
        }
    }

    private TestUtils() {}

    private static Provider getNonConscryptTlsProvider() {
        for (String protocol : DESIRED_JDK_PROTOCOLS) {
            Provider p = getNonConscryptProviderFor("SSLContext", protocol);
            if (p != null) {
                return p;
            }
        }
        return new BouncyCastleProvider();
    }

    static Provider getNonConscryptProviderFor(String type, String algorithm) {
        for (Provider p : Security.getProviders()) {
            if (!p.getClass().getPackage().getName().contains("conscrypt")
                && (p.getService(type, algorithm) != null)) {
                return p;
            }
        }
        return null;
    }

    static Provider getJdkProvider() {
        return JDK_PROVIDER;
    }

    public static boolean isClassAvailable(String classname) {
        try {
            Class.forName(classname);
            return true;
        } catch (ClassNotFoundException ignore) {
            // Ignored
        }
        return false;
    }

    private static void assumeClassAvailable(String classname) {
        Assume.assumeTrue("Skipping test: " + classname + " unavailable",
                isClassAvailable(classname));
    }

    public static void assumeSNIHostnameAvailable() {
        assumeClassAvailable("javax.net.ssl.SNIHostName");
    }

    public static void assumeExtendedTrustManagerAvailable() {
        assumeClassAvailable("javax.net.ssl.X509ExtendedTrustManager");
    }

    public static void assumeStatsLogAvailable() {
        assumeClassAvailable("android.util.StatsEvent");
    }

    public static void assumeSetEndpointIdentificationAlgorithmAvailable() {
        boolean supported = false;
        try {
            SSLParameters.class.getMethod("setEndpointIdentificationAlgorithm", String.class);
            supported = true;
        } catch (NoSuchMethodException ignore) {
            // Ignored
        }
        Assume.assumeTrue("Skipping test: "
                + "SSLParameters.setEndpointIdentificationAlgorithm unavailable", supported);
    }

    public static void assumeAEADAvailable() {
        assumeClassAvailable("javax.crypto.AEADBadTagException");
    }

    private static boolean isAndroid() {
        try {
            Class.forName("android.app.Application", false, ClassLoader.getSystemClassLoader());
            return true;
        } catch (Throwable ignored) {
            // Failed to load the class uniquely available in Android.
            return false;
        }
    }

    public static void assumeAndroid() {
        Assume.assumeTrue(isAndroid());
    }

    public static void assumeAllowsUnsignedCrypto() {
        // The Oracle JRE disallows loading crypto providers from unsigned jars
        Assume.assumeTrue(isAndroid()
                || !System.getProperty("java.vm.name").contains("HotSpot"));
    }

    public static void assumeSHA2WithDSAAvailable() {
        boolean available;
        try {
            Signature.getInstance("SHA256withDSA");
            available = true;
        } catch (NoSuchAlgorithmException e) {
            available = false;
        }
        Assume.assumeTrue("SHA2 with DSA signatures not available", available);
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
            String defaultName = (String) conscryptClass("Platform")
                .getDeclaredMethod("getDefaultProviderName")
                .invoke(null);
            Constructor<?> c = conscryptClass("OpenSSLProvider")
                .getDeclaredConstructor(String.class, Boolean.TYPE, String.class);

            if (!isClassAvailable("javax.net.ssl.X509ExtendedTrustManager")) {
                return (Provider) c.newInstance(defaultName, false, "TLSv1.3");
            } else {
                return (Provider) c.newInstance(defaultName, true, "TLSv1.3");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static synchronized void installConscryptAsDefaultProvider() {
        Provider conscryptProvider = getConscryptProvider();
        Provider[] providers = Security.getProviders();
        if (providers.length == 0 || !providers[0].equals(conscryptProvider)) {
            Security.insertProviderAt(conscryptProvider, 1);
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

    public static PublicKey readPublicKeyPemFile(String name)
            throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        String keyData = new String(readTestFile(name), StandardCharsets.US_ASCII);
        keyData = keyData.replace("-----BEGIN PUBLIC KEY-----", "");
        keyData = keyData.replace("-----END PUBLIC KEY-----", "");
        keyData = keyData.replace("\r", "");
        keyData = keyData.replace("\n", "");
        return KeyFactory.getInstance("EC").generatePublic(
                new X509EncodedKeySpec(decodeBase64(keyData)));
    }

    public static List<String[]> readCsvResource(String resourceName) throws IOException {
        InputStream stream = openTestFile(resourceName);
        List<String[]> lines = new ArrayList<>();
        try (BufferedReader reader
                     = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                lines.add(line.split(",", -1));
            }
        }
        return lines;
    }

    public static List<TestVector> readTestVectors(String resourceName) throws IOException {
        InputStream stream = openTestFile(resourceName);
        List<TestVector> result = new ArrayList<>();
        TestVector current = null;
        try (BufferedReader reader
                 = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                int index = line.indexOf('=');
                if (index < 0) {
                    throw new IllegalStateException("No = found: line " + lineNumber);
                }
                String label = line.substring(0, index).trim().toLowerCase(Locale.ROOT);
                String value = line.substring(index + 1).trim();
                if ("name".equals(label)) {
                    current = new TestVector();
                    result.add(current);
                } else if (current == null) {
                    throw new IllegalStateException("Vectors must start with a name: line "
                        + lineNumber);
                }
                current.put(label, value);
            }
        }
        return result;
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

    // Return a Class by name or null
    public static Class<?> findClass(String name) {
        try {
            return Class.forName(name);
        } catch (ClassNotFoundException ignored) {
            return null;
        }
    }

    public static SSLSocketFactory setUseEngineSocket(
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

    public static SSLServerSocketFactory setUseEngineSocket(
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

    static boolean getUseEngineSocketByDefault() {
        try {
            boolean sfDefault = getBooleanField(
                "OpenSSLSocketFactoryImpl", "useEngineSocketByDefault");
            boolean ssfDefault = getBooleanField(
                "OpenSSLServerSocketFactoryImpl", "useEngineSocketByDefault");
            if (sfDefault != ssfDefault) {
                throw new IllegalStateException("Socket factory and server socket factory must\n" +
                    "use the same default implementation during testing");
            }
            return sfDefault;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static boolean getBooleanField(String className, String fieldName) throws Exception {
        Class<?> clazz = conscryptClass(className);
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.getBoolean(null);
    }

    public static void setUseSessionTickets(SSLSocket socket, boolean useTickets) {
        try {
            Class<?> clazz = conscryptClass("Conscrypt");
            Method method = clazz.getMethod("setUseSessionTickets", SSLSocket.class, boolean.class);
            method.invoke(null, socket, useTickets);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static SSLContext newContext(Provider provider) {
        try {
            return SSLContext.getInstance("TLS", provider);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String highestCommonProtocol() {
        String[] common = getCommonProtocolSuites();
        Arrays.sort(common);
        return common[common.length - 1];
    }

    public static String[] getCommonProtocolSuites() {
        SSLContext jdkContext = newClientSslContext(getJdkProvider());
        SSLContext conscryptContext = newClientSslContext(getConscryptProvider());
        // No point building a Set here due to small list sizes.
        List<String> conscryptProtocols = getSupportedProtocols(conscryptContext);
        Predicate<String> predicate = p -> conscryptProtocols.contains(p)
            // TODO(prb): Certificate auth fails when connecting Conscrypt and JDK's TLS 1.3.
            && !p.equals(PROTOCOL_TLS_V1_3);
        return getSupportedProtocols(jdkContext, predicate);
    }

    public static String[] getCommonCipherSuites() {
        SSLContext jdkContext = newClientSslContext(getJdkProvider());
        SSLContext conscryptContext = newClientSslContext(getConscryptProvider());
        Set<String> conscryptCiphers =  new HashSet<>(getSupportedCiphers(conscryptContext));
        Predicate<String> predicate = c -> isTlsCipherSuite(c) && conscryptCiphers.contains(c);
        return getSupportedCiphers(jdkContext, predicate);
    }

    public static List<String> getSupportedCiphers(SSLContext ctx) {
        return Arrays.asList(ctx.getDefaultSSLParameters().getCipherSuites());
    }

    public static String[] getSupportedCiphers(SSLContext ctx, Predicate<String> predicate) {
        return Arrays.stream(ctx.getDefaultSSLParameters().getCipherSuites())
            .filter(predicate)
            .toArray(String[]::new);
    }

    public static String[] getSupportedProtocols() {
        return getSupportedProtocols(newClientSslContext(getConscryptProvider()))
                .toArray(new String[0]);
    }

    public static List<String> getSupportedProtocols(SSLContext ctx) {
        return Arrays.asList(ctx.getDefaultSSLParameters().getProtocols());
    }

    public static String[] getSupportedProtocols(SSLContext ctx, Predicate<String> predicate) {
        return Arrays.stream(ctx.getDefaultSSLParameters().getProtocols())
            .filter(predicate)
            .toArray(String[]::new);
    }

    private static boolean isTlsCipherSuite(String cipher) {
        return !cipher.startsWith("SSL_")
            && !cipher.startsWith("TLS_EMPTY")
            && !cipher.contains("_RC4_");
    }

    public static void assumeTlsV11Enabled(SSLContext context) {
        Assume.assumeTrue(getSupportedProtocols(context).contains(PROTOCOL_TLS_V1_1));
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

    public static SSLContext newClientSslContext(Provider provider) {
        SSLContext context = newContext(provider);
        return initClientSslContext(context);
    }

    public static SSLContext newServerSslContext(Provider provider) {
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
     * Performs the initial TLS handshake between the two {@link SSLEngine} instances.
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

    public static String pickArbitraryNonTls13Suite(String[] cipherSuites) {
        return pickArbitraryNonTls13Suite(Arrays.asList(cipherSuites));
    }

    public static String pickArbitraryNonTls13Suite(Iterable<String> cipherSuites) {
        for (String cipherSuite : cipherSuites) {
            if (!StandardNames.CIPHER_SUITES_TLS13.contains(cipherSuite)) {
                return cipherSuite;
            }
        }
        fail("No non-TLSv1.3 cipher suite available.");
        return null;
    }

    /**
     * Decodes the provided hexadecimal string into a byte array.  Odd-length inputs
     * are not allowed.
     * <p>
     * Throws an {@code IllegalArgumentException} if the input is malformed.
     */
    public static byte[] decodeHex(String encoded) throws IllegalArgumentException {
        return decodeHex(encoded.toCharArray());
    }

    /**
     * Decodes the provided hexadecimal string into a byte array. If {@code allowSingleChar}
     * is {@code true} odd-length inputs are allowed and the first character is interpreted
     * as the lower bits of the first result byte.
     * <p>
     * Throws an {@code IllegalArgumentException} if the input is malformed.
     */
    public static byte[] decodeHex(String encoded, boolean allowSingleChar) throws IllegalArgumentException {
        return decodeHex(encoded.toCharArray(), allowSingleChar);
    }

    /**
     * Decodes the provided hexadecimal string into a byte array.  Odd-length inputs
     * are not allowed.
     * <p>
     * Throws an {@code IllegalArgumentException} if the input is malformed.
     */
    public static byte[] decodeHex(char[] encoded) throws IllegalArgumentException {
        return decodeHex(encoded, false);
    }

    /**
     * Decodes the provided hexadecimal string into a byte array. If {@code allowSingleChar}
     * is {@code true} odd-length inputs are allowed and the first character is interpreted
     * as the lower bits of the first result byte.
     * <p>
     * Throws an {@code IllegalArgumentException} if the input is malformed.
     */
    public static byte[] decodeHex(char[] encoded, boolean allowSingleChar) throws IllegalArgumentException {
        int resultLengthBytes = (encoded.length + 1) / 2;
        byte[] result = new byte[resultLengthBytes];

        int resultOffset = 0;
        int i = 0;
        if (allowSingleChar) {
            if ((encoded.length % 2) != 0) {
                // Odd number of digits -- the first digit is the lower 4 bits of the first result byte.
                result[resultOffset++] = (byte) toDigit(encoded, i);
                i++;
            }
        } else {
            if ((encoded.length % 2) != 0) {
                throw new IllegalArgumentException("Invalid input length: " + encoded.length);
            }
        }

        for (int len = encoded.length; i < len; i += 2) {
            result[resultOffset++] = (byte) ((toDigit(encoded, i) << 4) | toDigit(encoded, i + 1));
        }

        return result;
    }

    private static int toDigit(char[] str, int offset) throws IllegalArgumentException {
        // NOTE: that this isn't really a code point in the traditional sense, since we're
        // just rejecting surrogate pairs outright.
        int pseudoCodePoint = str[offset];

        if ('0' <= pseudoCodePoint && pseudoCodePoint <= '9') {
            return pseudoCodePoint - '0';
        } else if ('a' <= pseudoCodePoint && pseudoCodePoint <= 'f') {
            return 10 + (pseudoCodePoint - 'a');
        } else if ('A' <= pseudoCodePoint && pseudoCodePoint <= 'F') {
            return 10 + (pseudoCodePoint - 'A');
        }

        throw new IllegalArgumentException("Illegal char: " + str[offset] +
                " at offset " + offset);
    }

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    public static String encodeHex(byte[] data) {
        char[] hex = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xff;
            hex[2 * i] = HEX_CHARS[value >>> 4];
            hex[2 * i + 1] = HEX_CHARS[value & 0x0f];
        }
        return new String(hex);
    }

    private static final String BASE64_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    public static String encodeBase64(byte[] data) {
        // Base64 was introduced in Java 8, so if it's not available we can use a hacky
        // solution that works in previous versions
        if (isClassAvailable("java.util.Base64")) {
            return Base64.getEncoder().encodeToString(data);
        } else {
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < data.length; i += 3) {
                int padding = (i + 2 < data.length) ? 0 : (i + 3 - data.length);
                byte b1 = data[i];
                byte b2 = padding >= 2 ? 0 : data[i+1];
                byte b3 = padding >= 1 ? 0 : data[i+2];

                char c1 = BASE64_ALPHABET.charAt((b1 & 0xFF) >>> 2);
                char c2 = BASE64_ALPHABET.charAt(((b1 & 0x03) << 4) | ((b2 & 0xFF) >>> 4));
                char c3 = BASE64_ALPHABET.charAt(((b2 & 0x0F) << 2) | ((b3 & 0xFF) >>> 6));
                char c4 = BASE64_ALPHABET.charAt(b3 & 0x3F);

                if (padding >= 1) {
                    c4 = '=';
                }
                if (padding >= 2) {
                    c3 = '=';
                }
                builder.append(c1).append(c2).append(c3).append(c4);
            }
            return builder.toString();
        }
    }

    public static byte[] decodeBase64(String data) {
        // Base64 was introduced in Java 8, so if it's not available we can use a hacky
        // solution that works in previous versions
        if (isClassAvailable("java.util.Base64")) {
            return Base64.getDecoder().decode(data);
        } else {
            while (data.endsWith("=")) {
                data = data.substring(0, data.length() - 1);
            }
            int padding = (data.length() % 4 == 0) ? 0 : 4 - (data.length() % 4);
            byte[] output = new byte[((data.length() - 1) / 4) * 3 + 3 - padding];
            int outputindex = 0;
            for (int i = 0; i < data.length(); i += 4) {
                char c1 = data.charAt(i);
                char c2 = data.charAt(i+1);
                char c3 = (i+2 < data.length()) ? data.charAt(i+2) : 'A';
                char c4 = (i+3 < data.length()) ? data.charAt(i+3) : 'A';

                byte b1 = (byte)
                        (BASE64_ALPHABET.indexOf(c1) << 2 | BASE64_ALPHABET.indexOf(c2) >>> 4);
                byte b2 = (byte)
                        ((BASE64_ALPHABET.indexOf(c2) & 0x0F) << 4 | BASE64_ALPHABET.indexOf(c3) >>> 2);
                byte b3 = (byte)
                        ((BASE64_ALPHABET.indexOf(c3) & 0x03) << 6 | BASE64_ALPHABET.indexOf(c4));

                output[outputindex++] = b1;
                if (outputindex < output.length) {
                    output[outputindex++] = b2;
                }
                if (outputindex < output.length) {
                    output[outputindex++] = b3;
                }
            }
            return output;
        }
    }

    public static boolean isJavaVersion(int version) {
        return javaVersion() >= version;
    }

    private static int javaVersion() {
        String[] v = System.getProperty("java.specification.version", "1.6").split("\\.", -1);
        if ("1".equals(v[0])) {
            return Integer.parseInt(v[1]);
        }
        return Integer.parseInt(v[0]);
    }

    public static void assumeJava8() {
        Assume.assumeTrue("Require Java 8: " + javaVersion(), isJavaVersion(8));
    }

    public static void assumeEngineSocket() {
        Assume.assumeTrue(getUseEngineSocketByDefault());
    }

    public static String osName() {
        return System.getProperty("os.name").toLowerCase(Locale.US).replaceAll("[^a-z0-9]+", "");
    }

    public static boolean isLinux() {
        return osName().startsWith("linux");
    }

    public static boolean isWindows() {
        return osName().startsWith("windows");
    }

    public static boolean isOsx() {
        String name = osName();
        return name.startsWith("macosx") || name.startsWith("osx");
    }

    public static void assumeXecClassesAvailable() {
        Assume.assumeTrue(findClass("java.security.spec.XECPrivateKeySpec") != null);
    }

    public static boolean isTlsV1Deprecated() {
        return callPlatformMethod("isTlsV1Deprecated", false);
    }

    public static boolean isTlsV1Filtered() {
        return callPlatformMethod("isTlsV1Filtered", true);
    }

    public static boolean isTlsV1Supported() {
        return callPlatformMethod("isTlsV1Supported", true);
    }

    public static boolean isJavaxCertificateSupported() {
        return callPlatformMethod("isJavaxCertificateSupported", true);
    }

    // Calls a boolean platform method by reflection.  If the method is not present, e.g.
    // due to version skew etc then return the default value.
    public static boolean callPlatformMethod(String methodName, boolean defaultValue) {
        try {
            return (Boolean) conscryptClass("Platform")
                    .getDeclaredMethod(methodName)
                    .invoke(null);
        } catch (NoSuchMethodException e) {
            return defaultValue;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException e) {
            throw new IllegalStateException("Reflection failure", e);
        }
    }

}
