/*
 * Copyright 2014 The Android Open Source Project
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

/*
 * Copyright 2013 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.conscrypt;

import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;
import java.nio.channels.SocketChannel;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import sun.security.x509.AlgorithmId;

/**
 * Platform-specific methods for OpenJDK.
 *
 * Uses reflection to implement Java 8 SSL features for backwards compatibility.
 */
final class Platform {
    private static final int JAVA_VERSION = javaVersion0();
    private static final Method GET_CURVE_NAME_METHOD;

    static {

        Method getCurveNameMethod = null;
        try {
            getCurveNameMethod = ECParameterSpec.class.getDeclaredMethod("getCurveName");
            getCurveNameMethod.setAccessible(true);
        } catch (Exception ignored) {
        }
        GET_CURVE_NAME_METHOD = getCurveNameMethod;
    }

    private Platform() {}

    static void setup() {}


    /**
     * Approximates the behavior of File.createTempFile without depending on SecureRandom.
     */
    static File createTempFile(String prefix, String suffix, File directory)
        throws IOException {
        if (directory == null) {
            throw new NullPointerException();
        }
        long time = System.currentTimeMillis();
        prefix = new File(prefix).getName();
        IOException suppressed = null;
        for (int i = 0; i < 10000; i++) {
            String tempName = String.format(Locale.US, "%s%d%04d%s", prefix, time, i, suffix);
            File tempFile = new File(directory, tempName);
            if (!tempName.equals(tempFile.getName())) {
                // The given prefix or suffix contains path separators.
                throw new IOException("Unable to create temporary file: " + tempFile);
            }
            try {
                if (tempFile.createNewFile()) {
                    return tempFile.getCanonicalFile();
                }
            } catch (IOException e) {
                // This may just be a transient error; store it just in case.
                suppressed = e;
            }
        }
        if (suppressed != null) {
            throw suppressed;
        } else {
            throw new IOException("Unable to create temporary file");
        }
    }

    /**
     * Default name used in the {@link java.security.Security JCE system} by {@code OpenSSLProvider}
     * if the default constructor is used.
     */
    static String getDefaultProviderName() {
        return "Conscrypt";
    }

    static boolean canExecuteExecutable(File file) throws IOException {
        if (JAVA_VERSION >= 7) {
            return Java7PlatformUtil.canExecuteExecutable(file);
        }
        return true;
    }

    static void addSuppressed(Throwable t, Throwable suppressed) {
        if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.addSuppressed(t, suppressed);
        }
    }

    static FileDescriptor getFileDescriptor(Socket s) {
        try {
            SocketChannel channel = s.getChannel();
            if (channel != null) {
                Field f_fd = channel.getClass().getDeclaredField("fd");
                f_fd.setAccessible(true);
                return (FileDescriptor) f_fd.get(channel);
            }
        } catch (Exception e) {
            // Try socket class below...
        }

        try {
            Field f_impl = Socket.class.getDeclaredField("impl");
            f_impl.setAccessible(true);
            Object socketImpl = f_impl.get(s);
            Field f_fd = SocketImpl.class.getDeclaredField("fd");
            f_fd.setAccessible(true);
            return (FileDescriptor) f_fd.get(socketImpl);
        } catch (Exception e) {
            throw new RuntimeException("Can't get FileDescriptor from socket", e);
        }
    }

    @SuppressWarnings("unused")
    static FileDescriptor getFileDescriptorFromSSLSocket(AbstractConscryptSocket socket) {
        return getFileDescriptor(socket);
    }

    @SuppressWarnings("unused")
    static String getCurveName(ECParameterSpec spec) {
        if (GET_CURVE_NAME_METHOD != null) {
            try {
                return (String) GET_CURVE_NAME_METHOD.invoke(spec);
            } catch (Exception ignored) {
                // Ignored
            }
        }
        return null;
    }

    @SuppressWarnings("unused")
    static void setCurveName(@SuppressWarnings("unused") ECParameterSpec spec,
            @SuppressWarnings("unused") String curveName) {
        // This doesn't appear to be needed.
    }

    /*
     * Call Os.setsockoptTimeval via reflection.
     */
    @SuppressWarnings("unused")
    static void setSocketWriteTimeout(@SuppressWarnings("unused") Socket s,
            @SuppressWarnings("unused") long timeoutMillis) throws SocketException {
        // TODO: figure this out on the RI
    }

    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        if (JAVA_VERSION >= 9) {
            Java9PlatformUtil.setSSLParameters(params, impl, socket);
        } else if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.setSSLParameters(params, impl, socket);
        } else if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.setSSLParameters(params, impl);
        }
    }

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        if (JAVA_VERSION >= 9) {
            Java9PlatformUtil.getSSLParameters(params, impl, socket);
        } else if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.getSSLParameters(params, impl, socket);
        } else if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.getSSLParameters(params, impl);
        }
    }

    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        if (JAVA_VERSION >= 9) {
            Java9PlatformUtil.setSSLParameters(params, impl, engine);
        } else if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.setSSLParameters(params, impl, engine);
        } else if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.setSSLParameters(params, impl);
        }
    }

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        if (JAVA_VERSION >= 9) {
            Java9PlatformUtil.getSSLParameters(params, impl, engine);
        } else if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.getSSLParameters(params, impl, engine);
        } else if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.getSSLParameters(params, impl);
        }
    }

    @SuppressWarnings("unused")
    static void setEndpointIdentificationAlgorithm(
            SSLParameters params, String endpointIdentificationAlgorithm) {
        params.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
    }

    @SuppressWarnings("unused")
    static String getEndpointIdentificationAlgorithm(SSLParameters params) {
        return params.getEndpointIdentificationAlgorithm();
    }

    @SuppressWarnings("unused")
    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            AbstractConscryptSocket socket) throws CertificateException {
        if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.checkClientTrusted(tm, chain, authType, socket);
        } else {
            tm.checkClientTrusted(chain, authType);
        }
    }

    @SuppressWarnings("unused")
    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            AbstractConscryptSocket socket) throws CertificateException {
        if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.checkServerTrusted(tm, chain, authType, socket);
        } else {
            tm.checkServerTrusted(chain, authType);
        }
    }

    @SuppressWarnings("unused")
    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            ConscryptEngine engine) throws CertificateException {
        if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.checkClientTrusted(tm, chain, authType, engine);
        } else {
            tm.checkClientTrusted(chain, authType);
        }
    }

    @SuppressWarnings("unused")
    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            ConscryptEngine engine) throws CertificateException {
        if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.checkServerTrusted(tm, chain, authType, engine);
        } else {
            tm.checkServerTrusted(chain, authType);
        }
    }

    /**
     * Wraps an old AndroidOpenSSL key instance. This is not needed on RI.
     */
    @SuppressWarnings("unused")
    static OpenSSLKey wrapRsaKey(@SuppressWarnings("unused") PrivateKey javaKey) {
        return null;
    }

    /**
     * Logs to the system EventLog system.
     */
    @SuppressWarnings("unused")
    static void logEvent(@SuppressWarnings("unused") String message) {}

    /**
     * Returns true if the supplied hostname is an literal IP address.
     */
    @SuppressWarnings("unused")
    static boolean isLiteralIpAddress(String hostname) {
        // TODO: any RI API to make this better?
        return AddressUtils.isLiteralIpAddress(hostname);
    }

    /**
     * For unbundled versions, SNI is always enabled by default.
     */
    @SuppressWarnings("unused")
    static boolean isSniEnabledByDefault() {
        return true;
    }

    static SSLEngine wrapEngine(ConscryptEngine engine) {
        if (JAVA_VERSION >= 8) {
            return Java8PlatformUtil.wrapEngine(engine);
        }
        return engine;
    }

    static SSLEngine unwrapEngine(SSLEngine engine) {
        if (JAVA_VERSION >= 8) {
            return Java8PlatformUtil.unwrapEngine(engine);
        }
        return engine;
    }

    static ConscryptEngineSocket createEngineSocket(SSLParametersImpl sslParameters)
            throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8EngineSocket(sslParameters);
        }
        return new ConscryptEngineSocket(sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(String hostname, int port,
            SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8EngineSocket(hostname, port, sslParameters);
        }
        return new ConscryptEngineSocket(hostname, port, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(InetAddress address, int port,
            SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8EngineSocket(address, port, sslParameters);
        }
        return new ConscryptEngineSocket(address, port, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(String hostname, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8EngineSocket(hostname, port, clientAddress, clientPort, sslParameters);
        }
        return new ConscryptEngineSocket(hostname, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(InetAddress address, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8EngineSocket(address, port, clientAddress, clientPort, sslParameters);
        }
        return new ConscryptEngineSocket(address, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(Socket socket, String hostname, int port,
            boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8EngineSocket(socket, hostname, port, autoClose, sslParameters);
        }
        return new ConscryptEngineSocket(socket, hostname, port, autoClose, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(SSLParametersImpl sslParameters)
            throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8FileDescriptorSocket(sslParameters);
        }
        return new ConscryptFileDescriptorSocket(sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(String hostname, int port,
            SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8FileDescriptorSocket(hostname, port, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(hostname, port, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(InetAddress address, int port,
            SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8FileDescriptorSocket(address, port, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(address, port, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(String hostname, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8FileDescriptorSocket(
                    hostname, port, clientAddress, clientPort, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(
                hostname, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(InetAddress address, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8FileDescriptorSocket(
                    address, port, clientAddress, clientPort, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(
                address, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(Socket socket, String hostname,
            int port, boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8FileDescriptorSocket(socket, hostname, port, autoClose, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(socket, hostname, port, autoClose, sslParameters);
    }

    /**
     * Currently we don't wrap anything from the RI.
     */
    @SuppressWarnings("unused")
    static SSLSocketFactory wrapSocketFactoryIfNeeded(OpenSSLSocketFactoryImpl factory) {
        return factory;
    }

    /**
     * Convert from platform's GCMParameterSpec to our internal version.
     */
    @SuppressWarnings("unused")
    static GCMParameters fromGCMParameterSpec(AlgorithmParameterSpec params) {
        if (params instanceof GCMParameterSpec) {
            GCMParameterSpec gcmParams = (GCMParameterSpec) params;
            return new GCMParameters(gcmParams.getTLen(), gcmParams.getIV());
        }
        return null;
    }

    /**
     * Convert from an opaque AlgorithmParameters to the platform's GCMParameterSpec.
     */
    static AlgorithmParameterSpec fromGCMParameters(AlgorithmParameters params) {
        try {
            return params.getParameterSpec(GCMParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            return null;
        }
    }

    /**
     * Creates a platform version of {@code GCMParameterSpec}.
     */
    @SuppressWarnings("unused")
    static AlgorithmParameterSpec toGCMParameterSpec(int tagLenInBits, byte[] iv) {
        return new GCMParameterSpec(tagLenInBits, iv);
    }

    /*
     * CloseGuard functions.
     */

    @SuppressWarnings("unused")
    static Object closeGuardGet() {
        return null;
    }

    @SuppressWarnings("unused")
    static void closeGuardOpen(@SuppressWarnings("unused") Object guardObj,
            @SuppressWarnings("unused") String message) {}

    @SuppressWarnings("unused")
    static void closeGuardClose(@SuppressWarnings("unused") Object guardObj) {}

    @SuppressWarnings("unused")
    static void closeGuardWarnIfOpen(@SuppressWarnings("unused") Object guardObj) {}

    /*
     * BlockGuard functions.
     */

    @SuppressWarnings("unused")
    static void blockGuardOnNetwork() {}

    /**
     * OID to Algorithm Name mapping.
     */
    @SuppressWarnings("unused")
    static String oidToAlgorithmName(String oid) {
        try {
            return AlgorithmId.get(oid).getName();
        } catch (NoSuchAlgorithmException e) {
            return oid;
        }
    }

    /*
     * Pre-Java-8 backward compatibility.
     */

    @SuppressWarnings("unused")
    static SSLSession wrapSSLSession(ConscryptSession sslSession) {
        if (JAVA_VERSION >= 8) {
            return Java8PlatformUtil.wrapSSLSession(sslSession);
        }
        if (JAVA_VERSION >= 7) {
            return Java7PlatformUtil.wrapSSLSession(sslSession);
        }
        return sslSession;
    }

    public static String getOriginalHostNameFromInetAddress(InetAddress addr) {
        try {
            Method getHolder = InetAddress.class.getDeclaredMethod("holder");
            getHolder.setAccessible(true);

            Method getOriginalHostName = Class.forName("java.net.InetAddress$InetAddressHolder")
                                                 .getDeclaredMethod("getOriginalHostName");
            getOriginalHostName.setAccessible(true);

            String originalHostName = (String) getOriginalHostName.invoke(getHolder.invoke(addr));
            if (originalHostName == null) {
                return addr.getHostAddress();
            }
            return originalHostName;
        } catch (InvocationTargetException e) {
            throw new RuntimeException("Failed to get originalHostName", e);
        } catch (ClassNotFoundException ignore) {
            // passthrough and return addr.getHostAddress()
        } catch (IllegalAccessException ignore) {
        } catch (NoSuchMethodException ignore) {
        }

        return addr.getHostAddress();
    }

    /*
     * Pre-Java-7 backward compatibility.
     */

    @SuppressWarnings("unused")
    static String getHostStringFromInetSocketAddress(InetSocketAddress addr) {
        if (JAVA_VERSION >= 7) {
            return Java7PlatformUtil.getHostStringFromInetSocketAddress(addr);
        }
        return null;
    }

    /**
     * Check if SCT verification is required for a given hostname.
     *
     * SCT Verification is enabled using {@code Security} properties.
     * The "conscrypt.ct.enable" property must be true, as well as a per domain property.
     * The reverse notation of the domain name, prefixed with "conscrypt.ct.enforce."
     * is used as the property name.
     * Basic globbing is also supported.
     *
     * For example, for the domain foo.bar.com, the following properties will be
     * looked up, in order of precedence.
     * - conscrypt.ct.enforce.com.bar.foo
     * - conscrypt.ct.enforce.com.bar.*
     * - conscrypt.ct.enforce.com.*
     * - conscrypt.ct.enforce.*
     */
    static boolean isCTVerificationRequired(String hostname) {
        if (hostname == null) {
            return false;
        }

        String property = Security.getProperty("conscrypt.ct.enable");
        if (property == null || !Boolean.valueOf(property.toLowerCase())) {
            return false;
        }

        List<String> parts = Arrays.asList(hostname.split("\\."));
        Collections.reverse(parts);

        boolean enable = false;
        StringBuilder propertyName = new StringBuilder("conscrypt.ct.enforce");
        // The loop keeps going on even once we've found a match
        // This allows for finer grained settings on subdomains
        for (String part : parts) {
            property = Security.getProperty(propertyName + ".*");
            if (property != null) {
                enable = Boolean.valueOf(property.toLowerCase());
            }

            propertyName.append(".").append(part);
        }

        property = Security.getProperty(propertyName.toString());
        if (property != null) {
            enable = Boolean.valueOf(property.toLowerCase());
        }
        return enable;
    }

    private static boolean isAndroid() {
        boolean android;
        try {
            Class.forName("android.app.Application", false, getSystemClassLoader());
            android = true;
        } catch (Throwable ignored) {
            // Failed to load the class uniquely available in Android.
            android = false;
        }
        return android;
    }

    static int javaVersion() {
        return JAVA_VERSION;
    }

    private static int javaVersion0() {
        final int majorVersion;

        if (isAndroid()) {
            majorVersion = 6;
        } else {
            majorVersion = majorVersionFromJavaSpecificationVersion();
        }

        return majorVersion;
    }

    private static int majorVersionFromJavaSpecificationVersion() {
        return majorVersion(System.getProperty("java.specification.version", "1.6"));
    }

    private static int majorVersion(final String javaSpecVersion) {
        final String[] components = javaSpecVersion.split("\\.");
        final int[] version = new int[components.length];
        for (int i = 0; i < components.length; i++) {
            version[i] = Integer.parseInt(components[i]);
        }

        if (version[0] == 1) {
            assert version[1] >= 6;
            return version[1];
        } else {
            return version[0];
        }
    }

    private static ClassLoader getSystemClassLoader() {
        if (System.getSecurityManager() == null) {
            return ClassLoader.getSystemClassLoader();
        } else {
            return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
                @Override
                public ClassLoader run() {
                    return ClassLoader.getSystemClassLoader();
                }
            });
        }
    }
}
