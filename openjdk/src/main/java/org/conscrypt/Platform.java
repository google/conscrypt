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

import java.io.FileDescriptor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;
import java.nio.channels.SocketChannel;
import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.spec.GCMParameterSpec;
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

    static FileDescriptor getFileDescriptorFromSSLSocket(AbstractConscryptSocket socket) {
        return getFileDescriptor(socket);
    }

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

    static void setCurveName(@SuppressWarnings("unused") ECParameterSpec spec,
            @SuppressWarnings("unused") String curveName) {
        // This doesn't appear to be needed.
    }

    /*
     * Call Os.setsockoptTimeval via reflection.
     */
    static void setSocketWriteTimeout(@SuppressWarnings("unused") Socket s,
            @SuppressWarnings("unused") long timeoutMillis) throws SocketException {
        // TODO: figure this out on the RI
    }

    public static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.setSSLParameters(params, impl, socket);
        } else if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.setSSLParameters(params, impl);
        }
    }

    public static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.getSSLParameters(params, impl, socket);
        } else if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.getSSLParameters(params, impl);
        }
    }

    public static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.setSSLParameters(params, impl, engine);
        } else if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.setSSLParameters(params, impl);
        }
    }

    public static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        if (JAVA_VERSION >= 8) {
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

    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            AbstractConscryptSocket socket) throws CertificateException {
        if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.checkClientTrusted(tm, chain, authType, socket);
        } else {
            tm.checkClientTrusted(chain, authType);
        }
    }

    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            AbstractConscryptSocket socket) throws CertificateException {
        if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.checkServerTrusted(tm, chain, authType, socket);
        } else {
            tm.checkServerTrusted(chain, authType);
        }
    }

    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            ConscryptEngine engine) throws CertificateException {
        if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.checkClientTrusted(tm, chain, authType, engine);
        } else {
            tm.checkClientTrusted(chain, authType);
        }
    }

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
    static OpenSSLKey wrapRsaKey(@SuppressWarnings("unused") PrivateKey javaKey) {
        return null;
    }

    /**
     * Logs to the system EventLog system.
     */
    static void logEvent(@SuppressWarnings("unused") String message) {}

    /**
     * Returns true if the supplied hostname is an literal IP address.
     */
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

    /**
     * Currently we don't wrap anything from the RI.
     */
    static SSLSocketFactory wrapSocketFactoryIfNeeded(OpenSSLSocketFactoryImpl factory) {
        return factory;
    }

    /**
     * Convert from platform's GCMParameterSpec to our internal version.
     */
    static GCMParameters fromGCMParameterSpec(AlgorithmParameterSpec params) {
        if (params instanceof GCMParameterSpec) {
            GCMParameterSpec gcmParams = (GCMParameterSpec) params;
            return new GCMParameters(gcmParams.getTLen(), gcmParams.getIV());
        }
        return null;
    }

    /**
     * Creates a platform version of {@code GCMParameterSpec}.
     */
    static AlgorithmParameterSpec toGCMParameterSpec(int tagLenInBits, byte[] iv) {
        return new GCMParameterSpec(tagLenInBits, iv);
    }

    /*
     * CloseGuard functions.
     */

    static Object closeGuardGet() {
        return null;
    }

    static void closeGuardOpen(@SuppressWarnings("unused") Object guardObj,
            @SuppressWarnings("unused") String message) {}

    static void closeGuardClose(@SuppressWarnings("unused") Object guardObj) {}

    static void closeGuardWarnIfOpen(@SuppressWarnings("unused") Object guardObj) {}

    /*
     * BlockGuard functions.
     */

    static void blockGuardOnNetwork() {}

    /**
     * OID to Algorithm Name mapping.
     */
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

    static SSLSession wrapSSLSession(ActiveSession sslSession) {
        return ExtendedSessionAdapter.wrap(sslSession);
    }

    @SuppressWarnings("unused")
    static SSLSession unwrapSSLSession(SSLSession sslSession) {
        return ExtendedSessionAdapter.getDelegate(sslSession);
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
        } catch (ReflectiveOperationException ignore) {
            // passthrough and return addr.getHostAddress()
        }
        return addr.getHostAddress();
    }

    /*
     * Pre-Java-7 backward compatibility.
     */

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

    // Package-private for testing only
    static int majorVersionFromJavaSpecificationVersion() {
        return majorVersion(System.getProperty("java.specification.version", "1.6"));
    }

    // Package-private for testing only
    static int majorVersion(final String javaSpecVersion) {
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

    static ClassLoader getSystemClassLoader() {
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
