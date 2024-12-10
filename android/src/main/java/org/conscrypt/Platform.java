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

package org.conscrypt;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.os.Binder;
import android.os.Build;
import android.os.SystemClock;
import android.system.Os;
import android.util.Log;

import dalvik.system.BlockGuard;
import dalvik.system.CloseGuard;

import org.conscrypt.ct.LogStore;
import org.conscrypt.ct.Policy;
import org.conscrypt.metrics.Source;
import org.conscrypt.metrics.StatsLog;
import org.conscrypt.metrics.StatsLogImpl;

import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;
import java.security.AlgorithmParameters;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509TrustManager;
import org.conscrypt.NativeCrypto;

/**
 * Platform-specific methods for unbundled Android.
 */
@Internal
final public class Platform {
    private static final String TAG = "Conscrypt";
    static boolean DEPRECATED_TLS_V1 = true;
    static boolean ENABLED_TLS_V1 = false;
    private static boolean FILTERED_TLS_V1 = true;

    private static Method m_getCurveName;
    static {
        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
        try {
            m_getCurveName = ECParameterSpec.class.getDeclaredMethod("getCurveName");
            m_getCurveName.setAccessible(true);
        } catch (Exception ignored) {
            //Ignored
        }
    }

    private Platform() {}

    public static void setup(boolean deprecatedTlsV1, boolean enabledTlsV1) {
        DEPRECATED_TLS_V1 = deprecatedTlsV1;
        ENABLED_TLS_V1 = enabledTlsV1;
        FILTERED_TLS_V1 = !enabledTlsV1;
        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
    }

    /**
     * Default name used in the {@link java.security.Security JCE system} by {@code OpenSSLProvider}
     * if the default constructor is used.
     */
    public static String getDefaultProviderName() {
        return "Conscrypt";
    }

    static boolean provideTrustManagerByDefault() {
        return false;
    }

    public static FileDescriptor getFileDescriptor(Socket s) {
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

    public static FileDescriptor getFileDescriptorFromSSLSocket(AbstractConscryptSocket socket) {
        return getFileDescriptor(socket);
    }

    public static String getCurveName(ECParameterSpec spec) {
        if (m_getCurveName == null) {
            return null;
        }
        try {
            return (String) m_getCurveName.invoke(spec);
        } catch (Exception e) {
            return null;
        }
    }

    public static void setCurveName(ECParameterSpec spec, String curveName) {
        try {
            Method setCurveName = spec.getClass().getDeclaredMethod("setCurveName", String.class);
            setCurveName.invoke(spec, curveName);
        } catch (Exception ignored) {
            //Ignored
        }
    }

    /**
     * Call Os.setsockoptTimeval via reflection.
     */
    public static void setSocketWriteTimeout(Socket s, long timeoutMillis) throws SocketException {
        try {
            FileDescriptor fd = getFileDescriptor(s);
            if (fd == null || !fd.valid()) {
                // Mirror the behavior of platform sockets when calling methods with bad fds
                throw new SocketException("Socket closed");
            }
            Class<?> c_structTimeval =
                    getClass("android.system.StructTimeval", "libcore.io.StructTimeval");
            if (c_structTimeval == null) {
                Log.w(TAG, "StructTimeval == null; not setting socket write timeout");
                return;
            }

            Method m_fromMillis = c_structTimeval.getDeclaredMethod("fromMillis", long.class);
            if (m_fromMillis == null) {
                Log.w(TAG, "fromMillis == null; not setting socket write timeout");
                return;
            }

            Object timeval = m_fromMillis.invoke(null, timeoutMillis);

            Class<?> c_Libcore = Class.forName("libcore.io.Libcore");
            if (c_Libcore == null) {
                Log.w(TAG, "Libcore == null; not setting socket write timeout");
                return;
            }

            Field f_os = c_Libcore.getField("os");
            if (f_os == null) {
                Log.w(TAG, "os == null; not setting socket write timeout");
                return;
            }

            Object instance_os = f_os.get(null);
            if (instance_os == null) {
                Log.w(TAG, "instance_os == null; not setting socket write timeout");
                return;
            }

            Class<?> c_osConstants =
                    getClass("android.system.OsConstants", "libcore.io.OsConstants");
            if (c_osConstants == null) {
                Log.w(TAG, "OsConstants == null; not setting socket write timeout");
                return;
            }

            Field f_SOL_SOCKET = c_osConstants.getField("SOL_SOCKET");
            if (f_SOL_SOCKET == null) {
                Log.w(TAG, "SOL_SOCKET == null; not setting socket write timeout");
                return;
            }

            Field f_SO_SNDTIMEO = c_osConstants.getField("SO_SNDTIMEO");
            if (f_SO_SNDTIMEO == null) {
                Log.w(TAG, "SO_SNDTIMEO == null; not setting socket write timeout");
                return;
            }

            Method m_setsockoptTimeval = instance_os.getClass().getMethod("setsockoptTimeval",
                    FileDescriptor.class, int.class, int.class, c_structTimeval);
            if (m_setsockoptTimeval == null) {
                Log.w(TAG, "setsockoptTimeval == null; not setting socket write timeout");
                return;
            }

            m_setsockoptTimeval.invoke(instance_os, fd, f_SOL_SOCKET.get(null),
                    f_SO_SNDTIMEO.get(null), timeval);
        } catch (Exception e) {
            // We don't want to spam the logcat since this isn't a fatal error, but we want to know
            // why this might be happening.
            logStackTraceSnippet("Could not set socket write timeout: " + e, e);
            Throwable cause = e.getCause();
            while (cause != null) {
                logStackTraceSnippet("Caused by: " + cause, cause);
                cause = cause.getCause();
            }
        }
    }

    /**
     * Logs an abbreviated stacktrace (summary and a couple of StackTraceElements).
     */
    private static void logStackTraceSnippet(String summary, Throwable throwable) {
        Log.w(TAG, summary);
        StackTraceElement[] elements = throwable.getStackTrace();
        for (int i = 0; i < 2 && i < elements.length; i++) {
            Log.w(TAG, "\tat " + elements[i].toString());
        }
    }

    private static void setSSLParametersOnImpl(SSLParameters params, SSLParametersImpl impl)
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        Method m_getEndpointIdentificationAlgorithm =
                params.getClass().getMethod("getEndpointIdentificationAlgorithm");
        impl.setEndpointIdentificationAlgorithm(
                (String) m_getEndpointIdentificationAlgorithm.invoke(params));

        Method m_getUseCipherSuitesOrder = params.getClass().getMethod("getUseCipherSuitesOrder");
        impl.setUseCipherSuitesOrder((boolean) m_getUseCipherSuitesOrder.invoke(params));
    }

    public static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        try {
            setSSLParametersOnImpl(params, impl);

            if (Build.VERSION.SDK_INT >= 24) {
                String sniHostname = getSniHostnameFromParams(params);
                if (sniHostname != null) {
                    socket.setHostname(sniHostname);
                }
            }
        } catch (NoSuchMethodException ignored) {
            //Ignored
        } catch (IllegalAccessException ignored) {
            //Ignored
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e.getCause());
        }
    }

    public static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        try {
            setSSLParametersOnImpl(params, impl);

            if (Build.VERSION.SDK_INT >= 24) {
                String sniHostname = getSniHostnameFromParams(params);
                if (sniHostname != null) {
                    engine.setHostname(sniHostname);
                }
            }
        } catch (NoSuchMethodException ignored) {
            //Ignored
        } catch (IllegalAccessException ignored) {
            //Ignored
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e.getCause());
        }
    }

    @TargetApi(24)
    private static String getSniHostnameFromParams(SSLParameters params)
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        Method m_getServerNames = params.getClass().getMethod("getServerNames");
        @SuppressWarnings("unchecked")
        List<SNIServerName> serverNames = (List<SNIServerName>) m_getServerNames.invoke(params);
        if (serverNames != null) {
            for (SNIServerName serverName : serverNames) {
                if (serverName.getType() == StandardConstants.SNI_HOST_NAME) {
                    return ((SNIHostName) serverName).getAsciiName();
                }
            }
        }

        return null;
    }

    private static void getSSLParametersFromImpl(SSLParameters params, SSLParametersImpl impl)
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        Method m_setEndpointIdentificationAlgorithm =
                params.getClass().getMethod("setEndpointIdentificationAlgorithm", String.class);
        m_setEndpointIdentificationAlgorithm.invoke(
                params, impl.getEndpointIdentificationAlgorithm());

        Method m_setUseCipherSuitesOrder =
                params.getClass().getMethod("setUseCipherSuitesOrder", boolean.class);
        m_setUseCipherSuitesOrder.invoke(params, impl.getUseCipherSuitesOrder());
    }

    public static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        try {
            getSSLParametersFromImpl(params, impl);

            if (Build.VERSION.SDK_INT >= 24) {
                setParametersSniHostname(params, impl, socket);
            }
        } catch (NoSuchMethodException ignored) {
            //Ignored
        } catch (IllegalAccessException ignored) {
            //Ignored
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e.getCause());
        }
    }

    @TargetApi(24)
    private static void setParametersSniHostname(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket)
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(socket.getHostname())) {
            Method m_setServerNames = params.getClass().getMethod("setServerNames", List.class);
            m_setServerNames.invoke(params,
                    Collections.<SNIServerName>singletonList(
                            new SNIHostName(socket.getHostname())));
        }
    }

    public static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        try {
            getSSLParametersFromImpl(params, impl);

            if (Build.VERSION.SDK_INT >= 24) {
                setParametersSniHostname(params, impl, engine);
            }
        } catch (NoSuchMethodException ignored) {
            //Ignored
        } catch (IllegalAccessException ignored) {
            //Ignored
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e.getCause());
        }
    }

    @TargetApi(24)
    private static void setParametersSniHostname(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine)
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(engine.getHostname())) {
            Method m_setServerNames = params.getClass().getMethod("setServerNames", List.class);
            m_setServerNames.invoke(params,
                    Collections.<SNIServerName>singletonList(
                            new SNIHostName(engine.getHostname())));
        }
    }

    /**
     * Tries to return a Class reference of one of the supplied class names.
     */
    private static Class<?> getClass(String... klasses) {
        for (String klass : klasses) {
            try {
                return Class.forName(klass);
            } catch (Exception ignored) {
                //Ignored
            }
        }
        return null;
    }

    public static void setEndpointIdentificationAlgorithm(
            SSLParameters params, String endpointIdentificationAlgorithm) {
        // TODO: implement this for unbundled
    }

    public static String getEndpointIdentificationAlgorithm(SSLParameters params) {
        // TODO: implement this for unbundled
        return null;
    }

    /**
     * Helper function to unify calls to the different names used for each function taking a
     * Socket, SSLEngine, or String (legacy Android).
     */
    private static boolean checkTrusted(String methodName, X509TrustManager tm,
            X509Certificate[] chain, String authType, Class<?> argumentClass,
            Object argumentInstance) throws CertificateException {
        // Use duck-typing to try and call the hostname-aware method if available.
        try {
            Method method = tm.getClass().getMethod(
                    methodName, X509Certificate[].class, String.class, argumentClass);
            method.invoke(tm, chain, authType, argumentInstance);
            return true;
        } catch (NoSuchMethodException ignored) {
            //Ignored
        } catch (IllegalAccessException ignored) {
            //Ignored
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof CertificateException) {
                throw(CertificateException) e.getCause();
            }
            throw new RuntimeException(e.getCause());
        }
        return false;
    }

    @SuppressLint("NewApi") // AbstractConscryptSocket defines getHandshakeSession()
    public static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain,
            String authType, AbstractConscryptSocket socket) throws CertificateException {
        if (!checkTrusted("checkClientTrusted", tm, chain, authType, Socket.class, socket)
                && !checkTrusted("checkClientTrusted", tm, chain, authType, String.class,
                           socket.getHandshakeSession().getPeerHost())) {
            tm.checkClientTrusted(chain, authType);
        }
    }

    @SuppressLint("NewApi") // AbstractConscryptSocket defines getHandshakeSession()
    public static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain,
            String authType, AbstractConscryptSocket socket) throws CertificateException {
        if (!checkTrusted("checkServerTrusted", tm, chain, authType, Socket.class, socket)
                && !checkTrusted("checkServerTrusted", tm, chain, authType, String.class,
                           socket.getHandshakeSession().getPeerHost())) {
            tm.checkServerTrusted(chain, authType);
        }
    }

    @SuppressLint("NewApi") // AbstractConscryptSocket defines getHandshakeSession()
    public static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain,
            String authType, ConscryptEngine engine) throws CertificateException {
        if (!checkTrusted("checkClientTrusted", tm, chain, authType, SSLEngine.class, engine)
                && !checkTrusted("checkClientTrusted", tm, chain, authType, String.class,
                           engine.getHandshakeSession().getPeerHost())) {
            tm.checkClientTrusted(chain, authType);
        }
    }

    @SuppressLint("NewApi") // AbstractConscryptSocket defines getHandshakeSession()
    public static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain,
            String authType, ConscryptEngine engine) throws CertificateException {
        if (!checkTrusted("checkServerTrusted", tm, chain, authType, SSLEngine.class, engine)
                && !checkTrusted("checkServerTrusted", tm, chain, authType, String.class,
                           engine.getHandshakeSession().getPeerHost())) {
            tm.checkServerTrusted(chain, authType);
        }
    }

    static SSLEngine wrapEngine(ConscryptEngine engine) {
        // For now, don't wrap on Android.
        return engine;
    }

    static SSLEngine unwrapEngine(SSLEngine engine) {
        // For now, don't wrap on Android.
        return engine;
    }

    static ConscryptEngineSocket createEngineSocket(SSLParametersImpl sslParameters)
            throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8EngineSocket(sslParameters);
        }
        return new ConscryptEngineSocket(sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(String hostname, int port,
            SSLParametersImpl sslParameters) throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8EngineSocket(hostname, port, sslParameters);
        }
        return new ConscryptEngineSocket(hostname, port, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(InetAddress address, int port,
            SSLParametersImpl sslParameters) throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8EngineSocket(address, port, sslParameters);
        }
        return new ConscryptEngineSocket(address, port, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(String hostname, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8EngineSocket(hostname, port, clientAddress, clientPort, sslParameters);
        }
        return new ConscryptEngineSocket(hostname, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(InetAddress address, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8EngineSocket(address, port, clientAddress, clientPort, sslParameters);
        }
        return new ConscryptEngineSocket(address, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(Socket socket, String hostname, int port,
            boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8EngineSocket(socket, hostname, port, autoClose, sslParameters);
        }
        return new ConscryptEngineSocket(socket, hostname, port, autoClose, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(SSLParametersImpl sslParameters)
            throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8FileDescriptorSocket(sslParameters);
        }
        return new ConscryptFileDescriptorSocket(sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(String hostname, int port,
            SSLParametersImpl sslParameters) throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8FileDescriptorSocket(hostname, port, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(hostname, port, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(InetAddress address, int port,
            SSLParametersImpl sslParameters) throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8FileDescriptorSocket(address, port, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(address, port, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(String hostname, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8FileDescriptorSocket(
                    hostname, port, clientAddress, clientPort, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(
                hostname, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(InetAddress address, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8FileDescriptorSocket(
                    address, port, clientAddress, clientPort, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(
                address, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(Socket socket, String hostname,
            int port, boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8FileDescriptorSocket(socket, hostname, port, autoClose, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(socket, hostname, port, autoClose, sslParameters);
    }

    /**
     * Wrap the SocketFactory with the platform wrapper if needed for compatability.
     */
    public static SSLSocketFactory wrapSocketFactoryIfNeeded(OpenSSLSocketFactoryImpl factory) {
        if (Build.VERSION.SDK_INT < 22) {
            return new KitKatPlatformOpenSSLSocketAdapterFactory(factory);
        }
        return factory;
    }

    /**
     * Convert from platform's GCMParameterSpec to our internal version.
     */
    @SuppressWarnings("LiteralClassName")
    public static GCMParameters fromGCMParameterSpec(AlgorithmParameterSpec params) {
        Class<?> gcmSpecClass;
        try {
            gcmSpecClass = Class.forName("javax.crypto.spec.GCMParameterSpec");
        } catch (ClassNotFoundException e) {
            gcmSpecClass = null;
        }

        if (gcmSpecClass != null && gcmSpecClass.isAssignableFrom(params.getClass())) {
            try {
                int tLen;
                byte[] iv;

                Method getTLenMethod = gcmSpecClass.getMethod("getTLen");
                Method getIVMethod = gcmSpecClass.getMethod("getIV");
                tLen = (int) getTLenMethod.invoke(params);
                iv = (byte[]) getIVMethod.invoke(params);

                return new GCMParameters(tLen, iv);
            } catch (NoSuchMethodException e) {
                throw new RuntimeException("GCMParameterSpec lacks expected methods", e);
            } catch (IllegalAccessException e) {
                throw new RuntimeException("GCMParameterSpec lacks expected methods", e);
            } catch (InvocationTargetException e) {
                throw new RuntimeException(
                        "Could not fetch GCM parameters", e.getTargetException());
            }
        }
        return null;
    }

    /**
     * Convert from an opaque AlgorithmParameters to the platform's GCMParameterSpec.
     */
    @SuppressWarnings({"LiteralClassName", "unchecked"})
    static AlgorithmParameterSpec fromGCMParameters(AlgorithmParameters params) {
        Class<?> gcmSpecClass;
        try {
            gcmSpecClass = Class.forName("javax.crypto.spec.GCMParameterSpec");
        } catch (ClassNotFoundException e) {
            gcmSpecClass = null;
        }

        if (gcmSpecClass != null) {
            try {
                return params.getParameterSpec((Class) gcmSpecClass);
            } catch (InvalidParameterSpecException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Creates a platform version of {@code GCMParameterSpec}.
     */
    @SuppressWarnings("LiteralClassName")
    public static AlgorithmParameterSpec toGCMParameterSpec(int tagLenInBits, byte[] iv) {
        Class<?> gcmSpecClass;
        try {
            gcmSpecClass = Class.forName("javax.crypto.spec.GCMParameterSpec");
        } catch (ClassNotFoundException e) {
            gcmSpecClass = null;
        }

        if (gcmSpecClass != null) {
            try {
                Constructor<?> constructor = gcmSpecClass.getConstructor(int.class, byte[].class);
                return (AlgorithmParameterSpec) constructor.newInstance(tagLenInBits, iv);
            } catch (NoSuchMethodException | InstantiationException | IllegalAccessException
                    | IllegalArgumentException e) {
                logStackTraceSnippet("Can't find GCMParameterSpec class", e);
            } catch (InvocationTargetException e) {
                logStackTraceSnippet("Can't find GCMParameterSpec class", e.getCause());
            }
        }
        return null;
    }

    /*
     * CloseGuard functions.
     */

    public static CloseGuard closeGuardGet() {
        return CloseGuard.get();
    }

    public static void closeGuardOpen(Object guardObj, String message) {
        CloseGuard guard = (CloseGuard) guardObj;
        guard.open(message);
    }

    public static void closeGuardClose(Object guardObj) {
        CloseGuard guard = (CloseGuard) guardObj;
        guard.close();
    }

    public static void closeGuardWarnIfOpen(Object guardObj) {
        CloseGuard guard = (CloseGuard) guardObj;
        guard.warnIfOpen();
    }

    /*
     * BlockGuard functions.
     */

    public static void blockGuardOnNetwork() {
        BlockGuard.getThreadPolicy().onNetwork();
    }

    /**
     * OID to Algorithm Name mapping.
     */
    @SuppressWarnings("LiteralClassName")
    public static String oidToAlgorithmName(String oid) {
        // Old Harmony style
        try {
            Class<?> algNameMapperClass =
                    Class.forName("org.apache.harmony.security.utils.AlgNameMapper");
            Method map2AlgNameMethod =
                    algNameMapperClass.getDeclaredMethod("map2AlgName", String.class);
            map2AlgNameMethod.setAccessible(true);
            return (String) map2AlgNameMethod.invoke(null, oid);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) {
                throw(RuntimeException) cause;
            } else if (cause instanceof Error) {
                throw(Error) cause;
            }
            throw new RuntimeException(e);
        } catch (Exception ignored) {
            //Ignored
        }

        // Newer OpenJDK style
        try {
            Class<?> algorithmIdClass = Class.forName("sun.security.x509.AlgorithmId");
            Method getMethod = algorithmIdClass.getDeclaredMethod("get", String.class);
            getMethod.setAccessible(true);
            Method getNameMethod = algorithmIdClass.getDeclaredMethod("getName");
            getNameMethod.setAccessible(true);

            Object algIdObj = getMethod.invoke(null, oid);
            return (String) getNameMethod.invoke(algIdObj);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) {
                throw(RuntimeException) cause;
            } else if (cause instanceof Error) {
                throw(Error) cause;
            }
            throw new RuntimeException(e);
        } catch (Exception ignored) {
            //Ignored
        }

        return oid;
    }

    /**
     * Provides extended capabilities for the session if supported by the platform.
     */
    public static SSLSession wrapSSLSession(ExternalSession sslSession) {
        if (Build.VERSION.SDK_INT >= 24) {
            return new Java8ExtendedSSLSession(sslSession);
        }

        return sslSession;
    }

    public static String getOriginalHostNameFromInetAddress(InetAddress addr) {
        if (Build.VERSION.SDK_INT > 27) {
            try {
                Method getHolder = InetAddress.class.getDeclaredMethod("holder");
                getHolder.setAccessible(true);

                Method getOriginalHostName = Class.forName("java.net.InetAddress$InetAddressHolder")
                                                     .getDeclaredMethod("getOriginalHostName");
                getOriginalHostName.setAccessible(true);

                String originalHostName =
                        (String) getOriginalHostName.invoke(getHolder.invoke(addr));
                if (originalHostName == null) {
                    return addr.getHostAddress();
                }
                return originalHostName;
            } catch (InvocationTargetException e) {
                throw new RuntimeException("Failed to get originalHostName", e);
            } catch (ClassNotFoundException ignore) {
                // passthrough and return addr.getHostAddress()
            } catch (IllegalAccessException ignore) {
                //Ignored
            } catch (NoSuchMethodException ignore) {
                //Ignored
            }
        }
        return addr.getHostAddress();
    }

    /*
     * Pre-Java-7 backward compatibility.
     */

    public static String getHostStringFromInetSocketAddress(InetSocketAddress addr) {
        if (Build.VERSION.SDK_INT > 23) {
            try {
                Method m_getHostString = InetSocketAddress.class.getDeclaredMethod("getHostString");
                return (String) m_getHostString.invoke(addr);
            } catch (InvocationTargetException e) {
                throw new RuntimeException(e);
            } catch (Exception ignored) {
                //Ignored
            }
        }
        return null;
    }

    // X509ExtendedTrustManager was added in API 24
    static boolean supportsX509ExtendedTrustManager() {
        return Build.VERSION.SDK_INT > 23;
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
    public static boolean isCTVerificationRequired(String hostname) {
        if (hostname == null) {
            return false;
        }
        // TODO: Use the platform version on platforms that support it

        String property = Security.getProperty("conscrypt.ct.enable");
        if (property == null || !Boolean.parseBoolean(property)) {
            return false;
        }

        List<String> parts = Arrays.asList(hostname.split("\\."));
        Collections.reverse(parts);

        boolean enable = false;
        String propertyName = "conscrypt.ct.enforce";
        // The loop keeps going on even once we've found a match
        // This allows for finer grained settings on subdomains
        for (String part : parts) {
            property = Security.getProperty(propertyName + ".*");
            if (property != null) {
                enable = Boolean.parseBoolean(property);
            }

            propertyName = propertyName + "." + part;
        }

        property = Security.getProperty(propertyName);
        if (property != null) {
            enable = Boolean.parseBoolean(property);
        }
        return enable;
    }

    static boolean supportsConscryptCertStore() {
        return false;
    }

    static KeyStore getDefaultCertKeyStore() throws KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance("AndroidCAStore");
        try {
            keyStore.load(null, null);
        } catch (IOException e) {
            throw new KeyStoreException(e);
        } catch (CertificateException e) {
            throw new KeyStoreException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyStoreException(e);
        }
        return keyStore;
    }

    static ConscryptCertStore newDefaultCertStore() {
        return null;
    }

    static CertBlocklist newDefaultBlocklist() {
        return null;
    }

    static LogStore newDefaultLogStore() {
        return null;
    }

    static Policy newDefaultPolicy() {
        return null;
    }

    static boolean serverNamePermitted(SSLParametersImpl parameters, String serverName) {
        if (Build.VERSION.SDK_INT >= 24) {
            return serverNamePermittedInternal(parameters, serverName);
        }
        return true;
    }

    @TargetApi(24)
    private static boolean serverNamePermittedInternal(
            SSLParametersImpl parameters, String serverName) {
        Collection<SNIMatcher> sniMatchers = parameters.getSNIMatchers();
        if (sniMatchers == null || sniMatchers.isEmpty()) {
            return true;
        }

        for (SNIMatcher m : sniMatchers) {
            boolean match = m.matches(new SNIHostName(serverName));
            if (match) {
                return true;
            }
        }
        return false;
    }

    public static ConscryptHostnameVerifier getDefaultHostnameVerifier() {
        return OkHostnameVerifier.strictInstance();
    }

    /**
     * Returns milliseconds elapsed since boot, including time spent in sleep.
     * @return long number of milliseconds elapsed since boot
     */
    static long getMillisSinceBoot() {
        return SystemClock.elapsedRealtime();
    }

    public static StatsLog getStatsLog() {
        if (Build.VERSION.SDK_INT >= 30) {
            return StatsLogImpl.getInstance();
        }
        return null;
    }

    public static Source getStatsSource() {
        return Source.SOURCE_GMS;
    }

    // Only called from StatsLogImpl, so protected by build version check above.
    @TargetApi(30)
    public static int[] getUids() {
        return new int[] {Os.getuid(), Binder.getCallingUid()};
    }

    public static boolean isJavaxCertificateSupported() {
        return true;
    }

    public static boolean isTlsV1Deprecated() {
        return DEPRECATED_TLS_V1;
    }

    public static boolean isTlsV1Filtered() {
        return FILTERED_TLS_V1;
    }

    public static boolean isTlsV1Supported() {
        return ENABLED_TLS_V1;
    }
}
