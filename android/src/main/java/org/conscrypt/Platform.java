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
import android.os.Build;
import android.util.Log;
import dalvik.system.BlockGuard;
import dalvik.system.CloseGuard;
import java.io.FileDescriptor;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509TrustManager;

/**
 * Platform-specific methods for unbundled Android.
 */
final class Platform {
    private static final String TAG = "Conscrypt";

    private static Method m_getCurveName;
    static {
        try {
            m_getCurveName = ECParameterSpec.class.getDeclaredMethod("getCurveName");
            m_getCurveName.setAccessible(true);
        } catch (Exception ignored) {
        }
    }

    private Platform() {}

    public static void setup() {}

    /**
     * Default name used in the {@link java.security.Security JCE system} by {@code OpenSSLProvider}
     * if the default constructor is used.
     */
    public static String getDefaultProviderName() {
        return "Conscrypt";
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
        }
    }

    /*
     * Call Os.setsockoptTimeval via reflection.
     */
    public static void setSocketWriteTimeout(Socket s, long timeoutMillis) throws SocketException {
        try {
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

            m_setsockoptTimeval.invoke(instance_os, getFileDescriptor(s), f_SOL_SOCKET.get(null),
                    f_SO_SNDTIMEO.get(null), timeval);
        } catch (Exception e) {
            // We don't want to spam the logcat since this isn't a fatal error, but we want to know
            // why this might be happening.
            Log.w(TAG, "Could not set socket write timeout:");
            StackTraceElement[] elements = e.getStackTrace();
            for (int i = 0; i < 2 && i < elements.length; i++) {
                Log.w(TAG, "   " + elements[i].toString());
            }
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
        } catch (IllegalAccessException ignored) {
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
        } catch (IllegalAccessException ignored) {
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
        } catch (IllegalAccessException ignored) {
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
        } catch (IllegalAccessException ignored) {
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
        } catch (IllegalAccessException ignored) {
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

    /**
     * Wraps an old AndroidOpenSSL key instance. This is not needed on platform
     * builds since we didn't backport, so return null. This code is from
     * Chromium's net/android/java/src/org/chromium/net/DefaultAndroidKeyStore.java
     */
    @SuppressWarnings("LiteralClassName")
    public static OpenSSLKey wrapRsaKey(PrivateKey javaKey) {
        // This fixup only applies to pre-JB-MR1
        if (Build.VERSION.SDK_INT >= 17) {
            return null;
        }

        // First, check that this is a proper instance of OpenSSLRSAPrivateKey
        // or one of its sub-classes.
        Class<?> superClass;
        try {
            superClass =
                    Class.forName("org.apache.harmony.xnet.provider.jsse.OpenSSLRSAPrivateKey");
        } catch (Exception e) {
            // This may happen if the target device has a completely different
            // implementation of the java.security APIs, compared to vanilla
            // Android. Highly unlikely, but still possible.
            Log.e(TAG, "Cannot find system OpenSSLRSAPrivateKey class: " + e);
            return null;
        }
        if (!superClass.isInstance(javaKey)) {
            // This may happen if the PrivateKey was not created by the
            // Conscrypt provider, which should be the default. That could happen if an
            // OEM decided to implement a different default provider. Also highly unlikely.
            Log.e(TAG,
                    "Private key is not an OpenSSLRSAPrivateKey instance, its class name is:"
                            + javaKey.getClass().getCanonicalName());
            return null;
        }

        try {
            // Use reflection to invoke the 'getOpenSSLKey()' method on
            // the private key. This returns another Java object that wraps
            // a native EVP_PKEY. Note that the method is final, so calling
            // the superclass implementation is ok.
            Method getKey = superClass.getDeclaredMethod("getOpenSSLKey");
            getKey.setAccessible(true);
            Object opensslKey = null;
            try {
                opensslKey = getKey.invoke(javaKey);
            } finally {
                getKey.setAccessible(false);
            }
            if (opensslKey == null) {
                // Bail when detecting OEM "enhancement".
                Log.e(TAG, "Could not getOpenSSLKey on instance: " + javaKey.toString());
                return null;
            }

            // Use reflection to invoke the 'getPkeyContext' method on the
            // result of the getOpenSSLKey(). This is an 32-bit integer
            // which is the address of an EVP_PKEY object. Note that this
            // method these days returns a 64-bit long, but since this code
            // path is used for older Android versions, it may still return
            // a 32-bit int here. To be on the safe side, we cast the return
            // value via Number rather than directly to Integer or Long.
            Method getPkeyContext;
            try {
                getPkeyContext = opensslKey.getClass().getDeclaredMethod("getPkeyContext");
            } catch (Exception e) {
                // Bail here too, something really not working as expected.
                Log.e(TAG, "No getPkeyContext() method on OpenSSLKey member:" + e);
                return null;
            }
            getPkeyContext.setAccessible(true);
            long evp_pkey = 0;
            try {
                evp_pkey = ((Number) getPkeyContext.invoke(opensslKey)).longValue();
            } finally {
                getPkeyContext.setAccessible(false);
            }
            if (evp_pkey == 0) {
                // The PrivateKey is probably rotten for some reason.
                Log.e(TAG, "getPkeyContext() returned null");
                return null;
            }
            return new OpenSSLKey(evp_pkey);
        } catch (Exception e) {
            Log.e(TAG, "Error during conversion of privatekey instance: " + javaKey.toString(), e);
            return null;
        }
    }

    /**
     * Logs to the system EventLog system.
     */
    @SuppressWarnings("LiteralClassName")
    public static void logEvent(String message) {
        try {
            Class<?> processClass = Class.forName("android.os.Process");
            Object processInstance = processClass.getDeclaredConstructor().newInstance();
            Method myUidMethod = processClass.getMethod("myUid", (Class[]) null);
            int uid = (Integer) myUidMethod.invoke(processInstance);

            Class<?> eventLogClass = Class.forName("android.util.EventLog");
            Object eventLogInstance = eventLogClass.getDeclaredConstructor().newInstance();
            Method writeEventMethod =
                    eventLogClass.getMethod("writeEvent", Integer.TYPE, Object[].class);
            writeEventMethod.invoke(eventLogInstance, 0x534e4554 /* SNET */,
                    new Object[] {"conscrypt", uid, message});
        } catch (Exception e) {
            // Fail silently
        }
    }

    /**
     * Returns true if the supplied hostname is an literal IP address.
     */
    public static boolean isLiteralIpAddress(String hostname) {
        try {
            Method m_isNumeric = InetAddress.class.getMethod("isNumeric", String.class);
            return (Boolean) m_isNumeric.invoke(null, hostname);
        } catch (Exception ignored) {
        }

        return AddressUtils.isLiteralIpAddress(hostname);
    }

    /**
     * Wrap the SocketFactory with the platform wrapper if needed for compatability.
     */
    public static SSLSocketFactory wrapSocketFactoryIfNeeded(OpenSSLSocketFactoryImpl factory) {
        if (Build.VERSION.SDK_INT < 19) {
            return new PreKitKatPlatformOpenSSLSocketAdapterFactory(factory);
        } else if (Build.VERSION.SDK_INT < 22) {
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
                e.printStackTrace();
            } catch (InvocationTargetException e) {
                e.getCause().printStackTrace();
            }
        }
        return null;
    }

    /*
     * CloseGuard functions.
     */

    public static CloseGuard closeGuardGet() {
        if (Build.VERSION.SDK_INT < 14) {
            return null;
        }

        return CloseGuard.get();
    }

    public static void closeGuardOpen(Object guardObj, String message) {
        if (Build.VERSION.SDK_INT < 14) {
            return;
        }

        CloseGuard guard = (CloseGuard) guardObj;
        guard.open(message);
    }

    public static void closeGuardClose(Object guardObj) {
        if (Build.VERSION.SDK_INT < 14) {
            return;
        }

        CloseGuard guard = (CloseGuard) guardObj;
        guard.close();
    }

    public static void closeGuardWarnIfOpen(Object guardObj) {
        if (Build.VERSION.SDK_INT < 14) {
            return;
        }

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
        }

        return oid;
    }

    /*
     * Pre-Java 8 backward compatibility.
     */

    public static SSLSession wrapSSLSession(ActiveSession sslSession) {
        if (Build.VERSION.SDK_INT <= 23) {
            return sslSession;
        }

        return ExtendedSessionAdapter.wrap(sslSession);
    }

    public static SSLSession unwrapSSLSession(SSLSession sslSession) {
        if (Build.VERSION.SDK_INT <= 23) {
            return sslSession;
        }

        return ExtendedSessionAdapter.getDelegate(sslSession);
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
            } catch (NoSuchMethodException ignore) {
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
            }
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
    public static boolean isCTVerificationRequired(String hostname) {
        if (hostname == null) {
            return false;
        }
        // TODO: Use the platform version on platforms that support it

        String property = Security.getProperty("conscrypt.ct.enable");
        if (property == null || !Boolean.valueOf(property)) {
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
                enable = Boolean.valueOf(property);
            }

            propertyName = propertyName + "." + part;
        }

        property = Security.getProperty(propertyName);
        if (property != null) {
            enable = Boolean.valueOf(property);
        }
        return enable;
    }
}
