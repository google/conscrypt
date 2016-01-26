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

import android.os.Build;
import android.util.Log;
import java.io.FileDescriptor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

/**
 *
 */
public class Platform {
    private static final String TAG = "Conscrypt";

    private static Method m_getCurveName;
    static {
        try {
            m_getCurveName = ECParameterSpec.class.getDeclaredMethod("getCurveName");
            m_getCurveName.setAccessible(true);
        } catch (Exception ignored) {
        }
    }

    public static void setup() {
    }

    public static FileDescriptor getFileDescriptor(Socket s) {
        try {
            Field f_impl = Socket.class.getDeclaredField("impl");
            f_impl.setAccessible(true);
            Object socketImpl = f_impl.get(s);
            Class<?> c_socketImpl = Class.forName("java.net.SocketImpl");
            Field f_fd = c_socketImpl.getDeclaredField("fd");
            f_fd.setAccessible(true);
            return (FileDescriptor) f_fd.get(socketImpl);
        } catch (Exception e) {
            throw new RuntimeException("Can't get FileDescriptor from socket", e);
        }
    }

    public static FileDescriptor getFileDescriptorFromSSLSocket(OpenSSLSocketImpl openSSLSocketImpl) {
        return getFileDescriptor(openSSLSocketImpl);
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
            Class<?> c_structTimeval = getClass("android.system.StructTimeval",
                    "libcore.io.StructTimeval");
            if (c_structTimeval == null) {
                Log.w(TAG, "Cannot find StructTimeval; not setting socket write timeout");
                return;
            }

            Method m_fromMillis = c_structTimeval.getDeclaredMethod("fromMillis", long.class);
            Object timeval = m_fromMillis.invoke(null, timeoutMillis);

            Class<?> c_Libcore = Class.forName("libcore.io.Libcore");
            if (c_Libcore == null) {
                Log.w(TAG, "Cannot find libcore.os.Libcore; not setting socket write timeout");
                return;
            }

            Field f_os = c_Libcore.getField("os");
            Object instance_os = f_os.get(null);

            Class<?> c_osConstants = getClass("android.system.OsConstants",
                    "libcore.io.OsConstants");
            Field f_SOL_SOCKET = c_osConstants.getField("SOL_SOCKET");
            Field f_SO_SNDTIMEO = c_osConstants.getField("SO_SNDTIMEO");

            Method m_setsockoptTimeval = instance_os.getClass().getMethod("setsockoptTimeval",
                    FileDescriptor.class, int.class, int.class, c_structTimeval);

            m_setsockoptTimeval.invoke(instance_os, getFileDescriptor(s), f_SOL_SOCKET.get(null),
                    f_SO_SNDTIMEO.get(null), timeval);
        } catch (Exception e) {
            Log.w(TAG, "Could not set socket write timeout: " + e.getMessage());
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

    public static void setEndpointIdentificationAlgorithm(SSLParameters params,
            String endpointIdentificationAlgorithm) {
        // TODO: implement this for unbundled
    }

    public static String getEndpointIdentificationAlgorithm(SSLParameters params) {
        // TODO: implement this for unbundled
        return null;
    }

    public static void checkServerTrusted(X509TrustManager x509tm, X509Certificate[] chain,
            String authType, String host) throws CertificateException {
        // TODO: use reflection to find whether we have TrustManagerImpl
        /*
        if (x509tm instanceof TrustManagerImpl) {
            TrustManagerImpl tm = (TrustManagerImpl) x509tm;
            tm.checkServerTrusted(chain, authType, host);
        } else {
        */
            x509tm.checkServerTrusted(chain, authType);
        /*
        }
        */
    }

    /**
     * Wraps an old AndroidOpenSSL key instance. This is not needed on platform
     * builds since we didn't backport, so return null. This code is from
     * Chromium's net/android/java/src/org/chromium/net/DefaultAndroidKeyStore.java
     */
    public static OpenSSLKey wrapRsaKey(PrivateKey javaKey) {
        // This fixup only applies to pre-JB-MR1
        if (Build.VERSION.SDK_INT >= 17) {
            return null;
        }

        // First, check that this is a proper instance of OpenSSLRSAPrivateKey
        // or one of its sub-classes.
        Class<?> superClass;
        try {
            superClass = Class
                    .forName("org.apache.harmony.xnet.provider.jsse.OpenSSLRSAPrivateKey");
        } catch (Exception e) {
            // This may happen if the target device has a completely different
            // implementation of the java.security APIs, compared to vanilla
            // Android. Highly unlikely, but still possible.
            Log.e(TAG, "Cannot find system OpenSSLRSAPrivateKey class: " + e);
            return null;
        }
        if (!superClass.isInstance(javaKey)) {
            // This may happen if the PrivateKey was not created by the
            // "AndroidOpenSSL"
            // provider, which should be the default. That could happen if an
            // OEM decided
            // to implement a different default provider. Also highly unlikely.
            Log.e(TAG, "Private key is not an OpenSSLRSAPrivateKey instance, its class name is:"
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
    public static void logEvent(String message) {
        try {
            Class processClass = Class.forName("android.os.Process");
            Object processInstance = processClass.newInstance();
            Method myUidMethod = processClass.getMethod("myUid", (Class[]) null);
            int uid = (Integer) myUidMethod.invoke(processInstance);

            Class eventLogClass = Class.forName("android.util.EventLog");
            Object eventLogInstance = eventLogClass.newInstance();
            Method writeEventMethod = eventLogClass.getMethod("writeEvent",
                    new Class[] { Integer.TYPE, Object[].class });
            writeEventMethod.invoke(eventLogInstance, 0x534e4554 /* SNET */,
                    new Object[] { "conscrypt", uid, message });
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
}
