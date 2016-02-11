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

import java.io.FileDescriptor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Collections;
import java.util.List;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import sun.security.x509.AlgorithmId;

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
        // This doesn't appear to be needed.
    }

    /*
     * Call Os.setsockoptTimeval via reflection.
     */
    public static void setSocketWriteTimeout(Socket s, long timeoutMillis) throws SocketException {
        // TODO: figure this out on the RI
    }

    public static void setSSLParameters(SSLParameters params, SSLParametersImpl impl,
            OpenSSLSocketImpl socket) {
        impl.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        impl.setUseCipherSuitesOrder(params.getUseCipherSuitesOrder());
        List<SNIServerName> serverNames = params.getServerNames();
        if (serverNames != null) {
            for (SNIServerName serverName : serverNames) {
                if (serverName.getType() == StandardConstants.SNI_HOST_NAME) {
                    socket.setHostname(((SNIHostName) serverName).getAsciiName());
                    break;
                }
            }
        }
    }

    public static void getSSLParameters(SSLParameters params, SSLParametersImpl impl,
            OpenSSLSocketImpl socket) {
        params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        params.setUseCipherSuitesOrder(impl.getUseCipherSuitesOrder());
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(socket.getHostname())) {
            params.setServerNames(Collections.<SNIServerName> singletonList(
                    new SNIHostName(socket.getHostname())));
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
        params.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
    }

    public static String getEndpointIdentificationAlgorithm(SSLParameters params) {
        return params.getEndpointIdentificationAlgorithm();
    }

    public static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain,
            String authType, OpenSSLSocketImpl socket) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkClientTrusted(chain, authType, socket);
        } else {
            tm.checkClientTrusted(chain, authType);
        }
    }

    public static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain,
            String authType, OpenSSLSocketImpl socket) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkServerTrusted(chain, authType, socket);
        } else {
            tm.checkServerTrusted(chain, authType);
        }
    }

    public static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain,
            String authType, OpenSSLEngineImpl engine) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkClientTrusted(chain, authType, engine);
        } else {
            tm.checkClientTrusted(chain, authType);
        }
    }

    public static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain,
            String authType, OpenSSLEngineImpl engine) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkServerTrusted(chain, authType, engine);
        } else {
            tm.checkServerTrusted(chain, authType);
        }
    }

    /**
     * Wraps an old AndroidOpenSSL key instance. This is not needed on RI.
     */
    public static OpenSSLKey wrapRsaKey(PrivateKey javaKey) {
        return null;
    }

    /**
     * Logs to the system EventLog system.
     */
    public static void logEvent(String message) {
    }

    /**
     * Returns true if the supplied hostname is an literal IP address.
     */
    public static boolean isLiteralIpAddress(String hostname) {
        // TODO: any RI API to make this better?
        return AddressUtils.isLiteralIpAddress(hostname);
    }

    /**
     * For unbundled versions, SNI is always enabled by default.
     */
    public static boolean isSniEnabledByDefault() {
        return true;
    }

    /**
     * Currently we don't wrap anything from the RI.
     */
    public static SSLSocketFactory wrapSocketFactoryIfNeeded(OpenSSLSocketFactoryImpl factory) {
        return factory;
    }

    /**
     * Convert from platform's GCMParameterSpec to our internal version.
     */
    public static GCMParameters fromGCMParameterSpec(AlgorithmParameterSpec params) {
        if (params instanceof GCMParameterSpec) {
            GCMParameterSpec gcmParams = (GCMParameterSpec) params;
            return new GCMParameters(gcmParams.getTLen(), gcmParams.getIV());
        }
        return null;
    }

    /**
     * Creates a platform version of {@code GCMParameterSpec}.
     */
    public static AlgorithmParameterSpec toGCMParameterSpec(int tagLenInBits, byte[] iv) {
        return new GCMParameterSpec(tagLenInBits, iv);
    }

    /*
     * CloseGuard functions.
     */

    public static Object closeGuardGet() {
        return null;
    }

    public static void closeGuardOpen(Object guardObj, String message) {
    }

    public static void closeGuardClose(Object guardObj) {
    }

    public static void closeGuardWarnIfOpen(Object guardObj) {
    }

    /*
     * BlockGuard functions.
     */

    public static void blockGuardOnNetwork() {
    }

    /**
     * OID to Algorithm Name mapping.
     */
    public static String oidToAlgorithmName(String oid) {
        try {
            return AlgorithmId.get(oid).getName();
        } catch (NoSuchAlgorithmException e) {
            return oid;
        }
    }

    /*
     * Pre-Java-8 backward compatibility.
     */

    public static SSLSession wrapSSLSession(OpenSSLSessionImpl sslSession) {
        return new OpenSSLExtendedSessionImpl(sslSession);
    }

    /*
     * Pre-Java-7 backward compatibility.
     */

    public static String getHostStringFromInetSocketAddress(InetSocketAddress addr) {
        return addr.getHostString();
    }
}
