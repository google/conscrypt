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
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;
import java.nio.channels.SocketChannel;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import sun.security.x509.AlgorithmId;

/**
 * Platform-specific methods for OpenJDK
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

    private Platform() {
    }

    public static void setup() {
    }

    public static FileDescriptor getFileDescriptor(Socket s) {
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

    public static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, OpenSSLEngineImpl engine) {
        impl.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        impl.setUseCipherSuitesOrder(params.getUseCipherSuitesOrder());
        List<SNIServerName> serverNames = params.getServerNames();
        if (serverNames != null) {
            for (SNIServerName serverName : serverNames) {
                if (serverName.getType() == StandardConstants.SNI_HOST_NAME) {
                    engine.setSniHostname(((SNIHostName) serverName).getAsciiName());
                    break;
                }
            }
        }
    }

    public static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, OpenSSLEngineImpl engine) {
        params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        params.setUseCipherSuitesOrder(impl.getUseCipherSuitesOrder());
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(engine.getSniHostname())) {
            params.setServerNames(Collections.<SNIServerName>singletonList(
                    new SNIHostName(engine.getSniHostname())));
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

    public static SSLSession wrapSSLSession(AbstractOpenSSLSession sslSession) {
        return new OpenSSLExtendedSessionImpl(sslSession);
    }

    public static SSLSession unwrapSSLSession(SSLSession sslSession) {
        if (sslSession instanceof OpenSSLExtendedSessionImpl) {
            return ((OpenSSLExtendedSessionImpl) sslSession).getDelegate();
        }
        return sslSession;
    }

    /*
     * Pre-Java-7 backward compatibility.
     */

    public static String getHostStringFromInetSocketAddress(InetSocketAddress addr) {
        return addr.getHostString();
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

        String property = Security.getProperty("conscrypt.ct.enable");
        if (property == null || Boolean.valueOf(property.toLowerCase()) == false) {
            return false;
        }

        List<String> parts = Arrays.asList(hostname.split("\\."));
        Collections.reverse(parts);

        boolean enable = false;
        String propertyName = "conscrypt.ct.enforce";
        // The loop keeps going on even once we've found a match
        // This allows for finer grained settings on subdomains
        for (String part: parts) {
            property = Security.getProperty(propertyName + ".*");
            if (property != null) {
                enable = Boolean.valueOf(property.toLowerCase());
            }

            propertyName = propertyName + "." + part;
        }

        property = Security.getProperty(propertyName);
        if (property != null) {
            enable = Boolean.valueOf(property.toLowerCase());
        }
        return enable;
    }
}
