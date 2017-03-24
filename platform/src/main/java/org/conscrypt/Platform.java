/*
 * Copyright 2013 The Android Open Source Project
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

import dalvik.system.BlockGuard;
import dalvik.system.CloseGuard;
import java.io.FileDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
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
import libcore.net.NetworkSecurityPolicy;

class Platform {
    private static class NoPreloadHolder {
        static final Platform MAPPER = new Platform();
    }

    /**
     * Runs all the setup for the platform that only needs to run once.
     */
    public static void setup() {
        NoPreloadHolder.MAPPER.ping();
    }

    /**
     * Just a placeholder to make sure the class is initialized.
     */
    private void ping() {
    }

    private Platform() {
    }

    static FileDescriptor getFileDescriptor(Socket s) {
        return JavaExtensions.getFileDescriptor(s);
    }

    static FileDescriptor getFileDescriptorFromSSLSocket(OpenSSLSocketImpl openSSLSocketImpl) {
        return JavaExtensions.getFileDescriptorFromSSLSocket(openSSLSocketImpl);
    }

    static String getCurveName(ECParameterSpec spec) {
        return JavaExtensions.getCurveName(spec);
    }

    static void setCurveName(ECParameterSpec spec, String curveName) {
        JavaExtensions.setCurveName(spec, curveName);
    }

    static void setSocketWriteTimeout(Socket s, long timeoutMillis) throws SocketException {
        JavaExtensions.setSocketWriteTimeout(s, timeoutMillis);
    }

    static void setSSLParameters(SSLParameters params, SSLParametersImpl impl,
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

    static void getSSLParameters(SSLParameters params, SSLParametersImpl impl,
            OpenSSLSocketImpl socket) {
        params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        params.setUseCipherSuitesOrder(impl.getUseCipherSuitesOrder());
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(socket.getHostname())) {
            params.setServerNames(Collections.<SNIServerName> singletonList(
                    new SNIHostName(socket.getHostname())));
        }
    }

    static void setSSLParameters(
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

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, OpenSSLEngineImpl engine) {
        params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        params.setUseCipherSuitesOrder(impl.getUseCipherSuitesOrder());
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(engine.getSniHostname())) {
            params.setServerNames(Collections.<SNIServerName>singletonList(
                    new SNIHostName(engine.getSniHostname())));
        }
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
            Method method = tm.getClass().getMethod(methodName,
                    X509Certificate[].class,
                    String.class,
                    argumentClass);
            method.invoke(tm, chain, authType, argumentInstance);
            return true;
        } catch (NoSuchMethodException | IllegalAccessException ignored) {
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof CertificateException) {
                throw (CertificateException) e.getCause();
            }
            throw new RuntimeException(e.getCause());
        }
        return false;
    }

    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain,
            String authType, OpenSSLSocketImpl socket) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkClientTrusted(chain, authType, socket);
        } else if (!checkTrusted("checkClientTrusted", tm, chain, authType, Socket.class, socket)
                && !checkTrusted("checkClientTrusted", tm, chain, authType, String.class,
                                 socket.getHandshakeSession().getPeerHost())) {
            tm.checkClientTrusted(chain, authType);
        }
    }

    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain,
            String authType, OpenSSLSocketImpl socket) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkServerTrusted(chain, authType, socket);
        } else if (!checkTrusted("checkServerTrusted", tm, chain, authType, Socket.class, socket)
                && !checkTrusted("checkServerTrusted", tm, chain, authType, String.class,
                                 socket.getHandshakeSession().getPeerHost())) {
            tm.checkServerTrusted(chain, authType);
        }
    }

    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain,
            String authType, OpenSSLEngineImpl engine) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkClientTrusted(chain, authType, engine);
        } else if (!checkTrusted("checkClientTrusted", tm, chain, authType, SSLEngine.class, engine)
                && !checkTrusted("checkClientTrusted", tm, chain, authType, String.class,
                                 engine.getHandshakeSession().getPeerHost())) {
            tm.checkClientTrusted(chain, authType);
        }
    }

    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain,
            String authType, OpenSSLEngineImpl engine) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkServerTrusted(chain, authType, engine);
        } else if (!checkTrusted("checkServerTrusted", tm, chain, authType, SSLEngine.class, engine)
                && !checkTrusted("checkServerTrusted", tm, chain, authType, String.class,
                                 engine.getHandshakeSession().getPeerHost())) {
            tm.checkServerTrusted(chain, authType);
        }
    }

    /**
     * Wraps an old AndroidOpenSSL key instance. This is not needed on platform
     * builds since we didn't backport, so return null.
     */
    static OpenSSLKey wrapRsaKey(PrivateKey key) {
        return null;
    }

    /**
     * Logs to the system EventLog system.
     */
    static void logEvent(String message) {
        try {
            @SuppressWarnings("LiteralClassName")
            Class<?> processClass = Class.forName("android.os.Process");
            Object processInstance = processClass.getConstructor().newInstance();
            Method myUidMethod = processClass.getMethod("myUid", (Class[]) null);
            int uid = (Integer) myUidMethod.invoke(processInstance);

            @SuppressWarnings("LiteralClassName")
            Class<?> eventLogClass = Class.forName("android.util.EventLog");
            Object eventLogInstance = eventLogClass.getConstructor().newInstance();
            Method writeEventMethod = eventLogClass.getMethod("writeEvent",
                    Integer.TYPE, Object[].class);
            writeEventMethod.invoke(eventLogInstance, 0x534e4554 /* SNET */,
                    new Object[] { "conscrypt", uid, message });
        } catch (Exception e) {
            // Do not log and fail silently
        }
    }

    /**
     * Returns true if the supplied hostname is an literal IP address.
     */
    static boolean isLiteralIpAddress(String hostname) {
        return JavaExtensions.isLiteralIpAddress(hostname);
    }

    /**
     * Wrap the SocketFactory with the platform wrapper if needed for compatability.
     * For the platform-bundled library we never need to wrap.
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

    static CloseGuard closeGuardGet() {
        return CloseGuard.get();
    }

    static void closeGuardOpen(Object guardObj, String message) {
        CloseGuard guard = (CloseGuard) guardObj;
        guard.open(message);
    }

    static void closeGuardClose(Object guardObj) {
        CloseGuard guard = (CloseGuard) guardObj;
        guard.close();
    }

    static void closeGuardWarnIfOpen(Object guardObj) {
        CloseGuard guard = (CloseGuard) guardObj;
        guard.warnIfOpen();
    }

    /*
     * BlockGuard functions.
     */

    static void blockGuardOnNetwork() {
        BlockGuard.getThreadPolicy().onNetwork();
    }

    /**
     * OID to Algorithm Name mapping.
     */
    static String oidToAlgorithmName(String oid) {
        return JavaExtensions.oidToAlgorithmName(oid);
    }

    /*
     * Pre-Java 8 backward compatibility.
     */

    static SSLSession wrapSSLSession(AbstractOpenSSLSession sslSession) {
        return new OpenSSLExtendedSessionImpl(sslSession);
    }

    static SSLSession unwrapSSLSession(SSLSession sslSession) {
        if (sslSession instanceof OpenSSLExtendedSessionImpl) {
            return ((OpenSSLExtendedSessionImpl) sslSession).getDelegate();
        }
        return sslSession;
    }

    /*
     * Pre-Java-7 backward compatibility.
     */

    static String getHostStringFromInetSocketAddress(InetSocketAddress addr) {
        return addr.getHostString();
    }

    static boolean isCTVerificationRequired(String hostname) {
        return NetworkSecurityPolicy.getInstance()
                .isCertificateTransparencyVerificationRequired(hostname);
    }
}
