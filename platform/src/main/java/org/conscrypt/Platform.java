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

import static android.system.OsConstants.SOL_SOCKET;
import static android.system.OsConstants.SO_SNDTIMEO;

import android.system.ErrnoException;
import android.system.Os;
import android.system.StructTimeval;

import dalvik.system.BlockGuard;
import dalvik.system.CloseGuard;
import dalvik.system.VMRuntime;

import libcore.net.NetworkSecurityPolicy;

import org.conscrypt.ct.LogStore;
import org.conscrypt.ct.LogStoreImpl;
import org.conscrypt.ct.Policy;
import org.conscrypt.ct.PolicyImpl;
import org.conscrypt.metrics.OptionalMethod;
import org.conscrypt.metrics.Source;
import org.conscrypt.metrics.StatsLog;
import org.conscrypt.metrics.StatsLogImpl;

import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.System;
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import sun.security.x509.AlgorithmId;

@Internal
final public class Platform {
    private static class NoPreloadHolder { public static final Platform MAPPER = new Platform(); }

    /**
     * Runs all the setup for the platform that only needs to run once.
     */
    public static void setup() {
        NoPreloadHolder.MAPPER.ping();
    }

    /**
     * Just a placeholder to make sure the class is initialized.
     */
    private void ping() {}

    private Platform() {}

    /**
     * Default name used in the {@link java.security.Security JCE system} by {@code OpenSSLProvider}
     * if the default constructor is used.
     */
    // @VisibleForTesting - used by CTS
    public static String getDefaultProviderName() {
        return "AndroidOpenSSL";
    }

    static boolean provideTrustManagerByDefault() {
        return false;
    }

    static FileDescriptor getFileDescriptor(Socket s) {
        return s.getFileDescriptor$();
    }

    static FileDescriptor getFileDescriptorFromSSLSocket(AbstractConscryptSocket socket) {
        try {
            Field f_impl = Socket.class.getDeclaredField("impl");
            f_impl.setAccessible(true);
            Object socketImpl = f_impl.get(socket);
            Field f_fd = SocketImpl.class.getDeclaredField("fd");
            f_fd.setAccessible(true);
            return (FileDescriptor) f_fd.get(socketImpl);
        } catch (Exception e) {
            throw new RuntimeException("Can't get FileDescriptor from socket", e);
        }
    }

    static String getCurveName(ECParameterSpec spec) {
        return spec.getCurveName();
    }

    static void setCurveName(ECParameterSpec spec, String curveName) {
        spec.setCurveName(curveName);
    }

    static void setSocketWriteTimeout(Socket s, long timeoutMillis) throws SocketException {
        StructTimeval tv = StructTimeval.fromMillis(timeoutMillis);
        try {
            Os.setsockoptTimeval(s.getFileDescriptor$(), SOL_SOCKET, SO_SNDTIMEO, tv);
        } catch (ErrnoException errnoException) {
            // Equivalent to errnoException.rethrowAsSocketException() but that causes
            // lint issues on AOSP.
            SocketException exception = new SocketException(errnoException.getMessage());
            exception.addSuppressed(errnoException);
            throw exception;
        }
    }

    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
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
        impl.setApplicationProtocols(params.getApplicationProtocols());
    }

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        params.setUseCipherSuitesOrder(impl.getUseCipherSuitesOrder());
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(socket.getHostname())) {
            params.setServerNames(Collections.<SNIServerName>singletonList(
                    new SNIHostName(socket.getHostname())));
        }
        params.setApplicationProtocols(impl.getApplicationProtocols());
    }

    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        impl.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        impl.setUseCipherSuitesOrder(params.getUseCipherSuitesOrder());
        List<SNIServerName> serverNames = params.getServerNames();
        if (serverNames != null) {
            for (SNIServerName serverName : serverNames) {
                if (serverName.getType() == StandardConstants.SNI_HOST_NAME) {
                    engine.setHostname(((SNIHostName) serverName).getAsciiName());
                    break;
                }
            }
        }
        impl.setApplicationProtocols(params.getApplicationProtocols());
    }

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        params.setUseCipherSuitesOrder(impl.getUseCipherSuitesOrder());
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(engine.getHostname())) {
            params.setServerNames(Collections.<SNIServerName>singletonList(
                    new SNIHostName(engine.getHostname())));
        }
        params.setApplicationProtocols(impl.getApplicationProtocols());
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
        } catch (NoSuchMethodException | IllegalAccessException ignored) {
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof CertificateException) {
                throw(CertificateException) e.getCause();
            }
            throw new RuntimeException(e.getCause());
        }
        return false;
    }

    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            AbstractConscryptSocket socket) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkClientTrusted(chain, authType, socket);
        } else if (!checkTrusted("checkClientTrusted", tm, chain, authType, Socket.class, socket)
                && !checkTrusted("checkClientTrusted", tm, chain, authType, String.class,
                           socket.getHandshakeSession().getPeerHost())) {
            tm.checkClientTrusted(chain, authType);
        }
    }

    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            AbstractConscryptSocket socket) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkServerTrusted(chain, authType, socket);
        } else if (!checkTrusted("checkServerTrusted", tm, chain, authType, Socket.class, socket)
                && !checkTrusted("checkServerTrusted", tm, chain, authType, String.class,
                           socket.getHandshakeSession().getPeerHost())) {
            tm.checkServerTrusted(chain, authType);
        }
    }

    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            ConscryptEngine engine) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkClientTrusted(chain, authType, engine);
        } else if (!checkTrusted("checkClientTrusted", tm, chain, authType, SSLEngine.class, engine)
                && !checkTrusted("checkClientTrusted", tm, chain, authType, String.class,
                           engine.getHandshakeSession().getPeerHost())) {
            tm.checkClientTrusted(chain, authType);
        }
    }

    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            ConscryptEngine engine) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkServerTrusted(chain, authType, engine);
        } else if (!checkTrusted("checkServerTrusted", tm, chain, authType, SSLEngine.class, engine)
                && !checkTrusted("checkServerTrusted", tm, chain, authType, String.class,
                           engine.getHandshakeSession().getPeerHost())) {
            tm.checkServerTrusted(chain, authType);
        }
    }

    static SSLEngine wrapEngine(ConscryptEngine engine) {
        return new Java8EngineWrapper(engine);
    }

    static SSLEngine unwrapEngine(SSLEngine engine) {
        return Java8EngineWrapper.getDelegate(engine);
    }

    static ConscryptEngineSocket createEngineSocket(SSLParametersImpl sslParameters)
            throws IOException {
        return new Java8EngineSocket(sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(String hostname, int port,
            SSLParametersImpl sslParameters) throws IOException {
        return new Java8EngineSocket(hostname, port, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(InetAddress address, int port,
            SSLParametersImpl sslParameters) throws IOException {
        return new Java8EngineSocket(address, port, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(String hostname, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
        return new Java8EngineSocket(hostname, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(InetAddress address, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
        return new Java8EngineSocket(address, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(Socket socket, String hostname, int port,
            boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        return new Java8EngineSocket(socket, hostname, port, autoClose, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(SSLParametersImpl sslParameters)
            throws IOException {
        return new Java8FileDescriptorSocket(sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(String hostname, int port,
            SSLParametersImpl sslParameters) throws IOException {
        return new Java8FileDescriptorSocket(hostname, port, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(InetAddress address, int port,
            SSLParametersImpl sslParameters) throws IOException {
        return new Java8FileDescriptorSocket(address, port, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(String hostname, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
        return new Java8FileDescriptorSocket(
                hostname, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(InetAddress address, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
        return new Java8FileDescriptorSocket(
                address, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(Socket socket, String hostname,
            int port, boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        return new Java8FileDescriptorSocket(socket, hostname, port, autoClose, sslParameters);
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
        try {
            return AlgorithmId.get(oid).getName();
        } catch (NoSuchAlgorithmException e) {
            return oid;
        }
    }

    /**
     * Provides extended capabilities for the session if supported by the platform.
     */
    static SSLSession wrapSSLSession(ExternalSession sslSession) {
        return new Java8ExtendedSSLSession(sslSession);
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

    static String getHostStringFromInetSocketAddress(InetSocketAddress addr) {
        return addr.getHostString();
    }

    // The platform always has X509ExtendedTrustManager
    static boolean supportsX509ExtendedTrustManager() {
        return true;
    }

    static boolean isCTVerificationRequired(String hostname) {
        if (Flags.certificateTransparencyPlatform()) {
            return NetworkSecurityPolicy.getInstance()
                    .isCertificateTransparencyVerificationRequired(hostname);
        }
        return false;
    }

    static boolean supportsConscryptCertStore() {
        return true;
    }

    static KeyStore getDefaultCertKeyStore() throws KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance("AndroidCAStore");
        try {
            keyStore.load(null, null);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new KeyStoreException(e);
        }
        return keyStore;
    }

    static ConscryptCertStore newDefaultCertStore() {
        return new TrustedCertificateStore();
    }

    static CertBlocklist newDefaultBlocklist() {
        return CertBlocklistImpl.getDefault();
    }

    static LogStore newDefaultLogStore() {
        return new LogStoreImpl();
    }

    static Policy newDefaultPolicy() {
        return new PolicyImpl();
    }

    static boolean serverNamePermitted(SSLParametersImpl parameters, String serverName) {
        Collection<SNIMatcher> sniMatchers = parameters.getSNIMatchers();
        if (sniMatchers == null || sniMatchers.isEmpty()) {
            return true;
        }

        SNIHostName hostname = new SNIHostName(serverName);
        for (SNIMatcher m : sniMatchers) {
            boolean match = m.matches(hostname);
            if (match) {
                return true;
            }
        }
        return false;
    }

    public static ConscryptHostnameVerifier getDefaultHostnameVerifier() {
        return Conscrypt.wrapHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
    }

    /**
     * Returns milliseconds elapsed since boot, including time spent in sleep.
     * @return long number of milliseconds elapsed since boot
     */
    static long getMillisSinceBoot() {
        return System.currentTimeMillis();
    }

    public static StatsLog getStatsLog() {
        return StatsLogImpl.getInstance();
    }

    public static Source getStatsSource() {
        return Source.SOURCE_MAINLINE;
    }

    public static int[] getUids() {
        return new int[] {Os.getuid()};
    }

    public static boolean isJavaxCertificateSupported() {
        return true;
    }

    public static boolean isTlsV1Deprecated() {
        return true;
    }

    public static boolean isTlsV1Filtered() {
        Object targetSdkVersion = getTargetSdkVersion();
        if ((targetSdkVersion != null) && ((int) targetSdkVersion > 34))
            return false;
        return true;
    }

    public static boolean isTlsV1Supported() {
        return false;
    }

    static Object getTargetSdkVersion() {
        try {
            Class<?> vmRuntime = Class.forName("dalvik.system.VMRuntime");
            if (vmRuntime == null) {
                return null;
            }
            OptionalMethod getSdkVersion =
                    new OptionalMethod(vmRuntime,
                                        "getTargetSdkVersion");
            return getSdkVersion.invokeStatic();
        } catch (ClassNotFoundException e) {
            return null;
        } catch (NullPointerException e) {
            return null;
        }
    }
}
