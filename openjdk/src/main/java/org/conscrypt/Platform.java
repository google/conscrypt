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

import static java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;

import org.conscrypt.ct.LogStore;
import org.conscrypt.ct.Policy;
import org.conscrypt.metrics.Source;
import org.conscrypt.metrics.StatsLog;

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
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import org.conscrypt.NativeCrypto;

/**
 * Platform-specific methods for OpenJDK.
 *
 * Uses reflection to implement Java 8 SSL features for backwards compatibility.
 */
@Internal
final public class Platform {
    private static final int JAVA_VERSION = javaVersion0();
    private static final Method GET_CURVE_NAME_METHOD;
    static boolean DEPRECATED_TLS_V1 = true;
    static boolean ENABLED_TLS_V1 = false;
    private static boolean FILTERED_TLS_V1 = true;

    static {
        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
        Method getCurveNameMethod = null;
        try {
            getCurveNameMethod = ECParameterSpec.class.getDeclaredMethod("getCurveName");
            getCurveNameMethod.setAccessible(true);
        } catch (Exception ignored) {
            // Method not available, leave it as null, which is checked before use
        }
        GET_CURVE_NAME_METHOD = getCurveNameMethod;
    }

    private Platform() {}

    public static void setup(boolean deprecatedTlsV1, boolean enabledTlsV1) {
        DEPRECATED_TLS_V1 = deprecatedTlsV1;
        ENABLED_TLS_V1 = enabledTlsV1;
        FILTERED_TLS_V1 = !enabledTlsV1;
        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
    }


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
            String tempName = String.format(Locale.ROOT, "%s%d%04d%s", prefix, time, i, suffix);
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

    static boolean provideTrustManagerByDefault() {
        return true;
    }

    static boolean canExecuteExecutable(File file) throws IOException {
        // If we can already execute, there is nothing to do.
        if (file.canExecute()) {
            return true;
        }

        // On volumes, with noexec set, even files with the executable POSIX permissions will
        // fail to execute. The File#canExecute() method honors this behavior, probably via
        // parsing the noexec flag when initializing the UnixFileStore, though the flag is not
        // exposed via a public API.  To find out if library is being loaded off a volume with
        // noexec, confirm or add executable permissions, then check File#canExecute().

        Set<PosixFilePermission> existingFilePermissions =
                Files.getPosixFilePermissions(file.toPath());
        Set<PosixFilePermission> executePermissions =
                EnumSet.of(OWNER_EXECUTE, GROUP_EXECUTE, OTHERS_EXECUTE);
        if (existingFilePermissions.containsAll(executePermissions)) {
            return false;
        }

        Set<PosixFilePermission> newPermissions = EnumSet.copyOf(existingFilePermissions);
        newPermissions.addAll(executePermissions);
        Files.setPosixFilePermissions(file.toPath(), newPermissions);
        return file.canExecute();
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
            Method m_getImpl = Socket.class.getDeclaredMethod("getImpl");
            m_getImpl.setAccessible(true);
            Object socketImpl = m_getImpl.invoke(s);
            try {
                Class<?> c_delegatingSocketImpl = Class.forName("java.net.DelegatingSocketImpl");
                if (c_delegatingSocketImpl.isAssignableFrom(socketImpl.getClass())) {
                    Method m_delegate = c_delegatingSocketImpl.getDeclaredMethod("delegate");
                    m_delegate.setAccessible(true);
                    socketImpl = m_delegate.invoke(socketImpl);
                }
            } catch (Exception ignored) {
                // Ignored
            }
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
        } else {
            impl.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        }
    }

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        if (JAVA_VERSION >= 9) {
            Java9PlatformUtil.getSSLParameters(params, impl, socket);
        } else if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.getSSLParameters(params, impl, socket);
        } else {
            params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        }
    }

    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        if (JAVA_VERSION >= 9) {
            Java9PlatformUtil.setSSLParameters(params, impl, engine);
        } else if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.setSSLParameters(params, impl, engine);
        } else {
            impl.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        }
    }

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        if (JAVA_VERSION >= 9) {
            Java9PlatformUtil.getSSLParameters(params, impl, engine);
        } else if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.getSSLParameters(params, impl, engine);
        } else {
            params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
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
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkClientTrusted(chain, authType, socket);
        } else {
            tm.checkClientTrusted(chain, authType);
        }
    }

    @SuppressWarnings("unused")
    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            AbstractConscryptSocket socket) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkServerTrusted(chain, authType, socket);
        } else {
            tm.checkServerTrusted(chain, authType);
        }
    }

    @SuppressWarnings("unused")
    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            ConscryptEngine engine) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkClientTrusted(chain, authType, engine);
        } else {
            tm.checkClientTrusted(chain, authType);
        }
    }

    @SuppressWarnings("unused")
    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            ConscryptEngine engine) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkServerTrusted(chain, authType, engine);
        } else {
            tm.checkServerTrusted(chain, authType);
        }
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

    /*
     * Pre-Java-8 backward compatibility.
     */

    @SuppressWarnings("unused")
    static SSLSession wrapSSLSession(ExternalSession sslSession) {
        if (JAVA_VERSION >= 8) {
            return Java8PlatformUtil.wrapSSLSession(sslSession);
        }
        return new Java7ExtendedSSLSession(sslSession);
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
        } catch (ClassNotFoundException | IllegalAccessException | NoSuchMethodException ignored) {
            // passthrough and return addr.getHostAddress()
        } catch (Exception maybeIgnored) {
            if (!maybeIgnored.getClass().getSimpleName().equals("InaccessibleObjectException")) {
                throw new RuntimeException("Failed to get originalHostName", maybeIgnored);
            }
            // Java versions which prevent reflection to get the original hostname.
            // Ugly workaround is parse it from toString(), which uses holder.hostname rather
            // than holder.originalHostName.  But in Java versions up to 21 at least and in the way
            // used by Conscrypt, hostname always equals originalHostname.
            String representation = addr.toString();
            int slash = representation.indexOf('/');
            if (slash != -1) {
                return representation.substring(0, slash);
            }
            // Give up and return the IP
        }

        return addr.getHostAddress();
    }

    @SuppressWarnings("unused")
    static String getHostStringFromInetSocketAddress(InetSocketAddress addr) {
        return addr.getHostString();
    }

    // OpenJDK always has X509ExtendedTrustManager
    static boolean supportsX509ExtendedTrustManager() {
        return true;
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
        if (property == null || !Boolean.parseBoolean(property.toLowerCase(Locale.ROOT))) {
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
                enable = Boolean.parseBoolean(property.toLowerCase(Locale.ROOT));
            }
            propertyName.append(".").append(part);
        }

        property = Security.getProperty(propertyName.toString());
        if (property != null) {
            enable = Boolean.parseBoolean(property.toLowerCase(Locale.ROOT));
        }
        return enable;
    }

    static boolean supportsConscryptCertStore() {
        return false;
    }

    static KeyStore getDefaultCertKeyStore() throws KeyStoreException {
        // Start with an empty KeyStore.  In the worst case, we'll end up returning it.
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            ks.load(null, null);
        } catch (NoSuchAlgorithmException ignored) {
            // TODO(prb): Should this be re-thrown? It happens if "the algorithm used to check
            // the integrity of the KeyStore cannot be found".
        } catch (IOException | CertificateException ignored) {
            // We're not loading anything, so ignore it
        }
        // Find the highest-priority non-Conscrypt provider that provides a PKIX
        // TrustManagerFactory implementation and ask it for its trusted CAs.  This is most
        // likely the OpenJDK-provided provider, in which case the platform default properties
        // for configuring CA certs will be used, but we'll accept any provider that can give
        // us at least one cert.
        Provider[] providers = Security.getProviders("TrustManagerFactory.PKIX");
        for (Provider p : providers) {
            if (Conscrypt.isConscrypt(p)) {
                // We need to skip any Conscrypt provider we find because this method is called
                // when we're trying to determine the default set of CA certs for one of our
                // TrustManagers, so trying to construct a TrustManager from this provider
                // would result in calling this method again and recursing infinitely.
                continue;
            }
            try {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", p);
                tmf.init((KeyStore) null);
                TrustManager[] tms = tmf.getTrustManagers();
                if (tms.length > 0) {
                    // Aliases are irrelevant for our purposes, so just number the certs
                    int certNum = 1;
                    for (TrustManager tm : tms) {
                        if (tm instanceof X509TrustManager) {
                            X509TrustManager xtm = (X509TrustManager) tm;
                            for (X509Certificate cert : xtm.getAcceptedIssuers()) {
                                ks.setCertificateEntry(Integer.toString(certNum++), cert);
                            }
                        }
                    }
                    if (certNum > 1) {
                        // We've loaded at least one certificate, so we're done.
                        break;
                    }
                }
            } catch (NoSuchAlgorithmException ignored) {
                // This TrustManagerFactory didn't work, try another one
            }
        }
        return ks;
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
        if (JAVA_VERSION >= 8) {
            return Java8PlatformUtil.serverNamePermitted(parameters, serverName);
        }
        return true;
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
        final String[] components = javaSpecVersion.split("\\.", -1);
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

    public static ConscryptHostnameVerifier getDefaultHostnameVerifier() {
        return  OkHostnameVerifier.strictInstance();
    }

    @SuppressWarnings("unused")
    static long getMillisSinceBoot() {
        return 0;
    }

    public static StatsLog getStatsLog() {
        return null;
    }

    @SuppressWarnings("unused")
    public static Source getStatsSource() {
        return null;
    }

    @SuppressWarnings("unused")
    public static int[] getUids() {
        return null;
    }

    public static boolean isJavaxCertificateSupported() {
        return JAVA_VERSION < 15;
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
