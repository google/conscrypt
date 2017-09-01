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
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;
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
    private static final Logger logger = Logger.getLogger(Platform.class.getName());

    private static final int JAVA_VERSION = javaVersion0();
    private static final String TEMP_DIR_PROPERTY_NAME = "org.conscrypt.tmpdir";
    private static final Method GET_CURVE_NAME_METHOD;

    static final OperatingSystem OS;
    static final Architecture ARCH;

    static {
        OS = getOperatingSystem(System.getProperty("os.name", ""));
        ARCH = getArchitecture(System.getProperty("os.arch", ""));

        Method getCurveNameMethod = null;
        try {
            getCurveNameMethod = ECParameterSpec.class.getDeclaredMethod("getCurveName");
            getCurveNameMethod.setAccessible(true);
        } catch (Exception ignored) {
        }
        GET_CURVE_NAME_METHOD = getCurveNameMethod;
    }

    /**
     * Enumeration of operating systems.
     */
    enum OperatingSystem {
        AIX,
        HPUX,
        OS400,
        LINUX,
        OSX,
        FREEBSD,
        OPENBSD,
        NETBSD,
        SUNOS,
        WINDOWS,
        UNKNOWN
    }

    /**
     * Enumeration of architectures.
     */
    enum Architecture {
        X86_64,
        X86_32,
        ITANIUM_64,
        SPARC_32,
        SPARC_64,
        ARM_32,
        AARCH_64,
        PPC_32,
        PPC_64,
        PPCLE_64,
        S390_32,
        S390_64,
        UNKNOWN
    }

    private Platform() {}

    static void setup() {}

    static boolean isWindows() {
        return Platform.OS == OperatingSystem.WINDOWS;
    }

    static boolean isOSX() {
        return Platform.OS == OperatingSystem.OSX;
    }

    static File getTempDir() {
        File f;
        try {
            // First, see if the application specified a temp dir for conscrypt.
            f = toDirectory(System.getProperty(TEMP_DIR_PROPERTY_NAME));
            if (f != null) {
                return f;
            }

            // Use the Java system property if available.
            f = toDirectory(System.getProperty("java.io.tmpdir"));
            if (f != null) {
                return f;
            }

            // This shouldn't happen, but just in case ..
            if (isWindows()) {
                f = toDirectory(System.getenv("TEMP"));
                if (f != null) {
                    return f;
                }

                String userprofile = System.getenv("USERPROFILE");
                if (userprofile != null) {
                    f = toDirectory(userprofile + "\\AppData\\Local\\Temp");
                    if (f != null) {
                        return f;
                    }

                    f = toDirectory(userprofile + "\\Local Settings\\Temp");
                    if (f != null) {
                        return f;
                    }
                }
            } else {
                f = toDirectory(System.getenv("TMPDIR"));
                if (f != null) {
                    return f;
                }
            }
        } catch (Exception ignored) {
            // Environment variable inaccessible
        }

        // Last resort.
        if (isWindows()) {
            f = new File("C:\\Windows\\Temp");
        } else {
            f = new File("/tmp");
        }

        logger.log(Level.WARNING,
            "Failed to get the temporary directory; falling back to: {0}", f);
        return f;
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

    @SuppressWarnings("ResultOfMethodCallIgnored")
    private static File toDirectory(String path) {
        if (path == null) {
            return null;
        }

        File f = new File(path);
        f.mkdirs();

        if (!f.isDirectory()) {
            return null;
        }

        try {
            return f.getAbsoluteFile();
        } catch (Exception ignored) {
            return f;
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
        if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.setSSLParameters(params, impl, socket);
        } else if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.setSSLParameters(params, impl);
        }
    }

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.getSSLParameters(params, impl, socket);
        } else if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.getSSLParameters(params, impl);
        }
    }

    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.setSSLParameters(params, impl, engine);
        } else if (JAVA_VERSION >= 7) {
            Java7PlatformUtil.setSSLParameters(params, impl);
        }
    }

    static void getSSLParameters(
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

    /**
     * Normalizes the os.name value into the value used by the Maven os plugin
     * (https://github.com/trustin/os-maven-plugin). This plugin is used to generate
     * platform-specific
     * classifiers for artifacts.
     */
    private static OperatingSystem getOperatingSystem(String value) {
        value = normalize(value);
        if (value.startsWith("aix")) {
            return OperatingSystem.AIX;
        }
        if (value.startsWith("hpux")) {
            return OperatingSystem.HPUX;
        }
        if (value.startsWith("os400")) {
            // Avoid the names such as os4000
            if (value.length() <= 5 || !Character.isDigit(value.charAt(5))) {
                return OperatingSystem.OS400;
            }
        }
        if (value.startsWith("linux")) {
            return OperatingSystem.LINUX;
        }
        if (value.startsWith("macosx") || value.startsWith("osx")) {
            return OperatingSystem.OSX;
        }
        if (value.startsWith("freebsd")) {
            return OperatingSystem.FREEBSD;
        }
        if (value.startsWith("openbsd")) {
            return OperatingSystem.OPENBSD;
        }
        if (value.startsWith("netbsd")) {
            return OperatingSystem.NETBSD;
        }
        if (value.startsWith("solaris") || value.startsWith("sunos")) {
            return OperatingSystem.SUNOS;
        }
        if (value.startsWith("windows")) {
            return OperatingSystem.WINDOWS;
        }

        return OperatingSystem.UNKNOWN;
    }

    /**
     * Normalizes the os.arch value into the value used by the Maven os plugin
     * (https://github.com/trustin/os-maven-plugin). This plugin is used to generate
     * platform-specific
     * classifiers for artifacts.
     */
    private static Architecture getArchitecture(String value) {
        value = normalize(value);
        if (value.matches("^(x8664|amd64|ia32e|em64t|x64)$")) {
            return Architecture.X86_64;
        }
        if (value.matches("^(x8632|x86|i[3-6]86|ia32|x32)$")) {
            return Architecture.X86_32;
        }
        if (value.matches("^(ia64|itanium64)$")) {
            return Architecture.ITANIUM_64;
        }
        if (value.matches("^(sparc|sparc32)$")) {
            return Architecture.SPARC_32;
        }
        if (value.matches("^(sparcv9|sparc64)$")) {
            return Architecture.SPARC_64;
        }
        if (value.matches("^(arm|arm32)$")) {
            return Architecture.ARM_32;
        }
        if ("aarch64".equals(value)) {
            return Architecture.AARCH_64;
        }
        if (value.matches("^(ppc|ppc32)$")) {
            return Architecture.PPC_32;
        }
        if ("ppc64".equals(value)) {
            return Architecture.PPC_64;
        }
        if ("ppc64le".equals(value)) {
            return Architecture.PPCLE_64;
        }
        if ("s390".equals(value)) {
            return Architecture.S390_32;
        }
        if ("s390x".equals(value)) {
            return Architecture.S390_64;
        }

        return Architecture.UNKNOWN;
    }

    private static String normalize(String value) {
        return value.toLowerCase(Locale.US).replaceAll("[^a-z0-9]+", "");
    }
}
