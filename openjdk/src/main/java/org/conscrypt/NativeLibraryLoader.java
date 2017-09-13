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
 * Copyright 2014 The Netty Project
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

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.text.MessageFormat;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Helper class to load JNI resources.
 */
final class NativeLibraryLoader {
    private static final Logger logger = Logger.getLogger(NativeLibraryLoader.class.getName());

    private static final String WORK_DIR_PROPERTY_NAME = "org.conscrypt.native.workdir";
    private static final String TEMP_DIR_PROPERTY_NAME = "org.conscrypt.tmpdir";
    private static final String DELETE_LIB_PROPERTY_NAME =
            "org.conscrypt.native.deleteLibAfterLoading";
    private static final String NATIVE_RESOURCE_HOME = "META-INF/native/";
    private static final File WORKDIR;
    private static final boolean DELETE_NATIVE_LIB_AFTER_LOADING;

    static final OperatingSystem OS;
    static final Architecture ARCH;

    static {
        OS = getOperatingSystem(System.getProperty("os.name", ""));
        ARCH = getArchitecture(System.getProperty("os.arch", ""));

        File workdir = getWorkDir();
        if (workdir == null) {
            workdir = getTempDir();
        }
        WORKDIR = workdir;
        log("-D{0}: {1}", WORK_DIR_PROPERTY_NAME, WORKDIR);

        DELETE_NATIVE_LIB_AFTER_LOADING =
                Boolean.valueOf(System.getProperty(DELETE_LIB_PROPERTY_NAME, "true"));
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
    static boolean isWindows() {
        return OS == OperatingSystem.WINDOWS;
    }

    static boolean isOSX() {
        return OS == OperatingSystem.OSX;
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

    private static File getWorkDir() {
        String dirName = System.getProperty(WORK_DIR_PROPERTY_NAME);
        if (dirName == null) {
            // Application didn't specify a workdir.
            return null;
        }

        File f = new File(dirName);
        // Create the directory if it doesn't already exist.
        if (!f.mkdirs() && !f.exists()) {
            // Unable to create the directory.
            log("Unable to find or create working directory: {0}", dirName);
            return null;
        }

        try {
            f = f.getAbsoluteFile();
        } catch (Exception ignored) {
            // Good to have an absolute path, but it's OK.
        }
        return f;
    }

    /**
     * Loads the first available library in the collection with the specified
     * {@link ClassLoader}.
     */
    static boolean loadFirstAvailable(
            ClassLoader loader, List<LoadResult> results, String... names) {
        for (String name : names) {
            if (load(name, loader, results)) {
                // Successfully loaded
                return true;
            }
        }
        return false;
    }

    /**
     * A result of a single attempt to load a library.
     */
    static final class LoadResult {
        final String name;
        final boolean absolute;
        final boolean loaded;
        final boolean usingHelperClassloader;
        final Throwable error;

        private static LoadResult newSuccessResult(
                String name, boolean absolute, boolean usingHelperClassloader) {
            return new LoadResult(name, absolute, true, usingHelperClassloader, null);
        }

        private static LoadResult newFailureResult(
                String name, boolean absolute, boolean usingHelperClassloader, Throwable error) {
            return new LoadResult(name, absolute, false, usingHelperClassloader, error);
        }

        private LoadResult(String name, boolean absolute, boolean loaded,
                boolean usingHelperClassloader, Throwable error) {
            this.name = name;
            this.absolute = absolute;
            this.loaded = loaded;
            this.usingHelperClassloader = usingHelperClassloader;
            this.error = error;
        }

        void log() {
            if (error != null) {
                NativeLibraryLoader.log(
                        "Unable to load the library {0} (using helper classloader={1})", name,
                        usingHelperClassloader, error);
            } else {
                NativeLibraryLoader.log(
                        "Successfully loaded library {0}  (using helper classloader={1})", name,
                        usingHelperClassloader);
            }
        }
    }

    /**
     * Load the given library with the specified {@link ClassLoader}
     */
    private static boolean load(String name, ClassLoader loader, List<LoadResult> results) {
        // Try loading from the fully-qualified classpath resource first. Otherwise just try
        // loading the non-absolute library name directly.
        return loadFromWorkdir(name, loader, results) || loadLibrary(loader, name, false, results);
    }

    private static boolean loadFromWorkdir(
            String name, ClassLoader loader, List<LoadResult> results) {
        String libname = System.mapLibraryName(name);
        String path = NATIVE_RESOURCE_HOME + libname;

        URL url = loader.getResource(path);
        if (url == null && isOSX()) {
            if (path.endsWith(".jnilib")) {
                url = loader.getResource(NATIVE_RESOURCE_HOME + "lib" + name + ".dynlib");
            } else {
                url = loader.getResource(NATIVE_RESOURCE_HOME + "lib" + name + ".jnilib");
            }
        }

        if (url == null) {
            return false;
        }

        int index = libname.lastIndexOf('.');
        String prefix = libname.substring(0, index);
        String suffix = libname.substring(index, libname.length());
        File tmpFile = null;
        try {
            // Create a temporary file.
            tmpFile = Platform.createTempFile(prefix, suffix, WORKDIR);
            if (tmpFile.isFile() && tmpFile.canRead() && !Platform.canExecuteExecutable(tmpFile)) {
                throw new IOException(MessageFormat.format("{0} exists but cannot be executed even "
                                + "when execute permissions set; check volume for "
                                + "\"noexec\" flag; use -D{1}=[path] to set native "
                                + "working directory separately.",
                        tmpFile.getPath(), WORK_DIR_PROPERTY_NAME));
            }

            // Copy the library from classpath to tmpFile
            copyLibrary(url, tmpFile);

            return loadLibrary(loader, tmpFile.getPath(), true, results);
        } catch (IOException e) {
            // Convert to an UnsatisfiedLinkError.
            Throwable error = new UnsatisfiedLinkError(
                    MessageFormat.format("Failed creating temp file ({0})",
                            tmpFile)).initCause(e);
            results.add(LoadResult.newFailureResult(name, true, false, error));
            return false;
        } finally {
            // After we load the library it is safe to delete the file.
            // We delete the file immediately to free up resources as soon as possible,
            // and if this fails fallback to deleting on JVM exit.
            if (tmpFile != null) {
                boolean deleted = false;
                if (DELETE_NATIVE_LIB_AFTER_LOADING) {
                    deleted = tmpFile.delete();
                }
                if (!deleted) {
                    tmpFile.deleteOnExit();
                }
            }
        }
    }

    /**
     * Copies the given shared library file from classpath to a temporary file.
     *
     * @param classpathUrl the URL of the library on classpath
     * @param tmpFile the destination temporary file.
     */
    private static void copyLibrary(URL classpathUrl, File tmpFile) throws IOException {
        InputStream in = null;
        OutputStream out = null;
        try {
            in = classpathUrl.openStream();
            out = new FileOutputStream(tmpFile);

            byte[] buffer = new byte[8192];
            int length;
            while ((length = in.read(buffer)) > 0) {
                out.write(buffer, 0, length);
            }
            out.flush();
        } finally {
            closeQuietly(in);
            closeQuietly(out);
        }
    }

    /**
     * Loading the native library into the specified {@link ClassLoader}.
     * @param loader - The {@link ClassLoader} where the native library will be loaded into
     * @param name - The native library path or name
     * @param absolute - Whether the native library will be loaded by path or by name
     * @return {@code true} if the library was successfully loaded.
     */
    private static boolean loadLibrary(final ClassLoader loader, final String name,
            final boolean absolute, List<LoadResult> results) {
        try {
            // Make sure the helper belongs to the target ClassLoader.
            final Class<?> newHelper = tryToLoadClass(loader, NativeLibraryUtil.class);
            LoadResult result = loadLibraryFromHelperClassloader(newHelper, name, absolute);
            results.add(result);
            if (result.loaded) {
                // Successfully loaded the library.
                return true;
            }
        } catch (Exception ignore) {
            // Failed loading the helper in the provided classloader - ignore.
        }

        // Fallback to loading from the local classloader.
        LoadResult result = loadLibraryFromCurrentClassloader(name, absolute);
        results.add(result);
        return result.loaded;
    }

    /**
     * Attempts to load the library by reflectively using the {@link NativeLibraryUtil} helper
     * from its classloader.
     *
     * @param helper The {@link NativeLibraryUtil} helper class
     * @param name the name of the library to load.
     * @param absolute true if {@code name} is an absolute path to the file.
     * @return the result of the load operation.
     */
    private static LoadResult loadLibraryFromHelperClassloader(
            final Class<?> helper, final String name, final boolean absolute) {
        return AccessController.doPrivileged(new PrivilegedAction<LoadResult>() {
            @Override
            public LoadResult run() {
                try {
                    // Invoke the helper to load the native library, if succeed, then the native
                    // library belongs to the specified ClassLoader.
                    Method method = helper.getMethod("loadLibrary", String.class, boolean.class);
                    method.setAccessible(true);
                    method.invoke(null, name, absolute);
                    return LoadResult.newSuccessResult(name, absolute, true);
                } catch (InvocationTargetException e) {
                    return LoadResult.newFailureResult(name, absolute, true, e.getCause());
                } catch (Throwable e) {
                    return LoadResult.newFailureResult(name, absolute, true, e);
                }
            }
        });
    }

    /**
     * Attempts to load the library using the {@link NativeLibraryUtil} helper from the current
     * classloader.
     *
     * @param name the name of the library to load.
     * @param absolute true if {@code name} is an absolute path
     * @return the result of the load operation.
     */
    private static LoadResult loadLibraryFromCurrentClassloader(String name, boolean absolute) {
        try {
            NativeLibraryUtil.loadLibrary(name, absolute);
            return LoadResult.newSuccessResult(name, absolute, false);
        } catch (Throwable e) {
            return LoadResult.newFailureResult(name, absolute, false, e);
        }
    }

    /**
     * Try to load the helper {@link Class} into specified {@link ClassLoader}.
     * @param loader - The {@link ClassLoader} where to load the helper {@link Class}
     * @param helper - The helper {@link Class}
     * @return A new helper Class defined in the specified ClassLoader.
     * @throws ClassNotFoundException Helper class not found or loading failed
     */
    private static Class<?> tryToLoadClass(final ClassLoader loader, final Class<?> helper)
            throws ClassNotFoundException {
        try {
            return loader.loadClass(helper.getName());
        } catch (ClassNotFoundException e) {
            // The helper class is NOT found in target ClassLoader, we have to define the helper
            // class.
            final byte[] classBinary = classToByteArray(helper);
            return AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
                @Override
                public Class<?> run() {
                    try {
                        // Define the helper class in the target ClassLoader,
                        //  then we can call the helper to load the native library.
                        Method defineClass = ClassLoader.class.getDeclaredMethod(
                                "defineClass", String.class, byte[].class, int.class, int.class);
                        defineClass.setAccessible(true);
                        return (Class<?>) defineClass.invoke(
                                loader, helper.getName(), classBinary, 0, classBinary.length);
                    } catch (Exception e) {
                        throw new IllegalStateException("Define class failed!", e);
                    }
                }
            });
        }
    }

    /**
     * Load the helper {@link Class} as a byte array, to be redefined in specified {@link
     * ClassLoader}.
     * @param clazz - The helper {@link Class} provided by this bundle
     * @return The binary content of helper {@link Class}.
     * @throws ClassNotFoundException Helper class not found or loading failed
     */
    private static byte[] classToByteArray(Class<?> clazz) throws ClassNotFoundException {
        String fileName = clazz.getName();
        int lastDot = fileName.lastIndexOf('.');
        if (lastDot > 0) {
            fileName = fileName.substring(lastDot + 1);
        }
        URL classUrl = clazz.getResource(fileName + ".class");
        if (classUrl == null) {
            throw new ClassNotFoundException(clazz.getName());
        }
        byte[] buf = new byte[1024];
        ByteArrayOutputStream out = new ByteArrayOutputStream(4096);
        InputStream in = null;
        try {
            in = classUrl.openStream();
            for (int r; (r = in.read(buf)) != -1;) {
                out.write(buf, 0, r);
            }
            return out.toByteArray();
        } catch (IOException ex) {
            throw new ClassNotFoundException(clazz.getName(), ex);
        } finally {
            closeQuietly(in);
            closeQuietly(out);
        }
    }

    private static void closeQuietly(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (IOException ignore) {
                // ignore
            }
        }
    }

    private NativeLibraryLoader() {
        // Utility
    }

    private static void log(String format, Object arg) {
        logger.log(Level.FINE, format, arg);
    }

    private static void log(String format, Object arg1, Object arg2) {
        logger.log(Level.FINE, format, new Object[] {arg1, arg2});
    }

    private static void log(String format, Object arg1, Object arg2, Throwable t) {
        debug(MessageFormat.format(format, arg1, arg2), t);
    }

    private static void debug(String message, Throwable t) {
        logger.log(Level.FINE, message, t);
    }

    private static String normalize(String value) {
        return value.toLowerCase(Locale.US).replaceAll("[^a-z0-9]+", "");
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
}
