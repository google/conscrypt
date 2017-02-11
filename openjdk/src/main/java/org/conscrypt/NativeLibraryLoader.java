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
import java.lang.reflect.Method;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.Locale;

/**
 * Helper class to load JNI resources.
 *
 */
final class NativeLibraryLoader {
    private static final String NATIVE_RESOURCE_HOME = "META-INF/native/";
    private static final String OSNAME;
    private static final File WORKDIR;

    static {
        OSNAME = System.getProperty("os.name", "")
                         .toLowerCase(Locale.US)
                         .replaceAll("[^a-z0-9]+", "");

        String workdir = System.getProperty("org.conscrypt.native.workdir");
        if (workdir != null) {
            File f = new File(workdir);
            f.mkdirs();

            try {
                f = f.getAbsoluteFile();
            } catch (Exception ignored) {
                // Good to have an absolute path, but it's OK.
            }

            WORKDIR = f;
        } else {
            WORKDIR = tmpdir();
        }
    }

    private static File tmpdir() {
        File f;
        try {
            f = toDirectory(System.getProperty("org.conscrypt.tmpdir"));
            if (f != null) {
                return f;
            }

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

    private static boolean isWindows() {
        return OSNAME.startsWith("windows");
    }

    private static boolean isOSX() {
        return OSNAME.startsWith("macosx") || OSNAME.startsWith("osx");
    }

    /**
     * Loads the first available library in the collection with the specified
     * {@link ClassLoader}.
     *
     * @throws IllegalArgumentException
     *         if none of the given libraries load successfully.
     */
    static void loadFirstAvailable(ClassLoader loader, String... names) {
        for (String name : names) {
            try {
                load(name, loader);
                return;
            } catch (Throwable t) {
                // Do nothing.
            }
        }
        throw new IllegalArgumentException(
                "Failed to load any of the given libraries: " + Arrays.toString(names));
    }

    /**
     * Load the given library with the specified {@link ClassLoader}
     */
    private static void load(String name, ClassLoader loader) {
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
            // Fall back to normal loading of JNI stuff
            loadLibrary(loader, name, false);
            return;
        }

        int index = libname.lastIndexOf('.');
        String prefix = libname.substring(0, index);
        String suffix = libname.substring(index, libname.length());
        InputStream in = null;
        OutputStream out = null;
        File tmpFile = null;
        try {
            tmpFile = createTempFile(prefix, suffix, WORKDIR);
            in = url.openStream();
            out = new FileOutputStream(tmpFile);

            byte[] buffer = new byte[8192];
            int length;
            while ((length = in.read(buffer)) > 0) {
                out.write(buffer, 0, length);
            }
            out.flush();

            // Close the output stream before loading the unpacked library,
            // because otherwise Windows will refuse to load it when it's in use by other process.
            closeQuietly(out);
            out = null;

            loadLibrary(loader, tmpFile.getPath(), true);
        } catch (Exception e) {
            throw(UnsatisfiedLinkError) new UnsatisfiedLinkError(
                    "could not load a native library: " + name)
                    .initCause(e);
        } finally {
            closeQuietly(in);
            closeQuietly(out);
            // After we load the library it is safe to delete the file.
            // We delete the file immediately to free up resources as soon as possible,
            // and if this fails fallback to deleting on JVM exit.
            if (tmpFile != null && !tmpFile.delete()) {
                tmpFile.deleteOnExit();
            }
        }
    }

    /**
     * Loading the native library into the specified {@link ClassLoader}.
     * @param loader - The {@link ClassLoader} where the native library will be loaded into
     * @param name - The native library path or name
     * @param absolute - Whether the native library will be loaded by path or by name
     */
    private static void loadLibrary(
            final ClassLoader loader, final String name, final boolean absolute) {
        try {
            // Make sure the helper is belong to the target ClassLoader.
            final Class<?> newHelper = tryToLoadClass(loader, NativeLibraryUtil.class);
            loadLibraryByHelper(newHelper, name, absolute);
            return;
        } catch (UnsatisfiedLinkError e) { // Should by pass the UnsatisfiedLinkError here!
            // Do nothing.
        } catch (Exception e) {
            // Do nothing.
        }
        NativeLibraryUtil.loadLibrary(name, absolute); // Fallback to local helper class.
    }

    private static void loadLibraryByHelper(final Class<?> helper, final String name,
            final boolean absolute) throws UnsatisfiedLinkError {
        Object ret = AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                try {
                    // Invoke the helper to load the native library, if succeed, then the native
                    // library belong to the specified ClassLoader.
                    Method method = helper.getMethod("loadLibrary", String.class, boolean.class);
                    method.setAccessible(true);
                    return method.invoke(null, name, absolute);
                } catch (Exception e) {
                    return e;
                }
            }
        });
        if (ret instanceof Throwable) {
            Throwable error = (Throwable) ret;
            Throwable cause = error.getCause();
            if (cause != null) {
                if (cause instanceof UnsatisfiedLinkError) {
                    throw(UnsatisfiedLinkError) cause;
                } else {
                    throw new UnsatisfiedLinkError(cause.getMessage());
                }
            }
            throw new UnsatisfiedLinkError(error.getMessage());
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

    // Approximates the behavior of File.createTempFile without depending on SecureRandom.
    private static File createTempFile(String prefix, String suffix, File directory)
            throws IOException {
        if (directory == null) {
            throw new NullPointerException();
        }
        long time = System.currentTimeMillis();
        prefix = new File(prefix).getName();
        IOException suppressed = null;
        for (int i = 0; i < 10000; i++) {
            String tempName = String.format("%s%d%04d%s", prefix, time, i, suffix);
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

    private NativeLibraryLoader() {
        // Utility
    }
}
