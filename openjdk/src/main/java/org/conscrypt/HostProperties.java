/*
 * Copyright 2017 The Android Open Source Project
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
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Utilities for interacting with properties of the host being run on.
 */
@Internal
class HostProperties {
    private static final Logger logger = Logger.getLogger(HostProperties.class.getName());

    private static final String TEMP_DIR_PROPERTY_NAME = "org.conscrypt.tmpdir";

    static final OperatingSystem OS;
    static final Architecture ARCH;

    static {
        OS = getOperatingSystem(System.getProperty("os.name", ""));
        ARCH = getArchitecture(System.getProperty("os.arch", ""));
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
        UNKNOWN;

        /**
         * Returns the value to use when building filenames for this OS.
         */
        public String getFileComponent() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /**
     * Enumeration of architectures.
     */
    enum Architecture {
        X86_64,
        X86_32 {
            @Override public String getFileComponent() {
                return "x86";
            }
        },
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
        UNKNOWN;

        /**
         * Returns the value to use when building filenames for this architecture.
         */
        public String getFileComponent() {
            return name().toLowerCase(Locale.ROOT);
        }
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

    private static String normalize(String value) {
        return value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "");
    }

    /*
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

    /*
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

    private HostProperties() {}

}
