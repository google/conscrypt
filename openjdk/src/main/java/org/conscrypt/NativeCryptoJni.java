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

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Helper to initialize the JNI libraries. This version runs when compiled as part of a host OpenJDK
 * build.
 */
final class NativeCryptoJni {
    private static final String LIB_NAME = "conscrypt_openjdk_jni";
    private static final String UNKNOWN = "unknown";
    private static final String LINUX = "linux";

    public static void init() {
        String os = normalizeOs(System.getProperty("os.name", ""));
        String arch = normalizeArch(System.getProperty("os.arch", ""));

        Set<String> libNames = new LinkedHashSet<String>(3);
        // First, try loading the platform-specific library. Platform-specific
        // libraries will be available if using a tcnative uber jar.
        libNames.add(LIB_NAME + "-" + os + '-' + arch);
        if (LINUX.equalsIgnoreCase(os)) {
            // Fedora SSL lib so naming (libssl.so.10 vs libssl.so.1.0.0).
            // Note: This is only needed if the jni lib is dynamically linked to OpenSSL.
            // BoringSSL does not have this problem since it's always statically linked.
            libNames.add(LIB_NAME + "-" + os + '-' + arch + "-fedora");
        }
        // finally the default library.
        libNames.add(LIB_NAME);

        NativeLibraryLoader.loadFirstAvailable(
                NativeCrypto.class.getClassLoader(), libNames.toArray(new String[libNames.size()]));
    }

    private NativeCryptoJni() {}

    /**
     * Normalizes the os.name value into the value used by the Maven os plugin
     * (https://github.com/trustin/os-maven-plugin). This plugin is used to generate
     * platform-specific
     * classifiers for artifacts.
     */
    private static String normalizeOs(String value) {
        value = normalize(value);
        if (value.startsWith("aix")) {
            return "aix";
        }
        if (value.startsWith("hpux")) {
            return "hpux";
        }
        if (value.startsWith("os400")) {
            // Avoid the names such as os4000
            if (value.length() <= 5 || !Character.isDigit(value.charAt(5))) {
                return "os400";
            }
        }
        if (value.startsWith(LINUX)) {
            return LINUX;
        }
        if (value.startsWith("macosx") || value.startsWith("osx")) {
            return "osx";
        }
        if (value.startsWith("freebsd")) {
            return "freebsd";
        }
        if (value.startsWith("openbsd")) {
            return "openbsd";
        }
        if (value.startsWith("netbsd")) {
            return "netbsd";
        }
        if (value.startsWith("solaris") || value.startsWith("sunos")) {
            return "sunos";
        }
        if (value.startsWith("windows")) {
            return "windows";
        }

        return UNKNOWN;
    }

    /**
     * Normalizes the os.arch value into the value used by the Maven os plugin
     * (https://github.com/trustin/os-maven-plugin). This plugin is used to generate
     * platform-specific
     * classifiers for artifacts.
     */
    private static String normalizeArch(String value) {
        value = normalize(value);
        if (value.matches("^(x8664|amd64|ia32e|em64t|x64)$")) {
            return "x86_64";
        }
        if (value.matches("^(x8632|x86|i[3-6]86|ia32|x32)$")) {
            return "x86_32";
        }
        if (value.matches("^(ia64|itanium64)$")) {
            return "itanium_64";
        }
        if (value.matches("^(sparc|sparc32)$")) {
            return "sparc_32";
        }
        if (value.matches("^(sparcv9|sparc64)$")) {
            return "sparc_64";
        }
        if (value.matches("^(arm|arm32)$")) {
            return "arm_32";
        }
        if ("aarch64".equals(value)) {
            return "aarch_64";
        }
        if (value.matches("^(ppc|ppc32)$")) {
            return "ppc_32";
        }
        if ("ppc64".equals(value)) {
            return "ppc_64";
        }
        if ("ppc64le".equals(value)) {
            return "ppcle_64";
        }
        if ("s390".equals(value)) {
            return "s390_32";
        }
        if ("s390x".equals(value)) {
            return "s390_64";
        }

        return UNKNOWN;
    }

    private static String normalize(String value) {
        return value.toLowerCase(Locale.US).replaceAll("[^a-z0-9]+", "");
    }
}
