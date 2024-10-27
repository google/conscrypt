/*
 * Copyright 2016 The Android Open Source Project
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

package org.conscrypt.java.security;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CpuFeatures {
    private CpuFeatures() {}

    public static boolean isAESHardwareAccelerated() {
        List<String> features = getListFromCpuinfo("Features");
        if (features != null && features.contains("aes")) {
            return true;
        }

        List<String> flags = getListFromCpuinfo("flags");
        if (flags != null && flags.contains("aes")) {
            return true;
        }

        features = getCpuFeaturesMac();
        if (features != null && features.contains("aes")) {
            return true;
        }

        // If we're in an emulated ABI, Conscrypt's NativeCrypto might bridge to
        // a library that has accelerated AES instructions. See if Conscrypt
        // detects that condition.
        Class<?> nativeCrypto = findNativeCrypto();
        if (nativeCrypto != null) {
            try {
                Method EVP_has_aes_hardware =
                        nativeCrypto.getDeclaredMethod("EVP_has_aes_hardware");
                EVP_has_aes_hardware.setAccessible(true);
                return ((Integer) EVP_has_aes_hardware.invoke(null)) == 1;
            } catch (NoSuchMethodException | IllegalArgumentException | IllegalAccessException |
                     SecurityException ignored) {
                // Ignored
            } catch (InvocationTargetException e) {
                throw new IllegalArgumentException(e);
            }
        }

        return false;
    }

    private static Class<?> findNativeCrypto() {
        for (String packageName : new String[]{"com.android.org.conscrypt", "org.conscrypt"}) {
            String name = packageName + ".NativeCrypto";
            try {
                return Class.forName(name);
            } catch (ClassNotFoundException e) {
                // Try the next one.
            }
        }
        return null;
    }

    @SuppressWarnings("DefaultCharset")
    private static String getFieldFromCpuinfo(String field) {
        try {

            try (BufferedReader br = new BufferedReader(new FileReader("/proc/cpuinfo"))) {
                Pattern p = Pattern.compile(field + "\\s*:\\s*(.*)");
                String line;
                while ((line = br.readLine()) != null) {
                    Matcher m = p.matcher(line);
                    if (m.matches()) {
                        return m.group(1);
                    }
                }
            }
        } catch (IOException ignored) {
            // Ignored.
        }

        return null;
    }

    private static List<String> getListFromCpuinfo(String fieldName) {
        String features = getFieldFromCpuinfo(fieldName);
        if (features == null)
            return null;

        return Arrays.asList(features.split("\\s"));
    }

    private static List<String> getCpuFeaturesMac() {
        try {
            StringBuilder output = new StringBuilder();
            Process proc = Runtime.getRuntime().exec("sysctl -a");
            if (proc.waitFor() == 0) {
                BufferedReader reader =
                        new BufferedReader(new InputStreamReader(proc.getInputStream(), US_ASCII));

                final String linePrefix = "machdep.cpu.features:";

                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.toLowerCase(Locale.ROOT);
                    if (line.startsWith(linePrefix)) {
                        // Strip the line prefix from the results.
                        output.append(line.substring(linePrefix.length())).append(' ');
                    }
                }
                if (output.length() > 0) {
                    String outputString = output.toString();
                    String[] parts = outputString.split("\\s+");
                    return Arrays.asList(parts);
                }
            }
        } catch (Exception ignored) {
            // Ignored.
        }

        return null;
    }
}
