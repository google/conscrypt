/*
 * Copyright (C) 2010 The Android Open Source Project
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Method;

@RunWith(JUnit4.class)
public final class NativeSslTest {
    @Test
    public void toBoringSslGroups_convertsKnownValues() {
        assertArrayEquals(new int[] {NativeConstants.NID_X25519},
                          NativeSsl.toBoringSslGroups(new String[] {"X25519"}));
        assertArrayEquals(new int[] {NativeConstants.NID_X25519},
                          NativeSsl.toBoringSslGroups(new String[] {"x25519"}));
        assertArrayEquals(new int[] {NativeConstants.NID_X9_62_prime256v1},
                          NativeSsl.toBoringSslGroups(new String[] {"P-256"}));
        assertArrayEquals(new int[] {NativeConstants.NID_X9_62_prime256v1},
                          NativeSsl.toBoringSslGroups(new String[] {"secp256r1"}));
        assertArrayEquals(new int[] {NativeConstants.NID_secp384r1},
                          NativeSsl.toBoringSslGroups(new String[] {"P-384"}));
        assertArrayEquals(new int[] {NativeConstants.NID_secp384r1},
                          NativeSsl.toBoringSslGroups(new String[] {"secp384r1"}));
        assertArrayEquals(new int[] {NativeConstants.NID_secp521r1},
                          NativeSsl.toBoringSslGroups(new String[] {"P-521"}));
        assertArrayEquals(new int[] {NativeConstants.NID_secp521r1},
                          NativeSsl.toBoringSslGroups(new String[] {"secp521r1"}));
        assertArrayEquals(new int[] {NativeConstants.NID_X25519MLKEM768},
                          NativeSsl.toBoringSslGroups(new String[] {"X25519MLKEM768"}));
        assertArrayEquals(new int[] {NativeConstants.NID_ML_KEM_1024},
                          NativeSsl.toBoringSslGroups(new String[] {"MLKEM1024"}));
    }

    @Test
    public void toBoringSslGroups_convertsLists() {
        assertArrayEquals(
                new int[] {NativeConstants.NID_X25519, NativeConstants.NID_X9_62_prime256v1},
                NativeSsl.toBoringSslGroups(new String[] {"X25519", "P-256"}));
    }

    @Test
    public void toBoringSslGroups_ignoresUnknownValues() {
        assertArrayEquals(
                new int[] {NativeConstants.NID_X25519},
                NativeSsl.toBoringSslGroups(new String[] {"Unknown", "X25519", "Unknown2"}));
    }

    @Test
    public void toBoringSslGroups_throwsIfNoKnownGroupsFound() {
        assertThrows(IllegalArgumentException.class,
                     () -> NativeSsl.toBoringSslGroups(new String[] {}));
        assertThrows(IllegalArgumentException.class,
                     () -> NativeSsl.toBoringSslGroups(new String[] {"Unknown"}));
        assertThrows(IllegalArgumentException.class,
                     () -> NativeSsl.toBoringSslGroups(new String[] {"Unknown", "Unknown2"}));
    }

    @Test
    public void getDefaultNamedGroups_returnsExplicitlyPinnedGroups() throws Exception {
        int[] pqcGroups = new int[] {NativeConstants.NID_X25519MLKEM768, NativeConstants.NID_X25519,
                                     NativeConstants.NID_X9_62_prime256v1,
                                     NativeConstants.NID_secp384r1};
        int[] classicalGroups = new int[] {
                NativeConstants.NID_X25519, NativeConstants.NID_X9_62_prime256v1,
                NativeConstants.NID_secp384r1};
        assertArrayEquals(pqcGroups,
                          NativeSsl.toBoringSslGroups(NativeSsl.DEFAULT_PQC_NAMED_GROUPS));
        assertArrayEquals(classicalGroups,
                          NativeSsl.toBoringSslGroups(NativeSsl.DEFAULT_CLASSICAL_NAMED_GROUPS));

        int[] defaultGroups = NativeSsl.getDefaultNamedGroups();
        assertNotNull(defaultGroups);
        assertArrayEquals(Platform.isPqcDefaultEnabled() ? pqcGroups : classicalGroups,
                          defaultGroups);

        try {
            Method setPqcForTesting = Platform.class.getDeclaredMethod(
                    "setPqcDefaultEnabledForTesting", boolean.class);
            boolean saved = Platform.isPqcDefaultEnabled();
            try {
                setPqcForTesting.invoke(null, true);
                assertArrayEquals(pqcGroups, NativeSsl.getDefaultNamedGroups());
                setPqcForTesting.invoke(null, false);
                assertArrayEquals(classicalGroups, NativeSsl.getDefaultNamedGroups());
            } finally {
                setPqcForTesting.invoke(null, saved);
            }
        } catch (NoSuchMethodException ignored) {
            // android/Platform does not define setPqcDefaultEnabledForTesting.
        }
    }

    @Test
    public void toBoringSslSignatureAlgorithms_convertsKnownValues() {
        assertArrayEquals(new int[] {NativeConstants.SSL_SIGN_ML_DSA_44},
                          NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"mldsa44"}));
        assertArrayEquals(new int[] {NativeConstants.SSL_SIGN_ML_DSA_44},
                          NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"ML-DSA-44"}));
        assertArrayEquals(new int[] {NativeConstants.SSL_SIGN_ML_DSA_65},
                          NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"mldsa65"}));
        assertArrayEquals(new int[] {NativeConstants.SSL_SIGN_ML_DSA_65},
                          NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"ML-DSA-65"}));
        assertArrayEquals(new int[] {NativeConstants.SSL_SIGN_ML_DSA_87},
                          NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"mldsa87"}));
        assertArrayEquals(new int[] {NativeConstants.SSL_SIGN_ML_DSA_87},
                          NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"ML-DSA-87"}));
        assertArrayEquals(new int[] {NativeConstants.SSL_SIGN_ECDSA_SECP256R1_SHA256},
                          NativeSsl.toBoringSslSignatureAlgorithms(
                                  new String[] {"ecdsa_secp256r1_sha256"}));
        assertArrayEquals(
                new int[] {NativeConstants.SSL_SIGN_RSA_PSS_RSAE_SHA256},
                NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"rsa_pss_rsae_sha256"}));
        assertArrayEquals(
                new int[] {NativeConstants.SSL_SIGN_RSA_PKCS1_SHA256},
                NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"rsa_pkcs1_sha256"}));
        assertArrayEquals(new int[] {NativeConstants.SSL_SIGN_ECDSA_SECP384R1_SHA384},
                          NativeSsl.toBoringSslSignatureAlgorithms(
                                  new String[] {"ecdsa_secp384r1_sha384"}));
        assertArrayEquals(
                new int[] {NativeConstants.SSL_SIGN_RSA_PSS_RSAE_SHA384},
                NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"rsa_pss_rsae_sha384"}));
        assertArrayEquals(
                new int[] {NativeConstants.SSL_SIGN_RSA_PKCS1_SHA384},
                NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"rsa_pkcs1_sha384"}));
        assertArrayEquals(new int[] {NativeConstants.SSL_SIGN_ECDSA_SECP521R1_SHA512},
                          NativeSsl.toBoringSslSignatureAlgorithms(
                                  new String[] {"ecdsa_secp521r1_sha512"}));
        assertArrayEquals(
                new int[] {NativeConstants.SSL_SIGN_RSA_PSS_RSAE_SHA512},
                NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"rsa_pss_rsae_sha512"}));
        assertArrayEquals(
                new int[] {NativeConstants.SSL_SIGN_RSA_PKCS1_SHA512},
                NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"rsa_pkcs1_sha512"}));
        assertArrayEquals(
                new int[] {NativeConstants.SSL_SIGN_RSA_PKCS1_SHA1},
                NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"rsa_pkcs1_sha1"}));
        assertArrayEquals(new int[] {NativeConstants.SSL_SIGN_ECDSA_SHA1},
                          NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"ecdsa_sha1"}));
        assertArrayEquals(new int[] {NativeConstants.SSL_SIGN_ED25519},
                          NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"ed25519"}));
    }

    @Test
    public void toBoringSslSignatureAlgorithms_convertsLists() {
        assertArrayEquals(new int[] {NativeConstants.SSL_SIGN_ML_DSA_65,
                                     NativeConstants.SSL_SIGN_ECDSA_SECP256R1_SHA256},
                          NativeSsl.toBoringSslSignatureAlgorithms(
                                  new String[] {"mldsa65", "ecdsa_secp256r1_sha256"}));
    }

    @Test
    public void toBoringSslSignatureAlgorithms_ignoresUnknownValues() {
        assertArrayEquals(
                new int[] {NativeConstants.SSL_SIGN_ECDSA_SECP256R1_SHA256},
                NativeSsl.toBoringSslSignatureAlgorithms(
                        new String[] {"Unknown", "ecdsa_secp256r1_sha256", "Unknown2"}));
    }

    @Test
    public void toBoringSslSignatureAlgorithms_throwsIfNoKnownAlgorithmsFound() {
        assertThrows(IllegalArgumentException.class,
                     () -> NativeSsl.toBoringSslSignatureAlgorithms(new String[] {}));
        assertThrows(IllegalArgumentException.class,
                     () -> NativeSsl.toBoringSslSignatureAlgorithms(new String[] {"Unknown"}));
        assertThrows(IllegalArgumentException.class,
                     () -> NativeSsl.toBoringSslSignatureAlgorithms(
                             new String[] {"Unknown", "Unknown2"}));
    }

    @Test
    public void getDefaultSignatureAlgorithms_returnsExplicitlyPinnedAlgorithms() throws Exception {
        int[] pqcAlgs = new int[] {
                NativeConstants.SSL_SIGN_ML_DSA_44,
                NativeConstants.SSL_SIGN_ML_DSA_65,
                NativeConstants.SSL_SIGN_ML_DSA_87,
                NativeConstants.SSL_SIGN_ECDSA_SECP256R1_SHA256,
                NativeConstants.SSL_SIGN_RSA_PSS_RSAE_SHA256,
                NativeConstants.SSL_SIGN_RSA_PKCS1_SHA256,
                NativeConstants.SSL_SIGN_ECDSA_SECP384R1_SHA384,
                NativeConstants.SSL_SIGN_RSA_PSS_RSAE_SHA384,
                NativeConstants.SSL_SIGN_RSA_PKCS1_SHA384,
                NativeConstants.SSL_SIGN_RSA_PSS_RSAE_SHA512,
                NativeConstants.SSL_SIGN_RSA_PKCS1_SHA512,
                NativeConstants.SSL_SIGN_RSA_PKCS1_SHA1,
        };
        int[] classicalAlgs = new int[] {
                NativeConstants.SSL_SIGN_ECDSA_SECP256R1_SHA256,
                NativeConstants.SSL_SIGN_RSA_PSS_RSAE_SHA256,
                NativeConstants.SSL_SIGN_RSA_PKCS1_SHA256,
                NativeConstants.SSL_SIGN_ECDSA_SECP384R1_SHA384,
                NativeConstants.SSL_SIGN_RSA_PSS_RSAE_SHA384,
                NativeConstants.SSL_SIGN_RSA_PKCS1_SHA384,
                NativeConstants.SSL_SIGN_RSA_PSS_RSAE_SHA512,
                NativeConstants.SSL_SIGN_RSA_PKCS1_SHA512,
                NativeConstants.SSL_SIGN_RSA_PKCS1_SHA1,
        };
        assertArrayEquals(
                pqcAlgs,
                NativeSsl.toBoringSslSignatureAlgorithms(
                        NativeSsl.DEFAULT_PQC_SIGNATURE_ALGORITHMS));
        assertArrayEquals(
                classicalAlgs,
                NativeSsl.toBoringSslSignatureAlgorithms(
                        NativeSsl.DEFAULT_CLASSICAL_SIGNATURE_ALGORITHMS));

        int[] defaultAlgs = NativeSsl.getDefaultSignatureAlgorithms();
        assertNotNull(defaultAlgs);
        assertArrayEquals(
                Platform.isPqcDefaultSignatureAlgorithmsEnabled() ? pqcAlgs : classicalAlgs,
                defaultAlgs);

        try {
            Method setPqcForTesting = Platform.class.getDeclaredMethod(
                    "setPqcDefaultSignatureAlgorithmsEnabledForTesting", boolean.class);
            boolean saved = Platform.isPqcDefaultSignatureAlgorithmsEnabled();
            try {
                setPqcForTesting.invoke(null, true);
                assertArrayEquals(pqcAlgs, NativeSsl.getDefaultSignatureAlgorithms());
                setPqcForTesting.invoke(null, false);
                assertArrayEquals(classicalAlgs, NativeSsl.getDefaultSignatureAlgorithms());
            } finally {
                setPqcForTesting.invoke(null, saved);
            }
        } catch (NoSuchMethodException ignored) {
            // platform/Platform does not define setPqcDefaultSignatureAlgorithmsEnabledForTesting.
        }
    }

    @Test
    public void parseNamedGroupsProperty_parsesProperty() {
        assertArrayEquals(new int[] {NativeConstants.NID_X25519},
                          NativeSsl.parseNamedGroupsProperty("X25519"));
        assertArrayEquals(
                new int[] {NativeConstants.NID_X25519, NativeConstants.NID_X9_62_prime256v1},
                NativeSsl.parseNamedGroupsProperty("X25519,P-256"));
        assertArrayEquals(
                new int[] {NativeConstants.NID_X25519, NativeConstants.NID_X9_62_prime256v1},
                NativeSsl.parseNamedGroupsProperty("X25519, P-256"));
        assertArrayEquals(
                new int[] {NativeConstants.NID_X25519, NativeConstants.NID_X9_62_prime256v1},
                NativeSsl.parseNamedGroupsProperty("X25519,Unknown,P-256"));
    }

    @Test
    public void parseNamedGroupsProperty_throwsIfNoKnownGroupsFound() {
        assertThrows(NullPointerException.class, () -> NativeSsl.parseNamedGroupsProperty(null));
        assertThrows(IllegalArgumentException.class, () -> NativeSsl.parseNamedGroupsProperty(""));
        assertThrows(IllegalArgumentException.class, () -> NativeSsl.parseNamedGroupsProperty(","));
        assertThrows(IllegalArgumentException.class,
                     () -> NativeSsl.parseNamedGroupsProperty(" ,"));
        assertThrows(IllegalArgumentException.class,
                     () -> NativeSsl.parseNamedGroupsProperty("Unknown"));
        assertThrows(IllegalArgumentException.class,
                     () -> NativeSsl.parseNamedGroupsProperty("Unknown,Unknown2"));
    }

    @Test
    public void parseTlsNamedGroupsProperty_works() throws Exception {
        String savedProperty = System.getProperty("jdk.tls.namedGroups");
        try {
            // Valid values.
            System.setProperty("jdk.tls.namedGroups", "P-384,X25519");
            NativeSsl.parseTlsNamedGroupsProperty();
            assertArrayEquals(new int[] {NativeConstants.NID_secp384r1, NativeConstants.NID_X25519},
                              NativeSsl.getParsedTlsNamedGroupsPropertyOrNull());

            // Property not set.
            System.clearProperty("jdk.tls.namedGroups");
            NativeSsl.parseTlsNamedGroupsProperty();
            assertNull(NativeSsl.getParsedTlsNamedGroupsPropertyOrNull());

            // Empty property.
            System.setProperty("jdk.tls.namedGroups", "");
            NativeSsl.parseTlsNamedGroupsProperty();
            assertNull(NativeSsl.getParsedTlsNamedGroupsPropertyOrNull());

            // Invalid values (calling repeatedly must continue to throw rather than caching invalid
            // property).
            System.setProperty("jdk.tls.namedGroups", "invalid,invalid2");
            assertThrows(IllegalArgumentException.class,
                         () -> NativeSsl.parseTlsNamedGroupsProperty());
            assertThrows(IllegalArgumentException.class,
                         () -> NativeSsl.parseTlsNamedGroupsProperty());
            assertNull(NativeSsl.getParsedTlsNamedGroupsPropertyOrNull());
        } finally {
            // Restore the property to its original value, to make sure that the test does not
            // have any side effects on other tests when setting the property.
            if (savedProperty == null) {
                System.clearProperty("jdk.tls.namedGroups");
            } else {
                System.setProperty("jdk.tls.namedGroups", savedProperty);
            }
            NativeSsl.getParsedTlsNamedGroupsPropertyOrNull();
        }
    }

    @Test
    public void staticInitializer_doesNotFailWhenNamedGroupsPropertyContainsOnlyUnrecognizedGroups()
            throws Exception {
        String savedProperty = System.getProperty("jdk.tls.namedGroups");
        try {
            System.setProperty("jdk.tls.namedGroups", "UnknownGroup1,UnknownGroup2");
            Class<?> isolatedNativeSsl = loadAndInitializeNativeSslInIsolatedClassLoader();
            assertNotNull(isolatedNativeSsl);
        } finally {
            if (savedProperty == null) {
                System.clearProperty("jdk.tls.namedGroups");
            } else {
                System.setProperty("jdk.tls.namedGroups", savedProperty);
            }
            NativeSsl.getParsedTlsNamedGroupsPropertyOrNull();
        }
    }

    private static Class<?> loadAndInitializeNativeSslInIsolatedClassLoader() throws Exception {
        final String className = NativeSsl.class.getName();
        final String resourceName = "NativeSsl.class";
        try (InputStream is = NativeSsl.class.getResourceAsStream(resourceName)) {
            if (is != null) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int read;
                while ((read = is.read(buffer)) != -1) {
                    baos.write(buffer, 0, read);
                }
                final byte[] classBytes = baos.toByteArray();
                ClassLoader loader = new ClassLoader(NativeSsl.class.getClassLoader()) {
                    @Override
                    protected Class<?> loadClass(String name, boolean resolve)
                            throws ClassNotFoundException {
                        if (name.equals(className)) {
                            Class<?> c = findLoadedClass(name);
                            if (c == null) {
                                c = defineClass(name, classBytes, 0, classBytes.length,
                                                NativeSsl.class.getProtectionDomain());
                            }
                            if (resolve) {
                                resolveClass(c);
                            }
                            return c;
                        }
                        return super.loadClass(name, resolve);
                    }
                };
                return Class.forName(className, /* initialize= */ true, loader);
            }
        }
        // On Android ART, classes are in DEX format rather than .class resources.
        // Include any APK/JAR dex paths from NativeSsl's ClassLoader (needed for unbundled APK
        // instrumentation tests where java.class.path is just "."), and delegate all classes except
        // NativeSsl itself to NativeSsl.class.getClassLoader().
        StringBuilder dexPathBuilder = new StringBuilder();
        ClassLoader sourceLoader = NativeSsl.class.getClassLoader();
        if (sourceLoader != null) {
            String loaderStr = sourceLoader.toString();
            int idx = 0;
            while ((idx = loaderStr.indexOf("zip file \"", idx)) != -1) {
                int start = idx + "zip file \"".length();
                int end = loaderStr.indexOf('"', start);
                if (end > start) {
                    if (dexPathBuilder.length() > 0) {
                        dexPathBuilder.append(File.pathSeparator);
                    }
                    dexPathBuilder.append(loaderStr, start, end);
                    idx = end + 1;
                } else {
                    break;
                }
            }
        }
        for (String prop : new String[] {"java.class.path", "java.boot.class.path"}) {
            String val = System.getProperty(prop, "");
            if (!val.isEmpty()) {
                if (dexPathBuilder.length() > 0) {
                    dexPathBuilder.append(File.pathSeparator);
                }
                dexPathBuilder.append(val);
            }
        }
        ClassLoader delegatingParent = new ClassLoader(sourceLoader) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve)
                    throws ClassNotFoundException {
                if (name.equals(className)) {
                    throw new ClassNotFoundException(name);
                }
                return super.loadClass(name, resolve);
            }
        };
        Class<?> pathClassLoaderClass = Class.forName("dalvik.system.PathClassLoader");
        ClassLoader dexLoader =
                (ClassLoader) pathClassLoaderClass.getConstructor(String.class, ClassLoader.class)
                        .newInstance(dexPathBuilder.toString(), delegatingParent);
        return Class.forName(className, /* initialize= */ true, dexLoader);
    }
}
