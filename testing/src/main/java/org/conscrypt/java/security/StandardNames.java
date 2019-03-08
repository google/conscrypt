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

package org.conscrypt.java.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * This class defines expected string names for protocols, key types,
 * client and server auth types, cipher suites.
 *
 * Initially based on "Appendix A: Standard Names" of
 * <a href="http://java.sun.com/j2se/1.5.0/docs/guide/security/jsse/JSSERefGuide.html#AppA">
 * Java &trade; Secure Socket Extension (JSSE) Reference Guide
 * for the Java &trade; 2 Platform Standard Edition 5
 * </a>.
 *
 * Updated based on the
 * <a href="http://download.java.net/jdk8/docs/technotes/guides/security/SunProviders.html">
 * Java &trade; Cryptography Architecture Oracle Providers Documentation
 * for Java &trade; Platform Standard Edition 7
 * </a>.
 * See also the
 * <a href="http://download.java.net/jdk8/docs/technotes/guides/security/StandardNames.html">
 * Java &trade; Cryptography Architecture Standard Algorithm Name Documentation
 * </a>.
 *
 * Further updates based on the
 * <a href=http://java.sun.com/javase/6/docs/technotes/guides/security/p11guide.html">
 * Java &trade; PKCS#11 Reference Guide
 * </a>.
 */
public final class StandardNames {
    public static final boolean IS_RI =
            !"Dalvik Core Library".equals(System.getProperty("java.specification.name"));
    public static final String JSSE_PROVIDER_NAME = IS_RI ? "Conscrypt" : "AndroidOpenSSL";

    public static final String KEY_MANAGER_FACTORY_DEFAULT = IS_RI ? "SunX509" : "PKIX";
    public static final String TRUST_MANAGER_FACTORY_DEFAULT = "PKIX";

    public static final String KEY_STORE_ALGORITHM = IS_RI ? "JKS" : "BKS";

    /**
     * RFC 5746's Signaling Cipher Suite Value to indicate a request for secure renegotiation
     */
    public static final String CIPHER_SUITE_SECURE_RENEGOTIATION =
            "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";

    /**
     * From https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00 it is a
     * signaling cipher suite value (SCSV) to indicate that this request is a
     * protocol fallback (e.g., TLS 1.0 -> SSL 3.0) because the server didn't respond
     * to the first request.
     */
    public static final String CIPHER_SUITE_FALLBACK = "TLS_FALLBACK_SCSV";

    private static final HashMap<String, HashSet<String>> CIPHER_MODES =
            new HashMap<String, HashSet<String>>();

    private static final HashMap<String, HashSet<String>> CIPHER_PADDINGS =
            new HashMap<String, HashSet<String>>();

    private static final HashMap<String, String[]> SSL_CONTEXT_PROTOCOLS_ENABLED =
            new HashMap<String, String[]>();

    private static void provideCipherModes(String algorithm, String newModes[]) {
        HashSet<String> modes = CIPHER_MODES.get(algorithm);
        if (modes == null) {
            modes = new HashSet<String>();
            CIPHER_MODES.put(algorithm, modes);
        }
        modes.addAll(Arrays.asList(newModes));
    }
    private static void provideCipherPaddings(String algorithm, String newPaddings[]) {
        HashSet<String> paddings = CIPHER_PADDINGS.get(algorithm);
        if (paddings == null) {
            paddings = new HashSet<String>();
            CIPHER_PADDINGS.put(algorithm, paddings);
        }
        paddings.addAll(Arrays.asList(newPaddings));
    }
    private static void provideSslContextEnabledProtocols(
            String algorithm, TLSVersion minimum, TLSVersion maximum) {
        if (minimum.ordinal() > maximum.ordinal()) {
            throw new RuntimeException("TLS version: minimum > maximum");
        }
        int versionsLength = maximum.ordinal() - minimum.ordinal() + 1;
        String[] versionNames = new String[versionsLength];
        for (int i = 0; i < versionsLength; i++) {
            versionNames[i] = TLSVersion.values()[i + minimum.ordinal()].name;
        }
        SSL_CONTEXT_PROTOCOLS_ENABLED.put(algorithm, versionNames);
    }
    static {
        // TODO: provideCipherModes and provideCipherPaddings for other Ciphers
        provideCipherModes("AES", new String[] {"CBC", "CFB", "CTR", "CTS", "ECB", "OFB"});
        provideCipherPaddings("AES", new String[] {"NoPadding", "PKCS5Padding"});
        // TODO: None?
        provideCipherModes("RSA", new String[] {"ECB"});
        // TODO: OAEPPadding
        provideCipherPaddings("RSA", new String[] {"NoPadding", "PKCS1Padding"});

        // Fixups for dalvik
        if (!IS_RI) {
            provideCipherPaddings("AES", new String[] {"PKCS7Padding"});
        }

        provideSslContextEnabledProtocols("TLS", TLSVersion.TLSv1, TLSVersion.TLSv13);
        provideSslContextEnabledProtocols("TLSv1", TLSVersion.TLSv1, TLSVersion.TLSv12);
        provideSslContextEnabledProtocols("TLSv1.1", TLSVersion.TLSv1, TLSVersion.TLSv12);
        provideSslContextEnabledProtocols("TLSv1.2", TLSVersion.TLSv1, TLSVersion.TLSv12);
        provideSslContextEnabledProtocols("TLSv1.3", TLSVersion.TLSv1, TLSVersion.TLSv13);
        provideSslContextEnabledProtocols("Default", TLSVersion.TLSv1, TLSVersion.TLSv13);
    }

    public static final String SSL_CONTEXT_PROTOCOLS_DEFAULT = "Default";
    public static final Set<String> SSL_CONTEXT_PROTOCOLS = new HashSet<String>(
            Arrays.asList(SSL_CONTEXT_PROTOCOLS_DEFAULT, "TLS", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"));
    public static final Set<String> SSL_CONTEXT_PROTOCOLS_WITH_DEFAULT_CONFIG = new HashSet<String>(
            Arrays.asList(SSL_CONTEXT_PROTOCOLS_DEFAULT, "TLS", "TLSv1.3"));

    public static final Set<String> KEY_TYPES = new HashSet<String>(
            Arrays.asList("RSA", "DSA", "DH_RSA", "DH_DSA", "EC", "EC_EC", "EC_RSA"));
    static {
        if (IS_RI) {
            // DH_* are specified by standard names, but do not seem to be supported by RI
            KEY_TYPES.remove("DH_RSA");
            KEY_TYPES.remove("DH_DSA");
        }
    }

    public static final Set<String> SSL_SOCKET_PROTOCOLS =
            new HashSet<String>(Arrays.asList("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"));

    private enum TLSVersion {
        SSLv3("SSLv3"),
        TLSv1("TLSv1"),
        TLSv11("TLSv1.1"),
        TLSv12("TLSv1.2"),
        TLSv13("TLSv1.3"),
        ;

        private final String name;

        TLSVersion(String name) {
            this.name = name;
        }
    }

    /**
     * Valid values for X509TrustManager.checkClientTrusted authType,
     * either the algorithm of the public key or UNKNOWN.
     */
    public static final Set<String> CLIENT_AUTH_TYPES =
            new HashSet<String>(Arrays.asList("RSA", "DSA", "EC", "UNKNOWN"));

    /**
     * Valid values for X509TrustManager.checkServerTrusted authType,
     * either key exchange algorithm part of the cipher suite, UNKNOWN,
     * or GENERIC (for TLS 1.3 cipher suites that don't imply a specific
     * key exchange method).
     */
    public static final Set<String> SERVER_AUTH_TYPES = new HashSet<String>(Arrays.asList("DHE_DSS",
            "DHE_DSS_EXPORT", "DHE_RSA", "DHE_RSA_EXPORT", "DH_DSS_EXPORT", "DH_RSA_EXPORT",
            "DH_anon", "DH_anon_EXPORT", "KRB5", "KRB5_EXPORT", "RSA", "RSA_EXPORT",
            "RSA_EXPORT1024", "ECDH_ECDSA", "ECDH_RSA", "ECDHE_ECDSA", "ECDHE_RSA", "UNKNOWN",
            "GENERIC"));

    public static final String CIPHER_SUITE_INVALID = "SSL_NULL_WITH_NULL_NULL";

    private static final Set<String> CIPHER_SUITES = new LinkedHashSet<String>();

    private static void addOpenSsl(String cipherSuite) {
        CIPHER_SUITES.add(cipherSuite);
    }

    static {
        addOpenSsl("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        addOpenSsl("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        addOpenSsl("TLS_RSA_WITH_AES_256_CBC_SHA");
        addOpenSsl("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
        addOpenSsl("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        addOpenSsl("TLS_RSA_WITH_AES_128_CBC_SHA");
        addOpenSsl("SSL_RSA_WITH_3DES_EDE_CBC_SHA");

        // TLSv1.2 cipher suites
        addOpenSsl("TLS_RSA_WITH_AES_128_GCM_SHA256");
        addOpenSsl("TLS_RSA_WITH_AES_256_GCM_SHA384");
        addOpenSsl("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        addOpenSsl("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        addOpenSsl("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        addOpenSsl("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        addOpenSsl("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
        addOpenSsl("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");

        // Pre-Shared Key (PSK) cipher suites
        addOpenSsl("TLS_PSK_WITH_AES_128_CBC_SHA");
        addOpenSsl("TLS_PSK_WITH_AES_256_CBC_SHA");
        addOpenSsl("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA");
        addOpenSsl("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA");
        addOpenSsl("TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256");

        // TLS 1.3 cipher suites
        addOpenSsl("TLS_AES_128_GCM_SHA256");
        addOpenSsl("TLS_AES_256_GCM_SHA384");
        addOpenSsl("TLS_CHACHA20_POLY1305_SHA256");

        // RFC 5746's Signaling Cipher Suite Value to indicate a request for secure renegotiation
        addOpenSsl(CIPHER_SUITE_SECURE_RENEGOTIATION);

        // From https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00 to indicate
        // TLS fallback request
        addOpenSsl(CIPHER_SUITE_FALLBACK);
    }

    /**
     * Cipher suites that are not negotiated when TLSv1.2 is selected on the RI.
     */
    public static final List<String> CIPHER_SUITES_OBSOLETE_TLS12 = Arrays.asList(
            "SSL_RSA_WITH_DES_CBC_SHA",
            "SSL_DHE_RSA_WITH_DES_CBC_SHA",
            "SSL_DHE_DSS_WITH_DES_CBC_SHA",
            "SSL_DH_anon_WITH_DES_CBC_SHA",
            "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
            "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
            "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA");

    /**
     * Cipher suites that are only supported with TLS 1.3.
     */
    public static final List<String> CIPHER_SUITES_TLS13 = Arrays.asList(
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256");

    // NOTE: This list needs to be kept in sync with Javadoc of javax.net.ssl.SSLSocket and
    // javax.net.ssl.SSLEngine.
    private static final List<String> CIPHER_SUITES_AES_HARDWARE = Arrays.asList(
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            CIPHER_SUITE_SECURE_RENEGOTIATION);

    // NOTE: This list needs to be kept in sync with Javadoc of javax.net.ssl.SSLSocket and
    // javax.net.ssl.SSLEngine.
    private static final List<String> CIPHER_SUITES_SOFTWARE = Arrays.asList(
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            CIPHER_SUITE_SECURE_RENEGOTIATION);

    // NOTE: This list needs to be kept in sync with Javadoc of javax.net.ssl.SSLSocket and
    // javax.net.ssl.SSLEngine.
    public static final List<String> CIPHER_SUITES_DEFAULT = CpuFeatures.isAESHardwareAccelerated()
            ? CIPHER_SUITES_AES_HARDWARE
            : CIPHER_SUITES_SOFTWARE;

    // NOTE: This list needs to be kept in sync with Javadoc of javax.net.ssl.SSLSocket and
    // javax.net.ssl.SSLEngine.
    public static final List<String> CIPHER_SUITES_DEFAULT_PSK = Arrays.asList(
            "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
            "TLS_PSK_WITH_AES_128_CBC_SHA",
            "TLS_PSK_WITH_AES_256_CBC_SHA");

    // Should be updated to match BoringSSL's defaults when they change.
    // https://boringssl.googlesource.com/boringssl/+/master/ssl/t1_lib.cc#289
    private static final List<String> ELLIPTIC_CURVES_DEFAULT =
            Arrays.asList("x25519 (29)", "secp256r1 (23)", "secp384r1 (24)");

    /**
     * Asserts that the cipher suites array is non-null and that it
     * all of its contents are cipher suites known to this
     * implementation. As a convenience, returns any unenabled cipher
     * suites in a test for those that want to verify separately that
     * all cipher suites were included.
     */
    private static Set<String> assertValidCipherSuites(
            Set<String> expected, String[] cipherSuites) {
        assertNotNull(cipherSuites);
        assertTrue(cipherSuites.length != 0);

        // Make sure all cipherSuites names are expected
        HashSet<String> remainingCipherSuites = new HashSet<String>(expected);
        HashSet<String> unknownCipherSuites = new HashSet<String>();
        for (String cipherSuite : cipherSuites) {
            boolean removed = remainingCipherSuites.remove(cipherSuite);
            if (!removed) {
                unknownCipherSuites.add(cipherSuite);
            }
        }
        assertEquals("Unknown cipher suites", Collections.EMPTY_SET, unknownCipherSuites);
        return remainingCipherSuites;
    }

    /**
     * After using assertValidCipherSuites on cipherSuites,
     * assertSupportedCipherSuites additionally verifies that all
     * supported cipher suites where in the input array.
     */
    private static void assertSupportedCipherSuites(Set<String> expected, String[] cipherSuites) {
        Set<String> remainingCipherSuites = assertValidCipherSuites(expected, cipherSuites);
        assertEquals("Missing cipher suites", Collections.EMPTY_SET, remainingCipherSuites);
        assertEquals(expected.size(), cipherSuites.length);
    }

    /**
     * Asserts that the protocols array is non-null and that it all of
     * its contents are protocols known to this implementation. As a
     * convenience, returns any unenabled protocols in a test for
     * those that want to verify separately that all protocols were
     * included.
     */
    private static Set<String> assertValidProtocols(Set<String> expected, String[] protocols) {
        assertNotNull(protocols);
        assertTrue(protocols.length != 0);

        // Make sure all protocols names are expected
        HashSet<String> remainingProtocols = new HashSet<String>(expected);
        HashSet<String> unknownProtocols = new HashSet<String>();
        for (String protocol : protocols) {
            if (!remainingProtocols.remove(protocol)) {
                unknownProtocols.add(protocol);
            }
        }
        assertEquals("Unknown protocols", Collections.EMPTY_SET, unknownProtocols);
        return remainingProtocols;
    }

    /**
     * After using assertValidProtocols on protocols,
     * assertSupportedProtocols additionally verifies that all
     * supported protocols where in the input array.
     */
    private static void assertSupportedProtocols(Set<String> expected, String[] protocols) {
        Set<String> remainingProtocols = assertValidProtocols(expected, protocols);
        assertEquals("Missing protocols", Collections.EMPTY_SET, remainingProtocols);
        assertEquals(expected.size(), protocols.length);
    }

    /**
     * Asserts that the provided list of protocols matches the supported list of protocols.
     */
    public static void assertSupportedProtocols(String[] protocols) {
        assertSupportedProtocols(SSL_SOCKET_PROTOCOLS, protocols);
    }

    /**
     * Assert that the provided list of cipher suites contains only the supported cipher suites.
     */
    public static void assertValidCipherSuites(String[] cipherSuites) {
        assertValidCipherSuites(CIPHER_SUITES, cipherSuites);
    }

    /**
     * Assert that the provided list of cipher suites matches the supported list.
     */
    public static void assertSupportedCipherSuites(String[] cipherSuites) {
        assertSupportedCipherSuites(CIPHER_SUITES, cipherSuites);
    }

    /**
     * Assert cipher suites match the default list in content and priority order and contain
     * only cipher suites permitted by default.
     */
    public static void assertDefaultCipherSuites(String[] cipherSuites) {
        assertValidCipherSuites(cipherSuites);

        Set<String> expected = new TreeSet<String>(CIPHER_SUITES_DEFAULT);
        Set<String> actual = new TreeSet<String>(Arrays.asList(cipherSuites));
        assertEquals(expected, actual);
    }

    public static void assertDefaultEllipticCurves(String[] curves) {
        assertEquals(ELLIPTIC_CURVES_DEFAULT, Arrays.asList(curves));
    }

    public static void assertSSLContextEnabledProtocols(String version, String[] protocols) {
        assertEquals("For protocol \"" + version + "\"",
                Arrays.toString(SSL_CONTEXT_PROTOCOLS_ENABLED.get(version)),
                Arrays.toString(protocols));
    }

    /**
     * Get all supported mode names for the given cipher.
     */
    public static Set<String> getModesForCipher(String cipher) {
        return CIPHER_MODES.get(cipher);
    }

    /**
     * Get all supported padding names for the given cipher.
     */
    public static Set<String> getPaddingsForCipher(String cipher) {
        return CIPHER_PADDINGS.get(cipher);
    }
}
