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

import static org.conscrypt.NativeConstants.SSL_MODE_CBC_RECORD_SPLITTING;
import static org.conscrypt.NativeConstants.SSL_MODE_ENABLE_FALSE_START;
import static org.conscrypt.NativeConstants.SSL_OP_NO_SSLv3;
import static org.conscrypt.NativeConstants.SSL_OP_NO_TLSv1;
import static org.conscrypt.NativeConstants.SSL_OP_NO_TLSv1_1;
import static org.conscrypt.NativeConstants.SSL_OP_NO_TLSv1_2;
import static org.conscrypt.NativeConstants.SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
import static org.conscrypt.NativeConstants.SSL_VERIFY_NONE;
import static org.conscrypt.NativeConstants.SSL_VERIFY_PEER;
import static org.conscrypt.TestUtils.openTestFile;
import static org.conscrypt.TestUtils.readTestFile;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import javax.security.auth.x500.X500Principal;
import libcore.io.IoUtils;
import libcore.java.security.StandardNames;
import libcore.java.security.TestKeyStore;
import org.conscrypt.NativeCrypto.SSLHandshakeCallbacks;
import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class NativeCryptoTest {
    private static final long NULL = 0;
    private static final FileDescriptor INVALID_FD = new FileDescriptor();
    private static final SSLHandshakeCallbacks DUMMY_CB =
            new TestSSLHandshakeCallbacks(null, 0, null);

    private static final long TIMEOUT_SECONDS = 5;

    private static OpenSSLKey SERVER_PRIVATE_KEY;
    private static OpenSSLX509Certificate[] SERVER_CERTIFICATES_HOLDER;
    private static long[] SERVER_CERTIFICATE_REFS;
    private static byte[][] ENCODED_SERVER_CERTIFICATES;
    private static OpenSSLKey CLIENT_PRIVATE_KEY;
    private static OpenSSLX509Certificate[] CLIENT_CERTIFICATES_HOLDER;
    private static long[] CLIENT_CERTIFICATE_REFS;
    private static byte[][] ENCODED_CLIENT_CERTIFICATES;
    private static byte[][] CA_PRINCIPALS;
    private static OpenSSLKey CHANNEL_ID_PRIVATE_KEY;
    private static byte[] CHANNEL_ID;
    private static Method m_Platform_getFileDescriptor;

    @BeforeClass
    public static void getPlatformMethods() throws Exception {
        Class<?> c_Platform = TestUtils.conscryptClass("Platform");
        m_Platform_getFileDescriptor =
                c_Platform.getDeclaredMethod("getFileDescriptor", Socket.class);
        m_Platform_getFileDescriptor.setAccessible(true);
    }

    @After
    public void tearDown() throws Exception {
        assertEquals(0, NativeCrypto.ERR_peek_last_error());
    }

    private static OpenSSLKey getServerPrivateKey() {
        initCerts();
        return SERVER_PRIVATE_KEY;
    }

    private static long[] getServerCertificateRefs() {
        initCerts();
        return SERVER_CERTIFICATE_REFS;
    }

    private static byte[][] getEncodedServerCertificates() {
        initCerts();
        return ENCODED_SERVER_CERTIFICATES;
    }

    private static OpenSSLKey getClientPrivateKey() {
        initCerts();
        return CLIENT_PRIVATE_KEY;
    }

    private static long[] getClientCertificateRefs() {
        initCerts();
        return CLIENT_CERTIFICATE_REFS;
    }

    private static byte[][] getEncodedClientCertificates() {
        initCerts();
        return ENCODED_CLIENT_CERTIFICATES;
    }

    private static byte[][] getCaPrincipals() {
        initCerts();
        return CA_PRINCIPALS;
    }

    /**
     * Lazily create shared test certificates.
     */
    private static synchronized void initCerts() {
        if (SERVER_PRIVATE_KEY != null) {
            return;
        }

        try {
            PrivateKeyEntry serverPrivateKeyEntry =
                    TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
            SERVER_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(serverPrivateKeyEntry.getPrivateKey());
            SERVER_CERTIFICATES_HOLDER =
                    encodeCertificateList(serverPrivateKeyEntry.getCertificateChain());
            SERVER_CERTIFICATE_REFS = getCertificateReferences(SERVER_CERTIFICATES_HOLDER);
            ENCODED_SERVER_CERTIFICATES = getEncodedCertificates(SERVER_CERTIFICATES_HOLDER);

            PrivateKeyEntry clientPrivateKeyEntry =
                    TestKeyStore.getClientCertificate().getPrivateKey("RSA", "RSA");
            CLIENT_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(clientPrivateKeyEntry.getPrivateKey());
            CLIENT_CERTIFICATES_HOLDER =
                    encodeCertificateList(clientPrivateKeyEntry.getCertificateChain());
            CLIENT_CERTIFICATE_REFS = getCertificateReferences(CLIENT_CERTIFICATES_HOLDER);
            ENCODED_CLIENT_CERTIFICATES = getEncodedCertificates(CLIENT_CERTIFICATES_HOLDER);

            KeyStore ks = TestKeyStore.getClient().keyStore;
            String caCertAlias = ks.aliases().nextElement();
            X509Certificate certificate = (X509Certificate) ks.getCertificate(caCertAlias);
            X500Principal principal = certificate.getIssuerX500Principal();
            CA_PRINCIPALS = new byte[][] {principal.getEncoded()};
            initChannelIdKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static long[] getCertificateReferences(OpenSSLX509Certificate[] certs) {
        final long[] certRefs = new long[certs.length];
        for (int i = 0; i < certs.length; i++) {
            certRefs[i] = certs[i].getContext();
        }
        return certRefs;
    }

    private static byte[][] getEncodedCertificates(OpenSSLX509Certificate[] certs) {
        try {
            final byte[][] encoded = new byte[certs.length][];
            for (int i = 0; i < certs.length; i++) {
                encoded[i] = certs[i].getEncoded();
            }
            return encoded;
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static OpenSSLX509Certificate[] encodeCertificateList(Certificate[] chain)
            throws CertificateEncodingException {
        final OpenSSLX509Certificate[] openSslCerts = new OpenSSLX509Certificate[chain.length];
        for (int i = 0; i < chain.length; i++) {
            openSslCerts[i] = OpenSSLX509Certificate.fromCertificate(chain[i]);
        }
        return openSslCerts;
    }

    private static synchronized void initChannelIdKey() throws Exception {
        if (CHANNEL_ID_PRIVATE_KEY != null) {
            return;
        }

        // NIST P-256 aka SECG secp256r1 aka X9.62 prime256v1
        OpenSSLECGroupContext openSslSpec = OpenSSLECGroupContext.getCurveByName("prime256v1");
        BigInteger s = new BigInteger(
                "229cdbbf489aea584828a261a23f9ff8b0f66f7ccac98bf2096ab3aee41497c5", 16);
        CHANNEL_ID_PRIVATE_KEY =
                new OpenSSLECPrivateKey(new ECPrivateKeySpec(s, openSslSpec.getECParameterSpec()))
                        .getOpenSSLKey();

        // Channel ID is the concatenation of the X and Y coordinates of the public key.
        CHANNEL_ID = new BigInteger(
                "702b07871fd7955c320b26f15e244e47eed60272124c92b9ebecf0b42f90069b"
                        + "ab53592ebfeb4f167dbf3ce61513afb0e354c479b1c1b69874fa471293494f77",
                16)
                             .toByteArray();
    }

    private static RSAPrivateCrtKey generateRsaKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);

        KeyPair keyPair = kpg.generateKeyPair();
        return (RSAPrivateCrtKey) keyPair.getPrivate();
    }

    private static NativeRef.EVP_PKEY getRsaPkey(RSAPrivateCrtKey privKey) throws Exception {
        return new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_new_RSA(
                privKey.getModulus().toByteArray(), privKey.getPublicExponent().toByteArray(),
                privKey.getPrivateExponent().toByteArray(), privKey.getPrimeP().toByteArray(),
                privKey.getPrimeQ().toByteArray(), privKey.getPrimeExponentP().toByteArray(),
                privKey.getPrimeExponentQ().toByteArray(),
                privKey.getCrtCoefficient().toByteArray()));
    }

    public static void assertEqualSessions(long expected, long actual) {
        assertEqualByteArrays(NativeCrypto.SSL_SESSION_session_id(expected),
                NativeCrypto.SSL_SESSION_session_id(actual));
    }
    public static void assertEqualByteArrays(byte[] expected, byte[] actual) {
        assertEquals(Arrays.toString(expected), Arrays.toString(actual));
    }

    public static void assertEqualPrincipals(byte[][] expected, byte[][] actual) {
        assertEqualByteArrays(expected, actual);
    }

    public static void assertEqualCertificateChains(long[] expected, long[] actual) {
        assertEquals(expected.length, actual.length);
        for (int i = 0; i < expected.length; i++) {
            NativeCrypto.X509_cmp(expected[i], actual[i]);
        }
    }

    public static void assertEqualByteArrays(byte[][] expected, byte[][] actual) {
        assertEquals(Arrays.deepToString(expected), Arrays.deepToString(actual));
    }

    @Test(expected = NullPointerException.class)
    public void EVP_PKEY_cmp_BothNullParameters() throws Exception {
        NativeCrypto.EVP_PKEY_cmp(null, null);
    }

    @Test(expected = NullPointerException.class)
    public void EVP_PKEY_cmp_withNullShouldThrow() throws Exception {
        RSAPrivateCrtKey privKey1 = generateRsaKey();
        NativeRef.EVP_PKEY pkey1 = getRsaPkey(privKey1);
        assertNotSame(NULL, pkey1);
        NativeCrypto.EVP_PKEY_cmp(pkey1, null);
    }

    @Test
    public void test_EVP_PKEY_cmp() throws Exception {
        RSAPrivateCrtKey privKey1 = generateRsaKey();

        NativeRef.EVP_PKEY pkey1 = getRsaPkey(privKey1);
        assertNotSame(NULL, pkey1);

        NativeRef.EVP_PKEY pkey1_copy = getRsaPkey(privKey1);
        assertNotSame(NULL, pkey1_copy);

        NativeRef.EVP_PKEY pkey2 = getRsaPkey(generateRsaKey());
        assertNotSame(NULL, pkey2);

        assertEquals("Same keys should be the equal", 1, NativeCrypto.EVP_PKEY_cmp(pkey1, pkey1));

        assertEquals(
                "Same keys should be the equal", 1, NativeCrypto.EVP_PKEY_cmp(pkey1, pkey1_copy));

        assertEquals(
                "Different keys should not be equal", 0, NativeCrypto.EVP_PKEY_cmp(pkey1, pkey2));
    }

    @Test
    public void test_SSL_CTX_new() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        assertTrue(c != NULL);
        long c2 = NativeCrypto.SSL_CTX_new();
        assertTrue(c != c2);
        NativeCrypto.SSL_CTX_free(c);
        NativeCrypto.SSL_CTX_free(c2);
    }

    @Test(expected = NullPointerException.class)
    public void test_SSL_CTX_free_NullArgument() throws Exception {
        NativeCrypto.SSL_CTX_free(NULL);
    }

    @Test
    public void test_SSL_CTX_free() throws Exception {
        NativeCrypto.SSL_CTX_free(NativeCrypto.SSL_CTX_new());
    }

    @Test(expected = NullPointerException.class)
    public void SSL_CTX_set_session_id_context_NullContextArgument() throws Exception {
        NativeCrypto.SSL_CTX_set_session_id_context(NULL, new byte[0]);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_CTX_set_session_id_context_withNullShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        try {
            NativeCrypto.SSL_CTX_set_session_id_context(c, null);
        } finally {
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void test_SSL_CTX_set_session_id_context_withInvalidIdShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        try {
            NativeCrypto.SSL_CTX_set_session_id_context(c, new byte[33]);
        } finally {
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test
    public void test_SSL_CTX_set_session_id_context() throws Exception {
        byte[] empty = new byte[0];

        long c = NativeCrypto.SSL_CTX_new();
        try {
            NativeCrypto.SSL_CTX_set_session_id_context(c, empty);
            NativeCrypto.SSL_CTX_set_session_id_context(c, new byte[32]);
        } finally {
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test
    public void test_SSL_new() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        assertTrue(s != NULL);
        assertTrue((NativeCrypto.SSL_get_options(s) & SSL_OP_NO_SSLv3) == 0);
        assertTrue((NativeCrypto.SSL_get_options(s) & SSL_OP_NO_TLSv1) == 0);
        assertTrue((NativeCrypto.SSL_get_options(s) & SSL_OP_NO_TLSv1_1) == 0);
        assertTrue((NativeCrypto.SSL_get_options(s) & SSL_OP_NO_TLSv1_2) == 0);

        long s2 = NativeCrypto.SSL_new(c);
        assertTrue(s != s2);
        NativeCrypto.SSL_free(s2);

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    @Test(expected = NullPointerException.class)
    public void setLocalCertsAndPrivateKey_withNullSSLShouldThrow() throws Exception {
        NativeCrypto.setLocalCertsAndPrivateKey(
                NULL, getEncodedServerCertificates(), getServerPrivateKey().getNativeRef());
    }

    @Test(expected = NullPointerException.class)
    public void setLocalCertsAndPrivateKey_withNullCertificatesShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.setLocalCertsAndPrivateKey(s, null, getServerPrivateKey().getNativeRef());
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test(expected = NullPointerException.class)
    public void setLocalCertsAndPrivateKey_withNullKeyShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.setLocalCertsAndPrivateKey(s, getEncodedServerCertificates(), null);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test
    public void setLocalCertsAndPrivateKey() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        NativeCrypto.setLocalCertsAndPrivateKey(
                s, getEncodedServerCertificates(), getServerPrivateKey().getNativeRef());

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_set1_tls_channel_id_withNullChannelShouldThrow() throws Exception {
        NativeCrypto.SSL_set1_tls_channel_id(NULL, null);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_set1_tls_channel_id_withNullKeyShouldThrow() throws Exception {
        initChannelIdKey();

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.SSL_set1_tls_channel_id(s, null);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test
    public void test_SSL_use_PrivateKey_for_tls_channel_id() throws Exception {
        initChannelIdKey();

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        // Use the key natively. This works because the initChannelIdKey method ensures that the
        // key is backed by OpenSSL.
        NativeCrypto.SSL_set1_tls_channel_id(s, CHANNEL_ID_PRIVATE_KEY.getNativeRef());

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_get_mode_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_get_mode(NULL);
    }

    @Test
    public void test_SSL_get_mode() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        assertTrue(NativeCrypto.SSL_get_mode(s) != 0);
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_set_mode_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_set_mode(NULL, 0);
    }

    @Test
    public void test_SSL_set_mode_and_clear_mode() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        // check SSL_MODE_ENABLE_FALSE_START on by default for BoringSSL
        assertEquals(SSL_MODE_ENABLE_FALSE_START,
                NativeCrypto.SSL_get_mode(s) & SSL_MODE_ENABLE_FALSE_START);
        // check SSL_MODE_CBC_RECORD_SPLITTING off by default
        assertEquals(0, NativeCrypto.SSL_get_mode(s) & SSL_MODE_CBC_RECORD_SPLITTING);

        // set SSL_MODE_ENABLE_FALSE_START on
        NativeCrypto.SSL_set_mode(s, SSL_MODE_ENABLE_FALSE_START);
        assertTrue((NativeCrypto.SSL_get_mode(s) & SSL_MODE_ENABLE_FALSE_START) != 0);
        // clear SSL_MODE_ENABLE_FALSE_START off
        NativeCrypto.SSL_clear_mode(s, SSL_MODE_ENABLE_FALSE_START);
        assertTrue((NativeCrypto.SSL_get_mode(s) & SSL_MODE_ENABLE_FALSE_START) == 0);

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_get_options_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_get_options(NULL);
    }

    @Test
    public void test_SSL_get_options() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        assertTrue(NativeCrypto.SSL_get_options(s) != 0);
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_set_options_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_set_options(NULL, 0);
    }

    @Test
    public void test_SSL_set_options() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        assertTrue((NativeCrypto.SSL_get_options(s) & SSL_OP_NO_SSLv3) == 0);
        NativeCrypto.SSL_set_options(s, SSL_OP_NO_SSLv3);
        assertTrue((NativeCrypto.SSL_get_options(s) & SSL_OP_NO_SSLv3) != 0);
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_clear_options_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_clear_options(NULL, 0);
    }

    @Test
    public void test_SSL_clear_options() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        assertTrue((NativeCrypto.SSL_get_options(s) & SSL_OP_NO_SSLv3) == 0);
        NativeCrypto.SSL_set_options(s, SSL_OP_NO_SSLv3);
        assertTrue((NativeCrypto.SSL_get_options(s) & SSL_OP_NO_SSLv3) != 0);
        NativeCrypto.SSL_clear_options(s, SSL_OP_NO_SSLv3);
        assertTrue((NativeCrypto.SSL_get_options(s) & SSL_OP_NO_SSLv3) == 0);
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_set_cipher_lists_withNullSslShouldThrow() throws Exception {
        NativeCrypto.SSL_set_cipher_lists(NULL, null);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_set_cipher_lists_withNullCiphersShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.SSL_set_cipher_lists(s, null);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test(expected = NullPointerException.class)
    public void test_SSL_set_cipher_lists_withNullCipherShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.SSL_set_cipher_lists(s, new String[] {null});
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test
    public void SSL_set_cipher_lists_withEmptyCiphersShouldSucceed() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        // Explicitly checking that the empty list is allowed.
        // b/21816861
        NativeCrypto.SSL_set_cipher_lists(s, new String[] {});

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    @Test
    public void SSL_set_cipher_lists_withIllegalCipherShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        // see OpenSSL ciphers man page
        String[] illegals = new String[] {// empty
                "",
                // never standardized
                "EXP1024-DES-CBC-SHA",
                // IDEA
                "IDEA-CBC-SHA", "IDEA-CBC-MD5"};

        for (String illegal : illegals) {
            try {
                NativeCrypto.SSL_set_cipher_lists(s, new String[] {illegal});
                fail("Exception now thrown for illegal cipher: " + illegal);
            } catch (IllegalArgumentException expected) {
                // Expected.
            }
        }

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    @Test
    public void SSL_set_cipher_lists_withValidCiphersShouldSucceed() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        List<String> ciphers = new ArrayList<>(NativeCrypto.SUPPORTED_CIPHER_SUITES_SET);
        NativeCrypto.SSL_set_cipher_lists(s, ciphers.toArray(new String[ciphers.size()]));

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_set_verify_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_set_verify(NULL, 0);
    }

    @Test
    public void test_SSL_set_verify() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        NativeCrypto.SSL_set_verify(s, SSL_VERIFY_NONE);
        NativeCrypto.SSL_set_verify(s, SSL_VERIFY_PEER);
        NativeCrypto.SSL_set_verify(s, SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
        NativeCrypto.SSL_set_verify(s, (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT));
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    private static final boolean DEBUG = false;

    public static class Hooks {
        String negotiatedCipherSuite;
        private OpenSSLKey channelIdPrivateKey;
        boolean pskEnabled;
        byte[] pskKey;
        List<String> enabledCipherSuites;

        /**
         * @throws SSLException if an error occurs creating the context.
         */
        public long getContext() throws SSLException {
            return NativeCrypto.SSL_CTX_new();
        }

        public long beforeHandshake(long context) throws SSLException {
            long s = NativeCrypto.SSL_new(context);
            // Limit cipher suites to a known set so authMethod is known.
            List<String> cipherSuites = new ArrayList<String>();
            if (enabledCipherSuites == null) {
                cipherSuites.add("ECDHE-RSA-AES128-SHA");
                if (pskEnabled) {
                    // In TLS-PSK the client indicates that PSK key exchange is desired by offering
                    // at least one PSK cipher suite.
                    cipherSuites.add(0, "PSK-AES128-CBC-SHA");
                }
            } else {
                cipherSuites.addAll(enabledCipherSuites);
            }
            NativeCrypto.setEnabledCipherSuites(
                    s, cipherSuites.toArray(new String[cipherSuites.size()]));

            if (channelIdPrivateKey != null) {
                NativeCrypto.SSL_set1_tls_channel_id(s, channelIdPrivateKey.getNativeRef());
            }
            return s;
        }
        public void configureCallbacks(
                @SuppressWarnings("unused") TestSSLHandshakeCallbacks callbacks) {}
        public void clientCertificateRequested(@SuppressWarnings("unused") long s)
                throws CertificateEncodingException, SSLException {}
        public void afterHandshake(long session, long ssl, long context, Socket socket,
                FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
            if (session != NULL) {
                negotiatedCipherSuite = NativeCrypto.SSL_SESSION_cipher(session);
                NativeCrypto.SSL_SESSION_free(session);
            }
            if (ssl != NULL) {
                try {
                    NativeCrypto.SSL_shutdown(ssl, fd, callback);
                } catch (IOException e) {
                    // Expected.
                }
                NativeCrypto.SSL_free(ssl);
            }
            if (context != NULL) {
                NativeCrypto.SSL_CTX_free(context);
            }
            if (socket != null) {
                socket.close();
            }
        }
    }

    static class TestSSLHandshakeCallbacks implements SSLHandshakeCallbacks {
        private final Socket socket;
        private final long sslNativePointer;
        private final Hooks hooks;

        TestSSLHandshakeCallbacks(Socket socket, long sslNativePointer, Hooks hooks) {
            this.socket = socket;
            this.sslNativePointer = sslNativePointer;
            this.hooks = hooks;
        }

        private long[] certificateChainRefs;
        private String authMethod;
        private boolean verifyCertificateChainCalled;

        @Override
        public void verifyCertificateChain(byte[][] certs, String authMethod)
            throws CertificateException {
            certificateChainRefs = new long[certs.length];
            for (int i = 0; i < certs.length; ++i) {
                byte[] cert = certs[i];
                try {
                    certificateChainRefs[i] = NativeCrypto.d2i_X509(cert);
                } catch (ParsingException e) {
                    throw new RuntimeException(e);
                }
            }
            this.authMethod = authMethod;
            this.verifyCertificateChainCalled = true;
        }

        private byte[] keyTypes;
        private byte[][] asn1DerEncodedX500Principals;
        private boolean clientCertificateRequestedCalled;

        @Override
        public void clientCertificateRequested(
                byte[] keyTypes, byte[][] asn1DerEncodedX500Principals)
                throws CertificateEncodingException, SSLException {
            if (DEBUG) {
                System.out.println("ssl=0x" + Long.toString(sslNativePointer, 16)
                        + " clientCertificateRequested"
                        + " keyTypes=" + Arrays.toString(keyTypes)
                        + " asn1DerEncodedX500Principals="
                        + Arrays.toString(asn1DerEncodedX500Principals));
            }
            this.keyTypes = keyTypes;
            this.asn1DerEncodedX500Principals = asn1DerEncodedX500Principals;
            this.clientCertificateRequestedCalled = true;
            if (hooks != null) {
                hooks.clientCertificateRequested(sslNativePointer);
            }
        }

        private boolean handshakeCompletedCalled;

        @Override
        public void onSSLStateChange(int type, int val) {
            if (DEBUG) {
                System.out.println(
                        "ssl=0x" + Long.toString(sslNativePointer, 16) + " onSSLStateChange");
            }
            this.handshakeCompletedCalled = true;
        }

        Socket getSocket() {
            return socket;
        }

        private boolean clientPSKKeyRequestedInvoked;
        private String clientPSKKeyRequestedIdentityHint;
        private int clientPSKKeyRequestedResult;
        private byte[] clientPSKKeyRequestedResultKey;
        private byte[] clientPSKKeyRequestedResultIdentity;

        @Override
        public int clientPSKKeyRequested(String identityHint, byte[] identity, byte[] key) {
            if (DEBUG) {
                System.out.println("ssl=0x" + Long.toString(sslNativePointer, 16)
                        + " clientPSKKeyRequested"
                        + " identityHint=" + identityHint + " identity capacity=" + identity.length
                        + " key capacity=" + key.length);
            }
            clientPSKKeyRequestedInvoked = true;
            clientPSKKeyRequestedIdentityHint = identityHint;
            if (clientPSKKeyRequestedResultKey != null) {
                System.arraycopy(clientPSKKeyRequestedResultKey, 0, key, 0,
                        clientPSKKeyRequestedResultKey.length);
            }
            if (clientPSKKeyRequestedResultIdentity != null) {
                System.arraycopy(clientPSKKeyRequestedResultIdentity, 0, identity, 0,
                        Math.min(clientPSKKeyRequestedResultIdentity.length, identity.length));
            }
            return clientPSKKeyRequestedResult;
        }

        private boolean serverPSKKeyRequestedInvoked;
        private int serverPSKKeyRequestedResult;
        private byte[] serverPSKKeyRequestedResultKey;
        private String serverPSKKeyRequestedIdentityHint;
        private String serverPSKKeyRequestedIdentity;

        @Override
        public int serverPSKKeyRequested(String identityHint, String identity, byte[] key) {
            if (DEBUG) {
                System.out.println("ssl=0x" + Long.toString(sslNativePointer, 16)
                        + " serverPSKKeyRequested"
                        + " identityHint=" + identityHint + " identity=" + identity
                        + " key capacity=" + key.length);
            }
            serverPSKKeyRequestedInvoked = true;
            serverPSKKeyRequestedIdentityHint = identityHint;
            serverPSKKeyRequestedIdentity = identity;
            if (serverPSKKeyRequestedResultKey != null) {
                System.arraycopy(serverPSKKeyRequestedResultKey, 0, key, 0,
                        serverPSKKeyRequestedResultKey.length);
            }
            return serverPSKKeyRequestedResult;
        }

        private boolean onNewSessionEstablishedInvoked;
        private boolean onNewSessionEstablishedSaveSession;
        private long onNewSessionEstablishedSessionNativePointer;

        @Override
        public void onNewSessionEstablished(long sslSessionNativePtr) {
            if (DEBUG) {
                System.out.println("ssl=0x" + Long.toString(sslNativePointer, 16)
                        + " onNewSessionCreated"
                        + " ssl=0x" + Long.toString(sslSessionNativePtr, 16));
            }
            onNewSessionEstablishedInvoked = true;

            if (onNewSessionEstablishedSaveSession) {
                NativeCrypto.SSL_SESSION_up_ref(sslSessionNativePtr);
                onNewSessionEstablishedSessionNativePointer = sslSessionNativePtr;
            }
        }

        @Override
        public long serverSessionRequested(byte[] id) {
            // TODO(nathanmittler): Implement server-side caching for TLS < 1.3
            return 0;
        }
    }

    static class ClientHooks extends Hooks {
        private String pskIdentity;

        @Override
        public void configureCallbacks(TestSSLHandshakeCallbacks callbacks) {
            super.configureCallbacks(callbacks);
            if (pskEnabled) {
                if (pskIdentity != null) {
                    // Create a NULL-terminated modified UTF-8 representation of pskIdentity.
                    byte[] b;
                    try {
                        b = pskIdentity.getBytes("UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        throw new RuntimeException("UTF-8 encoding not supported", e);
                    }
                    callbacks.clientPSKKeyRequestedResultIdentity = Arrays.copyOf(b, b.length + 1);
                }
                callbacks.clientPSKKeyRequestedResultKey = pskKey;
                callbacks.clientPSKKeyRequestedResult = (pskKey != null) ? pskKey.length : 0;
            }
        }

        @Override
        public long beforeHandshake(long c) throws SSLException {
            long s = super.beforeHandshake(c);
            if (pskEnabled) {
                NativeCrypto.set_SSL_psk_client_callback_enabled(s, true);
            }
            return s;
        }
    }

    static class ServerHooks extends Hooks {
        private final OpenSSLKey privateKey;
        private final byte[][] certificates;
        private boolean channelIdEnabled;
        private byte[] channelIdAfterHandshake;
        private Throwable channelIdAfterHandshakeException;

        private String pskIdentityHint;

        public ServerHooks() {
            this(null, null);
        }

        ServerHooks(OpenSSLKey privateKey, byte[][] certificates) {
            this.privateKey = privateKey;
            this.certificates = certificates;
        }

        @Override
        public long beforeHandshake(long c) throws SSLException {
            long s = super.beforeHandshake(c);
            if (privateKey != null && certificates != null) {
                NativeCrypto.setLocalCertsAndPrivateKey(s, certificates, privateKey.getNativeRef());
            }
            if (channelIdEnabled) {
                NativeCrypto.SSL_enable_tls_channel_id(s);
            }
            if (pskEnabled) {
                NativeCrypto.set_SSL_psk_server_callback_enabled(s, true);
                NativeCrypto.SSL_use_psk_identity_hint(s, pskIdentityHint);
            }
            NativeCrypto.SSL_set_verify(s, SSL_VERIFY_NONE);
            return s;
        }

        @Override
        public void configureCallbacks(TestSSLHandshakeCallbacks callbacks) {
            super.configureCallbacks(callbacks);
            if (pskEnabled) {
                callbacks.serverPSKKeyRequestedResultKey = pskKey;
                callbacks.serverPSKKeyRequestedResult = (pskKey != null) ? pskKey.length : 0;
            }
        }

        @Override
        public void afterHandshake(long session, long ssl, long context, Socket socket,
                FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
            if (channelIdEnabled) {
                try {
                    channelIdAfterHandshake = NativeCrypto.SSL_get_tls_channel_id(ssl);
                } catch (Exception e) {
                    channelIdAfterHandshakeException = e;
                }
            }
            super.afterHandshake(session, ssl, context, socket, fd, callback);
        }

        @Override
        public void clientCertificateRequested(long s) {
            fail("Server asked for client certificates");
        }
    }

    public static Future<TestSSLHandshakeCallbacks> handshake(final ServerSocket listener,
            final int timeout, final boolean client, final Hooks hooks,
            final byte[] alpnProtocols) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<TestSSLHandshakeCallbacks> future =
                executor.submit(new Callable<TestSSLHandshakeCallbacks>() {
                    @Override
                    public TestSSLHandshakeCallbacks call() throws Exception {
                        try {
                            @SuppressWarnings("resource")
                            // Socket needs to remain open after the handshake
                            Socket socket = (client ? new Socket(listener.getInetAddress(),
                                                              listener.getLocalPort())
                                                    : listener.accept());
                            if (timeout == -1) {
                                return new TestSSLHandshakeCallbacks(socket, 0, null);
                            }
                            FileDescriptor fd =
                                    (FileDescriptor) m_Platform_getFileDescriptor.invoke(
                                            null, socket);
                            long c = hooks.getContext();
                            long s = hooks.beforeHandshake(c);
                            TestSSLHandshakeCallbacks callback =
                                    new TestSSLHandshakeCallbacks(socket, s, hooks);
                            hooks.configureCallbacks(callback);
                            if (DEBUG) {
                                System.out.println("ssl=0x" + Long.toString(s, 16) + " handshake"
                                        + " context=0x" + Long.toString(c, 16) + " socket=" + socket
                                        + " fd=" + fd + " timeout=" + timeout
                                        + " client=" + client);
                            }
                            long session = NULL;
                            try {
                                if (client) {
                                    NativeCrypto.SSL_set_connect_state(s);
                                } else {
                                    NativeCrypto.SSL_set_accept_state(s);
                                }
                                NativeCrypto.SSL_configure_alpn(s, client, alpnProtocols);
                                NativeCrypto.SSL_do_handshake(s, fd, callback, timeout);
                                session = NativeCrypto.SSL_get1_session(s);
                                if (DEBUG) {
                                    System.out.println("ssl=0x" + Long.toString(s, 16)
                                            + " handshake"
                                            + " session=0x" + Long.toString(session, 16));
                                }
                            } finally {
                                // Ensure afterHandshake is called to free resources
                                hooks.afterHandshake(session, s, c, socket, fd, callback);
                            }
                            return callback;
                        } catch (Exception e) {
                            throw e;
                        }
                    }
                });
        executor.shutdown();
        return future;
    }

    @Test(expected = NullPointerException.class)
    public void test_SSL_do_handshake_NULL_SSL() throws Exception {
        NativeCrypto.SSL_do_handshake(NULL, null, null, 0);
    }

    @Test(expected = NullPointerException.class)
    public void test_SSL_do_handshake_withNullFdShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        NativeCrypto.SSL_set_connect_state(s);
        try {
            NativeCrypto.SSL_do_handshake(s, null, null, 0);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test(expected = NullPointerException.class)
    public void test_SSL_do_handshake_withNullShcShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        NativeCrypto.SSL_set_connect_state(s);
        try {
            NativeCrypto.SSL_do_handshake(s, INVALID_FD, null, 0);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test
    public void test_SSL_do_handshake_normal() throws Exception {
        // normal client and server case
        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new Hooks();
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(
                getServerCertificateRefs(), clientCallback.certificateChainRefs);
        assertEquals("ECDHE_RSA", clientCallback.authMethod);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback.onNewSessionEstablishedInvoked);
        assertTrue(serverCallback.onNewSessionEstablishedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
    }

    @Test
    public void test_SSL_do_handshake_reusedSession() throws Exception {
        // normal client and server case
        final ServerSocket listener = newServerSocket();

        Future<TestSSLHandshakeCallbacks> client1 = handshake(listener, 0, true, new ClientHooks() {
            @Override
            public void configureCallbacks(TestSSLHandshakeCallbacks callbacks) {
                callbacks.onNewSessionEstablishedSaveSession = true;
            }
        }, null);
        Future<TestSSLHandshakeCallbacks> server1 = handshake(listener, 0,
                false, new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
                    @Override
                    public void configureCallbacks(TestSSLHandshakeCallbacks callbacks) {
                        callbacks.onNewSessionEstablishedSaveSession = true;
                    }
                }, null);
        TestSSLHandshakeCallbacks clientCallback1 = client1.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback1 = server1.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback1.verifyCertificateChainCalled);
        assertEqualCertificateChains(
                getServerCertificateRefs(), clientCallback1.certificateChainRefs);
        assertEquals("ECDHE_RSA", clientCallback1.authMethod);
        assertFalse(serverCallback1.verifyCertificateChainCalled);
        assertFalse(clientCallback1.clientCertificateRequestedCalled);
        assertFalse(serverCallback1.clientCertificateRequestedCalled);
        assertFalse(clientCallback1.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback1.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback1.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback1.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback1.onNewSessionEstablishedInvoked);
        assertTrue(serverCallback1.onNewSessionEstablishedInvoked);
        assertTrue(clientCallback1.handshakeCompletedCalled);
        assertTrue(serverCallback1.handshakeCompletedCalled);

        final long clientSessionContext =
                clientCallback1.onNewSessionEstablishedSessionNativePointer;
        final long serverSessionContext =
                serverCallback1.onNewSessionEstablishedSessionNativePointer;

        Future<TestSSLHandshakeCallbacks> client2 = handshake(listener, 0, true, new ClientHooks() {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long sslNativePtr = super.beforeHandshake(c);
                NativeCrypto.SSL_set_session(sslNativePtr, clientSessionContext);
                return sslNativePtr;
            }
        }, null);
        Future<TestSSLHandshakeCallbacks> server2 = handshake(listener, 0,
                false, new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
                    @Override
                    public long beforeHandshake(long c) throws SSLException {
                        long sslNativePtr = super.beforeHandshake(c);
                        NativeCrypto.SSL_set_session(sslNativePtr, serverSessionContext);
                        return sslNativePtr;
                    }
                }, null);
        TestSSLHandshakeCallbacks clientCallback2 = client2.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback2 = server2.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback2.verifyCertificateChainCalled);
        assertEqualCertificateChains(
                getServerCertificateRefs(), clientCallback2.certificateChainRefs);
        assertEquals("ECDHE_RSA", clientCallback2.authMethod);
        assertFalse(serverCallback2.verifyCertificateChainCalled);
        assertFalse(clientCallback2.clientCertificateRequestedCalled);
        assertFalse(serverCallback2.clientCertificateRequestedCalled);
        assertFalse(clientCallback2.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback2.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback2.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback2.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback2.onNewSessionEstablishedInvoked);
        assertTrue(serverCallback2.onNewSessionEstablishedInvoked);
        assertTrue(clientCallback2.handshakeCompletedCalled);
        assertTrue(serverCallback2.handshakeCompletedCalled);

        NativeCrypto.SSL_SESSION_free(clientSessionContext);
        NativeCrypto.SSL_SESSION_free(serverSessionContext);
    }

    @Test
    public void test_SSL_do_handshake_optional_client_certificate() throws Exception {
        // optional client certificate case
        final ServerSocket listener = newServerSocket();

        Hooks cHooks = new Hooks() {
            @Override
            public void clientCertificateRequested(long s)
                    throws CertificateEncodingException, SSLException {
                super.clientCertificateRequested(s);
                NativeCrypto.setLocalCertsAndPrivateKey(
                        s, getEncodedClientCertificates(), getClientPrivateKey().getNativeRef());
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_set_client_CA_list(s, getCaPrincipals());
                NativeCrypto.SSL_set_verify(s, SSL_VERIFY_PEER);
                return s;
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(
                getServerCertificateRefs(), clientCallback.certificateChainRefs);
        assertEquals("ECDHE_RSA", clientCallback.authMethod);
        assertTrue(serverCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(
                getClientCertificateRefs(), serverCallback.certificateChainRefs);
        assertEquals("ECDHE_RSA", serverCallback.authMethod);

        assertTrue(clientCallback.clientCertificateRequestedCalled);
        assertNotNull(clientCallback.keyTypes);
        assertEquals(new HashSet<>(Arrays.asList("EC", "RSA")),
                SSLUtils.getSupportedClientKeyTypes(clientCallback.keyTypes));
        assertEqualPrincipals(getCaPrincipals(), clientCallback.asn1DerEncodedX500Principals);
        assertFalse(serverCallback.clientCertificateRequestedCalled);

        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback.onNewSessionEstablishedInvoked);
        assertTrue(serverCallback.onNewSessionEstablishedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
    }

    @Test
    public void test_SSL_do_handshake_missing_required_certificate() throws Exception {
        // required client certificate negative case
        final ServerSocket listener = newServerSocket();
        try {
            Hooks cHooks = new Hooks();
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
                @Override
                public long beforeHandshake(long c) throws SSLException {
                    long s = super.beforeHandshake(c);
                    NativeCrypto.SSL_set_client_CA_list(s, getCaPrincipals());
                    NativeCrypto.SSL_set_verify(
                            s, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
                    return s;
                }
            };
            @SuppressWarnings("unused")
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SSLProtocolException.class, expected.getCause().getClass());
        }
    }

    @Test
    public void test_SSL_do_handshake_client_timeout() throws Exception {
        // client timeout
        final ServerSocket listener = newServerSocket();
        Socket serverSocket = null;
        try {
            Hooks cHooks = new Hooks();
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 1, true, cHooks, null);
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, -1, false, sHooks, null);
            serverSocket = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).getSocket();
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SocketTimeoutException.class, expected.getCause().getClass());
        } finally {
            // Manually close peer socket when testing timeout
            IoUtils.closeQuietly(serverSocket);
        }
    }

    @Test
    public void test_SSL_do_handshake_server_timeout() throws Exception {
        // server timeout
        final ServerSocket listener = newServerSocket();
        Socket clientSocket = null;
        try {
            Hooks cHooks = new Hooks();
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, -1, true, cHooks, null);
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 1, false, sHooks, null);
            clientSocket = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).getSocket();
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SocketTimeoutException.class, expected.getCause().getClass());
        } finally {
            // Manually close peer socket when testing timeout
            IoUtils.closeQuietly(clientSocket);
        }
    }

    @Test
    public void test_SSL_do_handshake_with_channel_id_normal() throws Exception {
        initChannelIdKey();

        // Normal handshake with TLS Channel ID.
        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new Hooks();
        cHooks.channelIdPrivateKey = CHANNEL_ID_PRIVATE_KEY;
        // TLS Channel ID currently requires ECDHE-based key exchanges.
        cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-SHA");
        ServerHooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
        sHooks.channelIdEnabled = true;
        sHooks.enabledCipherSuites = cHooks.enabledCipherSuites;
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(
                getServerCertificateRefs(), clientCallback.certificateChainRefs);
        assertEquals("ECDHE_RSA", clientCallback.authMethod);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback.onNewSessionEstablishedInvoked);
        assertTrue(serverCallback.onNewSessionEstablishedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertNull(sHooks.channelIdAfterHandshakeException);
        assertEqualByteArrays(CHANNEL_ID, sHooks.channelIdAfterHandshake);
    }

    @Test
    public void test_SSL_do_handshake_with_channel_id_not_supported_by_server() throws Exception {
        initChannelIdKey();

        // Client tries to use TLS Channel ID but the server does not enable/offer the extension.
        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new Hooks();
        cHooks.channelIdPrivateKey = CHANNEL_ID_PRIVATE_KEY;
        // TLS Channel ID currently requires ECDHE-based key exchanges.
        cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-SHA");
        ServerHooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
        sHooks.channelIdEnabled = false;
        sHooks.enabledCipherSuites = cHooks.enabledCipherSuites;
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(
                getServerCertificateRefs(), clientCallback.certificateChainRefs);
        assertEquals("ECDHE_RSA", clientCallback.authMethod);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback.onNewSessionEstablishedInvoked);
        assertTrue(serverCallback.onNewSessionEstablishedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertNull(sHooks.channelIdAfterHandshakeException);
        assertNull(sHooks.channelIdAfterHandshake);
    }

    @Test
    public void test_SSL_do_handshake_with_channel_id_not_enabled_by_client() throws Exception {
        initChannelIdKey();

        // Client does not use TLS Channel ID when the server has the extension enabled/offered.
        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new Hooks();
        cHooks.channelIdPrivateKey = null;
        // TLS Channel ID currently requires ECDHE-based key exchanges.
        cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-SHA");
        ServerHooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
        sHooks.channelIdEnabled = true;
        sHooks.enabledCipherSuites = cHooks.enabledCipherSuites;
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(
                getServerCertificateRefs(), clientCallback.certificateChainRefs);
        assertEquals("ECDHE_RSA", clientCallback.authMethod);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback.onNewSessionEstablishedInvoked);
        assertTrue(serverCallback.onNewSessionEstablishedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertNull(sHooks.channelIdAfterHandshakeException);
        assertNull(sHooks.channelIdAfterHandshake);
    }

    @Test
    public void test_SSL_do_handshake_with_psk_normal() throws Exception {
        // normal TLS-PSK client and server case
        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
        sHooks.pskKey = cHooks.pskKey;
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertFalse(clientCallback.verifyCertificateChainCalled);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertTrue(clientCallback.onNewSessionEstablishedInvoked);
        assertTrue(serverCallback.onNewSessionEstablishedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertTrue(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertTrue(serverCallback.serverPSKKeyRequestedInvoked);
        assertContains(cHooks.negotiatedCipherSuite, "PSK");
        assertEquals(cHooks.negotiatedCipherSuite, sHooks.negotiatedCipherSuite);
        assertNull(clientCallback.clientPSKKeyRequestedIdentityHint);
        assertNull(serverCallback.serverPSKKeyRequestedIdentityHint);
        assertEquals("", serverCallback.serverPSKKeyRequestedIdentity);
    }

    @Test
    public void test_SSL_do_handshake_with_psk_with_identity_and_hint() throws Exception {
        // normal TLS-PSK client and server case where the server provides the client with a PSK
        // identity hint, and the client provides the server with a PSK identity.
        final ServerSocket listener = newServerSocket();
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
        sHooks.pskKey = cHooks.pskKey;
        sHooks.pskIdentityHint = "Some non-ASCII characters: \u00c4\u0332";
        cHooks.pskIdentity = "More non-ASCII characters: \u00f5\u044b";
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertFalse(clientCallback.verifyCertificateChainCalled);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertTrue(clientCallback.onNewSessionEstablishedInvoked);
        assertTrue(serverCallback.onNewSessionEstablishedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertTrue(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertTrue(serverCallback.serverPSKKeyRequestedInvoked);
        assertContains(cHooks.negotiatedCipherSuite, "PSK");
        assertEquals(cHooks.negotiatedCipherSuite, sHooks.negotiatedCipherSuite);
        assertEquals(sHooks.pskIdentityHint, clientCallback.clientPSKKeyRequestedIdentityHint);
        assertEquals(sHooks.pskIdentityHint, serverCallback.serverPSKKeyRequestedIdentityHint);
        assertEquals(cHooks.pskIdentity, serverCallback.serverPSKKeyRequestedIdentity);
    }

    @Test
    @SuppressWarnings("deprecation")
    public void test_SSL_do_handshake_with_psk_with_identity_and_hint_of_max_length()
            throws Exception {
        // normal TLS-PSK client and server case where the server provides the client with a PSK
        // identity hint, and the client provides the server with a PSK identity.
        final ServerSocket listener = newServerSocket();
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
        sHooks.pskKey = cHooks.pskKey;
        sHooks.pskIdentityHint = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
                + "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
        cHooks.pskIdentity = "123456789012345678901234567890123456789012345678901234567890"
                + "12345678901234567890123456789012345678901234567890123456789012345678";
        assertEquals(PSKKeyManager.MAX_IDENTITY_HINT_LENGTH_BYTES, sHooks.pskIdentityHint.length());
        assertEquals(PSKKeyManager.MAX_IDENTITY_LENGTH_BYTES, cHooks.pskIdentity.length());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertFalse(clientCallback.verifyCertificateChainCalled);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertTrue(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertTrue(serverCallback.serverPSKKeyRequestedInvoked);
        assertContains(cHooks.negotiatedCipherSuite, "PSK");
        assertEquals(cHooks.negotiatedCipherSuite, sHooks.negotiatedCipherSuite);
        assertEquals(sHooks.pskIdentityHint, clientCallback.clientPSKKeyRequestedIdentityHint);
        assertEquals(sHooks.pskIdentityHint, serverCallback.serverPSKKeyRequestedIdentityHint);
        assertEquals(cHooks.pskIdentity, serverCallback.serverPSKKeyRequestedIdentity);
    }

    @Test
    public void test_SSL_do_handshake_with_psk_key_mismatch() throws Exception {
        final ServerSocket listener = newServerSocket();
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
        sHooks.pskKey = "1, 2, 3, 3, Testing...".getBytes("UTF-8");
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        try {
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SSLProtocolException.class, expected.getCause().getClass());
        }
    }

    @Test
    public void test_SSL_do_handshake_with_psk_with_no_client_key() throws Exception {
        final ServerSocket listener = newServerSocket();
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = null;
        sHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        try {
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SSLProtocolException.class, expected.getCause().getClass());
        }
    }

    @Test
    public void test_SSL_do_handshake_with_psk_with_no_server_key() throws Exception {
        final ServerSocket listener = newServerSocket();
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
        sHooks.pskKey = null;
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        try {
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SSLProtocolException.class, expected.getCause().getClass());
        }
    }

    @Test
    @SuppressWarnings("deprecation")
    public void test_SSL_do_handshake_with_psk_key_too_long() throws Exception {
        final ServerSocket listener = newServerSocket();
        ClientHooks cHooks = new ClientHooks() {
            @Override
            public void configureCallbacks(TestSSLHandshakeCallbacks callbacks) {
                super.configureCallbacks(callbacks);
                callbacks.clientPSKKeyRequestedResult = PSKKeyManager.MAX_KEY_LENGTH_BYTES + 1;
            }
        };
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
        sHooks.pskKey = cHooks.pskKey;
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        try {
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SSLProtocolException.class, expected.getCause().getClass());
        }
    }

    @Test
    public void test_SSL_do_handshake_with_ocsp_response() throws Exception {
        final byte[] OCSP_TEST_DATA = new byte[] {1, 2, 3, 4};

        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new Hooks() {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_enable_ocsp_stapling(s);
                return s;
            }

            @Override
            public void afterHandshake(long session, long ssl, long context, Socket socket,
                    FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                assertEqualByteArrays(OCSP_TEST_DATA, NativeCrypto.SSL_get_ocsp_response(ssl));
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };

        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_set_ocsp_response(s, OCSP_TEST_DATA);
                return s;
            }
        };

        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);

        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
    }

    @Test
    public void test_SSL_do_handshake_with_sct_extension() throws Exception {
        // Fake SCT extension has a length of overall extension (unsigned 16-bit).
        // Each SCT entry has a length (unsigned 16-bit) and data.
        final byte[] SCT_TEST_DATA = new byte[] {0, 6, 0, 4, 1, 2, 3, 4};

        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new Hooks() {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_enable_signed_cert_timestamps(s);
                return s;
            }

            @Override
            public void afterHandshake(long session, long ssl, long context, Socket socket,
                    FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                assertEqualByteArrays(
                        SCT_TEST_DATA, NativeCrypto.SSL_get_signed_cert_timestamp_list(ssl));
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };

        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_set_signed_cert_timestamp_list(s, SCT_TEST_DATA);
                return s;
            }
        };

        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);

        assertTrue(clientCallback.onNewSessionEstablishedInvoked);
        assertTrue(serverCallback.onNewSessionEstablishedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
    }

    @Test
    @SuppressWarnings("deprecation")
    public void test_SSL_use_psk_identity_hint() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.SSL_use_psk_identity_hint(s, null);
            NativeCrypto.SSL_use_psk_identity_hint(s, "test");

            try {
                // 800 characters is much longer than the permitted maximum.
                StringBuilder pskIdentityHint = new StringBuilder();
                for (int i = 0; i < 160; i++) {
                    pskIdentityHint.append(" long");
                }
                assertTrue(pskIdentityHint.length() > PSKKeyManager.MAX_IDENTITY_HINT_LENGTH_BYTES);
                NativeCrypto.SSL_use_psk_identity_hint(s, pskIdentityHint.toString());
                fail();
            } catch (SSLException expected) {
                // Expected.
            }
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test(expected = NullPointerException.class)
    public void SSL_set_session_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_set_session(NULL, NULL);
    }

    @Test
    public void test_SSL_set_session() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        NativeCrypto.SSL_set_session(s, NULL);
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);

        {
            final long clientContext = NativeCrypto.SSL_CTX_new();
            final long serverContext = NativeCrypto.SSL_CTX_new();
            final ServerSocket listener = newServerSocket();
            final long[] clientSession = new long[] {NULL};
            final long[] serverSession = new long[] {NULL};
            {
                Hooks cHooks = new Hooks() {
                    @Override
                    public long getContext() throws SSLException {
                        return clientContext;
                    }
                    @Override
                    public void afterHandshake(long session, long s, long c, Socket sock,
                            FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                        super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                        clientSession[0] = session;
                    }
                };
                Hooks sHooks = new ServerHooks(
                        getServerPrivateKey(), getEncodedServerCertificates()) {
                    @Override
                    public long getContext() throws SSLException {
                        return serverContext;
                    }
                    @Override
                    public void afterHandshake(long session, long s, long c, Socket sock,
                            FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                        super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                        serverSession[0] = session;
                    }
                };
                Future<TestSSLHandshakeCallbacks> client =
                        handshake(listener, 0, true, cHooks, null);
                Future<TestSSLHandshakeCallbacks> server =
                        handshake(listener, 0, false, sHooks, null);
                client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
            assertEqualSessions(clientSession[0], serverSession[0]);
            {
                Hooks cHooks = new Hooks() {
                    @Override
                    public long getContext() throws SSLException {
                        return clientContext;
                    }
                    @Override
                    public long beforeHandshake(long c) throws SSLException {
                        long s = NativeCrypto.SSL_new(clientContext);
                        NativeCrypto.SSL_set_session(s, clientSession[0]);
                        return s;
                    }
                    @Override
                    public void afterHandshake(long session, long s, long c, Socket sock,
                            FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                        assertEqualSessions(clientSession[0], session);
                        super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                    }
                };
                Hooks sHooks = new ServerHooks(
                        getServerPrivateKey(), getEncodedServerCertificates()) {
                    @Override
                    public long getContext() throws SSLException {
                        return serverContext;
                    }
                    @Override
                    public void afterHandshake(long session, long s, long c, Socket sock,
                            FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                        assertEqualSessions(serverSession[0], session);
                        super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                    }
                };
                Future<TestSSLHandshakeCallbacks> client =
                        handshake(listener, 0, true, cHooks, null);
                Future<TestSSLHandshakeCallbacks> server =
                        handshake(listener, 0, false, sHooks, null);
                client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
            NativeCrypto.SSL_SESSION_free(clientSession[0]);
            NativeCrypto.SSL_SESSION_free(serverSession[0]);
            NativeCrypto.SSL_CTX_free(serverContext);
            NativeCrypto.SSL_CTX_free(clientContext);
        }
    }

    @Test(expected = NullPointerException.class)
    public void SSL_set_session_creation_enabled_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_set_session_creation_enabled(NULL, false);
    }

    @Test
    public void test_SSL_set_session_creation_enabled() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        NativeCrypto.SSL_set_session_creation_enabled(s, false);
        NativeCrypto.SSL_set_session_creation_enabled(s, true);
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);

        final ServerSocket listener = newServerSocket();

        // negative test case for SSL_set_session_creation_enabled(false) on client
        {
            Hooks cHooks = new Hooks() {
                @Override
                public long beforeHandshake(long c) throws SSLException {
                    long s = super.beforeHandshake(c);
                    NativeCrypto.SSL_set_session_creation_enabled(s, false);
                    return s;
                }
            };
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
            @SuppressWarnings("unused")
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
            try {
                client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                fail();
            } catch (ExecutionException expected) {
                assertEquals(SSLProtocolException.class, expected.getCause().getClass());
            }
            try {
                server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                fail();
            } catch (ExecutionException expected) {
                assertEquals(SSLProtocolException.class, expected.getCause().getClass());
            }
        }

        // negative test case for SSL_set_session_creation_enabled(false) on server
        {
            Hooks cHooks = new Hooks();
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
                @Override
                public long beforeHandshake(long c) throws SSLException {
                    long s = super.beforeHandshake(c);
                    NativeCrypto.SSL_set_session_creation_enabled(s, false);
                    return s;
                }
            };
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
            @SuppressWarnings("unused")
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
            try {
                client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                fail();
            } catch (ExecutionException expected) {
                assertEquals(SSLHandshakeException.class, expected.getCause().getClass());
            }
            try {
                server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                fail();
            } catch (ExecutionException expected) {
                assertEquals(SSLProtocolException.class, expected.getCause().getClass());
            }
        }
    }

    @Test(expected = NullPointerException.class)
    public void SSL_set_tlsext_host_name_withNullSslShouldThrow() throws Exception {
        NativeCrypto.SSL_set_tlsext_host_name(NULL, null);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_set_tlsext_host_name_withNullHostnameShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        try {
            NativeCrypto.SSL_set_tlsext_host_name(s, null);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test(expected = SSLException.class)
    public void SSL_set_tlsext_host_name_withTooLongHostnameShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        try {
            char[] longHostname = new char[256];
            Arrays.fill(longHostname, 'w');
            NativeCrypto.SSL_set_tlsext_host_name(s, new String(longHostname));
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test
    public void test_SSL_set_tlsext_host_name() throws Exception {
        final String hostname = "www.android.com";
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        assertNull(NativeCrypto.SSL_get_servername(s));
        NativeCrypto.SSL_set_tlsext_host_name(s, hostname);
        assertEquals(hostname, NativeCrypto.SSL_get_servername(s));

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);

        final ServerSocket listener = newServerSocket();

        // normal
        Hooks cHooks = new Hooks() {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_set_tlsext_host_name(s, hostname);
                return s;
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
            @Override
            public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                    SSLHandshakeCallbacks callback) throws Exception {
                assertEquals(hostname, NativeCrypto.SSL_get_servername(s));
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test
    public void test_SSL_AlpnNegotiateSuccess() throws Exception {
        final byte[] clientAlpnProtocols = new byte[] {
                8,
                'h',
                't',
                't',
                'p',
                '/',
                '1',
                '.',
                '1',
                3,
                'f',
                'o',
                'o',
                6,
                's',
                'p',
                'd',
                'y',
                '/',
                '2',
        };
        final byte[] serverAlpnProtocols = new byte[] {
                6,
                's',
                'p',
                'd',
                'y',
                '/',
                '2',
                3,
                'f',
                'o',
                'o',
                3,
                'b',
                'a',
                'r',
        };

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long ssl, long context, Socket socket,
                    FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                byte[] negotiated = NativeCrypto.SSL_get0_alpn_selected(ssl);
                assertEquals("spdy/2", new String(negotiated, "UTF-8"));
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
            @Override
            public void afterHandshake(long session, long ssl, long c, Socket sock,
                    FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                byte[] negotiated = NativeCrypto.SSL_get0_alpn_selected(ssl);
                assertEquals("spdy/2", new String(negotiated, "UTF-8"));
                super.afterHandshake(session, ssl, c, sock, fd, callback);
            }
        };

        ServerSocket listener = newServerSocket();
        Future<TestSSLHandshakeCallbacks> client =
                handshake(listener, 0, true, cHooks, clientAlpnProtocols);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, serverAlpnProtocols);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test(expected = NullPointerException.class)
    public void test_SSL_get_servername_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_get_servername(NULL);
    }

    @Test
    public void SSL_get_servername_shouldReturnNull() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        assertNull(NativeCrypto.SSL_get_servername(s));
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);

        // additional positive testing by test_SSL_set_tlsext_host_name
    }

    @Test(expected = NullPointerException.class)
    public void SSL_get0_peer_certificates_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_get0_peer_certificates(NULL);
    }

    @Test
    public void test_SSL_get0_peer_certificates() throws Exception {
        final ServerSocket listener = newServerSocket();

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                    SSLHandshakeCallbacks callback) throws Exception {
                byte[][] cc = NativeCrypto.SSL_get0_peer_certificates(s);
                assertEqualByteArrays(getEncodedServerCertificates(), cc);
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test
    public void test_SSL_cipher_names() throws Exception {
        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new Hooks();
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
        // Both legacy and standard names are accepted.
        cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-GCM-SHA256");
        sHooks.enabledCipherSuites =
                Collections.singletonList("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        // The standard name is always reported.
        assertEquals("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", cHooks.negotiatedCipherSuite);
        assertEquals("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", sHooks.negotiatedCipherSuite);
    }

    private final byte[] BYTES = new byte[] {2, -3, 5, 127, 0, -128};

    @Test(expected = NullPointerException.class)
    public void SSL_read_withNullSslShouldThrow() throws Exception {
        NativeCrypto.SSL_read(NULL, null, null, null, 0, 0, 0);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_read_withNullFdShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.SSL_read(s, null, DUMMY_CB, null, 0, 0, 0);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test(expected = NullPointerException.class)
    public void SSL_read_withNullCallbacksShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.SSL_read(s, INVALID_FD, null, null, 0, 0, 0);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test(expected = NullPointerException.class)
    public void SSL_read_withNullBytesShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.SSL_read(s, INVALID_FD, DUMMY_CB, null, 0, 0, 0);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test(expected = SSLException.class)
    public void SSL_read_beforeHandshakeShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.SSL_read(s, INVALID_FD, DUMMY_CB, new byte[1], 0, 1, 0);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test
    public void test_SSL_read() throws Exception {
        final ServerSocket listener = newServerSocket();

        // normal case
        {
            Hooks cHooks = new Hooks() {
                @Override
                public void afterHandshake(long session, long s, long c, Socket sock,
                        FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                    byte[] in = new byte[256];
                    assertEquals(BYTES.length,
                            NativeCrypto.SSL_read(s, fd, callback, in, 0, BYTES.length, 0));
                    for (int i = 0; i < BYTES.length; i++) {
                        assertEquals(BYTES[i], in[i]);
                    }
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            };
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
                @Override
                public void afterHandshake(long session, long s, long c, Socket sock,
                        FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                    NativeCrypto.SSL_write(s, fd, callback, BYTES, 0, BYTES.length, 0);
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            };
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }

        // timeout case
        try {
            Hooks cHooks = new Hooks() {
                @Override
                public void afterHandshake(long session, long s, long c, Socket sock,
                        FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                    NativeCrypto.SSL_read(s, fd, callback, new byte[1], 0, 1, 1);
                    fail();
                }
            };
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
                @Override
                public void afterHandshake(long session, long s, long c, Socket sock,
                        FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                    NativeCrypto.SSL_read(s, fd, callback, new byte[1], 0, 1, 0);
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            };
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
            @SuppressWarnings("unused")
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SocketTimeoutException.class, expected.getCause().getClass());
        }
    }

    @Test(expected = NullPointerException.class)
    public void SSL_write_withNullSslShouldThrow() throws Exception {
        NativeCrypto.SSL_write(NULL, null, null, null, 0, 0, 0);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_write_withNullFdShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.SSL_write(s, null, DUMMY_CB, null, 0, 1, 0);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test(expected = NullPointerException.class)
    public void SSL_write_withNullCallbacksShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.SSL_write(s, INVALID_FD, null, null, 0, 1, 0);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test(expected = NullPointerException.class)
    public void SSL_write_withNullBytesShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.SSL_write(s, INVALID_FD, DUMMY_CB, null, 0, 1, 0);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test(expected = SSLException.class)
    public void SSL_write_beforeHandshakeShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            NativeCrypto.SSL_write(s, INVALID_FD, DUMMY_CB, new byte[1], 0, 1, 0);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test
    public void SSL_interrupt_withNullShouldSucceed() {
        // SSL_interrupt is a rare case that tolerates a null SSL argument
        NativeCrypto.SSL_interrupt(NULL);
    }

    @Test
    public void SSL_interrupt_withoutHandshakeShouldSucceed() throws Exception {
        // also works without handshaking
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        NativeCrypto.SSL_interrupt(s);
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    @Test
    public void test_SSL_interrupt() throws Exception {
        final ServerSocket listener = newServerSocket();

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                    SSLHandshakeCallbacks callback) throws Exception {
                NativeCrypto.SSL_read(s, fd, callback, new byte[1], 0, 1, 0);
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates()) {
            @Override
            public void afterHandshake(long session, final long s, long c, Socket sock,
                    FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                new Thread() {
                    @Override
                    public void run() {
                        try {
                            Thread.sleep(1000);
                            NativeCrypto.SSL_interrupt(s);
                        } catch (Exception e) {
                            // Expected.
                        }
                    }
                }
                        .start();
                assertEquals(-1, NativeCrypto.SSL_read(s, fd, callback, new byte[1], 0, 1, 0));
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    private static abstract class SSLSessionWrappedTask {
        public abstract void run(long sslSession) throws Exception;
    }

    private void wrapWithSSLSession(SSLSessionWrappedTask task) throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        try {
            task.run(s);
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    @Test
    public void SSL_shutdown_withNullFdShouldSucceed() throws Exception {
        // We tolerate a null FileDescriptor
        wrapWithSSLSession(new SSLSessionWrappedTask() {
            @Override
            public void run(long sslSession) throws Exception {
                NativeCrypto.SSL_shutdown(sslSession, null, DUMMY_CB);
            }
        });
    }

    @Test(expected = NullPointerException.class)
    public void SSL_shutdown_withNullCallbacksShouldThrow() throws Exception {
        wrapWithSSLSession(new SSLSessionWrappedTask() {
            @Override
            public void run(long sslSession) throws Exception {
                NativeCrypto.SSL_shutdown(sslSession, INVALID_FD, null);
            }
        });
    }

    @Test
    public void SSL_shutdown_withNullSslShouldSucceed() throws Exception {
        // SSL_shutdown is a rare case that tolerates a null SSL argument
        NativeCrypto.SSL_shutdown(NULL, INVALID_FD, DUMMY_CB);
    }

    @Test(expected = SocketException.class)
    public void SSL_shutdown_beforeHandshakeShouldThrow() throws Exception {
        // handshaking not yet performed
        wrapWithSSLSession(new SSLSessionWrappedTask() {
            @Override
            public void run(long sslSession) throws Exception {
                NativeCrypto.SSL_shutdown(sslSession, INVALID_FD, DUMMY_CB);
            }
        });

        // positively tested elsewhere because handshake uses use
        // SSL_shutdown to ensure SSL_SESSIONs are reused.
    }

    @Test(expected = NullPointerException.class)
    public void SSL_free_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_free(NULL);
    }

    @Test
    public void test_SSL_free() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        NativeCrypto.SSL_free(NativeCrypto.SSL_new(c));
        NativeCrypto.SSL_CTX_free(c);

        // additional positive testing elsewhere because handshake
        // uses use SSL_free to cleanup in afterHandshake.
    }

    @Test(expected = NullPointerException.class)
    public void SSL_SESSION_session_id_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_SESSION_session_id(NULL);
    }

    @Test
    public void test_SSL_SESSION_session_id() throws Exception {
        final ServerSocket listener = newServerSocket();

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                    SSLHandshakeCallbacks callback) throws Exception {
                byte[] id = NativeCrypto.SSL_SESSION_session_id(session);
                assertNotNull(id);
                assertEquals(32, id.length);
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_SESSION_get_time_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_SESSION_get_time(NULL);
    }

    @Test
    public void test_SSL_SESSION_get_time() throws Exception {
        final ServerSocket listener = newServerSocket();

        {
            Hooks cHooks = new Hooks() {
                @Override
                public void afterHandshake(long session, long s, long c, Socket sock,
                        FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                    long time = NativeCrypto.SSL_SESSION_get_time(session);
                    assertTrue(time != 0);
                    assertTrue(time < System.currentTimeMillis());
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            };
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }
    }

    @Test(expected = NullPointerException.class)
    public void SSL_SESSION_get_version_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_SESSION_get_version(NULL);
    }

    @Test
    public void test_SSL_SESSION_get_version() throws Exception {
        final ServerSocket listener = newServerSocket();

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                    SSLHandshakeCallbacks callback) throws Exception {
                String v = NativeCrypto.SSL_SESSION_get_version(session);
                assertTrue(StandardNames.SSL_SOCKET_PROTOCOLS.contains(v));
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test(expected = NullPointerException.class)
    public void SSL_SESSION_cipher_withNullShouldThrow() throws Exception {
        NativeCrypto.SSL_SESSION_cipher(NULL);
    }

    @Test
    public void test_SSL_SESSION_cipher() throws Exception {
        final ServerSocket listener = newServerSocket();

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                    SSLHandshakeCallbacks callback) throws Exception {
                String nativeCipher = NativeCrypto.SSL_SESSION_cipher(session);
                String javaCipher = NativeCrypto.cipherSuiteFromJava(nativeCipher);
                assertTrue(NativeCrypto.SUPPORTED_CIPHER_SUITES_SET.contains(javaCipher));
                // SSL_SESSION_cipher should return a standard name rather than an OpenSSL name.
                assertTrue(nativeCipher.startsWith("TLS_"));
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    /*
     * Additional positive testing elsewhere because handshake
     * uses use SSL_SESSION_free to cleanup in afterHandshake.
     */
    @Test(expected = NullPointerException.class)
    public void SSL_SESSION_free_NullArgument() throws Exception {
        NativeCrypto.SSL_SESSION_free(NULL);
    }

    @Test(expected = NullPointerException.class)
    public void i2d_SSL_Session_WithNullSessionShouldThrow() throws Exception {
        NativeCrypto.i2d_SSL_SESSION(NULL);
    }

    @Test
    public void test_i2d_SSL_SESSION() throws Exception {
        final ServerSocket listener = newServerSocket();

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                    SSLHandshakeCallbacks callback) throws Exception {
                byte[] b = NativeCrypto.i2d_SSL_SESSION(session);
                assertNotNull(b);
                long session2 = NativeCrypto.d2i_SSL_SESSION(b);
                assertTrue(session2 != NULL);

                // Make sure d2i_SSL_SESSION retores SSL_SESSION_cipher value http://b/7091840
                assertTrue(NativeCrypto.SSL_SESSION_cipher(session2) != null);
                assertEquals(NativeCrypto.SSL_SESSION_cipher(session),
                        NativeCrypto.SSL_SESSION_cipher(session2));

                NativeCrypto.SSL_SESSION_free(session2);
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getEncodedServerCertificates());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test(expected = NullPointerException.class)
    public void d2i_SSL_SESSION_NullArgument() throws Exception {
        NativeCrypto.d2i_SSL_SESSION(null);
    }

    @Test(expected = IOException.class)
    public void d2i_SSL_SESSION_EmptyArgument() throws Exception {
        NativeCrypto.d2i_SSL_SESSION(new byte[0]);
    }

    @Test(expected = IOException.class)
    public void d2i_SSL_SESSION_InvalidArgument() throws Exception {
        NativeCrypto.d2i_SSL_SESSION(new byte[1]);
    }

    @Test
    public void test_X509_NAME_hashes() {
        // ensure these hash functions are stable over time since the
        // /system/etc/security/cacerts CA filenames have to be
        // consistent with the output.
        X500Principal name = new X500Principal("CN=localhost");
        assertEquals(-1372642656, NativeCrypto.X509_NAME_hash(name)); // SHA1
        assertEquals(-1626170662, NativeCrypto.X509_NAME_hash_old(name)); // MD5
    }

    @Test
    public void test_RAND_bytes_Success() throws Exception {
        byte[] output = new byte[128];
        NativeCrypto.RAND_bytes(output);

        boolean isZero = true;
        for (byte anOutput : output) {
            isZero &= (anOutput == 0);
        }

        assertFalse("Random output was zero. This is a very low probability event (1 in 2^128) "
                        + "and probably indicates an error.",
                isZero);
    }

    @Test(expected = RuntimeException.class)
    public void RAND_bytes_withNullShouldThrow() throws Exception {
        NativeCrypto.RAND_bytes(null);
    }

    @Test(expected = NullPointerException.class)
    public void test_EVP_get_digestbyname_NullArgument() throws Exception {
        NativeCrypto.EVP_get_digestbyname(null);
    }

    @Test(expected = RuntimeException.class)
    public void EVP_get_digestbyname_withEmptyShouldThrow() throws Exception {
        NativeCrypto.EVP_get_digestbyname("");
    }

    @Test(expected = RuntimeException.class)
    public void EVP_get_digestbyname_withInvalidDigestShouldThrow() throws Exception {
        NativeCrypto.EVP_get_digestbyname("foobar");
    }

    @Test
    public void test_EVP_get_digestbyname() throws Exception {
        assertTrue(NativeCrypto.EVP_get_digestbyname("sha256") != NULL);
    }

    @Test
    public void test_EVP_DigestSignInit() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);

        KeyPair kp = kpg.generateKeyPair();
        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) kp.getPrivate();

        NativeRef.EVP_PKEY pkey;
        pkey = new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_new_RSA(
                privKey.getModulus().toByteArray(), privKey.getPublicExponent().toByteArray(),
                privKey.getPrivateExponent().toByteArray(), privKey.getPrimeP().toByteArray(),
                privKey.getPrimeQ().toByteArray(), privKey.getPrimeExponentP().toByteArray(),
                privKey.getPrimeExponentQ().toByteArray(),
                privKey.getCrtCoefficient().toByteArray()));
        assertNotNull(pkey);

        final NativeRef.EVP_MD_CTX ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        long evpMd = NativeCrypto.EVP_get_digestbyname("sha256");
        NativeCrypto.EVP_DigestSignInit(ctx, evpMd, pkey);

        try {
            NativeCrypto.EVP_DigestSignInit(ctx, 0, pkey);
            fail();
        } catch (RuntimeException expected) {
            // Expected.
        }

        try {
            NativeCrypto.EVP_DigestSignInit(ctx, evpMd, null);
            fail();
        } catch (RuntimeException expected) {
            // Expected.
        }
    }

    @Test(expected = NullPointerException.class)
    public void get_RSA_private_params_NullArgument() throws Exception {
        NativeCrypto.get_RSA_private_params(null);
    }

    @Test(expected = RuntimeException.class)
    public void test_get_RSA_private_params() throws Exception {
        // Test getting params for the wrong kind of key.
        final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
        assertFalse(groupCtx == NULL);
        NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupCtx);
        NativeRef.EVP_PKEY ctx = new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(group));
        NativeCrypto.get_RSA_private_params(ctx);
    }

    @Test(expected = NullPointerException.class)
    public void get_RSA_public_params_NullArgument() throws Exception {
        NativeCrypto.get_RSA_public_params(null);
    }

    @Test(expected = RuntimeException.class)
    public void test_get_RSA_public_params() throws Exception {
        // Test getting params for the wrong kind of key.
        final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
        assertFalse(groupCtx == NULL);
        NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupCtx);
        NativeRef.EVP_PKEY ctx = new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(group));
        NativeCrypto.get_RSA_public_params(ctx);
    }

    @Test(expected = NullPointerException.class)
    public void RSA_size_NullArgumentFailure() throws Exception {
        NativeCrypto.RSA_size(null);
    }

    @Test(expected = NullPointerException.class)
    public void RSA_private_encrypt_NullArgumentFailure() throws Exception {
        NativeCrypto.RSA_private_encrypt(0, new byte[0], new byte[0], null, 0);
    }

    @Test(expected = NullPointerException.class)
    public void RSA_private_decrypt_NullArgumentFailure() throws Exception {
        NativeCrypto.RSA_private_decrypt(0, new byte[0], new byte[0], null, 0);
    }

    @Test(expected = NullPointerException.class)
    public void test_RSA_public_encrypt_NullArgumentFailure() throws Exception {
        NativeCrypto.RSA_public_encrypt(0, new byte[0], new byte[0], null, 0);
    }

    @Test(expected = NullPointerException.class)
    public void test_RSA_public_decrypt_NullArgumentFailure() throws Exception {
        NativeCrypto.RSA_public_decrypt(0, new byte[0], new byte[0], null, 0);
    }

    /*
     * Test vector generation:
     * openssl rand -hex 16
     */
    private static final byte[] AES_128_KEY = new byte[] {
            (byte) 0x3d,
            (byte) 0x4f,
            (byte) 0x89,
            (byte) 0x70,
            (byte) 0xb1,
            (byte) 0xf2,
            (byte) 0x75,
            (byte) 0x37,
            (byte) 0xf4,
            (byte) 0x0a,
            (byte) 0x39,
            (byte) 0x29,
            (byte) 0x8a,
            (byte) 0x41,
            (byte) 0x55,
            (byte) 0x5f,
    };

    @Test
    public void testEC_GROUP() throws Exception {
        /* Test using NIST's P-256 curve */
        check_EC_GROUP("prime256v1",
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
                "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
                "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 1L);
    }

    private void check_EC_GROUP(String name, String pStr, String aStr, String bStr, String xStr,
            String yStr, String nStr, long hLong) throws Exception {
        long groupRef = NativeCrypto.EC_GROUP_new_by_curve_name(name);
        assertFalse(groupRef == NULL);
        NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupRef);

        // prime
        BigInteger p = new BigInteger(pStr, 16);
        // first coefficient
        BigInteger a = new BigInteger(aStr, 16);
        // second coefficient
        BigInteger b = new BigInteger(bStr, 16);
        // x affine coordinate of generator
        BigInteger x = new BigInteger(xStr, 16);
        // y affine coordinate of generator
        BigInteger y = new BigInteger(yStr, 16);
        // order of the generator
        BigInteger n = new BigInteger(nStr, 16);
        // cofactor of generator
        BigInteger h = BigInteger.valueOf(hLong);

        byte[][] pab = NativeCrypto.EC_GROUP_get_curve(group);
        assertEquals(3, pab.length);

        BigInteger p2 = new BigInteger(pab[0]);
        assertEquals(p, p2);

        BigInteger a2 = new BigInteger(pab[1]);
        assertEquals(a, a2);

        BigInteger b2 = new BigInteger(pab[2]);
        assertEquals(b, b2);

        NativeRef.EC_POINT point =
                new NativeRef.EC_POINT(NativeCrypto.EC_GROUP_get_generator(group));

        byte[][] xy = NativeCrypto.EC_POINT_get_affine_coordinates(group, point);
        assertEquals(2, xy.length);

        BigInteger x2 = new BigInteger(xy[0]);
        assertEquals(x, x2);

        BigInteger y2 = new BigInteger(xy[1]);
        assertEquals(y, y2);

        BigInteger n2 = new BigInteger(NativeCrypto.EC_GROUP_get_order(group));
        assertEquals(n, n2);

        BigInteger h2 = new BigInteger(NativeCrypto.EC_GROUP_get_cofactor(group));
        assertEquals(h, h2);

        NativeRef.EVP_PKEY key1 = new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(group));
        NativeRef.EC_GROUP groupTmp = new NativeRef.EC_GROUP(NativeCrypto.EC_KEY_get1_group(key1));
        assertEquals(NativeCrypto.EC_GROUP_get_curve_name(group),
                NativeCrypto.EC_GROUP_get_curve_name(groupTmp));
    }

    @Test(expected = NullPointerException.class)
    public void test_EC_KEY_get_private_key_NullArgumentFailure() throws Exception {
        NativeCrypto.EC_KEY_get_private_key(null);
    }

    @Test(expected = NullPointerException.class)
    public void test_EC_KEY_get_public_key_NullArgumentFailure() throws Exception {
        NativeCrypto.EC_KEY_get_public_key(null);
    }

    @Test
    public void test_ECKeyPairGenerator_CurvesAreValid() throws Exception {
        OpenSSLECKeyPairGenerator.assertCurvesAreValid();
    }

    @Test
    public void test_ECDH_compute_key_null_key_Failure() throws Exception {
        final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
        assertFalse(groupCtx == NULL);
        NativeRef.EC_GROUP groupRef = new NativeRef.EC_GROUP(groupCtx);
        NativeRef.EVP_PKEY pkey1Ref =
                new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(groupRef));
        NativeRef.EVP_PKEY pkey2Ref =
                new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(groupRef));

        byte[] out = new byte[128];
        int outOffset = 0;
        // Assert that the method under test works fine with the two
        // non-null keys
        NativeCrypto.ECDH_compute_key(out, outOffset, pkey1Ref, pkey2Ref);

        // Assert that it fails when only the first key is null
        try {
            NativeCrypto.ECDH_compute_key(out, outOffset, null, pkey2Ref);
            fail();
        } catch (NullPointerException expected) {
            // Expected.
        }

        // Assert that it fails when only the second key is null
        try {
            NativeCrypto.ECDH_compute_key(out, outOffset, pkey1Ref, null);
            fail();
        } catch (NullPointerException expected) {
            // Expected.
        }
    }

    @Test(expected = NullPointerException.class)
    public void EVP_CipherInit_ex_withNullCtxShouldThrow() throws Exception {
        final long evpCipher = NativeCrypto.EVP_get_cipherbyname("aes-128-ecb");
        NativeCrypto.EVP_CipherInit_ex(null, evpCipher, null, null, true);
    }

    @Test
    public void test_EVP_CipherInit_ex_Null_Failure() throws Exception {
        final NativeRef.EVP_CIPHER_CTX ctx =
                new NativeRef.EVP_CIPHER_CTX(NativeCrypto.EVP_CIPHER_CTX_new());
        final long evpCipher = NativeCrypto.EVP_get_cipherbyname("aes-128-ecb");

        /* Initialize encrypting. */
        NativeCrypto.EVP_CipherInit_ex(ctx, evpCipher, null, null, true);
        NativeCrypto.EVP_CipherInit_ex(ctx, NULL, null, null, true);

        /* Initialize decrypting. */
        NativeCrypto.EVP_CipherInit_ex(ctx, evpCipher, null, null, false);
        NativeCrypto.EVP_CipherInit_ex(ctx, NULL, null, null, false);
    }

    @Test
    public void test_EVP_CipherInit_ex_Success() throws Exception {
        final NativeRef.EVP_CIPHER_CTX ctx =
                new NativeRef.EVP_CIPHER_CTX(NativeCrypto.EVP_CIPHER_CTX_new());
        final long evpCipher = NativeCrypto.EVP_get_cipherbyname("aes-128-ecb");
        NativeCrypto.EVP_CipherInit_ex(ctx, evpCipher, AES_128_KEY, null, true);
    }

    @Test
    public void test_EVP_CIPHER_iv_length() throws Exception {
        long aes128ecb = NativeCrypto.EVP_get_cipherbyname("aes-128-ecb");
        assertEquals(0, NativeCrypto.EVP_CIPHER_iv_length(aes128ecb));

        long aes128cbc = NativeCrypto.EVP_get_cipherbyname("aes-128-cbc");
        assertEquals(16, NativeCrypto.EVP_CIPHER_iv_length(aes128cbc));
    }

    @Test
    public void test_OpenSSLKey_toJava() throws Exception {
        OpenSSLKey key1;

        BigInteger e = BigInteger.valueOf(65537);
        key1 = new OpenSSLKey(NativeCrypto.RSA_generate_key_ex(1024, e.toByteArray()));
        assertTrue(key1.getPublicKey() instanceof RSAPublicKey);

        final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
        assertFalse(groupCtx == NULL);
        NativeRef.EC_GROUP group1 = new NativeRef.EC_GROUP(groupCtx);
        key1 = new OpenSSLKey(NativeCrypto.EC_KEY_generate_key(group1));
        assertTrue(key1.getPublicKey() instanceof ECPublicKey);
    }

    @Test
    public void test_create_BIO_InputStream() throws Exception {
        byte[] actual = "Test".getBytes("UTF-8");
        ByteArrayInputStream is = new ByteArrayInputStream(actual);

        @SuppressWarnings("resource")
        OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
        try {
            byte[] buffer = new byte[1024];
            int numRead = NativeCrypto.BIO_read(bis.getBioContext(), buffer);
            assertEquals(actual.length, numRead);
            assertEquals(Arrays.toString(actual),
                    Arrays.toString(Arrays.copyOfRange(buffer, 0, numRead)));
        } finally {
            bis.release();
        }
    }

    @Test
    public void test_create_BIO_OutputStream() throws Exception {
        byte[] actual = "Test".getBytes("UTF-8");
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        long ctx = NativeCrypto.create_BIO_OutputStream(os);
        try {
            NativeCrypto.BIO_write(ctx, actual, 0, actual.length);
            assertEquals(actual.length, os.size());
            assertEquals(Arrays.toString(actual), Arrays.toString(os.toByteArray()));
        } finally {
            NativeCrypto.BIO_free_all(ctx);
        }
    }

    @Test
    public void test_get_ocsp_single_extension() throws Exception {
        final String OCSP_SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.5";

        byte[] ocspResponse = readTestFile("ocsp-response.der");
        byte[] expected = readTestFile("ocsp-response-sct-extension.der");
        OpenSSLX509Certificate certificate =
                OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert-ct-poisoned.pem"));
        OpenSSLX509Certificate issuer =
                OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem"));

        byte[] extension = NativeCrypto.get_ocsp_single_extension(
                ocspResponse, OCSP_SCT_LIST_OID, certificate.getContext(), issuer.getContext());

        assertEqualByteArrays(expected, extension);
    }

    private static long getRawPkeyCtxForEncrypt() throws Exception {
        return NativeCrypto.EVP_PKEY_encrypt_init(getRsaPkey(generateRsaKey()));
    }

    private static NativeRef.EVP_PKEY_CTX getPkeyCtxForEncrypt() throws Exception {
        return new NativeRef.EVP_PKEY_CTX(getRawPkeyCtxForEncrypt());
    }

    @Test(expected = NullPointerException.class)
    public void EVP_PKEY_encrypt_NullKeyArgument() throws Exception {
        NativeCrypto.EVP_PKEY_encrypt(null, new byte[128], 0, new byte[128], 0, 128);
    }

    @Test(expected = NullPointerException.class)
    public void EVP_PKEY_encrypt_NullOutputArgument() throws Exception {
        NativeCrypto.EVP_PKEY_encrypt(getPkeyCtxForEncrypt(), null, 0, new byte[128], 0, 128);
    }

    @Test(expected = NullPointerException.class)
    public void EVP_PKEY_encrypt_NullInputArgument() throws Exception {
        NativeCrypto.EVP_PKEY_encrypt(getPkeyCtxForEncrypt(), new byte[128], 0, null, 0, 128);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void EVP_PKEY_encrypt_OutputIndexOOBUnder() throws Exception {
        NativeCrypto.EVP_PKEY_encrypt(
                getPkeyCtxForEncrypt(), new byte[128], -1, new byte[128], 0, 128);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void EVP_PKEY_encrypt_OutputIndexOOBOver() throws Exception {
        NativeCrypto.EVP_PKEY_encrypt(
                getPkeyCtxForEncrypt(), new byte[128], 129, new byte[128], 0, 128);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void EVP_PKEY_encrypt_InputIndexOOBUnder() throws Exception {
        NativeCrypto.EVP_PKEY_encrypt(
                getPkeyCtxForEncrypt(), new byte[128], 0, new byte[128], -1, 128);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void EVP_PKEY_encrypt_InputIndexOOBOver() throws Exception {
        NativeCrypto.EVP_PKEY_encrypt(
                getPkeyCtxForEncrypt(), new byte[128], 0, new byte[128], 128, 128);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void EVP_PKEY_encrypt_InputLengthNegative() throws Exception {
        NativeCrypto.EVP_PKEY_encrypt(
                getPkeyCtxForEncrypt(), new byte[128], 0, new byte[128], 0, -1);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void EVP_PKEY_encrypt_InputIndexLengthOOB() throws Exception {
        NativeCrypto.EVP_PKEY_encrypt(
                getPkeyCtxForEncrypt(), new byte[128], 0, new byte[128], 100, 29);
    }

    @Test(expected = NullPointerException.class)
    public void EVP_PKEY_CTX_set_rsa_mgf1_md_NullPkeyCtx() throws Exception {
        NativeCrypto.EVP_PKEY_CTX_set_rsa_mgf1_md(NULL, EvpMdRef.SHA256.EVP_MD);
    }

    @Test(expected = NullPointerException.class)
    public void EVP_PKEY_CTX_set_rsa_mgf1_md_NullMdCtx() throws Exception {
        long pkeyCtx = getRawPkeyCtxForEncrypt();
        NativeRef.EVP_PKEY_CTX holder = new NativeRef.EVP_PKEY_CTX(pkeyCtx);
        NativeCrypto.EVP_PKEY_CTX_set_rsa_mgf1_md(pkeyCtx, NULL);
    }

    @Test(expected = NullPointerException.class)
    public void EVP_PKEY_CTX_set_rsa_oaep_md_NullPkeyCtx() throws Exception {
        NativeCrypto.EVP_PKEY_CTX_set_rsa_oaep_md(NULL, EvpMdRef.SHA256.EVP_MD);
    }

    @Test(expected = NullPointerException.class)
    public void EVP_PKEY_CTX_set_rsa_oaep_md_NullMdCtx() throws Exception {
        long pkeyCtx = getRawPkeyCtxForEncrypt();
        new NativeRef.EVP_PKEY_CTX(pkeyCtx);
        NativeCrypto.EVP_PKEY_CTX_set_rsa_oaep_md(pkeyCtx, NULL);
    }

    @Test(expected = ParsingException.class)
    public void d2i_X509_InvalidFailure() throws Exception {
        NativeCrypto.d2i_X509(new byte[1]);
    }

    private static void assertContains(String actualValue, String expectedSubstring) {
        if (actualValue == null) {
            return;
        }
        if (actualValue.contains(expectedSubstring)) {
            return;
        }
        fail("\"" + actualValue + "\" does not contain \"" + expectedSubstring + "\"");
    }

    private static ServerSocket newServerSocket() throws IOException {
        return new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    }
}
