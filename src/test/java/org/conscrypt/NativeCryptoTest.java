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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
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

import junit.framework.TestCase;
import libcore.io.IoUtils;
import libcore.java.security.StandardNames;
import libcore.java.security.TestKeyStore;

import org.conscrypt.NativeCrypto.SSLHandshakeCallbacks;
import static org.conscrypt.NativeConstants.SSL_MODE_CBC_RECORD_SPLITTING;
import static org.conscrypt.NativeConstants.SSL_MODE_HANDSHAKE_CUTTHROUGH;

public class NativeCryptoTest extends TestCase {
    /** Corresponds to the native test library "libjavacoretests.so" */
    public static final String TEST_ENGINE_ID = "javacoretests";

    private static final long NULL = 0;
    private static final FileDescriptor INVALID_FD = new FileDescriptor();
    private static final SSLHandshakeCallbacks DUMMY_CB
            = new TestSSLHandshakeCallbacks(null, 0, null);

    private static final long TIMEOUT_SECONDS = 5;

    private static OpenSSLKey SERVER_PRIVATE_KEY;
    private static OpenSSLX509Certificate[] SERVER_CERTIFICATES_HOLDER;
    private static long[] SERVER_CERTIFICATES;
    private static OpenSSLKey CLIENT_PRIVATE_KEY;
    private static OpenSSLX509Certificate[] CLIENT_CERTIFICATES_HOLDER;
    private static long[] CLIENT_CERTIFICATES;
    private static byte[][] CA_PRINCIPALS;
    private static OpenSSLKey CHANNEL_ID_PRIVATE_KEY;
    private static byte[] CHANNEL_ID;

    @Override
    protected void tearDown() throws Exception {
        assertEquals(0, NativeCrypto.ERR_peek_last_error());
    }

    private static OpenSSLKey getServerPrivateKey() {
        initCerts();
        return SERVER_PRIVATE_KEY;
    }

    private static long[] getServerCertificates() {
        initCerts();
        return SERVER_CERTIFICATES;
    }

    private static OpenSSLKey getClientPrivateKey() {
        initCerts();
        return CLIENT_PRIVATE_KEY;
    }

    private static long[] getClientCertificates() {
        initCerts();
        return CLIENT_CERTIFICATES;
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
            PrivateKeyEntry serverPrivateKeyEntry
                    = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
            SERVER_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(serverPrivateKeyEntry.getPrivateKey());
            SERVER_CERTIFICATES_HOLDER = encodeCertificateList(
                    serverPrivateKeyEntry.getCertificateChain());
            SERVER_CERTIFICATES = getCertificateReferences(SERVER_CERTIFICATES_HOLDER);

            PrivateKeyEntry clientPrivateKeyEntry
                    = TestKeyStore.getClientCertificate().getPrivateKey("RSA", "RSA");
            CLIENT_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(clientPrivateKeyEntry.getPrivateKey());
            CLIENT_CERTIFICATES_HOLDER = encodeCertificateList(
                    clientPrivateKeyEntry.getCertificateChain());
            CLIENT_CERTIFICATES = getCertificateReferences(CLIENT_CERTIFICATES_HOLDER);

            KeyStore ks = TestKeyStore.getClient().keyStore;
            String caCertAlias = ks.aliases().nextElement();
            X509Certificate certificate = (X509Certificate) ks.getCertificate(caCertAlias);
            X500Principal principal = certificate.getIssuerX500Principal();
            CA_PRINCIPALS = new byte[][] { principal.getEncoded() };
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
        CHANNEL_ID_PRIVATE_KEY = new OpenSSLECPrivateKey(
                new ECPrivateKeySpec(s, openSslSpec.getECParameterSpec())).getOpenSSLKey();

        // Channel ID is the concatenation of the X and Y coordinates of the public key.
        CHANNEL_ID = new BigInteger(
                "702b07871fd7955c320b26f15e244e47eed60272124c92b9ebecf0b42f90069b" +
                        "ab53592ebfeb4f167dbf3ce61513afb0e354c479b1c1b69874fa471293494f77",
                16).toByteArray();
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

    public void test_EVP_PKEY_cmp() throws Exception {
        try {
            NativeCrypto.EVP_PKEY_cmp(null, null);
            fail("Should throw NullPointerException when arguments are NULL");
        } catch (NullPointerException expected) {
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);

        KeyPair kp1 = kpg.generateKeyPair();
        RSAPrivateCrtKey privKey1 = (RSAPrivateCrtKey) kp1.getPrivate();

        KeyPair kp2 = kpg.generateKeyPair();
        RSAPrivateCrtKey privKey2 = (RSAPrivateCrtKey) kp2.getPrivate();

        NativeRef.EVP_PKEY pkey1, pkey1_copy, pkey2;
        pkey1 = new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_new_RSA(
                privKey1.getModulus().toByteArray(),
                privKey1.getPublicExponent().toByteArray(),
                privKey1.getPrivateExponent().toByteArray(),
                privKey1.getPrimeP().toByteArray(),
                privKey1.getPrimeQ().toByteArray(),
                privKey1.getPrimeExponentP().toByteArray(),
                privKey1.getPrimeExponentQ().toByteArray(),
                privKey1.getCrtCoefficient().toByteArray()));
        assertNotSame(NULL, pkey1);

        pkey1_copy = new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_new_RSA(
                privKey1.getModulus().toByteArray(),
                privKey1.getPublicExponent().toByteArray(),
                privKey1.getPrivateExponent().toByteArray(),
                privKey1.getPrimeP().toByteArray(),
                privKey1.getPrimeQ().toByteArray(),
                privKey1.getPrimeExponentP().toByteArray(),
                privKey1.getPrimeExponentQ().toByteArray(),
                privKey1.getCrtCoefficient().toByteArray()));
        assertNotSame(NULL, pkey1_copy);

        pkey2 = new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_new_RSA(
                privKey2.getModulus().toByteArray(),
                privKey2.getPublicExponent().toByteArray(),
                privKey2.getPrivateExponent().toByteArray(),
                privKey2.getPrimeP().toByteArray(),
                privKey2.getPrimeQ().toByteArray(),
                privKey2.getPrimeExponentP().toByteArray(),
                privKey2.getPrimeExponentQ().toByteArray(),
                privKey2.getCrtCoefficient().toByteArray()));
        assertNotSame(NULL, pkey2);

        try {
            NativeCrypto.EVP_PKEY_cmp(pkey1, null);
            fail("Should throw NullPointerException when arguments are NULL");
        } catch (NullPointerException expected) {
        }

        try {
            NativeCrypto.EVP_PKEY_cmp(null, null);
            fail("Should throw NullPointerException when arguments are NULL");
        } catch (NullPointerException expected) {
        }

        assertEquals("Same keys should be the equal", 1,
                NativeCrypto.EVP_PKEY_cmp(pkey1, pkey1));

        assertEquals("Same keys should be the equal", 1,
                NativeCrypto.EVP_PKEY_cmp(pkey1, pkey1_copy));

        assertEquals("Different keys should not be equal", 0,
                NativeCrypto.EVP_PKEY_cmp(pkey1, pkey2));
    }

    public void test_SSL_CTX_new() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        assertTrue(c != NULL);
        long c2 = NativeCrypto.SSL_CTX_new();
        assertTrue(c != c2);
        NativeCrypto.SSL_CTX_free(c);
        NativeCrypto.SSL_CTX_free(c2);
    }

    public void test_SSL_CTX_free() throws Exception {
        try {
            NativeCrypto.SSL_CTX_free(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        NativeCrypto.SSL_CTX_free(NativeCrypto.SSL_CTX_new());
    }

    public void test_SSL_CTX_set_session_id_context() throws Exception {
        byte[] empty = new byte[0];
        try {
            NativeCrypto.SSL_CTX_set_session_id_context(NULL, empty);
            fail();
        } catch (NullPointerException expected) {
        }
        long c = NativeCrypto.SSL_CTX_new();
        try {
            NativeCrypto.SSL_CTX_set_session_id_context(c, null);
            fail();
        } catch (NullPointerException expected) {
        }
        NativeCrypto.SSL_CTX_set_session_id_context(c, empty);
        NativeCrypto.SSL_CTX_set_session_id_context(c, new byte[32]);
        try {
            NativeCrypto.SSL_CTX_set_session_id_context(c, new byte[33]);
        } catch (IllegalArgumentException expected) {
        }
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_new() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        assertTrue(s != NULL);
        assertTrue((NativeCrypto.SSL_get_options(s) & NativeConstants.SSL_OP_NO_SSLv3) == 0);
        assertTrue((NativeCrypto.SSL_get_options(s) & NativeConstants.SSL_OP_NO_TLSv1) == 0);
        assertTrue((NativeCrypto.SSL_get_options(s) & NativeConstants.SSL_OP_NO_TLSv1_1) == 0);
        assertTrue((NativeCrypto.SSL_get_options(s) & NativeConstants.SSL_OP_NO_TLSv1_2) == 0);

        long s2 = NativeCrypto.SSL_new(c);
        assertTrue(s != s2);
        NativeCrypto.SSL_free(s2);

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_use_certificate() throws Exception {
        try {
            NativeCrypto.SSL_use_certificate(NULL, null);
            fail();
        } catch (NullPointerException expected) {
        }

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        try {
            NativeCrypto.SSL_use_certificate(s, null);
            fail();
        } catch (NullPointerException expected) {
        }

        NativeCrypto.SSL_use_certificate(s, getServerCertificates());

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_use_PrivateKey_for_tls_channel_id() throws Exception {
        initChannelIdKey();

        try {
            NativeCrypto.SSL_set1_tls_channel_id(NULL, null);
            fail();
        } catch (NullPointerException expected) {
        }

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        try {
            NativeCrypto.SSL_set1_tls_channel_id(s, null);
            fail();
        } catch (NullPointerException expected) {
        }

        // Use the key natively. This works because the initChannelIdKey method ensures that the
        // key is backed by OpenSSL.
        NativeCrypto.SSL_set1_tls_channel_id(s, CHANNEL_ID_PRIVATE_KEY.getNativeRef());

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_use_PrivateKey() throws Exception {
        try {
            NativeCrypto.SSL_use_PrivateKey(NULL, null);
            fail();
        } catch (NullPointerException expected) {
        }

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        try {
            NativeCrypto.SSL_use_PrivateKey(s, null);
            fail();
        } catch (NullPointerException expected) {
        }

        NativeCrypto.SSL_use_PrivateKey(s, getServerPrivateKey().getNativeRef());

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_check_private_key_null() throws Exception {
        try {
            NativeCrypto.SSL_check_private_key(NULL);
            fail();
        } catch (NullPointerException expected) {
        }
    }

    public void test_SSL_check_private_key_no_key_no_cert() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        // neither private or certificate set
        try {
            NativeCrypto.SSL_check_private_key(s);
            fail();
        } catch (SSLException expected) {
        }

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_check_private_key_cert_then_key() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        // first certificate, then private
        NativeCrypto.SSL_use_certificate(s, getServerCertificates());

        try {
            NativeCrypto.SSL_check_private_key(s);
            fail();
        } catch (SSLException expected) {
        }

        NativeCrypto.SSL_use_PrivateKey(s, getServerPrivateKey().getNativeRef());
        NativeCrypto.SSL_check_private_key(s);

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }
    public void test_SSL_check_private_key_key_then_cert() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        // first private, then certificate
        NativeCrypto.SSL_use_PrivateKey(s, getServerPrivateKey().getNativeRef());

        try {
            NativeCrypto.SSL_check_private_key(s);
            fail();
        } catch (SSLException expected) {
        }

        NativeCrypto.SSL_use_certificate(s, getServerCertificates());
        NativeCrypto.SSL_check_private_key(s);

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_get_mode() throws Exception {
        try {
            NativeCrypto.SSL_get_mode(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        assertTrue(NativeCrypto.SSL_get_mode(s) != 0);
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_set_mode_and_clear_mode() throws Exception {
        try {
            NativeCrypto.SSL_set_mode(NULL, 0);
            fail();
        } catch (NullPointerException expected) {
        }

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        // check SSL_MODE_HANDSHAKE_CUTTHROUGH off by default
        assertEquals(0, NativeCrypto.SSL_get_mode(s) & SSL_MODE_HANDSHAKE_CUTTHROUGH);
        // check SSL_MODE_CBC_RECORD_SPLITTING off by default
        assertEquals(0, NativeCrypto.SSL_get_mode(s) & SSL_MODE_CBC_RECORD_SPLITTING);

        // set SSL_MODE_HANDSHAKE_CUTTHROUGH on
        NativeCrypto.SSL_set_mode(s, SSL_MODE_HANDSHAKE_CUTTHROUGH);
        assertTrue((NativeCrypto.SSL_get_mode(s)
                & SSL_MODE_HANDSHAKE_CUTTHROUGH) != 0);
        // clear SSL_MODE_HANDSHAKE_CUTTHROUGH off
        NativeCrypto.SSL_clear_mode(s, SSL_MODE_HANDSHAKE_CUTTHROUGH);
        assertTrue((NativeCrypto.SSL_get_mode(s)
                    & SSL_MODE_HANDSHAKE_CUTTHROUGH) == 0);

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_get_options() throws Exception {
        try {
            NativeCrypto.SSL_get_options(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        assertTrue(NativeCrypto.SSL_get_options(s) != 0);
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_set_options() throws Exception {
        try {
            NativeCrypto.SSL_set_options(NULL, 0);
            fail();
        } catch (NullPointerException expected) {
        }

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        assertTrue((NativeCrypto.SSL_get_options(s) & NativeConstants.SSL_OP_NO_SSLv3) == 0);
        NativeCrypto.SSL_set_options(s, NativeConstants.SSL_OP_NO_SSLv3);
        assertTrue((NativeCrypto.SSL_get_options(s) & NativeConstants.SSL_OP_NO_SSLv3) != 0);
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_clear_options() throws Exception {
        try {
            NativeCrypto.SSL_clear_options(NULL, 0);
            fail();
        } catch (NullPointerException expected) {
        }

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        assertTrue((NativeCrypto.SSL_get_options(s) & NativeConstants.SSL_OP_NO_SSLv3) == 0);
        NativeCrypto.SSL_set_options(s, NativeConstants.SSL_OP_NO_SSLv3);
        assertTrue((NativeCrypto.SSL_get_options(s) & NativeConstants.SSL_OP_NO_SSLv3) != 0);
        NativeCrypto.SSL_clear_options(s, NativeConstants.SSL_OP_NO_SSLv3);
        assertTrue((NativeCrypto.SSL_get_options(s) & NativeConstants.SSL_OP_NO_SSLv3) == 0);
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_set_cipher_lists() throws Exception {
        try {
            NativeCrypto.SSL_set_cipher_lists(NULL, null);
            fail("Exception not thrown for null ssl and null list");
        } catch (NullPointerException expected) {
        }

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        try {
            NativeCrypto.SSL_set_cipher_lists(s, null);
            fail("Exception not thrown for null list");
        } catch (NullPointerException expected) {
        }

        // Explicitly checking that the empty list is allowed.
        // b/21816861
        NativeCrypto.SSL_set_cipher_lists(s, new String[]{});

        try {
            NativeCrypto.SSL_set_cipher_lists(s, new String[] { null });
            fail("Exception not thrown for list with null element");
        } catch (NullPointerException expected) {
        }

        // see OpenSSL ciphers man page
        String[] illegals = new String[] {
            // empty
            "",
            // never standardized
            "EXP1024-DES-CBC-SHA", "EXP1024-RC4-SHA", "DHE-DSS-RC4-SHA",
            // IDEA
            "IDEA-CBC-SHA", "IDEA-CBC-MD5"
        };

        for (String illegal : illegals) {
            try {
                NativeCrypto.SSL_set_cipher_lists(s, new String[] { illegal });
                fail("Exception now thrown for illegal cipher: " + illegal);
            } catch (IllegalArgumentException expected) {
            }
        }

        List<String> ciphers
                = new ArrayList<String>(NativeCrypto.OPENSSL_TO_STANDARD_CIPHER_SUITES.keySet());
        NativeCrypto.SSL_set_cipher_lists(s, ciphers.toArray(new String[ciphers.size()]));

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_set_verify() throws Exception {
        try {
            NativeCrypto.SSL_set_verify(NULL, 0);
            fail();
        } catch (NullPointerException expected) {
        }

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        NativeCrypto.SSL_set_verify(s, NativeCrypto.SSL_VERIFY_NONE);
        NativeCrypto.SSL_set_verify(s, NativeCrypto.SSL_VERIFY_PEER);
        NativeCrypto.SSL_set_verify(s, NativeCrypto.SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
        NativeCrypto.SSL_set_verify(s, (NativeCrypto.SSL_VERIFY_PEER
                                        | NativeCrypto.SSL_VERIFY_FAIL_IF_NO_PEER_CERT));
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    private static final boolean DEBUG = false;

    public static class Hooks {
        protected String negotiatedCipherSuite;
        private OpenSSLKey channelIdPrivateKey;
        protected boolean pskEnabled;
        protected byte[] pskKey;
        protected List<String> enabledCipherSuites;

        /**
         * @throws SSLException
         */
        public long getContext() throws SSLException {
            return NativeCrypto.SSL_CTX_new();
        }
        public long beforeHandshake(long context) throws SSLException {
            long s = NativeCrypto.SSL_new(context);
            // without this SSL_set_cipher_lists call the tests were
            // negotiating DHE-RSA-AES256-SHA by default which had
            // very slow ephemeral RSA key generation
            List<String> cipherSuites = new ArrayList<String>();
            if (enabledCipherSuites == null) {
                cipherSuites.add("RC4-MD5");
                if (pskEnabled) {
                    // In TLS-PSK the client indicates that PSK key exchange is desired by offering
                    // at least one PSK cipher suite.
                    cipherSuites.add(0, "PSK-AES128-CBC-SHA");
                }
            } else {
                cipherSuites.addAll(enabledCipherSuites);
            }
            NativeCrypto.SSL_set_cipher_lists(
                    s, cipherSuites.toArray(new String[cipherSuites.size()]));

            if (channelIdPrivateKey != null) {
                NativeCrypto.SSL_set1_tls_channel_id(s, channelIdPrivateKey.getNativeRef());
            }
            return s;
        }
        public void configureCallbacks(
                @SuppressWarnings("unused") TestSSLHandshakeCallbacks callbacks) {}
        public void clientCertificateRequested(@SuppressWarnings("unused") long s) {}
        public void afterHandshake(long session, long ssl, long context,
                                   Socket socket, FileDescriptor fd,
                                   SSLHandshakeCallbacks callback)
                throws Exception {
            if (session != NULL) {
                negotiatedCipherSuite = NativeCrypto.SSL_SESSION_cipher(session);
                NativeCrypto.SSL_SESSION_free(session);
            }
            if (ssl != NULL) {
                try {
                    NativeCrypto.SSL_shutdown(ssl, fd, callback);
                } catch (IOException e) {
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

    public static class TestSSLHandshakeCallbacks implements SSLHandshakeCallbacks {
        private final Socket socket;
        private final long sslNativePointer;
        private final Hooks hooks;

        public TestSSLHandshakeCallbacks(Socket socket,
                                         long sslNativePointer,
                                         Hooks hooks) {
            this.socket = socket;
            this.sslNativePointer = sslNativePointer;
            this.hooks = hooks;
        }

        public long[] certificateChainRefs;
        public String authMethod;
        public boolean verifyCertificateChainCalled;

        @Override
        public void verifyCertificateChain(long sslSessionNativePtr, long[] certChainRefs,
                String authMethod) throws CertificateException {
            if (DEBUG) {
                System.out.println("ssl=0x" + Long.toString(sslNativePointer, 16)
                                   + " verifyCertificateChain"
                                   + " sessionPtr=0x" + Long.toString(sslSessionNativePtr, 16)
                                   + " asn1DerEncodedCertificateChain="
                                   + Arrays.toString(certChainRefs)
                                   + " authMethod=" + authMethod);
            }
            this.certificateChainRefs = certChainRefs;
            this.authMethod = authMethod;
            this.verifyCertificateChainCalled = true;
        }

        public byte[] keyTypes;
        public byte[][] asn1DerEncodedX500Principals;
        public boolean clientCertificateRequestedCalled;

        @Override
        public void clientCertificateRequested(byte[] keyTypes,
                                               byte[][] asn1DerEncodedX500Principals) {
            if (DEBUG) {
                System.out.println("ssl=0x" + Long.toString(sslNativePointer, 16)
                                   + " clientCertificateRequested"
                                   + " keyTypes=" + keyTypes
                                   + " asn1DerEncodedX500Principals="
                                   + asn1DerEncodedX500Principals);
            }
            this.keyTypes = keyTypes;
            this.asn1DerEncodedX500Principals = asn1DerEncodedX500Principals;
            this.clientCertificateRequestedCalled = true;
            if (hooks != null ) {
                hooks.clientCertificateRequested(sslNativePointer);
            }
        }

        public boolean handshakeCompletedCalled;

        @Override
        public void onSSLStateChange(long sslSessionNativePtr, int type, int val) {
            if (DEBUG) {
                System.out.println("ssl=0x" + Long.toString(sslNativePointer, 16)
                                   + " onSSLStateChange");
            }
            this.handshakeCompletedCalled = true;
        }

        public Socket getSocket() {
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
                                   + " identityHint=" + identityHint
                                   + " identity capacity=" + identity.length
                                   + " key capacity=" + key.length);
            }
            clientPSKKeyRequestedInvoked = true;
            clientPSKKeyRequestedIdentityHint = identityHint;
            if (clientPSKKeyRequestedResultKey != null) {
                System.arraycopy(
                        clientPSKKeyRequestedResultKey, 0,
                        key, 0,
                        clientPSKKeyRequestedResultKey.length);
            }
            if (clientPSKKeyRequestedResultIdentity != null) {
                System.arraycopy(
                        clientPSKKeyRequestedResultIdentity, 0,
                        identity, 0,
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
                                   + " identityHint=" + identityHint
                                   + " identity=" + identity
                                   + " key capacity=" + key.length);
            }
            serverPSKKeyRequestedInvoked = true;
            serverPSKKeyRequestedIdentityHint = identityHint;
            serverPSKKeyRequestedIdentity = identity;
            if (serverPSKKeyRequestedResultKey != null) {
                System.arraycopy(
                        serverPSKKeyRequestedResultKey, 0,
                        key, 0,
                        serverPSKKeyRequestedResultKey.length);
            }
            return serverPSKKeyRequestedResult;
        }
    }

    public static class ClientHooks extends Hooks {
        protected String pskIdentity;

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
                    callbacks.clientPSKKeyRequestedResultIdentity =
                            Arrays.copyOf(b, b.length + 1);
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

    public static class ServerHooks extends Hooks {
        private final OpenSSLKey privateKey;
        private final long[] certificates;
        private boolean channelIdEnabled;
        private byte[] channelIdAfterHandshake;
        private Throwable channelIdAfterHandshakeException;

        protected String pskIdentityHint;

        public ServerHooks() {
            this(null, null);
        }

        public ServerHooks(OpenSSLKey privateKey, long[] certificates) {
            this.privateKey = privateKey;
            this.certificates = certificates;
        }

        @Override
        public long beforeHandshake(long c) throws SSLException {
            long s = super.beforeHandshake(c);
            if (privateKey != null) {
                NativeCrypto.SSL_use_PrivateKey(s, privateKey.getNativeRef());
            }
            if (certificates != null) {
                NativeCrypto.SSL_use_certificate(s, certificates);
            }
            if (channelIdEnabled) {
                NativeCrypto.SSL_enable_tls_channel_id(s);
            }
            if (pskEnabled) {
                NativeCrypto.set_SSL_psk_server_callback_enabled(s, true);
                NativeCrypto.SSL_use_psk_identity_hint(s, pskIdentityHint);
            }
            NativeCrypto.SSL_set_verify(s, NativeCrypto.SSL_VERIFY_NONE);
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
        public void afterHandshake(long session, long ssl, long context,
                                   Socket socket, FileDescriptor fd,
                                   SSLHandshakeCallbacks callback)
                throws Exception {
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
            final int timeout, final boolean client, final Hooks hooks, final byte[] npnProtocols,
            final byte[] alpnProtocols) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<TestSSLHandshakeCallbacks> future = executor.submit(
                new Callable<TestSSLHandshakeCallbacks>() {
            @Override public TestSSLHandshakeCallbacks call() throws Exception {
                @SuppressWarnings("resource") // Socket needs to remain open after the handshake
                Socket socket = (client
                                 ? new Socket(listener.getInetAddress(),
                                              listener.getLocalPort())
                                 : listener.accept());
                if (timeout == -1) {
                    return new TestSSLHandshakeCallbacks(socket, 0, null);
                }
                FileDescriptor fd = socket.getFileDescriptor$();
                long c = hooks.getContext();
                long s = hooks.beforeHandshake(c);
                TestSSLHandshakeCallbacks callback
                        = new TestSSLHandshakeCallbacks(socket, s, hooks);
                hooks.configureCallbacks(callback);
                if (DEBUG) {
                    System.out.println("ssl=0x" + Long.toString(s, 16)
                                       + " handshake"
                                       + " context=0x" + Long.toString(c, 16)
                                       + " socket=" + socket
                                       + " fd=" + fd
                                       + " timeout=" + timeout
                                       + " client=" + client);
                }
                long session = NULL;
                try {
                    session = NativeCrypto.SSL_do_handshake(s, fd, callback, timeout, client,
                                                            npnProtocols, alpnProtocols);
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
            }
        });
        executor.shutdown();
        return future;
    }

    public void test_SSL_do_handshake_NULL_SSL() throws Exception {
        try {
            NativeCrypto.SSL_do_handshake(NULL, null, null, 0, false, null, null);
            fail();
        } catch (NullPointerException expected) {
        }
    }

    public void test_SSL_do_handshake_null_args() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);

        try {
            NativeCrypto.SSL_do_handshake(s, null, null, 0, true, null, null);
            fail();
        } catch (NullPointerException expected) {
        }

        try {
            NativeCrypto.SSL_do_handshake(s, INVALID_FD, null, 0, true, null, null);
            fail();
        } catch (NullPointerException expected) {
        }

        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);
    }

    public void test_SSL_do_handshake_normal() throws Exception {
        // normal client and server case
        final ServerSocket listener = new ServerSocket(0);
        Hooks cHooks = new Hooks();
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(getServerCertificates(),
                                     clientCallback.certificateChainRefs);
        assertEquals("RSA", clientCallback.authMethod);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
    }

    public void test_SSL_do_handshake_optional_client_certificate() throws Exception {
        // optional client certificate case
        final ServerSocket listener = new ServerSocket(0);

        Hooks cHooks = new Hooks() {
            @Override
            public void clientCertificateRequested(long s) {
                super.clientCertificateRequested(s);
                NativeCrypto.SSL_use_PrivateKey(s, getClientPrivateKey().getNativeRef());
                NativeCrypto.SSL_use_certificate(s, getClientCertificates());
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_set_client_CA_list(s, getCaPrincipals());
                NativeCrypto.SSL_set_verify(s, NativeCrypto.SSL_VERIFY_PEER);
                return s;
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(getServerCertificates(),
                                     clientCallback.certificateChainRefs);
        assertEquals("RSA", clientCallback.authMethod);
        assertTrue(serverCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(getClientCertificates(),
                serverCallback.certificateChainRefs);
        assertEquals("RSA", serverCallback.authMethod);

        assertTrue(clientCallback.clientCertificateRequestedCalled);
        assertNotNull(clientCallback.keyTypes);
        assertEquals(new HashSet<String>(Arrays.asList("EC", "RSA")),
                SSLParametersImpl.getSupportedClientKeyTypes(clientCallback.keyTypes));
        assertEqualPrincipals(getCaPrincipals(),
                              clientCallback.asn1DerEncodedX500Principals);
        assertFalse(serverCallback.clientCertificateRequestedCalled);

        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);

        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
    }

    public void test_SSL_do_handshake_missing_required_certificate() throws Exception {
        // required client certificate negative case
        final ServerSocket listener = new ServerSocket(0);
        try {
            Hooks cHooks = new Hooks();
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
                @Override
                public long beforeHandshake(long c) throws SSLException {
                    long s = super.beforeHandshake(c);
                    NativeCrypto.SSL_set_client_CA_list(s, getCaPrincipals());
                    NativeCrypto.SSL_set_verify(s,
                                                NativeCrypto.SSL_VERIFY_PEER
                                                | NativeCrypto.SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
                    return s;
                }
            };
            @SuppressWarnings("unused")
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null,
                    null);
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null,
                    null);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SSLProtocolException.class, expected.getCause().getClass());
        }
    }

    /**
     * Usually if a RuntimeException is thrown by the
     * clientCertificateRequestedCalled callback, the caller sees it
     * during the call to NativeCrypto_SSL_do_handshake.  However, IIS
     * does not request client certs until after the initial
     * handshake. It does an SSL renegotiation, which means we need to
     * be able to deliver the callback's exception in cases like
     * SSL_read, SSL_write, and SSL_shutdown.
     */
    public void test_SSL_do_handshake_clientCertificateRequested_throws_after_renegotiate()
            throws Exception {
        final ServerSocket listener = new ServerSocket(0);

        Hooks cHooks = new Hooks() {
            @Override
            public long beforeHandshake(long context) throws SSLException {
                long s = super.beforeHandshake(context);
                NativeCrypto.SSL_clear_mode(s, SSL_MODE_HANDSHAKE_CUTTHROUGH);
                return s;
            }
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                    throws Exception {
                NativeCrypto.SSL_read(s, fd, callback, new byte[1], 0, 1, 0);
                fail();
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
            @Override
            public void clientCertificateRequested(long s) {
                super.clientCertificateRequested(s);
                throw new RuntimeException("expected");
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                    throws Exception {
                try {
                    NativeCrypto.SSL_set_verify(s, NativeCrypto.SSL_VERIFY_PEER);
                    NativeCrypto.SSL_set_options(
                            s, NativeConstants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
                    NativeCrypto.SSL_renegotiate(s);
                    NativeCrypto.SSL_write(s, fd, callback, new byte[] { 42 }, 0, 1,
                                           (int) ((TIMEOUT_SECONDS * 1000) / 2));
                } catch (IOException expected) {
                } finally {
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        try {
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            if (!"expected".equals(e.getCause().getMessage())) {
                throw e;
            }
        }
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    public void test_SSL_do_handshake_client_timeout() throws Exception {
        // client timeout
        final ServerSocket listener = new ServerSocket(0);
        Socket serverSocket = null;
        try {
            Hooks cHooks = new Hooks();
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 1, true, cHooks, null,
                    null);
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, -1, false, sHooks, null,
                    null);
            serverSocket = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).getSocket();
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            if (SocketTimeoutException.class != expected.getCause().getClass()) {
                expected.printStackTrace();
            }
            assertEquals(SocketTimeoutException.class, expected.getCause().getClass());
        } finally {
            // Manually close peer socket when testing timeout
            IoUtils.closeQuietly(serverSocket);
        }
    }

    public void test_SSL_do_handshake_server_timeout() throws Exception {
        // server timeout
        final ServerSocket listener = new ServerSocket(0);
        Socket clientSocket = null;
        try {
            Hooks cHooks = new Hooks();
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, -1, true, cHooks, null, null);
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 1, false, sHooks, null, null);
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

    public void test_SSL_do_handshake_with_channel_id_normal() throws Exception {
        initChannelIdKey();

        // Normal handshake with TLS Channel ID.
        final ServerSocket listener = new ServerSocket(0);
        Hooks cHooks = new Hooks();
        cHooks.channelIdPrivateKey = CHANNEL_ID_PRIVATE_KEY;
        // TLS Channel ID currently requires ECDHE-based key exchanges.
        cHooks.enabledCipherSuites = Arrays.asList(new String[] {"ECDHE-RSA-AES128-SHA"});
        ServerHooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
        sHooks.channelIdEnabled = true;
        sHooks.enabledCipherSuites = cHooks.enabledCipherSuites;
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(getServerCertificates(),
                                     clientCallback.certificateChainRefs);
        assertEquals("ECDHE_RSA", clientCallback.authMethod);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertNull(sHooks.channelIdAfterHandshakeException);
        assertEqualByteArrays(CHANNEL_ID, sHooks.channelIdAfterHandshake);
    }

    public void test_SSL_do_handshake_with_channel_id_not_supported_by_server() throws Exception {
        initChannelIdKey();

        // Client tries to use TLS Channel ID but the server does not enable/offer the extension.
        final ServerSocket listener = new ServerSocket(0);
        Hooks cHooks = new Hooks();
        cHooks.channelIdPrivateKey = CHANNEL_ID_PRIVATE_KEY;
        // TLS Channel ID currently requires ECDHE-based key exchanges.
        cHooks.enabledCipherSuites = Arrays.asList(new String[] {"ECDHE-RSA-AES128-SHA"});
        ServerHooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
        sHooks.channelIdEnabled = false;
        sHooks.enabledCipherSuites = cHooks.enabledCipherSuites;
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(getServerCertificates(),
                                     clientCallback.certificateChainRefs);
        assertEquals("ECDHE_RSA", clientCallback.authMethod);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertNull(sHooks.channelIdAfterHandshakeException);
        assertNull(sHooks.channelIdAfterHandshake);
    }

    public void test_SSL_do_handshake_with_channel_id_not_enabled_by_client() throws Exception {
        initChannelIdKey();

        // Client does not use TLS Channel ID when the server has the extension enabled/offered.
        final ServerSocket listener = new ServerSocket(0);
        Hooks cHooks = new Hooks();
        cHooks.channelIdPrivateKey = null;
        // TLS Channel ID currently requires ECDHE-based key exchanges.
        cHooks.enabledCipherSuites = Arrays.asList(new String[] {"ECDHE-RSA-AES128-SHA"});
        ServerHooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
        sHooks.channelIdEnabled = true;
        sHooks.enabledCipherSuites = cHooks.enabledCipherSuites;
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(getServerCertificates(),
                                     clientCallback.certificateChainRefs);
        assertEquals("ECDHE_RSA", clientCallback.authMethod);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertNull(sHooks.channelIdAfterHandshakeException);
        assertNull(sHooks.channelIdAfterHandshake);
    }

    public void test_SSL_do_handshake_with_psk_normal() throws Exception {
        // normal TLS-PSK client and server case
        final ServerSocket listener = new ServerSocket(0);
        Hooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
        sHooks.pskKey = cHooks.pskKey;
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
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
        assertNull(clientCallback.clientPSKKeyRequestedIdentityHint);
        assertNull(serverCallback.serverPSKKeyRequestedIdentityHint);
        assertEquals("", serverCallback.serverPSKKeyRequestedIdentity);
    }

    public void test_SSL_do_handshake_with_psk_with_identity_and_hint() throws Exception {
        // normal TLS-PSK client and server case where the server provides the client with a PSK
        // identity hint, and the client provides the server with a PSK identity.
        final ServerSocket listener = new ServerSocket(0);
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
        sHooks.pskKey = cHooks.pskKey;
        sHooks.pskIdentityHint = "Some non-ASCII characters: \u00c4\u0332";
        cHooks.pskIdentity = "More non-ASCII characters: \u00f5\u044b";
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
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

    public void test_SSL_do_handshake_with_psk_with_identity_and_hint_of_max_length()
            throws Exception {
        // normal TLS-PSK client and server case where the server provides the client with a PSK
        // identity hint, and the client provides the server with a PSK identity.
        final ServerSocket listener = new ServerSocket(0);
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
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
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

    public void test_SSL_do_handshake_with_psk_key_mismatch() throws Exception {
        final ServerSocket listener = new ServerSocket(0);
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
        sHooks.pskKey = "1, 2, 3, 3, Testing...".getBytes("UTF-8");
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        try {
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SSLProtocolException.class, expected.getCause().getClass());
        }
    }

    public void test_SSL_do_handshake_with_psk_with_no_client_key() throws Exception {
        final ServerSocket listener = new ServerSocket(0);
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = null;
        sHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        try {
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SSLProtocolException.class, expected.getCause().getClass());
        }
    }

    public void test_SSL_do_handshake_with_psk_with_no_server_key() throws Exception {
        final ServerSocket listener = new ServerSocket(0);
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
        sHooks.pskKey = null;
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        try {
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SSLProtocolException.class, expected.getCause().getClass());
        }
    }

    public void test_SSL_do_handshake_with_psk_key_too_long() throws Exception {
        final ServerSocket listener = new ServerSocket(0);
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
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        try {
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SSLProtocolException.class, expected.getCause().getClass());
        }
    }

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
            }
        } finally {
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }
    }

    public void test_SSL_set_session() throws Exception {
        try {
            NativeCrypto.SSL_set_session(NULL, NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        {
            long c = NativeCrypto.SSL_CTX_new();
            long s = NativeCrypto.SSL_new(c);
            NativeCrypto.SSL_set_session(s, NULL);
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }

        {
            final long clientContext = NativeCrypto.SSL_CTX_new();
            final long serverContext = NativeCrypto.SSL_CTX_new();
            final ServerSocket listener = new ServerSocket(0);
            final long[] clientSession = new long[] { NULL };
            final long[] serverSession = new long[] { NULL };
            {
                Hooks cHooks = new Hooks() {
                    @Override
                    public long getContext() throws SSLException {
                        return clientContext;
                    }
                    @Override
                    public void afterHandshake(long session, long s, long c,
                                               Socket sock, FileDescriptor fd,
                                               SSLHandshakeCallbacks callback)
                            throws Exception {
                        super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                        clientSession[0] = session;
                    }
                };
                Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
                    @Override
                    public long getContext() throws SSLException {
                        return serverContext;
                    }
                    @Override
                    public void afterHandshake(long session, long s, long c,
                                               Socket sock, FileDescriptor fd,
                                               SSLHandshakeCallbacks callback)
                            throws Exception {
                        super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                        serverSession[0] = session;
                    }
                };
                Future<TestSSLHandshakeCallbacks> client
                        = handshake(listener, 0, true, cHooks, null, null);
                Future<TestSSLHandshakeCallbacks> server
                        = handshake(listener, 0, false, sHooks, null, null);
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
                    public void afterHandshake(long session, long s, long c,
                                               Socket sock, FileDescriptor fd,
                                               SSLHandshakeCallbacks callback)
                            throws Exception {
                        assertEqualSessions(clientSession[0], session);
                        super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                    }
                };
                Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
                    @Override
                    public long getContext() throws SSLException {
                        return serverContext;
                    }
                    @Override
                    public void afterHandshake(long session, long s, long c,
                                               Socket sock, FileDescriptor fd,
                                               SSLHandshakeCallbacks callback)
                            throws Exception {
                        assertEqualSessions(serverSession[0], session);
                        super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                    }
                };
                Future<TestSSLHandshakeCallbacks> client
                        = handshake(listener, 0, true, cHooks, null, null);
                Future<TestSSLHandshakeCallbacks> server
                        = handshake(listener, 0, false, sHooks, null, null);
                client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
            NativeCrypto.SSL_SESSION_free(clientSession[0]);
            NativeCrypto.SSL_SESSION_free(serverSession[0]);
            NativeCrypto.SSL_CTX_free(serverContext);
            NativeCrypto.SSL_CTX_free(clientContext);
        }
    }

    public void test_SSL_set_session_creation_enabled() throws Exception {
        try {
            NativeCrypto.SSL_set_session_creation_enabled(NULL, false);
            fail();
        } catch (NullPointerException expected) {
        }

        {
            long c = NativeCrypto.SSL_CTX_new();
            long s = NativeCrypto.SSL_new(c);
            NativeCrypto.SSL_set_session_creation_enabled(s, false);
            NativeCrypto.SSL_set_session_creation_enabled(s, true);
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }

        final ServerSocket listener = new ServerSocket(0);

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
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null,
                    null);
            @SuppressWarnings("unused")
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null,
                    null);
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
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
                @Override
                public long beforeHandshake(long c) throws SSLException {
                    long s = super.beforeHandshake(c);
                    NativeCrypto.SSL_set_session_creation_enabled(s, false);
                    return s;
                }
            };
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null,
                    null);
            @SuppressWarnings("unused")
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null,
                    null);
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

    public void test_SSL_set_tlsext_host_name() throws Exception {
        // NULL SSL
        try {
            NativeCrypto.SSL_set_tlsext_host_name(NULL, null);
            fail();
        } catch (NullPointerException expected) {
        }

        final String hostname = "www.android.com";

        {
            long c = NativeCrypto.SSL_CTX_new();
            long s = NativeCrypto.SSL_new(c);

            // null hostname
            try {
                NativeCrypto.SSL_set_tlsext_host_name(s, null);
                fail();
            } catch (NullPointerException expected) {
            }

            // too long hostname
            try {
                char[] longHostname = new char[256];
                Arrays.fill(longHostname, 'w');
                NativeCrypto.SSL_set_tlsext_host_name(s, new String(longHostname));
                fail();
            } catch (SSLException expected) {
            }

            assertNull(NativeCrypto.SSL_get_servername(s));
            NativeCrypto.SSL_set_tlsext_host_name(s, new String(hostname));
            assertEquals(hostname, NativeCrypto.SSL_get_servername(s));

            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }

        final ServerSocket listener = new ServerSocket(0);

        // normal
        Hooks cHooks = new Hooks() {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_set_tlsext_host_name(s, hostname);
                return s;
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                    throws Exception {
                assertEquals(hostname, NativeCrypto.SSL_get_servername(s));
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    public void test_SSL_NpnNegotiateSuccess() throws Exception {
        final byte[] clientNpnProtocols = new byte[] {
                8, 'h', 't', 't', 'p', '/', '1', '.', '1',
                3, 'f', 'o', 'o',
                6, 's', 'p', 'd', 'y', '/', '2',
        };
        final byte[] serverNpnProtocols = new byte[] {
                6, 's', 'p', 'd', 'y', '/', '2',
                3, 'f', 'o', 'o',
                3, 'b', 'a', 'r',
        };

        Hooks cHooks = new Hooks() {
            @Override public long beforeHandshake(long context) throws SSLException {
                NativeCrypto.SSL_CTX_enable_npn(context);
                return super.beforeHandshake(context);
            }
            @Override public void afterHandshake(long session, long ssl, long context, Socket socket,
                    FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                byte[] negotiated = NativeCrypto.SSL_get_npn_negotiated_protocol(ssl);
                assertEquals("spdy/2", new String(negotiated));
                assertTrue("NPN should enable cutthrough on the client",
                        0 != (NativeCrypto.SSL_get_mode(ssl) & SSL_MODE_HANDSHAKE_CUTTHROUGH));
                NativeCrypto.SSL_write(ssl, fd, callback, new byte[] { 42 }, 0, 1,
                        (int) ((TIMEOUT_SECONDS * 1000) / 2));
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
            @Override public long beforeHandshake(long context) throws SSLException {
                NativeCrypto.SSL_CTX_enable_npn(context);
                return super.beforeHandshake(context);
            }
            @Override public void afterHandshake(long session, long ssl, long c, Socket sock,
                    FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                byte[] negotiated = NativeCrypto.SSL_get_npn_negotiated_protocol(ssl);
                assertEquals("spdy/2", new String(negotiated));
                assertEquals("NPN should not enable cutthrough on the server",
                        0, NativeCrypto.SSL_get_mode(ssl) & SSL_MODE_HANDSHAKE_CUTTHROUGH);
                byte[] buffer = new byte[1];
                NativeCrypto.SSL_read(ssl, fd, callback, buffer, 0, 1, 0);
                assertEquals(42, buffer[0]);
                super.afterHandshake(session, ssl, c, sock, fd, callback);
            }
        };

        ServerSocket listener = new ServerSocket(0);
        Future<TestSSLHandshakeCallbacks> client
                = handshake(listener, 0, true, cHooks, clientNpnProtocols, null);
        Future<TestSSLHandshakeCallbacks> server
                = handshake(listener, 0, false, sHooks, serverNpnProtocols, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    public void test_SSL_AlpnNegotiateSuccess() throws Exception {
        final byte[] clientAlpnProtocols = new byte[] {
                8, 'h', 't', 't', 'p', '/', '1', '.', '1',
                3, 'f', 'o', 'o',
                6, 's', 'p', 'd', 'y', '/', '2',
        };
        final byte[] serverAlpnProtocols = new byte[] {
                6, 's', 'p', 'd', 'y', '/', '2',
                3, 'f', 'o', 'o',
                3, 'b', 'a', 'r',
        };

        Hooks cHooks = new Hooks() {
            @Override public long beforeHandshake(long context) throws SSLException {
                long sslContext = super.beforeHandshake(context);
                NativeCrypto.SSL_set_alpn_protos(sslContext, clientAlpnProtocols);
                return sslContext;
            }
            @Override public void afterHandshake(long session, long ssl, long context, Socket socket,
                    FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                byte[] negotiated = NativeCrypto.SSL_get0_alpn_selected(ssl);
                assertEquals("spdy/2", new String(negotiated));
                /*
                 * There is no callback on the client, so we can't enable
                 * cut-through
                 */
                assertEquals("ALPN should not enable cutthrough on the client", 0,
                        NativeCrypto.SSL_get_mode(ssl) & SSL_MODE_HANDSHAKE_CUTTHROUGH);
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
            @Override public void afterHandshake(long session, long ssl, long c, Socket sock,
                    FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                byte[] negotiated = NativeCrypto.SSL_get0_alpn_selected(ssl);
                assertEquals("spdy/2", new String(negotiated));
                assertEquals("ALPN should not enable cutthrough on the server",
                        0, NativeCrypto.SSL_get_mode(ssl) & SSL_MODE_HANDSHAKE_CUTTHROUGH);
                super.afterHandshake(session, ssl, c, sock, fd, callback);
            }
        };

        ServerSocket listener = new ServerSocket(0);
        Future<TestSSLHandshakeCallbacks> client
                = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server
                = handshake(listener, 0, false, sHooks, null, serverAlpnProtocols);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    public void test_SSL_get_servername_null() throws Exception {
        // NULL SSL
        try {
            NativeCrypto.SSL_get_servername(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c);
        assertNull(NativeCrypto.SSL_get_servername(s));
        NativeCrypto.SSL_free(s);
        NativeCrypto.SSL_CTX_free(c);

        // additional positive testing by test_SSL_set_tlsext_host_name
    }

    public void test_SSL_renegotiate() throws Exception {
        try {
            NativeCrypto.SSL_renegotiate(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        final ServerSocket listener = new ServerSocket(0);
        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                    throws Exception {
                byte[] buffer = new byte[1];
                NativeCrypto.SSL_read(s, fd, callback, buffer, 0, 1, 0);
                assertEquals(42, buffer[0]);
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                throws Exception {
                NativeCrypto.SSL_renegotiate(s);
                NativeCrypto.SSL_write(s, fd, callback, new byte[] { 42 }, 0, 1, 0);
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    public void test_SSL_get_certificate() throws Exception {
        try {
            NativeCrypto.SSL_get_certificate(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        final ServerSocket listener = new ServerSocket(0);
        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                throws Exception {
                assertNull(NativeCrypto.SSL_get_certificate(s));
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                    throws Exception {
                assertEqualCertificateChains(
                                             getServerCertificates(),
                                             NativeCrypto.SSL_get_certificate(s));
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    public void test_SSL_get_peer_cert_chain() throws Exception {
        try {
            NativeCrypto.SSL_get_peer_cert_chain(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        final ServerSocket listener = new ServerSocket(0);

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                    throws Exception {
                long[] cc = NativeCrypto.SSL_get_peer_cert_chain(s);
                assertEqualCertificateChains(getServerCertificates(), cc);
                for (long ref : cc) {
                    NativeCrypto.X509_free(ref);
                }
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    final byte[] BYTES = new byte[] { 2, -3, 5, 127, 0, -128 };

    public void test_SSL_read() throws Exception {

        // NULL ssl
        try {
            NativeCrypto.SSL_read(NULL, null, null, null, 0, 0, 0);
            fail();
        } catch (NullPointerException expected) {
        }

        // null FileDescriptor
        {
            long c = NativeCrypto.SSL_CTX_new();
            long s = NativeCrypto.SSL_new(c);
            try {
                NativeCrypto.SSL_read(s, null, DUMMY_CB, null, 0, 0, 0);
                fail();
            } catch (NullPointerException expected) {
            }
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }

        // null SSLHandshakeCallbacks
        {
            long c = NativeCrypto.SSL_CTX_new();
            long s = NativeCrypto.SSL_new(c);
            try {
                NativeCrypto.SSL_read(s, INVALID_FD, null, null, 0, 0, 0);
                fail();
            } catch (NullPointerException expected) {
            }
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }

        // null byte array
        {
            long c = NativeCrypto.SSL_CTX_new();
            long s = NativeCrypto.SSL_new(c);
            try {
                NativeCrypto.SSL_read(s, INVALID_FD, DUMMY_CB, null, 0, 0, 0);
                fail();
            } catch (NullPointerException expected) {
            }
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }

        // handshaking not yet performed
        {
            long c = NativeCrypto.SSL_CTX_new();
            long s = NativeCrypto.SSL_new(c);
            try {
                NativeCrypto.SSL_read(s, INVALID_FD, DUMMY_CB, new byte[1], 0, 1, 0);
                fail();
            } catch (SSLException expected) {
            }
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }

        final ServerSocket listener = new ServerSocket(0);

        // normal case
        {
            Hooks cHooks = new Hooks() {
                @Override
                public void afterHandshake(long session, long s, long c,
                                           Socket sock, FileDescriptor fd,
                                           SSLHandshakeCallbacks callback)
                        throws Exception {
                    byte[] in = new byte[256];
                    assertEquals(BYTES.length,
                                 NativeCrypto.SSL_read(s,
                                                       fd,
                                                       callback,
                                                       in,
                                                       0,
                                                       BYTES.length,
                                                       0));
                    for (int i = 0; i < BYTES.length; i++) {
                        assertEquals(BYTES[i], in[i]);
                    }
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            };
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
                @Override
                public void afterHandshake(long session, long s, long c,
                                           Socket sock, FileDescriptor fd,
                                           SSLHandshakeCallbacks callback)
                        throws Exception {
                    NativeCrypto.SSL_write(s, fd, callback, BYTES, 0, BYTES.length, 0);
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            };
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null,
                    null);
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null,
                    null);
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }

        // timeout case
        try {
            Hooks cHooks = new Hooks() {
                @Override
                public void afterHandshake(long session, long s, long c,
                                           Socket sock, FileDescriptor fd,
                                           SSLHandshakeCallbacks callback)
                        throws Exception {
                    NativeCrypto.SSL_read(s, fd, callback, new byte[1], 0, 1, 1);
                    fail();
                }
            };
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
                @Override
                public void afterHandshake(long session, long s, long c,
                                           Socket sock, FileDescriptor fd,
                                           SSLHandshakeCallbacks callback)
                        throws Exception {
                    NativeCrypto.SSL_read(s, fd, callback, new byte[1], 0, 1, 0);
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            };
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null,
                    null);
            @SuppressWarnings("unused")
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null,
                    null);
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SocketTimeoutException.class, expected.getCause().getClass());
        }
    }

    public void test_SSL_write() throws Exception {
        try {
            NativeCrypto.SSL_write(NULL, null, null, null, 0, 0, 0);
            fail();
        } catch (NullPointerException expected) {
        }

        // null FileDescriptor
        {
            long c = NativeCrypto.SSL_CTX_new();
            long s = NativeCrypto.SSL_new(c);
            try {
                NativeCrypto.SSL_write(s, null, DUMMY_CB, null, 0, 1, 0);
                fail();
            } catch (NullPointerException expected) {
            }
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }

        // null SSLHandshakeCallbacks
        {
            long c = NativeCrypto.SSL_CTX_new();
            long s = NativeCrypto.SSL_new(c);
            try {
                NativeCrypto.SSL_write(s, INVALID_FD, null, null, 0, 1, 0);
                fail();
            } catch (NullPointerException expected) {
            }
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }

        // null byte array
        {
            long c = NativeCrypto.SSL_CTX_new();
            long s = NativeCrypto.SSL_new(c);
            try {
                NativeCrypto.SSL_write(s, INVALID_FD, DUMMY_CB, null, 0, 1, 0);
                fail();
            } catch (NullPointerException expected) {
            }
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }

        // handshaking not yet performed
        {
            long c = NativeCrypto.SSL_CTX_new();
            long s = NativeCrypto.SSL_new(c);
            try {
                NativeCrypto.SSL_write(s, INVALID_FD, DUMMY_CB, new byte[1], 0, 1, 0);
                fail();
            } catch (SSLException expected) {
            }
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }

        // positively tested by test_SSL_read
    }

    public void test_SSL_interrupt() throws Exception {
        // SSL_interrupt is a rare case that tolerates a null SSL argument
        NativeCrypto.SSL_interrupt(NULL);

        // also works without handshaking
        {
            long c = NativeCrypto.SSL_CTX_new();
            long s = NativeCrypto.SSL_new(c);
            NativeCrypto.SSL_interrupt(s);
            NativeCrypto.SSL_free(s);
            NativeCrypto.SSL_CTX_free(c);
        }

        final ServerSocket listener = new ServerSocket(0);

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                    throws Exception {
                NativeCrypto.SSL_read(s, fd, callback, new byte[1], 0, 1, 0);
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates()) {
            @Override
            public void afterHandshake(long session, final long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                    throws Exception {
                new Thread() {
                    @Override
                    public void run() {
                        try {
                            Thread.sleep(1*1000);
                            NativeCrypto.SSL_interrupt(s);
                        } catch (Exception e) {
                        }
                    }
                }.start();
                assertEquals(-1, NativeCrypto.SSL_read(s, fd, callback, new byte[1], 0, 1, 0));
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
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

    public void test_SSL_shutdown() throws Exception {

        // null FileDescriptor
        wrapWithSSLSession(new SSLSessionWrappedTask() {
            @Override
            public void run(long sslSession) throws Exception {
                try {
                    NativeCrypto.SSL_shutdown(sslSession, null, DUMMY_CB);
                    fail();
                } catch (NullPointerException expected) {
                }
            }
        });

        // null SSLHandshakeCallbacks
        wrapWithSSLSession(new SSLSessionWrappedTask() {
            @Override
            public void run(long sslSession) throws Exception {
                try {
                    NativeCrypto.SSL_shutdown(sslSession, INVALID_FD, null);
                    fail();
                } catch (NullPointerException expected) {
                }
            }
        });

        // SSL_shutdown is a rare case that tolerates a null SSL argument
        NativeCrypto.SSL_shutdown(NULL, INVALID_FD, DUMMY_CB);

        // handshaking not yet performed
        wrapWithSSLSession(new SSLSessionWrappedTask() {
            @Override
            public void run(long sslSession) throws Exception {
                try {
                    NativeCrypto.SSL_shutdown(sslSession, INVALID_FD, DUMMY_CB);
                    fail();
                } catch (SocketException expected) {
                }
            }
        });

        // positively tested elsewhere because handshake uses use
        // SSL_shutdown to ensure SSL_SESSIONs are reused.
    }

    public void test_SSL_free() throws Exception {
        try {
            NativeCrypto.SSL_free(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        long c = NativeCrypto.SSL_CTX_new();
        NativeCrypto.SSL_free(NativeCrypto.SSL_new(c));
        NativeCrypto.SSL_CTX_free(c);

        // additional positive testing elsewhere because handshake
        // uses use SSL_free to cleanup in afterHandshake.
    }

    public void test_SSL_SESSION_session_id() throws Exception {
        try {
            NativeCrypto.SSL_SESSION_session_id(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        final ServerSocket listener = new ServerSocket(0);

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                    throws Exception {
                byte[] id = NativeCrypto.SSL_SESSION_session_id(session);
                assertNotNull(id);
                assertEquals(32, id.length);
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    public void test_SSL_SESSION_get_time() throws Exception {
        try {
            NativeCrypto.SSL_SESSION_get_time(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        final ServerSocket listener = new ServerSocket(0);

        {
            Hooks cHooks = new Hooks() {
                @Override
                public void afterHandshake(long session, long s, long c,
                                           Socket sock, FileDescriptor fd,
                                           SSLHandshakeCallbacks callback)
                        throws Exception {
                    long time = NativeCrypto.SSL_SESSION_get_time(session);
                    assertTrue(time != 0);
                    assertTrue(time < System.currentTimeMillis());
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            };
            Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
            Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null,
                    null);
            Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null,
                    null);
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }
    }

    public void test_SSL_SESSION_get_version() throws Exception {
        try {
            NativeCrypto.SSL_SESSION_get_version(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        final ServerSocket listener = new ServerSocket(0);

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                    throws Exception {
                String v = NativeCrypto.SSL_SESSION_get_version(session);
                assertTrue(StandardNames.SSL_SOCKET_PROTOCOLS.contains(v));
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    public void test_SSL_SESSION_cipher() throws Exception {
        try {
            NativeCrypto.SSL_SESSION_cipher(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        final ServerSocket listener = new ServerSocket(0);

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                        throws Exception {
                String a = NativeCrypto.SSL_SESSION_cipher(session);
                assertTrue(NativeCrypto.OPENSSL_TO_STANDARD_CIPHER_SUITES.containsKey(a));
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    public void test_SSL_SESSION_free() throws Exception {
        try {
            NativeCrypto.SSL_SESSION_free(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        // additional positive testing elsewhere because handshake
        // uses use SSL_SESSION_free to cleanup in afterHandshake.
    }

    public void test_i2d_SSL_SESSION() throws Exception {
        try {
            NativeCrypto.i2d_SSL_SESSION(NULL);
            fail();
        } catch (NullPointerException expected) {
        }

        final ServerSocket listener = new ServerSocket(0);

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c,
                                       Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback)
                    throws Exception {
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
        Hooks sHooks = new ServerHooks(getServerPrivateKey(), getServerCertificates());
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server = handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    public void test_d2i_SSL_SESSION() throws Exception {
        try {
            NativeCrypto.d2i_SSL_SESSION(null);
            fail();
        } catch (NullPointerException expected) {
        }

        assertEquals(NULL, NativeCrypto.d2i_SSL_SESSION(new byte[0]));
        assertEquals(NULL, NativeCrypto.d2i_SSL_SESSION(new byte[1]));

        // positive testing by test_i2d_SSL_SESSION
    }

    public void test_X509_NAME_hashes() {
        // ensure these hash functions are stable over time since the
        // /system/etc/security/cacerts CA filenames have to be
        // consistent with the output.
        X500Principal name = new X500Principal("CN=localhost");
        assertEquals(-1372642656, NativeCrypto.X509_NAME_hash(name)); // SHA1
        assertEquals(-1626170662, NativeCrypto.X509_NAME_hash_old(name)); // MD5
    }

    public void test_RAND_bytes_Success() throws Exception {
        byte[] output = new byte[128];
        NativeCrypto.RAND_bytes(output);

        boolean isZero = true;
        for (int i = 0; i < output.length; i++) {
            isZero &= (output[i] == 0);
        }

        assertFalse("Random output was zero. This is a very low probability event (1 in 2^128) "
                + "and probably indicates an error.", isZero);
    }

    public void test_RAND_bytes_Null_Failure() throws Exception {
        byte[] output = null;
        try {
            NativeCrypto.RAND_bytes(output);
            fail("Should be an error on null buffer input");
        } catch (RuntimeException expected) {
        }
    }

    public void test_EVP_get_digestbyname() throws Exception {
        assertTrue(NativeCrypto.EVP_get_digestbyname("sha256") != NULL);

        try {
            NativeCrypto.EVP_get_digestbyname(null);
            fail();
        } catch (NullPointerException expected) {
        }

        try {
            NativeCrypto.EVP_get_digestbyname("");
            NativeCrypto.EVP_get_digestbyname("foobar");
            fail();
        } catch (RuntimeException expected) {
        }
    }

    public void test_EVP_SignInit() throws Exception {
        final NativeRef.EVP_MD_CTX ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        assertEquals(1,
                NativeCrypto.EVP_SignInit(ctx, NativeCrypto.EVP_get_digestbyname("sha256")));

        try {
            NativeCrypto.EVP_SignInit(ctx, 0);
            fail();
        } catch (RuntimeException expected) {
        }
    }

    public void test_get_RSA_private_params() throws Exception {
        try {
            NativeCrypto.get_RSA_private_params(null);
        } catch (NullPointerException expected) {
        }

        try {
            NativeCrypto.get_RSA_private_params(null);
        } catch (NullPointerException expected) {
        }

        // Test getting params for the wrong kind of key.
        final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
        assertFalse(groupCtx == NULL);
        NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupCtx);
        NativeRef.EVP_PKEY ctx = new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(group));
        try {
            NativeCrypto.get_RSA_private_params(ctx);
            fail();
        } catch (RuntimeException expected) {
        }
    }

    public void test_get_RSA_public_params() throws Exception {
        try {
            NativeCrypto.get_RSA_public_params(null);
        } catch (NullPointerException expected) {
        }

        try {
            NativeCrypto.get_RSA_public_params(null);
        } catch (NullPointerException expected) {
        }

        // Test getting params for the wrong kind of key.
        final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
        assertFalse(groupCtx == NULL);
        NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupCtx);
        NativeRef.EVP_PKEY ctx = new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(group));
        try {
            NativeCrypto.get_RSA_public_params(ctx);
            fail();
        } catch (RuntimeException expected) {
        }
    }

    public void test_RSA_size_null_key_Failure() throws Exception {
        try {
            NativeCrypto.RSA_size(null);
            fail("Expecting null pointer exception for RSA_size with null key");
        } catch (NullPointerException expected) {}
    }

    public void test_RSA_private_encrypt_null_key_Failure() throws Exception {
        try {
            NativeCrypto.RSA_private_encrypt(0, new byte[0], new byte[0],
                    null, 0);
            fail("Expecting null pointer exception for RSA_private encrypt with null key");
        } catch (NullPointerException expected) {}
    }

    public void test_RSA_private_decrypt_null_key_Failure() throws Exception {
        try {
            NativeCrypto.RSA_private_decrypt(0, new byte[0], new byte[0],
 null, 0);
            fail("Expecting null pointer exception for RSA_private_decrypt with null key");
        } catch (NullPointerException expected) {}
    }

    public void test_RSA_public_encrypt_null_key_Failure() throws Exception {
        try {
            NativeCrypto.RSA_public_encrypt(0, new byte[0], new byte[0], null,
                    0);
            fail("Expecting null pointer exception for RSA_public encrypt with null key");
        } catch (NullPointerException expected) {}
    }

    public void test_RSA_public_decrypt_null_key_Failure() throws Exception {
        try {
            NativeCrypto.RSA_public_decrypt(0, new byte[0], new byte[0], null,
                    0);
            fail("Expecting null pointer exception for RSA_public decrypt with null key");
        } catch (NullPointerException expected) {}
    }

    /*
     * Test vector generation:
     * openssl rand -hex 16
     */
    private static final byte[] AES_128_KEY = new byte[] {
            (byte) 0x3d, (byte) 0x4f, (byte) 0x89, (byte) 0x70, (byte) 0xb1, (byte) 0xf2,
            (byte) 0x75, (byte) 0x37, (byte) 0xf4, (byte) 0x0a, (byte) 0x39, (byte) 0x29,
            (byte) 0x8a, (byte) 0x41, (byte) 0x55, (byte) 0x5f,
    };

    public void testEC_GROUP() throws Exception {
        /* Test using NIST's P-256 curve */
        check_EC_GROUP(NativeCrypto.EC_CURVE_GFP, "prime256v1",
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
                "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
                "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
                1L);
    }

    private void check_EC_GROUP(int type, String name, String pStr, String aStr, String bStr,
            String xStr, String yStr, String nStr, long hLong) throws Exception {
        long groupRef = NativeCrypto.EC_GROUP_new_by_curve_name(name);
        assertFalse(groupRef == NULL);
        NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupRef);
        assertEquals(NativeCrypto.OBJ_txt2nid_longName(name),
                NativeCrypto.EC_GROUP_get_curve_name(group));
        assertEquals(type, NativeCrypto.get_EC_GROUP_type(group));

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

        NativeRef.EC_POINT point = new NativeRef.EC_POINT(
                NativeCrypto.EC_GROUP_get_generator(group));

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

    public void test_EC_KEY_get_private_key_null_key_Failure() throws Exception {
        try {
            NativeCrypto.EC_KEY_get_private_key(null);
            fail();
        } catch (NullPointerException expected) {}
    }

    public void test_EC_KEY_get_public_key_null_key_Failure() throws Exception {
        try {
            NativeCrypto.EC_KEY_get_public_key(null);
            fail();
        } catch (NullPointerException expected) {}
    }

    public void test_ECKeyPairGenerator_CurvesAreValid() throws Exception {
        OpenSSLECKeyPairGenerator.assertCurvesAreValid();
    }

    public void test_ECDH_compute_key_null_key_Failure() throws Exception {
        final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
        assertFalse(groupCtx == NULL);
        NativeRef.EC_GROUP groupRef = new NativeRef.EC_GROUP(groupCtx);
        NativeRef.EVP_PKEY pkey1Ref = new NativeRef.EVP_PKEY(
                NativeCrypto.EC_KEY_generate_key(groupRef));
        NativeRef.EVP_PKEY pkey2Ref = new NativeRef.EVP_PKEY(
                NativeCrypto.EC_KEY_generate_key(groupRef));

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
        }

        // Assert that it fails when only the second key is null
        try {
            NativeCrypto.ECDH_compute_key(out, outOffset, pkey1Ref, null);
            fail();
        } catch (NullPointerException expected) {
        }
    }

    public void test_EVP_CipherInit_ex_Null_Failure() throws Exception {
        final NativeRef.EVP_CIPHER_CTX ctx = new NativeRef.EVP_CIPHER_CTX(
                NativeCrypto.EVP_CIPHER_CTX_new());
        final long evpCipher = NativeCrypto.EVP_get_cipherbyname("aes-128-ecb");

        try {
            NativeCrypto.EVP_CipherInit_ex(null, evpCipher, null, null, true);
            fail("Null context should throw NullPointerException");
        } catch (NullPointerException expected) {
        }

        /* Initialize encrypting. */
        NativeCrypto.EVP_CipherInit_ex(ctx, evpCipher, null, null, true);
        NativeCrypto.EVP_CipherInit_ex(ctx, NULL, null, null, true);

        /* Initialize decrypting. */
        NativeCrypto.EVP_CipherInit_ex(ctx, evpCipher, null, null, false);
        NativeCrypto.EVP_CipherInit_ex(ctx, NULL, null, null, false);
    }

    public void test_EVP_CipherInit_ex_Success() throws Exception {
        final NativeRef.EVP_CIPHER_CTX ctx = new NativeRef.EVP_CIPHER_CTX(
                NativeCrypto.EVP_CIPHER_CTX_new());
        final long evpCipher = NativeCrypto.EVP_get_cipherbyname("aes-128-ecb");
        NativeCrypto.EVP_CipherInit_ex(ctx, evpCipher, AES_128_KEY, null, true);
    }

    public void test_EVP_CIPHER_iv_length() throws Exception {
        long aes128ecb = NativeCrypto.EVP_get_cipherbyname("aes-128-ecb");
        assertEquals(0, NativeCrypto.EVP_CIPHER_iv_length(aes128ecb));

        long aes128cbc = NativeCrypto.EVP_get_cipherbyname("aes-128-cbc");
        assertEquals(16, NativeCrypto.EVP_CIPHER_iv_length(aes128cbc));
    }

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

    public void test_create_BIO_InputStream() throws Exception {
        byte[] actual = "Test".getBytes();
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

    public void test_create_BIO_OutputStream() throws Exception {
        byte[] actual = "Test".getBytes();
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

    private static void assertContains(String actualValue, String expectedSubstring) {
        if (actualValue == null) {
            return;
        }
        if (actualValue.contains(expectedSubstring)) {
            return;
        }
        fail("\"" + actualValue + "\" does not contain \"" + expectedSubstring + "\"");
    }
}
