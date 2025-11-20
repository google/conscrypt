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
import static org.conscrypt.NativeConstants.SSL_OP_CIPHER_SERVER_PREFERENCE;
import static org.conscrypt.NativeConstants.SSL_OP_NO_TICKET;
import static org.conscrypt.NativeConstants.SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
import static org.conscrypt.NativeConstants.SSL_VERIFY_NONE;
import static org.conscrypt.NativeConstants.SSL_VERIFY_PEER;
import static org.conscrypt.NativeConstants.TLS1_1_VERSION;
import static org.conscrypt.NativeConstants.TLS1_2_VERSION;
import static org.conscrypt.NativeConstants.TLS1_3_VERSION;
import static org.conscrypt.NativeConstants.TLS1_VERSION;
import static org.conscrypt.TestUtils.decodeHex;
import static org.conscrypt.TestUtils.isWindows;
import static org.conscrypt.TestUtils.openTestFile;
import static org.conscrypt.TestUtils.readTestFile;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.when;

import org.conscrypt.NativeCrypto.SSLHandshakeCallbacks;
import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
import org.conscrypt.java.security.StandardNames;
import org.conscrypt.java.security.TestKeyStore;
import org.conscrypt.javax.net.ssl.TestSSLContext;
import org.conscrypt.javax.net.ssl.TestSSLEnginePair;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
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

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

@RunWith(JUnit4.class)
public class NativeCryptoTest {
    private static final long NULL = 0;
    private static final FileDescriptor INVALID_FD = new FileDescriptor();
    private static final SSLHandshakeCallbacks DUMMY_CB =
            new TestSSLHandshakeCallbacks(0, null, null);

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
    private static RSAPrivateCrtKey TEST_RSA_KEY;

    // Helper managers for the SSLEngine harness
    private static TrustManager[] TRUST_ALL;

    @BeforeClass
    @SuppressWarnings("JdkObsolete") // Public API KeyStore.aliases() uses Enumeration
    public static void initStatics() throws Exception {
        // Removed reflective FileDescriptor access logic.

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

        // RSA keys are slow to generate, so prefer to reuse the key when possible.
        TEST_RSA_KEY = generateRsaKey();

        TRUST_ALL = new TrustManager[] {new X509TrustManager(){
                @Override public void checkClientTrusted(X509Certificate[] chain, String authType){}
                @Override public void checkServerTrusted(X509Certificate[] chain, String authType){}
                @Override public X509Certificate[] getAcceptedIssuers(){
                        return new X509Certificate[0];
    }
            }
        };
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

    private static RSAPrivateCrtKey generateRsaKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

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
            NativeCrypto.X509_cmp(expected[i], null, actual[i], null);
        }
    }

    public static void assertEqualByteArrays(byte[][] expected, byte[][] actual) {
        assertEquals(Arrays.deepToString(expected), Arrays.deepToString(actual));
    }

    @Test
    public void EVP_PKEY_cmp_BothNullParameters() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.EVP_PKEY_cmp(null, null));
    }

    @Test
    public void EVP_PKEY_cmp_withNullShouldThrow() throws Exception {
        RSAPrivateCrtKey privKey1 = TEST_RSA_KEY;
        NativeRef.EVP_PKEY pkey1 = getRsaPkey(privKey1);
        assertFalse(pkey1.isNull());
        assertThrows(NullPointerException.class, () -> NativeCrypto.EVP_PKEY_cmp(pkey1, null));
    }

    @Test
    public void test_EVP_PKEY_cmp() throws Exception {
        RSAPrivateCrtKey privKey1 = TEST_RSA_KEY;

        NativeRef.EVP_PKEY pkey1 = getRsaPkey(privKey1);
        assertFalse(pkey1.isNull());

        NativeRef.EVP_PKEY pkey1_copy = getRsaPkey(privKey1);
        assertFalse(pkey1_copy.isNull());

        // Generate a different key.
        NativeRef.EVP_PKEY pkey2 = getRsaPkey(generateRsaKey());
        assertFalse(pkey2.isNull());

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
        NativeCrypto.SSL_CTX_free(c, null);
        NativeCrypto.SSL_CTX_free(c2, null);
    }

    @Test
    public void test_SSL_CTX_free_NullArgument() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_CTX_free(NULL, null));
    }

    @Test
    public void test_SSL_CTX_free() throws Exception {
        NativeCrypto.SSL_CTX_free(NativeCrypto.SSL_CTX_new(), null);
    }

    @Test
    public void SSL_CTX_set_session_id_context_NullContextArgument() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.SSL_CTX_set_session_id_context(NULL, null, new byte[0]));
    }

    @Test
    public void SSL_CTX_set_session_id_context_withNullShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.SSL_CTX_set_session_id_context(c, null, null);
            } finally {
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void test_SSL_CTX_set_session_id_context_withInvalidIdShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        assertThrows(IllegalArgumentException.class, () -> {
            try {
                NativeCrypto.SSL_CTX_set_session_id_context(c, null, new byte[33]);
            } finally {
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void test_SSL_CTX_set_session_id_context() throws Exception {
        byte[] empty = new byte[0];

        long c = NativeCrypto.SSL_CTX_new();
        try {
            NativeCrypto.SSL_CTX_set_session_id_context(c, null, empty);
            NativeCrypto.SSL_CTX_set_session_id_context(c, null, new byte[32]);
        } finally {
            NativeCrypto.SSL_CTX_free(c, null);
        }
    }

    @Test
    public void test_SSL_new() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        assertTrue(s != NULL);
        assertTrue((NativeCrypto.SSL_get_options(s, null) & SSL_OP_NO_TICKET) != 0);

        long s2 = NativeCrypto.SSL_new(c, null);
        assertTrue(s != s2);
        NativeCrypto.SSL_free(s2, null);

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void setLocalCertsAndPrivateKey_withNullSSLShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                ()
                        -> NativeCrypto.setLocalCertsAndPrivateKey(NULL, null,
                                ENCODED_SERVER_CERTIFICATES, SERVER_PRIVATE_KEY.getNativeRef()));
    }

    @Test
    public void setLocalCertsAndPrivateKey_withNullCertificatesShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.setLocalCertsAndPrivateKey(
                        s, null, null, SERVER_PRIVATE_KEY.getNativeRef());
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void setLocalCertsAndPrivateKey_withNullKeyShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.setLocalCertsAndPrivateKey(s, null, ENCODED_SERVER_CERTIFICATES, null);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void setLocalCertsAndPrivateKey() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        NativeCrypto.setLocalCertsAndPrivateKey(
                s, null, ENCODED_SERVER_CERTIFICATES, SERVER_PRIVATE_KEY.getNativeRef());

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void SSL_set1_tls_channel_id_withNullChannelShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.SSL_set1_tls_channel_id(NULL, null, null));
    }

    @Test
    public void SSL_set1_tls_channel_id_withNullKeyShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.SSL_set1_tls_channel_id(s, null, null);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void test_SSL_use_PrivateKey_for_tls_channel_id() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        // Use the key natively. This works because the initChannelIdKey method ensures that the
        // key is backed by OpenSSL.
        NativeCrypto.SSL_set1_tls_channel_id(s, null, CHANNEL_ID_PRIVATE_KEY.getNativeRef());

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void SSL_get_mode_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_get_mode(NULL, null));
    }

    @Test
    public void test_SSL_get_mode() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertTrue(NativeCrypto.SSL_get_mode(s, null) != 0);
        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void SSL_set_mode_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_set_mode(NULL, null, 0));
    }

    @Test
    public void test_SSL_set_mode_and_clear_mode() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        // check SSL_MODE_ENABLE_FALSE_START on by default for BoringSSL
        assertEquals(SSL_MODE_ENABLE_FALSE_START,
                NativeCrypto.SSL_get_mode(s, null) & SSL_MODE_ENABLE_FALSE_START);
        // check SSL_MODE_CBC_RECORD_SPLITTING off by default
        assertEquals(0, NativeCrypto.SSL_get_mode(s, null) & SSL_MODE_CBC_RECORD_SPLITTING);

        // set SSL_MODE_ENABLE_FALSE_START on
        NativeCrypto.SSL_set_mode(s, null, SSL_MODE_ENABLE_FALSE_START);
        assertTrue((NativeCrypto.SSL_get_mode(s, null) & SSL_MODE_ENABLE_FALSE_START) != 0);
        // clear SSL_MODE_ENABLE_FALSE_START off
        NativeCrypto.SSL_clear_mode(s, null, SSL_MODE_ENABLE_FALSE_START);
        assertTrue((NativeCrypto.SSL_get_mode(s, null) & SSL_MODE_ENABLE_FALSE_START) == 0);

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void test_SSL_do_handshake_ech_grease_only() throws Exception {
        final byte[] key = readTestFile("boringssl-ech-private-key.bin");
        final byte[] serverConfig = readTestFile("boringssl-server-ech-config.bin");

        TestSSLContext c = TestSSLContext.create();
        Future<HandshakeResult> result = handshake(c, new Hooks() {
            @Override
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                long clientSsl = getNativeSsl(client);
                NativeSsl clientHolder = getNativeSslHolder(client);
                long serverSsl = getNativeSsl(server);
                NativeSsl serverHolder = getNativeSslHolder(server);

                assertEquals(1,
                        NativeCrypto.SSL_set_protocol_versions(
                                clientSsl, clientHolder, TLS1_VERSION, TLS1_3_VERSION));
                NativeCrypto.SSL_set_enable_ech_grease(clientSsl, clientHolder, true);

                assertEquals(1,
                        NativeCrypto.SSL_set_protocol_versions(
                                serverSsl, serverHolder, TLS1_VERSION, TLS1_3_VERSION));
            }
        });

        assertNotNull(result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS)
                        .client.getSession()
                        .getPeerCertificates());
    }

    /** Convenient debug print for ECH Config Lists */
    private void printEchConfigList(String msg, byte[] buf) {
        int blen = buf.length;
        System.out.print(msg + " (" + blen + "):\n    ");
        for (int i = 0; i < blen; i++) {
            if ((i != 0) && (i % 16 == 0))
                System.out.print("\n    ");
            System.out.print(String.format("%02x:", Byte.toUnsignedInt(buf[i])));
        }
        System.out.print("\n");
    }

    @Test
    public void test_SSL_do_handshake_ech_client_server() throws Exception {
        final byte[] key = readTestFile("boringssl-ech-private-key.bin");
        final byte[] serverConfig = readTestFile("boringssl-server-ech-config.bin");
        final byte[] clientConfigList = readTestFile("boringssl-ech-config-list.bin");

        TestSSLContext c = TestSSLContext.create();
        Future<HandshakeResult> result = handshake(c, new Hooks() {
            @Override
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                long clientSsl = getNativeSsl(client);
                NativeSsl clientHolder = getNativeSslHolder(client);
                assertEquals(1,
                        NativeCrypto.SSL_set_protocol_versions(
                                clientSsl, clientHolder, TLS1_VERSION, TLS1_3_VERSION));
                try {
                    NativeCrypto.SSL_set1_ech_config_list(clientSsl, clientHolder, clientConfigList);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });

        HandshakeResult res = result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertNotNull(res.client.getSession().getPeerCertificates());
        long clientSsl = getNativeSsl(res.client);
        NativeSsl clientHolder = getNativeSslHolder(res.client);
        assertFalse(NativeCrypto.SSL_ech_accepted(clientSsl, clientHolder));
    }

    @Test
    public void test_SSL_set_enable_ech_grease() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        NativeCrypto.SSL_set_enable_ech_grease(s, null, true);
        NativeCrypto.SSL_set_enable_ech_grease(s, null, false);

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void test_SSL_set1_ech_valid_config_list() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        final byte[] configList = readTestFile("boringssl-ech-config-list.bin");
        assertTrue(NativeCrypto.SSL_set1_ech_config_list(s, null, configList));

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void test_SSL_set1_ech_invalid_config_list() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        byte[] badConfigList = {
                0x00, 0x05, (byte) 0xfe, 0x0d, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        assertThrows(SSLException.class,
                () -> NativeCrypto.SSL_set1_ech_config_list(s, null, badConfigList));
        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void test_SSL_set1_ech_config_list_withNull() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.SSL_set1_ech_config_list(s, null, null));
        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void test_SSL_ECH_KEYS_new() throws Exception {
        long k = NativeCrypto.SSL_ECH_KEYS_new();
        NativeCrypto.SSL_ECH_KEYS_up_ref(k);
        assertTrue(k != NULL);
        long k2 = NativeCrypto.SSL_ECH_KEYS_new();
        NativeCrypto.SSL_ECH_KEYS_up_ref(k2);
        assertTrue(k != k2);
        NativeCrypto.SSL_ECH_KEYS_free(k);
        NativeCrypto.SSL_ECH_KEYS_free(k2);
    }

    @Test
    public void test_SSL_ech_accepted() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        assertFalse(NativeCrypto.SSL_ech_accepted(s, null));

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void test_SSL_CTX_ech_enable_server() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();

        final byte[] key = readTestFile("boringssl-ech-private-key.bin");
        final byte[] serverConfig = readTestFile("boringssl-server-ech-config.bin");
        assertTrue(NativeCrypto.SSL_CTX_ech_enable_server(c, null, key, serverConfig));

        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void test_SSL_get0_ech_retry_configs_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.SSL_get0_ech_retry_configs(NULL, null));
    }

    @Test
    public void test_SSL_CTX_ech_enable_server_NULL_SSL_CTX() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.SSL_CTX_ech_enable_server(NULL, null, null, null));
    }

    @Test
    public void test_SSL_CTX_ech_enable_server_ssl_withNullsShouldThrow() {
        long c = NativeCrypto.SSL_CTX_new();
        try {
            NativeCrypto.SSL_CTX_ech_enable_server(c, null, null, null);
        } catch (NullPointerException | AssertionError e) {
            // AssertionError when running with checkErrorQueue
            return;
        }
        fail();
    }

    @Test
    public void test_SSL_CTX_ech_enable_server_ssl_withNullConfigShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        final byte[] serverConfig = readTestFile("boringssl-server-ech-config.bin");
        try {
            NativeCrypto.SSL_CTX_ech_enable_server(c, null, null, serverConfig);
        } catch (NullPointerException | AssertionError e) {
            // AssertionError when running with checkErrorQueue
            return;
        }
        fail();
    }

    @Test
    public void test_SSL_CTX_ech_enable_server_ssl_withNullKeyShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        final byte[] key = readTestFile("boringssl-ech-private-key.bin");
        try {
            NativeCrypto.SSL_CTX_ech_enable_server(c, null, key, null);
        } catch (NullPointerException | AssertionError e) {
            // AssertionError when running with checkErrorQueue
            return;
        }
        fail();
    }

    @Test
    public void test_SSL_CTX_ech_enable_server_ssl_with_bad_key() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        final byte[] badKey = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
        final byte[] serverConfig = readTestFile("boringssl-server-ech-config.bin");
        assertThrows(InvalidKeyException.class,
                ()
                        -> assertFalse(NativeCrypto.SSL_CTX_ech_enable_server(
                                c, null, badKey, serverConfig)));
    }

    @Test
    public void test_SSL_CTX_ech_enable_server_ssl_with_bad_config() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        final byte[] key = readTestFile("boringssl-ech-private-key.bin");
        byte[] badConfig = {(byte) 0xfe, (byte) 0x0d, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        assertThrows(InvalidKeyException.class,
                () -> assertFalse(NativeCrypto.SSL_CTX_ech_enable_server(c, null, key, badConfig)));
    }

    @Test
    public void test_SSL_CTX_ech_enable_server_ssl_with_bad_key_config() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        final byte[] badKey = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
        byte[] badConfig = {(byte) 0xfe, (byte) 0x0d, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        assertThrows(InvalidKeyException.class,
                ()
                        -> assertFalse(NativeCrypto.SSL_CTX_ech_enable_server(
                                c, null, badKey, badConfig)));
    }

    @Test
    public void SSL_get_options_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_get_options(NULL, null));
    }

    @Test
    public void test_SSL_get_options() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertTrue(NativeCrypto.SSL_get_options(s, null) != 0);
        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void SSL_set_options_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_set_options(NULL, null, 0));
    }

    @Test
    public void test_SSL_set_options() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertTrue((NativeCrypto.SSL_get_options(s, null) & SSL_OP_CIPHER_SERVER_PREFERENCE) == 0);
        NativeCrypto.SSL_set_options(s, null, SSL_OP_CIPHER_SERVER_PREFERENCE);
        assertTrue((NativeCrypto.SSL_get_options(s, null) & SSL_OP_CIPHER_SERVER_PREFERENCE) != 0);
        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void SSL_clear_options_withNullShouldThrow() throws Exception {
        assertThrows(
                NullPointerException.class, () -> NativeCrypto.SSL_clear_options(NULL, null, 0));
    }

    @Test
    public void test_SSL_clear_options() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertTrue((NativeCrypto.SSL_get_options(s, null) & SSL_OP_CIPHER_SERVER_PREFERENCE) == 0);
        NativeCrypto.SSL_set_options(s, null, SSL_OP_CIPHER_SERVER_PREFERENCE);
        assertTrue((NativeCrypto.SSL_get_options(s, null) & SSL_OP_CIPHER_SERVER_PREFERENCE) != 0);
        NativeCrypto.SSL_clear_options(s, null, SSL_OP_CIPHER_SERVER_PREFERENCE);
        assertTrue((NativeCrypto.SSL_get_options(s, null) & SSL_OP_CIPHER_SERVER_PREFERENCE) == 0);
        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void SSL_set_protocol_versions_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.SSL_set_protocol_versions(NULL, null, 0, 0));
    }

    @Test
    public void SSL_set_protocol_versions() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertEquals(
                1, NativeCrypto.SSL_set_protocol_versions(s, null, TLS1_VERSION, TLS1_1_VERSION));
        assertEquals(
                1, NativeCrypto.SSL_set_protocol_versions(s, null, TLS1_2_VERSION, TLS1_2_VERSION));
        assertEquals(0,
                NativeCrypto.SSL_set_protocol_versions(
                        s, null, TLS1_2_VERSION + 413, TLS1_1_VERSION));
        assertEquals(0,
                NativeCrypto.SSL_set_protocol_versions(
                        s, null, TLS1_1_VERSION, TLS1_2_VERSION + 413));
        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void SSL_set_cipher_lists_withNullSslShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.SSL_set_cipher_lists(NULL, null, null));
    }

    @Test
    public void SSL_set_cipher_lists_withNullCiphersShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.SSL_set_cipher_lists(s, null, null);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void test_SSL_set_cipher_lists_withNullCipherShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.SSL_set_cipher_lists(s, null, new String[] {null});
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void SSL_set_cipher_lists_withEmptyCiphersShouldSucceed() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        // Explicitly checking that the empty list is allowed.
        // b/21816861
        NativeCrypto.SSL_set_cipher_lists(s, null, new String[] {});

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void SSL_set_cipher_lists_withIllegalCipherShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        // see OpenSSL ciphers man page
        String[] illegals = new String[] {// empty
                "",
                // never standardized
                "EXP1024-DES-CBC-SHA",
                // IDEA
                "IDEA-CBC-SHA", "IDEA-CBC-MD5"};

        for (String illegal : illegals) {
            try {
                NativeCrypto.SSL_set_cipher_lists(s, null, new String[] {illegal});
                fail("Exception now thrown for illegal cipher: " + illegal);
            } catch (IllegalArgumentException expected) {
                // Expected.
            }
        }

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void SSL_set_cipher_lists_withValidCiphersShouldSucceed() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        List<String> ciphers = new ArrayList<>(NativeCrypto.SUPPORTED_TLS_1_2_CIPHER_SUITES_SET);
        NativeCrypto.SSL_set_cipher_lists(s, null, ciphers.toArray(new String[0]));

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void SSL_set_verify_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_set_verify(NULL, null, 0));
    }

    @Test
    public void test_SSL_set_verify() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        NativeCrypto.SSL_set_verify(s, null, SSL_VERIFY_NONE);
        NativeCrypto.SSL_set_verify(s, null, SSL_VERIFY_PEER);
        NativeCrypto.SSL_set_verify(s, null, SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
        NativeCrypto.SSL_set_verify(s, null, (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT));
        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void test_SSL_do_handshake_normal() throws Exception {
        // normal client and server case
        TestSSLContext c = TestSSLContext.create(TestKeyStore.getClient(), TestKeyStore.getServer());
        Future<HandshakeResult> result = handshake(c, new Hooks() {
            @Override
            public void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                // Force TLS 1.2 to match cipher suite expectation
                client.setEnabledProtocols(new String[] { "TLSv1.2" });
                server.setEnabledProtocols(new String[] { "TLSv1.2" });
                client.setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"});
                server.setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"});
            }
        });

        HandshakeResult pair = result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertNotNull(pair.client.getSession().getPeerCertificates());
        assertEquals(ENCODED_SERVER_CERTIFICATES.length, pair.client.getSession().getPeerCertificates().length);
        assertEquals("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", pair.client.getSession().getCipherSuite());

        pair.close();
    }

    @Test
    public void test_SSL_do_handshake_reusedSession() throws Exception {
        // normal client and server case
        TestSSLContext c = TestSSLContext.create(TestKeyStore.getClient(), TestKeyStore.getServer());
        Future<HandshakeResult> result1 = handshake(c, null);
        HandshakeResult pair1 = result1.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        SSLSession session1 = pair1.client.getSession();
        pair1.close();

        Future<HandshakeResult> result2 = handshake(c, new Hooks() {
            @Override
            public void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                // Use reflection to set session if possible, or just rely on context
                try {
                    setSession(client, session1);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
        HandshakeResult pair2 = result2.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertArrayEquals(session1.getId(), pair2.client.getSession().getId());
        pair2.close();
    }

    @Test
    public void test_SSL_do_handshake_optional_client_certificate() throws Exception {
        // optional client certificate case
        TestSSLContext c = TestSSLContext.create(TestKeyStore.getClientCertificate(), TestKeyStore.getServer());
        Future<HandshakeResult> result = handshake(c, new Hooks() {
            @Override
            public void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                server.setWantClientAuth(true);
            }
        });
        HandshakeResult pair = result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertEquals(ENCODED_CLIENT_CERTIFICATES.length, pair.server.getSession().getPeerCertificates().length);
        pair.close();
    }

    @Test
    public void test_SSL_do_handshake_missing_required_certificate() throws Exception {
        // required client certificate negative case.
        // Create a client context with NO keys by passing null for client KeyStore.
        TestSSLContext c = TestSSLContext.create(null, TestKeyStore.getServer());
        try {
            Future<HandshakeResult> result = handshake(c, new Hooks() {
                @Override
                void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                    server.setNeedClientAuth(true);
                }
            });
            result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail("Should have thrown SSLHandshakeException");
        } catch (ExecutionException e) {
            if (e.getCause() instanceof SSLHandshakeException
                    || e.getCause() instanceof SSLException) {
                // Expected
            } else {
                throw e;
            }
        }
        c.close();
    }

    @Test
    public void test_SSL_do_handshake_with_channel_id_normal() throws Exception {
        // Normal handshake with TLS Channel ID.
        TestSSLContext c = TestSSLContext.create(TestKeyStore.getClient(), TestKeyStore.getServer());
        Future<HandshakeResult> result = handshake(c, new Hooks() {
            @Override
            public void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                try {
                    Conscrypt.setChannelIdEnabled(client, true);
                    Conscrypt.setChannelIdPrivateKey(client, CHANNEL_ID_PRIVATE_KEY.getPrivateKey());
                    NativeCrypto.SSL_enable_tls_channel_id(getNativeSsl(server), getNativeSslHolder(server));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
        HandshakeResult pair = result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        byte[] receivedChannelId = NativeCrypto.SSL_get_tls_channel_id(
                getNativeSsl(pair.server), getNativeSslHolder(pair.server));
        assertEqualByteArrays(CHANNEL_ID, receivedChannelId);
        pair.close();
    }

    @Test
    public void test_SSL_do_handshake_with_psk_normal() throws Exception {
        // normal TLS-PSK client and server case
        TestSSLContext c = TestSSLContext.create(TestKeyStore.getClient(), TestKeyStore.getServer());
        final byte[] pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
        Future<HandshakeResult> result = handshake(c, new Hooks() {
            @Override
            public void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                // Force TLS 1.2 for PSK
                client.setEnabledProtocols(new String[] { "TLSv1.2" });
                server.setEnabledProtocols(new String[] { "TLSv1.2" });
                client.setEnabledCipherSuites(new String[] {"TLS_PSK_WITH_AES_128_CBC_SHA"});
                server.setEnabledCipherSuites(new String[] {"TLS_PSK_WITH_AES_128_CBC_SHA"});
                installPskCallbacks(client, pskKey, "identity");
                installPskCallbacks(server, pskKey, null);
            }
        });
        HandshakeResult pair = result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(pair.client.getSession().getCipherSuite().contains("PSK"));
        pair.close();
    }

    private void installPskCallbacks(SSLEngine engine, byte[] key, String identity) {
        long ssl = getNativeSsl(engine);
        NativeSsl sslHolder = getNativeSslHolder(engine);
        TestSSLHandshakeCallbacks cb = new TestSSLHandshakeCallbacks(ssl, null, null);
        cb.pskKey = key;
        cb.pskIdentity = identity;
        try {
            if (engine.getUseClientMode()) {
                NativeCrypto.set_SSL_psk_client_callback_enabled(ssl, sslHolder, true);
                setClientSessionCallbacks(engine, cb);
            } else {
                NativeCrypto.set_SSL_psk_server_callback_enabled(ssl, sslHolder, true);
                setServerSessionCallbacks(engine, cb);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void test_SSL_set_tlsext_host_name() throws Exception {
        final String hostname = "www.android.com";
        TestSSLContext c = TestSSLContext.create();
        Future<HandshakeResult> result = handshake(c, new Hooks() {
            @Override
            public void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                try {
                    NativeCrypto.SSL_set_tlsext_host_name(getNativeSsl(client), getNativeSslHolder(client), hostname);
                } catch (SSLException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        HandshakeResult pair = result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertEquals(hostname, NativeCrypto.SSL_get_servername(getNativeSsl(pair.server), getNativeSslHolder(pair.server)));
        pair.close();
    }

    @Test
    public void test_SSL_cipher_names() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        Future<HandshakeResult> result = handshake(c, new Hooks() {
            @Override
            public void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                client.setEnabledProtocols(new String[] { "TLSv1.2" });
                server.setEnabledProtocols(new String[] { "TLSv1.2" });
                client.setEnabledCipherSuites(new String[] {"ECDHE-RSA-AES128-GCM-SHA256"});
                server.setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"});
            }
        });
        HandshakeResult pair = result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertEquals("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", pair.client.getSession().getCipherSuite());
        pair.close();
    }

    private final byte[] BYTES = new byte[] {2, -3, 5, 127, 0, -128};

    @Test
    public void SSL_read_withNullSslShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.SSL_read(NULL, null, null, null, null, 0, 0, 0));
    }

    @Test
    public void SSL_read_withNullFdShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.SSL_read(s, null, null, DUMMY_CB, null, 0, 0, 0);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void SSL_read_withNullCallbacksShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.SSL_read(s, null, INVALID_FD, null, null, 0, 0, 0);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void SSL_read_withNullBytesShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.SSL_read(s, null, INVALID_FD, DUMMY_CB, null, 0, 0, 0);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void SSL_read_beforeHandshakeShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(SSLException.class, () -> {
            try {
                NativeCrypto.SSL_read(s, null, INVALID_FD, DUMMY_CB, new byte[1], 0, 1, 0);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void SSL_write_withNullSslShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.SSL_write(NULL, null, null, null, null, 0, 0, 0));
    }

    @Test
    public void SSL_write_withNullFdShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.SSL_write(s, null, null, DUMMY_CB, null, 0, 1, 0);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void SSL_write_withNullCallbacksShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.SSL_write(s, null, INVALID_FD, null, null, 0, 1, 0);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void SSL_write_withNullBytesShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.SSL_write(s, null, INVALID_FD, DUMMY_CB, null, 0, 1, 0);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void SSL_write_beforeHandshakeShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(SSLException.class, () -> {
            try {
                NativeCrypto.SSL_write(s, null, INVALID_FD, DUMMY_CB, new byte[1], 0, 1, 0);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void SSL_interrupt_withNullShouldSucceed() {
        // SSL_interrupt is a rare case that tolerates a null SSL argument
        NativeCrypto.SSL_interrupt(NULL, null);
    }

    @Test
    public void SSL_interrupt_withoutHandshakeShouldSucceed() throws Exception {
        // also works without handshaking
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        NativeCrypto.SSL_interrupt(s, null);
        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    private static abstract class SSLSessionWrappedTask {
        public abstract void run(long sslSession) throws Exception;
    }

    private void wrapWithSSLSession(SSLSessionWrappedTask task) throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        try {
            task.run(s);
        } finally {
            NativeCrypto.SSL_free(s, null);
            NativeCrypto.SSL_CTX_free(c, null);
        }
    }

    @Test
    public void SSL_shutdown_withNullFdShouldSucceed() throws Exception {
        // We tolerate a null FileDescriptor
        wrapWithSSLSession(new SSLSessionWrappedTask() {
            @Override
            public void run(long sslSession) throws Exception {
                NativeCrypto.SSL_shutdown(sslSession, null, null, DUMMY_CB);
            }
        });
    }

    @Test
    public void SSL_shutdown_withNullCallbacksShouldThrow() throws Exception {
        assertThrows(
                NullPointerException.class, () -> wrapWithSSLSession(new SSLSessionWrappedTask() {
                    @Override
                    public void run(long sslSession) throws Exception {
                        NativeCrypto.SSL_shutdown(sslSession, null, INVALID_FD, null);
                    }
                }));
    }

    @Test
    public void SSL_shutdown_withNullSslShouldSucceed() throws Exception {
        // SSL_shutdown is a rare case that tolerates a null SSL argument
        NativeCrypto.SSL_shutdown(NULL, null, INVALID_FD, DUMMY_CB);
    }

    @Test
    public void SSL_shutdown_beforeHandshakeShouldThrow() throws Exception {
        // handshaking not yet performed
        assertThrows(SocketException.class, () -> wrapWithSSLSession(new SSLSessionWrappedTask() {
            @Override
            public void run(long sslSession) throws Exception {
                NativeCrypto.SSL_shutdown(sslSession, null, INVALID_FD, DUMMY_CB);
            }
        }));

        // positively tested elsewhere because handshake uses use
        // SSL_shutdown to ensure SSL_SESSIONs are reused.
    }

    @Test
    public void SSL_free_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_free(NULL, null));
    }

    @Test
    public void test_SSL_free() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        NativeCrypto.SSL_free(NativeCrypto.SSL_new(c, null), null);
        NativeCrypto.SSL_CTX_free(c, null);

        // additional positive testing elsewhere because handshake
        // uses use SSL_free to cleanup in afterHandshake.
    }

    @Test
    public void SSL_SESSION_session_id_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_SESSION_session_id(NULL));
    }

    @Test
    public void test_SSL_SESSION_session_id() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        Future<HandshakeResult> result = handshake(c, null);
        HandshakeResult pair = result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        long sessionPtr = getNativeSession(pair.client.getSession());
        byte[] id = NativeCrypto.SSL_SESSION_session_id(sessionPtr);
        assertNotNull(id);
        assertEquals(32, id.length);
        pair.close();
    }

    @Test
    public void SSL_SESSION_get_time_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_SESSION_get_time(NULL));
    }

    @Test
    public void test_SSL_SESSION_get_time() throws Exception {
        // TODO(prb) seems to fail regularly on Windows with time < System.currentTimeMillis()
        assumeFalse("Skipping SSLSession_getCreationTime() test on Windows", isWindows());

        TestSSLContext c = TestSSLContext.create();
        Future<HandshakeResult> result = handshake(c, null);
        HandshakeResult pair = result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        long sessionPtr = getNativeSession(pair.client.getSession());
        long time = NativeCrypto.SSL_SESSION_get_time(sessionPtr);
        assertTrue(time != 0);
        assertTrue(time < System.currentTimeMillis());
        pair.close();
    }

    @Test
    public void SSL_SESSION_get_version_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_SESSION_cipher(NULL));
    }

    @Test
    public void test_SSL_SESSION_get_version() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        Future<HandshakeResult> result = handshake(c, null);
        HandshakeResult pair = result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        long sessionPtr = getNativeSession(pair.client.getSession());
        String v = NativeCrypto.SSL_SESSION_get_version(sessionPtr);
        assertTrue(StandardNames.SSL_SOCKET_PROTOCOLS.contains(v));
        pair.close();
    }

    @Test
    public void SSL_SESSION_cipher_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_SESSION_cipher(NULL));
    }

    @Test
    public void test_SSL_SESSION_cipher() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        Future<HandshakeResult> result = handshake(c, null);
        HandshakeResult pair = result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        long sessionPtr = getNativeSession(pair.client.getSession());
        String nativeCipher = NativeCrypto.SSL_SESSION_cipher(sessionPtr);
        String javaCipher = NativeCrypto.cipherSuiteFromJava(nativeCipher);
        assertTrue(NativeCrypto.SUPPORTED_TLS_1_2_CIPHER_SUITES_SET.contains(javaCipher));
        // SSL_SESSION_cipher should return a standard name rather than an OpenSSL name.
        assertTrue(nativeCipher.startsWith("TLS_"));
        pair.close();
    }

    /*
     * Additional positive testing elsewhere because handshake
     * uses use SSL_SESSION_free to cleanup in afterHandshake.
     */
    @Test
    public void SSL_SESSION_free_NullArgument() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_SESSION_free(NULL));
    }

    @Test
    public void i2d_SSL_Session_WithNullSessionShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.i2d_SSL_SESSION(NULL));
    }

    @Test
    public void test_i2d_SSL_SESSION() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        Future<HandshakeResult> result = handshake(c, null);
        HandshakeResult pair = result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        long sessionPtr = getNativeSession(pair.client.getSession());
        byte[] b = NativeCrypto.i2d_SSL_SESSION(sessionPtr);
        assertNotNull(b);
        long session2 = NativeCrypto.d2i_SSL_SESSION(b);
        assertTrue(session2 != NULL);

        // Make sure d2i_SSL_SESSION retores SSL_SESSION_cipher value http://b/7091840
        assertNotNull(NativeCrypto.SSL_SESSION_cipher(session2));
        assertEquals(NativeCrypto.SSL_SESSION_cipher(sessionPtr),
                NativeCrypto.SSL_SESSION_cipher(session2));

        NativeCrypto.SSL_SESSION_free(session2);
        pair.close();
    }

    @Test
    public void d2i_SSL_SESSION_NullArgument() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.d2i_SSL_SESSION(null));
    }

    @Test
    public void d2i_SSL_SESSION_EmptyArgument() throws Exception {
        assertThrows(IOException.class, () -> NativeCrypto.d2i_SSL_SESSION(new byte[0]));
    }

    @Test
    public void d2i_SSL_SESSION_InvalidArgument() throws Exception {
        assertThrows(IOException.class, () -> NativeCrypto.d2i_SSL_SESSION(new byte[1]));
    }

    // Local handshake helper to replace package-private TestSSLEnginePair usage
    private static class HandshakeResult {
        final SSLEngine client;
        final SSLEngine server;
        HandshakeResult(SSLEngine client, SSLEngine server) {
            this.client = client;
            this.server = server;
        }
        void close() {
            TestSSLEnginePair.close(new SSLEngine[] {client, server});
        }
    }

    abstract static class Hooks {
        abstract void beforeBeginHandshake(SSLEngine client, SSLEngine server);
    }

    private Future<HandshakeResult> handshake(final TestSSLContext c, final Hooks hooks) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        return executor.submit(new Callable<HandshakeResult>() {
            @Override
            public HandshakeResult call() throws Exception {
                SSLEngine client = c.clientContext.createSSLEngine();
                client.setUseClientMode(true);
                SSLEngine server = c.serverContext.createSSLEngine();
                server.setUseClientMode(false);
                if (hooks != null) {
                    hooks.beforeBeginHandshake(client, server);
                }

                client.beginHandshake();
                server.beginHandshake();

                int packetBufferSize = client.getSession().getPacketBufferSize();
                ByteBuffer clientToServer = ByteBuffer.allocate(packetBufferSize);
                ByteBuffer serverToClient = ByteBuffer.allocate(packetBufferSize);
                ByteBuffer scratch =
                        ByteBuffer.allocate(client.getSession().getApplicationBufferSize());

                while (true) {
                    boolean clientDone =
                            client.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING;
                    boolean serverDone =
                            server.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING;
                    if (clientDone && serverDone)
                        break;

                    boolean progress = TestSSLEnginePair.handshakeStep(
                            client, clientToServer, serverToClient, scratch, new boolean[1]);
                    progress |= TestSSLEnginePair.handshakeStep(
                            server, serverToClient, clientToServer, scratch, new boolean[1]);
                    if (!progress)
                        break;
                }

                return new HandshakeResult(client, server);
            }
        });
    }

    private static Object unwrap(Object obj) {
        try {
            Class<?> clazz = obj.getClass();
            while (clazz != Object.class) {
                try {
                    Field f = clazz.getDeclaredField("delegate");
                    f.setAccessible(true);
                    return unwrap(f.get(obj));
                } catch (NoSuchFieldException e) {
                    // Try next
                }
                try {
                    Field f = clazz.getDeclaredField("engine");
                    f.setAccessible(true);
                    return unwrap(f.get(obj));
                } catch (NoSuchFieldException e) {
                    // Try next
                }
                clazz = clazz.getSuperclass();
            }
            return obj;
        } catch (Exception e) {
            return obj;
        }
    }

    private static long getNativeSsl(SSLEngine engine) {
        try {
            Object unwrapped = unwrap(engine);
            Class<?> clazz = unwrapped.getClass();
            while (clazz != null) {
                try {
                    Method m = clazz.getDeclaredMethod("getNativeSsl");
                    m.setAccessible(true);
                    return (long) m.invoke(unwrapped);
                } catch (NoSuchMethodException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            throw new RuntimeException("getNativeSsl not found on " + unwrapped.getClass());
        } catch (Exception e) {
            throw new RuntimeException("Failed to get native SSL pointer", e);
        }
    }

    private static NativeSsl getNativeSslHolder(SSLEngine engine) {
        try {
            Object unwrapped = unwrap(engine);
            Class<?> clazz = unwrapped.getClass();
            while (clazz != null) {
                try {
                    Field f = clazz.getDeclaredField("ssl");
                    f.setAccessible(true);
                    return (NativeSsl) f.get(unwrapped);
                } catch (NoSuchFieldException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static long getNativeSession(SSLSession session) {
        try {
            Object unwrapped = unwrap(session);
            Method m = unwrapped.getClass().getDeclaredMethod("getNativePointer");
            m.setAccessible(true);
            return (long) m.invoke(unwrapped);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get native session pointer", e);
        }
    }

    private void setSession(SSLEngine engine, SSLSession session) throws Exception {
        Object unwrapped = unwrap(engine);
        Method m = unwrapped.getClass().getDeclaredMethod("setSession", SSLSession.class);
        m.setAccessible(true);
        m.invoke(unwrapped, session);
    }

    private static void setClientSessionCallbacks(SSLEngine engine, SSLHandshakeCallbacks callbacks) throws Exception {
        Object unwrapped = unwrap(engine);
        Method m = unwrapped.getClass().getDeclaredMethod(
                "setClientSessionCallbacks", long.class, SSLHandshakeCallbacks.class);
        m.setAccessible(true);
        long ssl = getNativeSsl(engine);
        m.invoke(null, ssl, callbacks);
    }

    private static void setServerSessionCallbacks(SSLEngine engine, SSLHandshakeCallbacks callbacks) throws Exception {
        Object unwrapped = unwrap(engine);
        Method m = unwrapped.getClass().getDeclaredMethod(
                "setServerSessionCallbacks", long.class, SSLHandshakeCallbacks.class);
        m.setAccessible(true);
        long ssl = getNativeSsl(engine);
        m.invoke(null, ssl, callbacks);
    }

    // Restored and fixed TestSSLHandshakeCallbacks
    // Used for unit tests of NativeCrypto methods and PSK simulation
    static class TestSSLHandshakeCallbacks implements SSLHandshakeCallbacks {
        private final long sslNativePointer;
        private final Object hooks;
        private final ApplicationProtocolSelectorAdapter alpnSelector;

        public byte[] pskKey;
        public String pskIdentity;

        TestSSLHandshakeCallbacks(long sslNativePointer,
                Object hooks,
                ApplicationProtocolSelectorAdapter alpnSelector) {
            this.sslNativePointer = sslNativePointer;
            this.hooks = hooks;
            this.alpnSelector = alpnSelector;
        }

        @Override public void verifyCertificateChain(byte[][] certs, String authMethod) {}
        @Override public void clientCertificateRequested(byte[] keyTypes, int[] signatureAlgs, byte[][] asn1DerEncodedX500Principals) {}
        @Override public void onSSLStateChange(int type, int val) {}
        @Override public void onNewSessionEstablished(long sslSessionNativePtr) {}
        @Override public long serverSessionRequested(byte[] id) { return 0; }
        @Override public void serverCertificateRequested() {}

        @Override
        public int clientPSKKeyRequested(String identityHint, byte[] identity, byte[] key) {
            if (pskKey != null) {
                System.arraycopy(pskKey, 0, key, 0, pskKey.length);
                return pskKey.length;
            }
            return 0;
        }

        @Override
        public int serverPSKKeyRequested(String identityHint, String identity, byte[] key) {
            if (pskKey != null) {
                System.arraycopy(pskKey, 0, key, 0, pskKey.length);
                return pskKey.length;
            }
            return 0;
        }

        @Override
        public int selectApplicationProtocol(byte[] protocols) {
            if (alpnSelector != null) {
                return alpnSelector.selectApplicationProtocol(protocols);
            }
            return 0;
        }
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

    @Test
    public void RAND_bytes_withNullShouldThrow() throws Exception {
        assertThrows(RuntimeException.class, () -> NativeCrypto.RAND_bytes(null));
    }

    @Test
    public void test_EVP_get_digestbyname_NullArgument() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.EVP_get_digestbyname(null));
    }

    @Test
    public void EVP_get_digestbyname_withEmptyShouldThrow() throws Exception {
        assertThrows(RuntimeException.class, () -> NativeCrypto.EVP_get_digestbyname(""));
    }

    @Test
    public void EVP_get_digestbyname_withInvalidDigestShouldThrow() throws Exception {
        assertThrows(RuntimeException.class, () -> NativeCrypto.EVP_get_digestbyname("foobar"));
    }

    @Test
    public void test_EVP_get_digestbyname() throws Exception {
        assertTrue(NativeCrypto.EVP_get_digestbyname("sha256") != NULL);
    }

    @Test
    public void test_EVP_DigestSignInit() throws Exception {
        RSAPrivateCrtKey privKey = TEST_RSA_KEY;

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

    @Test
    public void test_ED25519_keypair_works() throws Exception {
        byte[] publicKeyBytes = new byte[32];
        byte[] privateKeyBytes = new byte[64];
        NativeCrypto.ED25519_keypair(publicKeyBytes, privateKeyBytes);

        byte[] publicKeyBytes2 = new byte[32];
        byte[] privateKeyBytes2 = new byte[64];
        NativeCrypto.ED25519_keypair(publicKeyBytes2, privateKeyBytes2);

        // keys must be random
        assertNotEquals(publicKeyBytes, publicKeyBytes2);
        assertNotEquals(privateKeyBytes, privateKeyBytes2);
    }

    @Test
    public void test_ED25519_keypair_32BytePrivateKey_throws() throws Exception {
        byte[] publicKeyBytes = new byte[32];
        byte[] privateKeyBytes = new byte[32];
        assertThrows(IllegalArgumentException.class,
                () -> NativeCrypto.ED25519_keypair(publicKeyBytes, privateKeyBytes));
    }

    @Test
    public void test_EVP_DigestSign_Ed25519_works() throws Exception {
        // Test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7
        // PKCS#8 encoding for Ed25519 is defined in https://datatracker.ietf.org/doc/html/rfc8410
        byte[] pkcs8EncodedPrivateKey = decodeHex(
                // PKCS#8 header
                "302e020100300506032b657004220420"
                // raw private key
                + "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] data = decodeHex("");
        byte[] expectedSig =
                decodeHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        NativeRef.EVP_PKEY privateKey =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_parse_private_key(pkcs8EncodedPrivateKey));

        NativeRef.EVP_MD_CTX ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());

        NativeCrypto.EVP_DigestSignInit(ctx, 0, privateKey);
        byte[] sig = NativeCrypto.EVP_DigestSign(ctx, data, 0, data.length);

        assertArrayEquals(expectedSig, sig);
    }

    @Test
    public void test_EVP_DigestVerify_Ed25519_works() throws Exception {
        // Test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7
        // X.509 encoding for Ed25519 is defined in https://datatracker.ietf.org/doc/html/rfc8410
        byte[] x509EncodedPublicKey = decodeHex(
                // X.509 header
                "302a300506032b6570032100"
                // raw public key
                + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] data = decodeHex("");
        byte[] sig = decodeHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        NativeRef.EVP_MD_CTX ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());

        NativeRef.EVP_PKEY publicKey =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_parse_public_key(x509EncodedPublicKey));

        NativeCrypto.EVP_DigestVerifyInit(ctx, 0, publicKey);
        boolean result =
                NativeCrypto.EVP_DigestVerify(ctx, sig, 0, sig.length, data, 0, data.length);

        assertTrue(result);
    }

    @Test
    public void get_RSA_private_params_NullArgument() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.get_RSA_private_params(null));
    }

    @Test
    public void test_get_RSA_private_params() throws Exception {
        // Test getting params for the wrong kind of key.
        final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
        assertNotEquals(NULL, groupCtx);
        NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupCtx);
        NativeRef.EVP_PKEY ctx = new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(group));
        assertThrows(RuntimeException.class, () -> NativeCrypto.get_RSA_private_params(ctx));
    }

    @Test
    public void get_RSA_public_params_NullArgument() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.get_RSA_public_params(null));
    }

    @Test
    public void test_get_RSA_public_params() throws Exception {
        // Test getting params for the wrong kind of key.
        final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
        assertNotEquals(NULL, groupCtx);
        NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupCtx);
        NativeRef.EVP_PKEY ctx = new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(group));
        assertThrows(RuntimeException.class, () -> NativeCrypto.get_RSA_public_params(ctx));
    }

    @Test
    public void RSA_size_NullArgumentFailure() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.RSA_size(null));
    }

    @Test
    public void RSA_private_encrypt_NullArgumentFailure() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.RSA_private_encrypt(0, new byte[0], new byte[0], null, 0));
    }

    @Test
    public void RSA_private_decrypt_NullArgumentFailure() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.RSA_private_decrypt(0, new byte[0], new byte[0], null, 0));
    }

    @Test
    public void test_RSA_public_encrypt_NullArgumentFailure() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.RSA_public_encrypt(0, new byte[0], new byte[0], null, 0));
    }

    @Test
    public void test_RSA_public_decrypt_NullArgumentFailure() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.RSA_public_decrypt(0, new byte[0], new byte[0], null, 0));
    }

    /*
     * Test vector generation:
     * openssl rand -hex 16
     */
    private static final byte[] AES_128_KEY = decodeHex("3d4f8970b1f27537f40a39298a41555f5f");

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
        assertNotEquals(NULL, groupRef);
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

    @Test
    public void test_EC_KEY_get_private_key_NullArgumentFailure() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.EC_KEY_get_private_key(null));
    }

    @Test
    public void test_EC_KEY_get_public_key_NullArgumentFailure() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.EC_KEY_get_public_key(null));
    }

    @Test
    public void test_ECKeyPairGenerator_CurvesAreValid() throws Exception {
        OpenSSLECKeyPairGenerator.assertCurvesAreValid();
    }

    @Test
    public void test_ECDH_compute_key_null_key_Failure() throws Exception {
        final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
        assertNotEquals(NULL, groupCtx);
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

    @Test
    public void EVP_CipherInit_ex_withNullCtxShouldThrow() throws Exception {
        final long evpCipher = NativeCrypto.EVP_get_cipherbyname("aes-128-ecb");
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.EVP_CipherInit_ex(null, evpCipher, null, null, true));
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
        assertNotEquals(NULL, groupCtx);
        NativeRef.EC_GROUP group1 = new NativeRef.EC_GROUP(groupCtx);
        key1 = new OpenSSLKey(NativeCrypto.EC_KEY_generate_key(group1));
        assertTrue(key1.getPublicKey() instanceof ECPublicKey);
    }

    @Test
    public void test_create_BIO_InputStream() throws Exception {
        byte[] actual = "Test".getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream is = new ByteArrayInputStream(actual);

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
        byte[] actual = "Test".getBytes(StandardCharsets.UTF_8);
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

        byte[] extension = NativeCrypto.get_ocsp_single_extension(ocspResponse, OCSP_SCT_LIST_OID,
                certificate.getContext(), certificate, issuer.getContext(), issuer);

        assertEqualByteArrays(expected, extension);
    }

    private static long getRawPkeyCtxForEncrypt() throws Exception {
        return NativeCrypto.EVP_PKEY_encrypt_init(getRsaPkey(TEST_RSA_KEY));
    }

    private static NativeRef.EVP_PKEY_CTX getPkeyCtxForEncrypt() throws Exception {
        return new NativeRef.EVP_PKEY_CTX(getRawPkeyCtxForEncrypt());
    }

    @Test
    public void EVP_PKEY_encrypt_NullKeyArgument() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.EVP_PKEY_encrypt(null, new byte[128], 0, new byte[128], 0, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_NullOutputArgument() throws Exception {
        assertThrows(NullPointerException.class,
                ()
                        -> NativeCrypto.EVP_PKEY_encrypt(
                                getPkeyCtxForEncrypt(), null, 0, new byte[128], 0, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_NullInputArgument() throws Exception {
        assertThrows(NullPointerException.class,
                ()
                        -> NativeCrypto.EVP_PKEY_encrypt(
                                getPkeyCtxForEncrypt(), new byte[128], 0, null, 0, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_OutputIndexOOBUnder() throws Exception {
        assertThrows(ArrayIndexOutOfBoundsException.class,
                ()
                        -> NativeCrypto.EVP_PKEY_encrypt(
                                getPkeyCtxForEncrypt(), new byte[128], -1, new byte[128], 0, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_OutputIndexOOBOver() throws Exception {
        assertThrows(ArrayIndexOutOfBoundsException.class,
                ()
                        -> NativeCrypto.EVP_PKEY_encrypt(
                                getPkeyCtxForEncrypt(), new byte[128], 129, new byte[128], 0, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_InputIndexOOBUnder() throws Exception {
        assertThrows(ArrayIndexOutOfBoundsException.class,
                ()
                        -> NativeCrypto.EVP_PKEY_encrypt(
                                getPkeyCtxForEncrypt(), new byte[128], 0, new byte[128], -1, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_InputIndexOOBOver() throws Exception {
        assertThrows(ArrayIndexOutOfBoundsException.class,
                ()
                        -> NativeCrypto.EVP_PKEY_encrypt(
                                getPkeyCtxForEncrypt(), new byte[128], 0, new byte[128], 128, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_InputLengthNegative() throws Exception {
        assertThrows(ArrayIndexOutOfBoundsException.class,
                ()
                        -> NativeCrypto.EVP_PKEY_encrypt(
                                getPkeyCtxForEncrypt(), new byte[128], 0, new byte[128], 0, -1));
    }

    @Test
    public void EVP_PKEY_encrypt_InputIndexLengthOOB() throws Exception {
        assertThrows(ArrayIndexOutOfBoundsException.class,
                ()
                        -> NativeCrypto.EVP_PKEY_encrypt(
                                getPkeyCtxForEncrypt(), new byte[128], 0, new byte[128], 100, 29));
    }

    @Test
    public void EVP_PKEY_CTX_set_rsa_mgf1_md_NullPkeyCtx() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.EVP_PKEY_CTX_set_rsa_mgf1_md(NULL, EvpMdRef.SHA256.EVP_MD));
    }

    @Test
    public void EVP_PKEY_CTX_set_rsa_mgf1_md_NullMdCtx() throws Exception {
        long pkeyCtx = getRawPkeyCtxForEncrypt();
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.EVP_PKEY_CTX_set_rsa_mgf1_md(pkeyCtx, NULL));
    }

    @Test
    public void EVP_PKEY_CTX_set_rsa_oaep_md_NullPkeyCtx() throws Exception {
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.EVP_PKEY_CTX_set_rsa_oaep_md(NULL, EvpMdRef.SHA256.EVP_MD));
    }

    @Test
    public void EVP_PKEY_CTX_set_rsa_oaep_md_NullMdCtx() throws Exception {
        long pkeyCtx = getRawPkeyCtxForEncrypt();
        assertThrows(NullPointerException.class,
                () -> NativeCrypto.EVP_PKEY_CTX_set_rsa_oaep_md(pkeyCtx, NULL));
    }

    @Test
    public void d2i_X509_InvalidFailure() throws Exception {
        assertThrows(ParsingException.class, () -> NativeCrypto.d2i_X509(new byte[1]));
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
        return new ServerSocket(0, 50, TestUtils.getLoopbackAddress());
    }

    @Test
    public void test_ecdsaSignVerify_works() throws Exception {
        final byte[] p256PrivateKeyPkcs8 = TestUtils.decodeBase64(
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXbi5zGvh/MoXidykzJKs1yEbrN99"
                + "/A3bQy1bMNQR/c2hRANCAAQqgfCMR3JAG/JhR386L6bTmo7XTd1B0oHCPaqPP5+YLzL5wY"
                + "AbDExaCdzXEljDvrupjn1HfqjZNCVAc0j13QIM");
        final byte[] p256PublicKeyX509 = TestUtils.decodeBase64(
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKoHwjEdyQBvyYUd/Oi+m05qO103dQdKBwj2qjz+f"
                + "mC8y+cGAGwxMWgnc1xJYw767qY59R36o2TQlQHNI9d0CDA==");
        NativeRef.EVP_PKEY privateKey =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_parse_private_key(p256PrivateKeyPkcs8));
        NativeRef.EVP_PKEY publicKey =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_parse_public_key(p256PublicKeyX509));
        byte[] data = decodeHex("AB");

        int signatureMaxLength = NativeCrypto.ECDSA_size(privateKey);
        byte[] signatureBuffer = new byte[signatureMaxLength];
        int signatureLength =
                NativeCrypto.ECDSA_sign(data, data.length, signatureBuffer, privateKey);
        assertTrue(signatureLength > 0);
        assertTrue(signatureLength <= signatureMaxLength);
        byte[] signature = Arrays.copyOf(signatureBuffer, signatureLength);

        int result = NativeCrypto.ECDSA_verify(data, data.length, signature, publicKey);
        assertEquals(1, result);

        // data buffer is larger than data
        byte[] dataBuffer = Arrays.copyOf(data, data.length + 42);
        assertEquals(1, NativeCrypto.ECDSA_verify(dataBuffer, data.length, signature, publicKey));

        // data too short
        assertEquals(0, NativeCrypto.ECDSA_verify(data, data.length - 1, signature, publicKey));

        byte[] signatureTooShort = Arrays.copyOf(signature, signature.length - 1);
        assertEquals(0, NativeCrypto.ECDSA_verify(data, data.length, signatureTooShort, publicKey));

        byte[] signatureTooLong = Arrays.copyOf(signature, signature.length + 1);
        assertEquals(0, NativeCrypto.ECDSA_verify(data, data.length, signatureTooLong, publicKey));

        byte[] modifiedSignature = signature.clone();
        modifiedSignature[0] = (byte) (modifiedSignature[0] ^ 0x01);
        assertEquals(0, NativeCrypto.ECDSA_verify(data, data.length, modifiedSignature, publicKey));

        byte[] modifiedData = data.clone();
        modifiedData[0] = (byte) (modifiedData[0] ^ 0x01);
        assertEquals(0, NativeCrypto.ECDSA_verify(modifiedData, data.length, signature, publicKey));

        byte[] signature2 = new byte[signatureLength];
        int invalidDataLen = data.length + 1;
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.ECDSA_sign(data, invalidDataLen, signature2, privateKey));
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.ECDSA_verify(data, invalidDataLen, signature, publicKey));
    }

    @Test
    public void xwingPublicKeyFromSeed_returnsPublicKeyIfPrivateKeyIsValid() throws Exception {
        // test vector from
        // https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-06#appendix-C
        byte[] privateKey =
                decodeHex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");

        byte[] publicKey = NativeCrypto.XWING_public_key_from_seed(privateKey);
        assertEquals(1216, publicKey.length);
        // verify that the first 8 bytes of the public key are as expected.
        assertArrayEquals(decodeHex("e2236b35a8c24b39"), Arrays.copyOf(publicKey, 8));

        byte[] privateKeyTooShort = Arrays.copyOf(privateKey, privateKey.length - 1);
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.XWING_public_key_from_seed(privateKeyTooShort));
        byte[] privateKeyTooLong = Arrays.copyOf(privateKey, privateKey.length + 1);
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.XWING_public_key_from_seed(privateKeyTooLong));
    }

    // HPKE constants.
    // see: https://www.iana.org/assignments/hpke/hpke.xhtml
    // KEM IDs
    private static final int DHKEM_P256_HKDF_SHA256 = 0x0010;
    private static final int DHKEM_P384_HKDF_SHA384 = 0x0011;
    private static final int DHKEM_P521_HKDF_SHA512 = 0x0012;
    private static final int DHKEM_X25519_HKDF_SHA256 = 0x0020;
    private static final int DHKEM_X448_HKDF_SHA256 = 0x0021;
    private static final int XWING = 0x647a;
    // KDF IDs
    private static final int HKDF_SHA256 = 0x0001;
    private static final int HKDF_SHA384 = 0x0002;
    private static final int HKDF_SHA512 = 0x0003;
    // AEAD IDs
    private static final int AES_128_GCM = 0x0001;
    private static final int AES_256_GCM = 0x0002;
    private static final int CHACHA20_POLY1305 = 0x0003;
    private static final int EXPORT_ONLY = 0xFFFF;

    @Test
    public void hpkeWithX25519Sha256_sealAndOpen_success() throws Exception {
        byte[] pkRecipient = new byte[32];
        byte[] skRecipient = new byte[32];
        NativeCrypto.X25519_keypair(pkRecipient, skRecipient);

        byte[] info = decodeHex("aa");
        byte[] plaintext = decodeHex("bb");
        byte[] aad = decodeHex("cc");

        int[] supportedAeads = new int[] {AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
        for (int aead : supportedAeads) {
            Object[] result = NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                    DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, aead, pkRecipient, info);
            NativeRef.EVP_HPKE_CTX ctxSender = (NativeRef.EVP_HPKE_CTX) result[0];
            byte[] encapsulated = (byte[]) result[1];
            byte[] ciphertext = NativeCrypto.EVP_HPKE_CTX_seal(ctxSender, plaintext, aad);

            NativeRef.EVP_HPKE_CTX ctxRecipient =
                    (NativeRef.EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_base_mode_recipient(
                            DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, aead, skRecipient, encapsulated,
                            info);
            byte[] output = NativeCrypto.EVP_HPKE_CTX_open(ctxRecipient, ciphertext, aad);

            assertArrayEquals(plaintext, output);
        }
    }

    @Test
    public void hpkeWithXwing_publicKeyFromSeedSealOpen_success() throws Exception {
        byte[] privateKey =
                decodeHex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        byte[] publicKey = NativeCrypto.XWING_public_key_from_seed(privateKey);

        byte[] info = decodeHex("aa");
        byte[] plaintext = decodeHex("bb");
        byte[] aad = decodeHex("cc");

        Object[] result = NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                XWING, HKDF_SHA256, HKDF_SHA256, publicKey, info);
        NativeRef.EVP_HPKE_CTX ctxSender = (NativeRef.EVP_HPKE_CTX) result[0];
        byte[] encapsulated = (byte[]) result[1];
        assertEquals(1120, encapsulated.length);

        byte[] ciphertext = NativeCrypto.EVP_HPKE_CTX_seal(ctxSender, plaintext, aad);

        NativeRef.EVP_HPKE_CTX ctxRecipient =
                (NativeRef.EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_base_mode_recipient(
                        /* kem= */ 0x647a, /*kdf=*/0x0001, /* aead= */ 0x0001, privateKey,
                        encapsulated, info);
        byte[] output = NativeCrypto.EVP_HPKE_CTX_open(ctxRecipient, ciphertext, aad);

        assertArrayEquals(plaintext, output);
    }

    @Test
    public void hpkeWithUnsupportedAlgorithms_setup_throwsIllegalArgumentException()
            throws Exception {
        byte[] pkRecipient = new byte[32];
        byte[] skRecipient = new byte[32];
        NativeCrypto.X25519_keypair(pkRecipient, skRecipient);
        byte[] info = decodeHex("aa");

        // These KEM IDs are currently not supported in Conscrypt.
        assertThrows(IllegalArgumentException.class,
                ()
                        -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(DHKEM_P256_HKDF_SHA256,
                                HKDF_SHA256, AES_128_GCM, pkRecipient, info));
        assertThrows(IllegalArgumentException.class,
                ()
                        -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(DHKEM_P384_HKDF_SHA384,
                                HKDF_SHA256, AES_128_GCM, pkRecipient, info));
        assertThrows(IllegalArgumentException.class,
                ()
                        -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(DHKEM_P521_HKDF_SHA512,
                                HKDF_SHA256, AES_128_GCM, pkRecipient, info));
        assertThrows(IllegalArgumentException.class,
                ()
                        -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(DHKEM_X448_HKDF_SHA256,
                                HKDF_SHA256, AES_128_GCM, pkRecipient, info));

        // These KDF IDs are currently not supported in Conscrypt.
        assertThrows(IllegalArgumentException.class,
                ()
                        -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                                DHKEM_X25519_HKDF_SHA256, HKDF_SHA384, AES_128_GCM, pkRecipient,
                                info));
        assertThrows(IllegalArgumentException.class,
                ()
                        -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                                DHKEM_X25519_HKDF_SHA256, HKDF_SHA512, AES_128_GCM, pkRecipient,
                                info));

        // These AEAD IDs are currently not supported in Conscrypt.
        assertThrows(IllegalArgumentException.class,
                ()
                        -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                                DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, EXPORT_ONLY, pkRecipient,
                                info));
    }

    @Test
    public void hpkeWithX25519Sha256_openWithRfc9180TestVector_success() throws Exception {
        // Test Vector from RFC 9180, Section A.1.1.1
        byte[] info = decodeHex("4f6465206f6e2061204772656369616e2055726e");
        byte[] skRecipient =
                decodeHex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        byte[] enc = decodeHex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        byte[] pt = decodeHex("4265617574792069732074727574682c20747275746820626561757479");
        byte[] aad = decodeHex("436f756e742d30");
        byte[] ct = decodeHex("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9"
                + "6d8770ac83d07bea87e13c512a");

        NativeRef.EVP_HPKE_CTX ctxRecipient =
                (NativeRef.EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_base_mode_recipient(
                        DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, AES_128_GCM, skRecipient, enc, info);

        byte[] openOutput = NativeCrypto.EVP_HPKE_CTX_open(ctxRecipient, ct, aad);
        assertArrayEquals(pt, openOutput);
    }

    @Test
    public void hpkeWithX25519Sha256_export_returnsValueAsInRfc9180() throws Exception {
        // Test Vector from RFC 9180, Section A.1.1.2
        byte[] info = decodeHex("4f6465206f6e2061204772656369616e2055726e");
        byte[] skRecipient =
                decodeHex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        byte[] enc = decodeHex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        byte[] exporterContext = decodeHex("");
        int exporterLength = 32;
        byte[] exportedValue =
                decodeHex("3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee");

        NativeRef.EVP_HPKE_CTX ctxRecipient =
                (NativeRef.EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_base_mode_recipient(
                        DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, AES_128_GCM, skRecipient, enc, info);

        byte[] output =
                NativeCrypto.EVP_HPKE_CTX_export(ctxRecipient, exporterContext, exporterLength);
        assertArrayEquals(exportedValue, output);
    }

    @Test
    public void test_mldsa65_works() throws Exception {
        byte[] privateKeySeed =
                decodeHex("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D");
        byte[] data =
                decodeHex("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");

        byte[] publicKey = NativeCrypto.MLDSA65_public_key_from_seed(privateKeySeed);
        assertEquals(1952, publicKey.length);

        byte[] signature = NativeCrypto.MLDSA65_sign(data, data.length, privateKeySeed);
        assertEquals(3309, signature.length);

        int result = NativeCrypto.MLDSA65_verify(data, data.length, signature, publicKey);
        assertEquals(1, result);

        // data buffer is larger than data
        byte[] dataBuffer = Arrays.copyOf(data, data.length + 42);
        assertEquals(1, NativeCrypto.MLDSA65_verify(dataBuffer, data.length, signature, publicKey));

        // data too short
        assertEquals(0, NativeCrypto.MLDSA65_verify(data, data.length - 1, signature, publicKey));

        byte[] signatureTooShort = Arrays.copyOf(signature, signature.length - 1);
        assertEquals(
                0, NativeCrypto.MLDSA65_verify(data, data.length, signatureTooShort, publicKey));

        byte[] signatureTooLong = Arrays.copyOf(signature, signature.length + 1);
        assertEquals(
                0, NativeCrypto.MLDSA65_verify(data, data.length, signatureTooLong, publicKey));

        byte[] modifiedSignature = signature.clone();
        modifiedSignature[0] = (byte) (modifiedSignature[0] ^ 0x01);
        assertEquals(
                0, NativeCrypto.MLDSA65_verify(data, data.length, modifiedSignature, publicKey));

        byte[] modifiedData = data.clone();
        modifiedData[0] = (byte) (modifiedData[0] ^ 0x01);
        assertEquals(
                0, NativeCrypto.MLDSA65_verify(modifiedData, data.length, signature, publicKey));

        int invalidDataLen = data.length + 1;
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA65_sign(data, invalidDataLen, privateKeySeed));
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA65_verify(data, invalidDataLen, signature, publicKey));

        byte[] privateKeySeedTooShort = Arrays.copyOf(privateKeySeed, privateKeySeed.length - 1);
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA65_public_key_from_seed(privateKeySeedTooShort));
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA65_sign(data, data.length, privateKeySeedTooShort));

        byte[] privateKeySeedTooLong = Arrays.copyOf(privateKeySeed, privateKeySeed.length + 1);
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA65_public_key_from_seed(privateKeySeedTooLong));
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA65_sign(data, data.length, privateKeySeedTooLong));

        byte[] publicKeyTooShort = Arrays.copyOf(publicKey, publicKey.length - 1);
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA65_verify(data, data.length, signature, publicKeyTooShort));

        byte[] publicKeyTooLong = Arrays.copyOf(publicKey, publicKey.length + 1);
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA65_verify(data, data.length, signature, publicKeyTooLong));
    }

    @Test
    public void test_mldsa87_works() throws Exception {
        byte[] privateKeySeed =
                decodeHex("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D");
        byte[] data =
                decodeHex("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");

        byte[] publicKey = NativeCrypto.MLDSA87_public_key_from_seed(privateKeySeed);
        assertEquals(2592, publicKey.length);

        byte[] signature = NativeCrypto.MLDSA87_sign(data, data.length, privateKeySeed);
        assertEquals(4627, signature.length);

        int result = NativeCrypto.MLDSA87_verify(data, data.length, signature, publicKey);
        assertEquals(1, result);

        // data buffer is larger than data
        byte[] dataBuffer = Arrays.copyOf(data, data.length + 42);
        assertEquals(1, NativeCrypto.MLDSA87_verify(dataBuffer, data.length, signature, publicKey));

        // data too short
        assertEquals(0, NativeCrypto.MLDSA87_verify(data, data.length - 1, signature, publicKey));

        byte[] signatureTooShort = Arrays.copyOf(signature, signature.length - 1);
        assertEquals(
                0, NativeCrypto.MLDSA87_verify(data, data.length, signatureTooShort, publicKey));

        byte[] signatureTooLong = Arrays.copyOf(signature, signature.length + 1);
        assertEquals(
                0, NativeCrypto.MLDSA87_verify(data, data.length, signatureTooLong, publicKey));

        byte[] modifiedSignature = signature.clone();
        modifiedSignature[0] = (byte) (modifiedSignature[0] ^ 0x01);
        assertEquals(
                0, NativeCrypto.MLDSA87_verify(data, data.length, modifiedSignature, publicKey));

        byte[] modifiedData = data.clone();
        modifiedData[0] = (byte) (modifiedData[0] ^ 0x01);
        assertEquals(
                0, NativeCrypto.MLDSA87_verify(modifiedData, data.length, signature, publicKey));

        int invalidDataLen = data.length + 1;
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA87_sign(data, invalidDataLen, privateKeySeed));
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA87_verify(data, invalidDataLen, signature, publicKey));

        byte[] privateKeySeedTooShort = Arrays.copyOf(privateKeySeed, privateKeySeed.length - 1);
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA87_public_key_from_seed(privateKeySeedTooShort));
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA87_sign(data, data.length, privateKeySeedTooShort));

        byte[] privateKeySeedTooLong = Arrays.copyOf(privateKeySeed, privateKeySeed.length + 1);
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA87_public_key_from_seed(privateKeySeedTooLong));
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA87_sign(data, data.length, privateKeySeedTooLong));

        byte[] publicKeyTooShort = Arrays.copyOf(publicKey, publicKey.length - 1);
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA87_verify(data, data.length, signature, publicKeyTooShort));

        byte[] publicKeyTooLong = Arrays.copyOf(publicKey, publicKey.length + 1);
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.MLDSA87_verify(data, data.length, signature, publicKeyTooLong));
    }

    @Test
    public void test_slhdsa_sha2_128s_works() throws Exception {
        byte[] publicKey = new byte[32];
        byte[] privateKey = new byte[64];
        NativeCrypto.SLHDSA_SHA2_128S_generate_key(publicKey, privateKey);

        byte[] data = decodeHex("AB");

        byte[] signature = NativeCrypto.SLHDSA_SHA2_128S_sign(data, data.length, privateKey);
        assertEquals(7856, signature.length);

        int result = NativeCrypto.SLHDSA_SHA2_128S_verify(data, data.length, signature, publicKey);
        assertEquals(1, result);

        // data buffer is larger than data
        byte[] dataBuffer = Arrays.copyOf(data, data.length + 42);
        assertEquals(1,
                NativeCrypto.SLHDSA_SHA2_128S_verify(
                        dataBuffer, data.length, signature, publicKey));

        // data too short
        assertEquals(0,
                NativeCrypto.SLHDSA_SHA2_128S_verify(data, data.length - 1, signature, publicKey));

        byte[] signatureTooShort = Arrays.copyOf(signature, signature.length - 1);
        assertEquals(0,
                NativeCrypto.SLHDSA_SHA2_128S_verify(
                        data, data.length, signatureTooShort, publicKey));

        byte[] signatureTooLong = Arrays.copyOf(signature, signature.length + 1);
        assertEquals(0,
                NativeCrypto.SLHDSA_SHA2_128S_verify(
                        data, data.length, signatureTooLong, publicKey));

        byte[] modifiedSignature = signature.clone();
        modifiedSignature[0] = (byte) (modifiedSignature[0] ^ 0x01);
        assertEquals(0,
                NativeCrypto.SLHDSA_SHA2_128S_verify(
                        data, data.length, modifiedSignature, publicKey));

        byte[] modifiedData = data.clone();
        modifiedData[0] = (byte) (modifiedData[0] ^ 0x01);
        assertEquals(0,
                NativeCrypto.SLHDSA_SHA2_128S_verify(
                        modifiedData, modifiedData.length, signature, publicKey));

        int invalidDataLen = data.length + 1;
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_sign(data, invalidDataLen, privateKey));
        assertThrows(RuntimeException.class,
                ()
                        -> NativeCrypto.SLHDSA_SHA2_128S_verify(
                                data, invalidDataLen, signature, publicKey));

        byte[] privateKeyTooShort = Arrays.copyOf(privateKey, privateKey.length - 1);
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_sign(data, data.length, privateKeyTooShort));

        byte[] privateKeyTooLong = Arrays.copyOf(privateKey, privateKey.length + 1);
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_sign(data, data.length, privateKeyTooLong));

        byte[] publicKeyTooShort = Arrays.copyOf(publicKey, publicKey.length - 1);
        assertThrows(RuntimeException.class,
                ()
                        -> NativeCrypto.SLHDSA_SHA2_128S_verify(
                                data, data.length, signature, publicKeyTooShort));

        byte[] publicKeyTooLong = Arrays.copyOf(publicKey, publicKey.length + 1);
        assertThrows(RuntimeException.class,
                ()
                        -> NativeCrypto.SLHDSA_SHA2_128S_verify(
                                data, data.length, signature, publicKeyTooLong));

        assertThrows(RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_generate_key(publicKey, privateKeyTooShort));
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_generate_key(publicKeyTooShort, privateKey));
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_generate_key(publicKey, privateKeyTooLong));
        assertThrows(RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_generate_key(publicKeyTooLong, privateKey));
    }
    }
