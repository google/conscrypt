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
import org.conscrypt.javax.net.ssl.TestSSLContext;
import org.conscrypt.javax.net.ssl.TestSSLEnginePair;
import org.conscrypt.java.security.StandardNames;
import org.conscrypt.java.security.TestKeyStore;
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
    private static TrustManager[] TRUST_ALL;

    @BeforeClass
    @SuppressWarnings("JdkObsolete") // Public API KeyStore.aliases() uses Enumeration
    public static void initStatics() throws Exception {

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

        TRUST_ALL = new TrustManager[] {
            new X509TrustManager() {
                @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
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

        TestSSLEnginePair pair = TestSSLEnginePair.create(new TestSSLEnginePair.Hooks() {
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

        // Verify client certificates
        assertNotNull(pair.client.getSession().getPeerCertificates());
        assertEquals(ENCODED_SERVER_CERTIFICATES.length, pair.client.getSession().getPeerCertificates().length);

        pair.close();
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

        TestSSLEnginePair pair = TestSSLEnginePair.create(new TestSSLEnginePair.Hooks() {
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

        // Verify handshake completed
        assertNotNull(pair.client.getSession().getPeerCertificates());

        long clientSsl = getNativeSsl(pair.client);
        NativeSsl clientHolder = getNativeSslHolder(pair.client);
        assertFalse(NativeCrypto.SSL_ech_accepted(clientSsl, clientHolder)); // Server wasn't configured for ECH

        pair.close();
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
        // TODO running this with checkErrorQueue after
        // test_SSL_CTX_ech_enable_server_ssl_with_bad_config fails here
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
        TestSSLEnginePair pair = TestSSLEnginePair.create(c, new TestSSLEnginePair.Hooks() {
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                // Ensure TLS 1.2 to match the cipher suite expectation
                client.setEnabledProtocols(new String[] { "TLSv1.2" });
                server.setEnabledProtocols(new String[] { "TLSv1.2" });
                client.setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"});
                server.setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"});
            }
        });
        assertNotNull(pair.client.getSession().getPeerCertificates());
        assertEquals(ENCODED_SERVER_CERTIFICATES.length, pair.client.getSession().getPeerCertificates().length);
        assertEquals("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", pair.client.getSession().getCipherSuite());
        pair.close();
    }

    @Test
    public void test_SSL_do_handshake_reusedSession() throws Exception {
        // normal client and server case
        TestSSLContext c = TestSSLContext.create(TestKeyStore.getClient(), TestKeyStore.getServer());
        TestSSLEnginePair pair1 = TestSSLEnginePair.create(c);
        SSLSession session1 = pair1.client.getSession();
        pair1.close();

        TestSSLEnginePair pair2 = TestSSLEnginePair.create(c, new TestSSLEnginePair.Hooks() {
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                // Use reflection to set session if possible, or just rely on context
                try {
                    setSession(client, session1);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
        assertArrayEquals(session1.getId(), pair2.client.getSession().getId());
        pair2.close();
    }

    @Test
    public void test_SSL_do_handshake_optional_client_certificate() throws Exception {
        // optional client certificate case
        TestSSLContext c = TestSSLContext.create(TestKeyStore.getClientCertificate(), TestKeyStore.getServer());
        TestSSLEnginePair pair = TestSSLEnginePair.create(c, new TestSSLEnginePair.Hooks() {
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                server.setWantClientAuth(true);
            }
        });
        assertEquals(ENCODED_CLIENT_CERTIFICATES.length, pair.server.getSession().getPeerCertificates().length);
        pair.close();
    }

    @Test
    public void test_SSL_do_handshake_missing_required_certificate() throws Exception {
        // required client certificate negative case. Use a client context WITHOUT keys.
        TestSSLContext c = TestSSLContext.create(TestKeyStore.getClient(), TestKeyStore.getServer());
        try {
            TestSSLEnginePair.create(c, new TestSSLEnginePair.Hooks() {
                void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                    server.setNeedClientAuth(true);
                }
            });
            fail("Should have thrown SSLHandshakeException");
        } catch (IOException e) {
            if (!(e.getCause() instanceof SSLHandshakeException)) throw e;
        }
    }

    @Test
    public void test_SSL_do_handshake_with_channel_id_normal() throws Exception {
        // Normal handshake with TLS Channel ID.
        TestSSLContext c = TestSSLContext.create(TestKeyStore.getClient(), TestKeyStore.getServer());
        TestSSLEnginePair pair = TestSSLEnginePair.create(c, new TestSSLEnginePair.Hooks() {
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                try {
                    Conscrypt.setChannelIdEnabled(client, true);
                    Conscrypt.setChannelIdPrivateKey(client, CHANNEL_ID_PRIVATE_KEY.getPrivateKey());
                    NativeCrypto.SSL_enable_tls_channel_id(getNativeSsl(server), getNativeSslHolder(server));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
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
        TestSSLEnginePair pair = TestSSLEnginePair.create(c, new TestSSLEnginePair.Hooks() {
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                client.setEnabledCipherSuites(new String[] {"TLS_PSK_WITH_AES_128_CBC_SHA"});
                server.setEnabledCipherSuites(new String[] {"TLS_PSK_WITH_AES_128_CBC_SHA"});
                // Force TLS 1.2 for PSK
                client.setEnabledProtocols(new String[] { "TLSv1.2" });
                server.setEnabledProtocols(new String[] { "TLSv1.2" });
                installPskCallbacks(client, pskKey, "identity");
                installPskCallbacks(server, pskKey, null);
            }
        });
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
        TestSSLEnginePair pair = TestSSLEnginePair.create(c, new TestSSLEnginePair.Hooks() {
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                try {
                    NativeCrypto.SSL_set_tlsext_host_name(getNativeSsl(client), getNativeSslHolder(client), hostname);
                } catch (SSLException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        assertEquals(hostname, NativeCrypto.SSL_get_servername(getNativeSsl(pair.server), getNativeSslHolder(pair.server)));
        pair.close();
    }

    @Test
    public void test_SSL_cipher_names() throws Exception {
        TestSSLContext c = TestSSLContext.create();
        TestSSLEnginePair pair = TestSSLEnginePair.create(c, new TestSSLEnginePair.Hooks() {
            void beforeBeginHandshake(SSLEngine client, SSLEngine server) {
                client.setEnabledProtocols(new String[] { "TLSv1.2" });
                server.setEnabledProtocols(new String[] { "TLSv1.2" });
                client.setEnabledCipherSuites(new String[] {"ECDHE-RSA-AES128-GCM-SHA256"});
                server.setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"});
            }
        });
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
        TestSSLEnginePair pair = TestSSLEnginePair.create(c);
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
        TestSSLEnginePair pair = TestSSLEnginePair.create(c);
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
        TestSSLEnginePair pair = TestSSLEnginePair.create(c);
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
        TestSSLEnginePair pair = TestSSLEnginePair.create(c);
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
        TestSSLEnginePair pair = TestSSLEnginePair.create(c);
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

    private static long getNativeSsl(SSLEngine engine) {
        try {
            Class<?> clazz = engine.getClass();
            while (clazz != null) {
                try {
                    Method m = clazz.getDeclaredMethod("getNativeSsl");
                    m.setAccessible(true);
                    return (long) m.invoke(engine);
                } catch (NoSuchMethodException ignored) {
                }
                clazz = clazz.getSuperclass();
            }
            throw new RuntimeException("Method getNativeSsl not found on " + engine.getClass());
        } catch (Exception e) {
            throw new RuntimeException("Failed to get native SSL pointer", e);
        }
    }

    private static NativeSsl getNativeSslHolder(SSLEngine engine) {
        try {
            Class<?> clazz = engine.getClass();
            while (clazz != null) {
                try {
                    Field f = clazz.getDeclaredField("ssl");
                    f.setAccessible(true);
                    return (NativeSsl) f.get(engine);
                } catch (NoSuchFieldException ignored) {
                }
                clazz = clazz.getSuperclass();
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static long getNativeSession(SSLSession session) {
        try {
            Class<?> clazz = session.getClass();
            while (clazz != null) {
                try {
                    Method m = clazz.getDeclaredMethod("getNativePointer");
                    m.setAccessible(true);
                    return (long) m.invoke(session);
                } catch (NoSuchMethodException ignored) {
                }
                clazz = clazz.getSuperclass();
            }
             throw new RuntimeException("Method getNativePointer not found on " + session.getClass());
        } catch (Exception e) {
            throw new RuntimeException("Failed to get native session pointer", e);
        }
    }

    private void setSession(SSLEngine engine, SSLSession session) throws Exception {
        Class<?> clazz = engine.getClass();
        while (clazz != null) {
            try {
                Method m = clazz.getDeclaredMethod("setSession", SSLSession.class);
                m.setAccessible(true);
                m.invoke(engine, session);
                return;
            } catch (NoSuchMethodException ignored) {
            }
            clazz = clazz.getSuperclass();
        }
        throw new RuntimeException("setSession not found on " + engine.getClass());
    }

    private static void setClientSessionCallbacks(SSLEngine engine, SSLHandshakeCallbacks callbacks) throws Exception {
        Class<?> clazz = engine.getClass();
        while (clazz != null) {
            try {
                Method m = clazz.getDeclaredMethod("setClientSessionCallbacks", long.class, SSLHandshakeCallbacks.class);
                m.setAccessible(true);
                long ssl = getNativeSsl(engine);
                m.invoke(null, ssl, callbacks);
                return;
            } catch (NoSuchMethodException ignored) {
            }
            clazz = clazz.getSuperclass();
        }
    }

    private static void setServerSessionCallbacks(SSLEngine engine, SSLHandshakeCallbacks callbacks) throws Exception {
        Class<?> clazz = engine.getClass();
        while (clazz != null) {
            try {
                Method m = clazz.getDeclaredMethod("setServerSessionCallbacks", long.class, SSLHandshakeCallbacks.class);
                m.setAccessible(true);
                long ssl = getNativeSsl(engine);
                m.invoke(null, ssl, callbacks);
                return;
            } catch (NoSuchMethodException ignored) {
            }
            clazz = clazz.getSuperclass();
        }
    }

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
}

