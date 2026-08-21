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
import org.conscrypt.io.IoUtils;
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
import java.io.EOFException;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import java.security.MessageDigest;
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

import javax.crypto.BadPaddingException;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import javax.security.auth.x500.X500Principal;

@RunWith(JUnit4.class)
public class NativeCryptoTest {
    private static final long NULL = 0;
    private static final FileDescriptor INVALID_FD = new FileDescriptor();
    private static final SSLHandshakeCallbacks DUMMY_CB =
            new TestSSLHandshakeCallbacks(null, 0, null, null);

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
    private static Method m_Platform_getFileDescriptor;
    private static RSAPrivateCrtKey TEST_RSA_KEY;

    @BeforeClass
    @SuppressWarnings("JdkObsolete") // Public API KeyStore.aliases() uses Enumeration
    public static void initStatics() throws Exception {
        if (!TestUtils.isJavaVersion(17)) {
            Class<?> c_Platform = TestUtils.conscryptClass("Platform");
            m_Platform_getFileDescriptor =
                    c_Platform.getDeclaredMethod("getFileDescriptor", Socket.class);
            m_Platform_getFileDescriptor.setAccessible(true);
        }

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

        // RSA keys are slow to generate, so prefer to reuse the key when possible.
        TEST_RSA_KEY = generateRsaKey();
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

    // Test values from wycheproof/testvectors/rsa_pkcs1_2048_test.json.
    @Test
    public void wrap_RSA_private_key_pkcs8_success() throws Exception {
        byte[] expectedPkcs8 = decodeHex(
                "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100b3510a"
                + "2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d2792e51aad5c1"
                + "24b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627ef5398b52c"
                + "0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247a"
                + "f9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3"
                + "391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e88"
                + "8d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af57326"
                + "1c98c8400aa12af38e43cad84d0203010001028201001a502d0eea6c7b69e21d5839101f705456ed"
                + "0ef852fb47fe21071f54c5f33c8ceb066c62d727e32d26c58137329f89d3195325b795264c195d85"
                + "472f7507dbd0961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131c543"
                + "ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9f19d96ea4c9afcbfe144"
                + "1ccc802cfb0689f59d804c6a4e4f404c15174745ed6cb8bc88ef0b33ba0d2a80e35e43bc90f35005"
                + "2e72016e75b00d357a381c9c0d467069ca660887c987766349fcc43460b4aa516bce079edd87ba16"
                + "4307b752c277ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd0281"
                + "8100ec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4fb71bd4dd856124498aaeba983d7"
                + "ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3aa15e74a1768778093be0edd4a8d"
                + "09b2def6dc9b67ff85764625c2e19236db4c401ce30a2572d3ecb4f969b7ad19c522c02d77446567"
                + "6e1a3776c54d6248348b02818100c2742abcd9897bd4b0b671f973fc82a8f84abf5705ff88dd4194"
                + "8623afe9dca60dc6543390767feaebeb539576ee8bfa61b5fcbca94a7cef75a09150c540fa9694dd"
                + "8004ad23718c889049219369c99f4458d4afc148f6f07df87324a96d9cf7b385dd8622414a1832f9"
                + "f29446f050c2d5a6407649dc41ab70e23b3dcc22c9870281810096a9798d250263400bb627734288"
                + "1627e07cecdf91187b01b89ff47314188a7c20fb24800156d2c85d5666e8df6ceff9f9804ddfad80"
                + "ff5767de56ecc029c72bf6c717df9f64daafc29acf9dc7908f9a0ad67e20e8949936ccba18d021a2"
                + "c4febb04349a2b2047c4901385b6e5d0c691d118b33f81802b32ac272ef09e42fad50281800554f4"
                + "1b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9e2dab6fee7b2455bafb42037e9d2"
                + "f7e533f348a147412fd72080be7c2633f5d802c91c39e6bcece3e675e59995033c55737020dad9e8"
                + "b30d04b828adfb9304ad54a11a35a4f50709876ac5b118236ba76a4d7c9a291dd9607b169de1d182"
                + "385691999f0281801c640189d9bfe8c623833210a76c420c6f44e5d760e259916cec2ae2b1564569"
                + "60fd95e2747660c389562250f055049cfab7e5c3039549384a7a2aaeb1c824d3af709482a8cf9b58"
                + "7022a00b1f0722db50f33cb26dc20dd2245d5265df61ee2983c938c2167dcee121fc4b4479c237e7"
                + "28cf633ab60a8c0ecd04fce7e3baa559");
        byte[] rawKey = decodeHex(
                "308204a30201000282010100b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871"
                + "b808bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013"
                + "cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf8"
                + "61075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e46"
                + "48cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9d"
                + "fed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e76"
                + "20a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d0203010001028201001a502d0e"
                + "ea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8ceb066c62d727e32d26c58137"
                + "329f89d3195325b795264c195d85472f7507dbd0961d2951f935a26b34f0ac24d15490e1128a9b71"
                + "38915bc7dbfa8fe396357131c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d"
                + "00f003d9f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6cb8bc88ef"
                + "0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d467069ca660887c987766349fc"
                + "c43460b4aa516bce079edd87ba164307b752c277ed9528ad3ba0bf1877349ed3b7966a6c24011040"
                + "9bf4d0fade0c68fdadd847fd02818100ec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4"
                + "fb71bd4dd856124498aaeba983d7ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3"
                + "aa15e74a1768778093be0edd4a8d09b2def6dc9b67ff85764625c2e19236db4c401ce30a2572d3ec"
                + "b4f969b7ad19c522c02d774465676e1a3776c54d6248348b02818100c2742abcd9897bd4b0b671f9"
                + "73fc82a8f84abf5705ff88dd41948623afe9dca60dc6543390767feaebeb539576ee8bfa61b5fcbc"
                + "a94a7cef75a09150c540fa9694dd8004ad23718c889049219369c99f4458d4afc148f6f07df87324"
                + "a96d9cf7b385dd8622414a1832f9f29446f050c2d5a6407649dc41ab70e23b3dcc22c98702818100"
                + "96a9798d250263400bb6277342881627e07cecdf91187b01b89ff47314188a7c20fb24800156d2c8"
                + "5d5666e8df6ceff9f9804ddfad80ff5767de56ecc029c72bf6c717df9f64daafc29acf9dc7908f9a"
                + "0ad67e20e8949936ccba18d021a2c4febb04349a2b2047c4901385b6e5d0c691d118b33f81802b32"
                + "ac272ef09e42fad50281800554f41b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9"
                + "e2dab6fee7b2455bafb42037e9d2f7e533f348a147412fd72080be7c2633f5d802c91c39e6bcece3"
                + "e675e59995033c55737020dad9e8b30d04b828adfb9304ad54a11a35a4f50709876ac5b118236ba7"
                + "6a4d7c9a291dd9607b169de1d182385691999f0281801c640189d9bfe8c623833210a76c420c6f44"
                + "e5d760e259916cec2ae2b156456960fd95e2747660c389562250f055049cfab7e5c3039549384a7a"
                + "2aaeb1c824d3af709482a8cf9b587022a00b1f0722db50f33cb26dc20dd2245d5265df61ee2983c9"
                + "38c2167dcee121fc4b4479c237e728cf633ab60a8c0ecd04fce7e3baa559");

        byte[] result = NativeCrypto.wrap_RSA_private_key_pkcs8(rawKey);
        assertArrayEquals(expectedPkcs8, result);
    }

    @Test
    public void wrap_RSA_private_key_pkcs8_fail() throws Exception {
        byte[] invalidKey = decodeHex("1234567890abcdef");
        assertThrows(ParsingException.class,
                     () -> { NativeCrypto.wrap_RSA_private_key_pkcs8(invalidKey); });
    }

    @Test
    public void wrap_EC_private_key_pkcs8_success() throws Exception {
        byte[] expectedPkcs8 = decodeHex(
                "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420b94e7609a7"
                + "176abafbd4a34fabae42b091e44d9e46e67fca566c2a188a63c65f");
        byte[] rawKey = decodeHex("30310201010420b94e7609a7176abafbd4a34fabae42b091e44d9e46e67fca56"
                                  + "6c2a188a63c65fa00a06082a8648ce3d030107");

        byte[] result = NativeCrypto.wrap_EC_private_key_pkcs8(rawKey);
        assertArrayEquals(expectedPkcs8, result);
    }

    @Test
    public void wrap_EC_private_key_pkcs8_fail() throws Exception {
        byte[] invalidKey = decodeHex("1234567890abcdef");
        assertThrows(ParsingException.class,
                     () -> NativeCrypto.wrap_EC_private_key_pkcs8(invalidKey));
    }

    // Test value from wycheproof/testvectors/rsa_pkcs1_2048_test.json.
    @Test
    public void unwrap_RSA_private_key_pkcs8_success() throws Exception {
        byte[] expectedRawKey = decodeHex(
                "308204a30201000282010100b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871"
                + "b808bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013"
                + "cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf8"
                + "61075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e46"
                + "48cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9d"
                + "fed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e76"
                + "20a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d0203010001028201001a502d0e"
                + "ea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8ceb066c62d727e32d26c58137"
                + "329f89d3195325b795264c195d85472f7507dbd0961d2951f935a26b34f0ac24d15490e1128a9b71"
                + "38915bc7dbfa8fe396357131c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d"
                + "00f003d9f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6cb8bc88ef"
                + "0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d467069ca660887c987766349fc"
                + "c43460b4aa516bce079edd87ba164307b752c277ed9528ad3ba0bf1877349ed3b7966a6c24011040"
                + "9bf4d0fade0c68fdadd847fd02818100ec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4"
                + "fb71bd4dd856124498aaeba983d7ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3"
                + "aa15e74a1768778093be0edd4a8d09b2def6dc9b67ff85764625c2e19236db4c401ce30a2572d3ec"
                + "b4f969b7ad19c522c02d774465676e1a3776c54d6248348b02818100c2742abcd9897bd4b0b671f9"
                + "73fc82a8f84abf5705ff88dd41948623afe9dca60dc6543390767feaebeb539576ee8bfa61b5fcbc"
                + "a94a7cef75a09150c540fa9694dd8004ad23718c889049219369c99f4458d4afc148f6f07df87324"
                + "a96d9cf7b385dd8622414a1832f9f29446f050c2d5a6407649dc41ab70e23b3dcc22c98702818100"
                + "96a9798d250263400bb6277342881627e07cecdf91187b01b89ff47314188a7c20fb24800156d2c8"
                + "5d5666e8df6ceff9f9804ddfad80ff5767de56ecc029c72bf6c717df9f64daafc29acf9dc7908f9a"
                + "0ad67e20e8949936ccba18d021a2c4febb04349a2b2047c4901385b6e5d0c691d118b33f81802b32"
                + "ac272ef09e42fad50281800554f41b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9"
                + "e2dab6fee7b2455bafb42037e9d2f7e533f348a147412fd72080be7c2633f5d802c91c39e6bcece3"
                + "e675e59995033c55737020dad9e8b30d04b828adfb9304ad54a11a35a4f50709876ac5b118236ba7"
                + "6a4d7c9a291dd9607b169de1d182385691999f0281801c640189d9bfe8c623833210a76c420c6f44"
                + "e5d760e259916cec2ae2b156456960fd95e2747660c389562250f055049cfab7e5c3039549384a7a"
                + "2aaeb1c824d3af709482a8cf9b587022a00b1f0722db50f33cb26dc20dd2245d5265df61ee2983c9"
                + "38c2167dcee121fc4b4479c237e728cf633ab60a8c0ecd04fce7e3baa559");
        byte[] pkcs8Der = decodeHex(
                "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100b3510a"
                + "2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d2792e51aad5c1"
                + "24b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627ef5398b52c"
                + "0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247a"
                + "f9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3"
                + "391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e88"
                + "8d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af57326"
                + "1c98c8400aa12af38e43cad84d0203010001028201001a502d0eea6c7b69e21d5839101f705456ed"
                + "0ef852fb47fe21071f54c5f33c8ceb066c62d727e32d26c58137329f89d3195325b795264c195d85"
                + "472f7507dbd0961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131c543"
                + "ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9f19d96ea4c9afcbfe144"
                + "1ccc802cfb0689f59d804c6a4e4f404c15174745ed6cb8bc88ef0b33ba0d2a80e35e43bc90f35005"
                + "2e72016e75b00d357a381c9c0d467069ca660887c987766349fcc43460b4aa516bce079edd87ba16"
                + "4307b752c277ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd0281"
                + "8100ec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4fb71bd4dd856124498aaeba983d7"
                + "ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3aa15e74a1768778093be0edd4a8d"
                + "09b2def6dc9b67ff85764625c2e19236db4c401ce30a2572d3ecb4f969b7ad19c522c02d77446567"
                + "6e1a3776c54d6248348b02818100c2742abcd9897bd4b0b671f973fc82a8f84abf5705ff88dd4194"
                + "8623afe9dca60dc6543390767feaebeb539576ee8bfa61b5fcbca94a7cef75a09150c540fa9694dd"
                + "8004ad23718c889049219369c99f4458d4afc148f6f07df87324a96d9cf7b385dd8622414a1832f9"
                + "f29446f050c2d5a6407649dc41ab70e23b3dcc22c9870281810096a9798d250263400bb627734288"
                + "1627e07cecdf91187b01b89ff47314188a7c20fb24800156d2c85d5666e8df6ceff9f9804ddfad80"
                + "ff5767de56ecc029c72bf6c717df9f64daafc29acf9dc7908f9a0ad67e20e8949936ccba18d021a2"
                + "c4febb04349a2b2047c4901385b6e5d0c691d118b33f81802b32ac272ef09e42fad50281800554f4"
                + "1b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9e2dab6fee7b2455bafb42037e9d2"
                + "f7e533f348a147412fd72080be7c2633f5d802c91c39e6bcece3e675e59995033c55737020dad9e8"
                + "b30d04b828adfb9304ad54a11a35a4f50709876ac5b118236ba76a4d7c9a291dd9607b169de1d182"
                + "385691999f0281801c640189d9bfe8c623833210a76c420c6f44e5d760e259916cec2ae2b1564569"
                + "60fd95e2747660c389562250f055049cfab7e5c3039549384a7a2aaeb1c824d3af709482a8cf9b58"
                + "7022a00b1f0722db50f33cb26dc20dd2245d5265df61ee2983c938c2167dcee121fc4b4479c237e7"
                + "28cf633ab60a8c0ecd04fce7e3baa559");

        byte[] result = NativeCrypto.unwrap_RSA_private_key_pkcs8(pkcs8Der);
        assertArrayEquals(expectedRawKey, result);
    }

    @Test
    public void unwrap_nonRSA_private_key_pkcs8_fail() throws Exception {
        byte[] invalidKey = decodeHex("1234567890abcdef");
        assertThrows(ParsingException.class,
                     () -> NativeCrypto.unwrap_RSA_private_key_pkcs8(invalidKey));
    }

    @Test
    public void unwrap_EC_private_key_pkcs8_success() throws Exception {
        byte[] expectedRawKey =
                decodeHex("30310201010420b94e7609a7176abafbd4a34fabae42b091e44d9e46e67fca56"
                          + "6c2a188a63c65fa00a06082a8648ce3d030107");
        byte[] pkcs8Der = decodeHex(
                "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420b94e7609a7"
                + "176abafbd4a34fabae42b091e44d9e46e67fca566c2a188a63c65f");

        byte[] result = NativeCrypto.unwrap_EC_private_key_pkcs8(pkcs8Der);
        assertArrayEquals(expectedRawKey, result);
    }

    @Test
    public void unwrap_nonEC_private_key_pkcs8_fail() throws Exception {
        byte[] invalidKey = decodeHex("1234567890abcdef");
        assertThrows(ParsingException.class,
                     () -> NativeCrypto.unwrap_EC_private_key_pkcs8(invalidKey));
    }

    // Test values from wycheproof/testvectors/rsa_pss_misc_test.json.
    @Test
    public void wrap_RSA_public_key_x509_success() throws Exception {
        byte[] expectedX509 = decodeHex("30820122300d06092a864886f70d01010105000382010f003082010a02"
                                        + "82010100b3510a2bcd4ce644c5b"
                                        + "594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d27"
                                        + "92e51aad5c124b43bda453dca5"
                                        + "cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627e"
                                        + "f5398b52c0cfd97d208abeb8d7"
                                        + "c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c"
                                        + "265247af9d3c9140ccb65309d0"
                                        + "7e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18"
                                        + "098a3391b4ce7161e98d57af8a"
                                        + "947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18"
                                        + "e888d12dc6aa09ce95ecfca83c"
                                        + "c5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af5732"
                                        + "61c98c8400aa12af38e43cad84"
                                        + "d0203010001");
        byte[] rawKey = decodeHex(
                "3082010a0282010100b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc"
                + "3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1"
                + "aa"
                + "3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c67"
                + "7c"
                + "81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f"
                + "0e"
                + "e7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465"
                + "ff"
                + "a712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623ca"
                + "dc"
                + "0f097af573261c98c8400aa12af38e43cad84d0203010001");

        byte[] result = NativeCrypto.wrap_RSA_public_key_x509(rawKey);
        assertArrayEquals(expectedX509, result);
    }

    @Test
    public void wrap_RSA_public_key_x509_fail() throws Exception {
        byte[] invalidKey = decodeHex("1234567890abcdef");
        assertThrows(ParsingException.class,
                     () -> NativeCrypto.wrap_RSA_public_key_x509(invalidKey));
    }

    // Test values from third_party/wycheproof/testvectors/ecdsa_secp256r1_sha256_test.json.
    @Test
    public void wrap_EC_public_key_x509_success() throws Exception {
        byte[] expectedX509 = decodeHex(
                "3059301306072a8648ce3d020106082a8648ce3d030107034200"
                + "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964"
                + "eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e");
        byte[] rawKey =
                decodeHex("042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c77879"
                          + "64eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e");
        byte[] result = NativeCrypto.wrap_EC_public_key_x509(rawKey, "prime256v1");
        assertArrayEquals(expectedX509, result);
    }

    @Test
    public void wrap_EC_public_key_x509_wrong_key_fails() throws Exception {
        byte[] invalidKey = decodeHex("1234567890abcdef");
        assertThrows(ParsingException.class,
                     () -> NativeCrypto.wrap_EC_public_key_x509(invalidKey, "prime256v1"));
    }

    @Test
    public void wrap_EC_public_key_x509_wrong_curve_fails() throws Exception {
        byte[] rawKey =
                decodeHex("042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c77879"
                          + "64eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e");
        assertThrows(ParsingException.class,
                     () -> NativeCrypto.wrap_EC_public_key_x509(rawKey, "unknowncurve"));
    }

    @Test
    public void unwrap_RSA_public_key_x509_success() throws Exception {
        byte[] expectedRawKey = decodeHex(
                "3082010a0282010100b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc"
                + "3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1"
                + "aa"
                + "3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c67"
                + "7c"
                + "81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f"
                + "0e"
                + "e7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465"
                + "ff"
                + "a712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623ca"
                + "dc"
                + "0f097af573261c98c8400aa12af38e43cad84d0203010001");
        byte[] x509Key = decodeHex("30820122300d06092a864886f70d01010105000382010f003082010a02"
                                   + "82010100b3510a2bcd4ce644c5b"
                                   + "594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d27"
                                   + "92e51aad5c124b43bda453dca5"
                                   + "cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627e"
                                   + "f5398b52c0cfd97d208abeb8d7"
                                   + "c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c"
                                   + "265247af9d3c9140ccb65309d0"
                                   + "7e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18"
                                   + "098a3391b4ce7161e98d57af8a"
                                   + "947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18"
                                   + "e888d12dc6aa09ce95ecfca83c"
                                   + "c5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af5732"
                                   + "61c98c8400aa12af38e43cad84"
                                   + "d0203010001");

        byte[] result = NativeCrypto.unwrap_RSA_public_key_x509(x509Key);
        assertArrayEquals(expectedRawKey, result);
    }

    @Test
    public void unwrap_nonRSA_public_key_x509_fail() throws Exception {
        byte[] invalidKey = decodeHex("1234567890abcdef");
        assertThrows(ParsingException.class,
                     () -> NativeCrypto.unwrap_RSA_public_key_x509(invalidKey));
    }

    // Test values from third_party/wycheproof/testvectors/ecdsa_secp256r1_sha256_test.json.
    @Test
    public void unwrap_EC_public_key_x509_success() throws Exception {
        byte[] expectedRawKey =
                decodeHex("042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c77879"
                          + "64eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e");
        byte[] x509Key = decodeHex(
                "3059301306072a8648ce3d020106082a8648ce3d030107034200"
                + "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964"
                + "eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e");

        byte[] result = NativeCrypto.unwrap_EC_public_key_x509(x509Key);
        assertArrayEquals(expectedRawKey, result);
    }

    @Test
    public void unwrap_nonEC_public_key_x509_fail() throws Exception {
        byte[] invalidKey = decodeHex("1234567890abcdef");
        assertThrows(ParsingException.class,
                     () -> NativeCrypto.unwrap_EC_public_key_x509(invalidKey));
    }

    @Test
    public void EVP_PKEY_new_RSA_invalidParameters_throwsBoringSSLErrorAndClearsQueue()
            throws Exception {
        RSAPrivateCrtKey privKey = TEST_RSA_KEY;

        RuntimeException ex = assertThrows(
                RuntimeException.class,
                ()
                        -> new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_new_RSA(
                                // we mixed the order of the arguments to make an invalid key.
                                privKey.getPrivateExponent().toByteArray(),
                                privKey.getPublicExponent().toByteArray(),
                                privKey.getModulus().toByteArray(),
                                privKey.getPrimeP().toByteArray(),
                                privKey.getPrimeQ().toByteArray(),
                                privKey.getPrimeExponentP().toByteArray(),
                                privKey.getPrimeExponentQ().toByteArray(),
                                privKey.getCrtCoefficient().toByteArray())));
        // check that the exception message contains the error message from BoringSSL.
        assertTrue(ex.getMessage().contains("OPENSSL_internal:"));

        // check that the error was cleared from the queue. We do this by trying to
        // open an invalid AEAD ciphertext, which should throw a BadPaddingException.
        // If the error was not cleared, this throws a RuntimeException instead.
        byte[] encodedKey = new byte[32];
        byte[] iv = new byte[12];
        byte[] in = new byte[100];
        byte[] aad = new byte[100];
        byte[] output = new byte[100];
        long evpAead = NativeCrypto.EVP_aead_chacha20_poly1305();
        assertThrows(BadPaddingException.class,
                     ()
                             -> NativeCrypto.EVP_AEAD_CTX_open(evpAead, encodedKey, 16, output, 0,
                                                               iv, in, 0, in.length, aad));
    }

    @Test
    public void setApplicationProtocols_invalid_clearsErrorQueue() throws Exception {
        long sslCtx = NativeCrypto.SSL_CTX_new();
        long ssl = NativeCrypto.SSL_new(sslCtx, null);
        try {
            assertThrows(SSLException.class,
                         ()
                                 -> NativeCrypto.setApplicationProtocols(
                                         ssl, null, true, new byte[] {(byte) 255, 0, 0}));

            byte[] encodedKey = new byte[32];
            byte[] iv = new byte[12];
            byte[] in = new byte[100];
            byte[] aad = new byte[100];
            byte[] output = new byte[100];
            long evpAead = NativeCrypto.EVP_aead_chacha20_poly1305();
            assertThrows(BadPaddingException.class,
                         ()
                                 -> NativeCrypto.EVP_AEAD_CTX_open(evpAead, encodedKey, 16, output,
                                                                   0, iv, in, 0, in.length, aad));
        } finally {
            NativeCrypto.SSL_free(ssl, null);
            NativeCrypto.SSL_CTX_free(sslCtx, null);
        }
    }

    @Test
    public void get_cipher_names_invalid_clearsErrorQueue() throws Exception {
        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class,
                             () -> NativeCrypto.get_cipher_names("INVALID_CIPHER_NAME"));
        assertTrue(e.getMessage().contains("Unable to"));

        byte[] encodedKey = new byte[32];
        byte[] iv = new byte[12];
        byte[] in = new byte[100];
        byte[] aad = new byte[100];
        byte[] output = new byte[100];
        long evpAead = NativeCrypto.EVP_aead_chacha20_poly1305();
        assertThrows(BadPaddingException.class,
                     ()
                             -> NativeCrypto.EVP_AEAD_CTX_open(evpAead, encodedKey, 16, output, 0,
                                                               iv, in, 0, in.length, aad));
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

        assertEquals("Same keys should be the equal", 1,
                     NativeCrypto.EVP_PKEY_cmp(pkey1, pkey1_copy));

        assertEquals("Different keys should not be equal", 0,
                     NativeCrypto.EVP_PKEY_cmp(pkey1, pkey2));
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
    public void setGroupsList_validGroups_works() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        NativeCrypto.SSL_set1_groups(s, null, new int[] {NativeConstants.NID_X25519});
        NativeCrypto.SSL_set1_groups(s, null, new int[] {NativeConstants.NID_X9_62_prime256v1});
        NativeCrypto.SSL_set1_groups(s, null, new int[] {NativeConstants.NID_secp384r1});
        NativeCrypto.SSL_set1_groups(s, null, new int[] {NativeConstants.NID_secp521r1});
        NativeCrypto.SSL_set1_groups(s, null, new int[] {NativeConstants.NID_X25519MLKEM768});
        NativeCrypto.SSL_set1_groups(s, null, new int[] {NativeConstants.NID_ML_KEM_1024});

        NativeCrypto.SSL_set1_groups(
                s, null,
                new int[] {NativeConstants.NID_X25519, NativeConstants.NID_X9_62_prime256v1,
                           NativeConstants.NID_secp384r1, NativeConstants.NID_secp521r1,
                           NativeConstants.NID_X25519MLKEM768, NativeConstants.NID_ML_KEM_1024});

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void setGroupsList_invalidInput_throws() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_set1_groups(s, null, null));

        assertThrows(SSLException.class,
                     ()
                             -> NativeCrypto.SSL_set1_groups(
                                     s, null, new int[] {NativeConstants.EVP_PKEY_RSA}));

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);
    }

    @Test
    public void setLocalCertsAndPrivateKey_withNullSSLShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                     ()
                             -> NativeCrypto.setLocalCertsAndPrivateKey(
                                     NULL, null, ENCODED_SERVER_CERTIFICATES,
                                     SERVER_PRIVATE_KEY.getNativeRef()));
    }

    @Test
    public void setLocalCertsAndPrivateKey_withNullCertificatesShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.setLocalCertsAndPrivateKey(s, null, null,
                                                        SERVER_PRIVATE_KEY.getNativeRef());
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

        NativeCrypto.setLocalCertsAndPrivateKey(s, null, ENCODED_SERVER_CERTIFICATES,
                                                SERVER_PRIVATE_KEY.getNativeRef());

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
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final ServerSocket listener = newServerSocket();

        final byte[] key = readTestFile("boringssl-ech-private-key.bin");
        final byte[] serverConfig = readTestFile("boringssl-server-ech-config.bin");
        Hooks cHooks = new ClientHooks() {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long ssl = super.beforeHandshake(c);
                assertEquals(1,
                             NativeCrypto.SSL_set_protocol_versions(ssl, null, TLS1_VERSION,
                                                                    TLS1_3_VERSION));
                NativeCrypto.SSL_set_enable_ech_grease(ssl, null, true);
                return ssl;
            }
        };
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long ssl = super.beforeHandshake(c);
                assertEquals(1,
                             NativeCrypto.SSL_set_protocol_versions(ssl, null, TLS1_VERSION,
                                                                    TLS1_3_VERSION));
                assertTrue(NativeCrypto.SSL_CTX_ech_enable_server(c, null, key, serverConfig));
                return ssl;
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertFalse(clientCallback.serverCertificateRequestedInvoked);
        assertTrue(serverCallback.serverCertificateRequestedInvoked);
    }

    @Test
    public void test_SSL_do_handshake_ech_client_server() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final ServerSocket listener = newServerSocket();

        final byte[] key = readTestFile("boringssl-ech-private-key.bin");
        final byte[] serverConfig = readTestFile("boringssl-server-ech-config.bin");
        final byte[] clientConfigList = readTestFile("boringssl-ech-config-list.bin");
        Hooks cHooks = new ClientHooks() {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long ssl = super.beforeHandshake(c);
                assertEquals(1,
                             NativeCrypto.SSL_set_protocol_versions(ssl, null, TLS1_VERSION,
                                                                    TLS1_3_VERSION));
                assertTrue(NativeCrypto.SSL_set1_ech_config_list(ssl, null, clientConfigList));
                return ssl;
            }

            @Override
            public void afterHandshake(long session, long ssl, long context, Socket socket,
                                       FileDescriptor fd, SSLHandshakeCallbacks callback)
                    throws Exception {
                assertTrue(NativeCrypto.SSL_ech_accepted(ssl, null));
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long ssl = super.beforeHandshake(c);
                assertEquals(1,
                             NativeCrypto.SSL_set_protocol_versions(ssl, null, TLS1_VERSION,
                                                                    TLS1_3_VERSION));
                assertTrue(NativeCrypto.SSL_CTX_ech_enable_server(c, null, key, serverConfig));
                return ssl;
            }

            @Override
            public void afterHandshake(long session, long ssl, long context, Socket socket,
                                       FileDescriptor fd, SSLHandshakeCallbacks callback)
                    throws Exception {
                assertTrue(NativeCrypto.SSL_ech_accepted(ssl, null));
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
        assertFalse(serverCallback.verifyCertificateChainCalled);
        assertFalse(clientCallback.clientCertificateRequestedCalled);
        assertFalse(serverCallback.clientCertificateRequestedCalled);
        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertFalse(clientCallback.serverCertificateRequestedInvoked);
        assertTrue(serverCallback.serverCertificateRequestedInvoked);
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
    }

    @Test
    public void test_SSL_set1_ech_invalid_config_list() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        byte[] badConfigList = {0x00,        0x05,        (byte) 0xfe, 0x0d,
                                (byte) 0xff, (byte) 0xff, (byte) 0xff};
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
                             -> assertFalse(NativeCrypto.SSL_CTX_ech_enable_server(c, null, badKey,
                                                                                   serverConfig)));
    }

    @Test
    public void test_SSL_CTX_ech_enable_server_ssl_with_bad_config() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        final byte[] key = readTestFile("boringssl-ech-private-key.bin");
        byte[] badConfig = {(byte) 0xfe, (byte) 0x0d, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        assertThrows(
                InvalidKeyException.class,
                () -> assertFalse(NativeCrypto.SSL_CTX_ech_enable_server(c, null, key, badConfig)));
    }

    @Test
    public void test_SSL_CTX_ech_enable_server_ssl_with_bad_key_config() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        final byte[] badKey = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
        byte[] badConfig = {(byte) 0xfe, (byte) 0x0d, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        assertThrows(InvalidKeyException.class,
                     ()
                             -> assertFalse(NativeCrypto.SSL_CTX_ech_enable_server(c, null, badKey,
                                                                                   badConfig)));
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
        assertThrows(NullPointerException.class,
                     () -> NativeCrypto.SSL_clear_options(NULL, null, 0));
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
        assertEquals(1,
                     NativeCrypto.SSL_set_protocol_versions(s, null, TLS1_VERSION, TLS1_1_VERSION));
        assertEquals(
                1, NativeCrypto.SSL_set_protocol_versions(s, null, TLS1_2_VERSION, TLS1_2_VERSION));
        assertEquals(0,
                     NativeCrypto.SSL_set_protocol_versions(s, null, TLS1_2_VERSION + 413,
                                                            TLS1_1_VERSION));
        assertEquals(0,
                     NativeCrypto.SSL_set_protocol_versions(s, null, TLS1_1_VERSION,
                                                            TLS1_2_VERSION + 413));
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

    private static final boolean DEBUG = false;

    public static class Hooks {
        String negotiatedCipherSuite;
        boolean pskEnabled;
        byte[] pskKey;
        List<String> enabledCipherSuites;
        byte[] echRetryConfigs;
        String echNameOverride;

        /**
         * @throws SSLException if an error occurs creating the context.
         */
        public long getContext() throws SSLException {
            return NativeCrypto.SSL_CTX_new();
        }

        public long beforeHandshake(long context) throws SSLException {
            long s = NativeCrypto.SSL_new(context, null);
            // Limit cipher suites to a known set so authMethod is known.
            List<String> cipherSuites = new ArrayList<>();
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
            // Protocol list is included for determining whether to send TLS_FALLBACK_SCSV
            NativeCrypto.setEnabledCipherSuites(s, null, cipherSuites.toArray(new String[0]),
                                                new String[] {"TLSv1.2"});

            return s;
        }
        public void configureCallbacks(@SuppressWarnings("unused")
                                       TestSSLHandshakeCallbacks callbacks) {}
        public void clientCertificateRequested(@SuppressWarnings("unused") long s)
                throws CertificateEncodingException, SSLException {}
        public void afterHandshake(long session, long ssl, long context, Socket socket,
                                   FileDescriptor fd, SSLHandshakeCallbacks callback)
                throws Exception {
            if (session != NULL) {
                negotiatedCipherSuite = NativeCrypto.SSL_SESSION_cipher(session);
                NativeCrypto.SSL_SESSION_free(session);
            }
            if (ssl != NULL) {
                NativeCrypto.SSL_free(ssl, null);
            }
            if (callback instanceof TestSSLHandshakeCallbacks) {
                long bio = ((TestSSLHandshakeCallbacks) callback).getBioRef();
                if (bio != 0) {
                    NativeCrypto.BIO_free_all(bio);
                }
            }
            if (context != NULL) {
                NativeCrypto.SSL_CTX_free(context, null);
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
        private final ApplicationProtocolSelectorAdapter alpnSelector;
        private EngineTestConnection engineConn;
        private long bioRef;

        void setEngineConn(EngineTestConnection conn) {
            this.engineConn = conn;
            this.bioRef = conn.bio;
        }

        EngineTestConnection getEngineConn() {
            return engineConn;
        }

        void setBioRef(long bioRef) {
            this.bioRef = bioRef;
        }

        long getBioRef() {
            return bioRef;
        }

        TestSSLHandshakeCallbacks(Socket socket, long sslNativePointer, Hooks hooks,
                                  ApplicationProtocolSelectorAdapter alpnSelector) {
            this.socket = socket;
            this.sslNativePointer = sslNativePointer;
            this.hooks = hooks;
            this.alpnSelector = alpnSelector;
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
        private int[] signatureAlgs;
        private byte[][] asn1DerEncodedX500Principals;
        private boolean clientCertificateRequestedCalled;

        @Override
        public void clientCertificateRequested(byte[] keyTypes, int[] signatureAlgs,
                                               byte[][] asn1DerEncodedX500Principals)
                throws CertificateEncodingException, SSLException {
            if (DEBUG) {
                System.out.println("ssl=0x" + Long.toString(sslNativePointer, 16)
                                   + " clientCertificateRequested"
                                   + " keyTypes=" + Arrays.toString(keyTypes)
                                   + " asn1DerEncodedX500Principals="
                                   + Arrays.toString(asn1DerEncodedX500Principals));
            }
            this.keyTypes = keyTypes;
            this.signatureAlgs = signatureAlgs;
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
                System.out.println("ssl=0x" + Long.toString(sslNativePointer, 16)
                                   + " onSSLStateChange");
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
                                   + " identityHint=" + identityHint + " identity capacity="
                                   + identity.length + " key capacity=" + key.length);
            }
            clientPSKKeyRequestedInvoked = true;
            clientPSKKeyRequestedIdentityHint = identityHint;
            if (clientPSKKeyRequestedResultKey != null) {
                System.arraycopy(clientPSKKeyRequestedResultKey, 0, key, 0,
                                 clientPSKKeyRequestedResultKey.length);
            }
            if (clientPSKKeyRequestedResultIdentity != null) {
                System.arraycopy(
                        clientPSKKeyRequestedResultIdentity, 0, identity, 0,
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

        private boolean serverCertificateRequestedInvoked;
        private int[] serverSignatureAlgs;

        @Override
        public void serverCertificateRequested(int[] signatureAlgs) {
            serverCertificateRequestedInvoked = true;
            this.serverSignatureAlgs = signatureAlgs;
        }

        @Override
        public int selectApplicationProtocol(byte[] protocols) {
            if (alpnSelector == null) {
                fail("Should not be called when no alpnSelector");
            }
            return alpnSelector.selectApplicationProtocol(protocols);
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
                    b = pskIdentity.getBytes(StandardCharsets.UTF_8);
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
                NativeCrypto.set_SSL_psk_client_callback_enabled(s, null, true);
            }
            return s;
        }
    }

    static class ServerHooks extends Hooks {
        private final OpenSSLKey privateKey;
        private final byte[][] certificates;

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
                NativeCrypto.setLocalCertsAndPrivateKey(s, null, certificates,
                                                        privateKey.getNativeRef());
            }
            if (pskEnabled) {
                NativeCrypto.set_SSL_psk_server_callback_enabled(s, null, true);
                NativeCrypto.SSL_use_psk_identity_hint(s, null, pskIdentityHint);
            }
            NativeCrypto.SSL_set_verify(s, null, SSL_VERIFY_NONE);
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
                                   FileDescriptor fd, SSLHandshakeCallbacks callback)
                throws Exception {
            super.afterHandshake(session, ssl, context, socket, fd, callback);
        }

        @Override
        public void clientCertificateRequested(long s) {
            fail("Server asked for client certificates");
        }
    }

    static class EngineTestConnection {
        final long ssl;
        final long bio;
        final Socket socket;
        final InputStream socketIn;
        final OutputStream socketOut;
        final SSLHandshakeCallbacks callback;
        final byte[] socketBuffer = new byte[8192];
        final byte[] bioBuffer = new byte[8192];
        final ByteBuffer directBuffer = ByteBuffer.allocateDirect(16384);
        boolean atEof = false;

        EngineTestConnection(long ssl, Socket socket, SSLHandshakeCallbacks callback)
                throws IOException {
            this.ssl = ssl;
            this.socket = socket;
            this.socketIn = socket.getInputStream();
            this.socketOut = socket.getOutputStream();
            this.callback = callback;
            this.bio = NativeCrypto.SSL_BIO_new(ssl, null);
        }

        void flushBIO() throws IOException {
            int pendingWrite = NativeCrypto.SSL_pending_written_bytes_in_BIO(bio);
            while (pendingWrite > 0) {
                int read = NativeCrypto.BIO_read(bio, bioBuffer);
                if (read > 0) {
                    socketOut.write(bioBuffer, 0, read);
                    socketOut.flush();
                } else {
                    break;
                }
                pendingWrite = NativeCrypto.SSL_pending_written_bytes_in_BIO(bio);
            }
        }

        void readToBIO() throws IOException {
            if (atEof) {
                return;
            }
            int read = socketIn.read(socketBuffer);
            if (read > 0) {
                NativeCrypto.BIO_write(bio, socketBuffer, 0, read);
            } else if (read < 0) {
                atEof = true;
            }
        }

        int doHandshake() throws IOException {
            int ret = NativeCrypto.ENGINE_SSL_do_handshake(ssl, null, callback);
            flushBIO();
            return ret;
        }

        void runHandshake(int timeoutMillis) throws IOException {
            int oldTimeout = socket.getSoTimeout();
            if (timeoutMillis > 0) {
                socket.setSoTimeout(timeoutMillis);
            }
            try {
                boolean finished = false;
                while (!finished) {
                    int ret = doHandshake();
                    if (ret == NativeConstants.SSL_ERROR_NONE) {
                        finished = true;
                    } else if (ret == NativeConstants.SSL_ERROR_WANT_READ) {
                        if (atEof) {
                            throw new SSLProtocolException(
                                    "Connection closed by peer during handshake");
                        }
                        readToBIO();
                    } else if (ret == NativeConstants.SSL_ERROR_WANT_WRITE) {
                        flushBIO();
                    } else {
                        throw new SSLException("Handshake failed with code: " + ret);
                    }
                }
            } finally {
                if (timeoutMillis > 0) {
                    socket.setSoTimeout(oldTimeout);
                }
            }
        }

        int read(byte[] b, int off, int len, int timeoutMillis)
                throws IOException, CertificateException {
            int oldTimeout = socket.getSoTimeout();
            if (timeoutMillis > 0) {
                socket.setSoTimeout(timeoutMillis);
            }
            try {
                directBuffer.clear();
                int toRead = Math.min(len, directBuffer.remaining());
                long address = NativeCrypto.getDirectBufferAddress(directBuffer);

                while (true) {
                    int read = NativeCrypto.ENGINE_SSL_read_direct(ssl, null, address, toRead,
                                                                   callback);
                    if (read > 0) {
                        directBuffer.position(read);
                        directBuffer.flip();
                        directBuffer.get(b, off, read);
                        return read;
                    }

                    if (read == -NativeConstants.SSL_ERROR_WANT_READ) {
                        if (atEof) {
                            return -1;
                        }
                        readToBIO();
                    } else if (read == -NativeConstants.SSL_ERROR_WANT_WRITE) {
                        flushBIO();
                    } else if (read == -NativeConstants.SSL_ERROR_ZERO_RETURN) {
                        return -1; // EOF
                    } else {
                        throw new SSLException("Read failed with code: " + read);
                    }
                }
            } finally {
                if (timeoutMillis > 0) {
                    socket.setSoTimeout(oldTimeout);
                }
            }
        }

        void write(byte[] b, int off, int len) throws IOException {
            int remaining = len;
            int currentOff = off;
            while (remaining > 0) {
                directBuffer.clear();
                int toWrite = Math.min(remaining, directBuffer.remaining());
                directBuffer.put(b, currentOff, toWrite);
                directBuffer.flip();
                long address = NativeCrypto.getDirectBufferAddress(directBuffer);

                int written = 0;
                while (written < toWrite) {
                    int ret = NativeCrypto.ENGINE_SSL_write_direct(ssl, null, address + written,
                                                                   toWrite - written, callback);
                    if (ret > 0) {
                        written += ret;
                        flushBIO();
                    } else {
                        int error = NativeCrypto.SSL_get_error(ssl, null, ret);
                        if (error == NativeConstants.SSL_ERROR_WANT_READ) {
                            readToBIO();
                        } else if (error == NativeConstants.SSL_ERROR_WANT_WRITE) {
                            flushBIO();
                        } else {
                            throw new SSLException("Write failed with error: " + error);
                        }
                    }
                }
                currentOff += toWrite;
                remaining -= toWrite;
            }
        }
    }

    // wrapper method added for ECH testing
    // Note: This method only works for pre Java 17 as it uses FD sockets.
    // TODO(b/502061834): Rewrite this for engine sockets to make it work on Java 17+.
    public static Future<TestSSLHandshakeCallbacks> handshake(
            final ServerSocket listener, final int timeout, final boolean client, final Hooks hooks,
            final byte[] alpnProtocols, final ApplicationProtocolSelectorAdapter alpnSelector) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<TestSSLHandshakeCallbacks> future =
                executor.submit(new Callable<TestSSLHandshakeCallbacks>() {
                    @Override
                    public TestSSLHandshakeCallbacks call() throws Exception {
                        // Socket needs to remain open after the handshake
                        Socket socket = (client ? new Socket(listener.getInetAddress(),
                                                             listener.getLocalPort())
                                                : listener.accept());
                        if (timeout == -1) {
                            return new TestSSLHandshakeCallbacks(socket, 0, null, null);
                        }
                        long c = hooks.getContext();
                        long s = hooks.beforeHandshake(c);
                        TestSSLHandshakeCallbacks callback =
                                new TestSSLHandshakeCallbacks(socket, s, hooks, alpnSelector);
                        hooks.configureCallbacks(callback);

                        EngineTestConnection conn = new EngineTestConnection(s, socket, callback);
                        callback.setEngineConn(conn);

                        if (DEBUG) {
                            System.out.println("ssl=0x" + Long.toString(s, 16) + " handshake"
                                               + " context=0x" + Long.toString(c, 16)
                                               + " socket=" + socket + " timeout=" + timeout
                                               + " client=" + client);
                        }
                        long session = NULL;
                        try {
                            if (client) {
                                NativeCrypto.SSL_set_connect_state(s, null);
                            } else {
                                NativeCrypto.SSL_set_accept_state(s, null);
                            }
                            if (alpnProtocols != null) {
                                NativeCrypto.setApplicationProtocols(s, null, client,
                                                                     alpnProtocols);
                            }
                            if (!client && alpnSelector != null) {
                                NativeCrypto.setHasApplicationProtocolSelector(s, null, true);
                            }

                            conn.runHandshake(timeout);

                            session = NativeCrypto.SSL_get1_session(s, null);
                            if (DEBUG) {
                                System.out.println("ssl=0x" + Long.toString(s, 16) + " handshake"
                                                   + " session=0x" + Long.toString(session, 16));
                            }
                        } finally {
                            // Ensure afterHandshake is called to free resources
                            hooks.afterHandshake(session, s, c, socket, null, callback);
                        }
                        return callback;
                    }
                });
        executor.shutdown();
        return future;
    }

    @Test
    public void test_SSL_do_handshake_NULL_SSL() throws Exception {
        assertThrows(NullPointerException.class,
                     () -> NativeCrypto.ENGINE_SSL_do_handshake(NULL, null, null));
    }

    @Test
    public void test_SSL_do_handshake_withNullShcShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        NativeCrypto.SSL_set_connect_state(s, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.ENGINE_SSL_do_handshake(s, null, null);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void test_SSL_do_handshake_normal() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        // normal client and server case
        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new Hooks();
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
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
        assertFalse(clientCallback.serverCertificateRequestedInvoked);
        assertTrue(serverCallback.serverCertificateRequestedInvoked);
        assertNotNull(serverCallback.serverSignatureAlgs);
    }

    @Test
    public void test_SSL_do_handshake_reusedSession() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        // normal client and server case
        final ServerSocket listener = newServerSocket();

        Future<TestSSLHandshakeCallbacks> client1 = handshake(listener, 0, true, new ClientHooks() {
            @Override
            public void configureCallbacks(TestSSLHandshakeCallbacks callbacks) {
                callbacks.onNewSessionEstablishedSaveSession = true;
            }
        }, null, null);
        Future<TestSSLHandshakeCallbacks> server1 =
                handshake(listener, 0,
                          false, new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                              @Override
                              public void configureCallbacks(TestSSLHandshakeCallbacks callbacks) {
                                  callbacks.onNewSessionEstablishedSaveSession = true;
                              }
                          }, null, null);
        TestSSLHandshakeCallbacks clientCallback1 = client1.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback1 = server1.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback1.verifyCertificateChainCalled);
        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback1.certificateChainRefs);
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
        assertFalse(clientCallback1.serverCertificateRequestedInvoked);
        assertTrue(serverCallback1.serverCertificateRequestedInvoked);

        final long clientSessionContext =
                clientCallback1.onNewSessionEstablishedSessionNativePointer;
        final long serverSessionContext =
                serverCallback1.onNewSessionEstablishedSessionNativePointer;

        Future<TestSSLHandshakeCallbacks> client2 = handshake(listener, 0, true, new ClientHooks() {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long sslNativePtr = super.beforeHandshake(c);
                NativeCrypto.SSL_set_session(sslNativePtr, null, clientSessionContext);
                return sslNativePtr;
            }
        }, null, null);
        Future<TestSSLHandshakeCallbacks> server2 = handshake(
                listener, 0,
                false, new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                    @Override
                    public long beforeHandshake(long c) throws SSLException {
                        long sslNativePtr = super.beforeHandshake(c);
                        NativeCrypto.SSL_set_session(sslNativePtr, null, serverSessionContext);
                        return sslNativePtr;
                    }
                }, null, null);
        TestSSLHandshakeCallbacks clientCallback2 = client2.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback2 = server2.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback2.verifyCertificateChainCalled);
        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback2.certificateChainRefs);
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
        assertFalse(clientCallback2.serverCertificateRequestedInvoked);
        assertTrue(serverCallback2.serverCertificateRequestedInvoked);

        NativeCrypto.SSL_SESSION_free(clientSessionContext);
        NativeCrypto.SSL_SESSION_free(serverSessionContext);
    }

    @Test
    public void test_SSL_do_handshake_optional_client_certificate() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        // optional client certificate case
        final ServerSocket listener = newServerSocket();

        Hooks cHooks = new Hooks() {
            @Override
            public void clientCertificateRequested(long s)
                    throws CertificateEncodingException, SSLException {
                super.clientCertificateRequested(s);
                NativeCrypto.setLocalCertsAndPrivateKey(s, null, ENCODED_CLIENT_CERTIFICATES,
                                                        CLIENT_PRIVATE_KEY.getNativeRef());
            }
        };
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_set_client_CA_list(s, null, CA_PRINCIPALS);
                NativeCrypto.SSL_set_verify(s, null, SSL_VERIFY_PEER);
                return s;
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(clientCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(SERVER_CERTIFICATE_REFS, clientCallback.certificateChainRefs);
        assertEquals("ECDHE_RSA", clientCallback.authMethod);
        assertTrue(serverCallback.verifyCertificateChainCalled);
        assertEqualCertificateChains(CLIENT_CERTIFICATE_REFS, serverCallback.certificateChainRefs);
        assertEquals("ECDHE_RSA", serverCallback.authMethod);

        assertTrue(clientCallback.clientCertificateRequestedCalled);
        assertNotNull(clientCallback.keyTypes);
        assertNotNull(clientCallback.signatureAlgs);
        assertEquals(new HashSet<String>(Arrays.asList("EC", "RSA")),
                     SSLUtils.getSupportedClientKeyTypes(clientCallback.keyTypes,
                                                         clientCallback.signatureAlgs));
        assertEqualPrincipals(CA_PRINCIPALS, clientCallback.asn1DerEncodedX500Principals);
        assertFalse(serverCallback.clientCertificateRequestedCalled);

        assertFalse(clientCallback.clientPSKKeyRequestedInvoked);
        assertFalse(serverCallback.clientPSKKeyRequestedInvoked);
        assertFalse(clientCallback.serverPSKKeyRequestedInvoked);
        assertFalse(serverCallback.serverPSKKeyRequestedInvoked);
        assertTrue(clientCallback.onNewSessionEstablishedInvoked);
        assertTrue(serverCallback.onNewSessionEstablishedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertFalse(clientCallback.serverCertificateRequestedInvoked);
        assertTrue(serverCallback.serverCertificateRequestedInvoked);
    }

    @Test
    public void test_SSL_do_handshake_missing_required_certificate() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        // required client certificate negative case
        final ServerSocket listener = newServerSocket();
        try {
            Hooks cHooks = new Hooks();
            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                @Override
                public long beforeHandshake(long c) throws SSLException {
                    long s = super.beforeHandshake(c);
                    NativeCrypto.SSL_set_client_CA_list(s, null, CA_PRINCIPALS);
                    NativeCrypto.SSL_set_verify(s, null,
                                                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
                    return s;
                }
            };
            @SuppressWarnings("unused")
            Future<TestSSLHandshakeCallbacks> client =
                    handshake(listener, 0, true, cHooks, null, null);
            Future<TestSSLHandshakeCallbacks> server =
                    handshake(listener, 0, false, sHooks, null, null);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SSLProtocolException.class, expected.getCause().getClass());
        }
    }

    @Test
    public void test_SSL_do_handshake_client_timeout() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        // client timeout
        final ServerSocket listener = newServerSocket();
        Socket serverSocket = null;
        try {
            Hooks cHooks = new Hooks();
            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
            Future<TestSSLHandshakeCallbacks> client =
                    handshake(listener, 1, true, cHooks, null, null);
            Future<TestSSLHandshakeCallbacks> server =
                    handshake(listener, -1, false, sHooks, null, null);
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
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        // server timeout
        final ServerSocket listener = newServerSocket();
        Socket clientSocket = null;
        try {
            Hooks cHooks = new Hooks();
            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
            Future<TestSSLHandshakeCallbacks> client =
                    handshake(listener, -1, true, cHooks, null, null);
            Future<TestSSLHandshakeCallbacks> server =
                    handshake(listener, 1, false, sHooks, null, null);
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
    public void test_SSL_do_handshake_with_psk_normal() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        // normal TLS-PSK client and server case
        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
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
        assertFalse(clientCallback.serverCertificateRequestedInvoked);
        assertTrue(serverCallback.serverCertificateRequestedInvoked);
    }

    @Test
    public void test_SSL_do_handshake_with_psk_with_identity_and_hint() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        // normal TLS-PSK client and server case where the server provides the client with a PSK
        // identity hint, and the client provides the server with a PSK identity.
        final ServerSocket listener = newServerSocket();
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
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
        assertFalse(clientCallback.serverCertificateRequestedInvoked);
        assertTrue(serverCallback.serverCertificateRequestedInvoked);
    }

    @Test
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated but still needs testing.
    public void test_SSL_do_handshake_with_psk_with_identity_and_hint_of_max_length()
            throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        // normal TLS-PSK client and server case where the server provides the client with a PSK
        // identity hint, and the client provides the server with a PSK identity.
        final ServerSocket listener = newServerSocket();
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
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

    @Test
    public void test_SSL_do_handshake_with_psk_key_mismatch() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final ServerSocket listener = newServerSocket();
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
        sHooks.pskKey = "1, 2, 3, 3, Testing...".getBytes(StandardCharsets.UTF_8);
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

    @Test
    public void test_SSL_do_handshake_with_psk_with_no_client_key() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final ServerSocket listener = newServerSocket();
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = null;
        sHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
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

    @Test
    public void test_SSL_do_handshake_with_psk_with_no_server_key() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final ServerSocket listener = newServerSocket();
        ClientHooks cHooks = new ClientHooks();
        ServerHooks sHooks = new ServerHooks();
        cHooks.pskEnabled = true;
        sHooks.pskEnabled = true;
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
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

    @Test
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated but still needs testing.
    public void test_SSL_do_handshake_with_psk_key_too_long() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

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
        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
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

    @Test
    public void test_SSL_do_handshake_with_ocsp_response() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final byte[] OCSP_TEST_DATA = new byte[] {1, 2, 3, 4};

        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new Hooks() {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_enable_ocsp_stapling(s, null);
                return s;
            }

            @Override
            public void afterHandshake(long session, long ssl, long context, Socket socket,
                                       FileDescriptor fd, SSLHandshakeCallbacks callback)
                    throws Exception {
                assertEqualByteArrays(OCSP_TEST_DATA,
                                      NativeCrypto.SSL_get_ocsp_response(ssl, null));
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };

        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_set_ocsp_response(s, null, OCSP_TEST_DATA);
                return s;
            }
        };

        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);

        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
    }

    @Test
    public void test_SSL_do_handshake_with_sct_extension() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        // Fake SCT extension has a length of overall extension (unsigned 16-bit).
        // Each SCT entry has a length (unsigned 16-bit) and data.
        final byte[] SCT_TEST_DATA = new byte[] {0, 6, 0, 4, 1, 2, 3, 4};

        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new Hooks() {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_enable_signed_cert_timestamps(s, null);
                return s;
            }

            @Override
            public void afterHandshake(long session, long ssl, long context, Socket socket,
                                       FileDescriptor fd, SSLHandshakeCallbacks callback)
                    throws Exception {
                assertEqualByteArrays(SCT_TEST_DATA,
                                      NativeCrypto.SSL_get_signed_cert_timestamp_list(ssl, null));
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };

        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_set_signed_cert_timestamp_list(s, null, SCT_TEST_DATA);
                return s;
            }
        };

        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        TestSSLHandshakeCallbacks clientCallback = client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        TestSSLHandshakeCallbacks serverCallback = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);

        assertTrue(clientCallback.onNewSessionEstablishedInvoked);
        assertTrue(serverCallback.onNewSessionEstablishedInvoked);
        assertTrue(clientCallback.handshakeCompletedCalled);
        assertTrue(serverCallback.handshakeCompletedCalled);
        assertFalse(clientCallback.serverCertificateRequestedInvoked);
        assertTrue(serverCallback.serverCertificateRequestedInvoked);
    }

    @Test
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated but still needs testing.
    public void test_SSL_use_psk_identity_hint() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        try {
            NativeCrypto.SSL_use_psk_identity_hint(s, null, null);
            NativeCrypto.SSL_use_psk_identity_hint(s, null, "test");

            try {
                // 800 characters is much longer than the permitted maximum.
                StringBuilder pskIdentityHint = new StringBuilder();
                for (int i = 0; i < 160; i++) {
                    pskIdentityHint.append(" long");
                }
                assertTrue(pskIdentityHint.length() > PSKKeyManager.MAX_IDENTITY_HINT_LENGTH_BYTES);
                NativeCrypto.SSL_use_psk_identity_hint(s, null, pskIdentityHint.toString());
                fail();
            } catch (SSLException expected) {
                // Expected.
            }
        } finally {
            NativeCrypto.SSL_free(s, null);
            NativeCrypto.SSL_CTX_free(c, null);
        }
    }

    @Test
    public void SSL_set_session_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                     () -> NativeCrypto.SSL_set_session(NULL, null, NULL));
    }

    @Test
    public void test_SSL_set_session() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        NativeCrypto.SSL_set_session(s, null, NULL);
        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);

        {
            final long clientContext = NativeCrypto.SSL_CTX_new();
            final long serverContext = NativeCrypto.SSL_CTX_new();
            final ServerSocket listener = newServerSocket();
            final long[] clientSession = new long[] {NULL};
            final long[] serverSession = new long[] {NULL};
            {
                Hooks cHooks = new Hooks() {
                    @Override
                    public long getContext() {
                        return clientContext;
                    }
                    @Override
                    public void afterHandshake(long session, long s, long c, Socket sock,
                                               FileDescriptor fd, SSLHandshakeCallbacks callback)
                            throws Exception {
                        super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                        clientSession[0] = session;
                    }
                };
                Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                    @Override
                    public long getContext() {
                        return serverContext;
                    }
                    @Override
                    public void afterHandshake(long session, long s, long c, Socket sock,
                                               FileDescriptor fd, SSLHandshakeCallbacks callback)
                            throws Exception {
                        super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                        serverSession[0] = session;
                    }
                };
                Future<TestSSLHandshakeCallbacks> client =
                        handshake(listener, 0, true, cHooks, null, null);
                Future<TestSSLHandshakeCallbacks> server =
                        handshake(listener, 0, false, sHooks, null, null);
                client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
            assertEqualSessions(clientSession[0], serverSession[0]);
            {
                Hooks cHooks = new Hooks() {
                    @Override
                    public long getContext() {
                        return clientContext;
                    }
                    @Override
                    public long beforeHandshake(long c) throws SSLException {
                        long s = NativeCrypto.SSL_new(clientContext, null);
                        NativeCrypto.SSL_set_session(s, null, clientSession[0]);
                        return s;
                    }
                    @Override
                    public void afterHandshake(long session, long s, long c, Socket sock,
                                               FileDescriptor fd, SSLHandshakeCallbacks callback)
                            throws Exception {
                        assertEqualSessions(clientSession[0], session);
                        super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                    }
                };
                Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                    @Override
                    public long getContext() {
                        return serverContext;
                    }
                    @Override
                    public void afterHandshake(long session, long s, long c, Socket sock,
                                               FileDescriptor fd, SSLHandshakeCallbacks callback)
                            throws Exception {
                        assertEqualSessions(serverSession[0], session);
                        super.afterHandshake(NULL, s, NULL, sock, fd, callback);
                    }
                };
                Future<TestSSLHandshakeCallbacks> client =
                        handshake(listener, 0, true, cHooks, null, null);
                Future<TestSSLHandshakeCallbacks> server =
                        handshake(listener, 0, false, sHooks, null, null);
                client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
            NativeCrypto.SSL_SESSION_free(clientSession[0]);
            NativeCrypto.SSL_SESSION_free(serverSession[0]);
            NativeCrypto.SSL_CTX_free(serverContext, null);
            NativeCrypto.SSL_CTX_free(clientContext, null);
        }
    }

    @Test
    public void SSL_set_session_creation_enabled_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                     () -> NativeCrypto.SSL_set_session_creation_enabled(NULL, null, false));
    }

    @Test
    public void test_SSL_set_session_creation_enabled() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        NativeCrypto.SSL_set_session_creation_enabled(s, null, false);
        NativeCrypto.SSL_set_session_creation_enabled(s, null, true);
        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);

        final ServerSocket listener = newServerSocket();

        // negative test case for SSL_set_session_creation_enabled(false) on client
        {
            Hooks cHooks = new Hooks() {
                @Override
                public long beforeHandshake(long c) throws SSLException {
                    long s = super.beforeHandshake(c);
                    NativeCrypto.SSL_set_session_creation_enabled(s, null, false);
                    return s;
                }
            };
            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
            Future<TestSSLHandshakeCallbacks> client =
                    handshake(listener, 0, true, cHooks, null, null);
            @SuppressWarnings("unused")
            Future<TestSSLHandshakeCallbacks> server =
                    handshake(listener, 0, false, sHooks, null, null);
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
            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                @Override
                public long beforeHandshake(long c) throws SSLException {
                    long s = super.beforeHandshake(c);
                    NativeCrypto.SSL_set_session_creation_enabled(s, null, false);
                    return s;
                }
            };
            Future<TestSSLHandshakeCallbacks> client =
                    handshake(listener, 0, true, cHooks, null, null);
            @SuppressWarnings("unused")
            Future<TestSSLHandshakeCallbacks> server =
                    handshake(listener, 0, false, sHooks, null, null);
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
    }

    @Test
    public void SSL_set_tlsext_host_name_withNullSslShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                     () -> NativeCrypto.SSL_set_tlsext_host_name(NULL, null, null));
    }

    @Test
    public void SSL_set_tlsext_host_name_withNullHostnameShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.SSL_set_tlsext_host_name(s, null, null);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void SSL_set_tlsext_host_name_withTooLongHostnameShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        assertThrows(SSLException.class, () -> {
            try {
                char[] longHostname = new char[256];
                Arrays.fill(longHostname, 'w');
                NativeCrypto.SSL_set_tlsext_host_name(s, null, new String(longHostname));
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void test_SSL_set_tlsext_host_name() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final String hostname = "www.android.com";
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);

        assertNull(NativeCrypto.SSL_get_servername(s, null));
        NativeCrypto.SSL_set_tlsext_host_name(s, null, hostname);
        assertEquals(hostname, NativeCrypto.SSL_get_servername(s, null));

        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);

        final ServerSocket listener = newServerSocket();

        // normal
        Hooks cHooks = new Hooks() {
            @Override
            public long beforeHandshake(long c) throws SSLException {
                long s = super.beforeHandshake(c);
                NativeCrypto.SSL_set_tlsext_host_name(s, null, hostname);
                return s;
            }
        };
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
            @Override
            public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback) throws Exception {
                assertEquals(hostname, NativeCrypto.SSL_get_servername(s, null));
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test
    public void alpnWithProtocolListShouldSucceed() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final byte[] clientAlpnProtocols =
                SSLUtils.encodeProtocols(new String[] {"http/1.1", "foo", "spdy/2"});
        final byte[] serverAlpnProtocols =
                SSLUtils.encodeProtocols(new String[] {"spdy/2", "foo", "bar"});

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long ssl, long context, Socket socket,
                                       FileDescriptor fd, SSLHandshakeCallbacks callback)
                    throws Exception {
                byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
                assertEquals("spdy/2", new String(negotiated, StandardCharsets.UTF_8));
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
            @Override
            public void afterHandshake(long session, long ssl, long c, Socket sock,
                                       FileDescriptor fd, SSLHandshakeCallbacks callback)
                    throws Exception {
                byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
                assertEquals("spdy/2", new String(negotiated, StandardCharsets.UTF_8));
                super.afterHandshake(session, ssl, c, sock, fd, callback);
            }
        };

        ServerSocket listener = newServerSocket();
        Future<TestSSLHandshakeCallbacks> client =
                handshake(listener, 0, true, cHooks, clientAlpnProtocols, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, serverAlpnProtocols, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test
    public void alpnWithProtocolListShouldFail() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final byte[] clientAlpnProtocols =
                SSLUtils.encodeProtocols(new String[] {"http/1.1", "foo", "spdy/2"});
        final byte[] serverAlpnProtocols =
                SSLUtils.encodeProtocols(new String[] {"h2", "bar", "baz"});

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long ssl, long context, Socket socket,
                                       FileDescriptor fd, SSLHandshakeCallbacks callback)
                    throws Exception {
                byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
                assertNull(negotiated);
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
            @Override
            public void afterHandshake(long session, long ssl, long c, Socket sock,
                                       FileDescriptor fd, SSLHandshakeCallbacks callback)
                    throws Exception {
                byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
                assertNull(negotiated);
                super.afterHandshake(session, ssl, c, sock, fd, callback);
            }
        };

        ServerSocket listener = newServerSocket();
        Future<TestSSLHandshakeCallbacks> client =
                handshake(listener, 0, true, cHooks, clientAlpnProtocols, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, serverAlpnProtocols, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test
    public void alpnWithServerProtocolSelectorShouldSucceed() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final byte[] clientAlpnProtocols =
                SSLUtils.encodeProtocols(new String[] {"http/1.1", "foo", "spdy/2"});

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long ssl, long context, Socket socket,
                                       FileDescriptor fd, SSLHandshakeCallbacks callback)
                    throws Exception {
                byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
                assertEquals("spdy/2", new String(negotiated, StandardCharsets.UTF_8));
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
            @Override
            public void afterHandshake(long session, long ssl, long c, Socket sock,
                                       FileDescriptor fd, SSLHandshakeCallbacks callback)
                    throws Exception {
                byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
                assertEquals("spdy/2", new String(negotiated, StandardCharsets.UTF_8));
                super.afterHandshake(session, ssl, c, sock, fd, callback);
            }
        };

        ApplicationProtocolSelector selector = Mockito.mock(ApplicationProtocolSelector.class);
        SSLEngine engine = Mockito.mock(SSLEngine.class);
        ApplicationProtocolSelectorAdapter adapter =
                new ApplicationProtocolSelectorAdapter(engine, selector);
        when(selector.selectApplicationProtocol(same(engine), ArgumentMatchers.<String>anyList()))
                .thenReturn("spdy/2");

        ServerSocket listener = newServerSocket();
        Future<TestSSLHandshakeCallbacks> client =
                handshake(listener, 0, true, cHooks, clientAlpnProtocols, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, adapter);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test
    public void alpnWithServerProtocolSelectorShouldFail() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final byte[] clientAlpnProtocols =
                SSLUtils.encodeProtocols(new String[] {"http/1.1", "foo", "spdy/2"});

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long ssl, long context, Socket socket,
                                       FileDescriptor fd, SSLHandshakeCallbacks callback)
                    throws Exception {
                byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
                assertNull(negotiated);
                super.afterHandshake(session, ssl, context, socket, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
            @Override
            public void afterHandshake(long session, long ssl, long c, Socket sock,
                                       FileDescriptor fd, SSLHandshakeCallbacks callback)
                    throws Exception {
                byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
                assertNull(negotiated);
                super.afterHandshake(session, ssl, c, sock, fd, callback);
            }
        };

        ApplicationProtocolSelector selector = Mockito.mock(ApplicationProtocolSelector.class);
        SSLEngine engine = Mockito.mock(SSLEngine.class);
        ApplicationProtocolSelectorAdapter adapter =
                new ApplicationProtocolSelectorAdapter(engine, selector);
        when(selector.selectApplicationProtocol(same(engine), ArgumentMatchers.<String>anyList()))
                .thenReturn("h2");

        ServerSocket listener = newServerSocket();
        Future<TestSSLHandshakeCallbacks> client =
                handshake(listener, 0, true, cHooks, clientAlpnProtocols, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, adapter);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test
    public void test_SSL_get_servername_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_get_servername(NULL, null));
    }

    @Test
    public void SSL_get_servername_shouldReturnNull() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertNull(NativeCrypto.SSL_get_servername(s, null));
        NativeCrypto.SSL_free(s, null);
        NativeCrypto.SSL_CTX_free(c, null);

        // additional positive testing by test_SSL_set_tlsext_host_name
    }

    @Test
    public void SSL_get0_peer_certificates_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                     () -> NativeCrypto.SSL_get0_peer_certificates(NULL, null));
    }

    @Test
    public void test_SSL_get0_peer_certificates() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final ServerSocket listener = newServerSocket();

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback) throws Exception {
                byte[][] cc = NativeCrypto.SSL_get0_peer_certificates(s, null);
                assertEqualByteArrays(ENCODED_SERVER_CERTIFICATES, cc);
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test
    public void test_SSL_cipher_names() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final ServerSocket listener = newServerSocket();
        Hooks cHooks = new Hooks();
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
        // Both legacy and standard names are accepted.
        cHooks.enabledCipherSuites = Collections.singletonList("ECDHE-RSA-AES128-GCM-SHA256");
        sHooks.enabledCipherSuites =
                Collections.singletonList("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        // The standard name is always reported.
        assertEquals("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", cHooks.negotiatedCipherSuite);
        assertEquals("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", sHooks.negotiatedCipherSuite);
    }

    private final byte[] BYTES = new byte[] {2, -3, 5, 127, 0, -128};

    @Test
    public void SSL_read_withNullSslShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                     () -> NativeCrypto.ENGINE_SSL_read_direct(NULL, null, 0, 0, null));
    }

    @Test
    public void SSL_read_withNullCallbacksShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.ENGINE_SSL_read_direct(s, null, 0, 0, null);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
    }

    @Test
    public void test_SSL_read() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final ServerSocket listener = newServerSocket();

        // normal case
        {
            Hooks cHooks = new Hooks() {
                @Override
                public void afterHandshake(long session, long s, long c, Socket sock,
                                           FileDescriptor fd, SSLHandshakeCallbacks callback)
                        throws Exception {
                    byte[] in = new byte[256];
                    EngineTestConnection conn =
                            ((TestSSLHandshakeCallbacks) callback).getEngineConn();
                    assertEquals(BYTES.length, conn.read(in, 0, BYTES.length, 0));
                    for (int i = 0; i < BYTES.length; i++) {
                        assertEquals(BYTES[i], in[i]);
                    }
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            };
            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                @Override
                public void afterHandshake(long session, long s, long c, Socket sock,
                                           FileDescriptor fd, SSLHandshakeCallbacks callback)
                        throws Exception {
                    EngineTestConnection conn =
                            ((TestSSLHandshakeCallbacks) callback).getEngineConn();
                    conn.write(BYTES, 0, BYTES.length);
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            };
            Future<TestSSLHandshakeCallbacks> client =
                    handshake(listener, 0, true, cHooks, null, null);
            Future<TestSSLHandshakeCallbacks> server =
                    handshake(listener, 0, false, sHooks, null, null);
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }

        // timeout case
        try {
            Hooks cHooks = new Hooks() {
                @Override
                public void afterHandshake(long session, long s, long c, Socket sock,
                                           FileDescriptor fd, SSLHandshakeCallbacks callback)
                        throws Exception {
                    EngineTestConnection conn =
                            ((TestSSLHandshakeCallbacks) callback).getEngineConn();
                    conn.read(new byte[1], 0, 1, 1);
                    fail();
                }
            };
            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                @Override
                public void afterHandshake(long session, long s, long c, Socket sock,
                                           FileDescriptor fd, SSLHandshakeCallbacks callback)
                        throws Exception {
                    EngineTestConnection conn =
                            ((TestSSLHandshakeCallbacks) callback).getEngineConn();
                    conn.read(new byte[1], 0, 1, 0);
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            };
            Future<TestSSLHandshakeCallbacks> client =
                    handshake(listener, 0, true, cHooks, null, null);
            @SuppressWarnings("unused")
            Future<TestSSLHandshakeCallbacks> server =
                    handshake(listener, 0, false, sHooks, null, null);
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            fail();
        } catch (ExecutionException expected) {
            assertEquals(SocketTimeoutException.class, expected.getCause().getClass());
        }
    }

    @Test
    public void SSL_write_withNullSslShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                     () -> NativeCrypto.ENGINE_SSL_write_direct(NULL, null, 0, 0, null));
    }

    @Test
    public void SSL_write_withNullCallbacksShouldThrow() throws Exception {
        long c = NativeCrypto.SSL_CTX_new();
        long s = NativeCrypto.SSL_new(c, null);
        assertThrows(NullPointerException.class, () -> {
            try {
                NativeCrypto.ENGINE_SSL_write_direct(s, null, 0, 0, null);
            } finally {
                NativeCrypto.SSL_free(s, null);
                NativeCrypto.SSL_CTX_free(c, null);
            }
        });
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
    public void SSL_shutdown_withNullCallbacksShouldThrow() throws Exception {
        assertThrows(NullPointerException.class,
                     () -> wrapWithSSLSession(new SSLSessionWrappedTask() {
                         @Override
                         public void run(long sslSession) throws Exception {
                             NativeCrypto.ENGINE_SSL_shutdown(sslSession, null, null);
                         }
                     }));
    }

    @Test
    public void SSL_shutdown_withNullSslShouldSucceed() throws Exception {
        // SSL_shutdown is a rare case that tolerates a null SSL argument
        NativeCrypto.ENGINE_SSL_shutdown(NULL, null, DUMMY_CB);
    }

    @Test
    public void SSL_shutdown_beforeHandshakeShouldThrow() throws Exception {
        // handshaking not yet performed
        assertThrows(SSLException.class, () -> wrapWithSSLSession(new SSLSessionWrappedTask() {
                         @Override
                         public void run(long sslSession) throws Exception {
                             NativeCrypto.ENGINE_SSL_shutdown(sslSession, null, DUMMY_CB);
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
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

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
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test
    public void SSL_SESSION_get_time_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_SESSION_get_time(NULL));
    }

    @Test
    public void test_SSL_SESSION_get_time() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        // TODO(prb) seems to fail regularly on Windows with time < System.currentTimeMillis()
        assumeFalse("Skipping SSLSession_getCreationTime() test on Windows", isWindows());

        final ServerSocket listener = newServerSocket();
        {
            Hooks cHooks = new Hooks() {
                @Override
                public void afterHandshake(long session, long s, long c, Socket sock,
                                           FileDescriptor fd, SSLHandshakeCallbacks callback)
                        throws Exception {
                    long time = NativeCrypto.SSL_SESSION_get_time(session);
                    assertTrue(time != 0);
                    assertTrue(time < System.currentTimeMillis());
                    super.afterHandshake(session, s, c, sock, fd, callback);
                }
            };
            Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
            Future<TestSSLHandshakeCallbacks> client =
                    handshake(listener, 0, true, cHooks, null, null);
            Future<TestSSLHandshakeCallbacks> server =
                    handshake(listener, 0, false, sHooks, null, null);
            client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }
    }

    @Test
    public void SSL_SESSION_get_version_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_SESSION_cipher(NULL));
    }

    @Test
    public void test_SSL_SESSION_get_version() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

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
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Test
    public void SSL_SESSION_cipher_withNullShouldThrow() throws Exception {
        assertThrows(NullPointerException.class, () -> NativeCrypto.SSL_SESSION_cipher(NULL));
    }

    @Test
    public void test_SSL_SESSION_cipher() throws Exception {
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

        final ServerSocket listener = newServerSocket();

        Hooks cHooks = new Hooks() {
            @Override
            public void afterHandshake(long session, long s, long c, Socket sock, FileDescriptor fd,
                                       SSLHandshakeCallbacks callback) throws Exception {
                String nativeCipher = NativeCrypto.SSL_SESSION_cipher(session);
                String javaCipher = NativeCrypto.cipherSuiteFromJava(nativeCipher);
                assertTrue(NativeCrypto.SUPPORTED_TLS_1_2_CIPHER_SUITES_SET.contains(javaCipher));
                // SSL_SESSION_cipher should return a standard name rather than an OpenSSL name.
                assertTrue(nativeCipher.startsWith("TLS_"));
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
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
        // This test only works on older versions of Java, see b/502061834.
        assumeFalse(TestUtils.isJavaVersion(17));

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
                assertNotNull(NativeCrypto.SSL_SESSION_cipher(session2));
                assertEquals(NativeCrypto.SSL_SESSION_cipher(session),
                             NativeCrypto.SSL_SESSION_cipher(session2));

                NativeCrypto.SSL_SESSION_free(session2);
                super.afterHandshake(session, s, c, sock, fd, callback);
            }
        };
        Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES);
        Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
        Future<TestSSLHandshakeCallbacks> server =
                handshake(listener, 0, false, sHooks, null, null);
        client.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
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
    public void x25519_fromToRaw_works() throws Exception {
        byte[] privateKeyBytes =
                decodeHex("0900000000000000000000000000000000000000000000000000000000000000");

        NativeRef.EVP_PKEY privateKey =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_raw_private_key(
                        NativeConstants.EVP_PKEY_X25519, privateKeyBytes));
        assertEquals(NativeConstants.EVP_PKEY_X25519, NativeCrypto.EVP_PKEY_type(privateKey));
        byte[] rawPrivateKey = NativeCrypto.EVP_PKEY_get_raw_private_key(privateKey);
        assertArrayEquals(privateKeyBytes, rawPrivateKey);

        // At the same time, test that getting the seed fails.
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.EVP_PKEY_get_private_seed(privateKey));
    }

    @Test
    public void ed25519_fromToRaw_works() throws Exception {
        // Test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7
        byte[] rawEd25519PrivateKey =
                decodeHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        NativeRef.EVP_PKEY privateKey =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_raw_private_key(
                        NativeConstants.EVP_PKEY_ED25519, rawEd25519PrivateKey));
        assertEquals(NativeConstants.EVP_PKEY_ED25519, NativeCrypto.EVP_PKEY_type(privateKey));

        byte[] output = NativeCrypto.EVP_PKEY_get_raw_private_key(privateKey);
        assertArrayEquals(rawEd25519PrivateKey, output);

        // At the same time, test that getting the seed fails.
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.EVP_PKEY_get_private_seed(privateKey));
    }

    @Test
    public void evpKeyFromRawPrivateKey_ed25519WithInvalidKeyLength_throws() throws Exception {
        final byte[] shortKey = new byte[31];
        assertThrows(ParsingException.class,
                     ()
                             -> new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_raw_private_key(
                                     NativeConstants.EVP_PKEY_ED25519, shortKey)));
        final byte[] longKey = new byte[33];
        assertThrows(ParsingException.class,
                     ()
                             -> new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_raw_private_key(
                                     NativeConstants.EVP_PKEY_ED25519, longKey)));
    }

    @Test
    public void evpKeyFromRawPrivateKey_x25519WithInvalidKeyLength_throws() throws Exception {
        final byte[] shortKey = new byte[31];
        assertThrows(Exception.class,
                     ()
                             -> new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_raw_private_key(
                                     NativeConstants.EVP_PKEY_X25519, shortKey)));
        final byte[] longKey = new byte[33];
        assertThrows(Exception.class,
                     ()
                             -> new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_raw_private_key(
                                     NativeConstants.EVP_PKEY_X25519, longKey)));
    }

    @Test
    public void mldsaPrivateKey_fromAndToSeed_works() throws Exception {
        for (int keyType :
             new int[] {NativeConstants.EVP_PKEY_ML_DSA_44, NativeConstants.EVP_PKEY_ML_DSA_65,
                        NativeConstants.EVP_PKEY_ML_DSA_87}) {
            byte[] seed = new byte[32];
            NativeCrypto.RAND_bytes(seed);
            NativeRef.EVP_PKEY privateKey =
                    new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_private_seed(keyType, seed));
            assertEquals(keyType, NativeCrypto.EVP_PKEY_type(privateKey));

            byte[] output = NativeCrypto.EVP_PKEY_get_private_seed(privateKey);
            assertArrayEquals(seed, output);
        }
    }

    @Test
    public void evpKeyFromPrivateSeed_invalidSeedLength_throws() throws Exception {
        for (int keyType :
             new int[] {NativeConstants.EVP_PKEY_ML_DSA_44, NativeConstants.EVP_PKEY_ML_DSA_65,
                        NativeConstants.EVP_PKEY_ML_DSA_87}) {
            final byte[] shortSeed = new byte[31];
            assertThrows(ParsingException.class,
                         ()
                                 -> new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_private_seed(
                                         keyType, shortSeed)));
            final byte[] longSeed = new byte[33];
            assertThrows(ParsingException.class,
                         ()
                                 -> new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_private_seed(
                                         keyType, longSeed)));
        }
    }

    @Test
    public void parseMldsaPrivateKeyFromRfc9881_works() throws Exception {
        // From:
        // https://datatracker.ietf.org/doc/html/rfc9881#appendix-C.1.2.1
        byte[] pkcs8EncodedPrivateKey = TestUtils.decodeBase64(
                "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f");
        byte[] expectedSeed = TestUtils.decodeHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        NativeRef.EVP_PKEY parsedPrivateKey =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_private_key_info(
                        pkcs8EncodedPrivateKey, new int[] {NativeConstants.EVP_PKEY_ML_DSA_65}));
        assertEquals(NativeConstants.EVP_PKEY_ML_DSA_65,
                     NativeCrypto.EVP_PKEY_type(parsedPrivateKey));
        byte[] outputSeed = NativeCrypto.EVP_PKEY_get_private_seed(parsedPrivateKey);
        assertArrayEquals(expectedSeed, outputSeed);

        // Using two key types works.
        NativeRef.EVP_PKEY parsedPrivateKey2 =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_private_key_info(
                        pkcs8EncodedPrivateKey,
                        new int[] {NativeConstants.EVP_PKEY_ML_DSA_87,
                                   NativeConstants.EVP_PKEY_ML_DSA_65}));
        assertEquals(NativeConstants.EVP_PKEY_ML_DSA_65,
                     NativeCrypto.EVP_PKEY_type(parsedPrivateKey2));

        // But using the wrong key type throws a parsing exception.
        assertThrows(ParsingException.class,
                     ()
                             -> new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_private_key_info(
                                     pkcs8EncodedPrivateKey,
                                     new int[] {NativeConstants.EVP_PKEY_ML_DSA_87})));
    }

    @Test
    public void parseMldsaPublicKeyFromRfc9881_works() throws Exception {
        // From:
        // https://datatracker.ietf.org/doc/html/rfc9881#name-example-public-keys
        String publicKeyBase64 = "MIIHsjALBglghkgBZQMEAxIDggehAEhoPZGXjjHrPd24sEc0gtK4il9iWUn9j1il"
                + "YeaWvUwn0Fs427Lt8B5mTv2Bvh6ok2iM5oqi1RxZWPi7xutOie5n0sAyCVTVchLK"
                + "xyKf8dbq8DkovVFRH42I2EdzbH3icw1ZeOVBBxMWCXiGdxG/VTmgv8TDUMK+Vyuv"
                + "DuLi+xbM/qCAKNmaxJrrt1k33c4RHNq2L/886ouiIz0eVvvFxaHnJt5j+t0q8Bax"
                + "GRd/o9lxotkncXP85VtndFrwt8IdWX2+uT5qMvNBxJpai+noJQiNHyqkUVXWyK4V"
                + "Nn5OsAO4/feFEHGUlzn5//CQI+r0UQTSqEpFkG7tRnGkTcKNJ5h7tV32np6FYfYa"
                + "gKcmmVA4Zf7Zt+5yqOF6GcQIFE9LKa/vcDHDpthXFhC0LJ9CEkWojxl+FoErAxFZ"
                + "tluWh+Wz6TTFIlrpinm6c9Kzmdc1EO/60Z5TuEUPC6j84QEv2Y0mCnSqqhP64kmg"
                + "BrHDT1uguILyY3giL7NvIoPCQ/D/618btBSgpw1V49QKVrbLyIrh8Dt7KILZje6i"
                + "jhRcne39jq8c7y7ZSosFD4lk9G0eoNDCpD4N2mGCrb9PbtF1tnQiV4Wb8i86QX7P"
                + "H52JMXteU51YevFrnhMT4EUU/6ZLqLP/K4Mh+IEcs/sCLI9kTnCkuAovv+5gSrtz"
                + "eQkeqObFx038AoNma0DAeThwAoIEoTa/XalWjreY00kDi9sMEeA0ReeEfLUGnHXP"
                + "KKxgHHeZ2VghDdvLIm5Rr++fHeR7Bzhz1tP5dFa+3ghQgudKKYss1I9LMJMVXzZs"
                + "j6YBxq+FjfoywISRsqKYh/kDNZSaXW7apnmIKjqV1r9tlwoiH0udPYy/OEr4GqyV"
                + "4rMpTgR4msg3J6XcBFWflq9B2KBTUW/u7rxSdG62qygZ4JEIcQ2DXwEfpjBlhyrT"
                + "NNXN/7KyMQUH6S/Jk64xfal/TzCc2vD2ftmdkCFVdgg4SflTskbX/ts/22dnmFCl"
                + "rUBOZBR/t89Pau3dBa+0uDSWjR/ogBSWDc5dlCI2Um4SpHjWnl++aXAxCzCMBoRQ"
                + "GM/HsqtDChOmsax7sCzMuz2RGsLxEGhhP74Cm/3OAs9c04lQ7XLIOUTt+8dWFa+H"
                + "+GTAUfPFVFbFQShjpAwG0dq1Yr3/BXG408ORe70wCIC7pemYI5uV+pG31kFtTzmL"
                + "OtvNMJg+01krTZ731CNv0A9Q2YqlOiNaxBcnIPd9lhcmcpgM/o/3pacCeD7cK6Mb"
                + "IlkBWhEvx/RoqcL5RkA5AC0w72eLTLeYvBFiFr96mnwYugO3tY/QdRXTEVBJ02FL"
                + "56B+dEMAdQ3x0sWHUziQWer8PXhczdMcB2SL7cA6XDuK1G0GTVnBPVc3Ryn8TilT"
                + "YuKlGRIEUwQovBUir6KP9f4WVeMEylvIwnrQ4MajndTfKJVsFLOMyTaCzv5AK71e"
                + "gtKcRk5E6103tI/FaN/gzG6OFrrqBeUTVZDxkpTnPoNnsCFtu4FQMLneVZE/CAOc"
                + "QjUcWeVRXdWvjgiaFeYl6Pbe5jk4bEZJfXomMoh3TeWBp96WKbQbRCQUH5ePuDMS"
                + "CO/ew8bg3jm8VwY/Pc1sRwNzwIiR6inLx8xtZIO4iJCDrOhqp7UbHCz+birRjZfO"
                + "NvvFbqQvrpfmp6wRSGRHjDZt8eux57EakJhQT9WXW98fSdxwACtjwXOanSY/utQH"
                + "P2qfbCuK9LTDMqEDoM/6Xe6y0GLKPCFf02ACa+fFFk9KRCTvdJSIBNZvRkh3Msgg"
                + "LHlUeGR7TqcdYnwIYCTMo1SkHwh3s48Zs3dK0glcjaU7Bp4hx2ri0gB+FnGe1ACA"
                + "0zT32lLp9aWZBDnK8IOpW4M/Aq0QoIwabQ8mDAByhb1KL0dwOlrvRlKH0lOxisIl"
                + "FDFiEP9WaBSxD4eik9bxmdPDlZmQ0MEmi09Q1fn877vyN70MKLgBgtZll0HxTxC/"
                + "uyG7oSq2IKojlvVsBoa06pAXmQIkIWsv6K12xKkUju+ahqNjWmqne8Hc+2+6Wad9"
                + "/am3Uw3AyoZIyNlzc44Burjwi0kF6EqkZBvWAkEM2XUgJl8vIx8rNeFesvoE0r2U"
                + "1ad6uvHg4WEBCpkAh/W0bqmIsrwFEv2g+pI9rdbEXFMB0JSDZzJltasuEPS6Ug9r"
                + "utVkpcPV4nvbCA99IOEylqMYGVTDnGSclD6+F99cH3quCo/hJsR3WFpdTWSKDQCL"
                + "avXozTG+aakpbU8/0l7YbyIeS5P2X1kplnUzYkuSNXUMMHB1ULWFNtEJpxMcWlu+"
                + "SlcVVnwSU0rsdmB2Huu5+uKJHHdFibgOVmrVV93vc2cZa3In6phw7wnd/seda5MZ"
                + "poebUgXXa/erpazzOvtZ0X/FTmg4PWvloI6bZtpT3N4Ai7KUuFgr0TLNzEmVn9vC"
                + "HlJyGIDIrQNSx58DpDu9hMTN/cbFKQBeHnzZo0mnFoo1Vpul3qgYlo1akUZr1uZO"
                + "IL9iQXGYr8ToHCjdd+1AKCMjmLUvvehryE9HW5AWcQziqrwRoGtNuskB7BbPNlyj"
                + "8tU4E5SKaToPk+ecRspdWm3KPSjKUK0YvRP8pVBZ3ZsYX3n5xHGWpOgbIQS8RgoF"
                + "HgLy6ERP";
        byte[] x509EncodedPublicKey = TestUtils.decodeBase64(publicKeyBase64);

        NativeRef.EVP_PKEY parsedPublicKey =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_subject_public_key_info(
                        x509EncodedPublicKey, new int[] {NativeConstants.EVP_PKEY_ML_DSA_65}));
        assertEquals(NativeConstants.EVP_PKEY_ML_DSA_65,
                     NativeCrypto.EVP_PKEY_type(parsedPublicKey));

        // Using two key types works.
        NativeRef.EVP_PKEY parsedPublicKey2 =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_subject_public_key_info(
                        x509EncodedPublicKey,
                        new int[] {NativeConstants.EVP_PKEY_ML_DSA_87,
                                   NativeConstants.EVP_PKEY_ML_DSA_65}));
        assertEquals(NativeConstants.EVP_PKEY_ML_DSA_65,
                     NativeCrypto.EVP_PKEY_type(parsedPublicKey2));

        // But using the wrong key type throws a parsing exception.
        assertThrows(ParsingException.class,
                     ()
                             -> new NativeRef.EVP_PKEY(
                                     NativeCrypto.EVP_PKEY_from_subject_public_key_info(
                                             x509EncodedPublicKey,
                                             new int[] {NativeConstants.EVP_PKEY_ML_DSA_87})));
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
        byte[] sig =
                decodeHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
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
    public void mldsa44_evpDigestSign_works() throws Exception {
        byte[] seed = new byte[32];
        byte[] data = new byte[100];

        NativeRef.EVP_PKEY privateKey = new NativeRef.EVP_PKEY(
                NativeCrypto.EVP_PKEY_from_private_seed(NativeConstants.EVP_PKEY_ML_DSA_44, seed));

        NativeRef.EVP_MD_CTX ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());

        NativeCrypto.EVP_DigestSignInit(ctx, 0, privateKey);
        byte[] sig = NativeCrypto.EVP_DigestSign(ctx, data, 0, data.length);
        assertEquals(2420, sig.length);

        // verify that sig is correct
        byte[] rawPublicKey = NativeCrypto.MLDSA44_public_key_from_seed(seed);
        NativeRef.EVP_PKEY publicKey =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_raw_public_key(
                        NativeConstants.EVP_PKEY_ML_DSA_44, rawPublicKey));
        NativeCrypto.EVP_DigestVerifyInit(ctx, 0, publicKey);
        boolean result =
                NativeCrypto.EVP_DigestVerify(ctx, sig, 0, sig.length, data, 0, data.length);
        assertTrue(result);

        // also verify that EVP_PKEY_get_raw_public_key works
        byte[] rawPublicKeyCopy = NativeCrypto.EVP_PKEY_get_raw_public_key(publicKey);
        assertArrayEquals(rawPublicKey, rawPublicKeyCopy);

        // check that parsing with the wrong key type fails.
        assertThrows(ParsingException.class,
                     ()
                             -> new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_raw_public_key(
                                     NativeConstants.EVP_PKEY_ML_DSA_87, rawPublicKey)));
    }

    @Test
    public void mldsa65_evpDigestSign_works() throws Exception {
        byte[] seed = new byte[32];
        byte[] data = new byte[100];

        NativeRef.EVP_PKEY privateKey = new NativeRef.EVP_PKEY(
                NativeCrypto.EVP_PKEY_from_private_seed(NativeConstants.EVP_PKEY_ML_DSA_65, seed));

        NativeRef.EVP_MD_CTX ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());

        NativeCrypto.EVP_DigestSignInit(ctx, 0, privateKey);
        byte[] sig = NativeCrypto.EVP_DigestSign(ctx, data, 0, data.length);
        assertEquals(3309, sig.length);

        // verify that sig is correct
        byte[] rawPublicKey = NativeCrypto.MLDSA65_public_key_from_seed(seed);
        NativeRef.EVP_PKEY publicKey =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_raw_public_key(
                        NativeConstants.EVP_PKEY_ML_DSA_65, rawPublicKey));
        NativeCrypto.EVP_DigestVerifyInit(ctx, 0, publicKey);
        boolean result =
                NativeCrypto.EVP_DigestVerify(ctx, sig, 0, sig.length, data, 0, data.length);
        assertTrue(result);

        // also verify that EVP_PKEY_get_raw_public_key works
        byte[] rawPublicKeyCopy = NativeCrypto.EVP_PKEY_get_raw_public_key(publicKey);
        assertArrayEquals(rawPublicKey, rawPublicKeyCopy);

        // check that parsing with the wrong key type fails.
        assertThrows(ParsingException.class,
                     ()
                             -> new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_raw_public_key(
                                     NativeConstants.EVP_PKEY_ML_DSA_87, rawPublicKey)));
    }

    @Test
    public void mldsa87_evpDigestSign_works() throws Exception {
        byte[] seed = new byte[32];
        byte[] data = new byte[100];

        NativeRef.EVP_PKEY privateKey = new NativeRef.EVP_PKEY(
                NativeCrypto.EVP_PKEY_from_private_seed(NativeConstants.EVP_PKEY_ML_DSA_87, seed));

        NativeRef.EVP_MD_CTX ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());

        NativeCrypto.EVP_DigestSignInit(ctx, 0, privateKey);
        byte[] sig = NativeCrypto.EVP_DigestSign(ctx, data, 0, data.length);
        assertEquals(4627, sig.length);

        byte[] rawPublicKey = NativeCrypto.MLDSA87_public_key_from_seed(seed);
        NativeRef.EVP_PKEY publicKey =
                new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_raw_public_key(
                        NativeConstants.EVP_PKEY_ML_DSA_87, rawPublicKey));
        NativeCrypto.EVP_DigestVerifyInit(ctx, 0, publicKey);
        boolean result =
                NativeCrypto.EVP_DigestVerify(ctx, sig, 0, sig.length, data, 0, data.length);

        assertTrue(result);

        // also verify that EVP_PKEY_get_raw_public_key works
        byte[] rawPublicKeyCopy = NativeCrypto.EVP_PKEY_get_raw_public_key(publicKey);
        assertArrayEquals(rawPublicKey, rawPublicKeyCopy);

        // check that parsing with the wrong key type fails.
        assertThrows(ParsingException.class,
                     ()
                             -> new NativeRef.EVP_PKEY(NativeCrypto.EVP_PKEY_from_raw_public_key(
                                     NativeConstants.EVP_PKEY_ML_DSA_65, rawPublicKey)));
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

        byte[] extension = NativeCrypto.get_ocsp_single_extension(
                ocspResponse, OCSP_SCT_LIST_OID, certificate.getContext(), certificate,
                issuer.getContext(), issuer);

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
        assertThrows(
                NullPointerException.class,
                () -> NativeCrypto.EVP_PKEY_encrypt(null, new byte[128], 0, new byte[128], 0, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_NullOutputArgument() throws Exception {
        assertThrows(NullPointerException.class,
                     ()
                             -> NativeCrypto.EVP_PKEY_encrypt(getPkeyCtxForEncrypt(), null, 0,
                                                              new byte[128], 0, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_NullInputArgument() throws Exception {
        assertThrows(NullPointerException.class,
                     ()
                             -> NativeCrypto.EVP_PKEY_encrypt(getPkeyCtxForEncrypt(), new byte[128],
                                                              0, null, 0, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_OutputIndexOOBUnder() throws Exception {
        assertThrows(ArrayIndexOutOfBoundsException.class,
                     ()
                             -> NativeCrypto.EVP_PKEY_encrypt(getPkeyCtxForEncrypt(), new byte[128],
                                                              -1, new byte[128], 0, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_OutputIndexOOBOver() throws Exception {
        assertThrows(ArrayIndexOutOfBoundsException.class,
                     ()
                             -> NativeCrypto.EVP_PKEY_encrypt(getPkeyCtxForEncrypt(), new byte[128],
                                                              129, new byte[128], 0, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_InputIndexOOBUnder() throws Exception {
        assertThrows(ArrayIndexOutOfBoundsException.class,
                     ()
                             -> NativeCrypto.EVP_PKEY_encrypt(getPkeyCtxForEncrypt(), new byte[128],
                                                              0, new byte[128], -1, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_InputIndexOOBOver() throws Exception {
        assertThrows(ArrayIndexOutOfBoundsException.class,
                     ()
                             -> NativeCrypto.EVP_PKEY_encrypt(getPkeyCtxForEncrypt(), new byte[128],
                                                              0, new byte[128], 128, 128));
    }

    @Test
    public void EVP_PKEY_encrypt_InputLengthNegative() throws Exception {
        assertThrows(ArrayIndexOutOfBoundsException.class,
                     ()
                             -> NativeCrypto.EVP_PKEY_encrypt(getPkeyCtxForEncrypt(), new byte[128],
                                                              0, new byte[128], 0, -1));
    }

    @Test
    public void EVP_PKEY_encrypt_InputIndexLengthOOB() throws Exception {
        assertThrows(ArrayIndexOutOfBoundsException.class,
                     ()
                             -> NativeCrypto.EVP_PKEY_encrypt(getPkeyCtxForEncrypt(), new byte[128],
                                                              0, new byte[128], 100, 29));
    }

    @Test
    public void EVP_PKEY_CTX_set1_signature_context_string_nullPkeyCtxThrows() throws Exception {
        assertThrows(
                NullPointerException.class,
                () -> NativeCrypto.EVP_PKEY_CTX_set1_signature_context_string(NULL, new byte[0]));
    }

    @Test
    public void EVP_PKEY_CTX_set1_signature_context_string_works() throws Exception {
        // Test case from wycheproof/testvectors_v1/mldsa_44_sign_seed_test.json.
        byte[] seed = TestUtils.decodeHex(
                "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
        NativeRef.EVP_PKEY privateKey = new NativeRef.EVP_PKEY(
                NativeCrypto.EVP_PKEY_from_private_seed(NativeConstants.EVP_PKEY_ML_DSA_44, seed));
        byte[] contextStr = TestUtils.decodeHex("436f6e74657874");
        byte[] data = TestUtils.decodeHex("48656c6c6f20776f726c64");
        byte[] expectedSig = TestUtils.decodeHex(
                "e11d24772c24efc107ae3abb0149817436f11684d3548748cba19fc0b373ddcb7c8f68f00407d96457"
                + "0c155a9a34823d5b33345a2bb4dfc43d2e178331bc6573f39d634239230cfc160bf03f41d176854d"
                + "fee5be915ed6c3f4112fff50d8effcc457708261e715fdf0676831989a15cbd16b92fc97bec06c75"
                + "919c114c167d2bfae8d7dfa384068c0d96a8e6039e755f9b90cb57b4b0e678854a88a8fada69b91b"
                + "bbea873f81a7489c0e3612774e8a00370b9b9650331bd2184b9037ce340d82b39436dab990f0c176"
                + "b90421e71fd182bc07ed70e54587bf2b92c038e8794aded666a6c9cdb29d8747c223967c5a283d3b"
                + "e2946584202a021c5264e04587b3c60bb5ec7a73e2d4d7caf4619e388d1beff4ec4bf7d104fee347"
                + "65ab6a51108660f052a05d16aa46efc49d46ff42d65bbc6521d8a18c8cbe104de453367bae5c72b4"
                + "3854def8222480746003fc8ec4efa2d122965ef9e0e5b3d68c9069af54ef4511036a079d9bb67a43"
                + "eabec138d37eeaa918bf14815159b0216352a354110d5c835ea9631075317ba617085f2d86215c09"
                + "c288a584add2809bcc7f50f9071fee5ea2fc08020f2a106fad222155155018f67162855ce6243287"
                + "24b659c645cc30c6382c6fdf48e1c9e8499bf6f8ccd63f06113e3262efd0800d2619d59cd8966d84"
                + "7c2de3854634f3b5e83f84e66cac84e1013b93fe3869f270380ccf8c26591a2635cfa048d1955516"
                + "560c95ce0c39b0cd7c12c3234b13939386adcf557118f21811c3595151919da2bce155f9c6300703"
                + "a7209fcd893305486df90a828bc551f23878b72f04fe471ed75982175b74ce135fbdf0c786acdefb"
                + "09829afdaf7eab308cd8c181345e8f713afd5b433a6be59a4e70b421c216a02a16bf0e9276309922"
                + "11d48d71ac0aec3d0626d84456303c3f35c132571eeafa0106cc7ff333e0d2dcd9352b3cdf36a8fe"
                + "c2a750e5c8ebfeed52a94e5f41c1d295ddc01de6ddbf9df9970460f33fb362b0b94fac9b496459c6"
                + "ca989e90d53ec8944d1518d7fcc21f1adca0bac93df266820dfbe9c7cbce4b762340ef8ea6464d26"
                + "c5fd4f2b67b9776548b567d7426511aa9c2fdd19d85206130ab6cf6d7f5115dcb7f53b628b99ed8f"
                + "a1bd6055764f950deeabae276b419370c4700cd37ca2a34b387d644d4e0ef6a380a5e2d2f32376b4"
                + "b8752bfc3003c2b67111105b775fd21c3e5ae678f79975097e6c63e759eae6b14d60c9778b4bc31a"
                + "aa4c9f4fa4911688dc390047aa11f9a998baa652eb9be561cb4039bd9801fd62eedb6f568ff4189d"
                + "ffa4c9a7bc11d9faf26499285098043fe699b565545a930d9ce8f5247eea4c5f6df27f3e050b8d01"
                + "eee5dd1058efe65190eebeaa0742515d9f8f36bd29e6d84e56d9e41c1a551d3ce6ad7e8967872abd"
                + "60488d4172c56006eb2db95cb25743287a1d73fb3a36ca4d7f7dce22fd2baf10ad47aeacf82b37da"
                + "fad7c06a6795be40bd6abfc8f998219f2a0e58531c8ccd1bf3ce66b960741a2da9d36971bad67ee4"
                + "d75e660e0805e889eab0f0be62b38439476ec289e77176341461b474f66f44120f784de5490529a1"
                + "f6f013eac2dfbdea11275733f1b1723357740a903085e09e8d61a2e2c84f26ddf95fe630a398329e"
                + "48cd58cbf358b98b839c7f17893b6e913ee286c976bea3a0bbc58177ce0a35a28c5bb4ac6d9d5ffd"
                + "b9dc626555a55bea17386237d8ccf2ef60a31393b1f49a37329598f706eeeca9c2d0b02ef13dfa6b"
                + "b9f1e84517aa51d7d7e85ffbdacf23892962d231f67c142df49d6236630bdb50dad047bc84fec4f5"
                + "17758c3f54c77f5f25fe78a12db9e4dd766198d6014b35cdbab0257cc50c7f9dfa5ac0a88c7d107c"
                + "8f6bb50dee4d7a3e35cc54fb12572d901f02f4e8bf15cb6fef1910fcd5d54530dbca4046bd9ba303"
                + "9c4ff97bcbfb6d00a16c1f902a25005c30d3d0d96a9d7116b15f81699614afe0aa448973b6da55c1"
                + "8f20395a15d2ac53c5725e45711f9b3050ca8f409d4776b568afa8d6657668e7d6d3553d23bdbe09"
                + "cd1957fc5c76fb733b237e60073dfff5d64ad3f03d3116fe1db0ee27c36b9671b0efa079cb0ae055"
                + "8023ac6a0aa36f1f2d887805658131398f78b4c2fb2e0bfc4a37e444015879f0db10abd5b56d5993"
                + "a3ccc0798651c0b85b658285cd00e898be4406a431e29d861379c26ed26cee7f23c05fba0519fa6d"
                + "0336120dffd6d441d7de14233ff6c345425b852e1cbef6ac4d442e6f121975b912b9e60538b5efe7"
                + "4c3df3861671b54d96d1d512725fe63b511c4d90261577f8a992746cfe6a4e1426a3d9fcbdb3098a"
                + "626681ed5c41c3158667708c321a515a978c47c337b1d9cdf6be83fae368d57843baaea2b8b7a943"
                + "98a8fcdb3b3e39c55a8feceae53f4b2b8967f5a7f671d7cff584596682ed7436979ee9e8610bdcdd"
                + "0c065b39e22b3fefdb8ebbe7ea59ddb2058980f8c186ec95428a8cea2c41376312a073543283f2c8"
                + "a970b11f1f31dc531748292cf198c63b2f21996f2bf769d397083f5f7c2da8952b38a199a2fa2698"
                + "e156cc5550f123d99d4f65852fab97e184f0f615ac419af60c236f4e1c3c209b4eda22ec47c963d6"
                + "b5318031cda0b1ce9dd0876b0a011d9d1a8a1233c38538581401dcb8766c4c9147d257828a0068a9"
                + "1e458e3a312e398c2b1affcbd7a702efdcb3f79a28d131667545f2ac3d04fefee0228f257e689a85"
                + "fb92f528d901768a2dfda51f65ad31e1b781759cde2a44adf0a4b84639a8160bf863445f94a04ab7"
                + "885fa247fe057c161246f1202bad84345aea9e34b77ef93fe01d090f49e1ba3e214acfea26bc04e4"
                + "bb2ef2f4fa2af4751a873573ee273d8ab7f1d59aad74c8da98232e2562966b6816f01c1db37c0b5a"
                + "55710011656ff76f8eb4bbba1e5875e954f1dc43bbd0d77b09cfbc57890acedf796507d31fee6330"
                + "5cc97209964cc7897befd20db3d6203a317bc8769b8b0081016f2180eb3b40d24ac1458d0afb8034"
                + "b8babe87c91ead17f25715104be58a526409e8f5053b67e48d7de17a2f81f68a679a6d9192120eda"
                + "7564c7970c88d4aa266f7063d6b24de7b402c69d9d14f8d51b3bdff45e952c45ead4e729d195f930"
                + "870fda380f64085011fff63caca5e79d1dae0b2b0dad7e01c4b7b2714b20d3bb69dcee4fe9e04124"
                + "20b55abba95bacbc1b1fe498474d8d3a5396968b057b8b5081ddb57eaae581da0a1b482879cdc1bd"
                + "a82fe83d4007375831cf06bcd334ac42c780cb91121eb4021f39f9292a6a023b1010b35d378a7986"
                + "01cd4a6cfebc0f45b1e7879a8f884e3d465a6680a0b8cbd5e0f210111a40464a586184859299a5e3"
                + "29384751b5c5c6eceef1ff1d3864879398a1b5b7cbd8000000000000000000000000000000000000"
                + "0000000000000000000000000000000b19242f");
        NativeRef.EVP_MD_CTX ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        long pkeyCtxVerify = NativeCrypto.EVP_DigestVerifyInit(ctx, 0, privateKey);

        NativeCrypto.EVP_PKEY_CTX_set1_signature_context_string(pkeyCtxVerify, contextStr);

        assertTrue(NativeCrypto.EVP_DigestVerify(ctx, expectedSig, 0, expectedSig.length, data, 0,
                                                 data.length));
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
    public void mlKem768PublicKeyFromSeed_returnsPublicKeyIfPrivateKeyIsValid() throws Exception {
        // test vector from https://www.ietf.org/archive/id/draft-ietf-hpke-pq-01.html, Section A.1
        byte[] privateKey =
                decodeHex("06f7d4f1495a828789f5543cb847369e10751ca5369a473c74e46043080f94f5"
                          + "25f2f8cb7d8cfbf3cf8496728611a6567afd446a6ed1d22f6d32f74ef266a97e");
        byte[] expectedPublicKey =
                decodeHex("33e49cea9c631f102595637291548f7220782f498bca5073b8039759f5582f45"
                          + "aa59245f41e5516da2a779b325e039651c348f57502602a3b7b8482b4b1576c9"
                          + "3aa8b8c5155e5bc5dbc6a08d57103bc970b016ab7ab22320c430291ba1e80855"
                          + "64c4a13686aafefb510ce76e36876f2fdb1b7ba49550c15f5d366abe420e7ff2"
                          + "459cd7af36f5c285981adcf84020b04a66a0bc58172f8a34280fc32497a56308"
                          + "238a9f27ae95f0a593a70ae7594260e60930695f5f803eb2210fe3ac61c8bc20"
                          + "ec2566dafc399cea81a3834619420e5d85476cd573c7a08eaec4c60cf7999acc"
                          + "98724b934e259cda793dfda761cfa4289530b1f75b6a592730b8f5607eba701a"
                          + "150c38ac0e21038bfef496d2cb808f7342317789d1581b6f8565e3018d796013"
                          + "fed26b59fb226b5988633923a72a9acf42960c228f1e25b84f18ba4fd8762067"
                          + "9d6c7a9e5f4340dadc3af252afd28231e3d52cb924209e50ba1ca632de811ae1"
                          + "097cd89803884a8c750663baec78c90254f038574fdcb74c527610e21469398a"
                          + "20abcce9f50e1537867aa036bf1452cbf70850e8a5f5464eccc8a2af260a4550"
                          + "7e2da24c4868699065c95e3946ace90a655696f654892d8470a535cda5d58c44"
                          + "c8c0cb7bcc7104a847bc4cb1f03b8872143f5491c9e8c8ed46a6a6703c07d42a"
                          + "b8fabc4e25477245754d718ad8c88ce753c9756c2403948c06c1345c570fbd9a"
                          + "5932982f326a2f2ac69ebf5a58bc788fdb72a4d90865d3169d7752579cc49ad5"
                          + "e27479260dbba4800b521d21d22eb633168632b5209c4b81f32026a8111e07b1"
                          + "48babf740297af87239bc760b976862c551622416a6fb23825112308867ba70a"
                          + "75ba33179c2373b97492235a27c1f266cbc18f71c0596e47a285bc2e09397a63"
                          + "2309ff67739cb132d8c4007d2926fafc5eb56a6cf1960e87b4488c4895aacc6f"
                          + "cbbc4b6dd2b56cc69616653836550bbb9663b678370c3916fb832e17ba753d04"
                          + "787d78b0ddf11f6410bbe847cd6b1abdcee2835d50867a40137723433fdb6e94"
                          + "f902fda88b96d95af872000447c3649a93d3e0013dab5350dbb45c6190089c56"
                          + "cd4c1fce162daba74abfe8ae673105e0ebb94e52b37967b609741eb4608723e9"
                          + "858937b4996269033ca2cb503c4d3ccda0e15137cbc602728cc9bb5cca55b2cb"
                          + "c4579d02bdca430a052bbfc68bb5c8eb7c0139272c545d09f345b49a800314ca"
                          + "63c5097ef24cd793946410a931d5437becb557197affa37071954eee9c093a34"
                          + "86492362595761c83aac2ce46cdaebaa07ab3c3c1363c15bb8c4c869f54c6fdf"
                          + "a78924b954e0b480d3a128a2f64f7527beb2ec92ea6994dddc5eac10bde8a456"
                          + "09784e7948b6acc7c5da8526dd970870f46812bb0b53867668e17183fa638926"
                          + "1fa5da9a3ad8451094cd8ddb28683c1ce853c0e1cb3a4f79a168502242f66217"
                          + "2bc21609492fa57a9f077a1889c42cb2aa3bc2583275ce6b171c3e3aa4279483"
                          + "b204cb3a1a98535a2fe7c1b3d322c52dfb9e9ec46f926562ef1c8992a2bc5fc0"
                          + "47961898d1eb3d35cb1a018cb440d84de5047e50a4abd891c84f9431e36bb813"
                          + "4642e6fa144c15307a5122f07252b1e65b0e9ab3c2a184826c9a9cd938bdd588"
                          + "138a731c1b51787f166ca6205dadaaffc05c609f747b99fc3b918359e2ac28c8");

        byte[] publicKey = NativeCrypto.MLKEM768_public_key_from_seed(privateKey);
        assertArrayEquals(expectedPublicKey, publicKey);

        byte[] privateKeyTooShort = Arrays.copyOf(privateKey, privateKey.length - 1);
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.MLKEM768_public_key_from_seed(privateKeyTooShort));
        byte[] privateKeyTooLong = Arrays.copyOf(privateKey, privateKey.length + 1);
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.MLKEM768_public_key_from_seed(privateKeyTooLong));
    }

    @Test
    public void mlKem1024PublicKeyFromSeed_returnsPublicKeyIfPrivateKeyIsValid() throws Exception {
        // test vector from https://www.ietf.org/archive/id/draft-ietf-hpke-pq-01.html, Section A.2
        byte[] privateKey =
                decodeHex("870150f8c622ea6866db299c3348c737f0e8da17c1e7f721029b5e035db59421"
                          + "68522e0bea336dd93031199ab74b3acd684cbd03d6e56f304e5c28e7a9cba3bc");
        byte[] expectedPublicKey =
                decodeHex("daa944e375a5c36c1f3771be499c297aba61d8762694256ef840460d10bed594"
                          + "641d58446e3795792c51f272383e78aa517112197230c3604993182d046679a8"
                          + "70495f1c44a6e2b30da7c251034f127561e02a234d0bbbb4ccc5a15224d06431"
                          + "08c44ad2973085371c80a064eaf524ebd90d5ad6057d45326a8b4ef532a7dfa9"
                          + "3ff83783ece423106c8b1ed2627b59ca34d71a3b4014698c9969db604589270b"
                          + "492124a80eba50909c2847a8bc9881b0788de95ad718a9c71a33b7ba98ab8ac3"
                          + "1ed744ffca6d6e08a170084c072bafaf7c25d5f56c519a6e3bdb30b0906192e2"
                          + "671da765ef53af8ac0197af2c9ac794a41038599766323718347f8821f3888ce"
                          + "250b84335eb8c43de4d9720f26b92531685af7576f62c6f39249c6645433387a"
                          + "8c617fdeb0650f77580de2af30019eb9959fb39ca2ed5364fc0a54e4809ac6a2"
                          + "424d284113e25179427b6a22936dc5839f3a9cb8bb49a5239ecd09278e432f65"
                          + "59bba0d56f9a9b87af068369c207b040022306a5fcc64d3264338a0789d7a833"
                          + "ad280b9ef2619c75769ed124a19c89a9b00a43c934b0042f24e28d2c353f2718"
                          + "ae9eb556bcd7c408f01e07bc7ad1d563b411133899312e5c6125f3cf39448ba6"
                          + "4c8a904414c32a8fc233649a2a69b98ab658094908f89c7089765e8211e5c75d"
                          + "949c6e53c6445d11902b25b452da79db853b78c8a629f1c5ef762f34f2126a20"
                          + "92c85b618c1a1bb506cd60e0c8b39b3c9aec088494c966878db1c3772b0992de"
                          + "4cb3a4958d2c43878f681a53cc207f446c6f95addb7047116bb4d5124b5fc532"
                          + "20401a7b5531fbb49bafa345479c620bfa8529f2a73f830c975b820b465a9745"
                          + "3483a746ec573289a8c02b53906c7423dac584495b6c771a60db498ae478a8f9"
                          + "a9833c81666a55a47a01adcd189b0e8c90aaa382a1d2301a873d9370c12ecc61"
                          + "04516e6b2957e3a7806c551d96aabe3b5cc47f918c467732dbe3a138305490c3"
                          + "8b33760d4b164bd509595415a3b560082a9b688b386c20f05c0667631555015e"
                          + "ba61e87174600c1fd0971b4e776e8452ad50748fd5a783ade73d80a97c8b07a3"
                          + "74ca53ba95c89157b5e2bb333518adce58c5ad90734ee20cc4646382f4bb91d9"
                          + "431968895f541a25da9a892c7086cb361e4240ae996afa5445c0cba188d13e4a"
                          + "8863c6918a7e247aa893c055a052bbaa3bd1b2731207006e5403e8742c844605"
                          + "d4aa64963b0af4978fbb7a1e409ca5470395dc24a700a850b189039f87bd2c78"
                          + "58f28a9e2c624ecea50f1f7889f6a99cfcfacb0c5861586c3e97a41d855319d5"
                          + "930e0aba9eb1b1bf013b32f6cb0d1570243eda540538a288d13bad128907d079"
                          + "25153925e9253c117e82ab0c27c49fc68162e465b0e3fb7c1671c0965c71b583"
                          + "6862301a85606122896e8d9a6d848c1818580ddc7955f3446f148338ca14149a"
                          + "205a3c6bb43e30abcf20a69f36a7a5e60efdf69b5922cd6a7744e420311f3b9c"
                          + "b2148ab6ea7e11b522c81ab0209a43f8da598f580fc8536b2838bb8ca0c26690"
                          + "5270609304ab78d6c40fa8a7015862b80ebc34a9ea25959a3c3fc4abd56a7961"
                          + "6215f2caaacb51033e02ba4b446c0fd47e515ca9ad44c7e3a2739b9b69242a6c"
                          + "c528880491c72c7858ac13804db088a97541ed11208b369bfab3c8e4890ff1c7"
                          + "3f2d783004c482458980eeb21f40c73d5d5282a78279d6f71bad650843c83d03"
                          + "23a7e90748b555853a50c091c31a9655b2388226e4524cdcbabb61543eb7caa8"
                          + "8396933e1a5986986e41da209f131a9bbc9a44d66ba077229c499386a4418b99"
                          + "0e20707c323846c861bcf227b2ff6ca3ee6511b37c190618c1e610be4672507f"
                          + "f7c7f5486930670d99bb6c2c28afaca54b815144aed10f82c27ad8922d5a9c86"
                          + "b15c9da866ad0ff96a2f569b42d52cdec8793d0414cfc35ddcebca8066b25e93"
                          + "0b36743db6b05a6ec6641b9403f88a5320842522f388683c72eb60bfe1db314a"
                          + "0b78a0a0cc76a692137c9613bb47c3f54911e67c1ba48a46081fcaf0974783ad"
                          + "ddc88492943d8b5934a41b46f95120fce5a21e0223dee7b140a924ce711e0e93"
                          + "c434616b58b02c2e30352599380ca04127f40a4134c5862c3bab08a3f265a467"
                          + "9c989cfc1f24c9c553cabb37ab2767f5ab2d7a20e57b0b65fb6e4a6119ba33a7"
                          + "36a9568de2ee95c312aad4c14639282831a3461d6e08800b592c8aa9d7ef6028");
        byte[] publicKey = NativeCrypto.MLKEM1024_public_key_from_seed(privateKey);
        assertArrayEquals(expectedPublicKey, publicKey);

        byte[] privateKeyTooShort = Arrays.copyOf(privateKey, privateKey.length - 1);
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.MLKEM1024_public_key_from_seed(privateKeyTooShort));
        byte[] privateKeyTooLong = Arrays.copyOf(privateKey, privateKey.length + 1);
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.MLKEM1024_public_key_from_seed(privateKeyTooLong));
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
    private static final int MLKEM768 = 0x0041;
    private static final int MLKEM1024 = 0x0042;
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
                XWING, HKDF_SHA256, AES_128_GCM, publicKey, info);
        NativeRef.EVP_HPKE_CTX ctxSender = (NativeRef.EVP_HPKE_CTX) result[0];
        byte[] encapsulated = (byte[]) result[1];
        assertEquals(1120, encapsulated.length);

        byte[] ciphertext = NativeCrypto.EVP_HPKE_CTX_seal(ctxSender, plaintext, aad);

        NativeRef.EVP_HPKE_CTX ctxRecipient =
                (NativeRef.EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_base_mode_recipient(
                        XWING, HKDF_SHA256, AES_128_GCM, privateKey, encapsulated, info);
        byte[] output = NativeCrypto.EVP_HPKE_CTX_open(ctxRecipient, ciphertext, aad);

        assertArrayEquals(plaintext, output);
    }

    @Test
    public void hpkeWithMLKEM768_publicKeyFromSeedSealOpen_success() throws Exception {
        byte[] privateKey = decodeHex(
                "06f7d4f1495a828789f5543cb847369e10751ca5369a473c74e46043080f94f525f2f8cb7d8cfbf3"
                + "cf8496728611a6567afd446a6ed1d22f6d32f74ef266a97e");
        byte[] publicKey = NativeCrypto.MLKEM768_public_key_from_seed(privateKey);

        byte[] info = decodeHex("aa");
        byte[] plaintext = decodeHex("bb");
        byte[] aad = decodeHex("cc");

        Object[] result = NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                MLKEM768, HKDF_SHA256, AES_128_GCM, publicKey, info);
        NativeRef.EVP_HPKE_CTX ctxSender = (NativeRef.EVP_HPKE_CTX) result[0];
        byte[] encapsulated = (byte[]) result[1];
        assertEquals(1088, encapsulated.length);

        byte[] ciphertext = NativeCrypto.EVP_HPKE_CTX_seal(ctxSender, plaintext, aad);

        NativeRef.EVP_HPKE_CTX ctxRecipient =
                (NativeRef.EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_base_mode_recipient(
                        MLKEM768, HKDF_SHA256, AES_128_GCM, privateKey, encapsulated, info);
        byte[] output = NativeCrypto.EVP_HPKE_CTX_open(ctxRecipient, ciphertext, aad);

        assertArrayEquals(plaintext, output);
    }

    @Test
    public void hpkeWithMLKEM1024_publicKeyFromSeedSealOpen_success() throws Exception {
        byte[] privateKey =
                decodeHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                          + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        byte[] publicKey = NativeCrypto.MLKEM1024_public_key_from_seed(privateKey);

        byte[] info = decodeHex("aa");
        byte[] plaintext = decodeHex("bb");
        byte[] aad = decodeHex("cc");

        Object[] result = NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                MLKEM1024, HKDF_SHA256, AES_128_GCM, publicKey, info);
        NativeRef.EVP_HPKE_CTX ctxSender = (NativeRef.EVP_HPKE_CTX) result[0];
        byte[] encapsulated = (byte[]) result[1];
        assertEquals(1568, encapsulated.length);

        byte[] ciphertext = NativeCrypto.EVP_HPKE_CTX_seal(ctxSender, plaintext, aad);

        NativeRef.EVP_HPKE_CTX ctxRecipient =
                (NativeRef.EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_base_mode_recipient(
                        MLKEM1024, HKDF_SHA256, AES_128_GCM, privateKey, encapsulated, info);
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
                             -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                                     DHKEM_P256_HKDF_SHA256, HKDF_SHA256, AES_128_GCM, pkRecipient,
                                     info));
        assertThrows(IllegalArgumentException.class,
                     ()
                             -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                                     DHKEM_P384_HKDF_SHA384, HKDF_SHA256, AES_128_GCM, pkRecipient,
                                     info));
        assertThrows(IllegalArgumentException.class,
                     ()
                             -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                                     DHKEM_P521_HKDF_SHA512, HKDF_SHA256, AES_128_GCM, pkRecipient,
                                     info));
        assertThrows(IllegalArgumentException.class,
                     ()
                             -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                                     DHKEM_X448_HKDF_SHA256, HKDF_SHA256, AES_128_GCM, pkRecipient,
                                     info));

        // These KDF IDs are currently not supported in Conscrypt.
        assertThrows(IllegalArgumentException.class,
                     ()
                             -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                                     DHKEM_X25519_HKDF_SHA256, HKDF_SHA384, AES_128_GCM,
                                     pkRecipient, info));
        assertThrows(IllegalArgumentException.class,
                     ()
                             -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                                     DHKEM_X25519_HKDF_SHA256, HKDF_SHA512, AES_128_GCM,
                                     pkRecipient, info));

        // These AEAD IDs are currently not supported in Conscrypt.
        assertThrows(IllegalArgumentException.class,
                     ()
                             -> NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
                                     DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, EXPORT_ONLY,
                                     pkRecipient, info));
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
    public void mldsa44_public_key_from_seed_works() throws Exception {
        byte[] privateKeySeed =
                decodeHex("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D");

        byte[] publicKey = NativeCrypto.MLDSA44_public_key_from_seed(privateKeySeed);
        assertEquals(1312, publicKey.length);

        byte[] privateKeySeedTooShort = Arrays.copyOf(privateKeySeed, privateKeySeed.length - 1);
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.MLDSA44_public_key_from_seed(privateKeySeedTooShort));

        byte[] privateKeySeedTooLong = Arrays.copyOf(privateKeySeed, privateKeySeed.length + 1);
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.MLDSA44_public_key_from_seed(privateKeySeedTooLong));
    }

    @Test
    public void mldsa65_public_key_from_seed_works() throws Exception {
        byte[] privateKeySeed =
                decodeHex("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D");

        byte[] publicKey = NativeCrypto.MLDSA65_public_key_from_seed(privateKeySeed);
        assertEquals(1952, publicKey.length);

        byte[] privateKeySeedTooShort = Arrays.copyOf(privateKeySeed, privateKeySeed.length - 1);
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.MLDSA65_public_key_from_seed(privateKeySeedTooShort));

        byte[] privateKeySeedTooLong = Arrays.copyOf(privateKeySeed, privateKeySeed.length + 1);
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.MLDSA65_public_key_from_seed(privateKeySeedTooLong));
    }

    @Test
    public void mldsa87_public_key_from_seed_works() throws Exception {
        byte[] privateKeySeed =
                decodeHex("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D");

        byte[] publicKey = NativeCrypto.MLDSA87_public_key_from_seed(privateKeySeed);
        assertEquals(2592, publicKey.length);

        byte[] privateKeySeedTooShort = Arrays.copyOf(privateKeySeed, privateKeySeed.length - 1);
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.MLDSA87_public_key_from_seed(privateKeySeedTooShort));

        byte[] privateKeySeedTooLong = Arrays.copyOf(privateKeySeed, privateKeySeed.length + 1);
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.MLDSA87_public_key_from_seed(privateKeySeedTooLong));
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
                     NativeCrypto.SLHDSA_SHA2_128S_verify(dataBuffer, data.length, signature,
                                                          publicKey));

        // data too short
        assertEquals(
                0,
                NativeCrypto.SLHDSA_SHA2_128S_verify(data, data.length - 1, signature, publicKey));

        byte[] signatureTooShort = Arrays.copyOf(signature, signature.length - 1);
        assertEquals(0,
                     NativeCrypto.SLHDSA_SHA2_128S_verify(data, data.length, signatureTooShort,
                                                          publicKey));

        byte[] signatureTooLong = Arrays.copyOf(signature, signature.length + 1);
        assertEquals(0,
                     NativeCrypto.SLHDSA_SHA2_128S_verify(data, data.length, signatureTooLong,
                                                          publicKey));

        byte[] modifiedSignature = signature.clone();
        modifiedSignature[0] = (byte) (modifiedSignature[0] ^ 0x01);
        assertEquals(0,
                     NativeCrypto.SLHDSA_SHA2_128S_verify(data, data.length, modifiedSignature,
                                                          publicKey));

        byte[] modifiedData = data.clone();
        modifiedData[0] = (byte) (modifiedData[0] ^ 0x01);
        assertEquals(0,
                     NativeCrypto.SLHDSA_SHA2_128S_verify(modifiedData, modifiedData.length,
                                                          signature, publicKey));

        int invalidDataLen = data.length + 1;
        assertThrows(RuntimeException.class,
                     () -> NativeCrypto.SLHDSA_SHA2_128S_sign(data, invalidDataLen, privateKey));
        assertThrows(RuntimeException.class,
                     ()
                             -> NativeCrypto.SLHDSA_SHA2_128S_verify(data, invalidDataLen,
                                                                     signature, publicKey));

        byte[] privateKeyTooShort = Arrays.copyOf(privateKey, privateKey.length - 1);
        assertThrows(
                RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_sign(data, data.length, privateKeyTooShort));

        byte[] privateKeyTooLong = Arrays.copyOf(privateKey, privateKey.length + 1);
        assertThrows(
                RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_sign(data, data.length, privateKeyTooLong));

        byte[] publicKeyTooShort = Arrays.copyOf(publicKey, publicKey.length - 1);
        assertThrows(RuntimeException.class,
                     ()
                             -> NativeCrypto.SLHDSA_SHA2_128S_verify(data, data.length, signature,
                                                                     publicKeyTooShort));

        byte[] publicKeyTooLong = Arrays.copyOf(publicKey, publicKey.length + 1);
        assertThrows(RuntimeException.class,
                     ()
                             -> NativeCrypto.SLHDSA_SHA2_128S_verify(data, data.length, signature,
                                                                     publicKeyTooLong));

        assertThrows(
                RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_generate_key(publicKey, privateKeyTooShort));
        assertThrows(
                RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_generate_key(publicKeyTooShort, privateKey));
        assertThrows(
                RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_generate_key(publicKey, privateKeyTooLong));
        assertThrows(
                RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_generate_key(publicKeyTooLong, privateKey));
    }

    @Test
    public void test_slhdsa_sha2_128s_prehash_works() throws Exception {
        byte[] publicKey = new byte[32];
        byte[] privateKey = new byte[64];
        NativeCrypto.SLHDSA_SHA2_128S_generate_key(publicKey, privateKey);

        byte[] msg = decodeHex("AB");
        MessageDigest md = MessageDigest.getInstance("SHA-384");
        byte[] digest = md.digest(msg);
        assertEquals(48, digest.length);
        int hashNid = NativeConstants.NID_sha384;

        byte[] signature =
                NativeCrypto.SLHDSA_SHA2_128S_prehash_sign(digest, digest.length, hashNid, privateKey);
        assertEquals(7856, signature.length);

        int result =
                NativeCrypto.SLHDSA_SHA2_128S_prehash_verify(
                        digest, digest.length, signature, hashNid, publicKey);
        assertEquals(1, result);

    // digest buffer is larger than digest
    byte[] digestBuffer = Arrays.copyOf(digest, digest.length + 42);
        assertEquals(
                1,
                NativeCrypto.SLHDSA_SHA2_128S_prehash_verify(
                        digestBuffer, digest.length, signature, hashNid, publicKey));

    // digest too short
    assertEquals(
        0,
        NativeCrypto.SLHDSA_SHA2_128S_prehash_verify(
            digest, digest.length - 1, signature, hashNid, publicKey));

        byte[] signatureTooShort = Arrays.copyOf(signature, signature.length - 1);
        assertEquals(
                0,
                NativeCrypto.SLHDSA_SHA2_128S_prehash_verify(
                        digest, digest.length, signatureTooShort, hashNid, publicKey));

        byte[] signatureTooLong = Arrays.copyOf(signature, signature.length + 1);
        assertEquals(
                0,
                NativeCrypto.SLHDSA_SHA2_128S_prehash_verify(
                        digest, digest.length, signatureTooLong, hashNid, publicKey));

        byte[] modifiedSignature = signature.clone();
        modifiedSignature[0] = (byte) (modifiedSignature[0] ^ 0x01);
        assertEquals(
                0,
                NativeCrypto.SLHDSA_SHA2_128S_prehash_verify(
                        digest, digest.length, modifiedSignature, hashNid, publicKey));

        byte[] modifiedDigest = digest.clone();
        modifiedDigest[0] = (byte) (modifiedDigest[0] ^ 0x01);
        assertEquals(
                0,
                NativeCrypto.SLHDSA_SHA2_128S_prehash_verify(
                        modifiedDigest, modifiedDigest.length, signature, hashNid, publicKey));

        int invalidDigestLen = digest.length + 1;
        assertThrows(
                RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_prehash_sign(digest, invalidDigestLen, hashNid, privateKey));
        assertThrows(
                RuntimeException.class,
                ()
                        -> NativeCrypto.SLHDSA_SHA2_128S_prehash_verify(
                                digest, invalidDigestLen, signature, hashNid, publicKey));

        byte[] privateKeyTooShort = Arrays.copyOf(privateKey, privateKey.length - 1);
        assertThrows(
                RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_prehash_sign(digest, digest.length, hashNid, privateKeyTooShort));

        byte[] privateKeyTooLong = Arrays.copyOf(privateKey, privateKey.length + 1);
        assertThrows(
                RuntimeException.class,
                () -> NativeCrypto.SLHDSA_SHA2_128S_prehash_sign(digest, digest.length, hashNid, privateKeyTooLong));

        byte[] publicKeyTooShort = Arrays.copyOf(publicKey, publicKey.length - 1);
        assertThrows(
                RuntimeException.class,
                ()
                        -> NativeCrypto.SLHDSA_SHA2_128S_prehash_verify(
                                digest, digest.length, signature, hashNid, publicKeyTooShort));

        byte[] publicKeyTooLong = Arrays.copyOf(publicKey, publicKey.length + 1);
        assertThrows(
                RuntimeException.class,
                ()
                        -> NativeCrypto.SLHDSA_SHA2_128S_prehash_verify(
                                digest, digest.length, signature, hashNid, publicKeyTooLong));
    }

    @Test
    public void x25519_testVector1FromRfc7748_works() throws Exception {
        // Test vector from RFC 7748, Section 6.1 (Alice's side)
        byte[] privateKey =
                decodeHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] expectedOutput =
                decodeHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        byte[] base = new byte[32];
        base[0] = 9;

        byte[] out = new byte[32];
        boolean success = NativeCrypto.X25519(out, privateKey, base);

        assertTrue(success);
        assertArrayEquals(expectedOutput, out);
    }

    @Test
    public void x25519_testVector2FromRfc7748_works() throws Exception {
        // Test vector from RFC 7748, Section 6.1 (Bob's side)
        byte[] privateKey =
                decodeHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] expectedOutput =
                decodeHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] base = new byte[32];
        base[0] = 9;

        byte[] out = new byte[32];
        boolean success = NativeCrypto.X25519(out, privateKey, base);

        assertTrue(success);
        assertArrayEquals(expectedOutput, out);
    }

    @Test
    public void x25519_invalidInputSize_throwsIllegalArgumentException() throws Exception {
        assertThrows(IllegalArgumentException.class,
                     () -> NativeCrypto.X25519(new byte[31], new byte[32], new byte[32]));

        assertThrows(IllegalArgumentException.class,
                     () -> NativeCrypto.X25519(new byte[32], new byte[31], new byte[32]));

        assertThrows(IllegalArgumentException.class,
                     () -> NativeCrypto.X25519(new byte[32], new byte[32], new byte[31]));
    }

    @Test
    public void x25519_nullInput_throwsIllegalArgumentException() throws Exception {
        assertThrows(NullPointerException.class,
                     () -> NativeCrypto.X25519(null, new byte[32], new byte[32]));

        assertThrows(NullPointerException.class,
                     () -> NativeCrypto.X25519(new byte[32], null, new byte[32]));

        assertThrows(NullPointerException.class,
                     () -> NativeCrypto.X25519(new byte[32], new byte[32], null));
    }
    @Test
    public void asn1_read_oid_raw_works() throws Exception {
        byte[] validOid = decodeHex("06082b06010505070627");
        long cbs = NativeCrypto.asn1_read_init(validOid);
        try {
            assertEquals("1.3.6.1.5.5.7.6.39", NativeCrypto.asn1_read_oid_raw(cbs));
        } finally {
            NativeCrypto.asn1_read_free(cbs);
        }
    }

    @Test
    public void asn1_read_oid_raw_wrongOidTag_throws() throws Exception {
        // OID tag byte 0x07 instead of 0x06.
        byte[] invalidTag = decodeHex("07082b06010505070627");
        long cbs = NativeCrypto.asn1_read_init(invalidTag);
        try {
            assertThrows(IOException.class, () -> NativeCrypto.asn1_read_oid_raw(cbs));
        } finally {
            NativeCrypto.asn1_read_free(cbs);
        }
    }

    @Test
    public void asn1_read_oid_raw_wrongOidLength_tooLong_throws() throws Exception {
        // OID length byte 0x13 instead of 0x08.
        byte[] invalidLong = decodeHex("06132b06010505070627");
        long cbs = NativeCrypto.asn1_read_init(invalidLong);
        try {
            assertThrows(IOException.class, () -> NativeCrypto.asn1_read_oid_raw(cbs));
        } finally {
            NativeCrypto.asn1_read_free(cbs);
        }
    }

    @Test
    public void asn1_read_oid_raw_wrongOidLength_tooShort_succeedsButLeavesData() throws Exception {
        // OID length byte 0x01 instead of 0x08.
        byte[] invalidShort = decodeHex("06012b06010505070627");
        long cbs = NativeCrypto.asn1_read_init(invalidShort);
        try {
            // "06 01 2b" successfully parses as OID "1.3", leaving the rest of the bytes.
            assertEquals("1.3", NativeCrypto.asn1_read_oid_raw(cbs));
            assertEquals(false, NativeCrypto.asn1_read_is_empty(cbs));
        } finally {
        }
    }
    @Test
    public void asn1_write_oid_raw_works() throws Exception {
        long cbb = NativeCrypto.asn1_write_init();
        try {
            NativeCrypto.asn1_write_oid_raw(cbb, "1.3.6.1.5.5.7.6.39");
            byte[] encoded = NativeCrypto.asn1_write_finish(cbb);
            cbb = 0;
            assertArrayEquals(decodeHex("06082b06010505070627"), encoded);
        } finally {
            if (cbb != 0) {
                NativeCrypto.asn1_write_free(cbb);
            }
        }
    }

    @Test
    public void asn1_write_oid_raw_invalidOid_throws() throws Exception {
        long cbb = NativeCrypto.asn1_write_init();
        try {
            assertThrows(IOException.class,
                         () -> NativeCrypto.asn1_write_oid_raw(cbb, "1.3.notanoid"));
        } finally {
            NativeCrypto.asn1_write_free(cbb);
        }
    }

    @Test
    public void asn1_write_bitstring_works() throws Exception {
        long cbb = NativeCrypto.asn1_write_init();
        try {
            NativeCrypto.asn1_write_bitstring(cbb, new byte[] {(byte) 0xaa});
            byte[] encoded = NativeCrypto.asn1_write_finish(cbb);
            cbb = 0;
            assertArrayEquals(decodeHex("030200aa"), encoded);
        } finally {
            if (cbb != 0) {
                NativeCrypto.asn1_write_free(cbb);
            }
        }
    }

    @Test
    public void asn1_read_bitstring_payload_works() throws Exception {
        byte[] bitString = decodeHex("030200aa"); // TAG 03, LEN 02, Padding 00, Payload aa
        long cbs = NativeCrypto.asn1_read_init(bitString);
        try {
            assertArrayEquals(new byte[] {(byte) 0xaa},
                              NativeCrypto.asn1_read_bitstring_payload(cbs, 0));
        } finally {
            NativeCrypto.asn1_read_free(cbs);
        }
    }

    @Test
    public void asn1_read_bitstring_payload_wrongTag_throws() throws Exception {
        byte[] invalidTag = decodeHex("040200aa"); // OCTET STRING 04 instead of BIT STRING 03
        long cbs = NativeCrypto.asn1_read_init(invalidTag);
        try {
            assertThrows(IOException.class, () -> NativeCrypto.asn1_read_bitstring_payload(cbs, 0));
        } finally {
            NativeCrypto.asn1_read_free(cbs);
        }
    }

    @Test
    public void asn1_read_bitstring_payload_wrongLength_throws() throws Exception {
        byte[] invalidLong = decodeHex("031300aa");
        long cbs = NativeCrypto.asn1_read_init(invalidLong);
        try {
            assertThrows(IOException.class, () -> NativeCrypto.asn1_read_bitstring_payload(cbs, 0));
        } finally {
            NativeCrypto.asn1_read_free(cbs);
        }
    }

    @Test
    public void asn1_read_bitstring_payload_wrongPadding_throws() throws Exception {
        // Encoded expects 0 padding, but the actual bytes specify 1 unused bit padding.
        byte[] invalidPadding = decodeHex("030201aa");
        long cbs = NativeCrypto.asn1_read_init(invalidPadding);
        try {
            assertThrows(IOException.class, () -> NativeCrypto.asn1_read_bitstring_payload(cbs, 0));
        } finally {
            NativeCrypto.asn1_read_free(cbs);
        }
    }

    @Test
    public void asn1_read_bitstring_payload_mismatchedExpectedPadding_throws() throws Exception {
        byte[] bitString = decodeHex("030200aa"); // Encoded padding is 0.
        long cbs = NativeCrypto.asn1_read_init(bitString);
        try {
            // But we tell the parser to explicitly expect padding 1.
            assertThrows(IOException.class, () -> NativeCrypto.asn1_read_bitstring_payload(cbs, 1));
        } finally {
            NativeCrypto.asn1_read_free(cbs);
        }
    }
}
