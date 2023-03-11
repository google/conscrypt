package org.conscrypt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import org.conscrypt.HpkeAlgorithmIdentifier.AEAD;
import org.conscrypt.HpkeAlgorithmIdentifier.KDF;
import org.conscrypt.HpkeAlgorithmIdentifier.KEM;
import org.conscrypt.HpkeAlgorithmIdentifier.KEM.SealedData;
import org.conscrypt.HpkeParameterSpec.Mode;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.Pair;

/**
 * Test OpenSSLCipherHpke
 */
@RunWith(JUnit4.class)
public class OpenSSLCipherHpkeTest {

    private static final byte[] DEFAULT_PRIVATE_KEY = TestUtils.decodeHex(
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    private static final byte[] DEFAULT_PUBLIC_KEY = TestUtils.decodeHex(
        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    private static final byte[] DEFAULT_ENC = TestUtils.decodeHex(
        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    private static final byte[] DEFAULT_IV = TestUtils.decodeHex(
        "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
    private static final byte[] DEFAULT_PSK = TestUtils.decodeHex(
        "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    private static final byte[] DEFAULT_PSK_ID = TestUtils.decodeHex(
        "456e6e796e20447572696e206172616e204d6f726961");
    private static final byte[] DEFAULT_AUTH_KEY = TestUtils.decodeHex(
        "fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4");
    private static final int DEFAULT_L = 32;
    private static final String ERROR_MESSAGE_INIT = "Cipher needs to be initialized";
    private static final String HPKE = "HPKE";

    @Test
    public void testEngineSetMode_anyParameter_throwException() {
        final List<String> modes = Arrays.asList(null, "", "base");
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();

        for (String mode : modes) {
            final NoSuchAlgorithmException e = assertThrows(
                NoSuchAlgorithmException.class,
                () -> openSSLCipherHpke.engineSetMode(mode));
            assertEquals("Mode " + mode + " not supported", e.getMessage());
        }
    }

    @Test
    public void testInvalidModes_encryptingNotMatchingCipher_throwException() {
        final List<HpkeParameterSpec> specs = new ArrayList<>();
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeBaseEncryption().build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modePskEncryption(DEFAULT_PSK, DEFAULT_PSK_ID).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthEncryption(DEFAULT_AUTH_KEY).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthPskEncryption(DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID)
            .build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeBaseSendExport(DEFAULT_L).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modePskSendExport(DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_L).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthSendExport(DEFAULT_AUTH_KEY, DEFAULT_L).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthPskSendExport(DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_L)
            .build());

        for (HpkeParameterSpec spec : specs) {
            final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
            assertThrows(
                IllegalStateException.class,
                () -> openSSLCipherHpke.engineInit(
                    Cipher.DECRYPT_MODE, buildDefaultPrivateKey(), spec, new SecureRandom()));
        }
    }

    @Test
    public void testInvalidModes_decryptingNotMatchingCipher_throwException() {
        final List<HpkeParameterSpec> specs = new ArrayList<>();
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeBaseDecryption(DEFAULT_ENC).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modePskDecryption(DEFAULT_ENC, DEFAULT_PSK, DEFAULT_PSK_ID).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthDecryption(DEFAULT_ENC, DEFAULT_AUTH_KEY).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthPskDecryption(DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID)
            .build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeBaseReceiveExport(DEFAULT_ENC, DEFAULT_L).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modePskReceiveExport(DEFAULT_ENC, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_L).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthReceiveExport(DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_L).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthPskReceiveExport(
                DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_L)
            .build());

        for (HpkeParameterSpec spec : specs) {
            final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
            assertThrows(
                IllegalStateException.class,
                () -> openSSLCipherHpke.engineInit(
                    Cipher.ENCRYPT_MODE, buildDefaultPublicKey(), spec, new SecureRandom()));
        }
    }

    @Test
    public void testInvalidModes_encryptingModesNotSupported_throwException() {
        final List<HpkeParameterSpec> specs = new ArrayList<>();
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modePskEncryption(DEFAULT_PSK, DEFAULT_PSK_ID).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthEncryption(DEFAULT_AUTH_KEY).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthPskEncryption(DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID)
            .build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modePskSendExport(DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_L).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthSendExport(DEFAULT_AUTH_KEY, DEFAULT_L).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthPskSendExport(DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_L)
            .build());

        for (HpkeParameterSpec spec : specs) {
            final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
            assertThrows(
                IllegalStateException.class,
                () -> openSSLCipherHpke.engineInit(
                    Cipher.ENCRYPT_MODE, buildDefaultPrivateKey(), spec, new SecureRandom()));
        }
    }

    @Test
    public void testInvalidModes_decryptingModesNotSupported_throwException() {
        final List<HpkeParameterSpec> specs = new ArrayList<>();
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modePskDecryption(DEFAULT_ENC, DEFAULT_PSK, DEFAULT_PSK_ID).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthDecryption(DEFAULT_ENC, DEFAULT_AUTH_KEY).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthPskDecryption(DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID)
            .build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modePskReceiveExport(DEFAULT_ENC, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_L).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthReceiveExport(DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_L).build());
        specs.add(new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeAuthPskReceiveExport(
                DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_L)
            .build());

        for (HpkeParameterSpec spec : specs) {
            final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
            assertThrows(
                IllegalStateException.class,
                () -> openSSLCipherHpke.engineInit(
                    Cipher.DECRYPT_MODE, buildDefaultPublicKey(), spec, new SecureRandom()));
        }
    }

    @Test
    public void testEngineSetPadding_anyParameter_throwException() {
        final List<String> paddings = Arrays.asList(null, "", "NoPadding");
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();

        for (String padding : paddings) {
            final NoSuchPaddingException e = assertThrows(
                NoSuchPaddingException.class,
                () -> openSSLCipherHpke.engineSetPadding(padding));
            assertEquals("Padding " + padding + " not supported", e.getMessage());
        }
    }

    @Test
    public void testEngineGetBlockSize_calledBeforeInitialization_throwException() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            openSSLCipherHpke::engineGetBlockSize);
        assertEquals(ERROR_MESSAGE_INIT, e.getMessage());
    }

    @Test
    public void testEngineGetBlockSize_validAeads_returnRespectiveBlockSize() throws Exception {
        final List<Pair<AEAD, Integer>> values = Arrays.asList(
            Pair.of(AEAD.AES_128_GCM, 16),
            Pair.of(AEAD.AES_256_GCM, 16),
            Pair.of(AEAD.CHACHA20POLY1305, 0));
        for (Pair<AEAD, Integer> value : values) {
            final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
            openSSLCipherHpke.engineInit(
                Cipher.ENCRYPT_MODE,
                buildDefaultPublicKey(),
                buildDefaultEncryptionSpecWithAead(value.getFirst()),
                new SecureRandom());
            assertEquals(value.getSecond().intValue(), openSSLCipherHpke.engineGetBlockSize());
        }
    }

    @Test
    public void testEngineGetOutputSize_EncryptionDecryption() throws Exception {
        final KEM supportedKem = KEM.DHKEM_X25519_HKDF_SHA256;
        final KDF supportedKdf = KDF.HKDF_SHA256;
        final List<AEAD> supportedAeads = Arrays.asList(AEAD.AES_128_GCM, AEAD.AES_256_GCM, AEAD.CHACHA20POLY1305);

        for (AEAD aead : supportedAeads) {
            final HpkeAlgorithmIdentifier algorithmIdentifier =
                new HpkeAlgorithmIdentifier(supportedKem, supportedKdf, aead);

            final OpenSSLCipherHpke encryptHpke = new OpenSSLCipherHpke();
            encryptHpke.engineInit(
                Cipher.ENCRYPT_MODE,
                buildDefaultPublicKey(),
                buildDefaultEncryptionSpecWithAead(aead),
                new SecureRandom());
            for (int i = 0 ; i < 1_000_000; i = i + 100_000) {
                final byte[] pt = new byte[i];
                final int expectedEncryptOutputSize = encryptHpke.engineGetOutputSize(pt.length);
                final byte[] encrypted = encryptHpke.engineDoFinal(pt, 0, pt.length);

                assertEquals(expectedEncryptOutputSize, encrypted.length);

                final SealedData sealedData = algorithmIdentifier.getKem().extract(encrypted);
                final byte[] enc = sealedData.getEnc();
                final byte[] ct = sealedData.getCt();

                final OpenSSLCipherHpke decryptHpke = new OpenSSLCipherHpke();
                decryptHpke.engineInit(
                    Cipher.DECRYPT_MODE,
                    buildDefaultPrivateKey(),
                    buildDefaultDecryptionSpecWithAead(aead, enc),
                    new SecureRandom());
                final int expectedDecryptOutputSize = decryptHpke.engineGetOutputSize(ct.length);
                final byte[] decrypted = decryptHpke.engineDoFinal(ct, 0, ct.length);

                assertEquals(expectedDecryptOutputSize, decrypted.length);
            }
        }
    }

    @Test
    public void testEngineGetOutputSize_SecretExports() throws Exception {
        final KEM supportedKem = KEM.DHKEM_X25519_HKDF_SHA256;
        final KDF supportedKdf = KDF.HKDF_SHA256;
        final List<AEAD> supportedAeads = Arrays.asList(AEAD.AES_128_GCM, AEAD.AES_256_GCM, AEAD.CHACHA20POLY1305);

        for (AEAD aead : supportedAeads) {
            final HpkeAlgorithmIdentifier algorithmIdentifier =
                new HpkeAlgorithmIdentifier(supportedKem, supportedKdf, aead);

            for (int i = 1; i < 1_000; i = i + 100) {
                final OpenSSLCipherHpke sendSecretExportHpke = new OpenSSLCipherHpke();
                sendSecretExportHpke.engineInit(
                    Cipher.ENCRYPT_MODE,
                    buildDefaultPublicKey(),
                    buildDefaultSendSecretExportSpecWithAead(aead, i),
                    new SecureRandom());


                final byte[] pt = new byte[i];
                final int expectedSendExportOutputSize = sendSecretExportHpke.engineGetOutputSize(pt.length);
                final byte[] sendExport = sendSecretExportHpke.engineDoFinal(pt, 0, pt.length);
                final SealedData sealedData = algorithmIdentifier.getKem().extract(sendExport);
                final byte[] enc = sealedData.getEnc();
                final byte[] ct = sealedData.getCt();

                assertEquals(expectedSendExportOutputSize, sendExport.length);
                assertEquals(i + enc.length, sendExport.length);

                final OpenSSLCipherHpke receiveSecretExportHpke = new OpenSSLCipherHpke();
                receiveSecretExportHpke.engineInit(
                    Cipher.DECRYPT_MODE,
                    buildDefaultPublicKey(),
                    buildDefaultReceiveSecretExportSpecWithAead(aead, enc, i),
                    new SecureRandom());
                final int expectedReceiveExportOutputSize = receiveSecretExportHpke.engineGetOutputSize(ct.length);
                final byte[] receiveExport = sendSecretExportHpke.engineDoFinal(ct, 0, ct.length);

                assertEquals(expectedReceiveExportOutputSize, receiveExport.length);
                assertEquals(i + enc.length, receiveExport.length);
            }
        }
    }

    @Test
    public void testEngineGetOutputSize_calledBeforeInitialization_throwException() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () -> openSSLCipherHpke.engineGetOutputSize(/* inputLen= */ 64));
        assertEquals(ERROR_MESSAGE_INIT, e.getMessage());
    }

    @Test
    public void testEngineGetOutputSize_exporting_returnL() throws Exception {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final HpkeParameterSpec spec = new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_256_GCM))
            .modeBaseSendExport(64).build();
        openSSLCipherHpke.engineInit(
            Cipher.ENCRYPT_MODE, buildDefaultPublicKey(), spec, new SecureRandom());
        final int anyInputLen = 0;
        final int expectedLen = 64 + KEM.DHKEM_X25519_HKDF_SHA256.getEncLength();
        assertEquals(expectedLen, openSSLCipherHpke.engineGetOutputSize(anyInputLen));
    }

    @Test
    public void testEngineGetOutputSize_encrypting_shouldReturnWithOverhead() throws Exception {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        openSSLCipherHpke.engineInit(
            Cipher.ENCRYPT_MODE,
            buildDefaultPublicKey(),
            buildDefaultEncryptionSpecWithAead(AEAD.AES_128_GCM),
            new SecureRandom());
        final int inputLen = 50;
        final int maxCtxOverhead = 16;
        final int expectedLen = inputLen + maxCtxOverhead +
            KEM.DHKEM_X25519_HKDF_SHA256.getEncLength();
        assertEquals(expectedLen, openSSLCipherHpke.engineGetOutputSize(inputLen));
    }

    @Test
    public void testEngineGetIv_calledBeforeInitialization_returnNull() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        assertNull(openSSLCipherHpke.engineGetIV());
    }

    @Test
    public void testEngineGetIv_passIv_returnSame() throws Exception {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final HpkeParameterSpec spec = new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.CHACHA20POLY1305))
            .iv(new byte[32])
            .modeBaseEncryption().build();
        openSSLCipherHpke.engineInit(
            Cipher.ENCRYPT_MODE, buildDefaultPublicKey(), spec, new SecureRandom());
        assertArrayEquals(new byte[32], openSSLCipherHpke.engineGetIV());
    }

    @Test
    public void testEngineGetIv_withoutIv_returnNull() throws Exception {
        final OpenSSLCipherHpke firstInstance = new OpenSSLCipherHpke();
        firstInstance.engineInit(
            Cipher.ENCRYPT_MODE,
            buildDefaultPublicKey(),
            buildDefaultEncryptionSpecWithAead(AEAD.AES_128_GCM),
            new SecureRandom());
        assertNull(firstInstance.engineGetIV());
    }

    @Test
    public void testEngineGetParameters_calledBeforeInitialization_returnNull() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        assertNull(openSSLCipherHpke.engineGetParameters());
    }

    @Test
    public void testEngineGetParameters_returnParamsPassedOnInitialization() throws Exception {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(
                /* algorithmIdentifier= */ new HpkeAlgorithmIdentifier(
                KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM),
                /* enc= */ DEFAULT_ENC,
                /* info= */ new byte[120],
                /* iv= */ DEFAULT_IV,
                /* L= */ 64,
                /* psk= */ null,
                /* pskId= */ null,
                /* authKey= */ null,
                Mode.BASE,
                /* encrypting= */ true,
                /* exporting= */ false)
                .build();
        openSSLCipherHpke.engineInit(
            Cipher.ENCRYPT_MODE, buildDefaultPublicKey(), spec, new SecureRandom());
        final HpkeParameterSpec specResult =
            openSSLCipherHpke.engineGetParameters().getParameterSpec(HpkeParameterSpec.class);
        assertEquals(spec.getAlgorithmIdentifier(), specResult.getAlgorithmIdentifier());
        assertArrayEquals(DEFAULT_ENC, specResult.getEnc());
        assertArrayEquals(new byte[120], specResult.getInfo());
        assertArrayEquals(DEFAULT_IV, specResult.getIv());
        assertEquals(64, specResult.getL());
    }

    @Test
    public void testEngineInit_doNotThrowException() throws Exception {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        openSSLCipherHpke.engineInit(
            Cipher.ENCRYPT_MODE,
            buildDefaultPublicKey(),
            buildDefaultEncryptionSpecWithAead(AEAD.CHACHA20POLY1305),
            new SecureRandom());
    }

    @Test
    public void testEngineInitWithSpec_invalidOpModes_throwException() {
        final List<Integer> opmodes = Arrays.asList(-1, 0, 3, 4, 5);
        for (Integer opmode : opmodes) {
            final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
            assertThrows(IllegalArgumentException.class,
                () ->
                    openSSLCipherHpke.engineInit(
                        opmode,
                        buildDefaultPublicKey(),
                        buildDefaultEncryptionSpecWithAead(AEAD.CHACHA20POLY1305),
                        new SecureRandom()));
        }
    }

    @Test
    public void testEngineInitWithSpec_invalidKeyType_throwException() throws Exception {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        final Key invalidKey = generator.generateKeyPair().getPublic();
        final InvalidKeyException e = assertThrows(InvalidKeyException.class,
            () ->
                openSSLCipherHpke.engineInit(
                    Cipher.ENCRYPT_MODE,
                    invalidKey,
                    buildDefaultEncryptionSpecWithAead(AEAD.CHACHA20POLY1305),
                    new SecureRandom()));
        assertEquals("Only SecretKey is supported", e.getMessage());
    }

    @Test
    public void testEngineInitWithSpec_invalidKeyIsNull_throwException() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final InvalidKeyException e = assertThrows(InvalidKeyException.class,
            () ->
                openSSLCipherHpke.engineInit(
                    Cipher.ENCRYPT_MODE,
                    /* key= */ null,
                    buildDefaultEncryptionSpecWithAead(AEAD.CHACHA20POLY1305),
                    new SecureRandom()));
        assertEquals("Only SecretKey is supported", e.getMessage());
    }

    @Test
    public void testEngineInitWithSpec_invalidKeyLength_throwException() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final Key invalidKey = new SecretKeySpec(new byte[31], HPKE);
        final InvalidKeyException e = assertThrows(InvalidKeyException.class,
            () ->
                openSSLCipherHpke.engineInit(
                    Cipher.ENCRYPT_MODE,
                    invalidKey,
                    buildDefaultEncryptionSpecWithAead(AEAD.CHACHA20POLY1305),
                    new SecureRandom()));
        assertEquals("Expected key length of 32 but was 31", e.getMessage());
    }

    @Test
    public void testEngineInitWithSpec_invalidKemSpec_throwException() {
        final List<KEM> invalidKems = Arrays.asList(
            KEM.DHKEM_P_256_HKDF_SHA256,
            KEM.DHKEM_P_384_HKDF_SHA384,
            KEM.DHKEM_P_521_HKDF_SHA512,
            KEM.DHKEM_X448_HKDF_SHA512);
        for (KEM kem : invalidKems) {
            final HpkeParameterSpec spec =
                new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
                    kem, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
                    .modeBaseEncryption().build();
            final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
            final InvalidAlgorithmParameterException e = assertThrows(
                InvalidAlgorithmParameterException.class,
                () ->
                    openSSLCipherHpke.engineInit(
                        Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[kem.getPkLength()], HPKE),
                        spec,
                        new SecureRandom()));
            assertEquals("KEM " + kem + " not supported", e.getMessage());
        }
    }

    @Test
    public void testEngineInitWithSpec_invalidKdfSpec_throwException() {
        final List<KDF> invalidKdfs = Arrays.asList(
            KDF.HKDF_SHA384,
            KDF.HKDF_SHA512);
        for (KDF kdf : invalidKdfs) {
            final HpkeParameterSpec spec =
                new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
                    KEM.DHKEM_X25519_HKDF_SHA256, kdf, AEAD.AES_128_GCM))
                    .modeBaseEncryption().build();
            final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
            final InvalidAlgorithmParameterException e = assertThrows(
                InvalidAlgorithmParameterException.class,
                () ->
                    openSSLCipherHpke.engineInit(
                        Cipher.ENCRYPT_MODE,
                        buildDefaultPublicKey(),
                        spec,
                        new SecureRandom()));
            assertEquals("KDF " + kdf + " not supported", e.getMessage());
        }
    }

    @Test
    public void testEngineInitWithSpec_invalidAeadSpec_throwException() {
        final List<AEAD> invalidAeads = Collections.singletonList(AEAD.EXPORT_ONLY_AEAD);
        for (AEAD aead : invalidAeads) {
            final HpkeParameterSpec spec =
                new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
                    KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, aead))
                    .modeBaseEncryption().build();
            final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
            final InvalidAlgorithmParameterException e = assertThrows(
                InvalidAlgorithmParameterException.class,
                () ->
                    openSSLCipherHpke.engineInit(
                        Cipher.ENCRYPT_MODE,
                        buildDefaultPublicKey(),
                        spec,
                        new SecureRandom()));
            assertEquals("AEAD " + aead + " not supported", e.getMessage());
        }
    }

    @Test
    public void testEngineInitWithParams_nullParams_noError() throws Exception {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        openSSLCipherHpke.engineInit(
            Cipher.ENCRYPT_MODE,
            buildDefaultPublicKey(),
            (AlgorithmParameters) null,
            new SecureRandom());
    }

    @Test
    public void testEngineUpdate_calledBeforeInitialization_throwException() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                openSSLCipherHpke.engineUpdate(
                    /* input= */ new byte[1],
                    /* inputOffset= */ 0,
                    /* inputLen= */ 1));
        assertEquals(ERROR_MESSAGE_INIT, e.getMessage());
    }

    @Test
    public void testEngineUpdateWithOutput_calledBeforeInitialization_throwException() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                openSSLCipherHpke.engineUpdate(
                    /* input= */ new byte[200],
                    /* inputOffset= */ 0,
                    /* inputLen= */ 200,
                    /* output= */ new byte[2000],
                    /* outputOffset= */ 0));
        assertEquals(ERROR_MESSAGE_INIT, e.getMessage());
    }

    @Test
    public void testEngineUpdateWithOutput_invalidOutput_throwException() throws Exception {
        final List<byte[]> invalidOutputs = Arrays.asList(null, new byte[100], new byte[200]);
        for (byte[] invalidOutput : invalidOutputs) {
            final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
            openSSLCipherHpke.engineInit(
                Cipher.ENCRYPT_MODE,
                buildDefaultPublicKey(),
                buildDefaultEncryptionSpecWithAead(AEAD.AES_128_GCM),
                new SecureRandom());
            final ShortBufferException e = assertThrows(
                ShortBufferException.class,
                () ->
                    openSSLCipherHpke.engineUpdate(
                        /* input= */ new byte[100],
                        /* inputOffset= */ 0,
                        /* inputLen= */ 100,
                        /* output= */ invalidOutput,
                        /* outputOffset= */ 100));
            assertEquals("Insufficient output space", e.getMessage());
        }
    }

    @Test
    public void testEngineDoFinal_calledBeforeInitialization_throwException() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> openSSLCipherHpke.engineDoFinal(
                /* input= */ new byte[5],/* inputOffset= */ 0,/* inputLen= */ 5));
        assertEquals(ERROR_MESSAGE_INIT, e.getMessage());
    }

    @Test
    public void testEngineDoFinal_nullInput_returnNull() throws Exception {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        openSSLCipherHpke.engineInit(
            Cipher.ENCRYPT_MODE,
            buildDefaultPublicKey(),
            buildDefaultEncryptionSpecWithAead(AEAD.AES_128_GCM),
            new SecureRandom());
        assertNull(openSSLCipherHpke.engineDoFinal(
            /* input= */ null,/* inputOffset= */ 0,/* inputLen= */ 5));
    }

    @Test
    public void testEngineDoFinalWithOutput_calledBeforeInitialization_throwException() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final IllegalStateException e = assertThrows(IllegalStateException.class,
            () ->
                openSSLCipherHpke.engineDoFinal(
                    /* input= */ new byte[100],
                    /* inputOffset= */ 0,
                    /* inputLen= */ 100,
                    /* output= */ new byte[1000],
                    /* outputOffset= */ 0));
        assertEquals(ERROR_MESSAGE_INIT, e.getMessage());
    }

    @Test
    public void testEngineDoFinal_nullInput_return0() throws Exception {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        openSSLCipherHpke.engineInit(
            Cipher.ENCRYPT_MODE,
            buildDefaultPublicKey(),
            buildDefaultEncryptionSpecWithAead(AEAD.AES_128_GCM),
            new SecureRandom());
        assertEquals(0, openSSLCipherHpke.engineDoFinal(
            /* input= */ null,
            /* inputOffset= */ 0,
            /* inputLen= */ 5,
            /* output= */ new byte[1],
            /* outputOffset= */ 0));
    }

    @Test
    public void testEngineUpdateAAD_calledBeforeInitialization_throwException() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final IllegalStateException e = assertThrows(IllegalStateException.class,
            () ->
                openSSLCipherHpke.engineUpdateAAD(
                    /* input= */ new byte[50],
                    /* inputOffset= */ 0,
                    /* inputLen= */ 50));
        assertEquals(ERROR_MESSAGE_INIT, e.getMessage());
    }

    @Test
    public void testEngineUpdateAADByteBuffer_calledBeforeInitialization_throwException() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> openSSLCipherHpke.engineUpdateAAD(ByteBuffer.allocate(10)));
        assertEquals(ERROR_MESSAGE_INIT, e.getMessage());
    }

    @Test
    public void testEngineGetKeySize() throws Exception {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final Key key = buildDefaultPublicKey();
        openSSLCipherHpke.engineInit(
            Cipher.ENCRYPT_MODE,
            key,
            buildDefaultEncryptionSpecWithAead(AEAD.AES_128_GCM),
            new SecureRandom());
        assertEquals(256, openSSLCipherHpke.engineGetKeySize(key));
    }

    @Test
    public void testEngineGetKeySize_calledBeforeInitialization_throwException() {
        final OpenSSLCipherHpke openSSLCipherHpke = new OpenSSLCipherHpke();
        final IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> openSSLCipherHpke.engineGetKeySize(buildDefaultPublicKey()));
        assertEquals(ERROR_MESSAGE_INIT, e.getMessage());
    }

    private Key buildDefaultPublicKey() {
        return new SecretKeySpec(DEFAULT_PUBLIC_KEY, HPKE);
    }

    private Key buildDefaultPrivateKey() {
        return new SecretKeySpec(DEFAULT_PRIVATE_KEY, HPKE);
    }

    private AlgorithmParameterSpec buildDefaultEncryptionSpecWithAead(AEAD aead) {
        return new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, aead))
            .modeBaseEncryption().build();
    }

    private AlgorithmParameterSpec buildDefaultDecryptionSpecWithAead(AEAD aead, byte[] enc) {
        return new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, aead))
            .modeBaseDecryption(enc).build();
    }

    private AlgorithmParameterSpec buildDefaultSendSecretExportSpecWithAead(AEAD aead, int l) {
        return new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, aead))
            .modeBaseSendExport(l).build();
    }

    private AlgorithmParameterSpec buildDefaultReceiveSecretExportSpecWithAead(AEAD aead, byte[] enc, int l) {
        return new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, aead))
            .modeBaseReceiveExport(enc, l).build();
    }
}
