package org.conscrypt.javax.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.conscrypt.HpkeAlgorithmIdentifier;
import org.conscrypt.HpkeAlgorithmIdentifier.AEAD;
import org.conscrypt.HpkeAlgorithmIdentifier.KDF;
import org.conscrypt.HpkeAlgorithmIdentifier.KEM;
import org.conscrypt.HpkeAlgorithmIdentifier.KEM.SealedData;
import org.conscrypt.HpkeParameterSpec;
import org.conscrypt.TestUtils;
import org.conscrypt.java.security.DefaultKeys;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test HPKE cryptographic operations
 */
@RunWith(JUnit4.class)
public class HpkeCipherTest {

    private static final String HPKE = "HPKE";
    private static final TestData VALID_TEST_DATA = new TestData(
        /* algorithmIdentifier= */ new HpkeAlgorithmIdentifier(
        KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.CHACHA20POLY1305),
        /* pk= */ TestUtils.decodeHex(
        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"),
        /* sk= */ TestUtils.decodeHex(
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"),
        /* iv= */ TestUtils.decodeHex(
        "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"),
        /* info= */ TestUtils.decodeHex("7368617265645f696e666f"),
        /* pt= */ TestUtils.decodeHex("436f6e736372797074"),
        /* encAndCt= */ TestUtils.decodeHex(
        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431935"
            + "f840c5d31bc6d266edd2310bd823c7ac1acf75832fad4d0")
    );

    @BeforeClass
    public static void setUp() {
        TestUtils.assumeAllowsUnsignedCrypto();
    }

    @Test
    public void testValidDecryption() throws Exception {
        final HpkeAlgorithmIdentifier algorithmIdentifier = VALID_TEST_DATA.algorithmIdentifier;
        final SealedData sealedData = KEM.DHKEM_X25519_HKDF_SHA256.extract(
            VALID_TEST_DATA.encAndCt);
        final byte[] enc = sealedData.getEnc();
        final byte[] info = VALID_TEST_DATA.info;

        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(algorithmIdentifier).modeBaseDecryption(enc).info(info)
                .build();
        final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
        params.init(spec);

        final byte[] secretKey = VALID_TEST_DATA.sk;
        final Cipher cipher = Cipher.getInstance(HPKE);
        cipher.init(Cipher.DECRYPT_MODE, createKey(secretKey), params);

        final byte[] ciphertext = sealedData.getCt();
        byte[] result = cipher.doFinal(ciphertext);

        final byte[] expectedPlaintext = VALID_TEST_DATA.pt;
        assertArrayEquals("Decrypted data is invalid", expectedPlaintext, result);
    }

    @Test
    public void testValidEncryption_withoutIv_generateRandomEncryptedResults() throws Exception {
        final HpkeAlgorithmIdentifier algorithmIdentifier = VALID_TEST_DATA.algorithmIdentifier;
        final byte[] info = VALID_TEST_DATA.info;
        final byte[] publicKey = VALID_TEST_DATA.pk;
        final byte[] plaintext = VALID_TEST_DATA.pt;
        final byte[] encAndCt = VALID_TEST_DATA.encAndCt;

        final AlgorithmParameterSpec spec = new HpkeParameterSpec.Builder(algorithmIdentifier)
            .modeBaseEncryption().info(info).build();
        final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
        params.init(spec);

        Cipher cipher = Cipher.getInstance(HPKE);
        cipher.init(Cipher.ENCRYPT_MODE, createKey(publicKey), params);

        byte[] result = cipher.doFinal(plaintext);
        final SealedData sealedData = algorithmIdentifier.getKem().extract(result);
        final String encResult = TestUtils.encodeHex(sealedData.getEnc());
        final String ctResult = TestUtils.encodeHex(sealedData.getCt());

        final SealedData expectedSealedData = algorithmIdentifier.getKem().extract(encAndCt);
        final String expectedEnc = TestUtils.encodeHex(expectedSealedData.getEnc());
        final String expectedCt = TestUtils.encodeHex(expectedSealedData.getCt());
        assertNotEquals("Encapsulated key is invalid", expectedEnc, encResult);
        assertNotEquals("Ciphertext is invalid", expectedCt, ctResult);

        cipher = Cipher.getInstance(HPKE);
        cipher.init(Cipher.ENCRYPT_MODE, createKey(publicKey), params);

        byte[] secondEncryptionResult = cipher.doFinal(plaintext);
        final SealedData secondSealedData = algorithmIdentifier.getKem()
            .extract(secondEncryptionResult);
        final String secondEncResult = TestUtils.encodeHex(secondSealedData.getEnc());
        final String secondCtResult = TestUtils.encodeHex(secondSealedData.getCt());
        assertNotEquals("Encapsulated key is invalid", encResult, secondEncResult);
        assertNotEquals("Ciphertext is invalid", ctResult, secondCtResult);
    }

    @Test
    public void testValidEncryption_withIv_generateExpectedResults() throws Exception {
        final HpkeAlgorithmIdentifier algorithmIdentifier = VALID_TEST_DATA.algorithmIdentifier;
        final byte[] iv = VALID_TEST_DATA.iv;
        final byte[] info = VALID_TEST_DATA.info;
        final byte[] publicKey = VALID_TEST_DATA.pk;
        final byte[] plaintext = VALID_TEST_DATA.pt;
        final byte[] encAndCt = VALID_TEST_DATA.encAndCt;

        final AlgorithmParameterSpec spec = new HpkeParameterSpec.Builder(algorithmIdentifier)
            .modeBaseEncryption().info(info).iv(iv).build();
        final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
        params.init(spec);

        Cipher cipher = Cipher.getInstance(HPKE);
        cipher.init(Cipher.ENCRYPT_MODE, createKey(publicKey), params);

        byte[] result = cipher.doFinal(plaintext);
        final SealedData sealedData = algorithmIdentifier.getKem().extract(result);
        final byte[] encResult = sealedData.getEnc();
        final byte[] ctResult = sealedData.getCt();

        final SealedData expectedSealedData = algorithmIdentifier.getKem().extract(encAndCt);
        final byte[] expectedEnc = expectedSealedData.getEnc();
        final byte[] expectedCt = expectedSealedData.getCt();
        assertArrayEquals("Encapsulated key is invalid", expectedEnc, encResult);
        assertArrayEquals("Ciphertext is invalid", expectedCt, ctResult);
    }

    @Test
    public void testValidTransformation_withDefault_noExceptionsThrown() throws Exception {
        List<String> validTransformations =
            Arrays.asList("HPKE", "hpke");

        for (String transformation : validTransformations) {
            Cipher.getInstance(transformation);
        }
    }

    @Test
    public void testInvalidTransformation_throwException() {
        assertThrows(
            NoSuchAlgorithmException.class,
            () -> Cipher.getInstance("HPKE/BASE/NoPadding"));
    }

    @Test
    public void testGetParameters_callBeforeBeingInitialized_returnNull() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameters parameters = cipher.getParameters();
        assertNull(parameters);
    }

    @Test
    public void testGetParameters_initializedWithNoParameters_returnDefaults() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        cipher.init(Cipher.ENCRYPT_MODE, createKey(VALID_TEST_DATA.pk));

        final AlgorithmParameters parameters = cipher.getParameters();

        assertNotNull(parameters);
        final HpkeParameterSpec actualSpec = parameters.getParameterSpec(HpkeParameterSpec.class);
        final HpkeParameterSpec defaultSpec = HpkeParameterSpec.DEFAULT_ENCRYPTION;
        final HpkeAlgorithmIdentifier defaultAlgorithm = defaultSpec.getAlgorithmIdentifier();
        assertEquals(defaultAlgorithm.getKem(), actualSpec.getAlgorithmIdentifier().getKem());
        assertEquals(defaultAlgorithm.getKdf(), actualSpec.getAlgorithmIdentifier().getKdf());
        assertEquals(defaultAlgorithm.getAead(), actualSpec.getAlgorithmIdentifier().getAead());
    }

    @Test
    public void testGetParameters_initializedWithParameterSpec_returnSame() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final HpkeAlgorithmIdentifier algorithmIdentifier = new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_256_GCM);
        final HpkeParameterSpec hpkeParameterSpec = new HpkeParameterSpec.Builder(
            algorithmIdentifier)
            .modeBaseEncryption().info(VALID_TEST_DATA.info).build();

        cipher.init(Cipher.ENCRYPT_MODE, createKey(VALID_TEST_DATA.pk), hpkeParameterSpec);

        final AlgorithmParameters parameters = cipher.getParameters();

        assertNotNull(parameters);
        final HpkeParameterSpec actualSpec = parameters.getParameterSpec(HpkeParameterSpec.class);
        assertEquals(algorithmIdentifier.getKem(), actualSpec.getAlgorithmIdentifier().getKem());
        assertEquals(algorithmIdentifier.getKdf(), actualSpec.getAlgorithmIdentifier().getKdf());
        assertEquals(algorithmIdentifier.getAead(), actualSpec.getAlgorithmIdentifier().getAead());
    }

    @Test
    public void testInit_validParameters_noErrors() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final Key key = createKey(VALID_TEST_DATA.pk);
        assertTrue(key instanceof SecretKeySpec);
        assertEquals(VALID_TEST_DATA.algorithmIdentifier.getKem().getPkLength(),
            key.getEncoded().length);
        cipher.init(Cipher.ENCRYPT_MODE, key);
    }

    @Test
    public void testInit_withWrapOpMode_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () -> cipher.init(Cipher.WRAP_MODE, createKey(VALID_TEST_DATA.pk)));

        assertEquals("Only default encryption mode supported", e.getMessage());
    }

    @Test
    public void testInit_withUnwrapOpMode_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () -> cipher.init(Cipher.UNWRAP_MODE, createKey(VALID_TEST_DATA.pk)));

        assertEquals("Only default encryption mode supported", e.getMessage());
    }

    @Test
    public void testInit_withUnknownOpMode_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> cipher.init(5, createKey(VALID_TEST_DATA.pk)));

        assertEquals("Invalid operation mode", e.getMessage());
    }

    @Test
    public void testInit_noKey_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        assertThrows(
            InvalidKeyException.class,
            () -> cipher.init(Cipher.ENCRYPT_MODE, (Key) null));
    }

    @Test
    public void testInit_keyNotInstanceOfSecretKey_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        final Key key = generator.generateKeyPair().getPublic();
        assertThrows(
            InvalidKeyException.class,
            () -> cipher.init(Cipher.ENCRYPT_MODE, key));
    }

    @Test
    public void testInit_keyInvalidLength_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final byte[] encoded = DefaultKeys.getPublicKey("XDH").getEncoded();
        final Key key = new SecretKeySpec(encoded, "XDH");
        assertEquals(44, key.getEncoded().length);
        final InvalidKeyException e = assertThrows(InvalidKeyException.class,
            () -> cipher.init(Cipher.ENCRYPT_MODE, key));
        assertEquals("Expected key length of 32 but was 44", e.getMessage());
    }

    @Test
    public void testInitWithParameterSpec_validParameters_noErrors() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec spec =
            new HpkeParameterSpec.Builder(VALID_TEST_DATA.algorithmIdentifier)
                .modeBaseEncryption().build();
        final Key key = createKey(VALID_TEST_DATA.pk);
        assertTrue(key instanceof SecretKeySpec);
        assertEquals(32, key.getEncoded().length);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    }

    @Test
    public void testInitWithParameterSpec_withWrapOpMode_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec spec =
            new HpkeParameterSpec.Builder(VALID_TEST_DATA.algorithmIdentifier)
                .modeBaseEncryption().build();
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> cipher.init(Cipher.WRAP_MODE, createKey(VALID_TEST_DATA.pk), spec));

        assertEquals("Opmode 3 not supported", e.getMessage());
    }

    @Test
    public void testInitWithParameterSpec_withUnwrapOpMode_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec spec =
            new HpkeParameterSpec.Builder(VALID_TEST_DATA.algorithmIdentifier)
                .modeBaseEncryption().build();
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> cipher.init(Cipher.UNWRAP_MODE, createKey(VALID_TEST_DATA.sk), spec));

        assertEquals("Opmode 4 not supported", e.getMessage());
    }

    @Test
    public void testInitWithParameterSpec_withUnknownOpMode_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec spec =
            new HpkeParameterSpec.Builder(VALID_TEST_DATA.algorithmIdentifier)
                .modeBaseEncryption().build();
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> cipher.init(5, createKey(VALID_TEST_DATA.sk), spec));

        assertEquals("Invalid operation mode", e.getMessage());
    }

    @Test
    public void testInitWithParameterSpec_noKey_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec parameterSpec =
            new HpkeParameterSpec.Builder(VALID_TEST_DATA.algorithmIdentifier)
                .modeBaseEncryption().build();
        assertThrows(InvalidKeyException.class,
            () -> cipher.init(Cipher.ENCRYPT_MODE, null, parameterSpec));
    }

    @Test
    public void testInitWithParameterSpec_keyNotInstanceOfSecretKey_throwException()
        throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec parameterSpec =
            new HpkeParameterSpec.Builder(VALID_TEST_DATA.algorithmIdentifier)
                .modeBaseEncryption().build();
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        final Key key = generator.generateKeyPair().getPublic();
        assertThrows(InvalidKeyException.class,
            () -> cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec));
    }

    @Test
    public void testInitWithParameterSpec_keyInvalidLength_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final byte[] encoded = DefaultKeys.getPublicKey("XDH").getEncoded();
        final Key key = new SecretKeySpec(encoded, "XDH");
        assertEquals(44, key.getEncoded().length);
        final HpkeParameterSpec spec = new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeBaseEncryption().build();
        assertEquals(32, spec.getAlgorithmIdentifier().getKem().getPkLength());
        final InvalidKeyException e = assertThrows(InvalidKeyException.class,
            () -> cipher.init(Cipher.ENCRYPT_MODE, key, spec));
        assertEquals("Expected key length of 32 but was 44", e.getMessage());
    }

    @Test
    public void testInitWithParameterSpec_invalidParameterSpec_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec parameterSpec = new GCMParameterSpec(1, new byte[0]);
        final Key key = createKey(VALID_TEST_DATA.pk);
        final InvalidAlgorithmParameterException e = assertThrows(
            InvalidAlgorithmParameterException.class,
            () -> cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec));

        assertEquals("Only HpkeParameterSpec supported", e.getMessage());
    }

    @Test
    public void testInitWithParameterSpec_NoParameterSpec_noError() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final Key key = createKey(VALID_TEST_DATA.pk);
        cipher.init(Cipher.ENCRYPT_MODE, key, (AlgorithmParameterSpec) null);
    }

    @Test
    public void testInitWithParameters_validParameters_noErrors() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec parameterSpec = getDefaultAlgorithmParameterSpec();
        final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
        params.init(parameterSpec);
        final Key key = createKey(VALID_TEST_DATA.pk);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
    }

    @Test
    public void testInitWithParameters_withWrapOpMode_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec parameterSpec = getDefaultAlgorithmParameterSpec();
        final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
        params.init(parameterSpec);
        final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> cipher.init(Cipher.WRAP_MODE, createKey(VALID_TEST_DATA.pk), params));

        assertEquals("Opmode 3 not supported", e.getMessage());
    }

    @Test
    public void testInitWithParameters_withUnwrapOpMode_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec parameterSpec = getDefaultAlgorithmParameterSpec();
        final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
        params.init(parameterSpec);
        final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> cipher.init(Cipher.UNWRAP_MODE, createKey(VALID_TEST_DATA.pk), params));

        assertEquals("Opmode 4 not supported", e.getMessage());
    }

    @Test
    public void testInitWithParameters_withUnknownOpMode_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec parameterSpec = getDefaultAlgorithmParameterSpec();
        final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
        params.init(parameterSpec);
        final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> cipher.init(5, createKey(VALID_TEST_DATA.pk), params));

        assertEquals("Invalid operation mode", e.getMessage());
    }

    @Test
    public void testInitWithParameters_noKey_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec parameterSpec = getDefaultAlgorithmParameterSpec();
        final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
        params.init(parameterSpec);
        assertThrows(InvalidKeyException.class,
            () -> cipher.init(Cipher.ENCRYPT_MODE, null, params));
    }

    @Test
    public void testInitWithParameters_keyNotInstanceOfSecretKey_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec parameterSpec = getDefaultAlgorithmParameterSpec();
        final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
        params.init(parameterSpec);
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        final Key key = generator.generateKeyPair().getPublic();
        assertThrows(InvalidKeyException.class,
            () -> cipher.init(Cipher.ENCRYPT_MODE, key, params));
    }

    @Test
    public void testInitWithParameters_keyInvalidLength_throwException() throws Exception {
        final Cipher cipher = Cipher.getInstance(HPKE);
        final AlgorithmParameterSpec parameterSpec = getDefaultAlgorithmParameterSpec();
        final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
        params.init(parameterSpec);
        final byte[] encoded = DefaultKeys.getPublicKey("XDH").getEncoded();
        final Key key = new SecretKeySpec(encoded, "XDH");
        assertEquals(44, key.getEncoded().length);
        assertThrows(InvalidKeyException.class,
            () -> cipher.init(Cipher.ENCRYPT_MODE, key, params));
    }

    @Test
    public void testInitWithParameters_invalidParameterSpec_throwException() throws Exception {
        final AlgorithmParameterSpec parameterSpec = new GCMParameterSpec(1, new byte[0]);
        final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
        final InvalidParameterSpecException e = assertThrows(
            InvalidParameterSpecException.class,
            () -> params.init(parameterSpec));

        assertEquals("Only HpkeParametersSpec is supported", e.getMessage());
    }

    @Test
    public void testInitWithParameters_NoParameterSpec_throwException() throws Exception {
        final AlgorithmParameters params = AlgorithmParameters.getInstance(HPKE);
        final InvalidParameterSpecException e = assertThrows(
            InvalidParameterSpecException.class,
            () -> params.init((AlgorithmParameterSpec) null));

        assertEquals("Only HpkeParametersSpec is supported", e.getMessage());
    }

    @Test
    public void testUpdateAAD_callBothUpdateAAD_aadShouldAppendValue() throws Exception {
        final AlgorithmParameterSpec spec =
            new HpkeParameterSpec.Builder(VALID_TEST_DATA.algorithmIdentifier)
                .modeBaseEncryption().iv(VALID_TEST_DATA.iv).build();

        Cipher cipher = Cipher.getInstance(HPKE);
        cipher.init(Cipher.ENCRYPT_MODE, createKey(VALID_TEST_DATA.pk), spec);
        cipher.updateAAD(new byte[8]);
        cipher.updateAAD(ByteBuffer.wrap(new byte[8]));

        byte[] result = cipher.doFinal(VALID_TEST_DATA.pt);
        final SealedData sealedData = VALID_TEST_DATA.algorithmIdentifier.getKem().extract(result);
        final byte[] encResult = sealedData.getEnc();
        final byte[] ctResult = sealedData.getCt();
        assertEquals(
            "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
            TestUtils.encodeHex(encResult));
        assertEquals("be706059bec66d05e01d1f49ba93e4a000591a1e6b11831d92",
            TestUtils.encodeHex(ctResult));
    }

    @Test
    public void testUpdateAAD_calledTwice_aadShouldAppendValue() throws Exception {
        final AlgorithmParameterSpec spec =
            new HpkeParameterSpec.Builder(VALID_TEST_DATA.algorithmIdentifier)
                .modeBaseEncryption().iv(VALID_TEST_DATA.iv).build();

        Cipher c1 = Cipher.getInstance(HPKE);
        c1.init(Cipher.ENCRYPT_MODE, createKey(VALID_TEST_DATA.pk), spec);
        c1.updateAAD(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05});
        c1.updateAAD(new byte[]{0x06, 0x07, 0x08, 0x09, 0x10});

        Cipher c2 = Cipher.getInstance(HPKE);
        c2.init(Cipher.ENCRYPT_MODE, createKey(VALID_TEST_DATA.pk), spec);
        c2.updateAAD(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10});

        assertEquals(Arrays.toString(c1.doFinal()), Arrays.toString(c2.doFinal()));
    }

    @Test
    public void testUpdateAAD_ByteBuffer() throws Exception {
        final AlgorithmParameterSpec spec =
            new HpkeParameterSpec.Builder(VALID_TEST_DATA.algorithmIdentifier)
                .modeBaseEncryption().iv(VALID_TEST_DATA.iv).build();

        Cipher c1 = Cipher.getInstance(HPKE);
        c1.init(Cipher.ENCRYPT_MODE, createKey(VALID_TEST_DATA.pk), spec);
        c1.updateAAD(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05});

        Cipher c2 = Cipher.getInstance(HPKE);
        c2.init(Cipher.ENCRYPT_MODE, createKey(VALID_TEST_DATA.pk), spec);
        c2.updateAAD(ByteBuffer.wrap(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05}));

        Cipher c3 = Cipher.getInstance(HPKE);
        c3.init(Cipher.ENCRYPT_MODE, createKey(VALID_TEST_DATA.pk), spec);
        ByteBuffer buf = ByteBuffer.allocateDirect(5);
        buf.put(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05});
        buf.flip();
        c3.updateAAD(buf);

        byte[] c1Final = c1.doFinal();
        byte[] c2Final = c2.doFinal();
        byte[] c3Final = c3.doFinal();
        assertEquals(Arrays.toString(c1Final), Arrays.toString(c2Final));
        assertEquals(Arrays.toString(c1Final), Arrays.toString(c3Final));
    }

    private Key createKey(byte[] key) {
        return new SecretKeySpec(key, HPKE);
    }

    private AlgorithmParameterSpec getDefaultAlgorithmParameterSpec() {
        return new HpkeParameterSpec.Builder(new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeBaseEncryption().build();
    }

    private static class TestData {

        private final HpkeAlgorithmIdentifier algorithmIdentifier;
        private final byte[] pk;
        private final byte[] sk;
        private final byte[] iv;
        private final byte[] info;
        private final byte[] pt;
        private final byte[] encAndCt;

        TestData(HpkeAlgorithmIdentifier algorithmIdentifier, byte[] pk, byte[] sk, byte[] iv,
            byte[] info, byte[] pt, byte[] encAndCt) {
            this.algorithmIdentifier = algorithmIdentifier;
            this.pk = pk;
            this.sk = sk;
            this.iv = iv;
            this.info = info;
            this.pt = pt;
            this.encAndCt = encAndCt;
        }
    }
}
