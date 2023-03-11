package org.conscrypt;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import org.conscrypt.HpkeAlgorithmIdentifier.AEAD;
import org.conscrypt.HpkeAlgorithmIdentifier.KDF;
import org.conscrypt.HpkeAlgorithmIdentifier.KEM;
import org.conscrypt.HpkeParameterSpec.Mode;
import org.junit.Test;

public class HpkeParameterSpecTest {

    private static final List<HpkeAlgorithmIdentifier> ALL_ALGORITHM_IDENTIFIERS;
    private static final HpkeAlgorithmIdentifier DEFAULT_ALGORITHM_IDENTIFIER =
        new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM);
    private static final byte[] DEFAULT_ENC =
        TestUtils.decodeHex("820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c");
    private static final byte[] DEFAULT_INFO =
        TestUtils.decodeHex("4f6465206f6e2061204772656369616e2055726e");
    private static final byte[] DEFAULT_IV =
        TestUtils.decodeHex("14de82a5897b613616a00c39b87429df35bc2b426bcfd73febcb45e903490768");
    private static final byte[] DEFAULT_PSK =
        TestUtils.decodeHex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    private static final byte[] DEFAULT_PSK_ID =
        TestUtils.decodeHex("456e6e796e20447572696e206172616e204d6f726961");
    private static final byte[] DEFAULT_AUTH_KEY =
        TestUtils.decodeHex("fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4");
    private static final int DEFAULT_EXPORT_L = 32;
    private static final int DEFAULT_NO_EXPORT_L = 0;

    static {
        ALL_ALGORITHM_IDENTIFIERS = new ArrayList<>();
        ALL_ALGORITHM_IDENTIFIERS.add(
            new HpkeAlgorithmIdentifier(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256,
                AEAD.AES_128_GCM));
        ALL_ALGORITHM_IDENTIFIERS.add(
            new HpkeAlgorithmIdentifier(KEM.DHKEM_P_256_HKDF_SHA256, KDF.HKDF_SHA256,
                AEAD.AES_128_GCM));
        ALL_ALGORITHM_IDENTIFIERS.add(
            new HpkeAlgorithmIdentifier(KEM.DHKEM_P_384_HKDF_SHA384, KDF.HKDF_SHA256,
                AEAD.AES_128_GCM));
        ALL_ALGORITHM_IDENTIFIERS.add(
            new HpkeAlgorithmIdentifier(KEM.DHKEM_P_521_HKDF_SHA512, KDF.HKDF_SHA256,
                AEAD.AES_128_GCM));
        ALL_ALGORITHM_IDENTIFIERS.add(
            new HpkeAlgorithmIdentifier(KEM.DHKEM_X448_HKDF_SHA512, KDF.HKDF_SHA256,
                AEAD.AES_128_GCM));
    }

    @Test
    public void testInternalConstructor() {
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER, DEFAULT_ENC, DEFAULT_INFO,
                DEFAULT_IV, DEFAULT_EXPORT_L, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_AUTH_KEY,
                Mode.BASE, /* encrypting= */ true, /* exporting= */ false)
                .build();

        assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
        assertArrayEquals(DEFAULT_ENC, spec.getEnc());
        assertArrayEquals(DEFAULT_INFO, spec.getInfo());
        assertArrayEquals(DEFAULT_IV, spec.getIv());
        assertArrayEquals(DEFAULT_PSK, spec.getPsk());
        assertArrayEquals(DEFAULT_PSK_ID, spec.getPskId());
        assertArrayEquals(DEFAULT_AUTH_KEY, spec.getAuthKey());
        assertEquals(DEFAULT_EXPORT_L, spec.getL());
    }

    @Test
    public void testModeBaseEncryption() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final HpkeParameterSpec spec =
                new HpkeParameterSpec.Builder(identifier)
                    .modeBaseEncryption()
                    .build();

            assertEquals(identifier, spec.getAlgorithmIdentifier());
            assertNull(spec.getEnc());
            assertNull(spec.getInfo());
            assertNull(spec.getIv());
            assertNull(spec.getPsk());
            assertNull(spec.getPskId());
            assertNull(spec.getAuthKey());
            assertEquals(DEFAULT_NO_EXPORT_L, spec.getL());
            assertFalse(spec.isExporting());
            assertTrue(spec.isEncrypting());
            assertEquals(Mode.BASE, spec.getMode());
        }
    }

    @Test
    public void testModeBaseEncryption_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeBaseEncryption()
                    .modeBaseEncryption());

        assertInitializationError(e);
    }

    @Test
    public void testModeBaseDecryption() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final HpkeParameterSpec spec =
                new HpkeParameterSpec.Builder(identifier)
                    .modeBaseDecryption(new byte[identifier.getKem().getEncLength()])
                    .build();

            assertEquals(identifier, spec.getAlgorithmIdentifier());
            assertArrayEquals(new byte[identifier.getKem().getEncLength()], spec.getEnc());
            assertNull(spec.getInfo());
            assertNull(spec.getIv());
            assertNull(spec.getPsk());
            assertNull(spec.getPskId());
            assertNull(spec.getAuthKey());
            assertEquals(DEFAULT_NO_EXPORT_L, spec.getL());
            assertFalse(spec.isExporting());
            assertFalse(spec.isEncrypting());
            assertEquals(Mode.BASE, spec.getMode());
        }
    }

    @Test
    public void testModeBaseDecryption_parameterEncIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeBaseDecryption(/* enc= */ null));
    }

    @Test
    public void testModeBaseDecryption_parameterEncHasInvalidLength_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final byte[] invalidLowerEdge = new byte[identifier.getKem().getEncLength() - 1];
            final byte[] invalidUpperEdge = new byte[identifier.getKem().getEncLength() + 1];
            final IllegalArgumentException eL = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeBaseDecryption(invalidLowerEdge));
            final IllegalArgumentException eU = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeBaseDecryption(invalidUpperEdge));

            assertEncError(eL, identifier.getKem().getEncLength(), invalidLowerEdge.length);
            assertEncError(eU, identifier.getKem().getEncLength(), invalidUpperEdge.length);
        }
    }

    @Test
    public void testModeBaseDecryption_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeBaseDecryption(DEFAULT_ENC)
                    .modeBaseDecryption(DEFAULT_ENC));

        assertInitializationError(e);
    }

    @Test
    public void testModeBaseSendExport() {
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modeBaseSendExport(DEFAULT_EXPORT_L)
                .build();

        assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
        assertNull(spec.getEnc());
        assertNull(spec.getInfo());
        assertNull(spec.getIv());
        assertNull(spec.getPsk());
        assertNull(spec.getPskId());
        assertNull(spec.getAuthKey());
        assertEquals(DEFAULT_EXPORT_L, spec.getL());
        assertTrue(spec.isExporting());
        assertTrue(spec.isEncrypting());
        assertEquals(Mode.BASE, spec.getMode());
    }

    @Test
    public void testModeBaseSendExport_parameterLHasInvalidLength_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final int upperLimitLength = identifier.getKdf().getHLength() * 255;
            final IllegalArgumentException eU = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeBaseSendExport(/* l= */ upperLimitLength + 1));
            assertLError(eU, upperLimitLength, upperLimitLength + 1);

            final IllegalArgumentException eL = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeBaseSendExport(/* l= */ 0));
            assertLError(eL, upperLimitLength, 0);
        }
    }

    @Test
    public void testModeBaseSendExport_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeBaseSendExport(DEFAULT_EXPORT_L)
                    .modeBaseSendExport(DEFAULT_EXPORT_L));

        assertInitializationError(e);
    }

    @Test
    public void testModeBaseReceiveExport() {
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modeBaseReceiveExport(DEFAULT_ENC, DEFAULT_EXPORT_L)
                .build();

        assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
        assertArrayEquals(DEFAULT_ENC, spec.getEnc());
        assertNull(spec.getInfo());
        assertNull(spec.getIv());
        assertNull(spec.getPsk());
        assertNull(spec.getPskId());
        assertNull(spec.getAuthKey());
        assertEquals(DEFAULT_EXPORT_L, spec.getL());
        assertTrue(spec.isExporting());
        assertFalse(spec.isEncrypting());
        assertEquals(Mode.BASE, spec.getMode());
    }

    @Test
    public void testModeBaseReceiveExport_parameterEncIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeBaseReceiveExport(/* enc= */ null, DEFAULT_EXPORT_L));
    }

    @Test
    public void testModeBaseReceiveExport_parameterEncHasInvalidLength_throwException() {
        final byte[] invalidEnc =
            new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeBaseReceiveExport(invalidEnc, DEFAULT_EXPORT_L));

        assertEncError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength(), invalidEnc.length);
    }

    @Test
    public void testModeBaseReceiveExport_parameterLHasInvalidLength_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final int upperLimitLength = identifier.getKdf().getHLength() * 255;
            final IllegalArgumentException eU = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeBaseReceiveExport(
                            /* enc= */ new byte[identifier.getKem().getEncLength()],
                            /* l= */ upperLimitLength + 1));
            assertLError(eU, upperLimitLength, upperLimitLength + 1);

            final IllegalArgumentException eL = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeBaseReceiveExport(
                            /* enc= */new byte[identifier.getKem().getEncLength()],
                            /* l= */ 0));
            assertLError(eL, upperLimitLength, 0);
        }
    }

    @Test
    public void testModeBaseReceiveExport_alreadyInitialized_throwError() {
        IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeBaseReceiveExport(DEFAULT_ENC, DEFAULT_EXPORT_L)
                    .modeBaseReceiveExport(DEFAULT_ENC, DEFAULT_EXPORT_L));

        assertInitializationError(e);
    }

    @Test
    public void testModePskEncryption() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final HpkeParameterSpec spec =
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskEncryption(
                        /* psk= */ new byte[identifier.getKdf().getHLength()],
                        DEFAULT_PSK_ID)
                    .build();

            assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
            assertNull(spec.getEnc());
            assertNull(spec.getInfo());
            assertNull(spec.getIv());
            assertArrayEquals(new byte[identifier.getKdf().getHLength()], spec.getPsk());
            assertArrayEquals(DEFAULT_PSK_ID, spec.getPskId());
            assertNull(spec.getAuthKey());
            assertEquals(DEFAULT_NO_EXPORT_L, spec.getL());
            assertFalse(spec.isExporting());
            assertTrue(spec.isEncrypting());
            assertEquals(Mode.PSK, spec.getMode());
        }
    }

    @Test
    public void testModePskEncryption_parameterPskIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskEncryption(/* psk= */ null, DEFAULT_PSK_ID));
    }

    @Test
    public void testModePskEncryption_parameterPskIdIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskEncryption(DEFAULT_PSK, /* pskId= */ null));
    }

    @Test
    public void testModePskEncryption_parameterPskEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskEncryption(/* psk= */ new byte[0], DEFAULT_PSK_ID));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModePskEncryption_parameterPskIdEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskEncryption(DEFAULT_PSK, /* pskId= */ new byte[0]));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModePskEncryption_parameterPskHasInvalidLength_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final int hLength = identifier.getKdf().getHLength();
            final IllegalArgumentException eL = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                        .modePskEncryption(/* psk= */ new byte[hLength - 1], DEFAULT_PSK_ID));

            assertPskLengthError(eL, hLength);
        }
    }

    @Test
    public void testModePskEncryption_alreadyInitialized_throwError() {
        IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskEncryption(DEFAULT_PSK, DEFAULT_PSK_ID)
                    .modePskEncryption(DEFAULT_PSK, DEFAULT_PSK_ID));

        assertInitializationError(e);
    }

    @Test
    public void testModePskDecryption() {
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modePskDecryption(DEFAULT_ENC, DEFAULT_PSK, DEFAULT_PSK_ID)
                .build();

        assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
        assertArrayEquals(DEFAULT_ENC, spec.getEnc());
        assertNull(spec.getInfo());
        assertNull(spec.getIv());
        assertArrayEquals(DEFAULT_PSK, spec.getPsk());
        assertArrayEquals(DEFAULT_PSK_ID, spec.getPskId());
        assertNull(spec.getAuthKey());
        assertEquals(DEFAULT_NO_EXPORT_L, spec.getL());
        assertFalse(spec.isExporting());
        assertFalse(spec.isEncrypting());
        assertEquals(Mode.PSK, spec.getMode());
    }

    @Test
    public void testModePskDecryption_parameterEncIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskDecryption(/* enc= */ null, DEFAULT_PSK, DEFAULT_PSK_ID));
    }

    @Test
    public void testModePskDecryption_parameterEncHasInvalidLength_throwException() {
        final byte[] invalidEnc =
            new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskDecryption(invalidEnc, DEFAULT_PSK, DEFAULT_PSK_ID));

        assertEncError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength(), invalidEnc.length);
    }

    @Test
    public void testModePskDecryption_parameterPskIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskDecryption(DEFAULT_ENC, /* psk= */ null, DEFAULT_PSK_ID));
    }

    @Test
    public void testModePskDecryption_parameterPskIdIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskDecryption(DEFAULT_ENC, DEFAULT_PSK, /* pskId= */ null));
    }

    @Test
    public void testModePskDecryption_parameterPskEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskDecryption(DEFAULT_ENC, /* psk= */ new byte[0], DEFAULT_PSK_ID));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModePskDecryption_parameterPskIdEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskDecryption(DEFAULT_ENC, DEFAULT_PSK, /* pskId= */ new byte[0]));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModePskDecryption_parameterPskHasInvalidLength_throwException() {
        final int hLength = DEFAULT_ALGORITHM_IDENTIFIER.getKdf().getHLength();
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskDecryption(DEFAULT_ENC, /* psk= */ new byte[hLength - 1],
                        DEFAULT_PSK_ID));

        assertPskLengthError(e, hLength);
    }

    @Test
    public void testModePskDecryption_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskDecryption(DEFAULT_ENC, DEFAULT_PSK, DEFAULT_PSK_ID)
                    .modePskDecryption(DEFAULT_ENC, DEFAULT_PSK, DEFAULT_PSK_ID));

        assertInitializationError(e);
    }

    @Test
    public void testModePskSendExport() {
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modePskSendExport(DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L)
                .build();

        assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
        assertNull(spec.getEnc());
        assertNull(spec.getInfo());
        assertNull(spec.getIv());
        assertArrayEquals(DEFAULT_PSK, spec.getPsk());
        assertArrayEquals(DEFAULT_PSK_ID, spec.getPskId());
        assertNull(spec.getAuthKey());
        assertEquals(DEFAULT_EXPORT_L, spec.getL());
        assertTrue(spec.isExporting());
        assertTrue(spec.isEncrypting());
        assertEquals(Mode.PSK, spec.getMode());
    }

    @Test
    public void testModePskSendExport_parameterPskIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskSendExport(/* psk= */ null, DEFAULT_PSK_ID, DEFAULT_EXPORT_L));
    }

    @Test
    public void testModePskSendExport_parameterPskIdIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskSendExport(DEFAULT_PSK, /* pskId= */ null, DEFAULT_EXPORT_L));
    }

    @Test
    public void testModePskSendExport_parameterPskEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskSendExport(/* psk= */ new byte[0], DEFAULT_PSK_ID, DEFAULT_EXPORT_L));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModePskSendExport_parameterPskIdEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskSendExport(DEFAULT_PSK, /* pskId= */ new byte[0], DEFAULT_EXPORT_L));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModePskSendExport_parameterPskHasInvalidLength_throwException() {
        final int hLength = DEFAULT_ALGORITHM_IDENTIFIER.getKdf().getHLength();
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskSendExport(
                        /* psk= */ new byte[hLength - 1],
                        DEFAULT_PSK_ID,
                        DEFAULT_EXPORT_L));

        assertPskLengthError(e, hLength);
    }

    @Test
    public void testModePskSendExport_parameterLHasInvalidLength_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final int upperLimitLength = identifier.getKdf().getHLength() * 255;
            final IllegalArgumentException upperE = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modePskSendExport(DEFAULT_PSK, DEFAULT_PSK_ID, /* l= */
                            upperLimitLength + 1));
            assertLError(upperE, upperLimitLength, upperLimitLength + 1);

            IllegalArgumentException lowerE = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modePskSendExport(DEFAULT_PSK, DEFAULT_PSK_ID, /* l= */ 0));
            assertLError(lowerE, upperLimitLength, 0);
        }
    }

    @Test
    public void testModePskSendExport_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskSendExport(DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L)
                    .modePskSendExport(DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L));

        assertInitializationError(e);
    }

    @Test
    public void testModePskReceiveExport() {
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modePskReceiveExport(DEFAULT_ENC, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L)
                .build();

        assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
        assertArrayEquals(DEFAULT_ENC, spec.getEnc());
        assertNull(spec.getInfo());
        assertNull(spec.getIv());
        assertArrayEquals(DEFAULT_PSK, spec.getPsk());
        assertArrayEquals(DEFAULT_PSK_ID, spec.getPskId());
        assertNull(spec.getAuthKey());
        assertEquals(DEFAULT_EXPORT_L, spec.getL());
        assertTrue(spec.isExporting());
        assertFalse(spec.isEncrypting());
        assertEquals(Mode.PSK, spec.getMode());
    }

    @Test
    public void testModePskReceiveExport_parameterEncIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskReceiveExport(
                        /* enc= */ null, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L));
    }

    @Test
    public void testModePskReceiveExport_parameterEncHasInvalidLength_throwException() {
        final byte[] invalidEnc =
            new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskReceiveExport(
                        /* enc= */ invalidEnc, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L));

        assertEncError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength(), invalidEnc.length);
    }

    @Test
    public void testModePskReceiveExport_parameterPskIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskReceiveExport(
                        DEFAULT_ENC, /* psk= */ null, DEFAULT_PSK_ID, DEFAULT_EXPORT_L));
    }

    @Test
    public void testModePskReceiveExport_parameterPskIdIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskReceiveExport(
                        DEFAULT_ENC, DEFAULT_PSK, /* pskId= */ null, DEFAULT_EXPORT_L));
    }

    @Test
    public void testModePskReceiveExport_parameterPskEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modePskReceiveExport(
                    DEFAULT_ENC, /* psk= */ new byte[0], DEFAULT_PSK_ID, DEFAULT_EXPORT_L));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModePskReceiveExport_parameterPskIdEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskReceiveExport(
                        DEFAULT_ENC, DEFAULT_PSK, /* pskId= */ new byte[0], DEFAULT_EXPORT_L));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModePskReceiveExport_parameterPskHasInvalidLength_throwException() {
        final int hLength = DEFAULT_ALGORITHM_IDENTIFIER.getKdf().getHLength();
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskReceiveExport(
                        DEFAULT_ENC,
                        /* psk= */ new byte[hLength - 1],
                        DEFAULT_PSK_ID,
                        DEFAULT_EXPORT_L));

        assertPskLengthError(e, hLength);
    }

    @Test
    public void testModePskReceiveExport_parameterLHasInvalidLength_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final int upperLimitLength = identifier.getKdf().getHLength() * 255;
            final IllegalArgumentException upperE = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modePskReceiveExport(
                            /* enc= */ new byte[identifier.getKem().getEncLength()],
                            DEFAULT_PSK,
                            DEFAULT_PSK_ID,
                            /* l= */ upperLimitLength + 1));
            assertLError(upperE, upperLimitLength, upperLimitLength + 1);

            IllegalArgumentException lowerE = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modePskReceiveExport(
                            /* enc= */ new byte[identifier.getKem().getEncLength()],
                            DEFAULT_PSK,
                            DEFAULT_PSK_ID,
                            /* l= */ 0));
            assertLError(lowerE, upperLimitLength, 0);
        }
    }

    @Test
    public void testModePskReceiveExport_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modePskReceiveExport(
                        DEFAULT_ENC, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L)
                    .modePskReceiveExport(
                        DEFAULT_ENC, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L));

        assertInitializationError(e);
    }

    @Test
    public void testModeAuthEncryption() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final HpkeParameterSpec spec =
                new HpkeParameterSpec.Builder(identifier)
                    .modeAuthEncryption(/* sk= */ new byte[identifier.getKem().getSkLength()])
                    .build();

            assertEquals(identifier, spec.getAlgorithmIdentifier());
            assertNull(spec.getEnc());
            assertNull(spec.getInfo());
            assertNull(spec.getIv());
            assertNull(spec.getPsk());
            assertNull(spec.getPskId());
            assertArrayEquals(new byte[identifier.getKem().getSkLength()], spec.getAuthKey());
            assertEquals(DEFAULT_NO_EXPORT_L, spec.getL());
            assertFalse(spec.isExporting());
            assertTrue(spec.isEncrypting());
            assertEquals(Mode.AUTH, spec.getMode());
        }
    }

    @Test
    public void testModeAuthEncryption_parameterSkIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthEncryption(/* sk= */ null));
    }

    @Test
    public void testModeAuthEncryption_parameterSkHasInvalidLength_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final byte[] lowerSk = new byte[identifier.getKem().getSkLength() - 1];
            final byte[] upperSk = new byte[identifier.getKem().getSkLength() - 1];

            final IllegalArgumentException eL = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeAuthEncryption(/* sk= */ lowerSk));
            assertSkLengthError(eL, identifier.getKem().getSkLength(), lowerSk.length);

            final IllegalArgumentException eU = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeAuthEncryption(/* sk= */ lowerSk));
            assertSkLengthError(eU, identifier.getKem().getSkLength(), upperSk.length);
        }
    }

    @Test
    public void testModeAuthEncryption_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthEncryption(DEFAULT_AUTH_KEY)
                    .modeAuthEncryption(DEFAULT_AUTH_KEY));

        assertInitializationError(e);
    }

    @Test
    public void testModeAuthDecryption() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final HpkeParameterSpec spec =
                new HpkeParameterSpec.Builder(identifier)
                    .modeAuthDecryption(
                        /* enc= */ new byte[identifier.getKem().getEncLength()],
                        /* pk= */ new byte[identifier.getKem().getPkLength()])
                    .build();

            assertEquals(identifier, spec.getAlgorithmIdentifier());
            assertArrayEquals(new byte[identifier.getKem().getEncLength()], spec.getEnc());
            assertNull(spec.getInfo());
            assertNull(spec.getIv());
            assertNull(spec.getPsk());
            assertNull(spec.getPskId());
            assertArrayEquals(new byte[identifier.getKem().getPkLength()], spec.getAuthKey());
            assertEquals(DEFAULT_NO_EXPORT_L, spec.getL());
            assertFalse(spec.isExporting());
            assertFalse(spec.isEncrypting());
            assertEquals(Mode.AUTH, spec.getMode());
        }
    }

    @Test
    public void testModeAuthDecryption_parameterEncIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthDecryption(/* enc= */ null, DEFAULT_AUTH_KEY));
    }

    @Test
    public void testModeAuthDecryption_parameterEncHasInvalidLength_throwException() {
        final byte[] invalidEnc =
            new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthDecryption(/* enc= */ invalidEnc, DEFAULT_AUTH_KEY));

        assertEncError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength(), invalidEnc.length);
    }

    @Test
    public void testModeAuthDecryption_parameterPkIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthDecryption(DEFAULT_ENC, /* pk= */ null));
    }

    @Test
    public void testModeAuthDecryption_parameterPkHasInvalidLength_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final byte[] lowerPk = new byte[identifier.getKem().getPkLength() - 1];
            final byte[] upperPk = new byte[identifier.getKem().getPkLength() - 1];

            final IllegalArgumentException eL = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeAuthDecryption(
                            /* enc= */ new byte[identifier.getKem().getEncLength()],
                            /* pk= */ lowerPk));
            assertPkLengthError(eL, identifier.getKem().getPkLength(), lowerPk.length);

            final IllegalArgumentException eU = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeAuthDecryption(
                            /* enc= */ new byte[identifier.getKem().getEncLength()],
                            /* pk= */ upperPk));
            assertPkLengthError(eU, identifier.getKem().getPkLength(), upperPk.length);
        }
    }

    @Test
    public void testModeAuthDecryption_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthDecryption(DEFAULT_ENC, DEFAULT_AUTH_KEY)
                    .modeAuthDecryption(DEFAULT_ENC, DEFAULT_AUTH_KEY));

        assertInitializationError(e);
    }

    @Test
    public void testModeAuthSendExport() {
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modeAuthSendExport(DEFAULT_AUTH_KEY, DEFAULT_EXPORT_L)
                .build();

        assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
        assertNull(spec.getEnc());
        assertNull(spec.getInfo());
        assertNull(spec.getIv());
        assertNull(spec.getPsk());
        assertNull(spec.getPskId());
        assertArrayEquals(DEFAULT_AUTH_KEY, spec.getAuthKey());
        assertEquals(DEFAULT_EXPORT_L, spec.getL());
        assertTrue(spec.isExporting());
        assertTrue(spec.isEncrypting());
        assertEquals(Mode.AUTH, spec.getMode());
    }

    @Test
    public void testModeAuthSendExport_parameterSkIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthSendExport(/* sk= */ null, DEFAULT_EXPORT_L));
    }

    @Test
    public void testModeAuthSendExport_parameterSkHasInvalidLength_throwException() {
        final byte[] sk = new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getSkLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthSendExport(/* sk= */ sk, DEFAULT_EXPORT_L));

        assertSkLengthError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getSkLength(), sk.length);
    }

    @Test
    public void testModeAuthSendExport_parameterLHasInvalidLength_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final int upperLimitLength = identifier.getKdf().getHLength() * 255;
            final IllegalArgumentException upperE = assertThrows(
                IllegalArgumentException.class,
                () -> new HpkeParameterSpec.Builder(identifier)
                    .modeAuthSendExport(
                        /* sk= */new byte[identifier.getKem().getSkLength()],
                        /* l= */ upperLimitLength + 1));
            assertLError(upperE, upperLimitLength, upperLimitLength + 1);

            IllegalArgumentException lowerE = assertThrows(
                IllegalArgumentException.class,
                () -> new HpkeParameterSpec.Builder(identifier)
                    .modeAuthSendExport(
                        /* sk= */new byte[identifier.getKem().getSkLength()],
                        /* l= */ 0));
            assertLError(lowerE, upperLimitLength, 0);
        }
    }

    @Test
    public void testModeAuthSendExport_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthSendExport(DEFAULT_AUTH_KEY, DEFAULT_EXPORT_L)
                    .modeAuthSendExport(DEFAULT_AUTH_KEY, DEFAULT_EXPORT_L));

        assertInitializationError(e);
    }

    @Test
    public void testModeAuthReceiveExport() {
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modeAuthReceiveExport(DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_EXPORT_L)
                .build();

        assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
        assertArrayEquals(DEFAULT_ENC, spec.getEnc());
        assertNull(spec.getInfo());
        assertNull(spec.getIv());
        assertNull(spec.getPsk());
        assertNull(spec.getPskId());
        assertArrayEquals(DEFAULT_AUTH_KEY, spec.getAuthKey());
        assertEquals(DEFAULT_EXPORT_L, spec.getL());
        assertTrue(spec.isExporting());
        assertFalse(spec.isEncrypting());
        assertEquals(Mode.AUTH, spec.getMode());
    }

    @Test
    public void testModeAuthReceiveExport_parameterEncIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthReceiveExport(/* enc= */ null, DEFAULT_AUTH_KEY, DEFAULT_EXPORT_L));
    }

    @Test
    public void testModeAuthReceiveExport_parameterEncHasInvalidLength_throwException() {
        final byte[] invalidEnc =
            new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthReceiveExport(
                        /* enc= */ invalidEnc, DEFAULT_AUTH_KEY, DEFAULT_EXPORT_L));

        assertEncError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength(), invalidEnc.length);
    }

    @Test
    public void testModeAuthReceiveExport_parameterPkIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthReceiveExport(DEFAULT_ENC, /* pk= */ null, DEFAULT_EXPORT_L));
    }

    @Test
    public void testModeAuthReceiveExport_parameterPkHasInvalidLength_throwException() {
        final byte[] pk = new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getPkLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthReceiveExport(DEFAULT_ENC, /* pk= */ pk, DEFAULT_EXPORT_L));

        assertPkLengthError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getPkLength(), pk.length);
    }

    @Test
    public void testModeAuthReceiveExport_parameterLHasInvalidLength_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final int upperLimitLength = identifier.getKdf().getHLength() * 255;
            final IllegalArgumentException upperE = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeAuthReceiveExport(
                            /* enc= */ new byte[identifier.getKem().getEncLength()],
                            /* pk= */ new byte[identifier.getKem().getPkLength()],
                            /* l= */ upperLimitLength + 1));
            assertLError(upperE, upperLimitLength, upperLimitLength + 1);

            final IllegalArgumentException lowerE = assertThrows(
                IllegalArgumentException.class,
                () -> new HpkeParameterSpec.Builder(identifier)
                    .modeAuthReceiveExport(
                        /* enc= */ new byte[identifier.getKem().getEncLength()],
                        /* pk= */ new byte[identifier.getKem().getPkLength()],
                        /* l= */ 0));
            assertLError(lowerE, upperLimitLength, 0);
        }
    }

    @Test
    public void testModeAuthReceiveExport_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthReceiveExport(DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_EXPORT_L)
                    .modeAuthReceiveExport(DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_EXPORT_L));

        assertInitializationError(e);
    }

    @Test
    public void testModeAuthPskEncryption() {
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modeAuthPskEncryption(DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID)
                .build();

        assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
        assertNull(spec.getEnc());
        assertNull(spec.getInfo());
        assertNull(spec.getIv());
        assertArrayEquals(DEFAULT_PSK, spec.getPsk());
        assertArrayEquals(DEFAULT_PSK_ID, spec.getPskId());
        assertArrayEquals(DEFAULT_AUTH_KEY, spec.getAuthKey());
        assertEquals(DEFAULT_NO_EXPORT_L, spec.getL());
        assertFalse(spec.isExporting());
        assertTrue(spec.isEncrypting());
        assertEquals(Mode.AUTH_PSK, spec.getMode());
    }

    @Test
    public void testModeAuthPskEncryption_parameterSkIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskEncryption(/* sk= */ null, DEFAULT_PSK, DEFAULT_PSK_ID));
    }

    @Test
    public void testModeAuthPskEncryption_parameterSkHasInvalidLength_throwException() {
        final byte[] sk = new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getSkLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskEncryption(/* sk= */ sk, DEFAULT_PSK, DEFAULT_PSK_ID));

        assertSkLengthError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getSkLength(), sk.length);
    }

    @Test
    public void testModeAuthPskEncryption_parameterPskIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskEncryption(DEFAULT_AUTH_KEY, /* psk= */ null, DEFAULT_PSK_ID));
    }

    @Test
    public void testModeAuthPskEncryption_parameterPskIdIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskEncryption(DEFAULT_AUTH_KEY, DEFAULT_PSK, /* pskId= */ null));
    }

    @Test
    public void testModeAuthPskEncryption_parameterPskEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskEncryption(
                        DEFAULT_AUTH_KEY, /* psk= */ new byte[0], DEFAULT_PSK_ID));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModeAuthPskEncryption_parameterPskIdEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskEncryption(
                        DEFAULT_AUTH_KEY, DEFAULT_PSK, /* pskId= */ new byte[0]));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModeAuthPskEncryption_parameterPskHasInvalidLength_throwException() {
        final int hLength = DEFAULT_ALGORITHM_IDENTIFIER.getKdf().getHLength();
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskEncryption(
                        DEFAULT_AUTH_KEY,
                        /* psk= */ new byte[hLength - 1],
                        DEFAULT_PSK_ID));

        assertPskLengthError(e, hLength);
    }

    @Test
    public void testModeAuthPskEncryption_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskEncryption(DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID)
                    .modeAuthPskEncryption(DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID));

        assertInitializationError(e);
    }

    @Test
    public void testModeAuthPskDecryption() {
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modeAuthPskDecryption(DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID)
                .build();

        assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
        assertArrayEquals(DEFAULT_ENC, spec.getEnc());
        assertNull(spec.getInfo());
        assertNull(spec.getIv());
        assertArrayEquals(DEFAULT_PSK, spec.getPsk());
        assertArrayEquals(DEFAULT_PSK_ID, spec.getPskId());
        assertArrayEquals(DEFAULT_AUTH_KEY, spec.getAuthKey());
        assertEquals(DEFAULT_NO_EXPORT_L, spec.getL());
        assertFalse(spec.isExporting());
        assertFalse(spec.isEncrypting());
        assertEquals(Mode.AUTH_PSK, spec.getMode());
    }

    @Test
    public void testModeAuthPskDecryption_parameterEncIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskDecryption(
                        /* enc= */ null,
                        DEFAULT_AUTH_KEY,
                        DEFAULT_PSK,
                        DEFAULT_PSK_ID));
    }

    @Test
    public void testModeAuthPskDecryption_parameterEncHasInvalidLength_throwException() {
        final byte[] invalidEnc =
            new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskDecryption(
                        /* enc= */ invalidEnc, DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID));

        assertEncError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength(), invalidEnc.length);
    }

    @Test
    public void testModeAuthPskDecryption_parameterPkIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskDecryption(
                        DEFAULT_ENC, /* pk= */ null, DEFAULT_PSK, DEFAULT_PSK_ID));
    }

    @Test
    public void testModeAuthPskDecryption_parameterPkHasInvalidLength_throwException() {
        final byte[] pk = new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getPkLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskDecryption(DEFAULT_ENC, /* pk= */ pk, DEFAULT_PSK, DEFAULT_PSK_ID));

        assertPkLengthError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getPkLength(), pk.length);
    }

    @Test
    public void testModeAuthPskDecryption_parameterPskIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskDecryption(
                        DEFAULT_ENC, DEFAULT_AUTH_KEY, /* psk= */ null, DEFAULT_PSK_ID));
    }

    @Test
    public void testModeAuthPskDecryption_parameterPskIdIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskDecryption(
                        DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_PSK, /* pskId= */ null));
    }

    @Test
    public void testModeAuthPskDecryption_parameterPskEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskDecryption(
                        DEFAULT_ENC, DEFAULT_AUTH_KEY, /* psk= */ new byte[0], DEFAULT_PSK_ID));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModeAuthPskDecryption_parameterPskIdEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskDecryption(
                        DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_PSK, /* pskId= */ new byte[0]));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModeAuthPskDecryption_parameterPskHasInvalidLength_throwException() {
        final int hLength = DEFAULT_ALGORITHM_IDENTIFIER.getKdf().getHLength();
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskDecryption(
                        DEFAULT_ENC,
                        DEFAULT_AUTH_KEY,
                        /* psk= */new byte[hLength - 1],
                        DEFAULT_PSK_ID));

        assertPskLengthError(e, hLength);
    }

    @Test
    public void testModeAuthPskDecryption_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskDecryption(
                        DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID)
                    .modeAuthPskDecryption(
                        DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID));

        assertInitializationError(e);
    }

    @Test
    public void testModeAuthPskSendExport() {
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modeAuthPskSendExport(
                    DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L)
                .build();

        assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
        assertNull(spec.getEnc());
        assertNull(spec.getInfo());
        assertNull(spec.getIv());
        assertArrayEquals(DEFAULT_PSK, spec.getPsk());
        assertArrayEquals(DEFAULT_PSK_ID, spec.getPskId());
        assertArrayEquals(DEFAULT_AUTH_KEY, spec.getAuthKey());
        assertEquals(DEFAULT_EXPORT_L, spec.getL());
        assertTrue(spec.isExporting());
        assertTrue(spec.isEncrypting());
        assertEquals(Mode.AUTH_PSK, spec.getMode());
    }

    @Test
    public void testModeAuthPskSendExport_parameterSkIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskSendExport(
                        /* sk= */ null, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L));
    }

    @Test
    public void testModeAuthPskSendExport_parameterSkHasInvalidLength_throwException() {
        final byte[] sk = new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getSkLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskSendExport(
                        /* sk= */ sk, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L));

        assertSkLengthError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getSkLength(), sk.length);
    }

    @Test
    public void testModeAuthPskSendExport_parameterPskIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskSendExport(
                        DEFAULT_AUTH_KEY, /* psk= */ null, DEFAULT_PSK_ID, DEFAULT_EXPORT_L));
    }

    @Test
    public void testModeAuthPskSendExport_parameterPskIdIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskSendExport(
                        DEFAULT_AUTH_KEY, DEFAULT_PSK, /* pskId= */ null, DEFAULT_EXPORT_L));
    }

    @Test
    public void testModeAuthPskSendExport_parameterPskEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskSendExport(
                        DEFAULT_AUTH_KEY,
                        /* psk= */ new byte[0],
                        DEFAULT_PSK_ID,
                        DEFAULT_EXPORT_L));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModeAuthPskSendExport_parameterPskIdEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modeAuthPskSendExport(
                    DEFAULT_AUTH_KEY, DEFAULT_PSK, /* pskId= */ new byte[0], DEFAULT_EXPORT_L));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModeAuthPskSendExport_parameterPskHasInvalidLength_throwException() {
        final int hLength = DEFAULT_ALGORITHM_IDENTIFIER.getKdf().getHLength();
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modeAuthPskSendExport(
                    DEFAULT_AUTH_KEY,
                    /* psk= */ new byte[hLength - 1],
                    DEFAULT_PSK_ID,
                    DEFAULT_EXPORT_L));

        assertPskLengthError(e, hLength);
    }

    @Test
    public void testModeAuthPskSendExport_parameterLHasInvalidLength_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final int upperLimitLength = identifier.getKdf().getHLength() * 255;
            final IllegalArgumentException upperE = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeAuthPskSendExport(
                            /* sk= */ new byte[identifier.getKem().getSkLength()],
                            DEFAULT_PSK,
                            DEFAULT_PSK_ID,
                            /* l= */ upperLimitLength + 1));
            assertLError(upperE, upperLimitLength, upperLimitLength + 1);

            final IllegalArgumentException lowerE = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeAuthPskSendExport(
                            /* sk= */ new byte[identifier.getKem().getSkLength()],
                            DEFAULT_PSK, DEFAULT_PSK_ID,
                            /* l= */ 0));
            assertLError(lowerE, upperLimitLength, 0);
        }
    }

    @Test
    public void testModeAuthPskSendExport_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskSendExport(
                        DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L)
                    .modeAuthPskSendExport(
                        DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L));

        assertInitializationError(e);
    }

    @Test
    public void testModeAuthPskReceiveExport() {
        final HpkeParameterSpec spec =
            new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modeAuthPskReceiveExport(
                    DEFAULT_ENC, DEFAULT_AUTH_KEY, DEFAULT_PSK, DEFAULT_PSK_ID, DEFAULT_EXPORT_L)
                .build();

        assertEquals(DEFAULT_ALGORITHM_IDENTIFIER, spec.getAlgorithmIdentifier());
        assertArrayEquals(DEFAULT_ENC, spec.getEnc());
        assertNull(spec.getInfo());
        assertNull(spec.getIv());
        assertArrayEquals(DEFAULT_PSK, spec.getPsk());
        assertArrayEquals(DEFAULT_PSK_ID, spec.getPskId());
        assertArrayEquals(DEFAULT_AUTH_KEY, spec.getAuthKey());
        assertEquals(DEFAULT_EXPORT_L, spec.getL());
        assertTrue(spec.isExporting());
        assertFalse(spec.isEncrypting());
        assertEquals(Mode.AUTH_PSK, spec.getMode());
    }

    @Test
    public void testModeAuthPskReceiveExport_parameterEncIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskReceiveExport(
                        /* enc= */ null,
                        DEFAULT_AUTH_KEY,
                        DEFAULT_PSK,
                        DEFAULT_PSK_ID,
                        DEFAULT_EXPORT_L));
    }

    @Test
    public void testModeAuthPskReceiveExport_parameterEncHasInvalidLength_throwException() {
        final byte[] invalidEnc =
            new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskReceiveExport(
                        /* enc= */ invalidEnc,
                        DEFAULT_AUTH_KEY,
                        DEFAULT_PSK,
                        DEFAULT_PSK_ID,
                        DEFAULT_EXPORT_L));

        assertEncError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getEncLength(), invalidEnc.length);
    }

    @Test
    public void testModeAuthPskReceiveExport_parameterPkIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskReceiveExport(
                        DEFAULT_ENC,
                        /* pk= */ null,
                        DEFAULT_PSK,
                        DEFAULT_PSK_ID,
                        DEFAULT_EXPORT_L));
    }

    @Test
    public void testModeAuthPskReceiveExport_parameterPkHasInvalidLength_throwException() {
        final byte[] pk = new byte[DEFAULT_ALGORITHM_IDENTIFIER.getKem().getPkLength() - 1];
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskReceiveExport(
                        DEFAULT_ENC,
                        /* pk= */ pk,
                        DEFAULT_PSK,
                        DEFAULT_PSK_ID,
                        DEFAULT_EXPORT_L));

        assertPkLengthError(e, DEFAULT_ALGORITHM_IDENTIFIER.getKem().getPkLength(), pk.length);
    }

    @Test
    public void testModeAuthPskReceiveExport_parameterPskIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskReceiveExport(
                        DEFAULT_ENC,
                        DEFAULT_AUTH_KEY,
                        /* psk= */ null,
                        DEFAULT_PSK_ID,
                        DEFAULT_EXPORT_L));
    }

    @Test
    public void testModeAuthPskReceiveExport_parameterPskIdIsNull_throwException() {
        assertThrows(
            NullPointerException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskReceiveExport(
                        DEFAULT_ENC,
                        DEFAULT_AUTH_KEY,
                        DEFAULT_PSK,
                        /* pskId= */ null,
                        DEFAULT_EXPORT_L));
    }

    @Test
    public void testModeAuthPskReceiveExport_parameterPskEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskReceiveExport(
                        DEFAULT_ENC,
                        DEFAULT_AUTH_KEY,
                        /* psk= */ new byte[0],
                        DEFAULT_PSK_ID,
                        DEFAULT_EXPORT_L));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModeAuthPskReceiveExport_parameterPskIdEmptyValue_throwException() {
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                .modeAuthPskReceiveExport(
                    DEFAULT_ENC,
                    DEFAULT_AUTH_KEY,
                    DEFAULT_PSK,
                    /* pskId= */ new byte[0],
                    DEFAULT_EXPORT_L));

        assertPskDefaultValuesError(e);
    }

    @Test
    public void testModeAuthPskReceiveExport_parameterPskHasInvalidLength_throwException() {
        final int hLength = DEFAULT_ALGORITHM_IDENTIFIER.getKdf().getHLength();
        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskReceiveExport(
                        DEFAULT_ENC,
                        DEFAULT_AUTH_KEY,
                        /* psk= */ new byte[hLength - 1],
                        DEFAULT_PSK_ID,
                        DEFAULT_EXPORT_L));

        assertPskLengthError(e, hLength);
    }

    @Test
    public void testModeAuthPskReceiveExport_parameterLHasInvalidLength_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final int upperLimitLength = identifier.getKdf().getHLength() * 255;
            final IllegalArgumentException upperE = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeAuthPskReceiveExport(
                            /* enc= */ new byte[identifier.getKem().getEncLength()], /* pk= */
                            new byte[identifier.getKem().getPkLength()],
                            DEFAULT_PSK,
                            DEFAULT_PSK_ID,
                            /* l= */ upperLimitLength + 1));
            assertLError(upperE, upperLimitLength, upperLimitLength + 1);

            final IllegalArgumentException lowerE = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(identifier)
                        .modeAuthPskReceiveExport(
                            /* enc= */ new byte[identifier.getKem().getEncLength()],
                            /* pk= */ new byte[identifier.getKem().getPkLength()],
                            DEFAULT_PSK,
                            DEFAULT_PSK_ID,
                            /* l= */ 0));
            assertLError(lowerE, upperLimitLength, 0);
        }
    }

    @Test
    public void testModeAuthPskReceiveExport_alreadyInitialized_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .modeAuthPskReceiveExport(
                        DEFAULT_ENC,
                        DEFAULT_AUTH_KEY,
                        DEFAULT_PSK,
                        DEFAULT_PSK_ID,
                        DEFAULT_EXPORT_L)
                    .modeAuthPskReceiveExport(
                        DEFAULT_ENC,
                        DEFAULT_AUTH_KEY,
                        DEFAULT_PSK,
                        DEFAULT_PSK_ID,
                        DEFAULT_EXPORT_L));

        assertInitializationError(e);
    }

    @Test
    public void testInfoAndIv() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final HpkeParameterSpec spec =
                new HpkeParameterSpec.Builder(identifier)
                    .info(DEFAULT_INFO)
                    .iv(new byte[identifier.getKem().getSkLength()])
                    .modeBaseEncryption()
                    .build();

            assertEquals(identifier, spec.getAlgorithmIdentifier());
            assertNull(spec.getEnc());
            assertArrayEquals(DEFAULT_INFO, spec.getInfo());
            assertArrayEquals(new byte[identifier.getKem().getSkLength()], spec.getIv());
            assertNull(spec.getPsk());
            assertNull(spec.getPskId());
            assertNull(spec.getAuthKey());
            assertEquals(DEFAULT_NO_EXPORT_L, spec.getL());
            assertFalse(spec.isExporting());
        }
    }

    @Test
    public void testInfoAndIv_invalidIv_throwException() {
        for (HpkeAlgorithmIdentifier identifier : ALL_ALGORITHM_IDENTIFIERS) {
            final IllegalArgumentException e = assertThrows(
                IllegalArgumentException.class,
                () ->
                    new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                        .info(DEFAULT_INFO)
                        .iv(new byte[identifier.getKem().getSkLength() - 1])
                        .modeBaseEncryption()
                        .build()
            );

            assertEquals("Expected IV length of "
                    + DEFAULT_ALGORITHM_IDENTIFIER.getKem().getSkLength() + " but was "
                    + (identifier.getKem().getSkLength() - 1),
                e.getMessage());
        }
    }

    @Test
    public void testNoModeSelected_throwError() {
        final IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () ->
                new HpkeParameterSpec.Builder(DEFAULT_ALGORITHM_IDENTIFIER)
                    .info(DEFAULT_INFO)
                    .iv(DEFAULT_IV)
                    .build());

        assertEquals("Please initialize builder with a valid mode", e.getMessage());
    }

    private void assertEncError(IllegalArgumentException e, int expectedLength, int actualLength) {
        assertEquals(
            "Expected enc length of " + expectedLength + " but was " + actualLength,
            e.getMessage());
    }

    private void assertInitializationError(IllegalStateException e) {
        assertEquals("Mode has already been configured", e.getMessage());
    }

    private void assertLError(IllegalArgumentException e, int upperLimitLength, int actualLength) {
        assertEquals(
            "Export length (L) must be greater than 0 and less than " + upperLimitLength +
            " but was " + actualLength,
            e.getMessage());
    }

    private void assertPskDefaultValuesError(IllegalArgumentException e) {
        assertEquals(
            "Psk and psk id should not be empty values",
            e.getMessage());
    }

    private void assertPskLengthError(IllegalArgumentException e, int minPskLength) {
        assertEquals(
            "Psk length must be greater than or equal to " + minPskLength,
            e.getMessage());
    }

    private void assertPkLengthError(IllegalArgumentException e, int expectedLength,
        int actualLength) {
        assertEquals(
            "Expected pk length of " + expectedLength + " but was " + actualLength,
            e.getMessage());
    }

    private void assertSkLengthError(IllegalArgumentException e, int expectedLength,
        int actualLength) {
        assertEquals(
            "Expected sk length of " + expectedLength + " but was " + actualLength,
            e.getMessage());
    }
}