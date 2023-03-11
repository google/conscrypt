package org.conscrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.conscrypt.HpkeAlgorithmIdentifier.AEAD;
import org.conscrypt.HpkeAlgorithmIdentifier.KDF;
import org.conscrypt.HpkeAlgorithmIdentifier.KEM;
import org.conscrypt.HpkeAlgorithmIdentifier.KEM.SealedData;
import org.junit.Test;

public class HpkeAlgorithmIdentifierTest {

    @Test
    public void testKemSecretLength() {
        assertEquals(32, KEM.DHKEM_P_256_HKDF_SHA256.getSecretLength());
        assertEquals(48, KEM.DHKEM_P_384_HKDF_SHA384.getSecretLength());
        assertEquals(64, KEM.DHKEM_P_521_HKDF_SHA512.getSecretLength());
        assertEquals(32, KEM.DHKEM_X25519_HKDF_SHA256.getSecretLength());
        assertEquals(64, KEM.DHKEM_X448_HKDF_SHA512.getSecretLength());
    }

    @Test
    public void testKemEncLength() {
        assertEquals(65, KEM.DHKEM_P_256_HKDF_SHA256.getEncLength());
        assertEquals(97, KEM.DHKEM_P_384_HKDF_SHA384.getEncLength());
        assertEquals(133, KEM.DHKEM_P_521_HKDF_SHA512.getEncLength());
        assertEquals(32, KEM.DHKEM_X25519_HKDF_SHA256.getEncLength());
        assertEquals(56, KEM.DHKEM_X448_HKDF_SHA512.getEncLength());
    }

    @Test
    public void testKemPkLength() {
        assertEquals(65, KEM.DHKEM_P_256_HKDF_SHA256.getPkLength());
        assertEquals(97, KEM.DHKEM_P_384_HKDF_SHA384.getPkLength());
        assertEquals(133, KEM.DHKEM_P_521_HKDF_SHA512.getPkLength());
        assertEquals(32, KEM.DHKEM_X25519_HKDF_SHA256.getPkLength());
        assertEquals(56, KEM.DHKEM_X448_HKDF_SHA512.getPkLength());
    }

    @Test
    public void testKemSkLength() {
        assertEquals(32, KEM.DHKEM_P_256_HKDF_SHA256.getSkLength());
        assertEquals(48, KEM.DHKEM_P_384_HKDF_SHA384.getSkLength());
        assertEquals(66, KEM.DHKEM_P_521_HKDF_SHA512.getSkLength());
        assertEquals(32, KEM.DHKEM_X25519_HKDF_SHA256.getSkLength());
        assertEquals(56, KEM.DHKEM_X448_HKDF_SHA512.getSkLength());
    }

    @Test
    public void testKemExtract() {
        String enc = "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325"
            + "ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4";
        String ct = "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f";
        byte[] encAndCt = TestUtils.decodeHex(enc + ct);
        SealedData sealed = KEM.DHKEM_P_256_HKDF_SHA256.extract(encAndCt);
        assertEquals(enc, TestUtils.encodeHex(sealed.getEnc()));
        assertEquals(ct, TestUtils.encodeHex(sealed.getCt()));

        enc = "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab89"
            + "00aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731e"
            + "ce2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed06"
            + "92237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0";
        ct = "170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b20";
        encAndCt = TestUtils.decodeHex(enc + ct);
        sealed = KEM.DHKEM_P_521_HKDF_SHA512.extract(encAndCt);
        assertEquals(enc, TestUtils.encodeHex(sealed.getEnc()));
        assertEquals(ct, TestUtils.encodeHex(sealed.getCt()));

        enc = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
        ct = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9";
        encAndCt = TestUtils.decodeHex(enc + ct);
        sealed = KEM.DHKEM_X25519_HKDF_SHA256.extract(encAndCt);
        assertEquals(enc, TestUtils.encodeHex(sealed.getEnc()));
        assertEquals(ct, TestUtils.encodeHex(sealed.getCt()));

        enc = "ce3c6a238c40cccf3f63cd48ea0aea71d4a8518945f37f14a5134cd65b8b66886a44a"
            + "a63dbc2f99c7951384ba8fddbcb51382f110b38af0b";
        ct = "e50d1a2bed3b67d869ac0506d318dfebd8377d786fcbea89b8a9baf1c43a0d355039a1"
            + "fd4c2806c318fe667243";
        encAndCt = TestUtils.decodeHex(enc + ct);
        sealed = KEM.DHKEM_X448_HKDF_SHA512.extract(encAndCt);
        assertEquals(enc, TestUtils.encodeHex(sealed.getEnc()));
        assertEquals(ct, TestUtils.encodeHex(sealed.getCt()));
    }

    @Test
    public void testKemExtract_nullParameter_throwException() {
        assertThrows(
            NullPointerException.class,
            () -> KEM.DHKEM_P_256_HKDF_SHA256.extract(null)
        );
    }

    @Test
    public void testKemExtract_invalidEncLengthParameter_throwException() {
        final byte[] emptyEnc = new byte[0];
        IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> KEM.DHKEM_X25519_HKDF_SHA256.extract(emptyEnc)
        );

        assertEquals("Invalid encapsulated key length", e.getMessage());
    }

    @Test
    public void testKemExtract_validEncButNotCiphertext_throwException() {
        final byte[] encLimit = new byte[KEM.DHKEM_X25519_HKDF_SHA256.getEncLength()];
        IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> KEM.DHKEM_X25519_HKDF_SHA256.extract(encLimit)
        );

        assertEquals("Invalid ciphertext length", e.getMessage());
    }


    @Test
    public void testKdfHLength() {
        assertEquals(32, KDF.HKDF_SHA256.getHLength());
        assertEquals(48, KDF.HKDF_SHA384.getHLength());
        assertEquals(64, KDF.HKDF_SHA512.getHLength());
    }

    @Test
    public void testAeadKLength() {
        assertEquals(16, AEAD.AES_128_GCM.getKLength());
        assertEquals(32, AEAD.AES_256_GCM.getKLength());
        assertEquals(32, AEAD.CHACHA20POLY1305.getKLength());
        assertEquals(-1, AEAD.EXPORT_ONLY_AEAD.getKLength());
    }

    @Test
    public void testAeadNLength() {
        assertEquals(12, AEAD.AES_128_GCM.getNLength());
        assertEquals(12, AEAD.AES_256_GCM.getNLength());
        assertEquals(12, AEAD.CHACHA20POLY1305.getNLength());
        assertEquals(-1, AEAD.EXPORT_ONLY_AEAD.getNLength());
    }

    @Test
    public void testAeadTLength() {
        assertEquals(16, AEAD.AES_128_GCM.getTLength());
        assertEquals(16, AEAD.AES_256_GCM.getTLength());
        assertEquals(16, AEAD.CHACHA20POLY1305.getTLength());
        assertEquals(-1, AEAD.EXPORT_ONLY_AEAD.getTLength());
    }

    @Test
    public void testValidConstructor() {
        HpkeAlgorithmIdentifier algorithmIdentifier = new HpkeAlgorithmIdentifier(
            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_256_GCM);

        assertEquals(KEM.DHKEM_X25519_HKDF_SHA256, algorithmIdentifier.getKem());
        assertEquals(KDF.HKDF_SHA256, algorithmIdentifier.getKdf());
        assertEquals(AEAD.AES_256_GCM, algorithmIdentifier.getAead());
    }

    @Test
    public void testInvalidKem() {
        assertThrows(
            NullPointerException.class,
            () -> new HpkeAlgorithmIdentifier(
                /* kem= */ null, KDF.HKDF_SHA256, AEAD.AES_256_GCM));
    }

    @Test
    public void testInvalidKdf() {
        assertThrows(
            NullPointerException.class,
            () -> new HpkeAlgorithmIdentifier(
                KEM.DHKEM_X25519_HKDF_SHA256, /* kdf= */ null, AEAD.AES_256_GCM));
    }

    @Test
    public void testInvalidAead() {
        assertThrows(
            NullPointerException.class,
            () -> new HpkeAlgorithmIdentifier(
                KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, /* aead= */ null));
    }
}