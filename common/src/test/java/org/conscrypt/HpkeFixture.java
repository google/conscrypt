package org.conscrypt;

import static org.conscrypt.HpkeSuite.AEAD_AES_256_GCM;
import static org.conscrypt.HpkeSuite.KDF_HKDF_SHA256;
import static org.conscrypt.HpkeSuite.KEM_DHKEM_X25519_HKDF_SHA256;
import static org.conscrypt.TestUtils.decodeHex;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class HpkeFixture {
    static final byte[] DEFAULT_AAD = decodeHex("436f756e742d30");
    static final byte[] DEFAULT_ENC =
            decodeHex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    static final byte[] DEFAULT_INFO = decodeHex("4f6465206f6e2061204772656369616e2055726e");

    static final byte[] DEFAULT_PK =
            decodeHex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    static final byte[] DEFAULT_SK =
            decodeHex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");

    static final byte[] DEFAULT_PT =
            decodeHex("4265617574792069732074727574682c20747275746820626561757479");
    static final byte[] DEFAULT_CT = decodeHex(
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a");

    static final int DEFAULT_EXPORTER_LENGTH = 32;
    static final byte[] DEFAULT_EXPORTER_CONTEXT = decodeHex("00");

    static HpkeContextRecipient createDefaultHpkeContextRecipient(byte[] enc)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return createDefaultHpkeContextRecipient(enc, DEFAULT_INFO);
    }

    static HpkeContextRecipient createDefaultHpkeContextRecipient(byte[] enc, byte[] info)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final HpkeSuite suite = createDefaultHpkeSuite();
        return HpkeContextRecipient.setupBase(suite, enc, createPrivateKey(DEFAULT_SK), info);
    }

    static HpkeContextSender createDefaultHpkeContextSender()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return createDefaultHpkeContextSender(DEFAULT_INFO);
    }

    static HpkeContextSender createDefaultHpkeContextSender(byte[] info)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final HpkeSuite suite = createDefaultHpkeSuite();
        return HpkeContextSender.setupBase(suite, createPublicKey(DEFAULT_PK), info);
    }

    static HpkeSuite createDefaultHpkeSuite() {
        return new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);
    }

    static PublicKey createPublicKey(byte[] publicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyFactory factory = KeyFactory.getInstance("XDH");
        final KeySpec spec = new XdhKeySpec(publicKey);
        return factory.generatePublic(spec);
    }

    static PrivateKey createPrivateKey(byte[] privateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyFactory factory = KeyFactory.getInstance("XDH");
        final KeySpec spec = new XdhKeySpec(privateKey);
        return factory.generatePrivate(spec);
    }
}
