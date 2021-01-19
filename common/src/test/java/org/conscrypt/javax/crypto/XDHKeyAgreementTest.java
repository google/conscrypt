package org.conscrypt.javax.crypto;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.assertArrayEquals;

/**
 * Tests for all registered X25519 and X448 {@link KeyAgreement} providers.
 */
@RunWith(JUnit4.class)
public class XDHKeyAgreementTest {
    private static final byte[] RFC_7748_X25519_OUR_PRIV_KEY = new byte[] {
            (byte) 0x30, (byte) 0x2e, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x30, (byte) 0x05, (byte) 0x06,
            (byte) 0x03, (byte) 0x2b, (byte) 0x65, (byte) 0x6e, (byte) 0x04, (byte) 0x22, (byte) 0x04, (byte) 0x20,
            (byte) 0xa5, (byte) 0x46, (byte) 0xe3, (byte) 0x6b, (byte) 0xf0, (byte) 0x52, (byte) 0x7c, (byte) 0x9d,
            (byte) 0x3b, (byte) 0x16, (byte) 0x15, (byte) 0x4b, (byte) 0x82, (byte) 0x46, (byte) 0x5e, (byte) 0xdd,
            (byte) 0x62, (byte) 0x14, (byte) 0x4c, (byte) 0x0a, (byte) 0xc1, (byte) 0xfc, (byte) 0x5a, (byte) 0x18,
            (byte) 0x50, (byte) 0x6a, (byte) 0x22, (byte) 0x44, (byte) 0xba, (byte) 0x44, (byte) 0x9a, (byte) 0xc4,
    };

    private static final byte[] RFC_7748_X25519_THEIR_PUB_KEY = new byte[] {
            (byte) 0x30, (byte) 0x2a, (byte) 0x30, (byte) 0x05, (byte) 0x06, (byte) 0x03, (byte) 0x2b, (byte) 0x65,
            (byte) 0x6e, (byte) 0x03, (byte) 0x21, (byte) 0x00, (byte) 0xe6, (byte) 0xdb, (byte) 0x68, (byte) 0x67,
            (byte) 0x58, (byte) 0x30, (byte) 0x30, (byte) 0xdb, (byte) 0x35, (byte) 0x94, (byte) 0xc1, (byte) 0xa4,
            (byte) 0x24, (byte) 0xb1, (byte) 0x5f, (byte) 0x7c, (byte) 0x72, (byte) 0x66, (byte) 0x24, (byte) 0xec,
            (byte) 0x26, (byte) 0xb3, (byte) 0x35, (byte) 0x3b, (byte) 0x10, (byte) 0xa9, (byte) 0x03, (byte) 0xa6,
            (byte) 0xd0, (byte) 0xab, (byte) 0x1c, (byte) 0x4c,
    };

    private static final byte[] RFC_7748_X25519_SECRET = new byte[] {
            (byte) 0xc3, (byte) 0xda, (byte) 0x55, (byte) 0x37, (byte) 0x9d, (byte) 0xe9, (byte) 0xc6, (byte) 0x90,
            (byte) 0x8e, (byte) 0x94, (byte) 0xea, (byte) 0x4d, (byte) 0xf2, (byte) 0x8d, (byte) 0x08, (byte) 0x4f,
            (byte) 0x32, (byte) 0xec, (byte) 0xcf, (byte) 0x03, (byte) 0x49, (byte) 0x1c, (byte) 0x71, (byte) 0xf7,
            (byte) 0x54, (byte) 0xb4, (byte) 0x07, (byte) 0x55, (byte) 0x77, (byte) 0xa2, (byte) 0x85, (byte) 0x52,
    };

    private PrivateKey rfc7748X25519PrivateKey;
    private PublicKey rfc7748X25519PublicKey;

    @Before
    public void setupKeys() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("XDH");

        rfc7748X25519PrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(RFC_7748_X25519_OUR_PRIV_KEY));
        rfc7748X25519PublicKey = kf.generatePublic(new X509EncodedKeySpec(RFC_7748_X25519_THEIR_PUB_KEY));
    }

    @Test
    public void x25519_keyAgreement_rfc7748_kat_success() throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(rfc7748X25519PrivateKey);
        ka.doPhase(rfc7748X25519PublicKey, true);

        assertArrayEquals(RFC_7748_X25519_SECRET, ka.generateSecret());
    }
}
