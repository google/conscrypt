package org.conscrypt.javax.crypto;

import static org.conscrypt.TestUtils.decodeHex;
import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

/** Tests for all registered XDH {@link KeyAgreement} providers. */
@RunWith(JUnit4.class)
public class XDHKeyAgreementTest {
    // Test vectors from https://datatracker.ietf.org/doc/html/rfc7748#section-5.2.
    private static final String RFC_7748_X25519_INPUT_SCALAR_HEX =
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
    private static final String RFC_7748_X25519_INPUT_U_COORD_HEX =
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
    private static final byte[] RFC_7748_X25519_OUTPUT =
            decodeHex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    private static final byte[] PKCS8_X25519_OUR_PRIV_KEY =
            decodeHex("302e020100300506032b656e04220420" + RFC_7748_X25519_INPUT_SCALAR_HEX);
    private static final byte[] BROKEN_PKCS8_X25519_OUR_PRIV_KEY =
            decodeHex("302e020100300506032b656e0420" + RFC_7748_X25519_INPUT_SCALAR_HEX);
    private static final byte[] X509_X25519_THEIR_PUB_KEY =
            decodeHex("302a300506032b656e032100" + RFC_7748_X25519_INPUT_U_COORD_HEX);

    private void keyAgreementReturnsCorrectSecret(String algorithm) throws Exception {
        final String keyAgreementAlgorithm = String.format("KeyAgreement.%s", algorithm);
        for (Provider p : Security.getProviders(keyAgreementAlgorithm)) {
            // Skip testing Android Keystore as it's covered by CTS tests.
            if ("AndroidKeyStore".equals(p.getName())) {
                continue;
            }

            KeyFactory kf = KeyFactory.getInstance(algorithm, p);

            byte[] pkcs8EncodedPrivateKey;
            if ("SunEC".equalsIgnoreCase(p.getName())
                    && "11".equals(System.getProperty("java.specification.version"))) {
                // SunEC in OpenJDK 11 has a bug where the format specified in RFC 8410
                // Section 7. It uses a single OCTET STRING to represent the key instead
                // of an OCTET STRING inside of an OCTET STRING as defined in the RFC:
                // ("For the keys defined in this document, the private key is always an
                //   opaque byte sequence.  The ASN.1 type CurvePrivateKey is defined in
                //   this document to hold the byte sequence.  Thus, when encoding a
                //   OneAsymmetricKey object, the private key is wrapped in a
                //   CurvePrivateKey object and wrapped by the OCTET STRING of the
                //   "privateKey" field.")
                pkcs8EncodedPrivateKey = BROKEN_PKCS8_X25519_OUR_PRIV_KEY;
            } else {
                pkcs8EncodedPrivateKey = PKCS8_X25519_OUR_PRIV_KEY;
            }

            PrivateKey privateKey =
                    kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedPrivateKey));
            PublicKey publicKey =
                    kf.generatePublic(new X509EncodedKeySpec(X509_X25519_THEIR_PUB_KEY));

            KeyAgreement ka = KeyAgreement.getInstance(algorithm, p);
            ka.init(privateKey);
            ka.doPhase(publicKey, true);

            assertArrayEquals(RFC_7748_X25519_OUTPUT, ka.generateSecret());
        }
    }

    @Test
    public void xdhKeyAgreement_returnsCorrectSecret() throws Exception {
        keyAgreementReturnsCorrectSecret("XDH");
    }

    @Test
    public void x25519KeyAgreement_returnsCorrectSecret() throws Exception {
        keyAgreementReturnsCorrectSecret("X25519");
    }
}
