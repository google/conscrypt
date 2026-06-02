package org.conscrypt.javax.crypto;

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

/**
 * Tests for all registered X25519 {@link KeyAgreement} providers.
 */
@RunWith(JUnit4.class)
public class X25519KeyAgreementTest extends XDHKeyAgreementTest {
    @Override
    protected String getAlgorithm() {
        return "X25519";
    }
}
