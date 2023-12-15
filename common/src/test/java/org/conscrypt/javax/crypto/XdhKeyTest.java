/*
 * Copyright 2023 The Android Open Source Project
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
package org.conscrypt.javax.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import org.conscrypt.ArrayUtils;
import org.conscrypt.OpenSSLX25519PrivateKey;
import org.conscrypt.OpenSSLX25519PublicKey;
import org.conscrypt.OpenSSLXDHKeyPairGenerator;
import org.conscrypt.XdhKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class XdhKeyTest {
    private final OpenSSLXDHKeyPairGenerator generator = new OpenSSLXDHKeyPairGenerator();
    private final KeyPair keyPair = generator.generateKeyPair();
    private final OpenSSLX25519PublicKey publicKey = (OpenSSLX25519PublicKey) keyPair.getPublic();
    private final byte[] publicKeyBytes = publicKey.getU();
    private final OpenSSLX25519PrivateKey privateKey = (OpenSSLX25519PrivateKey) keyPair.getPrivate();
    private final byte[] privateKeyBytes = privateKey.getU();

    @Test
    public void constructor() throws Exception {
        assertKeysWork(publicKey, privateKey);
    }

    @Test
    public void publicKey_Raw() throws Exception {
        OpenSSLX25519PublicKey copy = new OpenSSLX25519PublicKey(publicKeyBytes);
        assertEquals(publicKey, copy);
        assertNotSame(publicKey, copy);
        assertKeysWork(copy, privateKey);
        assertThrows(IllegalArgumentException.class,
                () -> new OpenSSLX25519PublicKey(loseOneByte(publicKeyBytes)));
        assertThrows(IllegalArgumentException.class,
                () -> new OpenSSLX25519PublicKey(gainOneByte(publicKeyBytes)));
    }

    @Test
    public void publicKey_RawSpec() throws Exception {
        OpenSSLX25519PublicKey copy = new OpenSSLX25519PublicKey(new XdhKeySpec(publicKeyBytes));
        assertEquals(publicKey, copy);
        assertNotSame(publicKey, copy);
        assertKeysWork(copy, privateKey);

        assertThrows(InvalidKeySpecException.class,
                () -> new OpenSSLX25519PublicKey(new XdhKeySpec(loseOneByte(publicKeyBytes))));
        assertThrows(InvalidKeySpecException.class,
                () -> new OpenSSLX25519PublicKey(new XdhKeySpec(gainOneByte(publicKeyBytes))));
    }

    @Test
    public void publicKey_X509() throws Exception {
        assertEquals("X.509", publicKey.getFormat());
        byte[] x509bytes = publicKey.getEncoded();

        OpenSSLX25519PublicKey copy = new OpenSSLX25519PublicKey(new X509EncodedKeySpec(x509bytes));
        assertEquals(publicKey, copy);
        assertNotSame(publicKey, copy);
        assertKeysWork(copy, privateKey);

        assertThrows(InvalidKeySpecException.class,
                () -> new OpenSSLX25519PublicKey(new X509EncodedKeySpec(privateKeyBytes)));
        assertThrows(InvalidKeySpecException.class,
                () -> new OpenSSLX25519PublicKey(new X509EncodedKeySpec(flipBit(x509bytes))));
        assertThrows(InvalidKeySpecException.class,
                () -> new OpenSSLX25519PublicKey(new X509EncodedKeySpec(loseOneByte(x509bytes))));

        // Should ignore extra data for better JCA compatibility.
        copy = new OpenSSLX25519PublicKey(new X509EncodedKeySpec(gainOneByte(x509bytes)));
        assertEquals(publicKey, copy);
        assertNotSame(publicKey, copy);
        assertKeysWork(copy, privateKey);


    }

    @Test
    public void privateKey_Raw() throws Exception {
        OpenSSLX25519PrivateKey copy = new OpenSSLX25519PrivateKey(privateKeyBytes);
        assertEquals(privateKey, copy);
        assertNotSame(privateKey, copy);
        assertKeysWork(publicKey, copy);

        assertThrows(IllegalArgumentException.class,
                () -> new OpenSSLX25519PrivateKey(loseOneByte(privateKeyBytes)));
        assertThrows(IllegalArgumentException.class,
                () -> new OpenSSLX25519PrivateKey(gainOneByte(privateKeyBytes)));
    }

    @Test
    public void privateKey_RawSpec() throws Exception {
        // Create copy of key via raw EncodedKeySpec
        OpenSSLX25519PrivateKey copy = new OpenSSLX25519PrivateKey(new XdhKeySpec(privateKeyBytes));
        assertEquals(privateKey, copy);
        assertNotSame(privateKey, copy);
        assertKeysWork(publicKey, copy);

        assertThrows(InvalidKeySpecException.class,
                () -> new OpenSSLX25519PrivateKey(new XdhKeySpec(loseOneByte(publicKeyBytes))));
        assertThrows(InvalidKeySpecException.class,
                () -> new OpenSSLX25519PrivateKey(new XdhKeySpec(gainOneByte(publicKeyBytes))));
    }

    @Test
    public void privateKey_PKCS8() throws Exception {
        assertEquals("PKCS#8", privateKey.getFormat());
        byte[] pkcs8Bytes = privateKey.getEncoded();

        OpenSSLX25519PrivateKey copy =
                new OpenSSLX25519PrivateKey(new PKCS8EncodedKeySpec(pkcs8Bytes));
        assertEquals(privateKey, copy);
        assertNotSame(privateKey, copy);
        assertKeysWork(publicKey, copy);

        assertThrows(InvalidKeySpecException.class, () ->
                new OpenSSLX25519PrivateKey(new X509EncodedKeySpec(pkcs8Bytes)));
        assertThrows(InvalidKeySpecException.class, () ->
                new OpenSSLX25519PrivateKey(new PKCS8EncodedKeySpec(flipBit(pkcs8Bytes))));
        assertThrows(InvalidKeySpecException.class, () ->
                new OpenSSLX25519PrivateKey(new PKCS8EncodedKeySpec(loseOneByte(pkcs8Bytes))));

        // EVP_parse_private_key ignores extra data for JCA compatibility.
        copy = new OpenSSLX25519PrivateKey(new PKCS8EncodedKeySpec(gainOneByte(pkcs8Bytes)));
        assertEquals(privateKey, copy);
        assertNotSame(privateKey, copy);
        assertKeysWork(publicKey, copy);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        assertThrows(InvalidKeySpecException.class, () -> new OpenSSLX25519PrivateKey(
                new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded())));
    }

    @Test
    public void destruction() {
        OpenSSLX25519PrivateKey privateCopy = new OpenSSLX25519PrivateKey(privateKeyBytes);
        privateCopy.destroy();
        assertTrue(privateCopy.isDestroyed());
    }

    private void assertKeysWork(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        // Ideally we should check public is derived from private here too, but math is hard.
        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        assertNotNull(ka.generateSecret());
    }

    private byte[] loseOneByte(byte[] input) {
        return Arrays.copyOfRange(input, 0, input.length - 1);
    }

    private byte[] gainOneByte(byte[] input) {
        return ArrayUtils.concat(input, new byte[1]);
    }

    private byte[] flipBit(byte[] input) {
        byte[] corrupted = input.clone();
        // Offset 3 chosen by fair dice roll.
        corrupted[3] = (byte) (corrupted[3] ^ 0x01);
        return corrupted;
    }
}
