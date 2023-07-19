/*
 * Copyright (C) 2023 The Android Open Source Project
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
 * limitations under the License
 */

package org.conscrypt;

import static org.conscrypt.HpkeSuite.AEAD_AES_128_GCM;
import static org.conscrypt.HpkeSuite.AEAD_AES_256_GCM;
import static org.conscrypt.HpkeSuite.AEAD_CHACHA20POLY1305;
import static org.conscrypt.HpkeSuite.KDF_HKDF_SHA256;
import static org.conscrypt.HpkeSuite.KEM_DHKEM_X25519_HKDF_SHA256;
import static org.conscrypt.TestUtils.decodeHex;
import static org.conscrypt.TestUtils.encodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import org.conscrypt.java.security.DefaultKeys;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class HpkeTest {
  private static final byte[] DEFAULT_AAD = decodeHex("436f756e742d30");
  private static final byte[] DEFAULT_ENC =
      decodeHex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
  private static final byte[] DEFAULT_INFO =
      decodeHex("4f6465206f6e2061204772656369616e2055726e");

  private static final byte[] DEFAULT_PK =
      decodeHex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
  private static final byte[] DEFAULT_SK =
      decodeHex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");

  private static final byte[] DEFAULT_PT =
      decodeHex("4265617574792069732074727574682c20747275746820626561757479");
  private static final byte[] DEFAULT_CT = decodeHex(
      "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a");

  private static final int DEFAULT_EXPORTER_LENGTH = 32;
  private static final byte[] DEFAULT_EXPORTER_CONTEXT = decodeHex("00");

  @Test
  public void testConstructor_validAlgorithms_noExceptionsThrown() {
    final List<HpkeSuite> supportedSuites = new ArrayList<>();
    supportedSuites.add(new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM));
    supportedSuites.add(new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM));
    supportedSuites.add(new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_CHACHA20POLY1305));

    for (HpkeSuite hpkeSuite : supportedSuites) {
      new HpkeContext(hpkeSuite);
    }
  }

  @Test
  public void testConstructor_invalidKem_throwsArgumentException() {
    final IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> new HpkeSuite(700, KDF_HKDF_SHA256, AEAD_AES_128_GCM));
    assertEquals("KEM 700 not supported.", e.getMessage());
  }

  @Test
  public void testConstructor_invalidKdf_throwsArgumentException() {
    final IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, 800, AEAD_AES_128_GCM));
    assertEquals("KDF 800 not supported.", e.getMessage());
  }

  @Test
  public void testConstructor_invalidAead_throwsArgumentException() {
    final IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, 900));
    assertEquals("AEAD 900 not supported.", e.getMessage());
  }

  @Test
  public void testSealOpen_randomnessResult() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    final byte[] enc1 = hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO);
    final byte[] ciphertext1 = hpkeContext.seal(DEFAULT_PT, /* aad= */ null);

    final byte[] enc2 = hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO);
    final byte[] ciphertext2 = hpkeContext.seal(DEFAULT_PT, /* aad= */ null);

    assertNotNull(enc1);
    assertNotNull(ciphertext1);
    assertNotNull(enc2);
    assertNotNull(ciphertext2);
    assertNotEquals(encodeHex(enc1), encodeHex(enc2));
    assertNotEquals(encodeHex(DEFAULT_PT), encodeHex(ciphertext1));
    assertNotEquals(encodeHex(ciphertext1), encodeHex(ciphertext2));

    hpkeContext.setupBaseRecipient(enc1, privateKey, DEFAULT_INFO);
    byte[] plaintext1 = hpkeContext.open(ciphertext1, /* aad= */ null);

    hpkeContext.setupBaseRecipient(enc2, privateKey, DEFAULT_INFO);
    byte[] plaintext2 = hpkeContext.open(ciphertext2, /* aad= */ null);

    assertNotNull(plaintext1);
    assertNotNull(plaintext2);
    assertArrayEquals(DEFAULT_PT, plaintext1);
    assertArrayEquals(DEFAULT_PT, plaintext2);
  }

  @Test
  public void testSealOpen_aadNullSameAsEmtpy() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    final byte[] enc1 = hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO);
    final byte[] ciphertext1 = hpkeContext.seal(DEFAULT_PT, /* aad= */ null);

    final byte[] enc2 = hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO);
    final byte[] ciphertext2 = hpkeContext.seal(DEFAULT_PT, /* aad= */ new byte[0]);

    assertNotNull(enc1);
    assertNotNull(ciphertext1);
    assertNotNull(enc2);
    assertNotNull(ciphertext2);
    assertNotEquals(encodeHex(enc1), encodeHex(enc2));
    assertNotEquals(encodeHex(DEFAULT_PT), encodeHex(ciphertext1));
    assertNotEquals(encodeHex(ciphertext1), encodeHex(ciphertext2));

    hpkeContext.setupBaseRecipient(enc1, privateKey, DEFAULT_INFO);
    byte[] plaintext1 = hpkeContext.open(ciphertext1, /* aad= */ new byte[0]);

    hpkeContext.setupBaseRecipient(enc2, privateKey, DEFAULT_INFO);
    byte[] plaintext2 = hpkeContext.open(ciphertext2, /* aad= */ null);

    assertNotNull(plaintext1);
    assertNotNull(plaintext2);
    assertArrayEquals(DEFAULT_PT, plaintext1);
    assertArrayEquals(DEFAULT_PT, plaintext2);
  }

  @Test
  public void testSealOpen_infoNullSameAsEmtpy() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    final byte[] enc1 = hpkeContext.setupBaseSender(publicKey, /* info= */ null);
    final byte[] ciphertext1 = hpkeContext.seal(DEFAULT_PT, DEFAULT_AAD);

    final byte[] enc2 = hpkeContext.setupBaseSender(publicKey, /* info= */ new byte[0]);
    final byte[] ciphertext2 = hpkeContext.seal(DEFAULT_PT, DEFAULT_AAD);

    assertNotNull(enc1);
    assertNotNull(ciphertext1);
    assertNotNull(enc2);
    assertNotNull(ciphertext2);
    assertNotEquals(encodeHex(enc1), encodeHex(enc2));
    assertNotEquals(encodeHex(DEFAULT_PT), encodeHex(ciphertext1));
    assertNotEquals(encodeHex(ciphertext1), encodeHex(ciphertext2));

    hpkeContext.setupBaseRecipient(enc1, privateKey, /* info= */ new byte[0]);
    byte[] plaintext1 = hpkeContext.open(ciphertext1, DEFAULT_AAD);

    hpkeContext.setupBaseRecipient(enc2, privateKey, /* info= */ null);
    byte[] plaintext2 = hpkeContext.open(ciphertext2, DEFAULT_AAD);

    assertNotNull(plaintext1);
    assertNotNull(plaintext2);
    assertArrayEquals(DEFAULT_PT, plaintext1);
    assertArrayEquals(DEFAULT_PT, plaintext2);
  }

  @Test
  public void testSealOpen_withKeysFlipped_throwStateException() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PublicKey publicKey = createPublicKey(DEFAULT_SK);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_PK);

    final byte[] enc1 = hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO);
    final byte[] ciphertext1 = hpkeContext.seal(DEFAULT_PT, DEFAULT_AAD);

    hpkeContext.setupBaseRecipient(enc1, privateKey, DEFAULT_INFO);
    assertThrows(IllegalStateException.class, () -> hpkeContext.open(ciphertext1, DEFAULT_AAD));
  }

  @Test
  public void testSeal_missingRequiredParameters_throwNullException() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);

    hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO);
    assertThrows(
        NullPointerException.class, () -> hpkeContext.seal(/* plaintext= */ null, DEFAULT_AAD));
  }

  @Test
  public void testSeal_withoutCallingSetup_throwStateException() {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();

    final IllegalStateException e =
        assertThrows(IllegalStateException.class, () -> hpkeContext.seal(DEFAULT_PT, DEFAULT_AAD));
    assertEquals("Setup sender needs to be called before encryption", e.getMessage());
  }

  @Test
  public void testSeal_callingWrongSetup_throwStateException() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    hpkeContext.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO);
    final IllegalStateException e =
        assertThrows(IllegalStateException.class, () -> hpkeContext.seal(DEFAULT_PT, DEFAULT_AAD));
    assertEquals("Setup sender needs to be called before encryption", e.getMessage());
  }

  @Test
  public void testOpen_missingRequiredParameters_throwNullException() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    hpkeContext.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO);
    assertThrows(
        NullPointerException.class, () -> hpkeContext.open(/* ciphertext= */ null, DEFAULT_AAD));
  }

  @Test
  public void testOpen_withoutCallingSetup_throwStateException() {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();

    final IllegalStateException e =
        assertThrows(IllegalStateException.class, () -> hpkeContext.open(DEFAULT_CT, DEFAULT_AAD));
    assertEquals("Setup recipient needs to be called before decryption", e.getMessage());
  }

  @Test
  public void testOpen_callingWrongSetup_throwStateException() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);

    hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO);
    final IllegalStateException e =
        assertThrows(IllegalStateException.class, () -> hpkeContext.open(DEFAULT_CT, DEFAULT_AAD));
    assertEquals("Setup recipient needs to be called before decryption", e.getMessage());
  }

  @Test
  public void testOpen_validKeyButNotTheRightOne_throwStateException() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PrivateKey privateKey = createPrivateKey(
        decodeHex("497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d"));

    hpkeContext.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO);
    assertThrows(IllegalStateException.class, () -> hpkeContext.open(DEFAULT_CT, DEFAULT_AAD));
  }

  @Test
  public void testOpen_validKeyButWrongEnc_throwStateException() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    final byte[] enc =
        decodeHex("6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256");
    hpkeContext.setupBaseRecipient(enc, privateKey, DEFAULT_INFO);
    assertThrows(IllegalStateException.class, () -> hpkeContext.open(DEFAULT_CT, DEFAULT_AAD));
  }

  @Test
  public void testOpen_invalidCiphertext_throwStateException() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    hpkeContext.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO);
    assertThrows(
        IllegalStateException.class, () -> hpkeContext.open(/* ct= */ new byte[32], DEFAULT_AAD));
  }

  @Test
  public void testExportWithSetupSenderAndReceiver_randomnessResult() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    final byte[] enc = hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO);
    final byte[] export1 = hpkeContext.export(DEFAULT_EXPORTER_LENGTH, DEFAULT_EXPORTER_CONTEXT);

    hpkeContext.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO);
    final byte[] export2 = hpkeContext.export(DEFAULT_EXPORTER_LENGTH, DEFAULT_EXPORTER_CONTEXT);

    assertNotNull(enc);
    assertNotNull(export1);
    assertEquals(DEFAULT_EXPORTER_LENGTH, export1.length);
    assertNotNull(export2);
    assertEquals(DEFAULT_EXPORTER_LENGTH, export2.length);
    assertNotEquals(encodeHex(DEFAULT_ENC), encodeHex(enc));
    assertNotEquals(encodeHex(export1), encodeHex(export2));
  }

  @Test
  public void testExport_withNullValue() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);

    final byte[] enc = hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO);
    final byte[] export = hpkeContext.export(DEFAULT_EXPORTER_LENGTH, /* exporterContext= */ null);

    assertNotNull(enc);
    assertNotNull(export);
    assertEquals(DEFAULT_EXPORTER_LENGTH, export.length);
  }

  @Test
  public void testExport_verifyOutputLength() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);

    final byte[] enc = hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO);
    for (int i = 0; i < 8_000; i += 500) {
      final byte[] export = hpkeContext.export(i, DEFAULT_EXPORTER_CONTEXT);
      assertNotNull(enc);
      assertNotNull(export);
      assertEquals(i, export.length);
    }
  }

  @Test
  public void testExport_lowerEdgeLength() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);

    final byte[] enc = hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO);
    final byte[] export = hpkeContext.export(/* length= */ 0, DEFAULT_EXPORTER_CONTEXT);
    assertNotNull(enc);
    assertNotNull(export);

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpkeContext.export(/* length= */ -1, DEFAULT_EXPORTER_CONTEXT));
    assertEquals("Export length (L) must be between 0 and 8160, but was -1", e.getMessage());
  }

  @Test
  public void testExport_withoutCallingSetup_throwStateException() {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();

    final IllegalStateException e = assertThrows(IllegalStateException.class,
        () -> hpkeContext.export(DEFAULT_EXPORTER_LENGTH, DEFAULT_EXPORTER_CONTEXT));
    assertEquals("Setup sender or recipient needs to be called before export", e.getMessage());
  }

  @Test
  public void testSetupBaseRecipient_encLengthNotMatchingKemSpec_throwArgumentException()
      throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpkeContext.setupBaseRecipient(new byte[1], privateKey, DEFAULT_INFO));
    assertEquals("Expected enc length of 32, but was 1", e.getMessage());
  }

  @Test
  public void testSetupBaseRecipient_skNotMatchingKemSpec_throwArgumentException()
      throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PrivateKey privateKey = createPrivateKey(new byte[1]);

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpkeContext.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO));
    assertEquals("Expected private key length of 32, but was 1", e.getMessage());
  }

  @Test
  public void testSetupBaseRecipient_invalidKeyAlgorithm_throwArgumentException()
      throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PrivateKey privateKey = DefaultKeys.getPrivateKey("DH");

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpkeContext.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO));
    assertEquals("Private key algorithm DH is not supported", e.getMessage());
  }

  @Test
  public void testSetupBaseSender_pkNotMatchingKemSpec_throwArgumentException() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PublicKey publicKey = createPublicKey(new byte[1]);

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO));
    assertEquals("Expected public key length of 32, but was 1", e.getMessage());
  }

  @Test
  public void testSetupBaseSender_invalidKeyAlgorithm_throwArgumentException() throws Exception {
    final HpkeContext hpkeContext = createDefaultHpkeInstance();
    final PublicKey publicKey = DefaultKeys.getPublicKey("DH");

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpkeContext.setupBaseSender(publicKey, DEFAULT_INFO));
    assertEquals("Public key algorithm DH is not supported", e.getMessage());
  }

  private HpkeContext createDefaultHpkeInstance() {
    return new HpkeContext(new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM));
  }

  private static PublicKey createPublicKey(byte[] publicKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    final KeyFactory factory = KeyFactory.getInstance("XDH");
    final KeySpec spec = new SecretKeySpec(publicKey, "RAW");
    return factory.generatePublic(spec);
  }

  private static PrivateKey createPrivateKey(byte[] privateKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    final KeyFactory factory = KeyFactory.getInstance("XDH");
    final KeySpec spec = new SecretKeySpec(privateKey, "RAW");
    return factory.generatePrivate(spec);
  }
}
