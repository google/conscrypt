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
    supportedSuites.add(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    supportedSuites.add(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM);
    supportedSuites.add(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20POLY1305);

    for (HpkeSuite hpkeSuite : supportedSuites) {
      new Hpke(hpkeSuite);
    }
  }

  @Test
  public void testSealOpen_randomnessResult() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    hpke.setupBaseSender(publicKey, DEFAULT_INFO);
    HpkeResult result1 = hpke.seal(DEFAULT_PT, /* aad= */ null);

    hpke.setupBaseSender(publicKey, DEFAULT_INFO);
    HpkeResult result2 = hpke.seal(DEFAULT_PT, /* aad= */ null);

    assertNotNull(result1);
    assertNotNull(result1.getEnc());
    assertNotNull(result1.getOutput());
    assertNotNull(result2);
    assertNotNull(result2.getEnc());
    assertNotNull(result2.getOutput());
    assertNotEquals(encodeHex(result1.getEnc()), encodeHex(result2.getEnc()));
    assertNotEquals(encodeHex(DEFAULT_PT), encodeHex(result1.getOutput()));
    assertNotEquals(encodeHex(result1.getOutput()), encodeHex(result2.getOutput()));

    hpke.setupBaseRecipient(result1.getEnc(), privateKey, DEFAULT_INFO);
    byte[] plaintext1 = hpke.open(result1.getOutput(), /* aad= */ null);

    hpke.setupBaseRecipient(result2.getEnc(), privateKey, DEFAULT_INFO);
    byte[] plaintext2 = hpke.open(result2.getOutput(), /* aad= */ null);

    assertNotNull(plaintext1);
    assertNotNull(plaintext2);
    assertArrayEquals(DEFAULT_PT, plaintext1);
    assertArrayEquals(DEFAULT_PT, plaintext2);
  }

  @Test
  public void testSealOpen_aadNullSameAsEmtpy() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    hpke.setupBaseSender(publicKey, DEFAULT_INFO);
    HpkeResult result1 = hpke.seal(DEFAULT_PT, /* aad= */ null);

    hpke.setupBaseSender(publicKey, DEFAULT_INFO);
    HpkeResult result2 = hpke.seal(DEFAULT_PT, /* aad= */ new byte[0]);

    assertNotNull(result1);
    assertNotNull(result1.getEnc());
    assertNotNull(result1.getOutput());
    assertNotNull(result2);
    assertNotNull(result2.getEnc());
    assertNotNull(result2.getOutput());
    assertNotEquals(encodeHex(result1.getEnc()), encodeHex(result2.getEnc()));
    assertNotEquals(encodeHex(DEFAULT_PT), encodeHex(result1.getOutput()));
    assertNotEquals(encodeHex(result1.getOutput()), encodeHex(result2.getOutput()));

    hpke.setupBaseRecipient(result1.getEnc(), privateKey, DEFAULT_INFO);
    byte[] plaintext1 = hpke.open(result1.getOutput(), /* aad= */ new byte[0]);

    hpke.setupBaseRecipient(result2.getEnc(), privateKey, DEFAULT_INFO);
    byte[] plaintext2 = hpke.open(result2.getOutput(), /* aad= */ null);

    assertNotNull(plaintext1);
    assertNotNull(plaintext2);
    assertArrayEquals(DEFAULT_PT, plaintext1);
    assertArrayEquals(DEFAULT_PT, plaintext2);
  }

  @Test
  public void testSealOpen_infoNullSameAsEmtpy() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    hpke.setupBaseSender(publicKey, /* info= */ null);
    HpkeResult result1 = hpke.seal(DEFAULT_PT, DEFAULT_AAD);

    hpke.setupBaseSender(publicKey, /* info= */ new byte[0]);
    HpkeResult result2 = hpke.seal(DEFAULT_PT, DEFAULT_AAD);

    assertNotNull(result1);
    assertNotNull(result1.getEnc());
    assertNotNull(result1.getOutput());
    assertNotNull(result2);
    assertNotNull(result2.getEnc());
    assertNotNull(result2.getOutput());
    assertNotEquals(encodeHex(result1.getEnc()), encodeHex(result2.getEnc()));
    assertNotEquals(encodeHex(DEFAULT_PT), encodeHex(result1.getOutput()));
    assertNotEquals(encodeHex(result1.getOutput()), encodeHex(result2.getOutput()));

    hpke.setupBaseRecipient(result1.getEnc(), privateKey, /* info= */ new byte[0]);
    byte[] plaintext1 = hpke.open(result1.getOutput(), DEFAULT_AAD);

    hpke.setupBaseRecipient(result2.getEnc(), privateKey, /* info= */ null);
    byte[] plaintext2 = hpke.open(result2.getOutput(), DEFAULT_AAD);

    assertNotNull(plaintext1);
    assertNotNull(plaintext2);
    assertArrayEquals(DEFAULT_PT, plaintext1);
    assertArrayEquals(DEFAULT_PT, plaintext2);
  }

  @Test
  public void testSealOpen_withKeysFlipped_throwStateException() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = createPublicKey(DEFAULT_SK);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_PK);

    hpke.setupBaseSender(publicKey, DEFAULT_INFO);
    HpkeResult result = hpke.seal(DEFAULT_PT, DEFAULT_AAD);

    hpke.setupBaseRecipient(result.getEnc(), privateKey, DEFAULT_INFO);
    assertThrows(IllegalStateException.class, () -> hpke.open(result.getOutput(), DEFAULT_AAD));
  }

  @Test
  public void testSeal_missingRequiredParameters_throwNullException() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);

    hpke.setupBaseSender(publicKey, DEFAULT_INFO);
    assertThrows(
        NullPointerException.class, () -> hpke.seal(/* plaintext= */ null, DEFAULT_AAD));
  }

  @Test
  public void testSeal_withoutCallingSetup_throwStateException() {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);

    final IllegalStateException e =
        assertThrows(IllegalStateException.class, () -> hpke.seal(DEFAULT_PT, DEFAULT_AAD));
    assertEquals("Setup sender needs to be called before encryption", e.getMessage());
  }

  @Test
  public void testSeal_callingWrongSetup_throwStateException() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    hpke.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO);
    final IllegalStateException e =
        assertThrows(IllegalStateException.class, () -> hpke.seal(DEFAULT_PT, DEFAULT_AAD));
    assertEquals("Setup sender needs to be called before encryption", e.getMessage());
  }

  @Test
  public void testOpen_missingRequiredParameters_throwNullException() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    hpke.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO);
    assertThrows(
        NullPointerException.class, () -> hpke.open(/* ciphertext= */ null, DEFAULT_AAD));
  }

  @Test
  public void testOpen_withoutCallingSetup_throwStateException() {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);

    final IllegalStateException e =
        assertThrows(IllegalStateException.class, () -> hpke.open(DEFAULT_CT, DEFAULT_AAD));
    assertEquals("Setup recipient needs to be called before decryption", e.getMessage());
  }

  @Test
  public void testOpen_callingWrongSetup_throwStateException() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);

    hpke.setupBaseSender(publicKey, DEFAULT_INFO);
    final IllegalStateException e =
        assertThrows(IllegalStateException.class, () -> hpke.open(DEFAULT_CT, DEFAULT_AAD));
    assertEquals("Setup recipient needs to be called before decryption", e.getMessage());
  }

  @Test
  public void testOpen_validKeyButNotTheRightOne_throwStateException() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PrivateKey privateKey = createPrivateKey(
        decodeHex("497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d"));

    hpke.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO);
    assertThrows(IllegalStateException.class, () -> hpke.open(DEFAULT_CT, DEFAULT_AAD));
  }

  @Test
  public void testOpen_validKeyButWrongEnc_throwStateException() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    final byte[] enc =
        decodeHex("6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256");
    hpke.setupBaseRecipient(enc, privateKey, DEFAULT_INFO);
    assertThrows(IllegalStateException.class, () -> hpke.open(DEFAULT_CT, DEFAULT_AAD));
  }

  @Test
  public void testOpen_invalidCiphertext_throwStateException() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    hpke.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO);
    assertThrows(
        IllegalStateException.class, () -> hpke.open(/* ct= */ new byte[32], DEFAULT_AAD));
  }

  @Test
  public void testExportWithSetupSenderAndReceiver_randomnessResult() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    hpke.setupBaseSender(publicKey, DEFAULT_INFO);
    final HpkeResult result1 = hpke.export(DEFAULT_EXPORTER_LENGTH, DEFAULT_EXPORTER_CONTEXT);

    hpke.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO);
    final HpkeResult result2 = hpke.export(DEFAULT_EXPORTER_LENGTH, DEFAULT_EXPORTER_CONTEXT);

    assertNotNull(result1);
    assertNotNull(result1.getEnc());
    assertNotNull(result1.getOutput());
    assertEquals(DEFAULT_EXPORTER_LENGTH, result1.getOutput().length);
    assertNotNull(result2);
    assertNotNull(result2.getEnc());
    assertNotNull(result2.getOutput());
    assertEquals(DEFAULT_EXPORTER_LENGTH, result2.getOutput().length);
    assertNotEquals(encodeHex(result1.getEnc()), encodeHex(result2.getEnc()));
    assertNotEquals(encodeHex(result1.getOutput()), encodeHex(result2.getOutput()));
  }

  @Test
  public void testExport_withNullValue() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);

    hpke.setupBaseSender(publicKey, DEFAULT_INFO);
    final HpkeResult result = hpke.export(DEFAULT_EXPORTER_LENGTH, /* exporterContext= */ null);

    assertNotNull(result);
    assertNotNull(result.getEnc());
    assertNotNull(result.getOutput());
    assertEquals(DEFAULT_EXPORTER_LENGTH, result.getOutput().length);
  }

  @Test
  public void testExport_verifyOutputLength() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);

    hpke.setupBaseSender(publicKey, DEFAULT_INFO);
    for (int i = 0; i < 8_000; i += 500) {
      HpkeResult result = hpke.export(i, DEFAULT_EXPORTER_CONTEXT);
      assertNotNull(result);
      assertNotNull(result.getEnc());
      assertNotNull(result.getOutput());
      assertEquals(i, result.getOutput().length);
    }
  }

  @Test
  public void testExport_lowerEdgeLength() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);

    hpke.setupBaseSender(publicKey, DEFAULT_INFO);
    final HpkeResult result = hpke.export(/* length= */ 0, DEFAULT_EXPORTER_CONTEXT);
    assertNotNull(result);
    assertNotNull(result.getEnc());
    assertNotNull(result.getOutput());

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpke.export(/* length= */ -1, DEFAULT_EXPORTER_CONTEXT));
    assertEquals("Export length (L) must be between 0 and 8160, but was -1", e.getMessage());
  }

  @Test
  public void testExport_upperEdgeLength() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = createPublicKey(DEFAULT_PK);

    hpke.setupBaseSender(publicKey, DEFAULT_INFO);
    final HpkeResult result = hpke.export(/* length= */ 8160, DEFAULT_EXPORTER_CONTEXT);
    assertNotNull(result);
    assertNotNull(result.getEnc());
    assertNotNull(result.getOutput());

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpke.export(/* length= */ 8161, DEFAULT_EXPORTER_CONTEXT));
    assertEquals("Export length (L) must be between 0 and 8160, but was 8161", e.getMessage());
  }

  @Test
  public void testExport_withoutCallingSetup_throwStateException() {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);

    final IllegalStateException e = assertThrows(IllegalStateException.class,
        () -> hpke.export(DEFAULT_EXPORTER_LENGTH, DEFAULT_EXPORTER_CONTEXT));
    assertEquals("Setup sender or recipient needs to be called before export", e.getMessage());
  }

  @Test
  public void testSetupBaseRecipient_encLengthNotMatchingKemSpec_throwArgumentException()
      throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpke.setupBaseRecipient(new byte[1], privateKey, DEFAULT_INFO));
    assertEquals("Expected enc length of 32, but was 1", e.getMessage());
  }

  @Test
  public void testSetupBaseRecipient_skNotMatchingKemSpec_throwArgumentException()
      throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PrivateKey privateKey = createPrivateKey(new byte[1]);

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpke.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO));
    assertEquals("Expected private key length of 32, but was 1", e.getMessage());
  }

  @Test
  public void testSetupBaseRecipient_invalidKeyAlgorithm_throwArgumentException()
      throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PrivateKey privateKey = DefaultKeys.getPrivateKey("DH");

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpke.setupBaseRecipient(DEFAULT_ENC, privateKey, DEFAULT_INFO));
    assertEquals("Private key algorithm DH is not supported", e.getMessage());
  }

  @Test
  public void testSetupBaseSender_pkNotMatchingKemSpec_throwArgumentException() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = createPublicKey(new byte[1]);

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpke.setupBaseSender(publicKey, DEFAULT_INFO));
    assertEquals("Expected public key length of 32, but was 1", e.getMessage());
  }

  @Test
  public void testSetupBaseSender_invalidKeyAlgorithm_throwArgumentException() throws Exception {
    final Hpke hpke = new Hpke(HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
    final PublicKey publicKey = DefaultKeys.getPublicKey("DH");

    final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> hpke.setupBaseSender(publicKey, DEFAULT_INFO));
    assertEquals("Public key algorithm DH is not supported", e.getMessage());
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
