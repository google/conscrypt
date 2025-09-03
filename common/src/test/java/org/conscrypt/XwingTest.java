/*
 * Copyright (C) 2025 The Android Open Source Project
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

package org.conscrypt;

import static org.conscrypt.HpkeSuite.AEAD_AES_128_GCM;
import static org.conscrypt.HpkeSuite.AEAD_AES_256_GCM;
import static org.conscrypt.HpkeSuite.AEAD_CHACHA20POLY1305;
import static org.conscrypt.HpkeSuite.KDF_HKDF_SHA256;
import static org.conscrypt.HpkeSuite.KEM_XWING;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class XwingTest {
  private final Provider conscryptProvider = TestUtils.getConscryptProvider();

  @BeforeClass
  public static void setUp() {
    TestUtils.assumeAllowsUnsignedCrypto();
  }

  public static final class RawKeySpec extends EncodedKeySpec {
    public RawKeySpec(byte[] encoded) {
      super(encoded);
    }

    @Override
    public String getFormat() {
      return "raw";
    }
  }

  @Test
  public void createKeyAndGetRawKey_works() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("XWING", conscryptProvider);
    KeyPair keyPair = keyGen.generateKeyPair();

    KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);

    EncodedKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
    assertEquals("raw", privateKeySpec.getFormat());
    byte[] rawPrivateKey = privateKeySpec.getEncoded();
    assertEquals(32, rawPrivateKey.length);

    EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
    assertEquals("raw", publicKeySpec.getFormat());
    byte[] rawPublicKey = publicKeySpec.getEncoded();
    assertEquals(1216, rawPublicKey.length);

    PrivateKey privateKey2 = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));
    PublicKey publicKey2 = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));

    assertEquals(keyPair.getPublic(), publicKey2);
    assertEquals(keyPair.getPrivate(), privateKey2);
  }

  @Test
  public void generatePrivate_fromRawPrivateKey_validatesSize() throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);

    PrivateKey unused = keyFactory.generatePrivate(new RawKeySpec(new byte[32]));
    assertThrows(
        InvalidKeySpecException.class,
        () -> keyFactory.generatePrivate(new RawKeySpec(new byte[31])));
    assertThrows(
        InvalidKeySpecException.class,
        () -> keyFactory.generatePrivate(new RawKeySpec(new byte[33])));
  }

  @Test
  public void generatePublic_fromRawPublicKey_validatesSize() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("XWING", conscryptProvider);
    KeyPair keyPair = keyGen.generateKeyPair();
    KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);
    EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
    byte[] rawPublicKey = publicKeySpec.getEncoded();

    PublicKey unused = keyFactory.generatePublic(new RawKeySpec(new byte[rawPublicKey.length]));
    assertThrows(
        InvalidKeySpecException.class,
        () -> keyFactory.generatePublic(new RawKeySpec(new byte[rawPublicKey.length - 1])));
    assertThrows(
        InvalidKeySpecException.class,
        () -> keyFactory.generatePublic(new RawKeySpec(new byte[rawPublicKey.length + 1])));
  }

  @Test
  public void x509AndPkcs8_areNotSupported() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("XWING", conscryptProvider);
    KeyPair keyPair = keyGen.generateKeyPair();

    KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);

    assertThrows(
        UnsupportedOperationException.class,
        () -> keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class));
    assertThrows(
        UnsupportedOperationException.class,
        () -> keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class));
  }

  @Test
  public void serialize_throwsUnsupportedOperationException() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("XWING", conscryptProvider);
    KeyPair keyPair = keyGen.generateKeyPair();

    ObjectOutputStream oos = new ObjectOutputStream(new ByteArrayOutputStream(16384));
    assertThrows(UnsupportedOperationException.class, () -> oos.writeObject(keyPair.getPrivate()));
    assertThrows(UnsupportedOperationException.class, () -> oos.writeObject(keyPair.getPublic()));
  }

  @Test
  public void sealAndOpen_works() throws Exception {
    byte[] info = TestUtils.decodeHex("aa");
    byte[] plaintext = TestUtils.decodeHex("bb");
    byte[] aad = TestUtils.decodeHex("cc");
    for (int aead : new int[] {AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_CHACHA20POLY1305}) {

      HpkeSuite suite = new HpkeSuite(KEM_XWING, KDF_HKDF_SHA256, aead);
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("XWING", conscryptProvider);
      KeyPair keyPairRecipient = keyGen.generateKeyPair();

      HpkeContextSender ctxSender = HpkeContextSender.getInstance(suite.name(), conscryptProvider);
      ctxSender.init(keyPairRecipient.getPublic(), info);

      byte[] encapsulated = ctxSender.getEncapsulated();
      byte[] ciphertext = ctxSender.seal(plaintext, aad);

      HpkeContextRecipient contextRecipient =
          HpkeContextRecipient.getInstance(suite.name(), conscryptProvider);
      contextRecipient.init(encapsulated, keyPairRecipient.getPrivate(), info);
      byte[] output = contextRecipient.open(ciphertext, aad);

      assertArrayEquals(plaintext, output);
    }
  }

  @Test
  public void kemTestVectors_encapsulatedIsCorrect() throws Exception {
    HpkeSuite suite = new HpkeSuite(KEM_XWING, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
    List<TestVector> vectors = TestUtils.readTestVectors("crypto/xwing.txt");
    byte[] unusedInfo = TestUtils.decodeHex("aa");

    for (TestVector vector : vectors) {
      String errMsg = vector.getString("name");
      byte[] eseed = vector.getBytes("eseed");
      byte[] pk = vector.getBytes("pk");
      byte[] ct = vector.getBytes("ct");

      KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);
      PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(pk));

      HpkeContextSender ctxSender = HpkeContextSender.getInstance(suite.name(), conscryptProvider);
      ctxSender.initForTesting(publicKey, unusedInfo, eseed);
      byte[] encapsulated = ctxSender.getEncapsulated();

      assertArrayEquals("test case: " + errMsg, ct, encapsulated);
    }
  }
}

