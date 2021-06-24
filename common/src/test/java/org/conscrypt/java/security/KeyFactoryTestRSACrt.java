/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.conscrypt.java.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

// Similar to KeyFactoryTestRSA, but uses RSAPrivateCrtKeySpec instead of RSAPrivateKeySpec.
@RunWith(JUnit4.class)
public class KeyFactoryTestRSACrt extends
    AbstractKeyFactoryTest<RSAPublicKeySpec, RSAPrivateCrtKeySpec> {

  public KeyFactoryTestRSACrt() {
    super("RSA", RSAPublicKeySpec.class, RSAPrivateCrtKeySpec.class);
  }

  @Override
  protected void check(KeyPair keyPair) throws Exception {
    new CipherAsymmetricCryptHelper("RSA").test(keyPair);
  }

  @Override
  public ServiceTester customizeTester(ServiceTester tester) {
    // BouncyCastle's KeyFactory.engineGetKeySpec() doesn't handle custom PublicKey
    // implmenetations.
    return tester.skipProvider("BC");
  }

  @Test
  public void testExtraBufferSpace_Private() throws Exception {
    PrivateKey privateKey = DefaultKeys.getPrivateKey("RSA");
    assertTrue(privateKey instanceof RSAPrivateCrtKey);

    byte[] encoded = privateKey.getEncoded();
    byte[] longBuffer = new byte[encoded.length + 147];
    System.arraycopy(encoded, 0, longBuffer, 0, encoded.length);
    PrivateKey copy =
            KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(longBuffer));
    assertEquals(privateKey, copy);
  }

  @Test
  public void javaSerialization() throws Exception{
    PrivateKey privateKey = DefaultKeys.getPrivateKey("RSA");
    assertTrue(privateKey instanceof RSAPrivateCrtKey);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream out = new ObjectOutputStream(bos);
    out.writeObject(privateKey);

    ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
    ObjectInputStream in = new ObjectInputStream(bis);
    PrivateKey copy = (PrivateKey) in.readObject();
    assertTrue(copy instanceof RSAPrivateCrtKey);

    assertEquals(privateKey.getFormat(), copy.getFormat());
    assertArrayEquals(privateKey.getEncoded(), copy.getEncoded());
  }
}
