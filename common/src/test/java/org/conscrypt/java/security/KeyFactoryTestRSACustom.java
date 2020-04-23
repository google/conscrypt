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

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

// Similar to KeyFactoryTestRSA, but uses custom RSA PublicKey
// implementation to exercise less common parts of OpenSSLRSAKeyFactory.
@RunWith(JUnit4.class)
public class KeyFactoryTestRSACustom extends
    AbstractKeyFactoryTest<RSAPublicKeySpec, RSAPrivateKeySpec> {

  public KeyFactoryTestRSACustom() {
    super("RSA", RSAPublicKeySpec.class, RSAPrivateKeySpec.class);
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

  @Override
  protected List<KeyPair> getKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
    return Arrays.asList(
        new KeyPair(
            new TestPublicKey(DefaultKeys.getPublicKey("RSA")),
            new TestPrivateKey(DefaultKeys.getPrivateKey("RSA"))
        )
    );
  }
}
