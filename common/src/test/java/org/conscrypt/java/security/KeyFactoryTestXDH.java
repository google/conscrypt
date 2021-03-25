/*
 * Copyright (C) 2019 The Android Open Source Project
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class KeyFactoryTestXDH extends
    AbstractKeyFactoryTest<X509EncodedKeySpec, PKCS8EncodedKeySpec> {

  public KeyFactoryTestXDH() {
    super("XDH", X509EncodedKeySpec.class, PKCS8EncodedKeySpec.class);
  }

  @Override
  protected void check(KeyPair keyPair) throws Exception {
    new KeyAgreementHelper("XDH").test(keyPair);
  }

  @Override
  protected ServiceTester customizeTester(ServiceTester tester) {
    // TODO: fix this test when Conscrypt's XDH keys can inherit from XECPublicKey and XECPrivateKey
    return tester.skipProvider("SunEC");
  }

  @Override
  protected List<KeyPair> getKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
    return Arrays.asList(
        new KeyPair(
            DefaultKeys.getPublicKey("XDH"),
            DefaultKeys.getPrivateKey("XDH")
        ),
        new KeyPair(
            new TestPublicKey(DefaultKeys.getPublicKey("XDH")),
            new TestPrivateKey(DefaultKeys.getPrivateKey("XDH"))
        )
    );
  }
}
