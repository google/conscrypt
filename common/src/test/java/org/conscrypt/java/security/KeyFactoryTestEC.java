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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class KeyFactoryTestEC extends AbstractKeyFactoryTest<ECPublicKeySpec, ECPrivateKeySpec> {
    public KeyFactoryTestEC() {
        super("EC", ECPublicKeySpec.class, ECPrivateKeySpec.class);
    }

    @Override
    public ServiceTester customizeTester(ServiceTester tester) {
        // BC's EC keys always use explicit params, even though it's a bad idea, and we don't
        // support those, so don't test BC keys
        return tester.skipProvider("BC");
    }

    @Override
    protected void check(KeyPair keyPair) throws Exception {
        new SignatureHelper("SHA256withECDSA").test(keyPair);
    }

    @Override
    protected List<KeyPair> getKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return Arrays.asList(
                new KeyPair(DefaultKeys.getPublicKey("EC"), DefaultKeys.getPrivateKey("EC")),
                new KeyPair(new TestPublicKey(DefaultKeys.getPublicKey("EC")),
                        new TestPrivateKey(DefaultKeys.getPrivateKey("EC"))),
                new KeyPair(new TestECPublicKey((ECPublicKey) DefaultKeys.getPublicKey("EC")),
                        new TestECPrivateKey((ECPrivateKey) DefaultKeys.getPrivateKey("EC"))));
    }

    @Test
    public void shouldThrowInvalidKeySpecException_whenKeySpecIsOdd() throws Exception {
        Provider p = Security.getProvider(StandardNames.JSSE_PROVIDER_NAME);
        final KeyFactory factory = KeyFactory.getInstance("EC", p);

        try {
            assertThat(factory.getKeySpec(
                               new TestECPublicKey((ECPublicKey) DefaultKeys.getPublicKey("EC")),
                               FakeECPublicKeySpec.class),
                    instanceOf(FakeECPublicKeySpec.class));
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            assertThat(
                    factory.getKeySpec(DefaultKeys.getPublicKey("EC"), FakeECPublicKeySpec.class),
                    instanceOf(FakeECPublicKeySpec.class));
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            assertThat(factory.getKeySpec(
                               new TestECPrivateKey((ECPrivateKey) DefaultKeys.getPrivateKey("EC")),
                               FakeECPrivateKeySpec.class),
                    instanceOf(FakeECPrivateKeySpec.class));
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            assertThat(
                    factory.getKeySpec(DefaultKeys.getPrivateKey("EC"), FakeECPrivateKeySpec.class),
                    instanceOf(FakeECPrivateKeySpec.class));
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            assertThat(factory.getKeySpec(DefaultKeys.getPrivateKey("EC"), FakePKCS8.class),
                    instanceOf(FakePKCS8.class));
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            assertThat(factory.getKeySpec(DefaultKeys.getPublicKey("EC"), FakeX509.class),
                    instanceOf(FakeX509.class));
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }
    }

    private static class FakeECPublicKeySpec extends ECPublicKeySpec {
        public FakeECPublicKeySpec(ECPoint w, ECParameterSpec params) {
            super(w, params);
        }
    }

    private static class FakeECPrivateKeySpec extends ECPrivateKeySpec {
        public FakeECPrivateKeySpec(BigInteger s, ECParameterSpec params) {
            super(s, params);
        }
    }

    private static class FakePKCS8 extends PKCS8EncodedKeySpec {
        public FakePKCS8(byte[] encodedKey) {
            super(encodedKey);
        }
    }

    private static class FakeX509 extends X509EncodedKeySpec {
        public FakeX509(byte[] encodedKey) {
            super(encodedKey);
        }
    }
}
