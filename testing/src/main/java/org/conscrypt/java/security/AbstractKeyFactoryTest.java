/*
 * Copyright (C) 2009 The Android Open Source Project
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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import tests.util.ServiceTester;

public abstract class AbstractKeyFactoryTest<PublicKeySpec extends KeySpec, PrivateKeySpec extends KeySpec> {

    private final String algorithmName;
    private final Class<PublicKeySpec> publicKeySpecClass;
    private final Class<PrivateKeySpec> privateKeySpecClass;

    public AbstractKeyFactoryTest(String algorithmName,
            Class<PublicKeySpec> publicKeySpecClass,
            Class<PrivateKeySpec> privateKeySpecClass) {
        this.algorithmName = algorithmName;
        this.publicKeySpecClass = publicKeySpecClass;
        this.privateKeySpecClass = privateKeySpecClass;
    }

    @Test
    public void testKeyFactory() throws Exception {
        customizeTester(ServiceTester.test("KeyFactory")
            .withAlgorithm(algorithmName)
            // On OpenJDK 7, the SunPKCS11-NSS provider sometimes doesn't accept keys created by
            // other providers in getKeySpec(), so it fails some of the tests.
            .skipProvider("SunPKCS11-NSS")
            // Android Keystore's KeyFactory must be initialized with its own classes, it can't use
            // the standard init() calls
            .skipProvider("AndroidKeyStore"))
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    final KeyFactory factory = KeyFactory.getInstance(algorithm, p);

                    for (KeyPair pair : getKeys()) {
                        final PrivateKeySpec privateKeySpec = factory.getKeySpec(pair.getPrivate(),
                            privateKeySpecClass);
                        PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
                        final PublicKeySpec publicKeySpec = factory.getKeySpec(pair.getPublic(),
                            publicKeySpecClass);
                        PublicKey publicKey = factory.generatePublic(publicKeySpec);
                        check(new KeyPair(publicKey, privateKey));

                        // Test that keys from any other KeyFactory can be translated into working
                        // keys from this KeyFactory
                        customizeTester(ServiceTester.test("KeyFactory")
                            .withAlgorithm(algorithmName)
                            .skipProvider(p.getName())
                            .skipProvider("SunPKCS11-NSS")
                            .skipProvider("AndroidKeyStore"))
                            .run(new ServiceTester.Test() {
                                @Override
                                public void test(Provider p2, String algorithm) throws Exception {
                                    KeyFactory factory2 = KeyFactory.getInstance(algorithm, p2);
                                    PrivateKey privateKey2 = factory2.generatePrivate(privateKeySpec);
                                    PublicKey publicKey2 = factory2.generatePublic(publicKeySpec);

                                    check(new KeyPair((PublicKey) factory.translateKey(publicKey2),
                                        (PrivateKey) factory.translateKey(privateKey2)));
                                }
                            });
                    }
                }
            });
    }

    protected ServiceTester customizeTester(ServiceTester tester) {
        return tester;
    }

    protected void check(KeyPair keyPair) throws Exception {}

    protected List<KeyPair> getKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return Arrays.asList(
            new KeyPair(
                DefaultKeys.getPublicKey(algorithmName),
                DefaultKeys.getPrivateKey(algorithmName)
            )
        );
    }
}
