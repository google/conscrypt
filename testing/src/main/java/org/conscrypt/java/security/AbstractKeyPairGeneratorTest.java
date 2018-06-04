/*
 * Copyright (C) 2008 The Android Open Source Project
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

package org.conscrypt.java.security;

import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.Before;
import org.junit.Test;

public abstract class AbstractKeyPairGeneratorTest {

    private final String algorithmName;
    private final TestHelper<KeyPair> helper;

    private KeyPairGenerator generator;

    protected AbstractKeyPairGeneratorTest(String algorithmName, TestHelper<KeyPair> helper) {
        this.algorithmName = algorithmName;
        this.helper = helper;
    }

    @Before
    public void setUp() throws Exception {
        generator = KeyPairGenerator.getInstance(algorithmName);
    }

    @Test
    public void testKeyPairGenerator() throws Exception {
        generator.initialize(1024);

        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull("no keypair generated", keyPair);
        assertNotNull("no public key generated", keyPair.getPublic());
        assertNotNull("no private key generated", keyPair.getPrivate());

        helper.test(keyPair);
    }
}
