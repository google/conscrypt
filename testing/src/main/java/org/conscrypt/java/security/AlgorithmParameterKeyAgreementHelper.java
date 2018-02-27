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

import static org.junit.Assert.assertNotNull;

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyAgreement;

public class AlgorithmParameterKeyAgreementHelper extends TestHelper<AlgorithmParameters> {

    private final String algorithmName;

    public AlgorithmParameterKeyAgreementHelper(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    @Override
    public void test(AlgorithmParameters parameters) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithmName);
        generator.initialize(1024);

        KeyPair keyPair = generator.generateKeyPair();
        KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithmName);
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(keyPair.getPublic(), true);
        assertNotNull("generated secret is null", keyAgreement.generateSecret());
    }
}
