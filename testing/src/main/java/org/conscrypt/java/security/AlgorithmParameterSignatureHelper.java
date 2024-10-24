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

import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;

public class AlgorithmParameterSignatureHelper<T extends AlgorithmParameterSpec>
        extends TestHelper<AlgorithmParameters> {

    private final String algorithmName;
    private final String keyPairAlgorithmName;
    private final String plainData = "some data do sign and verify";
    private final Class<T> parameterSpecClass;

    public AlgorithmParameterSignatureHelper(String algorithmName, Class<T> parameterSpecCla1ss) {
        this.algorithmName = algorithmName;
        this.keyPairAlgorithmName = algorithmName;
        this.parameterSpecClass = parameterSpecCla1ss;
    }

    public AlgorithmParameterSignatureHelper(String algorithmName, String keyPairAlgorithmName,
            Class<T> parameterSpecCla1ss) {
        this.algorithmName = algorithmName;
        this.keyPairAlgorithmName = keyPairAlgorithmName;
        this.parameterSpecClass = parameterSpecCla1ss;
    }

    @Override
    public void test(AlgorithmParameters parameters) throws Exception {
        Signature signature = Signature.getInstance(algorithmName);
        T parameterSpec = parameters.getParameterSpec(parameterSpecClass);
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyPairAlgorithmName);

        generator.initialize(parameterSpec);
        KeyPair keyPair = generator.genKeyPair();

        signature.initSign(keyPair.getPrivate());
        signature.update(plainData.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();

        signature.initVerify(keyPair.getPublic());
        signature.update(plainData.getBytes(StandardCharsets.UTF_8));
        assertTrue("signature should verify", signature.verify(signed));
    }
}
