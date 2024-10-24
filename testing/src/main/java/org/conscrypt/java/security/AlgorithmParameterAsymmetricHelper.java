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

import static org.junit.Assert.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;

public class AlgorithmParameterAsymmetricHelper extends TestHelper<AlgorithmParameters> {

    private static final String plainData = "some data to encrypt and decrypt";
    private final String algorithmName;

    public AlgorithmParameterAsymmetricHelper(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    private String baseName() {
        return algorithmName.contains("/")
                ? algorithmName.substring(0, algorithmName.indexOf('/'))
                : algorithmName;
    }

    @Override
    public void test(AlgorithmParameters parameters) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(baseName());
        generator.initialize(1024);
        KeyPair keyPair = generator.generateKeyPair();

        Cipher cipher = Cipher.getInstance(algorithmName);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), parameters);
        byte[] bs = cipher.doFinal(plainData.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), parameters);
        byte[] decrypted = cipher.doFinal(bs);
        assertArrayEquals(plainData.getBytes(StandardCharsets.UTF_8), decrypted);
    }
}
