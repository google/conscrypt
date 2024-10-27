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
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SignatureHelper extends TestHelper<KeyPair> {

    private final String algorithmName;
    private final String plainData = "some data do sign and verify";

    public SignatureHelper(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    @Override
    public void test(KeyPair keyPair) throws Exception {
        test(keyPair.getPrivate(), keyPair.getPublic());
    }

    public void test(PrivateKey encryptKey, PublicKey decryptKey) throws Exception {
        Signature signature = Signature.getInstance(algorithmName);
        signature.initSign(encryptKey);
        signature.update(plainData.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();

        signature.initVerify(decryptKey);
        signature.update(plainData.getBytes(StandardCharsets.UTF_8));
        assertTrue("signature could not be verified", signature.verify(signed));
    }
}
