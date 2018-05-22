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

import static org.junit.Assert.assertEquals;

import java.security.Key;
import javax.crypto.Cipher;

public abstract class CipherHelper<T> extends TestHelper<T> {

    private final String algorithmName;
    private final String plainData;
    private final int mode1;
    private final int mode2;

    public CipherHelper(String algorithmName, String plainData, int mode1, int mode2) {
        this.algorithmName = algorithmName;
        this.plainData = plainData;
        this.mode1 = mode1;
        this.mode2 = mode2;
    }

    public void test(Key encryptKey, Key decryptKey) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithmName);
        cipher.init(mode1, encryptKey);
        byte[] encrypted = cipher.doFinal(plainData.getBytes("UTF-8"));

        cipher.init(mode2, decryptKey);
        byte[] decrypted = cipher.doFinal(encrypted);
        String decryptedString = new String(decrypted, "UTF-8");

        assertEquals("transformed data does not match", plainData, decryptedString);
    }
}
