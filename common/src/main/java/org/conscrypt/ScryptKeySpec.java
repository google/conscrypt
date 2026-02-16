/*
 * Copyright (C) 2022 The Android Open Source Project
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

package org.conscrypt;

import java.security.spec.KeySpec;

/**
 * Mirrors the <a
 * href="https://javadoc.io/static/org.bouncycastle/bcprov-jdk15on/1.68/org/bouncycastle/jcajce/spec/ScryptKeySpec.html">class
 * of the same name</a> from BouncyCastle.
 */
public class ScryptKeySpec implements KeySpec {
    private final char[] password;
    private final byte[] salt;
    private final int costParameter;
    private final int blockSize;
    private final int parallelizationParameter;
    private final int keyOutputBits;

    public ScryptKeySpec(char[] password, byte[] salt, int costParameter, int blockSize,
                         int parallelizationParameter, int keyOutputBits) {
        this.password = password;
        this.salt = salt;
        this.costParameter = costParameter;
        this.blockSize = blockSize;
        this.parallelizationParameter = parallelizationParameter;
        this.keyOutputBits = keyOutputBits;
    }

    public char[] getPassword() {
        return password;
    }

    public byte[] getSalt() {
        return salt;
    }

    public int getCostParameter() {
        return costParameter;
    }

    public int getBlockSize() {
        return blockSize;
    }

    public int getParallelizationParameter() {
        return parallelizationParameter;
    }

    public int getKeyLength() {
        return keyOutputBits;
    }
}
