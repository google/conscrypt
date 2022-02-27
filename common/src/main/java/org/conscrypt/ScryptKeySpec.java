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

public class ScryptKeySpec implements KeySpec {
    private final byte[] password;
    private final byte[] salt;
    private final long n;
    private final long r;
    private final long p;
    private final int keyLength;

    public ScryptKeySpec(byte[] password, byte[] salt, long n, long r, long p, int keyLength) {
        this.password = password;
        this.salt = salt;
        this.n = n;
        this.r = r;
        this.p = p;
        this.keyLength = keyLength;
    }

    public byte[] getPassword() {
        return password;
    }

    public byte[] getSalt() {
        return salt;
    }

    public long getN() {
        return n;
    }

    public long getR() {
        return r;
    }

    public long getP() {
        return p;
    }

    public int getKeyLength() {
        return keyLength;
    }
}
