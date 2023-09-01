/*
 * Copyright (C) 2023 The Android Open Source Project
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

import static org.conscrypt.TestUtils.decodeHex;

import java.util.HashMap;
import java.util.Map;

public final class TestVector {
    private final Map<String, String> map = new HashMap<>();

    public void put(String label, String value) {
        map.put(label, value);
    }
    public String getString(String label) {
        return map.get(label);
    }

    public byte[] getBytes(String label) {
        return decodeHex(getString(label));
    }

    public byte[] getBytesOrEmpty(String label) {
        return contains(label) ? getBytes(label) : new byte[0];
    }

    public int getInt(String label) {
        return Integer.parseInt(getString(label));
    }

    public boolean contains(String label) {
        return map.containsKey(label);
    }

    @Override
    public String toString() {
        return map.toString();
    }
}
