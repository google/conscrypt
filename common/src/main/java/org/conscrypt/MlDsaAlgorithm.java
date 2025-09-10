/*
 * Copyright 2025 The Android Open Source Project
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

/** ML-DSA algorithm. */
public enum MlDsaAlgorithm {
    ML_DSA_65("ML-DSA-65", 1952),
    ML_DSA_87("ML-DSA-87", 2592);

    private final String name;
    private final int publicKeySize;

    private MlDsaAlgorithm(String name, int publicKeySize) {
        this.name = name;
        this.publicKeySize = publicKeySize;
    }

    @Override
    public String toString() {
        return name;
    }

    public int publicKeySize() {
        return publicKeySize;
    }

    public static MlDsaAlgorithm parse(String name) {
        switch (name) {
            case "ML-DSA-65":
                return ML_DSA_65;
            case "ML-DSA-87":
                return ML_DSA_87;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + name);
        }
    }
}
