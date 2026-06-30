/*
 * Copyright (C) 2026 The Android Open Source Project
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

/** ML-KEM algorithm. */
public enum MlKemAlgorithm {
    // Values from https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf, table 3.
    ML_KEM_768("ML-KEM-768", 1184),
    ML_KEM_1024("ML-KEM-1024", 1568);

    private final String name;
    private final int publicKeySize;

    private MlKemAlgorithm(String name, int publicKeySize) {
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
}
