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

package javax.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;

@SuppressWarnings({"unused", "DoNotCallSuggester"})
public final class KDF {
    private KDF() {}

    public static KDF getInstance(String algorithm) throws NoSuchAlgorithmException {
        throw new UnsupportedOperationException("Stub!");
    }

    public static KDF getInstance(String algorithm, KDFParameters kdfParameters)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        throw new UnsupportedOperationException("Stub!");
    }

    public static KDF getInstance(String algorithm, Provider provider)
            throws NoSuchAlgorithmException {
        throw new UnsupportedOperationException("Stub!");
    }

    public static KDF getInstance(String algorithm, KDFParameters kdfParameters, Provider provider)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        throw new UnsupportedOperationException("Stub!");
    }

    public static KDF getInstance(String algorithm, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        throw new UnsupportedOperationException("Stub!");
    }

    public static KDF getInstance(String algorithm, KDFParameters kdfParameters, String provider)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                   NoSuchProviderException {
        throw new UnsupportedOperationException("Stub!");
    }

    public String getAlgorithm() {
        throw new UnsupportedOperationException("Stub!");
    }

    public Provider getProvider() {
        throw new UnsupportedOperationException("Stub!");
    }

    public KDFParameters getParameters() {
        throw new UnsupportedOperationException("Stub!");
    }

    public SecretKey deriveKey(String alg, AlgorithmParameterSpec derivationSpec)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        throw new UnsupportedOperationException("Stub!");
    }

    public byte[] deriveData(AlgorithmParameterSpec derivationSpec)
            throws InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("Stub!");
    }
}
