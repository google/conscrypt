/*
 * Copyright 2026 The Android Open Source Project
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

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

/**
 * Internal security provider used by Conscrypt classes to instantiate Conscrypt's own JCA
 * implementations without relying on globally registered security providers.
 */
final class InternalProvider extends Provider {
    private static final Provider INSTANCE = new InternalProvider();

    // Provider(String, String, String) is not available on Android.
    @SuppressWarnings("deprecation")
    private InternalProvider() {
        super("ConscryptInternal", 1.0, "");
        put("AlgorithmParameters.AES", IvParameters.AES.class.getName());
        put("AlgorithmParameters.ChaCha20", IvParameters.ChaCha20.class.getName());
        put("AlgorithmParameters.DESEDE", IvParameters.DESEDE.class.getName());
        put("AlgorithmParameters.GCM", GCMParameters.class.getName());
        put("AlgorithmParameters.XChaCha20", IvParameters.XChaCha20.class.getName());
        put("AlgorithmParameters.OAEP", OAEPParameters.class.getName());
        put("AlgorithmParameters.PSS", PSSParameters.class.getName());
    }

    static AlgorithmParameters getIvParameters(String algorithm, byte[] iv) {
        if (iv == null || iv.length == 0) {
            return null;
        }
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance(algorithm, INSTANCE);
            params.init(new IvParameterSpec(iv));
            return params;
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            return null;
        }
    }

    static AlgorithmParameters getGcmParametersInstance() {
        try {
            return AlgorithmParameters.getInstance("GCM", INSTANCE);
        } catch (NoSuchAlgorithmException e) {
            // We should not get here.
            throw new IllegalStateException("GCM not supported", e);
        }
    }

    static AlgorithmParameters getOaepParametersInstance() {
        try {
            return AlgorithmParameters.getInstance("OAEP", INSTANCE);
        } catch (NoSuchAlgorithmException e) {
            // We should not get here.
            throw new IllegalStateException("OAEP not supported", e);
        }
    }

    static AlgorithmParameters getPssParametersInstance() {
        try {
            return AlgorithmParameters.getInstance("PSS", INSTANCE);
        } catch (NoSuchAlgorithmException e) {
            // We should not get here.
            throw new IllegalStateException("PSS not supported", e);
        }
    }

}
