/*
 * Copyright (C) 2024 The Android Open Source Project
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

package android.net.ssl;

import libcore.util.NonNull;
import libcore.util.Nullable;

import java.security.InvalidParameterException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * An class representing a PAKE (Password Authenticated Key Exchange)
 * option for TLS connections.
 *
 * <p>Instances of this class are immutable. Use the {@link Builder} to create
 * instances.</p>
 *
 * @hide
 */
public final class PakeOption {
    /**
     * Returns the algorithm of the PAKE algorithm.
     *
     * @return The algorithm of the PAKE algorithm.
     */
    public @NonNull String getAlgorithm() {
        throw new RuntimeException("Stub!");
    }

    /**
     * Returns the message component with the given key.
     *
     * @param key The algorithm of the component.
     * @return The component data, or {@code null} if no component with the given
     *         key exists.
     */
    public @Nullable byte[] getMessageComponent(@NonNull String key) {
        throw new RuntimeException("Stub!");
    }

    /**
     * A builder for creating {@link PakeOption} instances.
     *
     * @hide
     */
    public static final class Builder {
        /**
         * Constructor for the builder.
         *
         * @param algorithm The algorithm of the PAKE algorithm.
         * @throws InvalidParameterException If the algorithm is invalid.
         */
        public Builder(@NonNull String algorithm) {
            throw new RuntimeException("Stub!");
        }

        /**
         * Adds a message component.
         *
         * @param key The algorithm of the component.
         * @param value The component data.
         * @return This builder.
         * @throws InvalidParameterException If the key is invalid.
         */
        public @NonNull Builder addMessageComponent(@NonNull String key, @Nullable byte[] value) {
            throw new RuntimeException("Stub!");
        }

        /**
         * Builds a new {@link PakeOption} instance.
         *
         * <p>This method performs validation to ensure that the message components
         * are consistent with the PAKE algorithm.</p>
         *
         * @return A new {@link PakeOption} instance.
         * @throws InvalidParameterException If the message components are invalid.
         */
        public @NonNull PakeOption build() {
            throw new RuntimeException("Stub!");
        }
    }
}
