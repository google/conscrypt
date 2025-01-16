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

import static java.util.Objects.requireNonNull;

import libcore.util.NonNull;
import libcore.util.Nullable;

import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.ManagerFactoryParameters;

/**
 * Parameters for configuring a {@code KeyManager} that supports PAKE (Password
 * Authenticated Key Exchange).
 *
 * <p>This class holds the necessary information for the {@code KeyManager} to perform PAKE
 * authentication, including the IDs of the client and server involved and the available PAKE
 * options.</p>
 *
 * <p>Instances of this class are immutable. Use the {@link Builder} to create
 * instances.</p>
 *
 * @hide
 */
public final class PakeClientKeyManagerParameters implements ManagerFactoryParameters {
    /**
     * Returns the client identifier.
     *
     * @return The client identifier.
     */
    public @Nullable byte[] getClientId() {
        throw new RuntimeException("Stub!");
    }

    /**
     * Returns the server identifier.
     *
     * @return The server identifier.
     */
    public @Nullable byte[] getServerId() {
        throw new RuntimeException("Stub!");
    }

    /**
     * Returns a copy of the list of available PAKE options.
     *
     * @return A copy of the list of available PAKE options.
     */
    public @NonNull List<PakeOption> getOptions() {
        throw new RuntimeException("Stub!");
    }

    /**
     * A builder for creating {@link PakeClientKeyManagerParameters} instances.
     *
     * @hide
     */
    public static final class Builder {
        /**
         * Sets the ID of the client involved in the PAKE exchange.
         *
         * @param clientId The ID of the client involved in the PAKE exchange.
         * @return This builder.
         */
        public @NonNull Builder setClientId(@Nullable byte[] clientId) {
            throw new RuntimeException("Stub!");
        }

        /**
         * Sets the ID of the server involved in the PAKE exchange.
         *
         * @param serverId The ID of the server involved in the PAKE exchange.
         * @return This builder.
         */
        public @NonNull Builder setServerId(@Nullable byte[] serverId) {
            throw new RuntimeException("Stub!");
        }

        /**
         * Adds a PAKE option.
         *
         * @param option The PAKE option to add.
         * @return This builder.
         * @throws InvalidParameterException If an option with the same algorithm already exists.
         */
        public @NonNull Builder addOption(@NonNull PakeOption option) {
            throw new RuntimeException("Stub!");
        }

        /**
         * Builds a new {@link PakeClientKeyManagerParameters} instance.
         *
         * @return A new {@link PakeClientKeyManagerParameters} instance.
         * @throws InvalidParameterException If no PAKE options are provided.
         */
        public @NonNull PakeClientKeyManagerParameters build() {
            throw new RuntimeException("Stub!");
        }
    }
}
