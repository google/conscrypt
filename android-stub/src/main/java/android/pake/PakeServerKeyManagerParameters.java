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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.ManagerFactoryParameters;

/**
 * Parameters for configuring a {@code KeyManager} that supports PAKE
 * (Password Authenticated Key Exchange) on the server side.
 *
 * <p>This class holds the necessary information for the {@code KeyManager} to perform PAKE
 * authentication, including a mapping of client and server IDs (links) to their corresponding PAKE
 * options.</p>
 *
 * <p>Instances of this class are immutable. Use the {@link Builder} to create
 * instances.</p>
 *
 * @hide
 */
public final class PakeServerKeyManagerParameters implements ManagerFactoryParameters {
    /**
     * Returns a set of the links.
     *
     * @return The known links.
     */
    public @NonNull Set<Link> getLinks() {
        throw new RuntimeException("Stub!");
    }

    /**
     * Returns an unmodifiable list of PAKE options for the given {@link Link}.
     *
     * @param link The link for which to retrieve the options. Should have been obtained through
     *             {@link #getLinks}.
     * @return An unmodifiable list of PAKE options for the given link.
     */
    public @NonNull List<PakeOption> getOptions(@NonNull Link link) {
        throw new RuntimeException("Stub!");
    }

    /**
     * Returns an unmodifiable list of PAKE options for the given client-server pair.
     *
     * @param clientId The client identifier for the link.
     * @param serverId The server identifier for the link.
     * @return An unmodifiable list of PAKE options for the given link.
     */
    public @NonNull List<PakeOption> getOptions(
            @Nullable byte[] clientId, @Nullable byte[] serverId) {
        throw new RuntimeException("Stub!");
    }

    /**
     * A PAKE link class combining the client and server IDs.
     *
     * @hide
     */
    public static final class Link {
        /**
         * Constructs a {@code Link} object.
         *
         * @param clientId The client identifier for the link.
         * @param serverId The server identifier for the link.
         */
        private Link(@Nullable byte[] clientId, @Nullable byte[] serverId) {
            throw new RuntimeException("Stub!");
        }

        /**
         * Returns the client identifier for the link.
         *
         * @return The client identifier for the link.
         */
        public @Nullable byte[] getClientId() {
            throw new RuntimeException("Stub!");
        }

        /**
         * Returns the server identifier for the link.
         *
         * @return The server identifier for the link.
         */
        public @Nullable byte[] getServerId() {
            throw new RuntimeException("Stub!");
        }

        @Override
        public boolean equals(Object o) {
            throw new RuntimeException("Stub!");
        }

        @Override
        public int hashCode() {
            throw new RuntimeException("Stub!");
        }
    }

    /**
     * A builder for creating {@link PakeServerKeyManagerParameters} instances.
     *
     * @hide
     */
    public static final class Builder {
        /**
         * Adds PAKE options for the given client and server IDs.
         * Only the first link for SPAKE2PLUS_PRERELEASE will be used.
         *
         * @param clientId The client ID.
         * @param serverId The server ID.
         * @param options The list of PAKE options to add.
         * @return This builder.
         * @throws InvalidParameterException If the provided options are invalid.
         */
        public @NonNull Builder setOptions(@Nullable byte[] clientId, @Nullable byte[] serverId,
                @NonNull List<PakeOption> options) {
            throw new RuntimeException("Stub!");
        }

        /**
         * Builds a new {@link PakeServerKeyManagerParameters} instance.
         *
         * @return A new {@link PakeServerKeyManagerParameters} instance.
         * @throws InvalidParameterException If no links are provided.
         */
        public @NonNull PakeServerKeyManagerParameters build() {
            throw new RuntimeException("Stub!");
        }
    }
}
