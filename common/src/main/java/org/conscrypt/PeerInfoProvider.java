/*
 * Copyright (C) 2017 The Android Open Source Project
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

/**
 * A provider for the peer host and port information.
 */
abstract class PeerInfoProvider {
    private static final PeerInfoProvider NULL_PEER_INFO_PROVIDER = new PeerInfoProvider() {
        @Override
        String getHostname() {
            return null;
        }

        @Override
        public String getHostnameOrIP() {
            return null;
        }

        @Override
        public int getPort() {
            return -1;
        }
    };

    /**
     * Returns the hostname supplied during engine/socket creation. No DNS resolution is
     * attempted before returning the hostname.
     */
    abstract String getHostname();

    /**
     * This method attempts to create a textual representation of the peer host or IP. Does
     * not perform a reverse DNS lookup. This is typically used during session creation.
     */
    abstract String getHostnameOrIP();

    /**
     * Gets the port of the peer.
     */
    abstract int getPort();

    static PeerInfoProvider nullProvider() {
        return NULL_PEER_INFO_PROVIDER;
    }

    static PeerInfoProvider forHostAndPort(final String host, final int port) {
        return new PeerInfoProvider() {
            @Override
            String getHostname() {
                return host;
            }

            @Override
            public String getHostnameOrIP() {
                return host;
            }

            @Override
            public int getPort() {
                return port;
            }
        };
    }
}
