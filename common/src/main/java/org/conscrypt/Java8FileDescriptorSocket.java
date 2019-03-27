/*
 * Copyright 2017 The Android Open Source Project
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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

/**
 * A version of ConscryptFileDescriptorSocket that includes the new Java 9 (and potentially later
 * patches of 8) {@code setHandshakeApplicationProtocolSelector} API (which requires Java 8 for
 * compilation, due to the use of {@link BiFunction}).
 */
final class Java8FileDescriptorSocket extends ConscryptFileDescriptorSocket {
    private BiFunction<SSLSocket, List<String>, String> selector;

    Java8FileDescriptorSocket(SSLParametersImpl sslParameters) throws IOException {
        super(sslParameters);
    }

    Java8FileDescriptorSocket(String hostname, int port, SSLParametersImpl sslParameters)
            throws IOException {
        super(hostname, port, sslParameters);
    }

    Java8FileDescriptorSocket(InetAddress address, int port, SSLParametersImpl sslParameters)
            throws IOException {
        super(address, port, sslParameters);
    }

    Java8FileDescriptorSocket(String hostname, int port, InetAddress clientAddress, int clientPort,
            SSLParametersImpl sslParameters) throws IOException {
        super(hostname, port, clientAddress, clientPort, sslParameters);
    }

    Java8FileDescriptorSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort,
            SSLParametersImpl sslParameters) throws IOException {
        super(address, port, clientAddress, clientPort, sslParameters);
    }

    Java8FileDescriptorSocket(Socket socket, String hostname, int port, boolean autoClose,
            SSLParametersImpl sslParameters) throws IOException {
        super(socket, hostname, port, autoClose, sslParameters);
    }

    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java < 9.
    public void setHandshakeApplicationProtocolSelector(
            final BiFunction<SSLSocket, List<String>, String> selector) {
        this.selector = selector;
        setApplicationProtocolSelector(toApplicationProtocolSelector(selector));
    }

    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java < 9.
    public BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return selector;
    }

    private static ApplicationProtocolSelector toApplicationProtocolSelector(
        final BiFunction<SSLSocket, List<String>, String> selector) {
        return selector == null ? null : new ApplicationProtocolSelector() {
            @Override
            public String selectApplicationProtocol(SSLEngine socket, List<String> protocols) {
                throw new UnsupportedOperationException();
            }

            @Override
            public String selectApplicationProtocol(SSLSocket socket, List<String> protocols) {
                return selector.apply(socket, protocols);
            }
        };
    }
}
