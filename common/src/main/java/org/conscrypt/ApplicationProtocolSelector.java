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

import java.util.List;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

/**
 * Server-side selector for the ALPN protocol. This is a backward-compatibility shim for Java 9's
 * new {@code setHandshakeApplicationProtocolSelector} API, which takes a {@code BiFunction}
 * (available in Java 8+). This interface is provided to support protocol selection in Java < 8.
 */
public abstract class ApplicationProtocolSelector {
    /**
     * Selects the appropriate ALPN protocol.
     *
     * @param engine the server-side engine
     * @param protocols The list of client-supplied protocols
     * @return The function's result is an application protocol name, or {@code null} to indicate
     * that none of the advertised names are acceptable. If the return value is an empty
     * {@link String} then application protocol indications will not be used. If the return value
     * is {@code null} (no value chosen) or is a value that was not advertised by the peer, a
     * "no_application_protocol" alert will be sent to the peer and the connection will be
     * terminated.
     */
    public abstract String selectApplicationProtocol(SSLEngine engine, List<String> protocols);

    /**
     * Selects the appropriate ALPN protocol.
     *
     * @param socket the server-side socket
     * @param protocols The list of client-supplied protocols
     * @return The function's result is an application protocol name, or {@code null} to indicate
     * that none of the advertised names are acceptable. If the return value is an empty
     * {@link String} then application protocol indications will not be used. If the return value
     * is {@code null} (no value chosen) or is a value that was not advertised by the peer, a
     * "no_application_protocol" alert will be sent to the peer and the connection will be
     * terminated.
     */
    public abstract String selectApplicationProtocol(SSLSocket socket, List<String> protocols);
}
