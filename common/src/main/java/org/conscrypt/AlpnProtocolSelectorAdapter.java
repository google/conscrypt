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

import static org.conscrypt.Preconditions.checkNotNull;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

/**
 * An adapter to bridge between the native code and the {@link AlpnProtocolSelector} API.
 */
final class AlpnProtocolSelectorAdapter {
    private static final int NO_PROTOCOL_SELECTED = -1;

    private final SSLEngine engine;
    private final SSLSocket socket;
    private final AlpnProtocolSelector selector;

    AlpnProtocolSelectorAdapter(SSLEngine engine, AlpnProtocolSelector selector) {
        this.engine = checkNotNull(engine, "engine");
        this.socket = null;
        this.selector = checkNotNull(selector, "selector");
    }

    AlpnProtocolSelectorAdapter(SSLSocket socket, AlpnProtocolSelector selector) {
        this.engine = null;
        this.socket = checkNotNull(socket, "socket");
        this.selector = checkNotNull(selector, "selector");
    }

    /**
     * Performs the ALPN protocol selection from the given list of length-delimited peer protocols.
     * @param lengthPrefixedList the peer protocols in length-delimited form.
     * @return If successful, returns the offset into the {@code lenghPrefixedList} array of the
     * selected protocol (i.e. points to the length prefix). Otherwise, returns
     * {@link #NO_PROTOCOL_SELECTED}.
     */
    int selectAlpnProtocol(byte[] lengthPrefixedList) {
        if (lengthPrefixedList == null || lengthPrefixedList.length == 0) {
            return NO_PROTOCOL_SELECTED;
        }

        // Convert the protocols to a list of strings.
        List<String> stringProtocols = new ArrayList<String>();
        for (int i = 0; i < lengthPrefixedList.length;) {
            int protocolLength = lengthPrefixedList[i++];
            Charset US_ASCII = Charset.forName("US-ASCII");
            stringProtocols.add(new String(lengthPrefixedList, i, protocolLength, US_ASCII));
            i += protocolLength;
        }

        // Select the protocol.
        final String selected;
        if (engine != null ) {
            selected = selector.selectAlpnProtocol(engine, stringProtocols);
        } else {
            selected = selector.selectAlpnProtocol(socket, stringProtocols);
        }
        if (selected == null || selected.isEmpty()) {
            return NO_PROTOCOL_SELECTED;
        }

        int offset = 0;
        for (String protocol : stringProtocols) {
            if (selected.equals(protocol)) {
                // Found the selected protocol. Return the index position of the beginning of
                // the protocol.
                return offset;
            }
            offset += 1 + protocol.length();
        }

        return NO_PROTOCOL_SELECTED;
    }
}
