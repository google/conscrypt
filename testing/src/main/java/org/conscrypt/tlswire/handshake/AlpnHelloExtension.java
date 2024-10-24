/*
 * Copyright (C) 2018 The Android Open Source Project
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
package org.conscrypt.tlswire.handshake;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.conscrypt.tlswire.util.IoUtils;

/**
 * {@code application_layer_protocol_negotiation} {@link HelloExtension} from RFC 7301 section 3.1.
 */
public class AlpnHelloExtension extends HelloExtension {

    public List<String> protocols;

    @Override
    protected void parseData() throws IOException {
        byte[] alpnListBytes = IoUtils.readTlsVariableLengthByteVector(
                new DataInputStream(new ByteArrayInputStream(data)), 0xffff);
        protocols = new ArrayList<>();
        DataInputStream alpnList = new DataInputStream(new ByteArrayInputStream(alpnListBytes));
        while (alpnList.available() > 0) {
            byte[] alpnValue = IoUtils.readTlsVariableLengthByteVector(alpnList, 0xff);
            protocols.add(new String(alpnValue, StandardCharsets.US_ASCII));
        }
    }

    @Override
    public String toString() {
        return "HelloExtension{type: elliptic_curves, protocols: " + protocols + '}';
    }
}
