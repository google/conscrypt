/*
 * Copyright (C) 2014 The Android Open Source Project
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
 * {@code server_name} (SNI) {@link HelloExtension} from TLS 1.2 RFC 5246.
 */
public class ServerNameHelloExtension extends HelloExtension {
    private static final int TYPE_HOST_NAME = 0;
    public List<String> hostnames;
    @Override
    protected void parseData() throws IOException {
        byte[] serverNameListBytes = IoUtils.readTlsVariableLengthByteVector(
                new DataInputStream(new ByteArrayInputStream(data)), 0xffff);
        ByteArrayInputStream serverNameListIn = new ByteArrayInputStream(serverNameListBytes);
        DataInputStream in = new DataInputStream(serverNameListIn);
        hostnames = new ArrayList<>();
        while (serverNameListIn.available() > 0) {
            int type = in.readUnsignedByte();
            if (type != TYPE_HOST_NAME) {
                throw new IOException("Unsupported ServerName type: " + type);
            }
            byte[] hostnameBytes = IoUtils.readTlsVariableLengthByteVector(in, 0xffff);
            String hostname = new String(hostnameBytes, StandardCharsets.US_ASCII);
            hostnames.add(hostname);
        }
    }
    @Override
    public String toString() {
        return "HelloExtension{type: server_name, hostnames: " + hostnames + "}";
    }
}
