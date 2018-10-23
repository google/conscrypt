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
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.conscrypt.tlswire.util.IoUtils;
import org.conscrypt.tlswire.util.TlsProtocolVersion;

/**
 * {@link ClientHello} {@link HandshakeMessage} from TLS 1.2 RFC 5246.
 */
public class ClientHello extends HandshakeMessage {
    public TlsProtocolVersion clientVersion;
    public byte[] random;
    public byte[] sessionId;
    public List<CipherSuite> cipherSuites;
    public List<CompressionMethod> compressionMethods;
    /** Extensions or {@code null} for no extensions. */
    public List<HelloExtension> extensions;
    @Override
    protected void parseBody(DataInput in) throws IOException {
        clientVersion = TlsProtocolVersion.read(in);
        random = new byte[32];
        in.readFully(random);
        sessionId = IoUtils.readTlsVariableLengthByteVector(in, 32);
        int[] cipherSuiteCodes = IoUtils.readTlsVariableLengthUnsignedShortVector(in, 0xfffe);
        cipherSuites = new ArrayList<CipherSuite>(cipherSuiteCodes.length);
        for (int i = 0; i < cipherSuiteCodes.length; i++) {
            cipherSuites.add(CipherSuite.valueOf(cipherSuiteCodes[i]));
        }
        byte[] compressionMethodCodes = IoUtils.readTlsVariableLengthByteVector(in, 0xff);
        compressionMethods = new ArrayList<CompressionMethod>(compressionMethodCodes.length);
        for (int i = 0; i < compressionMethodCodes.length; i++) {
            int code = compressionMethodCodes[i] & 0xff;
            compressionMethods.add(CompressionMethod.valueOf(code));
        }
        int extensionsSectionSize;
        try {
            extensionsSectionSize = in.readUnsignedShort();
        } catch (EOFException e) {
            // No extensions present
            extensionsSectionSize = 0;
        }
        if (extensionsSectionSize > 0) {
            extensions = new ArrayList<HelloExtension>();
            byte[] extensionsBytes = new byte[extensionsSectionSize];
            in.readFully(extensionsBytes);
            ByteArrayInputStream extensionsIn = new ByteArrayInputStream(extensionsBytes);
            DataInput extensionsDataIn = new DataInputStream(extensionsIn);
            while (extensionsIn.available() > 0) {
                try {
                    extensions.add(HelloExtension.read(extensionsDataIn));
                } catch (IOException e) {
                    throw new IOException(
                            "Failed to read HelloExtension #" + (extensions.size() + 1));
                }
            }
        }
    }
    public HelloExtension findExtensionByType(int extensionType) {
        if (extensions == null) {
            return null;
        }
        for (HelloExtension extension : extensions) {
            if (extension.type == extensionType) {
                return extension;
            }
        }
        return null;
    }
    @Override
    public String toString() {
        return "ClientHello{client version: " + clientVersion + ", random: "
                + new BigInteger(1, random).toString(16) + ", sessionId: "
                + new BigInteger(1, sessionId).toString(16) + ", cipher suites: " + cipherSuites
                + ", compression methods: " + compressionMethods
                + ((extensions != null) ? (", extensions: " + String.valueOf(extensions)) : "")
                + "}";
    }
}
