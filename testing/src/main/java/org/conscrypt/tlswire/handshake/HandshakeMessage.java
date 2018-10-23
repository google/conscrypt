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
import java.io.IOException;
import org.conscrypt.tlswire.util.IoUtils;

/**
 * Handshake Protocol message from TLS 1.2 RFC 5246.
 */
public class HandshakeMessage {
    public static final int TYPE_CLIENT_HELLO = 1;
    public int type;
    public byte[] body;
    /**
     * Parses the provided TLS record as a handshake message.
     */
    public static HandshakeMessage read(DataInput in) throws IOException {
        int type = in.readUnsignedByte();
        HandshakeMessage result;
        switch (type) {
            case TYPE_CLIENT_HELLO:
                result = new ClientHello();
                break;
            default:
                result = new HandshakeMessage();
                break;
        }
        result.type = type;
        int bodyLength = IoUtils.readUnsignedInt24(in);
        result.body = new byte[bodyLength];
        in.readFully(result.body);
        result.parseBody(new DataInputStream(new ByteArrayInputStream(result.body)));
        return result;
    }
    /**
     * Parses the provided body. The default implementation does nothing.
     *
     * @throws IOException if an I/O error occurs.
     */
    protected void parseBody(@SuppressWarnings("unused") DataInput in) throws IOException {}
}
