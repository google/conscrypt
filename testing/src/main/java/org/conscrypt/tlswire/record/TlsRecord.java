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
package org.conscrypt.tlswire.record;

import java.io.DataInput;
import java.io.IOException;
import org.conscrypt.tlswire.util.TlsProtocolVersion;

/**
 * TLS Record Protocol record from TLS 1.2 RFC 5246.
 */
public class TlsRecord {
    public int type;
    public TlsProtocolVersion version;
    public byte[] fragment;
    public static TlsRecord read(DataInput in) throws IOException {
        TlsRecord result = new TlsRecord();
        result.type = in.readUnsignedByte();
        result.version = TlsProtocolVersion.read(in);
        int fragmentLength = in.readUnsignedShort();
        result.fragment = new byte[fragmentLength];
        in.readFully(result.fragment);
        return result;
    }
}
