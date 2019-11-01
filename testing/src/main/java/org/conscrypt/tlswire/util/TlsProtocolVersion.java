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
package org.conscrypt.tlswire.util;
import java.io.DataInput;
import java.io.IOException;
/**
 * {@code ProtovolVersion} struct from TLS 1.2 RFC 5246.
 */
public class TlsProtocolVersion {
    public static final TlsProtocolVersion SSLV3 = new TlsProtocolVersion(3, 0, "SSLv3");
    public static final TlsProtocolVersion TLSv1_0 = new TlsProtocolVersion(3, 1, "TLSv1.0");
    public static final TlsProtocolVersion TLSv1_1 = new TlsProtocolVersion(3, 2, "TLSv1.1");
    public static final TlsProtocolVersion TLSv1_2 = new TlsProtocolVersion(3, 3, "TLSv1.2");
    public static final TlsProtocolVersion TLSv1_3 = new TlsProtocolVersion(3, 4, "TLSv1.3");
    public final int major;
    public final int minor;
    public final String name;
    private TlsProtocolVersion(int major, int minor, String name) {
        this.major = major;
        this.minor = minor;
        this.name = name;
    }
    public static TlsProtocolVersion valueOf(int major, int minor) {
        if (major == 3) {
            switch (minor) {
                case 0:
                    return SSLV3;
                case 1:
                    return TLSv1_0;
                case 2:
                    return TLSv1_1;
                case 3:
                    return TLSv1_2;
                case 4:
                    return TLSv1_3;
            }
        }
        return new TlsProtocolVersion(major, minor, major + "." + minor);
    }
    public static TlsProtocolVersion read(DataInput in) throws IOException {
        int major = in.readUnsignedByte();
        int minor = in.readUnsignedByte();
        return TlsProtocolVersion.valueOf(major, minor);
    }
    @Override
    public String toString() {
        return name;
    }
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + major;
        result = prime * result + minor;
        return result;
    }
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof TlsProtocolVersion)) {
            return false;
        }
        TlsProtocolVersion other = (TlsProtocolVersion) obj;
        if (major != other.major) {
            return false;
        }
        if (minor != other.minor) {
            return false;
        }
        return true;
    }
}
