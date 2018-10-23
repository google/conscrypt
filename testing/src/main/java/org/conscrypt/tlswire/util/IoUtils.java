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
public class IoUtils {
    public static int readUnsignedInt24(DataInput in) throws IOException {
        return (in.readUnsignedByte() << 16) | in.readUnsignedShort();
    }
    public static byte[] readTlsVariableLengthByteVector(DataInput in, int maxSizeBytes)
            throws IOException {
        int sizeBytes = readTlsVariableLengthVectorSizeBytes(in, maxSizeBytes);
        byte[] result = new byte[sizeBytes];
        in.readFully(result);
        return result;
    }
    public static int[] readTlsVariableLengthUnsignedShortVector(DataInput in, int maxSizeBytes)
            throws IOException {
        int sizeBytes = readTlsVariableLengthVectorSizeBytes(in, maxSizeBytes);
        int elementCount = sizeBytes / 2;
        int[] result = new int[elementCount];
        for (int i = 0; i < elementCount; i++) {
            result[i] = in.readUnsignedShort();
        }
        return result;
    }
    private static int readTlsVariableLengthVectorSizeBytes(DataInput in, int maxSizeBytes)
            throws IOException {
        if (maxSizeBytes < 0x100) {
            return in.readUnsignedByte();
        } else if (maxSizeBytes < 0x10000) {
            return in.readUnsignedShort();
        } else if (maxSizeBytes < 0x1000000) {
            return readUnsignedInt24(in);
        } else {
            return in.readInt();
        }
    }
}
