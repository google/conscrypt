/*
 * Copyright (C) 2026 The Android Open Source Project
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

import java.nio.ByteBuffer;

/**
 * Data used to configure ECH (Encrypted Client Hello) in a TLS handshake.
 *
 * <p>This object can only be constructed by feeding in the raw bytes of the EchConfigList from
 * a HTTPS DNS record (see https://datatracker.ietf.org/doc/html/rfc460), and may contain multiple
 * EchConfigs.
 *
 * <p>The general structure starts with the length of the EchConfigList (2 bytes), then each
 * entry in the list contains the following:
 * <ul>
 * <li>Version: 2 bytes
 * <li>Length of the individual EchConfig: 2 bytes
 * <li>Contents: unspecified number of bytes
 * </ul>
 *
 * <p>See https://datatracker.ietf.org/doc/draft-ietf-tls-esni for details of the exact structure.
 */
public class EchConfigList {
    private final byte[] rawData;

    private EchConfigList(byte[] rawData) {
        // Make a copy of the raw data to prevent the caller from being able to modify it directly.
        this.rawData = rawData.clone();
    }

    /**
     * Factory method to construct a new {@code EchConfigList} from a byte array.
     *
     * <p>The raw bytes from a HTTPS DNS record should be fed directly into this method.
     *
     * @throws NullPointerException if {@code byteArr} is null.
     * @throws InvalidEchDataException if the ECH data is empty, does not contain a length, or has
     * a length mismatch.
     */
    public static EchConfigList fromBytes(byte[] byteArr) throws InvalidEchDataException {
        if (byteArr == null) {
            throw new NullPointerException("ECH config list should not be null");
        }

        if (byteArr.length == 0) {
            throw new InvalidEchDataException("Empty ECH config list");
        }

        if (byteArr.length < 2) {
            throw new InvalidEchDataException("ECH config list does not contain a length");
        }

        int echConfigListLength = Short.toUnsignedInt(ByteBuffer.wrap(byteArr).getShort());
        // Subtract the 2 bytes corresponding to the overall EchConfigList length
        if (echConfigListLength != byteArr.length - 2) {
            throw new InvalidEchDataException("ECH config list length does not match");
        }

        return new EchConfigList(byteArr);
    }

    /** Returns the raw byte representation of an EchConfigList. */
    public byte[] toBytes() {
        // Defensive copy, so that the caller can't modify the underlying raw data.
        return rawData.clone();
    }
}

