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

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SSLUtilsTest {
    private static final byte[] VALID_CHARACTERS =
            "0123456789abcdefghijklmnopqrstuvwxyz".getBytes();

    @Test
    public void noProtocolsShouldSucceed() {
        byte[] expected = new byte[0];
        byte[] actual = SSLUtils.toLengthPrefixedList();
        assertArrayEquals(expected, actual);
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyProtocolShouldThrow() {
        SSLUtils.toLengthPrefixedList("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void longProtocolShouldThrow() {
        SSLUtils.toLengthPrefixedList(new String(newValidProtocol(256)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void protocolWithInvalidCharacterShouldThrow() {
        SSLUtils.toLengthPrefixedList("This is a bad character: €");
    }

    @Test
    public void validProtocolsShouldSucceed() {
        byte[][] protocols = new byte[][]{
                "protocol-1".getBytes(),
                "protocol-2".getBytes(),
                "protocol-3".getBytes(),
        };
        byte[] expected = getExpectedEncodedBytes(protocols);
        byte[] actual = SSLUtils.toLengthPrefixedList(toStrings(protocols));
        assertArrayEquals(expected, actual);
    }

    private static String[] toStrings(byte[][] protocols) {
        int numProtocols = protocols.length;
        String[] out = new String[numProtocols];
        for(int i = 0; i < numProtocols; ++i) {
            out[i] = new String(protocols[i]);
        }
        return out;
    }

    private static byte[] getExpectedEncodedBytes(byte[][] protocols) {
        int numProtocols = protocols.length;
        int encodedLength = numProtocols;
        for (byte[] protocol : protocols) {
            encodedLength += protocol.length;
        }
        byte[] encoded = new byte[encodedLength];
        for(int encodedIndex = 0, i = 0; i < numProtocols; ++i) {
            byte[] protocol = protocols[i];
            encoded[encodedIndex++] = (byte) protocol.length;
            System.arraycopy(protocol, 0, encoded, encodedIndex, protocol.length);
            encodedIndex += protocol.length;
        }
        return encoded;
    }

    private static byte[] newValidProtocol(int length) {
        byte[] chars = new byte[length];
        for (int i = 0; i < length; ++i) {
            int charIndex = i % VALID_CHARACTERS.length;
            chars[i] = VALID_CHARACTERS[charIndex];
        }
        return chars;
    }
}
