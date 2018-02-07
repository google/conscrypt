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

import static org.conscrypt.TestUtils.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Arrays;
import java.util.HashSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SSLUtilsTest {
    private static final byte[] VALID_CHARACTERS =
            "0123456789abcdefghijklmnopqrstuvwxyz".getBytes(UTF_8);

    @Test
    public void noProtocolsShouldSucceed() {
        byte[] expected = new byte[0];
        byte[] actual = SSLUtils.encodeProtocols(EmptyArray.STRING);
        assertArrayEquals(expected, actual);
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyProtocolShouldThrow() {
        SSLUtils.encodeProtocols(new String[] {""});
    }

    @Test(expected = IllegalArgumentException.class)
    public void longProtocolShouldThrow() {
        SSLUtils.encodeProtocols(new String[] {new String(newValidProtocol(256), UTF_8)});
    }

    @Test(expected = IllegalArgumentException.class)
    public void protocolWithInvalidCharacterShouldThrow() {
        SSLUtils.encodeProtocols(new String[] {"This is a bad character: €"});
    }

    @Test
    public void encodeProtocolsShouldSucceed() {
        byte[][] protocols = new byte[][]{
                "protocol-1".getBytes(UTF_8),
                "protocol-2".getBytes(UTF_8),
                "protocol-3".getBytes(UTF_8),
        };
        byte[] expected = getExpectedEncodedBytes(protocols);
        byte[] actual = SSLUtils.encodeProtocols(toStrings(protocols));
        assertArrayEquals(expected, actual);
    }

    @Test(expected = NullPointerException.class)
    public void decodeNullProtocolsShouldThrow() {
        SSLUtils.decodeProtocols(null);
    }

    @Test
    public void decodeEmptyProtocolsShouldSucceed() {
        assertArrayEquals(EmptyArray.STRING, SSLUtils.decodeProtocols(EmptyArray.BYTE));
    }

    @Test
    public void decodeProtocolsShouldSucceed() {
        byte[][] protocols = new byte[][]{
            "protocol-1".getBytes(UTF_8),
            "protocol-2".getBytes(UTF_8),
            "protocol-3".getBytes(UTF_8),
        };
        byte[] encoded = getExpectedEncodedBytes(protocols);
        String[] strings = SSLUtils.decodeProtocols(encoded);
        assertArrayEquals(toStrings(protocols), strings);
    }

    @Test
    public void testGetClientKeyType() throws Exception {
        // See http://www.ietf.org/assignments/tls-parameters/tls-parameters.xml
        byte b = Byte.MIN_VALUE;
        do {
            String byteString = Byte.toString(b);
            String keyType = SSLUtils.getClientKeyType(b);
            switch (b) {
                case 1:
                    assertEquals(byteString, "RSA", keyType);
                    break;
                case 64:
                    assertEquals(byteString, "EC", keyType);
                    break;
                default:
                    assertNull(byteString, keyType);
            }
            b++;
        } while (b != Byte.MIN_VALUE);
    }

    @Test
    public void testGetSupportedClientKeyTypes() throws Exception {
        // Create an array with all possible values. Also, duplicate all values.
        byte[] allClientCertificateTypes = new byte[512];
        for (int i = 0; i < allClientCertificateTypes.length; i++) {
            allClientCertificateTypes[i] = (byte) i;
        }
        assertEquals(new HashSet<String>(Arrays.asList("RSA", "EC")),
                SSLUtils.getSupportedClientKeyTypes(allClientCertificateTypes));
    }

    private static String[] toStrings(byte[][] protocols) {
        int numProtocols = protocols.length;
        String[] out = new String[numProtocols];
        for(int i = 0; i < numProtocols; ++i) {
            out[i] = new String(protocols[i], UTF_8);
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
