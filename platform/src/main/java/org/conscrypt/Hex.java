/*
 * Copyright 2013 The Android Open Source Project
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

/**
 * Helper class for dealing with hexadecimal strings.
 */
@Internal
public final class Hex {
    private Hex() {}

    private final static char[] DIGITS = {'0', '1', '2', '3', '4', '5', '6', '7',
                                          '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public static String intToHexString(int i, int minWidth) {
        int bufLen = 8; // Max number of hex digits in an int
        char[] buf = new char[bufLen];
        int cursor = bufLen;

        do {
            buf[--cursor] = DIGITS[i & 0xf];
        } while ((i >>>= 4) != 0 || (bufLen - cursor < minWidth));

        return new String(buf, cursor, bufLen - cursor);
    }

    public static byte[] decodeHex(String encoded) throws IllegalArgumentException {
        if ((encoded.length() % 2) != 0) {
            throw new IllegalArgumentException("Invalid input length: " + encoded.length());
        }

        int resultLengthBytes = encoded.length() / 2;
        byte[] result = new byte[resultLengthBytes];

        int resultOffset = 0;
        int i = 0;
        for (int len = encoded.length(); i < len; i += 2) {
            result[resultOffset++] =
                    (byte) ((toDigit(encoded.charAt(i)) << 4) | toDigit(encoded.charAt(i + 1)));
        }

        return result;
    }

    private static int toDigit(char pseudoCodePoint) throws IllegalArgumentException {
        if ('0' <= pseudoCodePoint && pseudoCodePoint <= '9') {
            return pseudoCodePoint - '0';
        } else if ('a' <= pseudoCodePoint && pseudoCodePoint <= 'f') {
            return 10 + (pseudoCodePoint - 'a');
        } else if ('A' <= pseudoCodePoint && pseudoCodePoint <= 'F') {
            return 10 + (pseudoCodePoint - 'A');
        }
        throw new IllegalArgumentException("Illegal char: " + pseudoCodePoint);
    }
}
