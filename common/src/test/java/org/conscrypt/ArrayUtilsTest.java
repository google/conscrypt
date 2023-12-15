/*
 * Copyright 2023 The Android Open Source Project
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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ArrayUtilsTest {
    @Test
    public void offsetCount() {
        byte[] data = bytes("Some data");
        for (int offset = 0; offset <= data.length; offset++) {
            for (int length = 0; length <= data.length - offset; length++) {
                ArrayUtils.checkOffsetAndCount(data.length, offset, length);
            }
        }
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> ArrayUtils.checkOffsetAndCount(data.length, 0, data.length + 1));
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> ArrayUtils.checkOffsetAndCount(data.length, data.length, 1));

    }

    @Test
    public void offsetCount_Empty() {
        ArrayUtils.checkOffsetAndCount(0, 0, 0);
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> ArrayUtils.checkOffsetAndCount(0, 0, 1));
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> ArrayUtils.checkOffsetAndCount(0, 1, 0));
    }

    @Test
    public void concatStringArrays() {
        String[] data = new String[] {"a", "b", "c", "d", "e", "f"};
        for (int i = 0; i <= data.length; i++) {
            String[] a1 = Arrays.copyOfRange(data, 0, i);
            String[] a2 = Arrays.copyOfRange(data, i, data.length);
            assertArrayEquals(data, ArrayUtils.concat(a1, a2));
        }
    }

    @Test
    public void concatStringValues() {
        String[] expected = new String[] { "a", "b", "c",};

        assertArrayEquals(expected,
                ArrayUtils.concatValues(new String[] {}, "a", "b", "c"));
        assertArrayEquals(expected,
                ArrayUtils.concatValues(new String[] { "a" }, "b", "c"));
        assertArrayEquals(expected,
                ArrayUtils.concatValues(new String[] { "a", "b" }, "c"));
        assertArrayEquals(expected,
                ArrayUtils.concatValues(new String[] { "a", "b", "c" }));
    }

    @Test
    public void concatByteArrays() {
        byte[] data = bytes("Some bytes");
        for (int i = 0; i <= data.length; i++) {
            byte[] a1 = Arrays.copyOfRange(data, 0, i);
            byte[] a2 = Arrays.copyOfRange(data, i, data.length);
            assertArrayEquals(data, ArrayUtils.concat(a1, a2));
        }
    }

    @Test
    public void startsWith() {
        byte[] data = bytes("OneTwoThree");
        assertTrue(ArrayUtils.startsWith(data, bytes("One")));
        assertTrue(ArrayUtils.startsWith(data, bytes("")));
        assertFalse(ArrayUtils.startsWith(data, bytes("Two")));
    }

    @Test
    public void startsWith_Empty() {
        byte[] data = new byte[0];
        assertFalse(ArrayUtils.startsWith(data, bytes("One")));
        assertTrue(ArrayUtils.startsWith(data, bytes("")));
    }
    @Test
    public void reverse() {
        assertArrayEquals(new byte[0], ArrayUtils.reverse(new byte[0]));
        assertArrayEquals(bytes("fedcba"), ArrayUtils.reverse(bytes("abcdef")));
    }

 static byte[] bytes(String string) {
        return string.getBytes(StandardCharsets.UTF_8);
    }
}
