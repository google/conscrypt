/*
 * Copyright 2014 The Android Open Source Project
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

import java.util.Arrays;

/**
 * Compatibility utility for Arrays.
 */
@Internal
public final class ArrayUtils {
    private ArrayUtils() {}

    /**
     * Checks that the range described by {@code offset} and {@code count}
     * doesn't exceed {@code arrayLength}.
     */
    static void checkOffsetAndCount(int arrayLength, int offset, int count) {
        if ((offset | count) < 0 || offset > arrayLength || arrayLength - offset < count) {
            throw new ArrayIndexOutOfBoundsException("length=" + arrayLength + "; regionStart="
                    + offset + "; regionLength=" + count);
        }
    }

    @SafeVarargs
    @SuppressWarnings("varargs")
    public static <T> T[] concatValues(T[] a1, T... values) {
        return concat (a1, values);
    }

    public static <T> T[] concat(T[] a1, T[] a2) {
        T[] result = Arrays.copyOf(a1, a1.length + a2.length);
        System.arraycopy(a2, 0, result, a1.length, a2.length);
        return result;
    }

    public static byte[] concat(byte[] a1, byte[] a2) {
        byte[] result = Arrays.copyOf(a1, a1.length + a2.length);
        System.arraycopy(a2, 0, result, a1.length, a2.length);
        return result;
    }

    public static boolean startsWith(byte[] array, byte[] startsWith) {
        if (array.length < startsWith.length) {
            return false;
        }
        for (int i = 0; i < startsWith.length; i++) {
            if (array[i] != startsWith[i]) {
                return false;
            }
        }
        return true;
    }

    public static byte[] reverse(byte[] array) {
        byte[] result = new byte[array.length];
        int front = 0;
        int back = array.length - 1;
        while (back >= 0) {
            result[front++] = array[back--];
        }
        return result;
    }

    /**
     * Checks if given array is null or has zero elements.
     */
    public static <T> boolean isEmpty(T[] array) {
        return array == null || array.length == 0;
    }
}
