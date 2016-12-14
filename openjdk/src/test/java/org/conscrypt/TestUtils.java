/*
 * Copyright (C) 2015 The Android Open Source Project
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

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

final class TestUtils {
    private TestUtils() {}

    static InputStream openTestFile(String name) throws FileNotFoundException {
        InputStream is = TestUtils.class.getResourceAsStream("/" + name);
        if (is == null) {
            throw new FileNotFoundException(name);
        }
        return is;
    }

    static byte[] readTestFile(String name) throws IOException {
        return readFully(openTestFile(name));
    }

    /**
     * Returns a byte[] containing the remainder of 'in', closing it when done.
     */
    private static byte[] readFully(InputStream in) throws IOException {
        try {
            return readFullyNoClose(in);
        } finally {
            in.close();
        }
    }

    /**
     * Returns a byte[] containing the remainder of 'in'.
     */
    private static byte[] readFullyNoClose(InputStream in) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int count;
        while ((count = in.read(buffer)) != -1) {
            bytes.write(buffer, 0, count);
        }
        return bytes.toByteArray();
    }
}
