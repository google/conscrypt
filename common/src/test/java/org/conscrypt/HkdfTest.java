/*
 * Copyright (C) 2023 The Android Open Source Project
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
 * limitations under the License
 */

package org.conscrypt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.Mac;

@RunWith(JUnit4.class)
public class HkdfTest {
    private final String SHA256 = "HmacSHA256";

    @Test
    public void constructor() throws Exception {
        assertThrows(NullPointerException.class, () ->  new Hkdf(null));
        assertThrows(NoSuchAlgorithmException.class, () -> new Hkdf("No such MAC"));

        Hkdf hkdf = new Hkdf(SHA256);
        assertEquals(Mac.getInstance(SHA256).getMacLength(), hkdf.getMacLength());
    }

    @Test
    public void extract() throws Exception {
        Hkdf hkdf = new Hkdf(SHA256);
        assertThrows(NullPointerException.class, () -> hkdf.extract(null, new byte[0]));
        assertThrows(NullPointerException.class, () -> hkdf.extract(new byte[0], null));
        assertThrows(NullPointerException.class, () -> hkdf.extract(null, null));
        assertThrows(IllegalArgumentException.class, () -> hkdf.extract(new byte[0], new byte[0]));
    }

    @Test
    public void expand() throws Exception {
        Hkdf hkdf = new Hkdf(SHA256);
        int macLen = hkdf.getMacLength();
        assertThrows(NullPointerException.class, () -> hkdf.expand(null, new byte[0], 1));
        assertThrows(NullPointerException.class, () -> hkdf.expand(new byte[macLen], null, 1));
        assertThrows(NullPointerException.class, () -> hkdf.expand(null, null, 1));
        assertThrows(NullPointerException.class, () -> hkdf.expand(null, null, 1));
        // Negative length
        assertThrows(IllegalArgumentException.class,
            () -> hkdf.expand(new byte[macLen], new byte[0], -1));
        // PRK too small
        assertThrows(IllegalArgumentException.class,
            () -> hkdf.expand(new byte[0], new byte[0], 1));
        // Length too large
        assertThrows(IllegalArgumentException.class,
            () -> hkdf.expand(new byte[macLen], new byte[0], 255 * macLen + 1));
    }

    @Test
    public void testVectors() throws Exception {
        List<TestVector> vectors = TestUtils.readTestVectors("crypto/hkdf.txt");

        for (TestVector vector : vectors) {
            String errMsg =  vector.getString("name");
            String macName = vector.getString("hash");
            byte[] ikm = vector.getBytes("ikm");
            byte[] salt = vector.getBytesOrEmpty("salt");
            byte[] prk_expected = vector.getBytes("prk");

            Hkdf hkdf = new Hkdf(macName);
            byte[] prk = hkdf.extract(salt, ikm);
            assertArrayEquals(errMsg, prk_expected, prk);

            byte[] info = vector.getBytes("info");
            int length = vector.getInt("l");
            byte[] okm_expected = vector.getBytes("okm");

            byte[] okm = hkdf.expand(prk, info, length);
            assertArrayEquals(errMsg, okm_expected, okm);
        }
    }
}
