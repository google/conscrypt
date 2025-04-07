/*
 * Copyright 2025 The Android Open Source Project
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class KeySpecUtilTest {
    public static final class RawKeySpec extends EncodedKeySpec {
        public RawKeySpec(byte[] encoded) {
            super(encoded);
        }

        @Override
        public String getFormat() {
            return "raw";
        }
    }

    public static final class OtherKeySpec extends EncodedKeySpec {
        public OtherKeySpec(byte[] encoded) {
            super(encoded);
        }

        @Override
        public String getFormat() {
            return "other";
        }
    }

    @Test
    public void makeRawKeySpec_returnsRawKeySpec() {
        byte[] rawBytes = new byte[] {1, 2, 3};

        RawKeySpec rawKeySpec = KeySpecUtil.makeRawKeySpec(rawBytes, RawKeySpec.class);

        assertEquals("raw", rawKeySpec.getFormat());
        assertArrayEquals(rawBytes, rawKeySpec.getEncoded());
    }

    @Test
    public void makeRawKeySpec_notRawKeySpecClass_throws() {
        byte[] rawBytes = new byte[] {1, 2, 3};

        assertThrows(InvalidKeySpecException.class,
                () -> KeySpecUtil.makeRawKeySpec(rawBytes, OtherKeySpec.class));
    }
}
