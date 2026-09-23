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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class EchConfigListTest {
    // Actual EchConfigList in the cloudflare-ech.com HTTPS DNS record
    // Explicit byte casting required to prevent lossy conversion errors
    private static final byte[] VALID_ECH_CONFIG_LIST = new byte[] {
            0x00,        0x45,        (byte) 0xfe, 0x0d,        0x00,        0x41,
            (byte) 0xf7, 0x00,        0x20,        0x00,        0x20,        (byte) 0xfd,
            0x4b,        (byte) 0x91, 0x2a,        (byte) 0xf0, (byte) 0xdc, (byte) 0xba,
            0x52,        (byte) 0xb5, (byte) 0x98, (byte) 0x8b, (byte) 0xea, (byte) 0xb2,
            0x50,        0x7b,        (byte) 0xfc, 0x4f,        (byte) 0x24,        (byte) 0xea,
            (byte) 0xdb, (byte) 0xf9, 0x54,        0x3a,        (byte) 0xa3, 0x71,
            0x34,        (byte) 0xdd, (byte) 0xff, 0x40,        (byte) 0xcc, (byte) 0xa8,
            0x68,        0x00,        0x04,        0x00,        0x01,        0x00,
            0x01,        0x00,        0x12,        0x63,        0x6c,        0x6f,
            0x75,        0x64,        0x66,        0x6c,        0x61,        0x72,
            0x65,        0x2d,        0x65,        0x63,        0x68,        0x2e,
            0x63,        0x6f,        0x6d,        0x00,        0x00};

    @Test
    public void testFromBytes_whenNull_throwsNullPointerException() {
        assertThrows(NullPointerException.class,
                     () -> EchConfigList.fromBytes(/* byteArr= */ null));
    }

    @Test
    public void testFromBytes_whenEmpty_throwsInvalidEchDataException() {
        assertThrows("Empty ECH config list", InvalidEchDataException.class,
                     () -> EchConfigList.fromBytes(new byte[] {}));
    }

    @Test
    public void testFromBytes_whenTooShort_throwsInvalidEchDataException() {
        assertThrows("ECH config list does not contain a length", InvalidEchDataException.class,
                     () -> EchConfigList.fromBytes(new byte[] {0x00}));
    }

    @Test
    public void testFromBytes_whenMismatchedLength_throwsInvalidEchDataException() {
        byte[] byteArr = new byte[] {0x00, 0x02, 0x05, 0x06, 0x7};

        assertThrows("ECH config list length does not match", InvalidEchDataException.class,
                     () -> EchConfigList.fromBytes(byteArr));
    }

    @Test
    public void testFromBytes_whenValidEchConfigList_createsObject() throws Exception {
        EchConfigList echConfigList = EchConfigList.fromBytes(VALID_ECH_CONFIG_LIST);

        assertArrayEquals(VALID_ECH_CONFIG_LIST, echConfigList.toBytes());
    }

    @Test
    public void testToBytes_defensiveCopy() throws Exception {
        EchConfigList echConfigList = EchConfigList.fromBytes(VALID_ECH_CONFIG_LIST);
        byte[] bytes = echConfigList.toBytes();
        bytes[0] = (byte) 0xFF;

        assertArrayEquals(VALID_ECH_CONFIG_LIST, echConfigList.toBytes());
    }
}

