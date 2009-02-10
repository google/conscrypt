/*
 * Copyright (C) 2008 The Android Open Source Project
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
package org.apache.harmony.crypto.tests.javax.crypto.func;

import dalvik.annotation.TestLevel;
import dalvik.annotation.TestTargetClass;
import dalvik.annotation.TestTargetNew;

import junit.framework.TestCase;

import targets.Cipher;

@TestTargetClass(Cipher.PBE.class)
public class CipherPBETest extends TestCase {
// 2 cases checked
    @TestTargetNew(
            level = TestLevel.COMPLETE,
            notes = "",
            method = "method",
            args = {}
        )
    public void test_PBEWithMD5AndDES() throws Exception {
        CipherPBEThread PBEWithMD5AndDES = new CipherPBEThread("PBEWithMD5AndDES",
                new int[]{40, 128},
                new String[] {"CBC"},
                new String[]{"PKCS5Padding"});

        PBEWithMD5AndDES.launcher();

        assertEquals(PBEWithMD5AndDES.getFailureMessages(), 0, PBEWithMD5AndDES.getTotalFailuresNumber());
    }

//  2 cases checked. Not supported on Android.
    @TestTargetNew(
            level = TestLevel.COMPLETE,
            notes = "",
            method = "method",
            args = {}
        )
    public void _test_PBEWithSHA1AndDESede() throws Exception {
        CipherPBEThread PBEWithSHA1AndDESede = new CipherPBEThread("PBEWithSHA1AndDESede",
                new int[]{40, 128},
                new String[] {"CBC"},
                new String[]{"PKCS5Padding"});

        PBEWithSHA1AndDESede.launcher();

        assertEquals(PBEWithSHA1AndDESede.getFailureMessages(), 0, PBEWithSHA1AndDESede.getTotalFailuresNumber());
    }

//  2 cases checked. Not supported on Android.
    @TestTargetNew(
            level = TestLevel.COMPLETE,
            notes = "",
            method = "method",
            args = {}
        )
    public void _test_PBEWithSHA1AndRC2_40() throws Exception {
        CipherPBEThread PBEWithSHA1AndRC2_40 = new CipherPBEThread("PBEWithSHA1AndRC2_40",
                new int[]{40, 128},
                new String[] {"CBC"},
                new String[]{"PKCS5Padding"});

        PBEWithSHA1AndRC2_40.launcher();

        assertEquals(PBEWithSHA1AndRC2_40.getFailureMessages(), 0, PBEWithSHA1AndRC2_40.getTotalFailuresNumber());
    }

// Key factory does not supported.    
    @TestTargetNew(
            level = TestLevel.COMPLETE,
            notes = "",
            method = "method",
            args = {}
        )
    public void _test_PBEWITHSHAAND3() throws Exception {
        CipherPBEThread PBEWithSHA1AndRC2_40 = new CipherPBEThread("PBEWITHSHAAND3",
                new int[]{40, 128},
                new String[] {"CBC"},
                new String[]{"NoPadding", "PKCS5Padding", "ISO10126PADDING"});

        PBEWithSHA1AndRC2_40.launcher();

        assertEquals(PBEWithSHA1AndRC2_40.getFailureMessages(), 0, PBEWithSHA1AndRC2_40.getTotalFailuresNumber());
    }
}
