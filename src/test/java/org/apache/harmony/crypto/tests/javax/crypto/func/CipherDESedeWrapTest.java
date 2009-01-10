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
import dalvik.annotation.TestTargetNew;
import dalvik.annotation.TestTargetClass;

import junit.framework.TestCase;


import targets.Cipher;

@TestTargetClass(Cipher.DESedeWrap.class)
public class CipherDESedeWrapTest extends TestCase {
//  2 cases checked. Mode "CBC" not supported.
    @TestTargetNew(
            level = TestLevel.COMPLETE,
            notes = "",
            method = "method",
            args = {}
        )
    public void _test_DESedeWrap() {
        CipherWrapThread DESedeWrap = new CipherWrapThread("DESedeWrap",
                new int[]{112, 168},
                new String[] {"CBC"},
                new String[]{"NoPadding"});

        DESedeWrap.launcher();
        
        assertEquals(DESedeWrap.getFailureMessages(), 0, DESedeWrap.getTotalFailuresNumber());
    }

    public void test_DESede() {
        CipherWrapThread DESedeWrap = new CipherWrapThread("DESede",
                new int[]{112, 168},
                new String[] {"CBC"},
                new String[]{"NoPadding"});

        DESedeWrap.launcher();
        
        assertEquals(DESedeWrap.getFailureMessages(), 0, DESedeWrap.getTotalFailuresNumber());
    }
}
