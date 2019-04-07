/*
 * Copyright 2018 The Android Open Source Project
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

import static org.conscrypt.Conscrypt.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ConscryptTest {
    private static Version _210 = new Version(2, 1, 0);
    private static Version _200 = new Version(2, 0, 0);
    private static Version _301 = new Version(3, 0, 1);
    private static Version _103 = new Version(1, 0, 3);


    /**
     * This confirms that the version machinery is working.
     */
    @Test
    public void testVersionIsSensible() {
        Version version = version();
        assertNotNull(version);
        // The version object should be a singleton
        assertSame(version, version());

        assertTrue("Major version: " + version.major(), 1 <= version.major());
        assertTrue("Minor version: " + version.minor(), 0 <= version.minor());
        assertTrue("Patch version: " + version.patch(), 0 <= version.patch());
    }

    @Test
    public void testVersionParse() {
        assertEquals(new Version(2, 1, 0), Version.fromString("2.1.0"));
        assertFailsParse("2.1");
        assertFailsParse("2");
        assertFailsParse("-2.1.0");
        assertFailsParse("two");
        assertFailsParse("2.1.a");
    }

    @Test
    public void testVersionAtLeast() {
        assertTrue(_210.atLeast(_103));
        assertTrue(_210.atLeast(_200));
        assertTrue(_210.atLeast(_210));
        assertFalse(_210.atLeast(_301));

        assertFalse(_103.atLeast(_210));
        assertFalse(_200.atLeast(_210));
        assertTrue(_301.atLeast(_210));
    }

    private void assertFailsParse(String s) {
        try {
            Version.fromString(s);
            fail("Expected failed parse for '" + s + "'");
        } catch (IllegalArgumentException iae) {
        }
    }
}
