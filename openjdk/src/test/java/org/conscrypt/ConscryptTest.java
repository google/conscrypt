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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ConscryptTest {

    /**
     * This confirms that the version machinery is working.
     */
    @Test
    public void testVersionIsSensible() {
        Conscrypt.Version version = Conscrypt.version();
        assertNotNull(version);
        // The version object should be a singleton
        assertSame(version, Conscrypt.version());

        assertTrue("Major version: " + version.major(), 1 <= version.major());
        assertTrue("Minor version: " + version.minor(), 0 <= version.minor());
        assertTrue("Patch version: " + version.patch(), 0 <= version.patch());
    }
}
