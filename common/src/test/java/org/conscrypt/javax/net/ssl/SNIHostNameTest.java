/*
 * Copyright 2016 The Android Open Source Project
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

package org.conscrypt.javax.net.ssl;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.StandardConstants;
import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SNIHostNameTest {
    @Test
    public void test_byteArray_Constructor() throws Exception {
        TestUtils.assumeSNIHostnameAvailable();

        // From draft-josefsson-idn-test-vectors-00 section 5.2
        byte[] idnEncoded = new byte[] {
            (byte) 0xE4, (byte) 0xBB, (byte) 0x96, (byte) 0xE4, (byte) 0xBB, (byte) 0xAC,
            (byte) 0xE4, (byte) 0xB8, (byte) 0xBA, (byte) 0xE4, (byte) 0xBB, (byte) 0x80,
            (byte) 0xE4, (byte) 0xB9, (byte) 0x88, (byte) 0xE4, (byte) 0xB8, (byte) 0x8D,
            (byte) 0xE8, (byte) 0xAF, (byte) 0xB4, (byte) 0xE4, (byte) 0xB8, (byte) 0xAD,
            (byte) 0xE6, (byte) 0x96, (byte) 0x87,
        };

        SNIHostName hostName = new SNIHostName(idnEncoded);
        assertEquals("xn--ihqwcrb4cv8a8dqg056pqjye", hostName.getAsciiName());
        assertEquals(StandardConstants.SNI_HOST_NAME, hostName.getType());
        assertEquals(Arrays.toString(idnEncoded), Arrays.toString(hostName.getEncoded()));
    }
}
