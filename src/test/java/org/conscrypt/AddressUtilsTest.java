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

import junit.framework.TestCase;

/**
 * Test for AddressUtils
 */
public class AddressUtilsTest extends TestCase {
    public void test_isValidSniHostname_Success() throws Exception {
        assertTrue(AddressUtils.isValidSniHostname("www.google.com"));
    }

    public void test_isValidSniHostname_NotFQDN_Failure() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("www"));
    }

    public void test_isValidSniHostname_IPv4_Failure() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("192.168.0.1"));
    }

    public void test_isValidSniHostname_IPv6_Failure() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("2001:db8::1"));
    }
}
