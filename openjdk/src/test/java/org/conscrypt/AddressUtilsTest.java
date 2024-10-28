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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test for AddressUtils
 */
@RunWith(JUnit4.class)
public class AddressUtilsTest {
    @Test
    public void test_isValidSniHostname_Success() throws Exception {
        assertTrue(AddressUtils.isValidSniHostname("www.google.com"));
    }

    @Test
    public void test_isValidSniHostname_NotFQDN_Failure() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("www"));
    }

    @Test
    public void test_isValidSniHostname_Localhost_Success() throws Exception {
        assertTrue(AddressUtils.isValidSniHostname("LOCALhost"));
    }

    @Test
    public void test_isValidSniHostname_IPv4_Failure() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("192.168.0.1"));
    }

    @Test
    public void test_isValidSniHostname_IPv6_Failure() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("2001:db8::1"));
    }

    @Test
    public void test_isValidSniHostname_TrailingDot() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("www.google.com."));
    }

    @Test
    public void test_isValidSniHostname_NullByte() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("www\0.google.com"));
    }

    @Test
    public void test_isLiteralIpAddress_IPv4_Success() throws Exception {
        assertTrue(AddressUtils.isLiteralIpAddress("127.0.0.1"));
        assertTrue(AddressUtils.isLiteralIpAddress("255.255.255.255"));
        assertTrue(AddressUtils.isLiteralIpAddress("0.0.00.000"));
        assertTrue(AddressUtils.isLiteralIpAddress("192.009.010.19"));
        assertTrue(AddressUtils.isLiteralIpAddress("254.249.190.094"));
    }

    @Test
    public void test_isLiteralIpAddress_IPv4_ExtraCharacters_Failure() throws Exception {
        assertFalse(AddressUtils.isLiteralIpAddress("127.0.0.1a"));
        assertFalse(AddressUtils.isLiteralIpAddress(" 255.255.255.255"));
        assertFalse(AddressUtils.isLiteralIpAddress("0.0.00.0009"));
        assertFalse(AddressUtils.isLiteralIpAddress("192.009z.010.19"));
        assertFalse(AddressUtils.isLiteralIpAddress("254.249..094"));
        assertFalse(AddressUtils.isLiteralIpAddress("192.168.2.1%1"));
        assertFalse(AddressUtils.isLiteralIpAddress("192.168.2.1%eth0"));
    }

    @Test
    public void test_isLiteralIpAddress_IPv4_NumbersTooLarge_Failure() throws Exception {
        assertFalse(AddressUtils.isLiteralIpAddress("256.255.255.255"));
        assertFalse(AddressUtils.isLiteralIpAddress("255.255.255.256"));
        assertFalse(AddressUtils.isLiteralIpAddress("192.168.1.260"));
    }

    @Test
    public void test_isLiteralIpAddress_IPv6_Success() throws Exception {
        assertTrue(AddressUtils.isLiteralIpAddress("::1"));
        assertTrue(AddressUtils.isLiteralIpAddress("2001:Db8::1"));
        assertTrue(AddressUtils.isLiteralIpAddress("2001:cdbA:0000:0000:0000:0000:3257:9652"));
        assertTrue(AddressUtils.isLiteralIpAddress("2001:cdba:0:0:0:0:3257:9652"));
        assertTrue(AddressUtils.isLiteralIpAddress("2001:cdBA::3257:9652"));
        assertTrue(AddressUtils.isLiteralIpAddress("2001:cdba::3257:9652%1"));
        assertTrue(AddressUtils.isLiteralIpAddress("2001:cdba::3257:9652%eth0"));
        assertTrue(AddressUtils.isLiteralIpAddress("2001:cdba::3257:9652%int2.3!"));
    }

    @Test
    public void test_isLiteralIpAddress_IPv6_Failure() throws Exception {
        assertFalse(AddressUtils.isLiteralIpAddress(":::1"));
        assertFalse(AddressUtils.isLiteralIpAddress("::11111"));
        assertFalse(AddressUtils.isLiteralIpAddress("20011::1111"));
        assertFalse(AddressUtils.isLiteralIpAddress("2001:db8:::1"));
        assertFalse(AddressUtils.isLiteralIpAddress("2001:cdba:0000:00000:0000:0000:3257:9652"));
        assertFalse(AddressUtils.isLiteralIpAddress("2001:cdbA:0000:0000:0000:0000:0000:3257:9652"));
        assertFalse(AddressUtils.isLiteralIpAddress("2001:cdba:0::0:0:0:3257:9652"));
        assertFalse(AddressUtils.isLiteralIpAddress("02001:cdba::3257:9652"));
        assertFalse(AddressUtils.isLiteralIpAddress("2001:cdba::3257:96521"));
        assertFalse(AddressUtils.isLiteralIpAddress("2001:cdba::3257:9652%"));
    }
}
