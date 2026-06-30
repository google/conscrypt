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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.Random;
import java.util.regex.Pattern;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for AddressUtils */
@RunWith(JUnit4.class)
public class AddressUtilsTest {
    @Test
    public void test_isValidSniHostname_success() throws Exception {
        assertTrue(AddressUtils.isValidSniHostname("www.google.com"));
    }

    @Test
    public void test_isValidSniHostname_notFQDN_failure() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("www"));
    }

    @Test
    public void test_isValidSniHostname_localhost_success() throws Exception {
        assertTrue(AddressUtils.isValidSniHostname("LOCALhost"));
    }

    @Test
    public void test_isValidSniHostname_iPv4_failure() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("192.168.0.1"));
    }

    @Test
    public void test_isValidSniHostname_iPv6_failure() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("2001:db8::1"));
    }

    @Test
    public void test_isValidSniHostname_trailingDot() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("www.google.com."));
    }

    @Test
    public void test_isValidSniHostname_nullByte() throws Exception {
        assertFalse(AddressUtils.isValidSniHostname("www\0.google.com"));
    }

    @Test
    public void test_isLiteralIpAddress_iPv4_success() throws Exception {
        assertTrue(AddressUtils.isLiteralIpAddress("127.0.0.1"));
        assertTrue(AddressUtils.isLiteralIpAddress("255.255.255.255"));
        assertTrue(AddressUtils.isLiteralIpAddress("0.0.00.000"));
        assertTrue(AddressUtils.isLiteralIpAddress("192.009.010.19"));
        assertTrue(AddressUtils.isLiteralIpAddress("254.249.190.094"));
    }

    @Test
    public void test_isLiteralIpAddress_iPv4_extraCharacters_failure() throws Exception {
        assertFalse(AddressUtils.isLiteralIpAddress("127.0.0.1a"));
        assertFalse(AddressUtils.isLiteralIpAddress(" 255.255.255.255"));
        assertFalse(AddressUtils.isLiteralIpAddress("0.0.00.0009"));
        assertFalse(AddressUtils.isLiteralIpAddress("192.009z.010.19"));
        assertFalse(AddressUtils.isLiteralIpAddress("254.249..094"));
        assertFalse(AddressUtils.isLiteralIpAddress("192.168.2.1%1"));
        assertFalse(AddressUtils.isLiteralIpAddress("192.168.2.1%eth0"));
    }

    @Test
    public void test_isLiteralIpAddress_iPv4_numbersTooLarge_failure() throws Exception {
        assertFalse(AddressUtils.isLiteralIpAddress("256.255.255.255"));
        assertFalse(AddressUtils.isLiteralIpAddress("255.255.255.256"));
        assertFalse(AddressUtils.isLiteralIpAddress("192.168.1.260"));
    }

    @Test
    public void test_isLiteralIpAddress_iPv6_success() throws Exception {
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
    public void test_isLiteralIpAddress_iPv6_failure() throws Exception {
        assertFalse(AddressUtils.isLiteralIpAddress(":::1"));
        assertFalse(AddressUtils.isLiteralIpAddress("::11111"));
        assertFalse(AddressUtils.isLiteralIpAddress("20011::1111"));
        assertFalse(AddressUtils.isLiteralIpAddress("2001:db8:::1"));
        assertFalse(AddressUtils.isLiteralIpAddress("2001:cdba:0000:00000:0000:0000:3257:9652"));
        assertFalse(
                AddressUtils.isLiteralIpAddress("2001:cdbA:0000:0000:0000:0000:0000:3257:9652"));
        assertFalse(AddressUtils.isLiteralIpAddress("2001:cdba:0::0:0:0:3257:9652"));
        assertFalse(AddressUtils.isLiteralIpAddress("02001:cdba::3257:9652"));
        assertFalse(AddressUtils.isLiteralIpAddress("2001:cdba::3257:96521"));
        assertFalse(AddressUtils.isLiteralIpAddress("2001:cdba::3257:9652%"));
    }

    @Test
    public void test_isLiteralIpAddress_null_throwsNPE() throws Exception {
        assertThrows(NullPointerException.class, () -> AddressUtils.isLiteralIpAddress(null));
    }

    private static final String OLD_IP_PATTERN =
            // IPv4 part: matches d.d.d.d where d is 0-255 (allows leading zeros)
            "^(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9]))|"
                    // IPv6 part (case-insensitive)
                    + "(?i:"
                    // Case 1: 7 prefix groups. Matches full (8 groups) or compressed at end (7
                    // groups + ::)
                    // e.g., 1:2:3:4:5:6:7:8 or 1:2:3:4:5:6:7::
                    + "(?:(?:[0-9a-f]{1,4}:){7}(?:[0-9a-f]{1,4}|:))|"
                    // Case 2: 6 prefix groups. Matches compressed in middle, compressed at end, or
                    // embedded
                    // IPv4
                    // e.g., 1:2:3:4:5:6::8, 1:2:3:4:5:6::, 1:2:3:4:5:6:1.2.3.4
                    + "(?:(?:[0-9a-f]{1,4}:){6}(?::[0-9a-f]{1,4}|(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|"
                    // Case 3: 5 prefix groups.
                    // e.g., 1:2:3:4:5::7:8, 1:2:3:4:5::1.2.3.4, 1:2:3:4:5::
                    + "(?:(?:[0-9a-f]{1,4}:){5}(?:(?:(?::[0-9a-f]{1,4}){1,2})|:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|"
                    // Case 4: 4 prefix groups.
                    + "(?:(?:[0-9a-f]{1,4}:){4}(?:(?:(?::[0-9a-f]{1,4}){1,3})|(?:(?::[0-9a-f]{1,4})?:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|"
                    // Case 5: 3 prefix groups.
                    + "(?:(?:[0-9a-f]{1,4}:){3}(?:(?:(?::[0-9a-f]{1,4}){1,4})|(?:(?::[0-9a-f]{1,4}){0,2}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|"
                    // Case 6: 2 prefix groups.
                    + "(?:(?:[0-9a-f]{1,4}:){2}(?:(?:(?::[0-9a-f]{1,4}){1,5})|(?:(?::[0-9a-f]{1,4}){0,3}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|"
                    // Case 7: 1 prefix group.
                    + "(?:(?:[0-9a-f]{1,4}:){1}(?:(?:(?::[0-9a-f]{1,4}){1,6})|(?:(?::[0-9a-f]{1,4}){0,4}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|"
                    // Case 8: 0 prefix groups. Starts with ::
                    // e.g., ::1, ::1.2.3.4, ::
                    + "(?::(?:(?:(?::[0-9a-f]{1,4}){1,7})|(?:(?::[0-9a-f]{1,4}){0,5}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))"
                    // Optional Zone ID (e.g., %eth0) at the end of IPv6
                    + ")(?:%.+)?$";
    private static final Pattern OLD_PATTERN = Pattern.compile(OLD_IP_PATTERN);

    private static boolean oldIsLiteralIpAddress(String hostname) {
        return OLD_PATTERN.matcher(hostname).matches();
    }

    @Test
    public void test_isLiteralIpAddress_differential() {
        String[] testCases = {
            // IPv4 Success
            "127.0.0.1",
            "255.255.255.255",
            "0.0.00.000",
            "192.009.010.19",
            "254.249.190.094",
            // IPv4 Failure
            "127.0.0.1a",
            " 255.255.255.255",
            "0.0.00.0009",
            "192.009z.010.19",
            "254.249..094",
            "192.168.2.1%1",
            "192.168.2.1%eth0",
            "256.255.255.255",
            "255.255.255.256",
            "192.168.1.260",
            // IPv6 Success
            "::1",
            "2001:Db8::1",
            "2001:cdbA:0000:0000:0000:0000:3257:9652",
            "2001:cdba:0:0:0:0:3257:9652",
            "2001:cdBA::3257:9652",
            "2001:cdba::3257:9652%1",
            "2001:cdba::3257:9652%eth0",
            "2001:cdba::3257:9652%int2.3!",
            // IPv6 Failure
            ":::1",
            "::11111",
            "20011::1111",
            "2001:db8:::1",
            "2001:cdba:0000:00000:0000:0000:3257:9652",
            "2001:cdbA:0000:0000:0000:0000:0000:3257:9652",
            "2001:cdba:0::0:0:0:3257:9652",
            "02001:cdba::3257:9652",
            "2001:cdba::3257:96521",
            "2001:cdba::3257:9652%",
            // Additional Edge Cases
            "",
            " ",
            "a",
            "1",
            "1.",
            "1.2",
            "1.2.3",
            "1.2.3.",
            "11.22.33.",
            "1.2.3.4.5",
            ":",
            ":::",
            "::::",
            "1:",
            ":1",
            "1::2::",
            "::1::2",
            "2001:db8:1:2:3:4:5:6:7",
            "2001:db8:1:2:3:4:5:6:7:8",
            "1:2:3:4:5:6:7:8::",
            "2001:db8:1:2:3:4:5:6:1.2.3.4",
            "2001:db8:1:2:3:4:5:1.2.3.4",
            "2001:db8:1:2:3:4:1.2.3.4.5",
            "2001:db8:1:2:3:4:256.1.1.1",
            "2001:db8::1.2.3.4%zone",
            "2001:db8::1.2.3.4%",
            "2001:db8::1.2.3.04",
            "localhost",
            "www.google.com",
            "127.0.0.1.ipv4.google.com",
            "1::",
            "2001:db8::1%eth%0",
            "2001:db8::1%eth 0",
            "2001:db8::1%\u000B",
            "2001:db8::1%\u000C",
            "2001:db8::1%\r",
            "2001:db8::1%\n",
            "2001:db8::1%\u0085",
            "2001:db8::1%\u2028",
            "2001:db8::1%\u2029",
            // Some random junk
            "asdfasdfasdf",
            "1:2:3:4:5:6:7:8:9:0",
            "::1.2.3.4.5.6",
            "2001:db8::1%_unsafe_zone_name",
            "2001:db8::1%eth\n0",
            "2001:db8::1.2.3.4%eth\n0",
            "[2001:db8::1]",
            "[::1]",
            "2001:db8::1%eth0%1",
            "2001:db8::1%eth0\u000C",
            "2001:db8::1%%",
            "2001:db8::1.2.3.4%%",
            "1.2.3.4\u0000",
            "2001:db8::1\u0000",
            "2001:db8::1%\u0000",
            "2001:db8::1%eth0\n",
            "127.0.0.1\n",
            "2001:db8::1\n",
            "::ffff:192.168.1.1",
            "::192.168.1.1",
            "::1.2.3.4::",
            "2001:db8::1.2.3.4::",
            // Tricky Zone ID cases
            "2001:db8::1%eth%0",
            "2001:db8::1.2.3.4%eth%0",
            "2001:db8::1%eth%",
            "2001:db8::1.2.3.4%eth%",
            "1.2.3.4%eth0",
            "1.2.3.4%",
            "2001:db8::1%",
            "2001:db8::1.2.3.4%",
            "2001:db8::1%eth0::",
            "2001:db8::1.2.3.4%eth0::",
            "2001:db8::1.2.3.4%eth0%eth1",
            "2001:db8:1:2:3:4:5:6%eth0::1",
            "2001:db8::%eth0",
            ":.1.2.3.4",
            "1::.2",
            "2001:db8::.1.2.3.4",
            // Tricky group and compression count cases
            "1:2:3:4:5:6::7",
            "1:2:3:4:5:6:7::",
            "::1:2:3:4:5:6:7",
            "1:2:3:4:5:6:7:8::",
            "::1:2:3:4:5:6:7:8",
            "1:2:3:4:5:6:7::8",
            // Leading zeros in IPv4/embedded IPv4
            "1.2.3.01",
            "0000.0.0.0",
            "2001:db8::1.2.3.0",
            "2001:db8::1.2.3.00",
            "2001:db8::%1.2.3.4",
            "2001:db8::1.2.3.4%5.6.7.8",
            "::%eth0",
            "1:2:3:4:5:6:7::",
            "1:2:3:4:5:6:7:8::",
            "1:2:3:4:5:6:7:8%eth0",
            "1:2:3:4:5:6:7:8:9%eth0",
            "2001:db8::1.2.3.01",
            "2001:db8::1.2.3.0",
            "2001:db8::1.2.3.00",
            // Systematic Regex Cases
            // Case 1 (7 prefix):
            "1:2:3:4:5:6:7:8",
            "1:2:3:4:5:6:7::",
            // Case 2 (6 prefix):
            "1:2:3:4:5:6::8",
            "1:2:3:4:5:6:1.2.3.4",
            "1:2:3:4:5:6::",
            // Case 3 (5 prefix):
            "1:2:3:4:5::8",
            "1:2:3:4:5::7:8",
            "1:2:3:4:5::1.2.3.4",
            "1:2:3:4:5::",
            // Case 4 (4 prefix):
            "1:2:3:4::8",
            "1:2:3:4::7:8",
            "1:2:3:4::6:7:8",
            "1:2:3:4::1.2.3.4",
            "1:2:3:4::8:1.2.3.4",
            "1:2:3:4::",
            // Case 5 (3 prefix):
            "1:2:3::8",
            "1:2:3::7:8",
            "1:2:3::6:7:8",
            "1:2:3::5:6:7:8",
            "1:2:3::1.2.3.4",
            "1:2:3::8:1.2.3.4",
            "1:2:3::7:8:1.2.3.4",
            "1:2:3::",
            // Case 6 (2 prefix):
            "1:2::8",
            "1:2::7:8",
            "1:2::6:7:8",
            "1:2::5:6:7:8",
            "1:2::4:5:6:7:8",
            "1:2::1.2.3.4",
            "1:2::8:1.2.3.4",
            "1:2::7:8:1.2.3.4",
            "1:2::6:7:8:1.2.3.4",
            "1:2::",
            // Case 7 (1 prefix):
            "1::8",
            "1::7:8",
            "1::6:7:8",
            "1::5:6:7:8",
            "1::4:5:6:7:8",
            "1::3:4:5:6:7:8",
            "1::1.2.3.4",
            "1::8:1.2.3.4",
            "1::7:8:1.2.3.4",
            "1::6:7:8:1.2.3.4",
            "1::5:6:7:8:1.2.3.4",
            "1::",
            // Case 8 (0 prefix):
            "::8",
            "::7:8",
            "::6:7:8",
            "::5:6:7:8",
            "::4:5:6:7:8",
            "::3:4:5:6:7:8",
            "::2:3:4:5:6:7:8",
            "::1.2.3.4",
            "::8:1.2.3.4",
            "::7:8:1.2.3.4",
            "::6:7:8:1.2.3.4",
            "::5:6:7:8:1.2.3.4",
            "::4:5:6:7:8:1.2.3.4",
            "::"
        };

        for (String tc : testCases) {
            boolean expected = oldIsLiteralIpAddress(tc);
            boolean actual = AddressUtils.isLiteralIpAddress(tc);
            if (!isRealAndroid() && isQuirkyCase(tc)) {
                // On OpenJDK (non-Android), the old regex (JDK) returns true for these quirky
                // cases,
                // but the new implementation consistently returns false (rejects them as invalid).
                Assert.assertTrue("Old regex should return true on OpenJDK for: " + tc, expected);
                Assert.assertFalse("New implementation should return false for: " + tc, actual);
            } else {
                Assert.assertEquals("Mismatched result for input: " + tc, expected, actual);
            }
        }
    }

    @Test
    public void test_isLiteralIpAddress_exhaustive() {
        String[] prefixes = {
            "",
            "1:",
            "1:2:",
            "1:2:3:",
            "1:2:3:4:",
            "1:2:3:4:5:",
            "1:2:3:4:5:6:",
            "1:2:3:4:5:6:7:",
            "1:2:3:4:5:6:7:8:",
            "::",
            "1::",
            "::1",
            "1::2",
            "1:2::",
            "::1:2",
            "1:2::3",
            "1::2:3",
            "1:2:3::",
            "::1:2:3",
            "1:2:3::4",
            "1::2:3:4",
            "1:2:3:4::",
            "::1:2:3:4",
            "1:2:3:4::5",
            "1::2:3:4:5",
            "1:2:3:4:5::",
            "::1:2:3:4:5",
            "1:2:3:4:5::6",
            "1::2:3:4:5:6",
            "1:2:3:4:5:6::",
            "::1:2:3:4:5:6",
            "1:2:3:4:5:6::7",
            "1::2:3:4:5:6:7",
            "1:2:3:4:5:6:7::",
            "::1:2:3:4:5:6:7",
            "1:2::3::4"
        };

        String[] suffixes = {
            "8",
            "8:9",
            "8:9:10",
            "1.2.3.4",
            "1.2.3.4.5",
            "1.2.3",
            "256.1.2.3",
            "1.2.3.04",
            "01.2.3.4",
            ""
        };

        String[] zones = {"", "%eth0", "%", "%eth0%1", "%\n"};

        for (String prefix : prefixes) {
            for (String suffix : suffixes) {
                for (String zone : zones) {
                    String tc = prefix + suffix + zone;
                    boolean expected = oldIsLiteralIpAddress(tc);
                    boolean actual = AddressUtils.isLiteralIpAddress(tc);
                    Assert.assertEquals("Mismatched result for input: " + tc, expected, actual);
                }
            }
        }
    }

    @Test
    public void test_isLiteralIpAddress_randomFuzz() {
        Random rand = new Random(42);
        char[] chars =
                "0123456789abcdefABCDEF:.% \n\r\0[]gGhHxXyYzZ+-/\u0085\u2028\u2029\u000B\u000C"
                        .toCharArray();
        for (int i = 0; i < 500000; i++) {
            int len = rand.nextInt(50);
            StringBuilder sb = new StringBuilder(len);
            for (int j = 0; j < len; j++) {
                sb.append(chars[rand.nextInt(chars.length)]);
            }
            String tc = sb.toString();
            boolean expected = oldIsLiteralIpAddress(tc);
            boolean actual = AddressUtils.isLiteralIpAddress(tc);
            if (expected != actual) {
                Assert.fail(
                        String.format(
                                "Mismatch for input '%s' (hex: %s): expected %b, actual %b",
                                tc, toHex(tc), expected, actual));
            }
        }
    }

    private static String toHex(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            sb.append(String.format("\\u%04x", (int) c));
        }
        return sb.toString();
    }

    private static boolean isRealAndroid() {
        String vmName = System.getProperty("java.vm.name");
        return vmName != null && vmName.contains("Dalvik");
    }

    private static boolean isQuirkyCase(String tc) {
        return tc.contains("\u000B") || tc.contains("\u000C");
    }
}
