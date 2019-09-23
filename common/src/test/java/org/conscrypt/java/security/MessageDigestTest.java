/*
 * Copyright (C) 2010 The Android Open Source Project
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

package org.conscrypt.java.security;

import static org.junit.Assert.assertEquals;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public final class MessageDigestTest {

    private final byte[] sha_456 = {
            -24,   9, -59, -47,  -50,  -92, 123, 69, -29,  71,
              1, -46,  63,  96, -118, -102,  88,  3,  77, -55
    };

    @Test
    public void testShaReset() throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA");
        sha.update(new byte[] { 1, 2, 3 });
        sha.reset();
        sha.update(new byte[] { 4, 5, 6 });
        assertEquals(Arrays.toString(sha_456), Arrays.toString(sha.digest()));
    }

    @Test
    public void test_getInstance() throws Exception {
        ServiceTester.test("MessageDigest")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider provider, String algorithm) throws Exception {
                    // MessageDigest.getInstance(String)
                    MessageDigest md1 = MessageDigest.getInstance(algorithm);
                    assertEquals(algorithm, md1.getAlgorithm());
                    test_MessageDigest(md1);

                    // MessageDigest.getInstance(String, Provider)
                    MessageDigest md2 = MessageDigest.getInstance(algorithm, provider);
                    assertEquals(algorithm, md2.getAlgorithm());
                    assertEquals(provider, md2.getProvider());
                    test_MessageDigest(md2);

                    // MessageDigest.getInstance(String, String)
                    MessageDigest md3 = MessageDigest.getInstance(algorithm, provider.getName());
                    assertEquals(algorithm, md3.getAlgorithm());
                    assertEquals(provider, md3.getProvider());
                    test_MessageDigest(md3);
                }
            });
    }

    private static final Map<String, Map<String, byte[]>> EXPECTATIONS
            = new HashMap<String, Map<String, byte[]>>();
    private static void putExpectation(String algorithm, String inputName, byte[] expected) {
        algorithm = algorithm.toUpperCase();
        Map<String, byte[]> expectations = EXPECTATIONS.get(algorithm);
        if (expectations == null) {
            expectations = new HashMap<String, byte[]>();
            EXPECTATIONS.put(algorithm, expectations);
        }
        expectations.put(inputName, expected);
    }
    private static Map<String, byte[]> getExpectations(String algorithm) throws Exception {
        algorithm = algorithm.toUpperCase();
        Map<String, byte[]> expectations = EXPECTATIONS.get(algorithm);
        if (expectations == null) {
            throw new Exception("No expectations for MessageDigest." + algorithm);
        }
        return expectations;
    }
    private static final String INPUT_EMPTY = "empty";
    private static final String INPUT_256MB = "256mb";
    static {
        // INPUT_EMPTY
        putExpectation("MD2",
                       INPUT_EMPTY,
                       new byte[] { -125, 80, -27, -93, -30, 76, 21, 61,
                                    -14, 39, 92, -97, -128, 105, 39, 115 });
        putExpectation("MD5",
                       INPUT_EMPTY,
                       new byte[] { -44, 29, -116, -39, -113, 0, -78, 4,
                                    -23, -128, 9, -104, -20, -8, 66, 126 });
        putExpectation("SHA",
                       INPUT_EMPTY,
                       new byte[] { -38, 57, -93, -18, 94, 107, 75, 13,
                                    50, 85, -65, -17, -107, 96, 24, -112,
                                    -81, -40, 7, 9});
        putExpectation("SHA1",
                       INPUT_EMPTY,
                       new byte[] { -38, 57, -93, -18, 94, 107, 75, 13,
                                    50, 85, -65, -17, -107, 96, 24, -112,
                                    -81, -40, 7, 9});
        putExpectation("SHA-1",
                       INPUT_EMPTY,
                       new byte[] { -38, 57, -93, -18, 94, 107, 75, 13,
                                    50, 85, -65, -17, -107, 96, 24, -112,
                                    -81, -40, 7, 9});
        putExpectation("SHA-224",
                       INPUT_EMPTY,
                       new byte[] { -47, 74, 2, -116, 42, 58, 43, -55, 71,
                                    97, 2, -69, 40, -126, 52, -60, 21,
                                    -94, -80, 31, -126, -114, -90, 42,
                                    -59, -77, -28, 47});
        putExpectation("SHA-256",
                       INPUT_EMPTY,
                       new byte[] { -29, -80, -60, 66, -104, -4, 28, 20,
                                    -102, -5, -12, -56, -103, 111, -71, 36,
                                    39, -82, 65, -28, 100, -101, -109, 76,
                                    -92, -107, -103, 27, 120, 82, -72, 85 });
        putExpectation("SHA-384",
                       INPUT_EMPTY,
                       new byte[] { 56, -80, 96, -89, 81, -84, -106, 56,
                                    76, -39, 50, 126, -79, -79, -29, 106,
                                    33, -3, -73, 17, 20, -66, 7, 67,
                                    76, 12, -57, -65, 99, -10, -31, -38,
                                    39, 78, -34, -65, -25, 111, 101, -5,
                                    -43, 26, -46, -15, 72, -104, -71, 91 });
        putExpectation("SHA-512",
                       INPUT_EMPTY,
                       new byte[] { -49, -125, -31, 53, 126, -17, -72, -67,
                                    -15, 84, 40, 80, -42, 109, -128, 7,
                                    -42, 32, -28, 5, 11, 87, 21, -36,
                                    -125, -12, -87, 33, -45, 108, -23, -50,
                                    71, -48, -47, 60, 93, -123, -14, -80,
                                    -1, -125, 24, -46, -121, 126, -20, 47,
                                    99, -71, 49, -67, 71, 65, 122, -127,
                                    -91, 56, 50, 122, -7, 39, -38, 62 });
        putExpectation("SHA-512/224",
            INPUT_EMPTY,
            TestUtils.decodeHex(
                "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"));
        putExpectation("SHA-512/256",
            INPUT_EMPTY,
            TestUtils.decodeHex(
                "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"));
        putExpectation("SHA3-224",
            INPUT_EMPTY,
            TestUtils.decodeHex(
                "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"));
        putExpectation("SHA3-256",
            INPUT_EMPTY,
            TestUtils.decodeHex(
                "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
        putExpectation("SHA3-384",
            INPUT_EMPTY,
            TestUtils.decodeHex(
                "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
                    + "c3713831264adb47fb6bd1e058d5f004"));
        putExpectation("SHA3-512",
            INPUT_EMPTY,
            TestUtils.decodeHex(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                    + "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"));

        // Regression test for a SHA-1 problem with inputs larger than 256 MiB. http://b/4501620
        // In mid-2013 this takes 3 minutes even on the host, so let's not run it on devices.
        if (System.getenv("ANDROID_BUILD_TOP") != null) {
            // INPUT_256MB
            putExpectation("MD2",
                           INPUT_256MB,
                           new byte[] { -63, -120, 6, 67, 12, -87, -39, -11,
                                        -67, -3, -31, -41, -91, 16, -35, 91 });
            putExpectation("MD5",
                           INPUT_256MB,
                           new byte[] { 31, 80, 57, -27, 11, -42, 107, 41,
                                        12, 86, 104, 77, -123, 80, -58, -62 });
            putExpectation("SHA",
                           INPUT_256MB,
                           new byte[] { 123, -111, -37, -36, 86, -59, 120, 30,
                                        -33, 108, -120, 71, -76, -86, 105, 101,
                                        86, 108, 92, 117 });
            putExpectation("SHA-1",
                           INPUT_256MB,
                           new byte[] { 123, -111, -37, -36, 86, -59, 120, 30,
                                        -33, 108, -120, 71, -76, -86, 105, 101,
                                        86, 108, 92, 117 });
            putExpectation("SHA-224",
                           INPUT_256MB,
                           new byte[] { -78, 82, 5, -71, 57, 119, 77, -32,
                                        -62, -74, -40, 64, -57, 79, 40, 116,
                                        -18, 48, -69, 45, 18, -94, 111, 114,
                                        -45, -93, 43, -11 });
            putExpectation("SHA-256",
                           INPUT_256MB,
                           new byte[] { -90, -41, 42, -57, 105, 15, 83, -66,
                                        106, -28, 107, -88, -123, 6, -67, -105,
                                        48, 42, 9, 63, 113, 8, 71, 43,
                                        -39, -17, -61, -50, -3, -96, 100, -124 });
            putExpectation("SHA-384",
                           INPUT_256MB,
                           new byte[] { 71, 72, 77, -83, -110, 22, -118, -18,
                                        -58, 119, 115, 74, -67, -36, 84, 122,
                                        -105, -67, -75, 15, -33, 37, 78, -95,
                                        4, 118, -53, 106, 65, -115, -19, 121,
                                        -59, -94, -45, -111, -124, 35, 35, 60,
                                        67, -34, 62, 106, -16, 122, -110, -14 });
            putExpectation("SHA-512",
                           INPUT_256MB,
                           new byte[] { 36, 7, -120, 39, -87, -87, 84, -40,
                                        -66, 114, 62, -73, 107, 101, -117, -12,
                                        -124, 20, 109, 103, -92, 125, 111, 102,
                                        12, 114, -68, 100, 30, 25, -88, 62,
                                        108, 56, 9, -107, 89, -25, -50, 118,
                                        -87, 100, 13, 37, -14, 66, -40, -97,
                                        105, -27, 79, -62, 53, -31, 83, 40,
                                        4, 57, 90, -81, 63, -77, -42, 113 });
        }
    }

    private void test_MessageDigest(MessageDigest md) throws Exception {
        String algorithm = md.getAlgorithm();
        for (Map.Entry<String, byte[]> expectation : getExpectations(algorithm).entrySet()) {
            String inputName = expectation.getKey();
            byte[] expected = expectation.getValue();
            byte[] actual;
            if (inputName.equals(INPUT_EMPTY)) {
                actual = md.digest();
            } else if (inputName.equals(INPUT_256MB)) {
                byte[] mb = new byte[1 * 1024 * 1024];
                for (int i = 0; i < 256; i++) {
                    md.update(mb);
                }
                actual = md.digest();
            } else {
                throw new AssertionError(inputName);
            }
            assertEquals(algorithm, javaBytes(expected), javaBytes(actual));
            assertEquals(algorithm, expected.length, md.getDigestLength());
        }
    }

    private String javaBytes(byte[] bytes) {
        StringBuilder buf = new StringBuilder();
        buf.append("new byte[] { ");
        for (byte b : bytes) {
            buf.append(b);
            buf.append(", ");
        }
        buf.append(" }");
        return buf.toString();
    }
}
