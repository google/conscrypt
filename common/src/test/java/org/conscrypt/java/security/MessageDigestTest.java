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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

// android-add: import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
import org.conscrypt.TestUtils;
// android-add: import org.junit.ClassRule;
import org.junit.Test;
// android-add: import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public final class MessageDigestTest {
    // android-add: Allow access to deprecated BC algorithms.

    private final byte[] sha_456 = {-24, 9,   -59, -47, -50,  -92,  123, 69, -29, 71,
                                    1,   -46, 63,  96,  -118, -102, 88,  3,  77,  -55};

    @Test
    public void testShaReset() throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA");
        sha.update(new byte[] {1, 2, 3});
        sha.reset();
        sha.update(new byte[] {4, 5, 6});
        assertEquals(Arrays.toString(sha_456), Arrays.toString(sha.digest()));
    }

    @Test
    public void test_getInstance() {
        ServiceTester.test("MessageDigest").run((provider, algorithm) -> {
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
        });
    }

    private static final Map<String, Map<String, byte[]>> EXPECTATIONS = new HashMap<>();
    private static void putExpectation(String algorithm, String inputName, byte[] expected) {
        algorithm = algorithm.toUpperCase(Locale.ROOT);
        Map<String, byte[]> expectations =
                EXPECTATIONS.computeIfAbsent(algorithm, k -> new HashMap<>());
        expectations.put(inputName, expected);
    }
    private static Map<String, byte[]> getExpectations(String algorithm) throws Exception {
        algorithm = algorithm.toUpperCase(Locale.ROOT);
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
        putExpectation("MD2", INPUT_EMPTY,
                       new byte[] {-125, 80, -27, -93, -30, 76, 21, 61, -14, 39, 92, -97, -128, 105,
                                   39, 115});
        putExpectation("MD5", INPUT_EMPTY,
                       new byte[] {-44, 29, -116, -39, -113, 0, -78, 4, -23, -128, 9, -104, -20, -8,
                                   66, 126});
        putExpectation("SHA", INPUT_EMPTY,
                       new byte[] {-38, 57,  -93,  -18, 94, 107,  75,  13,  50, 85,
                                   -65, -17, -107, 96,  24, -112, -81, -40, 7,  9});
        putExpectation("SHA1", INPUT_EMPTY,
                       new byte[] {-38, 57,  -93,  -18, 94, 107,  75,  13,  50, 85,
                                   -65, -17, -107, 96,  24, -112, -81, -40, 7,  9});
        putExpectation("SHA-1", INPUT_EMPTY,
                       new byte[] {-38, 57,  -93,  -18, 94, 107,  75,  13,  50, 85,
                                   -65, -17, -107, 96,  24, -112, -81, -40, 7,  9});
        putExpectation(
                "SHA-224", INPUT_EMPTY,
                new byte[] {-47, 74,  2,  -116, 42,  58, 43,   -55,  71,  97, 2,   -69, 40,  -126,
                            52,  -60, 21, -94,  -80, 31, -126, -114, -90, 42, -59, -77, -28, 47});
        putExpectation("SHA-256", INPUT_EMPTY,
                       new byte[] {-29,  -80,  -60, 66,   -104, -4, 28,  20, -102, -5,  -12,
                                   -56,  -103, 111, -71,  36,   39, -82, 65, -28,  100, -101,
                                   -109, 76,   -92, -107, -103, 27, 120, 82, -72,  85});
        putExpectation("SHA-384", INPUT_EMPTY,
                       new byte[] {56,  -80, 96,  -89, 81,  -84, -106, 56,  76, -39,  50,  126,
                                   -79, -79, -29, 106, 33,  -3,  -73,  17,  20, -66,  7,   67,
                                   76,  12,  -57, -65, 99,  -10, -31,  -38, 39, 78,   -34, -65,
                                   -25, 111, 101, -5,  -43, 26,  -46,  -15, 72, -104, -71, 91});
        putExpectation(
                "SHA-512", INPUT_EMPTY,
                new byte[] {-49, -125, -31,  53,   126, -17,  -72, -67, -15, 84, 40,  80,   -42,
                            109, -128, 7,    -42,  32,  -28,  5,   11,  87,  21, -36, -125, -12,
                            -87, 33,   -45,  108,  -23, -50,  71,  -48, -47, 60, 93,  -123, -14,
                            -80, -1,   -125, 24,   -46, -121, 126, -20, 47,  99, -71, 49,   -67,
                            71,  65,   122,  -127, -91, 56,   50,  122, -7,  39, -38, 62});
        putExpectation(
                "SHA-512/224", INPUT_EMPTY,
                TestUtils.decodeHex("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"));
        putExpectation("SHA-512/256", INPUT_EMPTY,
                       TestUtils.decodeHex(
                               "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"));
        putExpectation(
                "SHA3-224", INPUT_EMPTY,
                TestUtils.decodeHex("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"));
        putExpectation("SHA3-256", INPUT_EMPTY,
                       TestUtils.decodeHex(
                               "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
        putExpectation("SHA3-384", INPUT_EMPTY,
                       TestUtils.decodeHex(
                               "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
                               + "c3713831264adb47fb6bd1e058d5f004"));
        putExpectation(
                "SHA3-512", INPUT_EMPTY,
                TestUtils.decodeHex(
                        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                        + "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"));
        putExpectation("SHAKE128-256", INPUT_EMPTY,
                       TestUtils.decodeHex(
                               "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"));
        putExpectation(
                "SHAKE256-512", INPUT_EMPTY,
                TestUtils.decodeHex(
                        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
                        + "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"));

        // Regression test for a SHA-1 problem with inputs larger than 256 MiB. http://b/4501620
        // In mid-2013 this takes 3 minutes even on the host, so let's not run it on devices.
        if (System.getenv("ANDROID_BUILD_TOP") != null) {
            // INPUT_256MB
            putExpectation("MD2", INPUT_256MB,
                           new byte[] {-63, -120, 6, 67, 12, -87, -39, -11, -67, -3, -31, -41, -91,
                                       16, -35, 91});
            putExpectation("MD5", INPUT_256MB,
                           new byte[] {31, 80, 57, -27, 11, -42, 107, 41, 12, 86, 104, 77, -123, 80,
                                       -58, -62});
            putExpectation("SHA", INPUT_256MB,
                           new byte[] {123,  -111, -37, -36, 86,  -59, 120, 30,  -33, 108,
                                       -120, 71,   -76, -86, 105, 101, 86,  108, 92,  117});
            putExpectation("SHA-1", INPUT_256MB,
                           new byte[] {123,  -111, -37, -36, 86,  -59, 120, 30,  -33, 108,
                                       -120, 71,   -76, -86, 105, 101, 86,  108, 92,  117});
            putExpectation("SHA-224", INPUT_256MB,
                           new byte[] {-78, 82,  5,   -71, 57,  119, 77,  -32, -62, -74,
                                       -40, 64,  -57, 79,  40,  116, -18, 48,  -69, 45,
                                       18,  -94, 111, 114, -45, -93, 43,  -11});
            putExpectation("SHA-256", INPUT_256MB,
                           new byte[] {-90, -41,  42,  -57, 105,  15,  83, -66, 106, -28, 107,
                                       -88, -123, 6,   -67, -105, 48,  42, 9,   63,  113, 8,
                                       71,  43,   -39, -17, -61,  -50, -3, -96, 100, -124});
            putExpectation(
                    "SHA-384", INPUT_256MB,
                    new byte[] {71,   72,  77,  -83, -110, 22,   -118, -18, -58, 119, 115,  74,
                                -67,  -36, 84,  122, -105, -67,  -75,  15,  -33, 37,  78,   -95,
                                4,    118, -53, 106, 65,   -115, -19,  121, -59, -94, -45,  -111,
                                -124, 35,  35,  60,  67,   -34,  62,   106, -16, 122, -110, -14});
            putExpectation(
                    "SHA-512", INPUT_256MB,
                    new byte[] {36,  7,    -120, 39,   -87, -87, 84,  -40, -66, 114,  62,  -73, 107,
                                101, -117, -12,  -124, 20,  109, 103, -92, 125, 111,  102, 12,  114,
                                -68, 100,  30,   25,   -88, 62,  108, 56,  9,   -107, 89,  -25, -50,
                                118, -87,  100,  13,   37,  -14, 66,  -40, -97, 105,  -27, 79,  -62,
                                53,  -31,  83,   40,   4,   57,  90,  -81, 63,  -77,  -42, 113});
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
                byte[] mb = new byte[1024 * 1024];
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

    // SHAKE256 with 512-bit output of the 1600-bit message consisting of 200 bytes of 0xa3, from
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg1600.pdf
    private static final String SHAKE256_512_OF_MSG1600 =
            "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d"
            + "2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b";

    /**
     * SHAKE256 is an extendable-output function, which Conscrypt exposes through the fixed-length
     * MessageDigest algorithm "SHAKE256-512". Checks that the fixed output length is applied
     * consistently across one-shot, incremental, cloned, and reused digests.
     */
    @Test
    public void testShake256_512() throws Exception {
        Provider conscrypt = TestUtils.getConscryptProvider();
        byte[] msg1600 = new byte[200];
        Arrays.fill(msg1600, (byte) 0xa3);
        byte[] expectedMsg1600 = TestUtils.decodeHex(SHAKE256_512_OF_MSG1600);
        byte[] expectedEmpty = getExpectations("SHAKE256-512").get(INPUT_EMPTY);

        MessageDigest md = MessageDigest.getInstance("SHAKE256-512", conscrypt);
        assertEquals("SHAKE256-512", md.getAlgorithm());
        assertEquals(64, md.getDigestLength());
        assertArrayEquals(expectedMsg1600, md.digest(msg1600));

        // digest() resets the state, so the same instance can be reused.
        assertArrayEquals(expectedEmpty, md.digest());

        // Incremental updates give the same result as the one-shot computation.
        md.update(msg1600, 0, 100);
        for (int i = 100; i < 150; i++) {
            md.update(msg1600[i]);
        }
        md.update(ByteBuffer.wrap(msg1600, 150, 50));
        assertArrayEquals(expectedMsg1600, md.digest());

        // A clone taken part-way through continues independently of the original.
        md.update(msg1600, 0, 100);
        MessageDigest copy = (MessageDigest) md.clone();
        md.reset();
        assertArrayEquals(expectedMsg1600, copy.digest(Arrays.copyOfRange(msg1600, 100, 200)));
        assertArrayEquals(expectedEmpty, md.digest());

        // The id-shake256 OID (RFC 8702) is an alias for SHAKE256-512.
        MessageDigest byOid = MessageDigest.getInstance("2.16.840.1.101.3.4.2.12", conscrypt);
        assertEquals(64, byOid.getDigestLength());
        assertArrayEquals(expectedMsg1600, byOid.digest(msg1600));
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
