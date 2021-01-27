/*
 * Copyright (C) 2021 The Android Open Source Project
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

import static org.conscrypt.TestUtils.decodeHex;
import static org.conscrypt.TestUtils.encodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Random;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MacTest {
    // Column indices in test vector CSV file
    private static final int ALGORITHM_INDEX = 0;
    private static final int KEY_INDEX = 1;
    private static final int MESSAGE_INDEX = 2;
    private static final int MAC_INDEX = 3;

    // Number of splits to use when testing multiple buffers
    private static final int NUM_SPLITS = 4;

    private final Random random = new Random(System.currentTimeMillis());

    @BeforeClass
    public static void setUp() {
        TestUtils.assumeAllowsUnsignedCrypto();
    }

    @Test
    public void knownAnswerTest() throws Exception {
        List<String[]> data = TestUtils.readCsvResource("crypto/macs.csv");

        for (String[] entry : data) {
            String algorithm = entry[ALGORITHM_INDEX];
            String key = entry[KEY_INDEX];
            String msg = entry[MESSAGE_INDEX];
            String expected = entry[MAC_INDEX];

            byte[] keyBytes = decodeHex(key);
            byte[] msgBytes = decodeHex(msg);
            byte[] expectedBytes = decodeHex(expected);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "RawBytes");

            String baseFailMsg = String.format("Mac=%s\nKey=%s\nMsg=%s\nExpected=%s",
                    algorithm, key, msg, expected);

            // Calculate using Mac.update(byte[])
            byte[] macBytes = generateMacUsingUpdate(algorithm, secretKey, msgBytes);
            assertArrayEquals(failMessage("Using update()", baseFailMsg, macBytes),
                    expectedBytes, macBytes);

            // Calculate using Mac.final(byte[])
            macBytes = generateMacUsingFinal(algorithm, secretKey, msgBytes);
            assertArrayEquals(failMessage("Using final()", baseFailMsg, macBytes),
                    expectedBytes, macBytes);

            // Calculate using Mac.update(ByteBuffer) with a single non-direct ByteBuffer
            ByteBuffer nondirectBuffer = ByteBuffer.wrap(msgBytes);
            macBytes = generateMac(algorithm, secretKey, nondirectBuffer);
            assertArrayEquals(failMessage("Non-direct ByteBuffer", baseFailMsg, macBytes),
                    expectedBytes, macBytes);

            // Calculate using Mac.update(ByteBuffer) with a single direct ByteBuffer
            ByteBuffer directBuffer = ByteBuffer.allocateDirect(msgBytes.length);
            directBuffer.put(msgBytes);
            directBuffer.flip();
            macBytes = generateMac(algorithm, secretKey, directBuffer);
            assertArrayEquals(failMessage("Direct ByteBuffer", baseFailMsg, macBytes),
                    expectedBytes, macBytes);

            // Calculate using Mac.update(ByteBuffer) with a multiple non-direct ByteBuffers
            nondirectBuffer.flip();
            macBytes = generateMac(algorithm, secretKey, split(nondirectBuffer));
            assertArrayEquals(failMessage("Multiple non-direct ByteBuffers", baseFailMsg, macBytes),
                    expectedBytes, macBytes);

            // Calculate using Mac.update(ByteBuffer) with a multiple direct ByteBuffers
            directBuffer.flip();
            macBytes = generateMac(algorithm, secretKey, split(directBuffer));
            assertArrayEquals(failMessage("Multiple direct ByteBuffers", baseFailMsg, macBytes),
                    expectedBytes, macBytes);

            // Calculated using a pre-loved Mac
            macBytes = generateReusingMac(algorithm, keyBytes, msgBytes);
            assertArrayEquals(failMessage("Re-use Mac", baseFailMsg, macBytes),
                    expectedBytes, macBytes);
        }
    }

    private String failMessage(String test, String base, byte[] mac) {
        return String.format("Test %s\n%s\nActual=  %s", test, base, encodeHex(mac));
    }

    // Splits a ByteBuffer into an array of NUM_SPLITS ByteBuffers containing the same data.
    // If input.remaining < NUM_SPLITS then some buffers will be empty, which is fine.
    private ByteBuffer[] split(ByteBuffer input) {
        ByteBuffer[] buffers = new ByteBuffer[NUM_SPLITS];
        int targetSize = (input.remaining() / NUM_SPLITS) + 1;
        ByteBuffer buffer;
        for (int i = 0; i < NUM_SPLITS; i++) {
            int size = Math.min(targetSize, input.remaining());
            buffer = input.isDirect() ? ByteBuffer.allocateDirect(size) : ByteBuffer.allocate(size);
            buffers[i] = buffer;

            int savedLimit = input.limit();
            input.limit(input.position() + size);
            buffer.put(input);
            buffer.flip();
            input.limit(savedLimit);
        }
        assertEquals(0, input.remaining());
        return buffers;
    }

    private byte[] generateMacUsingUpdate(String algorithm, SecretKeySpec key, byte[] message)
            throws Exception {
        Mac mac = Mac.getInstance(algorithm);
        assertNotNull(mac);
        mac.init(key);
        mac.update(message);
        return mac.doFinal();
    }

    private byte[] generateMacUsingFinal(String algorithm, SecretKeySpec key, byte[] message)
            throws Exception {
        Mac mac = Mac.getInstance(algorithm);
        assertNotNull(mac);
        mac.init(key);
        return mac.doFinal(message);
    }

    private byte[] generateMac(String algorithm, SecretKeySpec key, ByteBuffer buffer)
            throws Exception {
        return generateMac(algorithm, key, new ByteBuffer[] { buffer });
    }

    private byte[] generateMac(String algorithm, SecretKeySpec key, ByteBuffer[] buffers)
            throws Exception {
        Mac mac = Mac.getInstance(algorithm);
        assertNotNull(mac);
        mac.init(key);
        for (ByteBuffer buffer : buffers) {
            mac.update(buffer);
        }
        return mac.doFinal();
    }

    private byte[] generateReusingMac(String algorithm, byte[] keyBytes, byte[] message)
            throws Exception {
        Mac mac = Mac.getInstance(algorithm);
        assertNotNull(mac);

        // Mutate the original message and key and calculate a MAC from them
        byte[] otherKeyBytes = new byte[keyBytes.length];
        random.nextBytes(otherKeyBytes);
        SecretKeySpec otherKey = new SecretKeySpec(otherKeyBytes, "RawBytes");
        byte[] otherMessage = new byte[message.length];
        random.nextBytes(otherMessage);
        mac.init(otherKey);
        mac.doFinal(otherMessage);

        // Then re-use the same Mac with the original key and message
        SecretKeySpec key = new SecretKeySpec(keyBytes, "RawBytes");
        mac.reset();
        mac.init(key);
        mac.update(message);
        return mac.doFinal();
    }
}
