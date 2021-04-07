/*
 * Copyright 2021 The Android Open Source Project
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;
import org.conscrypt.TestUtils.BufferType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;


@RunWith(Parameterized.class)
public class BufferUtilsTest {
    private static final int K64 = 64 * 1024;
    private static final int K16 = 16 * 1024;

    private static final int[][] TEST_SIZES = {
            // All even numbers as several tests use size/2
            { 0 },
            { 0, 0, 0, 0 },
            { 0, 0, 0, 2 },
            { 2, 0, 0, 0 },
            { 100, 200, 300 },
            { 1000, 2000, 3000 },
            { K16 },
            { 0, 0, K16 },
            { K16, 0, 0 },
            { K64 },
            { 0, 0, K64 },
            { K64, 0, 0 },
            { 100, 100, K64 },
            { K64, 100, 100 },
            { K64, K64, K64 },
    };


    @Parameters(name = "{0}")
    public static BufferType[] data() {
        return new BufferType[] { BufferType.HEAP, BufferType.DIRECT };
    }

    @Parameter
    public BufferType bufferType;

    @Test
    public void checkNotNull() {
        for (int[] sizes : TEST_SIZES) {
            BufferUtils.checkNotNull(bufferType.newRandomBuffers(sizes));
        }

        ByteBuffer[] buffers = bufferType.newRandomBuffers(10, 10, 10, 10, 10);
        buffers[2] = null;
        try {
            BufferUtils.checkNotNull(buffers);
            fail();
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

    @Test
    public void remaining() {
        for (int[] sizes : TEST_SIZES) {
            assertEquals(arraySum(sizes),
                    BufferUtils.remaining(bufferType.newRandomBuffers(sizes)));
        }
    }

    @Test
    public void consume() {
        for (int[] sizes : TEST_SIZES) {
            ByteBuffer[] buffers = bufferType.newRandomBuffers(sizes);
            int totalSize = arraySum(sizes);

            BufferUtils.consume(buffers, 0);
            assertEquals(totalSize, BufferUtils.remaining(buffers));

            BufferUtils.consume(buffers,totalSize / 2);
            assertEquals(totalSize / 2, BufferUtils.remaining(buffers));

            BufferUtils.consume(buffers,totalSize / 2);
            assertEquals(0, BufferUtils.remaining(buffers));

            if (totalSize > 0) {
                try {
                    BufferUtils.consume(buffers, totalSize / 2);
                    fail("Managed to consume past end of buffer array");
                } catch (IllegalArgumentException e) {
                    // Expected
                }
            }
        }
    }

    @Test
    public void copyNoConsume() {
        for (BufferType destinationType : BufferType.values()) {
            for (int[] sizes : TEST_SIZES) {
                ByteBuffer[] buffers = bufferType.newRandomBuffers(sizes);
                int totalSize = arraySum(sizes);

                ByteBuffer destination = destinationType.newBuffer(totalSize);
                BufferUtils.copyNoConsume(buffers, destination, totalSize);
                assertEquals(totalSize, BufferUtils.remaining(buffers));

                assertArrayEquals(toArray(buffers), toArray(destination));
            }
        }
    }

    private static byte[] toArray(ByteBuffer... buffers) {
        byte[] bytes = new byte[(int) BufferUtils.remaining(buffers)];
        int offset = 0;
        for (ByteBuffer buffer : buffers) {
            int length = buffer.remaining();
            if (length > 0) {
                buffer.get(bytes, offset, length);
                offset += length;
            }
        }
        return bytes;
    }

    @Test
    public void getBufferLargerThan_allSmall() {
        ByteBuffer[] buffers = bufferType.newRandomBuffers(100, 200, 300, 400);

        assertNull(BufferUtils.getBufferLargerThan(buffers, K16));

        BufferUtils.consume(buffers, 300);
        assertNull(BufferUtils.getBufferLargerThan(buffers, K16));
        assertSame(buffers[2], BufferUtils.getBufferLargerThan(buffers, 100));

        BufferUtils.consume(buffers, 300);
        assertSame(buffers[3], BufferUtils.getBufferLargerThan(buffers, K16));

        BufferUtils.consume(buffers, 200);
        assertSame(buffers[3], BufferUtils.getBufferLargerThan(buffers, K16));

        BufferUtils.consume(buffers, 200);
        ByteBuffer buffer = BufferUtils.getBufferLargerThan(buffers, K16);
        assertNull(buffer);
    }

    @Test
    public void getBufferLargerThan_oneLarge() {
        ByteBuffer[] buffers = bufferType.newRandomBuffers(100, K64, 300, 400);

        assertNull(BufferUtils.getBufferLargerThan(buffers, K16));

        BufferUtils.consume(buffers, 100);
        assertSame(buffers[1], BufferUtils.getBufferLargerThan(buffers, K16));

        BufferUtils.consume(buffers, 1024); // 63K remaining in buffers[1]
        assertSame(buffers[1], BufferUtils.getBufferLargerThan(buffers, K16));

        BufferUtils.consume(buffers, 60 * 1024); // 3K remaining in buffers[1]
        assertNull(BufferUtils.getBufferLargerThan(buffers, K16));

        BufferUtils.consume(buffers, 3 * 1024);
        assertEquals(0, buffers[1].remaining());
        assertNull(BufferUtils.getBufferLargerThan(buffers, K16));

        BufferUtils.consume(buffers, 300);
        assertSame(buffers[3], BufferUtils.getBufferLargerThan(buffers, K16));

        BufferUtils.consume(buffers, 400);
        ByteBuffer buffer = BufferUtils.getBufferLargerThan(buffers, K16);
        assertNull(buffer);
    }

    @Test
    public void getBufferLargerThan_onlyOneBuffer() {
        ByteBuffer[] buffers = bufferType.newRandomBuffers(0, 0, 100, 0, 0);

        assertSame(buffers[2], BufferUtils.getBufferLargerThan(buffers, K16));
    }

    private int arraySum(int[] sizes) {
        int sum = 0;
        for (int i : sizes) {
            sum += i;
        }
        return sum;
    }
}
