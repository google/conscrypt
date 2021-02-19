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

import static java.lang.Math.min;
import static org.conscrypt.Preconditions.checkArgument;

import java.nio.ByteBuffer;

final class BufferUtils {
    private BufferUtils() {}

    /**
     * Returns {@code true} if none of the buffers in the buffer array are null,
     * otherwise {@code false}.
     */
    static boolean noNulls(ByteBuffer[] buffers) {
        for (ByteBuffer buffer : buffers) {
            if (buffer == null) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns the total number of bytes remaining in the buffer array.
     */
    static long remaining(ByteBuffer[] buffers) {
        long size = 0;
        for (ByteBuffer buffer : buffers) {
            size += buffer.remaining();
        }
        return size;
    }

    /**
     * Marks {@code toConsume} bytes of data as consumed from the buffer array.
     *
     * @throws IllegalArgumentException if there are fewer than {@code toConsume} bytes remaining
     */
    static void consume(ByteBuffer[] sourceBuffers, int toConsume) {
        for (ByteBuffer sourceBuffer : sourceBuffers) {
            int amount = min(sourceBuffer.remaining(), toConsume);
            if (amount > 0) {
                sourceBuffer.position(sourceBuffer.position() + amount);
                toConsume -= amount;
                if (toConsume == 0) {
                    break;
                }
            }
        }
        if (toConsume > 0) {
            throw new IllegalArgumentException("toConsume > data size");
        }
    }

    /**
     * Looks for a buffer in the buffer array which EITHER is larger than {@code minSize} AND
     * has no preceding non-empty buffers OR is the only non-empty buffer in the array.
     */
    static ByteBuffer getBufferLargerThan(ByteBuffer[] buffers, int minSize) {
        int length = buffers.length;
        for (int i = 0; i < length; i++) {
            ByteBuffer buffer = buffers[i];
            int remaining = buffer.remaining();
            if (remaining > 0) {
                if (remaining >= minSize) {
                    return buffer;
                }
                for (int j = i + 1; j < length; j++) {
                    if (buffers[j].remaining() > 0) {
                        return null;
                    }
                }
                return buffer;
            }
        }
        return null;
    }

    /**
     * Copies up to {@code maxAmount} bytes from a buffer array to {@code destination}.
     * The copied data is <b>not</b> marked as consumed from the source buffers, on the
     * assumption the copy will be passed to some method which will consume between 0 and
     * {@code maxAmount} bytes which can then be reflected in the source array using the
     * {@code consume()} method.
     *
     */
    static ByteBuffer copyNoConsume(ByteBuffer[] buffers, ByteBuffer destination, int maxAmount) {
	checkArgument(destination.remaining() >= maxAmount, "Destination buffer too small");
	int needed = maxAmount;
        for (ByteBuffer buffer : buffers) {
	    int remaining = buffer.remaining();
            if (remaining > 0) {
                // If this buffer can fit completely then copy it all, otherwise temporarily
                // adjust its limit to fill so as to the output buffer completely
                int oldPosition = buffer.position();
                if (remaining <= needed) {
                    destination.put(buffer);
                    needed -= remaining;
                } else {
                    int oldLimit = buffer.limit();
                    buffer.limit(buffer.position() + needed);
                    destination.put(buffer);
                    buffer.limit(oldLimit);
                    needed = 0;
                }
                // Restore the buffer's position, the data won't get marked as consumed until
                // outputBuffer has been successfully consumed.
                buffer.position(oldPosition);
                if (needed == 0) {
                    break;
                }
            }
        }
        destination.flip();
        return destination;
    }
}
