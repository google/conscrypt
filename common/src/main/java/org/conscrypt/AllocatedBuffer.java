/*
 * Copyright (C) 2017 The Android Open Source Project
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

/*
 * Copyright 2013 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.conscrypt;

import static org.conscrypt.Preconditions.checkNotNull;

import java.nio.ByteBuffer;

/**
 * A buffer that was allocated by a {@link BufferAllocator}.
 */
@ExperimentalApi
public abstract class AllocatedBuffer {
    /**
     * Returns the {@link ByteBuffer} that backs this buffer.
     */
    public abstract ByteBuffer nioBuffer();

    /**
     * Increases the reference count by {@code 1}.
     */
    public abstract AllocatedBuffer retain();

    /**
     * Decreases the reference count by {@code 1} and deallocates this object if the reference count
     * reaches at {@code 0}.
     *
     * @return {@code true} if and only if the reference count became {@code 0} and this object has
     * been deallocated
     */
    public abstract AllocatedBuffer release();

    /**
     * Creates a new {@link AllocatedBuffer} that is backed by the given {@link ByteBuffer}.
     */
    public static AllocatedBuffer wrap(final ByteBuffer buffer) {
        checkNotNull(buffer, "buffer");

        return new AllocatedBuffer() {

            @Override
            public ByteBuffer nioBuffer() {
                return buffer;
            }

            @Override
            public AllocatedBuffer retain() {
                // Do nothing.
                return this;
            }

            @Override
            public AllocatedBuffer release() {
                // Do nothing.
                return this;
            }
        };
    }
}
