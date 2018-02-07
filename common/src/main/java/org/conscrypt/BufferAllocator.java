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
package org.conscrypt;

import java.nio.ByteBuffer;

/**
 * An object responsible for allocation of buffers. This is an extension point to enable buffer
 * pooling within an application.
 */
@ExperimentalApi
public abstract class BufferAllocator {
    private static final BufferAllocator UNPOOLED = new BufferAllocator() {
        @Override
        public AllocatedBuffer allocateDirectBuffer(int capacity) {
            return AllocatedBuffer.wrap(ByteBuffer.allocateDirect(capacity));
        }
    };

    /**
     * Returns an unpooled buffer allocator, which will create a new buffer for each request.
     */
    public static BufferAllocator unpooled() {
        return UNPOOLED;
    }

    /**
     * Allocates a direct (i.e. non-heap) buffer with the given capacity.
     */
    public abstract AllocatedBuffer allocateDirectBuffer(int capacity);
}
