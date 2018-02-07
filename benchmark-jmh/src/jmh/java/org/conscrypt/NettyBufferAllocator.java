/*
 * Copyright 2017 The Android Open Source Project
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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.PooledByteBufAllocator;
import java.nio.ByteBuffer;

/**
 * A {@link BufferAllocator} that is backed by a Netty buffer pool.
 */
final class NettyBufferAllocator extends BufferAllocator {
    private static final ByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
    private static final NettyBufferAllocator instance = new NettyBufferAllocator();

    static NettyBufferAllocator getInstance() {
        return instance;
    }

    private NettyBufferAllocator() {}

    @Override
    public AllocatedBuffer allocateDirectBuffer(int capacity) {
        return new ByteBufAdapter(alloc.directBuffer(capacity));
    }

    private static final class ByteBufAdapter extends AllocatedBuffer {
        private final ByteBuf nettyBuffer;
        private final ByteBuffer buffer;

        private ByteBufAdapter(ByteBuf nettyBuffer) {
            this.nettyBuffer = nettyBuffer;
            this.buffer = nettyBuffer.nioBuffer(0, nettyBuffer.capacity());
        }

        @Override
        public ByteBuffer nioBuffer() {
            return buffer;
        }

        @Override
        public AllocatedBuffer retain() {
            nettyBuffer.retain();
            return this;
        }

        @Override
        public AllocatedBuffer release() {
            nettyBuffer.release();
            return this;
        }
    }
}
