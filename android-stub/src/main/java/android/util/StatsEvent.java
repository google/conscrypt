/*
 * Copyright (C) 2020 The Android Open Source Project
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

package android.util;

@SuppressWarnings({"unused",  "DoNotCallSuggester"})
public final class StatsEvent {
    public static StatsEvent.Builder newBuilder() {
        throw new RuntimeException("Stub!");
    }

    public int getAtomId() {
        throw new RuntimeException("Stub!");
    }

    public byte[] getBytes() {
        throw new RuntimeException("Stub!");
    }

    public int getNumBytes() {
        throw new RuntimeException("Stub!");
    }

    public void release() {
        throw new RuntimeException("Stub!");
    }

    private static final class Buffer {
    }

    @SuppressWarnings({"unused",  "DoNotCallSuggester"})
    public static final class Builder {
        public StatsEvent.Builder setAtomId(int atomId) {
            throw new RuntimeException("Stub!");
        }

        public StatsEvent.Builder writeBoolean(boolean value) {
            throw new RuntimeException("Stub!");
        }

        public StatsEvent.Builder writeInt(int value) {
            throw new RuntimeException("Stub!");
        }

        public StatsEvent.Builder writeIntArray(int[] values) {
            throw new RuntimeException("Stub!");
        }

        public StatsEvent.Builder writeLong(long value) {
            throw new RuntimeException("Stub!");
        }

        public StatsEvent.Builder writeFloat(float value) {
            throw new RuntimeException("Stub!");
        }

        public StatsEvent.Builder writeString(String value) {
            throw new RuntimeException("Stub!");
        }

        public StatsEvent.Builder writeByteArray(byte[] value) {
            throw new RuntimeException("Stub!");
        }

        public StatsEvent.Builder writeAttributionChain(int[] uids, String[] tags) {
            throw new RuntimeException("Stub!");
        }

        public StatsEvent.Builder addBooleanAnnotation(byte annotationId, boolean value) {
            throw new RuntimeException("Stub!");
        }

        public StatsEvent.Builder addIntAnnotation(byte annotationId, int value) {
            throw new RuntimeException("Stub!");
        }

        public StatsEvent.Builder usePooledBuffer() {
            throw new RuntimeException("Stub!");
        }

        public StatsEvent build() {
            throw new RuntimeException("Stub!");
        }
    }
}
