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
package org.conscrypt.metrics;

import org.conscrypt.Internal;

/**
 * Reflection wrapper around android.util.StatsEvent.
 */
@Internal
public class ReflexiveStatsEvent {
    private static final OptionalMethod newBuilder;
    private static final Class<?> c_statsEvent;

    static {
        c_statsEvent = initStatsEventClass();
        newBuilder = new OptionalMethod(c_statsEvent, "newBuilder");
    }

    private static Class<?> initStatsEventClass() {
        try {
            return Class.forName("android.util.StatsEvent");
        } catch (ClassNotFoundException ignored) {
            return null;
        }
    }

    private Object statsEvent;

    private ReflexiveStatsEvent(Object statsEvent) {
        this.statsEvent = statsEvent;
    }

    public Object getStatsEvent() {
        return statsEvent;
    }

    public static ReflexiveStatsEvent.Builder newBuilder() {
        return new ReflexiveStatsEvent.Builder();
    }

    public static ReflexiveStatsEvent buildEvent(
            int atomId, boolean success, int protocol, int cipherSuite, int duration) {
        ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
        builder.setAtomId(atomId);
        builder.writeBoolean(success);
        builder.writeInt(protocol);
        builder.writeInt(cipherSuite);
        builder.writeInt(duration);
        builder.usePooledBuffer();
        return builder.build();
    }

    public static final class Builder {
        private static final Class<?> c_statsEvent_Builder;
        private static final OptionalMethod setAtomId;
        private static final OptionalMethod writeBoolean;
        private static final OptionalMethod writeInt;
        private static final OptionalMethod build;
        private static final OptionalMethod usePooledBuffer;

        static {
            c_statsEvent_Builder = initStatsEventBuilderClass();
            setAtomId = new OptionalMethod(c_statsEvent_Builder, "setAtomId", int.class);
            writeBoolean = new OptionalMethod(c_statsEvent_Builder, "writeBoolean", boolean.class);
            writeInt = new OptionalMethod(c_statsEvent_Builder, "writeInt", int.class);
            build = new OptionalMethod(c_statsEvent_Builder, "build");
            usePooledBuffer = new OptionalMethod(c_statsEvent_Builder, "usePooledBuffer");
        }

        private static Class<?> initStatsEventBuilderClass() {
            try {
                return Class.forName("android.util.StatsEvent$Builder");
            } catch (ClassNotFoundException ignored) {
                return null;
            }
        }

        private Object builder;

        private Builder() {
            this.builder = newBuilder.invoke(null);
        }

        public Builder setAtomId(final int atomId) {
            setAtomId.invoke(this.builder, atomId);
            return this;
        }

        public Builder writeBoolean(final boolean value) {
            writeBoolean.invoke(this.builder, value);
            return this;
        }

        public Builder writeInt(final int value) {
            writeInt.invoke(this.builder, value);
            return this;
        }

        public void usePooledBuffer() {
            usePooledBuffer.invoke(this.builder);
        }

        public ReflexiveStatsEvent build() {
            Object statsEvent = build.invoke(this.builder);
            return new ReflexiveStatsEvent(statsEvent);
        }
    }
}