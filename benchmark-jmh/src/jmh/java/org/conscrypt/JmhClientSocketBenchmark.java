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

import org.conscrypt.ClientSocketBenchmark.Config;
import org.openjdk.jmh.annotations.AuxCounters;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;

/**
 * Benchmark for comparing performance of client socket implementations. All benchmarks use Netty
 * with tcnative as the server.
 */
@State(Scope.Benchmark)
@Fork(1)
@Threads(1)
public class JmhClientSocketBenchmark {
    /**
     * Use an AuxCounter so we can measure that bytes per second as they accumulate without
     * consuming CPU in the benchmark method.
     */
    @AuxCounters
    @State(Scope.Thread)
    public static class BytesPerSecondCounter {
        @Setup(Level.Iteration)
        public void clean() {
            ClientSocketBenchmark.reset();
        }

        @SuppressWarnings("unused")
        public long bytesPerSecond() {
            return ClientSocketBenchmark.bytesPerSecond();
        }
    }

    private final JmhConfig config = new JmhConfig();

    @Param
    public SocketType socketType;

    @Param({"64", "512", "4096"})
    public int messageSize;

    @Param({TestUtils.TEST_CIPHER})
    public String cipher;

    @Param
    public ChannelType channelType;

    private ClientSocketBenchmark benchmark;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        benchmark = new ClientSocketBenchmark(config);
    }

    @TearDown(Level.Trial)
    public void teardown() throws Exception {
        benchmark.close();
    }

    @Benchmark
    public final void throughput(@SuppressWarnings("unused") BytesPerSecondCounter counter)
            throws Exception {
        benchmark.throughput();
    }

    private final class JmhConfig implements Config {
        @Override
        public SocketType socketType() {
            return socketType;
        }

        @Override
        public int messageSize() {
            return messageSize;
        }

        @Override
        public String cipher() {
            return cipher;
        }

        @Override
        public ChannelType channelType() {
            return channelType;
        }
    }
}
