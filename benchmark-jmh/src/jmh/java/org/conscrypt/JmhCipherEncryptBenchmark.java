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

import org.conscrypt.CipherEncryptBenchmark.Config;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.infra.Blackhole;

/**
 * Benchmark comparing Cipher creation performance.
 */
@State(Scope.Benchmark)
@Fork(1)
@Threads(1)
public class JmhCipherEncryptBenchmark {
    private final JmhConfig config = new JmhConfig();

    @Param
    public Transformation a_tx;

    @Param
    public CipherEncryptBenchmark.BufferType b_bufferType;

    @Param
    public OpenJdkCipherFactory c_provider;

    private CipherEncryptBenchmark benchmark;

    @Setup(Level.Iteration)
    public void setup() throws Exception {
        benchmark = new CipherEncryptBenchmark(config);
    }

    @Benchmark
    public void encrypt(Blackhole bh) throws Exception {
        bh.consume(benchmark.encrypt());
    }

    private final class JmhConfig implements Config {
        @Override
        public CipherEncryptBenchmark.BufferType bufferType() {
            return b_bufferType;
        }

        @Override
        public CipherFactory cipherFactory() {
            return c_provider;
        }

        @Override
        public Transformation transformation() {
            return a_tx;
        }
    }
}
