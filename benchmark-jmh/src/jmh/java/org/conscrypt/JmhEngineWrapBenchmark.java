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

/*
 * Copyright 2017 The Netty Project
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

import javax.net.ssl.SSLException;
import org.conscrypt.EngineWrapBenchmark.Config;
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
 * Benchmark comparing performance of various engine implementations to conscrypt.
 */
@State(Scope.Benchmark)
@Fork(1)
@Threads(1)
public class JmhEngineWrapBenchmark {
    private final JmhConfig config = new JmhConfig();

    @Param({TestUtils.TEST_CIPHER})
    public String a_cipher;

    @Param
    public BufferType b_buffer;

    @Param({"128", "4096"})
    public int c_message;

    @Param
    public OpenJdkEngineFactory d_engine;

    private EngineWrapBenchmark benchmark;

    @Setup(Level.Iteration)
    public void setup() throws Exception {
        benchmark = new EngineWrapBenchmark(config);
    }

    @TearDown(Level.Iteration)
    public void teardown() {
        benchmark.teardown();
    }

    @Benchmark
    public void wrap() throws SSLException {
        benchmark.wrap();
    }

    @Benchmark
    public void wrapAndUnwrap() throws SSLException {
        benchmark.wrapAndUnwrap();
    }

    private final class JmhConfig implements Config {

        @Override
        public BufferType bufferType() {
            return b_buffer;
        }

        @Override
        public EngineFactory engineFactory() {
            return d_engine;
        }

        @Override
        public int messageSize() {
            return c_message;
        }

        @Override
        public String cipher() {
            return a_cipher;
        }
    }
}
