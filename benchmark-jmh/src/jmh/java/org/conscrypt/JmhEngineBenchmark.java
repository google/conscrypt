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
import org.conscrypt.EngineBenchmark.Config;
import org.conscrypt.EngineBenchmark.SslProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;

/**
 * Benchmark comparing performance of various engine implementations to conscrypt.
 */
@State(Scope.Benchmark)
@Fork(1)
@Threads(1)
public class JmhEngineBenchmark {
    private final JmhConfig config = new JmhConfig();

    @Param
    public SslProvider sslProvider;

    @Param({"64", "512", "4096"})
    public int messageSize;

    @Param({TestUtils.TEST_CIPHER})
    public String cipher;

    private EngineBenchmark benchmark;

    @Setup
    public void setup() throws Exception {
        benchmark = new EngineBenchmark(config);
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
        public SslProvider sslProvider() {
            return sslProvider;
        }

        @Override
        public int messageSize() {
            return messageSize;
        }

        @Override
        public String cipher() {
            return cipher;
        }
    }
}
