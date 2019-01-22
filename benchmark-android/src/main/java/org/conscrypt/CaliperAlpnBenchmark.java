/*
 * Copyright 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.conscrypt;

import com.google.caliper.BeforeExperiment;
import com.google.caliper.Benchmark;
import com.google.caliper.Param;
import org.conscrypt.EngineHandshakeBenchmark.Config;

/**
 * Cipher benchmarks. Only runs on AES currently because of the combinatorial
 * explosion of the test as it stands.
 */
@SuppressWarnings("unused")
public class CaliperAlpnBenchmark {
    private final CaliperConfig config = new CaliperConfig();

    @Param({TestUtils.TEST_CIPHER})
    public String a_cipher;

    @Param
    public BufferType b_buffer;

    @Param({"CONSCRYPT_UNPOOLED"})
    public AndroidEngineFactory c_engine;

    private EngineHandshakeBenchmark benchmark;

    @BeforeExperiment
    public void setUp() throws Exception {
        benchmark = new EngineHandshakeBenchmark(config);
    }

    @Benchmark
    public void timeHandshake(int reps) throws Exception {
        for (int i = 0; i < reps; ++i) {
            benchmark.handshake();
        }
    }

    private final class CaliperConfig implements Config {
        @Override
        public BufferType bufferType() {
            return b_buffer;
        }

        @Override
        public EngineFactory engineFactory() {
            return c_engine;
        }

        @Override
        public String cipher() {
            return a_cipher;
        }

        @Override
        public boolean useAlpn() {
            return true;
        }

        @Override
        public BenchmarkProtocol protocol() {
            return BenchmarkProtocol.TLSv12;
        }

        @Override
        public int rttMillis() {
            return 0;
        }
    }
}
