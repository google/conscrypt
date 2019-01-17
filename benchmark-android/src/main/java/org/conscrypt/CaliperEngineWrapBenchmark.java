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

import com.google.caliper.AfterExperiment;
import com.google.caliper.BeforeExperiment;
import com.google.caliper.Benchmark;
import com.google.caliper.Param;
import javax.net.ssl.SSLException;
import org.conscrypt.EngineWrapBenchmark.Config;

/**
 * Benchmark comparing performance of various engine implementations to conscrypt.
 */
@SuppressWarnings("unused")
public class CaliperEngineWrapBenchmark {
    private final CaliperConfig config = new CaliperConfig();

    @Param({TestUtils.TEST_CIPHER})
    public String a_cipher;

    @Param
    public BufferType b_buffer;

    @Param({"64", "512", "4096"})
    public int c_message;

    @Param({"CONSCRYPT_UNPOOLED"})
    public AndroidEngineFactory d_engine;

    private EngineWrapBenchmark benchmark;

    @BeforeExperiment
    public void setUp() throws Exception {
        benchmark = new EngineWrapBenchmark(config);
    }

    @AfterExperiment
    public void teardown() {
        benchmark.teardown();
    }

    @Benchmark
    public void timeWrap(int reps) throws SSLException {
        for (int i = 0; i < reps; ++i) {
            benchmark.wrap();
        }
    }

    public void timeWrapAndUnwrap(int reps) throws SSLException {
        for (int i = 0; i < reps; ++i) {
            benchmark.wrapAndUnwrap();
        }
    }

    private final class CaliperConfig implements Config {

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
