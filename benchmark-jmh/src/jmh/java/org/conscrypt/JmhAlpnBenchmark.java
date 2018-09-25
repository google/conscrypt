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

import javax.net.ssl.SSLException;
import org.conscrypt.EngineHandshakeBenchmark.Config;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;

/**
 * Benchmark comparing ALPN performance between Conscrypt and Netty.
 */
@State(Scope.Benchmark)
@Fork(1)
@Threads(1)
public class JmhAlpnBenchmark {
  private final JmhConfig config = new JmhConfig();

  @Param({TestUtils.TEST_CIPHER})
  public String a_cipher;

  @Param
  public BufferType b_buffer;

  // JDK does not support ALPN, so exclude it from the benchmarks.
  @Param({"CONSCRYPT_UNPOOLED", "CONSCRYPT_POOLED", "NETTY", "NETTY_REF_CNT"})
  public OpenJdkEngineFactory c_engine;

  private EngineHandshakeBenchmark benchmark;

  @Setup(Level.Iteration)
  public void setup() throws Exception {
    benchmark = new EngineHandshakeBenchmark(config);
  }

  @Benchmark
  public void hs() throws SSLException {
    benchmark.handshake();
  }

  private final class JmhConfig implements Config {

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
    public int rttMillis() {
      return 0;
    }

    @Override
    public BenchmarkProtocol protocol() {
      return BenchmarkProtocol.TLSv12;
    }
  }
}

