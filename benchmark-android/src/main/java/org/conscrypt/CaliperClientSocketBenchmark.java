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

import com.google.caliper.AfterExperiment;
import com.google.caliper.BeforeExperiment;
import com.google.caliper.Benchmark;
import com.google.caliper.Param;
import org.conscrypt.ClientSocketBenchmark.Config;

/**
 * Benchmark for comparing performance of client socket implementations.
 */
@SuppressWarnings("unused")
public class CaliperClientSocketBenchmark {

  private final CaliperConfig config = new CaliperConfig();

  @Param
  public AndroidEndpointFactory socketType;

  @Param({"64", "512", "4096"})
  public int messageSize;

  @Param({TestUtils.TEST_CIPHER})
  public String cipher;

  @Param
  public BenchmarkProtocol protocol;

  @Param
  public ChannelType channelType;

  private ClientSocketBenchmark benchmark;

  @BeforeExperiment
  public void setup() throws Exception {
    benchmark = new ClientSocketBenchmark(config);
  }

  @AfterExperiment
  public void teardown() throws Exception {
    benchmark.close();
  }

  @Benchmark
  public final void time(int numMessages) throws Exception {
    benchmark.time(numMessages);
  }

  private final class CaliperConfig implements Config {
    @Override
    public EndpointFactory clientFactory() {
      return socketType;
    }

    @Override
    public EndpointFactory serverFactory() {
      // Use the same server for all benchmarks, since we're looking at the perf of the client.
      return AndroidEndpointFactory.CONSCRYPT_ENGINE;
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

    @Override
    public BenchmarkProtocol protocol() {
      return protocol;
    }
  }
}
