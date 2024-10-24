/*
 * Copyright (C) 2019 The Android Open Source Project
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

package tests.util;

import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A utility for testing all the implementations of a particular service (such as MessageDigest or
 * KeyGenerator).
 * <p>
 * An instance of this class may only be used to run one test.
 */
public final class ServiceTester {

  public interface Test {
    /**
     * Run the test for the given provider and algorithm.  This method should throw an exception
     * if the test fails or do nothing if it passes.
     */
    void test(Provider p, String algorithm) throws Exception;
  }

  private static final String SEPARATOR = "||";
  private final String service;
  private final Set<Provider> providers = new LinkedHashSet<>();
  private final Set<Provider> skipProviders = new HashSet<>();
  private final Set<String> algorithms = new LinkedHashSet<>();
  private final Set<String> skipAlgorithms = new HashSet<>();
  private final Set<String> skipCombinations = new HashSet<>();

  private ServiceTester(String service) {
    this.service = service;
  }

  /**
   * Create a new ServiceTester for the given service.
   */
  public static ServiceTester test(String service) {
    if (service.equalsIgnoreCase("Cipher")) {
      // Cipher is complicated because the parameterized transformations mean that you have
      // to check for a lot of combinations (eg, a test for AES/CBC/NoPadding might be satisfied by
      // a provider providing AES, AES/CBC, AES//NoPadding, or AES/CBC/NoPadding).  We don't
      // really need it, so we haven't implemented it.
      throw new IllegalArgumentException("ServiceTester doesn't support Cipher");
    }
    return new ServiceTester(service);
  }

  /**
   * Specifies the list of providers to test.  If this method is called multiple times, the
   * collections are combined.  If this method is never called, this will test all installed
   * providers.
   *
   * @throws IllegalArgumentException if a named provider is not installed
   */
  public ServiceTester withProviders(Collection<String> providers) {
    for (String name : providers) {
      Provider p = Security.getProvider(name);
      if (p == null) {
        throw new IllegalArgumentException("No such provider: " + name);
      }
      this.providers.add(p);
    }
    return this;
  }

  /**
   * Causes the given provider to be omitted from this instance's testing.  If the given provider
   * is not installed, does nothing.
   */
  public ServiceTester skipProvider(String provider) {
    Provider p = Security.getProvider(provider);
    if (p != null) {
      skipProviders.add(p);
    }
    return this;
  }

  /**
   * Specifies the algorithm to test.  If this method and/or {@link #withAlgorithms(Collection)}}
   * are called multiple times, all values are combined.  If neither method is called, this will
   * test all algorithms supported by any tested provider.
   */
  public ServiceTester withAlgorithm(String algorithm) {
    this.algorithms.add(algorithm);
    return this;
  }

  /**
   * Specifies the algorithms to test.  If this method and/or {@link #withAlgorithm(String)}}
   * are called multiple times, all values are combined.  If neither method is called, this will
   * test all algorithms supported by any tested provider.
   */
  public ServiceTester withAlgorithms(Collection<String> algorithms) {
    this.algorithms.addAll(algorithms);
    return this;
  }

  /**
   * Causes the given algorithm to be omitted from this instance's testing.  If no tested provider
   * provides the given algorithm, does nothing.
   */
  public ServiceTester skipAlgorithm(String algorithm) {
    skipAlgorithms.add(algorithm);
    return this;
  }

  /**
   * Causes the given combination of provider and algorithm to be omitted from this instance's
   * testing. If no tested provider provides the given algorithm, does nothing.
   */
  public ServiceTester skipCombination(String provider, String algorithm) {
    Provider p = Security.getProvider(provider);
    if (p != null) {
      skipCombinations.add(makeCombination(provider, algorithm));
    }
    return this;
  }

  /**
   * Runs the given test against the configured combination of providers and algorithms.  Continues
   * running all combinations even if some fail.  If any of the test runs fail, this throws
   * an exception with the details of the failure(s).
   */
  public void run(Test test) {
    if (providers.isEmpty()) {
      providers.addAll(Arrays.asList(Security.getProviders()));
    }
    providers.removeAll(skipProviders);
    final ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
    PrintStream errors = new PrintStream(errBuffer);
    for (Provider p : providers) {
      if (algorithms.isEmpty()) {
        for (Provider.Service s : p.getServices()) {
          if (s.getType().equals(service)
              && !skipAlgorithms.contains(s.getAlgorithm())
              && shouldUseCombination(p.getName(), s.getAlgorithm())) {
            doTest(test, p, s.getAlgorithm(), errors);
          }
        }
      } else {
        algorithms.removeAll(skipAlgorithms);
        for (String algorithm : algorithms) {
          if (p.getService(service, algorithm) != null
              && shouldUseCombination(p.getName(), algorithm)) {
            doTest(test, p, algorithm, errors);
          }
        }
      }
    }
    errors.flush();
    if (errBuffer.size() > 0) {
      fail("Tests failed:\n\n" + errBuffer);
    }
  }

  private String makeCombination(String provider, String algorithm) {
    return provider + SEPARATOR + algorithm;
  }

  private boolean shouldUseCombination(String provider, String algorithm) {
    return !skipCombinations.contains(makeCombination(provider, algorithm));
  }

  private void doTest(Test test, Provider p, String algorithm, PrintStream errors) {
    try {
      test.test(p, algorithm);
    } catch (Exception|AssertionError e) {
      errors.append("Failure testing " + service + ":" + algorithm
          + " from provider " + p.getName() + ":\n");
      e.printStackTrace(errors);
    }
  }

}
