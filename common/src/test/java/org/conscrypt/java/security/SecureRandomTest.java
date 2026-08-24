/*
 * Copyright (C) 2026 The Android Open Source Project
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

package org.conscrypt.java.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.Provider;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

@RunWith(JUnit4.class)
public class SecureRandomTest {
    @Test
    public void testSHA1PRNG_isThreadSafe_attribute() throws Exception {
        Provider provider = TestUtils.getConscryptProvider();
        Provider.Service service = provider.getService("SecureRandom", "SHA1PRNG");
        assertNotNull(service);
        assertEquals("true", service.getAttribute("ThreadSafe"));
    }

    @Test
    public void testSHA1PRNG_Concurrency() throws Exception {
        Provider provider = TestUtils.getConscryptProvider();
        final SecureRandom random = SecureRandom.getInstance("SHA1PRNG", provider);

        int numThreads = 10;
        final int iterations = 1000;
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < numThreads; i++) {
            futures.add(executor.submit(new Runnable() {
                @Override
                public void run() {
                    byte[] bytes = new byte[16];
                    for (int j = 0; j < iterations; j++) {
                        random.nextBytes(bytes);
                    }
                }
            }));
        }

        executor.shutdown();
        assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));

        for (Future<?> future : futures) {
            future.get(); // Will throw exception if any thread failed
        }
    }
}
