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

package org.conscrypt;

import org.junit.runner.Description;
import org.junit.runner.notification.RunListener;

import java.security.Provider;
import java.security.Security;

import tests.util.ServiceTester;

/**
 * Custom JUnit RunListener for Conscrypt tests.
 *
 * This is required in Google3 because UTP (Unified Test Platform) automatically
 * shards and splits the ConscryptAndroidSuite, running individual test classes
 * directly. This bypasses the suite's @BeforeClass setup which registers the provider.
 *
 * Additionally, this listener configures ServiceTester to only test Conscrypt,
 * preventing tests from failing due to Bouncy Castle deprecation on Android.
 */
public class ConscryptTestListener extends RunListener {
    @Override
    public void testRunStarted(Description description) throws Exception {
        Provider conscryptProvider = TestUtils.getConscryptProvider();
        Security.insertProviderAt(conscryptProvider, 1);
        ServiceTester.setProviders(new Provider[] {conscryptProvider});
        super.testRunStarted(description);
    }
}
