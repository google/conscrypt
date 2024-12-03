/*
 * Copyright (C) 2024 The Android Open Source Project
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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.Provider;

@RunWith(JUnit4.class)
public class AndroidHpkeSpiTest {
    private static final String[] HPKE_NAMES = new String[]{
            "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM",
            "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM",
            "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/CHACHA20POLY1305"
    };

    // This only needs to test the wrapper functionality as the implementation and client
    // APIs are tested elsewhere.  What we're looking for is that HPKE SPI instances returned
    // by the provider are *always* instances of Conscrypt's HpkeSpi and *always* usable by
    // a Conscrypt duck typed SPI.  And if the Android platform SPI class is available then
    // they should also be usable as instances of that.
    @Test
    public void functionalTest() throws Exception {
        Class<?> conscryptSpiClass = HpkeSpi.class;
        Class<?> platformSpiClass = TestUtils.findClass("android.crypto.hpke.HpkeSpi");
        Provider provider = TestUtils.getConscryptProvider();
        for (String algorithm : HPKE_NAMES) {
            Object spi = provider.getService("ConscryptHpke", algorithm)
                    .newInstance(null);
            assertNotNull(spi);
            if (platformSpiClass != null) {
                assertTrue(platformSpiClass.isAssignableFrom(spi.getClass()));
            }
            assertTrue(conscryptSpiClass.isAssignableFrom(spi.getClass()));
            assertNotNull(DuckTypedHpkeSpi.newInstance(spi));
        }
    }
}