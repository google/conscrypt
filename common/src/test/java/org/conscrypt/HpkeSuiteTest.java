/*
 * Copyright (C) 2023 The Android Open Source Project
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
 * limitations under the License
 */

package org.conscrypt;

import static org.conscrypt.HpkeSuite.AEAD_AES_128_GCM;
import static org.conscrypt.HpkeSuite.AEAD_AES_256_GCM;
import static org.conscrypt.HpkeSuite.AEAD_CHACHA20POLY1305;
import static org.conscrypt.HpkeSuite.KDF_HKDF_SHA256;
import static org.conscrypt.HpkeSuite.KEM_DHKEM_X25519_HKDF_SHA256;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class HpkeSuiteTest {
    @Test
    public void testConstructor_validAlgorithms_noExceptionsThrown() {
        new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
        new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);
        new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_CHACHA20POLY1305);
    }

    @Test
    public void testConstructor_invalidKem_throwsArgumentException() {
        final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new HpkeSuite(700, KDF_HKDF_SHA256, AEAD_AES_128_GCM));
        assertEquals("KEM 700 not supported.", e.getMessage());
    }

    @Test
    public void testConstructor_invalidKdf_throwsArgumentException() {
        final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, 800, AEAD_AES_128_GCM));
        assertEquals("KDF 800 not supported.", e.getMessage());
    }

    @Test
    public void testConstructor_invalidAead_throwsArgumentException() {
        final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, 900));
        assertEquals("AEAD 900 not supported.", e.getMessage());
    }
}
