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

import static org.conscrypt.HpkeFixture.DEFAULT_AAD;
import static org.conscrypt.HpkeFixture.DEFAULT_CT;
import static org.conscrypt.HpkeFixture.DEFAULT_ENC;
import static org.conscrypt.HpkeFixture.DEFAULT_EXPORTER_CONTEXT;
import static org.conscrypt.HpkeFixture.DEFAULT_EXPORTER_LENGTH;
import static org.conscrypt.HpkeFixture.DEFAULT_INFO;
import static org.conscrypt.HpkeFixture.DEFAULT_PT;
import static org.conscrypt.HpkeFixture.DEFAULT_SK;
import static org.conscrypt.HpkeFixture.createDefaultHpkeContextRecipient;
import static org.conscrypt.HpkeFixture.createDefaultHpkeSuite;
import static org.conscrypt.HpkeFixture.createPrivateKey;
import static org.conscrypt.TestUtils.decodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import java.security.PrivateKey;
import org.conscrypt.java.security.DefaultKeys;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class HpkeContextRecipientTest {
    @Test
    public void testSetupBase_missingSuiteParameter_throwNullException() {
        assertThrows(NullPointerException.class,
                ()
                        -> HpkeContextRecipient.setupBase(
                                /* hpkeSuite= */ null, DEFAULT_ENC, createPrivateKey(DEFAULT_SK),
                                DEFAULT_INFO));
    }

    @Test
    public void testSetupBase_missingEncParameter_throwNullException() {
        assertThrows(NullPointerException.class,
                ()
                        -> HpkeContextRecipient.setupBase(createDefaultHpkeSuite(), /* enc= */ null,
                                createPrivateKey(DEFAULT_SK), DEFAULT_INFO));
    }

    @Test
    public void testSetupBase_missingSkParameter_throwNullException() {
        assertThrows(NullPointerException.class,
                ()
                        -> HpkeContextRecipient.setupBase(createDefaultHpkeSuite(), DEFAULT_ENC,
                                /* privateKey= */ null, DEFAULT_INFO));
    }

    @Test
    public void testSetupBase_encLengthNotMatchingKemSpec_throwArgumentException()
            throws Exception {
        final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);
        final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                ()
                        -> HpkeContextRecipient.setupBase(createDefaultHpkeSuite(),
                                /* enc= */ new byte[1], privateKey, DEFAULT_INFO));
        assertEquals("Expected enc length of 32, but was 1", e.getMessage());
    }

    @Test
    public void testSetupBase_keyAlgorithmNotSupported_throwArgumentException() throws Exception {
        final PrivateKey privateKey = DefaultKeys.getPrivateKey("DH");
        final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                ()
                        -> HpkeContextRecipient.setupBase(
                                createDefaultHpkeSuite(), DEFAULT_ENC, privateKey, DEFAULT_INFO));
        assertEquals("Private key algorithm DH is not supported", e.getMessage());
    }

    @Test
    public void testOpen_successfully() throws Exception {
        final HpkeSuite suite = new HpkeSuite(HpkeSuite.KEM_DHKEM_X25519_HKDF_SHA256,
                HpkeSuite.KDF_HKDF_SHA256, HpkeSuite.AEAD_AES_128_GCM);
        final HpkeContextRecipient ctxRecipient = HpkeContextRecipient.setupBase(
                suite, DEFAULT_ENC, createPrivateKey(DEFAULT_SK), DEFAULT_INFO);
        byte[] plaintext = ctxRecipient.open(DEFAULT_CT, DEFAULT_AAD);
        assertNotNull(plaintext);
        assertArrayEquals(DEFAULT_PT, plaintext);
    }

    @Test
    public void testOpen_missingRequiredParameters_throwNullException() throws Exception {
        final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);
        final HpkeContextRecipient ctxRecipient = HpkeContextRecipient.setupBase(
                createDefaultHpkeSuite(), DEFAULT_ENC, privateKey, DEFAULT_INFO);
        assertThrows(NullPointerException.class,
                () -> ctxRecipient.open(/* ciphertext= */ null, DEFAULT_AAD));
    }

    @Test
    public void testOpen_validSkButNotTheRightOne_throwStateException() throws Exception {
        final PrivateKey privateKey = createPrivateKey(
                decodeHex("497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d"));
        final HpkeContextRecipient ctxRecipient = HpkeContextRecipient.setupBase(
                createDefaultHpkeSuite(), DEFAULT_ENC, privateKey, DEFAULT_INFO);
        assertThrows(IllegalStateException.class, () -> ctxRecipient.open(DEFAULT_CT, DEFAULT_AAD));
    }

    @Test
    public void testOpen_validSkButWrongEnc_throwStateException() throws Exception {
        final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);
        final byte[] enc =
                decodeHex("6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256");
        final HpkeContextRecipient ctxRecipient = HpkeContextRecipient.setupBase(
                createDefaultHpkeSuite(), enc, privateKey, DEFAULT_INFO);
        assertThrows(IllegalStateException.class, () -> ctxRecipient.open(DEFAULT_CT, DEFAULT_AAD));
    }

    @Test
    public void testOpen_invalidCiphertext_throwStateException() throws Exception {
        final PrivateKey privateKey = createPrivateKey(DEFAULT_SK);
        final HpkeContextRecipient ctxRecipient = HpkeContextRecipient.setupBase(
                createDefaultHpkeSuite(), DEFAULT_ENC, privateKey, DEFAULT_INFO);
        assertThrows(IllegalStateException.class,
                () -> ctxRecipient.open(/* ct= */ new byte[32], DEFAULT_AAD));
    }

    @Test
    public void testExport_withNullValue() throws Exception {
        final HpkeContextRecipient ctxRecipient = createDefaultHpkeContextRecipient(DEFAULT_ENC);
        final byte[] export =
                ctxRecipient.export(DEFAULT_EXPORTER_LENGTH, /* exporterContext= */ null);
        assertNotNull(export);
        assertEquals(DEFAULT_EXPORTER_LENGTH, export.length);
    }

    @Test
    public void testExport_verifyOutputLength() throws Exception {
        final HpkeContextRecipient ctxRecipient = createDefaultHpkeContextRecipient(DEFAULT_ENC);
        for (int i = 0; i < 8_000; i += 500) {
            final byte[] export = ctxRecipient.export(i, DEFAULT_EXPORTER_CONTEXT);
            assertNotNull(export);
            assertEquals(i, export.length);
        }
    }

    @Test
    public void testExport_lowerEdgeLength() throws Exception {
        final HpkeContextRecipient ctxRecipient = createDefaultHpkeContextRecipient(DEFAULT_ENC);
        final byte[] export = ctxRecipient.export(/* length= */ 0, DEFAULT_EXPORTER_CONTEXT);
        assertNotNull(export);
        final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ctxRecipient.export(/* length= */ -1, DEFAULT_EXPORTER_CONTEXT));
        assertEquals("Export length (L) must be between 0 and 8160, but was -1", e.getMessage());
    }
}
