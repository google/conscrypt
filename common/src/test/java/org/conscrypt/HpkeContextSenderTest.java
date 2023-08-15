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
import static org.conscrypt.HpkeFixture.DEFAULT_EXPORTER_CONTEXT;
import static org.conscrypt.HpkeFixture.DEFAULT_EXPORTER_LENGTH;
import static org.conscrypt.HpkeFixture.DEFAULT_INFO;
import static org.conscrypt.HpkeFixture.DEFAULT_PK;
import static org.conscrypt.HpkeFixture.createDefaultHpkeContextSender;
import static org.conscrypt.HpkeFixture.createDefaultHpkeSuite;
import static org.conscrypt.HpkeFixture.createPublicKey;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import java.security.PublicKey;
import org.conscrypt.java.security.DefaultKeys;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class HpkeContextSenderTest {
    @Test
    public void testSetupBase_missingSuiteParameter_throwNullException() {
        assertThrows(NullPointerException.class,
                ()
                        -> HpkeContextSender.setupBase(
                                /* hpkeSuite= */ null, createPublicKey(DEFAULT_PK), DEFAULT_INFO));
    }

    @Test
    public void testSetupBase_missingPkParameter_throwNullException() {
        assertThrows(NullPointerException.class,
                ()
                        -> HpkeContextSender.setupBase(
                                createDefaultHpkeSuite(), /* publicKey= */ null, DEFAULT_INFO));
    }

    @Test
    public void testSetupBase_keyAlgorithmNotSupported_throwArgumentException() throws Exception {
        final PublicKey publicKey = DefaultKeys.getPublicKey("DH");
        final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                ()
                        -> HpkeContextSender.setupBase(
                                createDefaultHpkeSuite(), publicKey, DEFAULT_INFO));
        assertEquals("Public key algorithm DH is not supported", e.getMessage());
    }

    @Test
    public void testSeal_missingRequiredParameters_throwNullException() throws Exception {
        final PublicKey publicKey = createPublicKey(DEFAULT_PK);
        final HpkeContextSender ctxSender =
                HpkeContextSender.setupBase(createDefaultHpkeSuite(), publicKey, DEFAULT_INFO);
        assertThrows(NullPointerException.class,
                () -> ctxSender.seal(/* plaintext= */ null, DEFAULT_AAD));
    }

    @Test
    public void testExport_withNullValue() throws Exception {
        final HpkeContextSender ctxSender = createDefaultHpkeContextSender();
        final byte[] enc = ctxSender.getEnc();
        final byte[] export =
                ctxSender.export(DEFAULT_EXPORTER_LENGTH, /* exporterContext= */ null);
        assertNotNull(enc);
        assertNotNull(export);
        assertEquals(DEFAULT_EXPORTER_LENGTH, export.length);
    }

    @Test
    public void testExport_verifyOutputLength() throws Exception {
        final HpkeContextSender ctxSender = createDefaultHpkeContextSender();
        final byte[] enc = ctxSender.getEnc();
        for (int i = 0; i < 8_000; i += 500) {
            final byte[] export = ctxSender.export(i, DEFAULT_EXPORTER_CONTEXT);
            assertNotNull(enc);
            assertNotNull(export);
            assertEquals(i, export.length);
        }
    }

    @Test
    public void testExport_lowerEdgeLength() throws Exception {
        final HpkeContextSender ctxSender = createDefaultHpkeContextSender();
        final byte[] enc = ctxSender.getEnc();
        final byte[] export = ctxSender.export(/* length= */ 0, DEFAULT_EXPORTER_CONTEXT);
        assertNotNull(enc);
        assertNotNull(export);
        final IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ctxSender.export(/* length= */ -1, DEFAULT_EXPORTER_CONTEXT));
        assertEquals("Export length (L) must be between 0 and 8160, but was -1", e.getMessage());
    }
}
