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
import static org.conscrypt.HpkeFixture.DEFAULT_SUITE_NAME;
import static org.conscrypt.HpkeFixture.createDefaultHpkeContextSender;
import static org.conscrypt.HpkeFixture.createPublicKey;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;

import org.conscrypt.java.security.DefaultKeys;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class HpkeContextSenderTest {
    @Test
    public void testGetInstance() throws Exception {
        assertThrows(NoSuchAlgorithmException.class,
                () -> HpkeContextSender.getInstance(null));
        assertThrows(NoSuchAlgorithmException.class,
            () -> HpkeContextSender.getInstance("No/Such/Thing"));
        assertThrows(IllegalArgumentException.class,
            () -> HpkeContextSender.getInstance(DEFAULT_SUITE_NAME, (String) null));
        assertThrows(IllegalArgumentException.class,
            () -> HpkeContextSender.getInstance(DEFAULT_SUITE_NAME, (Provider) null));
        assertThrows(NoSuchProviderException.class,
            () -> HpkeContextSender.getInstance(DEFAULT_SUITE_NAME, "NonsenseProviderName"));
        HpkeContextSender sender = HpkeContextSender.getInstance(DEFAULT_SUITE_NAME);
        assertNotNull(sender);
    }

    @Test
    public void testInit() throws Exception {
        HpkeContextSender sender = HpkeContextSender.getInstance(DEFAULT_SUITE_NAME);

        PublicKey dhKey = DefaultKeys.getPublicKey("DH");
        PublicKey validKey = createPublicKey(DEFAULT_PK);

        assertThrows(InvalidKeyException.class,
            () -> sender.init(HpkeContextSender.MODE_BASE, null, null));
        assertThrows(InvalidKeyException.class,
            () -> sender.init(HpkeContextSender.MODE_BASE, null, DEFAULT_INFO));
        assertThrows(UnsupportedOperationException.class,
            () -> sender.init(0x01 /* MODE_PSK */, dhKey , DEFAULT_INFO));

        // DH keys not supported
        assertThrows(InvalidKeyException.class,
            () -> sender.init(HpkeContextSender.MODE_BASE, dhKey , DEFAULT_INFO));

        assertThrows(IllegalArgumentException.class,
            () -> sender.initForTesting(HpkeContextSender.MODE_BASE, dhKey , DEFAULT_INFO, null));

        // Should succeed
        sender.init(HpkeContextSender.MODE_BASE, validKey, DEFAULT_INFO);

        // Re-initialisation not supported
        assertThrows(IllegalStateException.class,
            () -> sender.init(HpkeContextSender.MODE_BASE, validKey , null));

        HpkeContextSender sender2 = HpkeContextSender.getInstance(DEFAULT_SUITE_NAME);
        // null info is explicitly allowed
        sender2.init(HpkeContextSender.MODE_BASE, validKey, null);
    }

    @Test
    public void testUninitialised() throws Exception {
        HpkeContextSender sender = HpkeContextSender.getInstance(DEFAULT_SUITE_NAME);

        assertThrows(IllegalStateException.class,
            () -> sender.seal(new byte[16], new byte[16]));
        assertThrows(IllegalStateException.class,
            () -> sender.export(16, new byte[16]));
    }
    @Test
    public void testSeal_missingRequiredParameters_throwNullException() throws Exception {
        HpkeContextSender ctxSender = HpkeContextSender.getInstance(DEFAULT_SUITE_NAME);
        final PublicKey publicKey = createPublicKey(DEFAULT_PK);
        ctxSender.init(HpkeContextSender.MODE_BASE,publicKey, DEFAULT_INFO);
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

    @Test
    public void getInstance() throws Exception {
        HpkeContextSender ctxSender = createDefaultHpkeContextSender();
        assertNotNull(ctxSender);
        for (int i = 0; i < 8_000; i += 500) {
            final byte[] export = ctxSender.export(i, DEFAULT_EXPORTER_CONTEXT);
            assertNotNull(export);
            assertEquals(i, export.length);
        }
    }
}
