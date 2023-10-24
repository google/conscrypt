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
import static org.conscrypt.HpkeFixture.DEFAULT_ENC;
import static org.conscrypt.HpkeFixture.DEFAULT_EXPORTER_CONTEXT;
import static org.conscrypt.HpkeFixture.DEFAULT_EXPORTER_LENGTH;
import static org.conscrypt.HpkeFixture.DEFAULT_INFO;
import static org.conscrypt.HpkeFixture.DEFAULT_PK_BYTES;
import static org.conscrypt.HpkeFixture.DEFAULT_PT;
import static org.conscrypt.HpkeFixture.DEFAULT_SK_BYTES;
import static org.conscrypt.HpkeFixture.DEFAULT_SUITE_NAME;
import static org.conscrypt.HpkeFixture.createDefaultHpkeContextRecipient;
import static org.conscrypt.HpkeFixture.createDefaultHpkeContextSender;
import static org.conscrypt.HpkeFixture.createPrivateKey;
import static org.conscrypt.HpkeFixture.createPublicKey;
import static org.conscrypt.TestUtils.encodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class HpkeContextTest {
    @Test
    public void testSealOpen_randomnessResult() throws Exception {
        final HpkeContextSender ctxSender1 = createDefaultHpkeContextSender();
        final byte[] enc1 = ctxSender1.getEncapsulated();
        final byte[] ciphertext1 = ctxSender1.seal(DEFAULT_PT, /* aad= */ null);

        final HpkeContextSender ctxSender2 = createDefaultHpkeContextSender();
        final byte[] enc2 = ctxSender2.getEncapsulated();
        final byte[] ciphertext2 = ctxSender2.seal(DEFAULT_PT, /* aad= */ null);

        assertNotNull(enc1);
        assertNotNull(ciphertext1);
        assertNotNull(enc2);
        assertNotNull(ciphertext2);
        assertNotEquals(encodeHex(enc1), encodeHex(enc2));
        assertNotEquals(encodeHex(DEFAULT_PT), encodeHex(ciphertext1));
        assertNotEquals(encodeHex(ciphertext1), encodeHex(ciphertext2));

        final HpkeContextRecipient ctxRecipient1 = createDefaultHpkeContextRecipient(enc1);
        byte[] plaintext1 = ctxRecipient1.open(ciphertext1, /* aad= */ null);

        final HpkeContextRecipient ctxRecipient2 = createDefaultHpkeContextRecipient(enc2);
        byte[] plaintext2 = ctxRecipient2.open(ciphertext2, /* aad= */ null);

        assertNotNull(plaintext1);
        assertNotNull(plaintext2);
        assertArrayEquals(DEFAULT_PT, plaintext1);
        assertArrayEquals(DEFAULT_PT, plaintext2);
    }

    @Test
    public void testSealOpen_aadNullSameAsEmpty() throws Exception {
        final HpkeContextSender ctxSender1 = createDefaultHpkeContextSender();
        final byte[] enc1 = ctxSender1.getEncapsulated();
        final byte[] ciphertext1 = ctxSender1.seal(DEFAULT_PT, /* aad= */ null);

        final HpkeContextSender ctxSender2 = createDefaultHpkeContextSender();
        final byte[] enc2 = ctxSender2.getEncapsulated();
        final byte[] ciphertext2 = ctxSender2.seal(DEFAULT_PT, /* aad= */ new byte[0]);

        assertNotNull(enc1);
        assertNotNull(ciphertext1);
        assertNotNull(enc2);
        assertNotNull(ciphertext2);
        assertNotEquals(encodeHex(enc1), encodeHex(enc2));
        assertNotEquals(encodeHex(DEFAULT_PT), encodeHex(ciphertext1));
        assertNotEquals(encodeHex(ciphertext1), encodeHex(ciphertext2));

        final HpkeContextRecipient ctxRecipient1 = createDefaultHpkeContextRecipient(enc1);
        byte[] plaintext1 = ctxRecipient1.open(ciphertext1, /* aad= */ new byte[0]);

        final HpkeContextRecipient ctxRecipient2 = createDefaultHpkeContextRecipient(enc2);
        byte[] plaintext2 = ctxRecipient2.open(ciphertext2, /* aad= */ null);

        assertNotNull(plaintext1);
        assertNotNull(plaintext2);
        assertArrayEquals(DEFAULT_PT, plaintext1);
        assertArrayEquals(DEFAULT_PT, plaintext2);
    }

    @Test
    public void testSealOpen_infoNullSameAsEmpty() throws Exception {
        final HpkeContextSender ctxSender1 = createDefaultHpkeContextSender(/* info= */ null);
        final byte[] enc1 = ctxSender1.getEncapsulated();
        final byte[] ciphertext1 = ctxSender1.seal(DEFAULT_PT, DEFAULT_AAD);

        final HpkeContextSender ctxSender2 =
                createDefaultHpkeContextSender(/* info= */ new byte[0]);
        final byte[] enc2 = ctxSender2.getEncapsulated();
        final byte[] ciphertext2 = ctxSender2.seal(DEFAULT_PT, DEFAULT_AAD);

        assertNotNull(enc1);
        assertNotNull(ciphertext1);
        assertNotNull(enc2);
        assertNotNull(ciphertext2);
        assertNotEquals(encodeHex(enc1), encodeHex(enc2));
        assertNotEquals(encodeHex(DEFAULT_PT), encodeHex(ciphertext1));
        assertNotEquals(encodeHex(ciphertext1), encodeHex(ciphertext2));

        final HpkeContextRecipient ctxRecipient1 =
                createDefaultHpkeContextRecipient(enc1, /* info= */ new byte[0]);
        byte[] plaintext1 = ctxRecipient1.open(ciphertext1, DEFAULT_AAD);

        final HpkeContextRecipient ctxRecipient2 =
                createDefaultHpkeContextRecipient(enc2, /* info= */ null);
        byte[] plaintext2 = ctxRecipient2.open(ciphertext2, DEFAULT_AAD);

        assertNotNull(plaintext1);
        assertNotNull(plaintext2);
        assertArrayEquals(DEFAULT_PT, plaintext1);
        assertArrayEquals(DEFAULT_PT, plaintext2);
    }

    @Test
    public void testSealOpen_withKeysFlipped_throwException() throws Exception {
        final PublicKey publicKey = createPublicKey(DEFAULT_SK_BYTES);
        final PrivateKey privateKey = createPrivateKey(DEFAULT_PK_BYTES);

        final HpkeContextSender ctxSender = HpkeContextSender.getInstance(DEFAULT_SUITE_NAME);
        ctxSender.init(publicKey, DEFAULT_INFO);

        final byte[] enc = ctxSender.getEncapsulated();
        final byte[] ciphertext = ctxSender.seal(DEFAULT_PT, DEFAULT_AAD);

        final HpkeContextRecipient ctxRecipient =
                HpkeContextRecipient.getInstance(DEFAULT_SUITE_NAME);
        ctxRecipient.init(enc, privateKey, DEFAULT_INFO);
        assertThrows(GeneralSecurityException.class, () -> ctxRecipient.open(ciphertext, DEFAULT_AAD));
    }

    @Test
    public void testExportWithSetupSenderAndReceiver_randomnessResult() throws Exception {
        final HpkeContextSender ctxSender = createDefaultHpkeContextSender();
        final byte[] enc = ctxSender.getEncapsulated();
        final byte[] export1 = ctxSender.export(DEFAULT_EXPORTER_LENGTH, DEFAULT_EXPORTER_CONTEXT);

        final HpkeContextRecipient ctxRecipient = createDefaultHpkeContextRecipient(DEFAULT_ENC);
        final byte[] export2 =
                ctxRecipient.export(DEFAULT_EXPORTER_LENGTH, DEFAULT_EXPORTER_CONTEXT);

        assertNotNull(enc);
        assertNotNull(export1);
        assertEquals(DEFAULT_EXPORTER_LENGTH, export1.length);
        assertNotNull(export2);
        assertEquals(DEFAULT_EXPORTER_LENGTH, export2.length);
        assertNotEquals(encodeHex(DEFAULT_ENC), encodeHex(enc));
        assertNotEquals(encodeHex(export1), encodeHex(export2));
    }
}
