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

import static org.conscrypt.HpkeFixture.DEFAULT_ENC;
import static org.conscrypt.HpkeFixture.DEFAULT_EXPORTER_CONTEXT;
import static org.conscrypt.HpkeFixture.DEFAULT_EXPORTER_LENGTH;
import static org.conscrypt.HpkeFixture.DEFAULT_PT;
import static org.conscrypt.HpkeFixture.createDefaultHpkeContextRecipient;
import static org.conscrypt.HpkeFixture.createDefaultHpkeContextSender;
import static org.conscrypt.HpkeTestVectorsTest.getHpkeEncryptionRecords;
import static org.conscrypt.TestUtils.encodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.conscrypt.HpkeTestVectorsTest.HpkeData;
import org.conscrypt.HpkeTestVectorsTest.HpkeEncryptionData;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.List;


/**
 * Tests for DuckTypedHpkeSpiTest. Essentially the same as the tests for HpkeContext but
 * with a "foreign" HPKE Provider inserted ahead of Conscrypt. That is, one which returns
 * SPI instances with all the correct methods but which don't inherit dirctly from "our"
 * HpkeSpi.
 */
@RunWith(JUnit4.class)
public class DuckTypedHpkeSpiTest {
    private static final Provider conscryptProvider = TestUtils.getConscryptProvider();

    @Before
    public void before() {
        Security.insertProviderAt(new ForeignHpkeProvider(), 1);
    }

    @After
    public void after() {
        Security.removeProvider(ForeignHpkeProvider.NAME);
    }

    // Copied from HpkeContextTest but with extra checks to ensure we are operating on
    // duck typed instances.
    @Test
    public void sealOpen() throws Exception {
        final HpkeContextSender ctxSender1 = createDefaultHpkeContextSender();
        assertForeign(ctxSender1);
        final byte[] enc1 = ctxSender1.getEnc();
        final byte[] ciphertext1 = ctxSender1.seal(DEFAULT_PT, /* aad= */ null);

        final HpkeContextSender ctxSender2 = createDefaultHpkeContextSender();
        assertForeign(ctxSender2);
        final byte[] enc2 = ctxSender2.getEnc();
        final byte[] ciphertext2 = ctxSender2.seal(DEFAULT_PT, /* aad= */ null);

        assertNotNull(enc1);
        assertNotNull(ciphertext1);
        assertNotNull(enc2);
        assertNotNull(ciphertext2);
        assertNotEquals(encodeHex(enc1), encodeHex(enc2));
        assertNotEquals(encodeHex(DEFAULT_PT), encodeHex(ciphertext1));
        assertNotEquals(encodeHex(ciphertext1), encodeHex(ciphertext2));

        final HpkeContextRecipient ctxRecipient1 = createDefaultHpkeContextRecipient(enc1);
        assertForeign(ctxRecipient1);
        byte[] plaintext1 = ctxRecipient1.open(ciphertext1, /* aad= */ null);

        final HpkeContextRecipient ctxRecipient2 = createDefaultHpkeContextRecipient(enc2);
        assertForeign(ctxRecipient2);
        byte[] plaintext2 = ctxRecipient2.open(ciphertext2, /* aad= */ null);

        assertNotNull(plaintext1);
        assertNotNull(plaintext2);
        assertArrayEquals(DEFAULT_PT, plaintext1);
        assertArrayEquals(DEFAULT_PT, plaintext2);
    }

    // Copied from HpkeContextTest but with extra checks to ensure we are operating on
    // duck typed instances.
    @Test
    public void export() throws Exception {
        final HpkeContextSender ctxSender = createDefaultHpkeContextSender();
        assertForeign(ctxSender);
        final byte[] enc = ctxSender.getEnc();
        final byte[] export1 = ctxSender.export(DEFAULT_EXPORTER_LENGTH, DEFAULT_EXPORTER_CONTEXT);

        final HpkeContextRecipient ctxRecipient = createDefaultHpkeContextRecipient(DEFAULT_ENC);
        assertForeign(ctxRecipient);
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

    @Test
    public void vectors() throws Exception {
        final List<HpkeData> records = getHpkeEncryptionRecords();
        for (HpkeData record : records) {
            testHpkeEncryption(record);
        }
    }

    // Copied from HpkeTestVectorsTest but with extra checks to ensure we are operating on
    // duck typed instances.
    private void testHpkeEncryption(HpkeData record) throws Exception {
        final byte[] enc = record.pkEm;

        // Encryption
        final HpkeContextSender contextSender =
            setupBaseForTesting(record.hpkeSuite, record.pkRm, record.info, record.skEm);
        assertForeign(contextSender);
        final byte[] encResult = contextSender.getEnc();
        assertArrayEquals("Failed encryption 'enc' " + encodeHex(enc), enc, encResult);
        for (HpkeEncryptionData encryption : record.encryptions) {
            final byte[] ciphertext = contextSender.seal(encryption.pt, encryption.aad);
            assertArrayEquals("Failed encryption 'ciphertext' on data : " + encryption,
                encryption.ct, ciphertext);
        }

        // Decryption
        final HpkeContextRecipient contextRecipient =
            HpkeContextRecipient.getInstance(record.hpkeSuite.name());
        assertForeign(contextRecipient);
        contextRecipient.init(HpkeContextRecipient.MODE_BASE, enc, record.skRm, record.info);
        for (HpkeEncryptionData encryption : record.encryptions) {
            final byte[] plaintext = contextRecipient.open(encryption.ct, encryption.aad);
            assertArrayEquals(
                "Failed decryption on data : " + encryption, encryption.pt, plaintext);
        }
    }

    private HpkeContextSender setupBaseForTesting(
        HpkeSuite suite, PublicKey publicKey, byte[] info, byte[] sKem) throws Exception {
        String algorithm = suite.name();
        HpkeContextSender sender = HpkeContextSender.getInstance(algorithm);
        sender.initForTesting(HpkeContextSender.MODE_BASE, publicKey, info, sKem);
        return sender;
    }

    // Asserts that an HpkeContext is duck-typed and configured as we expect it.
    private static void assertForeign(HpkeContext context) {
        // Instance should be coming from the foreign Provider.
        assertEquals(ForeignHpkeProvider.NAME, context.getProvider().getName());

        // Its SPI should be duck typed, because the foreign Provider returns instances
        // which use HpkeForeignSpi which *doesn't* implement HpkeSpi.
        assertTrue(context.getSpi() instanceof DuckTypedHpkeSpi);
        DuckTypedHpkeSpi duckTyped = (DuckTypedHpkeSpi) context.getSpi();

        // Verify the SPI is indeed foreign.
        assertTrue(duckTyped.getDelegate() instanceof HpkeForeignSpi);

        // And that it is delegating to a real HpkeImpl, so we can test it.
        HpkeForeignSpi foreign = (HpkeForeignSpi) duckTyped.getDelegate();
        assertTrue(foreign.delegate instanceof HpkeImpl);
        assertEquals(conscryptProvider.getName(), foreign.delegate.getProvider().getName());
    }

    // Provides HpkeContext instances that use a "foreign" SPI, that is one that isn't
    // know to inherit HpkeSpi but implements the same methods and so can be used via
    // duck typing.
    //
    // Some complexity here: We want to test end-to-end, so the foreign SPI delegates to a
    // real Conscrypt SPI for its implentation so there are two levels of delegation. That is:
    // * ForeignHpkeProvider provides instances of HpkeForeignSpi. This *doesn't* inherit from
    // HpkeSpi and so is representative of the case here the SPI comes from a different
    // Conscrypt variant or indeed some other provider.  HpkeContext created a
    // DuckTypedHpkeSpi to wrap this SPI and that is what we're testing above.
    // * HpkeForeignSpi finds its equivalent SPI from the real Conscrypt Provider and
    // delegates all operations to it (by direct method calls not duck typing).  This is just
    // a test setup quirk so we can test end-to-end.
    private static class ForeignHpkeProvider extends Provider {
        private static final String NAME = "Foreign_Hpke";

        protected ForeignHpkeProvider() {
            super( NAME, 1.0, "HPKE unit test usage only");
            put("ConscryptHpke.DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM",
                HpkeForeignSpi.X25519_AES_128.class.getName());
            put("ConscryptHpke.DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM",
                HpkeForeignSpi.X25519_AES_256.class.getName());
            put("ConscryptHpke.DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/CHACHA20POLY1305",
                HpkeForeignSpi.X25519_CHACHA20.class.getName());
        }
    }
    public static class HpkeForeignSpi {
        private final Provider provider;
        private final HpkeSpi delegate;

        public HpkeForeignSpi(Object arg, String hpkeSuite) throws NoSuchAlgorithmException {
            assertTrue(arg instanceof Provider);
            provider = (Provider) arg;

            Provider.Service service =
                conscryptProvider.getService("ConscryptHpke", hpkeSuite);
            assertNotNull(service);
            delegate = (HpkeSpi) service.newInstance(conscryptProvider);
            assertNotNull(delegate);
        }

        public void engineInitSender(int mode, PublicKey key, byte[] info, byte[] sKe)
            throws InvalidKeyException {
            delegate.engineInitSender(mode, key, info, sKe);
        }

        public void engineInitRecipient(int mode, byte[] enc, PrivateKey key, byte[] info)
            throws InvalidKeyException {
            delegate.engineInitRecipient(mode, enc, key, info);
        }

        public byte[] engineSeal(byte[] plaintext, byte[] aad) {
            return delegate.engineSeal(plaintext, aad);
        }

        public byte[] engineExport(int length, byte[] exporterContext) {
            return delegate.engineExport(length, exporterContext);
        }

        public byte[] engineOpen(byte[] ciphertext, byte[] aad) {
            return delegate.engineOpen(ciphertext, aad);
        }

        public byte[] getEnc() {
            return delegate.getEnc();
        }

        public Provider getProvider() {
            return provider;
        }

        public static class X25519_AES_128 extends HpkeForeignSpi {
            public X25519_AES_128(Object arg) throws NoSuchAlgorithmException {
                super(arg, "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM");
            }
        }

        public static class X25519_AES_256 extends HpkeForeignSpi {
            public X25519_AES_256(Object arg) throws NoSuchAlgorithmException {
                super(arg, "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM");
            }
        }

        public static class X25519_CHACHA20 extends HpkeForeignSpi {
            public X25519_CHACHA20(Object arg) throws NoSuchAlgorithmException {
                super(arg, "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/CHACHA20POLY1305");
            }
        }
    }
}