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

import libcore.util.NonNull;
import libcore.util.Nullable;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Delegating wrapper for HpkeImpl that inherits the Android platform's SPI
 * as well as Conscrypt's own.
 */
@SuppressWarnings("NewApi")
public class AndroidHpkeSpi implements android.crypto.hpke.HpkeSpi, org.conscrypt.HpkeSpi {
    private final org.conscrypt.HpkeSpi delegate;

    public AndroidHpkeSpi(org.conscrypt.HpkeSpi delegate) {
        this.delegate = delegate;
    }

    @Override
    public void engineInitSender(PublicKey recipientKey, byte @Nullable[] info,
                                 PrivateKey senderKey, byte @Nullable[] psk,
                                 byte @Nullable[] psk_id) throws InvalidKeyException {
        delegate.engineInitSender(recipientKey, info, senderKey, psk, psk_id);
    }

    @Override
    public void engineInitSenderForTesting(PublicKey recipientKey, byte[] info,
                                           PrivateKey senderKey, byte[] psk, byte[] psk_id,
                                           byte[] sKe) throws InvalidKeyException {
        delegate.engineInitSenderForTesting(recipientKey, info, senderKey, psk, psk_id, sKe);
    }

    @Override
    public void engineInitSenderWithSeed(PublicKey recipientKey, byte @Nullable[] info,
                                         PrivateKey senderKey, byte @Nullable[] psk,
                                         byte @Nullable[] psk_id, byte @NonNull[] sKe)
            throws InvalidKeyException {
        delegate.engineInitSenderForTesting(recipientKey, info, senderKey, psk, psk_id, sKe);
    }

    @Override
    public void engineInitRecipient(byte @NonNull[] encapsulated, PrivateKey recipientKey,
                                    byte @Nullable[] info, PublicKey senderKey,
                                    byte @Nullable[] psk, byte @Nullable[] psk_id)
            throws InvalidKeyException {
        delegate.engineInitRecipient(encapsulated, recipientKey, info, senderKey, psk, psk_id);
    }

    @Override
    public byte @NonNull[] engineSeal(byte @NonNull[] plaintext, byte @Nullable[] aad) {
        return delegate.engineSeal(plaintext, aad);
    }

    @Override
    public byte @NonNull[] engineOpen(byte @NonNull[] ciphertext, byte @Nullable[] aad)
            throws GeneralSecurityException {
        return delegate.engineOpen(ciphertext, aad);
    }

    @Override
    public byte @NonNull[] engineExport(int length, byte @Nullable[] context) {
        return delegate.engineExport(length, context);
    }

    @Override
    public byte @NonNull[] getEncapsulated() {
        return delegate.getEncapsulated();
    }

    public static class X25519_AES_128 extends AndroidHpkeSpi {
        public X25519_AES_128() {
            super(new HpkeImpl.X25519_AES_128());
        }
    }

    public static class X25519_AES_256 extends AndroidHpkeSpi {
        public X25519_AES_256() {
            super(new HpkeImpl.X25519_AES_256());
        }
    }

    public static class X25519_CHACHA20 extends AndroidHpkeSpi {
        public X25519_CHACHA20() {
            super(new HpkeImpl.X25519_CHACHA20());
        }
    }
}
