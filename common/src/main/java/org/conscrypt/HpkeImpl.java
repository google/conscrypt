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

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Implementation of {@link HpkeSpi}.  Should not be used directly, but rather by one
 * of the subclasses of {@link HpkeContext}.
 */
public class HpkeImpl implements HpkeSpi {
  private final HpkeSuite hpkeSuite;

  private NativeRef.EVP_HPKE_CTX ctx;
  private byte[] encapsulated = null;


  public HpkeImpl(HpkeSuite hpkeSuite) {
    this.hpkeSuite = hpkeSuite;
  }

  @Override
  public void engineInitSender(int mode, PublicKey publicKey, byte[] info, byte[] sKe)
          throws InvalidKeyException {
    checkNotInitialised();
    if (publicKey == null) {
      throw new InvalidKeyException("null key");
    }
    if (mode != HpkeContextSender.MODE_BASE) {
      throw new UnsupportedOperationException("Unsupported mode " + mode);
    }
    final byte[] pk = hpkeSuite.getKem().validatePublicKeyTypeAndGetRawKey(publicKey);

    final Object[] result = (sKe == null)
            ? NativeCrypto.EVP_HPKE_CTX_setup_sender(
                    hpkeSuite.getKem().getId(), hpkeSuite.getKdf().getId(),
                    hpkeSuite.getAead().getId(), pk, info)
            : NativeCrypto.EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
                    hpkeSuite.getKem().getId(), hpkeSuite.getKdf().getId(),
                    hpkeSuite.getAead().getId(), pk, info, sKe);
    ctx = (NativeRef.EVP_HPKE_CTX) result[0];
    encapsulated = (byte[]) result[1];
  }

  @Override
  public void engineInitRecipient(int mode, byte[] encapsulated, PrivateKey key, byte[] info)
          throws InvalidKeyException {
    checkNotInitialised();
    if (key == null) {
      throw new InvalidKeyException("null key");
    }
    if (mode != HpkeContextSender.MODE_BASE) {
      throw new UnsupportedOperationException("Unsupported mode " + mode);
    }
    hpkeSuite.getKem().validateEncapsulatedLength(encapsulated);
    final byte[] sk = hpkeSuite.getKem().validatePrivateKeyTypeAndGetRawKey(key);

    ctx = (NativeRef.EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_recipient(
        hpkeSuite.getKem().getId(), hpkeSuite.getKdf().getId(),
        hpkeSuite.getAead().getId(), sk, encapsulated, info);
  }

  @Override
  public byte[] engineSeal(byte[] plaintext, byte[] aad) {
    checkIsSender();
    Preconditions.checkNotNull(plaintext, "null plaintext");
    return NativeCrypto.EVP_HPKE_CTX_seal(ctx, plaintext, aad);
  }

  @Override
  public byte[] engineExport(int length, byte[] exporterContext) {
    checkInitialised();
    hpkeSuite.getKdf().validateExportLength(length);
    return NativeCrypto.EVP_HPKE_CTX_export(ctx, exporterContext, length);
  }

  @Override
  public byte[] engineOpen(byte[] ciphertext, byte[] aad) {
    checkIsRecipient();
    Preconditions.checkNotNull(ciphertext, "null ciphertext");
    return NativeCrypto.EVP_HPKE_CTX_open(ctx, ciphertext, aad);
  }

  private void checkInitialised() {
    if (ctx == null) {
      throw new IllegalStateException("Not initialised");
    }
  }

  private void checkNotInitialised() {
    if (ctx != null) {
      throw new IllegalStateException("Already initialised");
    }
  }

  private void checkIsSender() {
    checkInitialised();
    if (encapsulated == null) {
      throw new IllegalStateException("Internal error");
    }
  }

  private void checkIsRecipient() {
    checkInitialised();
    if (encapsulated != null) {
      throw new IllegalStateException("Internal error");
    }
  }

  @Override
  public byte[] getEncapsulated() {
    checkIsSender();
    return encapsulated;
  }

  public static class X25519_AES_128 extends HpkeImpl {
    public X25519_AES_128() {
      super(new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM));
    }
  }

  public static class X25519_AES_256 extends HpkeImpl {
    public X25519_AES_256() {
      super(new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM));
    }
  }

  public static class X25519_CHACHA20 extends HpkeImpl {
    public X25519_CHACHA20() {
      super(new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_CHACHA20POLY1305));
    }
  }
}
