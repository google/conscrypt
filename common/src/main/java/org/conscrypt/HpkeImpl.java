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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import javax.crypto.BadPaddingException;

/**
 * Implementation of {@link HpkeSpi}.  Should not be used directly, but rather by one
 * of the subclasses of {@link HpkeContext}.
 */
@Internal
public class HpkeImpl implements HpkeSpi {
  private final HpkeSuite hpkeSuite;

  private NativeRef.EVP_HPKE_CTX ctx;
  private byte[] encapsulated = null;

  public HpkeImpl(HpkeSuite hpkeSuite) {
    this.hpkeSuite = hpkeSuite;
  }

  byte[] getPublicKeyBytes(PublicKey publicKey) throws InvalidKeyException {
    if (publicKey == null) {
      throw new InvalidKeyException("null recipient key");
    } else if ((publicKey instanceof OpenSSLX25519PublicKey)) {
      return ((OpenSSLX25519PublicKey) publicKey).getU();
    } else if ((publicKey instanceof OpenSslXwingPublicKey)) {
      return ((OpenSslXwingPublicKey) publicKey).getRaw();
    } else {
      throw new InvalidKeyException("Unsupported recipient key class: " + publicKey.getClass());
    }
  }

  @Override
  public void engineInitSender(PublicKey recipientKey, byte[] info, PrivateKey senderKey,
          byte[] psk, byte[] psk_id) throws InvalidKeyException {
    checkNotInitialised();
    checkArgumentsForBaseModeOnly(senderKey, psk, psk_id);

    final Object[] result = NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender(
            hpkeSuite, getPublicKeyBytes(recipientKey), info);
    ctx = (NativeRef.EVP_HPKE_CTX) result[0];
    encapsulated = (byte[]) result[1];
  }

  @Override
  public void engineInitSenderForTesting(PublicKey recipientKey, byte[] info,
          PrivateKey senderKey, byte[] psk, byte[] psk_id, byte[] sKe) throws InvalidKeyException {
    checkNotInitialised();
    Objects.requireNonNull(sKe);
    checkArgumentsForBaseModeOnly(senderKey, psk, psk_id);

    final Object[] result = NativeCrypto.EVP_HPKE_CTX_setup_base_mode_sender_with_seed_for_testing(
            hpkeSuite, getPublicKeyBytes(recipientKey), info, sKe);
    ctx = (NativeRef.EVP_HPKE_CTX) result[0];
    encapsulated = (byte[]) result[1];
  }

  byte[] getPrivateKeyBytes(PrivateKey privateKey) throws InvalidKeyException {
    if (privateKey == null) {
      throw new InvalidKeyException("null recipient private key");
    } else if ((privateKey instanceof OpenSSLX25519PrivateKey)) {
      return ((OpenSSLX25519PrivateKey) privateKey).getU();
    } else if ((privateKey instanceof OpenSslXwingPrivateKey)) {
      return ((OpenSslXwingPrivateKey) privateKey).getRaw();
    } else {
      throw new InvalidKeyException(
          "Unsupported recipient private key class: " + privateKey.getClass());
    }
  }

  @Override
  public void engineInitRecipient(byte[] encapsulated, PrivateKey recipientKey,
          byte[] info, PublicKey senderKey, byte[] psk, byte[] psk_id) throws InvalidKeyException {
    checkNotInitialised();
    checkArgumentsForBaseModeOnly(senderKey, psk, psk_id);
    Preconditions.checkNotNull(encapsulated, "null encapsulated data");
    if (encapsulated.length != hpkeSuite.getKem().getEncapsulatedLength()) {
      throw new InvalidKeyException("Invalid encapsulated length: " + encapsulated.length);
    }

    ctx = (NativeRef.EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_base_mode_recipient(
            hpkeSuite, getPrivateKeyBytes(recipientKey), encapsulated, info);
  }

  private void checkArgumentsForBaseModeOnly(Key senderKey, byte[] psk, byte[] psk_id) {
    if (senderKey != null) {
      throw new UnsupportedOperationException("Asymmetric authentication not supported");
    }
    // PSK args can only be null if the application passed them in.
    Objects.requireNonNull(psk);
    Objects.requireNonNull(psk_id);
    if (psk.length > 0 || psk_id.length > 0) {
      throw new UnsupportedOperationException("PSK authentication not supported");
    }
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
    long maxLength = hpkeSuite.getKdf().maxExportLength();
    if (length < 0 || length > maxLength) {
      throw new IllegalArgumentException("Export length must be between 0 and "
              + maxLength + ", but was " + length);
    }
    return NativeCrypto.EVP_HPKE_CTX_export(ctx, exporterContext, length);
  }

  @Override
  public byte[] engineOpen(byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
    checkIsRecipient();
    Preconditions.checkNotNull(ciphertext, "null ciphertext");
    try {
      return NativeCrypto.EVP_HPKE_CTX_open(ctx, ciphertext, aad);
    } catch (BadPaddingException e) {
      throw new HpkeDecryptException(e.getMessage());
    }
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

  /** Implementation of XWING/HKDF_SHA256/AES_128_GCM. */
  public static class XwingHkdfSha256Aes128Gcm extends HpkeImpl {
    public XwingHkdfSha256Aes128Gcm() {
      super(new HpkeSuite(KEM_XWING, KDF_HKDF_SHA256, AEAD_AES_128_GCM));
    }
  }

  /** Implementation of XWING/HKDF_SHA256/AES_256_GCM. */
  public static class XwingHkdfSha256Aes256Gcm extends HpkeImpl {
    public XwingHkdfSha256Aes256Gcm() {
      super(new HpkeSuite(KEM_XWING, KDF_HKDF_SHA256, AEAD_AES_256_GCM));
    }
  }

  /** Implementation of XWING/HKDF_SHA256/CHACHA20_POLY1305. */
  public static class XwingHkdfSha256ChaCha20Poly1305 extends HpkeImpl {
    public XwingHkdfSha256ChaCha20Poly1305() {
      super(new HpkeSuite(KEM_XWING, KDF_HKDF_SHA256, AEAD_CHACHA20POLY1305));
    }
  }
}
