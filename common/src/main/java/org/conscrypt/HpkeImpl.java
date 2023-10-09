package org.conscrypt;

import static org.conscrypt.HpkeSuite.AEAD_AES_128_GCM;
import static org.conscrypt.HpkeSuite.AEAD_AES_256_GCM;
import static org.conscrypt.HpkeSuite.AEAD_CHACHA20POLY1305;
import static org.conscrypt.HpkeSuite.KDF_HKDF_SHA256;
import static org.conscrypt.HpkeSuite.KEM_DHKEM_X25519_HKDF_SHA256;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

public class HpkeImpl implements HpkeSpi {
  private final Provider provider;
  private final HpkeSuite hpkeSuite;

  private NativeRef.EVP_HPKE_CTX ctx;
  private byte[] enc = null;


  public HpkeImpl(Object arg, HpkeSuite hpkeSuite) {
    if (arg instanceof Provider) {
      provider = (Provider) arg;
    } else {
      provider = null;
    }
    this.hpkeSuite = hpkeSuite;
  }

  @Override
  public void engineInitSender(int mode, PublicKey publicKey, byte[] info, byte[] sKe) throws InvalidKeyException {
    if (publicKey == null) {
      throw new InvalidKeyException("null key");
    }
    if (mode != HpkeContextSender.MODE_BASE) {
      throw new UnsupportedOperationException("Unsupported mode " + mode);
    }
    final byte[] pk = hpkeSuite.getKem().validatePublicKeyTypeAndGetRawKey(publicKey);
    checkNotInitialised();

    final Object[] result = (sKe == null)
        ? NativeCrypto.EVP_HPKE_CTX_setup_sender(hpkeSuite.getKem().getId(),
        hpkeSuite.getKdf().getId(), hpkeSuite.getAead().getId(), pk, info)
        : NativeCrypto.EVP_HPKE_CTX_setup_sender_with_seed_for_testing(hpkeSuite.getKem().getId(),
        hpkeSuite.getKdf().getId(), hpkeSuite.getAead().getId(), pk, info, sKe);
    ctx = (NativeRef.EVP_HPKE_CTX) result[0];
    enc = (byte[]) result[1];
  }

  @Override
  public void engineInitRecipient(int mode, byte[] enc, PrivateKey key, byte[] info, byte[] seed) throws InvalidKeyException {
    if (key == null) {
      throw new InvalidKeyException("null key");
    }
    if (mode != HpkeContextSender.MODE_BASE) {
      throw new UnsupportedOperationException("Unsupported mode " + mode);
    }
    final byte[] sk = hpkeSuite.getKem().validatePrivateKeyTypeAndGetRawKey(key);

    checkNotInitialised();
    ctx = (NativeRef.EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_recipient(
        hpkeSuite.getKem().getId(), hpkeSuite.getKdf().getId(),
        hpkeSuite.getAead().getId(), sk, enc, info);
  }


  @Override
  public byte[] engineSeal(byte[] plaintext, byte[] aad) {
    Preconditions.checkNotNull(plaintext, "null plaintext");
    checkSender();
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
    Preconditions.checkNotNull(ciphertext, "null ciphertext");
    checkRecipient();
    try {
      return NativeCrypto.EVP_HPKE_CTX_open(ctx, ciphertext, aad);
    } catch (Exception e) {
      throw new IllegalStateException("Decryption failed");
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

  private void checkSender() {
    checkInitialised();
    if (enc == null) {
      throw new IllegalStateException("Internal error");
    }
  }

  private void checkRecipient() {
    checkInitialised();
    if (enc != null) {
      throw new IllegalStateException("Internal error");
    }
  }


  @Override
  public byte[] getEnc() {
    return enc;
  }

  @Override
  public Provider getProvider() {
    return provider;
  }

  public static class X25519_AES_128 extends HpkeImpl {

    public X25519_AES_128(Object arg) {
      super(arg, new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM));
    }

  }
  public static class X25519_AES_256 extends HpkeImpl {
    public X25519_AES_256(Object arg) {
      super(arg, new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM));
    }
  }

  public static class X25519_CHACHA20 extends HpkeImpl {
    public X25519_CHACHA20(Object arg) {
      super(arg, new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_CHACHA20POLY1305));
    }
  }
}
