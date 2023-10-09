package org.conscrypt;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

public interface HpkeSpi {
  void engineInitSender(int mode, PublicKey key, byte[] info, byte[] sKe) throws InvalidKeyException;
  void engineInitRecipient(int mode, byte[] enc, PrivateKey key, byte[] info, byte[] seed) throws InvalidKeyException;

  byte[] engineSeal(byte[] plaintext, byte[] aad);

  byte[] engineExport(int length, byte[] exporterContext);

  byte[] engineOpen(byte[] ciphertext, byte[] aad);

  byte[] getEnc();

  Provider getProvider();
}
