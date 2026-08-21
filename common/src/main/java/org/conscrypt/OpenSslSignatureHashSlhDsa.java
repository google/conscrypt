/*
 * Copyright (C) 2026 The Android Open Source Project
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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * Implements the JDK Signature interface needed for HashSLH-DSA-SHA2-128S signature generation and
 * verification using BoringSSL.
 */
@Internal
public class OpenSslSignatureHashSlhDsa extends SignatureSpi {
  private final int hashNid;
  private OpenSSLMessageDigestJDK messageDigest;

  /** The current OpenSSL key we're operating on. */
  private OpenSslSlhDsaPrivateKey privateKey;

  private OpenSslSlhDsaPublicKey publicKey;

  protected OpenSslSignatureHashSlhDsa(int hashNid) {
    this.hashNid = hashNid;
  }

  /** SHA-384 prehash SLH-DSA signature implementation. */
  public static final class Sha384 extends OpenSslSignatureHashSlhDsa {
    public Sha384() {
      super(NativeConstants.NID_sha384);
    }
  }

  private void resetDigest() {
    try {
      if (hashNid == NativeConstants.NID_sha384) {
        messageDigest = new OpenSSLMessageDigestJDK.SHA384();
      } else {
        throw new IllegalStateException("Unsupported hash NID: " + hashNid);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError("Failed to create message digest", e);
    }
  }

  @Override
  protected void engineUpdate(byte input) throws SignatureException {
    if (messageDigest == null) {
      throw new SignatureException("Not initialized");
    }
    messageDigest.engineUpdate(input);
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) throws SignatureException {
    if (messageDigest == null) {
      throw new SignatureException("Not initialized");
    }
    messageDigest.engineUpdate(input, offset, len);
  }

  @Override
  // Deprecated in Java 9, but still required by SignatureSpi.
  @SuppressWarnings("deprecation")
  protected Object engineGetParameter(String param) {
    return null;
  }

  @Override
  @SuppressWarnings("PatternMatchingInstanceof")
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    if (!(privateKey instanceof OpenSslSlhDsaPrivateKey)) {
      throw new InvalidKeyException("Must be OpenSslSlhDsaPrivateKey");
    }
    this.privateKey = (OpenSslSlhDsaPrivateKey) privateKey;
    this.publicKey = null;
    resetDigest();
  }

  @Override
  @SuppressWarnings("PatternMatchingInstanceof")
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    if (!(publicKey instanceof OpenSslSlhDsaPublicKey)) {
      throw new InvalidKeyException("Must be OpenSslSlhDsaPublicKey");
    }
    this.publicKey = (OpenSslSlhDsaPublicKey) publicKey;
    this.privateKey = null;
    resetDigest();
  }

  @Override
  // Deprecated in Java 9, but still required by SignatureSpi.
  @SuppressWarnings("deprecation")
  protected void engineSetParameter(String param, Object value) {}

  @Override
  protected byte[] engineSign() throws SignatureException {
    if (privateKey == null || messageDigest == null) {
      throw new SignatureException("Not initialized for signing");
    }
    byte[] digest = messageDigest.engineDigest();
    return NativeCrypto.SLHDSA_SHA2_128S_prehash_sign(
        digest, digest.length, hashNid, privateKey.getRaw());
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    if (publicKey == null || messageDigest == null) {
      throw new SignatureException("Not initialized for verification");
    }
    byte[] digest = messageDigest.engineDigest();
    int result =
        NativeCrypto.SLHDSA_SHA2_128S_prehash_verify(
            digest, digest.length, sigBytes, hashNid, publicKey.getRaw());
    return result == 1;
  }
}
