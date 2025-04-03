/*
 * Copyright 2022 The Android Open Source Project
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

import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/** A SLH-DSA private key. */
public class OpenSslSlhDsaPrivateKey implements PrivateKey {

  static final int PRIVATE_KEY_SIZE_BYTES = 64;

  private byte[] raw;

  public OpenSslSlhDsaPrivateKey(EncodedKeySpec keySpec) throws InvalidKeySpecException {
        byte[] encoded = keySpec.getEncoded();
    if ("raw".equalsIgnoreCase(keySpec.getFormat())) {
        if (encoded.length != PRIVATE_KEY_SIZE_BYTES) {
            throw new InvalidKeySpecException("Invalid key size");
        }
        raw = encoded;
        } else {
      throw new InvalidKeySpecException("Encoding must be in raw format");
        }

    }

  public OpenSslSlhDsaPrivateKey(byte[] raw) {
        if (raw.length != PRIVATE_KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("Invalid key size");
        }
        this.raw = raw.clone();
    }

    @Override
    public String getAlgorithm() {
      return "SLH-DSA";
    }

    @Override
    public String getFormat() {
      throw new UnsupportedOperationException("getFormat() not yet supported");
    }

    @Override
    public byte[] getEncoded() {
      throw new UnsupportedOperationException("getEncoded() not yet supported");
    }

    byte[] getRaw() {
    if (raw == null) {
            throw new IllegalStateException("key is destroyed");
        }
    return raw.clone();
    }

    @Override
    public void destroy() {
    if (raw != null) {
      Arrays.fill(raw, (byte) 0);
      raw = null;
        }
    }

    @Override
    public boolean isDestroyed() {
    return raw == null;
    }

    @Override
    public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof OpenSslSlhDsaPrivateKey)) {
      return false;
    }
    OpenSslSlhDsaPrivateKey that = (OpenSslSlhDsaPrivateKey) o;
    return Arrays.equals(raw, that.raw);
    }

    @Override
    public int hashCode() {
    return Arrays.hashCode(raw);
    }
}
