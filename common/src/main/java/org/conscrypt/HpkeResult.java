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

/**
 * Wrapper to hold the result returned by {@link Hpke#seal(byte[], byte[])} and
 * {@link Hpke#export(int, byte[])}. These APIs return 2 parameters, an encapsulated key (enc)
 * and an output that could be either a ciphertext or an export (depending on the API).
 */
public final class HpkeResult {
  private final byte[] mEnc;
  private final byte[] mOutput;

  /**
   * {@link HpkeResult} constructor.
   *
   * @param enc    encapsulated key
   * @param output ciphertext or export
   */
  @Internal
  HpkeResult(byte[] enc, byte[] output) {
    mEnc = enc;
    mOutput = output;
  }

  /**
   * Returns the encapsulated key (enc).
   * If the API for setting up a sender is made, the enc will be generated during that process.
   * If the API for setting up a recipient is called, the enc will be matching to the enc passed
   * during the setup phase.
   *
   * @return encapsulated key (enc)
   */
  public byte[] getEnc() {
    return mEnc;
  }

  /**
   * Returns the output which could be a ciphertext or an export. If calling
   * {@link Hpke#seal(byte[], byte[])}, the result will be a ciphertext.
   * If calling {@link Hpke#export(int, byte[])}, the result will be an export.
   *
   * @return output either a ciphertext or export
   */
  public byte[] getOutput() {
    return mOutput;
  }
}
