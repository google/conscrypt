/*
 * Copyright (C) 2017 The Android Open Source Project
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

import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Enumeration for creating ciphers with various providers.
 */
public enum OpenJdkCipherFactory implements CipherFactory {
  JDK {
    @Override
    public Cipher newCipher(String transformation)
        throws NoSuchPaddingException, NoSuchAlgorithmException {
      return Cipher.getInstance(transformation);
    }
  },
  CONSCRYPT {
    @Override
    public Cipher newCipher(String transformation)
        throws NoSuchPaddingException, NoSuchAlgorithmException {
      return Cipher.getInstance(transformation, TestUtils.getConscryptProvider());
    }
  };
}
