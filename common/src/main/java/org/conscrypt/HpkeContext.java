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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

/**
 * Hybrid Public Key Encryption (HPKE) sender APIs.
 * <p>
 * Base class for HPKE sender and recipient contexts.
 * <p>
 * This is the client API for HPKE usage, all operations are delegated to an implementation
 * class implementing {@link HpkeSpi} which is located using the JCA {@link Provider}
 * mechanism.
 * <p>
 * The implementation maintains the context for an HPKE exchange, including the key schedule
 * to use for seal and open operations.
 *
 * Secret key material based on the context may also be generated and exported as per RFC 9180.
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#hpke-export">RFC 9180 (HPKE)</a>
 */
public abstract class HpkeContext {
  protected final HpkeSpi spi;

  protected HpkeContext(HpkeSpi spi) {
    this.spi = spi;
  }

  /**
   * Exports secret key material from this HpkeContext as described in RFC 9180.
   *
   * @param length  expected output length
   * @param context optional context string, may be null or empty
   * @return exported value
   * @throws IllegalArgumentException if the length is not valid for the KDF in use
   * @throws IllegalStateException if this HpkeContext has not been initialised
   *
   */
  public byte[] export(int length, byte[] context) {
    return spi.engineExport(length, context);
  }

  /**
   * Returns the {@link HpkeSpi} being used by this HpkeContext.
   *
   * @return the SPI
   */
  public HpkeSpi getSpi() {
    return spi;
  }

  protected static HpkeSpi findSpi(String algorithm) throws NoSuchAlgorithmException {
    if (algorithm == null) {
      // Same behaviour as Cipher.getInstance
      throw new NoSuchAlgorithmException("null algorithm");
    }
    return findSpi(algorithm, findFirstProvider(algorithm));
  }

  private static Provider findFirstProvider(String algorithm) throws NoSuchAlgorithmException {
    for (Provider p : Security.getProviders()) {
      Provider.Service service = p.getService("ConscryptHpke", algorithm);
      if (service != null) {
        return service.getProvider();
      }
    }
    throw new NoSuchAlgorithmException("No Provider found for: " + algorithm);
  }

  protected static HpkeSpi findSpi(String algorithm, String providerName) throws
      NoSuchAlgorithmException, IllegalArgumentException, NoSuchProviderException {
    if (providerName == null || providerName.isEmpty()) {
      // Same behaviour as Cipher.getInstance
      throw new IllegalArgumentException("Invalid provider name");
    }
    Provider provider = Security.getProvider(providerName);
    if (provider == null) {
      throw new NoSuchProviderException("Unknown Provider: " + providerName);
    }
    return findSpi(algorithm, provider);
  }

  protected static HpkeSpi findSpi(String algorithm, Provider provider) throws
      NoSuchAlgorithmException, IllegalArgumentException {
    if (provider == null) {
      throw new IllegalArgumentException("null Provider");
    }
    Provider.Service service = provider.getService("ConscryptHpke", algorithm);
    if (service == null) {
      throw new NoSuchAlgorithmException("Unknown algorithm");
    }
    Object instance = service.newInstance(null);
    HpkeSpi spi = (instance instanceof HpkeSpi) ? (HpkeSpi) instance
            : DuckTypedHpkeSpi.newInstance(instance);
    if (spi != null) {
      return spi;
    }
    throw new IllegalStateException(
        String.format("Provider %s is providing incorrect instances", provider.getName()));
  }
}
