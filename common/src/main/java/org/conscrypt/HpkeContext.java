package org.conscrypt;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

public class HpkeContext {
  public static final int MODE_BASE = 0x00;
  protected final HpkeSpi spi;

  protected HpkeContext(HpkeSpi spi) {
    this.spi = spi;
  }

  /**
   * Hybrid Public Key Encryption (HPKE) secret export.
   *
   * @param length          expected output length
   * @param exporterContext optional exporter context
   * @return exported value
   * @throws IllegalArgumentException if the length is not valid based on the KDF spec
   */
  public byte[] export(int length, byte[] exporterContext) {
    return spi.engineExport(length, exporterContext);
  }

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
