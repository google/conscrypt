package org.conscrypt;

import static org.conscrypt.TestUtils.installConscryptAsDefaultProvider;

import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  AddressUtilsTest.class,
  ApplicationProtocolSelectorAdapterTest.class,
  ClientSessionContextTest.class,
  ConscryptSocketTest.class,
  ConscryptTest.class,
  DuckTypedPSKKeyManagerTest.class,
  FileClientSessionCacheTest.class,
  NativeCryptoTest.class,
  NativeRefTest.class,
  NativeSslSessionTest.class,
  OpenSSLKeyTest.class,
  OpenSSLX509CertificateTest.class,
  PlatformTest.class,
  ServerSessionContextTest.class,
  SSLUtilsTest.class,
  TestSessionBuilderTest.class,
})
public class ConscryptOpenJdkSuite {

  @BeforeClass
  public static void setupStatic() {
    installConscryptAsDefaultProvider();
  }

}
