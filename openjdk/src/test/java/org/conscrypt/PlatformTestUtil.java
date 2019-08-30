package org.conscrypt;

import org.junit.Assume;

public final class PlatformTestUtil {

  public static boolean isJavaVersion(int version) {
    return Platform.javaVersion() >= version;
  }

  public static void assumeJava8() {
    Assume.assumeTrue("Require Java 8: " + Platform.javaVersion(), isJavaVersion(8));
  }
}
