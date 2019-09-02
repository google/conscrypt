package org.conscrypt;

import org.junit.Assume;

final class PlatformTestUtil {
    static boolean isJavaVersion(int version) {
        return Platform.javaVersion() >= version;
    }

    static void assumeJava8() {
        Assume.assumeTrue("Require Java 8: " + Platform.javaVersion(), isJavaVersion(8));
    }
}
