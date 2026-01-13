package org.conscrypt;

import com.google.common.flogger.GoogleLogger;
import com.google.common.jni.JniLoader;
import com.google.devtools.java.launcher.LauncherExport;
import com.google.wrappers.base.GoogleInit;

class NativeCryptoJni {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  public static void init() {
    logger.atFine().log("Initializing Conscrypt");
    if (GoogleInit.isNativeDepsInLauncher()) {
      // This is the typical case. The Google3 launcher will allow us to load like this.
      // Note: it is important that we do not try `JniLoader.loadLibrary` if we are using the
      // Google3 launcher as this might lead to C++ undefined behavior.
      LauncherExport.loadFromLauncher("conscrypt_google3");
      logger.atInfo().log("Successfully loaded Conscrypt");
    } else {
      // This is the uncommon case. Since we are not using NativeDepsInLauncher we need to call
      // `JniLoader.loadLibrary`.
      logger.atInfo().log("Attempting to load conscrypt via Shared Library JNI loading.");
      JniLoader.loadLibrary("third_party/java_src/conscrypt/libconscrypt_openjdk_jni.so");
      GoogleInit.initializeLibraryWithSystemPropertyFlags(NativeCrypto.class.getName());
      logger.atInfo().log("Successfully loaded conscrypt via Shared Library JNI loading.");
    }
  }

  private NativeCryptoJni() {}
}
