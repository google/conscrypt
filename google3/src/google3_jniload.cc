
// JNI_OnLoad for Google3.

#include <conscrypt/compatibility_close_monitor.h>
#include <conscrypt/jniutil.h>
#include <conscrypt/logging.h>
#include <conscrypt/native_crypto.h>
#include <jni.h>

using ::conscrypt::CompatibilityCloseMonitor;
using ::conscrypt::NativeCrypto;

// This replicates functionality in jniload.cc for a couple of reasons:
//  * This needs to be declared 'extern "C"', and jniload's isn't.
//  * We can't include jniload.cc in our .so target at all due to
//    symbol collisions in some targets that also compile in jniload.cc
//    in a separate compilation unit(!).
//
// // TODO(b/408158702): Some refactoring of jniload.cc in upstream conscrypt
// could remove the need for all or some of this.
extern "C" JNIEXPORT jint JNI_OnLoad_conscrypt_google3(JavaVM* vm,
                                                       void* reserved) {
  JNIEnv* env;
  if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8) != JNI_OK) {
    CONSCRYPT_LOG_ERROR("Could not get JNIEnv");
    return JNI_ERR;
  }

  // Initialize the JNI constants.
  conscrypt::jniutil::init(vm, env);

  // Register all of the native JNI methods.
  NativeCrypto::registerNativeMethods(env);

  // Perform static initialization of the close monitor (if required on this
  // platform).
  CompatibilityCloseMonitor::init();
  return JNI_VERSION_1_8;
}
