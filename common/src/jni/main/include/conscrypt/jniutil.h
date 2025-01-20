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

#ifndef CONSCRYPT_JNIUTIL_H_
#define CONSCRYPT_JNIUTIL_H_

#include <jni.h>
#include <openssl/ssl.h>

#include <conscrypt/logging.h>
#include <conscrypt/macros.h>
#include <nativehelper/scoped_local_ref.h>

namespace conscrypt {
namespace jniutil {

extern JavaVM* gJavaVM;
extern jclass cryptoUpcallsClass;
extern jclass openSslInputStreamClass;
extern jclass nativeRefClass;
extern jclass nativeRefHpkeCtxClass;

extern jclass byteArrayClass;
extern jclass calendarClass;
extern jclass objectClass;
extern jclass objectArrayClass;
extern jclass integerClass;
extern jclass inputStreamClass;
extern jclass outputStreamClass;
extern jclass stringClass;
extern jclass byteBufferClass;

extern jfieldID nativeRef_address;

extern jmethodID calendar_setMethod;
extern jmethodID inputStream_readMethod;
extern jmethodID integer_valueOfMethod;
extern jmethodID openSslInputStream_readLineMethod;
extern jmethodID outputStream_writeMethod;
extern jmethodID outputStream_flushMethod;
extern jmethodID buffer_positionMethod;
extern jmethodID buffer_limitMethod;
extern jmethodID buffer_isDirectMethod;
extern jmethodID cryptoUpcallsClass_rawSignMethod;
extern jmethodID cryptoUpcallsClass_rsaSignMethod;
extern jmethodID cryptoUpcallsClass_rsaDecryptMethod;
extern jmethodID nativeRefHpkeCtxClass_constructor;
extern jmethodID sslHandshakeCallbacks_verifyCertificateChain;
extern jmethodID sslHandshakeCallbacks_onSSLStateChange;
extern jmethodID sslHandshakeCallbacks_clientCertificateRequested;
extern jmethodID sslHandshakeCallbacks_serverCertificateRequested;
extern jmethodID sslHandshakeCallbacks_clientPSKKeyRequested;
extern jmethodID sslHandshakeCallbacks_serverPSKKeyRequested;
extern jmethodID sslHandshakeCallbacks_onNewSessionEstablished;
extern jmethodID sslHandshakeCallbacks_selectApplicationProtocol;
extern jmethodID sslHandshakeCallbacks_serverSessionRequested;

/**
 * Initializes the JNI constants from the environment.
 */
void init(JavaVM* vm, JNIEnv* env);

/**
 * Obtains the current thread's JNIEnv
 */
inline JNIEnv* getJNIEnv(JavaVM* gJavaVM) {
    JNIEnv* env;

#ifdef ANDROID
    int ret = gJavaVM->AttachCurrentThread(&env, nullptr);
#else
    int ret = gJavaVM->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr);
#endif
    if (ret < 0) {
        CONSCRYPT_LOG_ERROR("Could not attach JavaVM to find current JNIEnv");
        return nullptr;
    }
    return env;
}

/**
 * Obtains the current thread's JNIEnv
 */
inline JNIEnv* getJNIEnv() {
    return getJNIEnv(gJavaVM);
}

inline jclass getGlobalRefToClass(JNIEnv* env, const char* className) {
    ScopedLocalRef<jclass> localClass(env, env->FindClass(className));
    jclass globalRef = reinterpret_cast<jclass>(env->NewGlobalRef(localClass.get()));
    if (globalRef == nullptr) {
        CONSCRYPT_LOG_ERROR("failed to find class %s", className);
        abort();
    }
    return globalRef;
}

inline jmethodID getMethodRef(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jmethodID localMethod = env->GetMethodID(clazz, name, sig);
    if (localMethod == nullptr) {
        CONSCRYPT_LOG_ERROR("could not find method %s", name);
        abort();
    }
    return localMethod;
}

inline jfieldID getFieldRef(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jfieldID localField = env->GetFieldID(clazz, name, sig);
    if (localField == nullptr) {
        CONSCRYPT_LOG_ERROR("could not find field %s", name);
        abort();
    }
    return localField;
}

inline jclass findClass(JNIEnv* env, const char* name) {
    ScopedLocalRef<jclass> localClass(env, env->FindClass(name));
    jclass result = reinterpret_cast<jclass>(env->NewGlobalRef(localClass.get()));
    if (result == nullptr) {
        CONSCRYPT_LOG_ERROR("failed to find class '%s'", name);
        abort();
    }
    return result;
}

/**
 * Register one or more native methods with a particular class.
 * "className" looks like "java/lang/String". Aborts on failure.
 */
void jniRegisterNativeMethods(JNIEnv* env, const char* className, const JNINativeMethod* gMethods,
                              int numMethods);

/**
 * Returns the int fd from a java.io.FileDescriptor.
 */
extern int jniGetFDFromFileDescriptor(JNIEnv* env, jobject fileDescriptor);

/**
 * Returns true if buffer is a non-null direct ByteBuffer instance.
 */
extern bool isDirectByteBufferInstance(JNIEnv* env, jobject buffer);

/**
 * Returns true if the VM's JNI GetByteArrayElements method is likely to create a copy when
 * invoked on an array of the provided size.
 */
extern bool isGetByteArrayElementsLikelyToReturnACopy(size_t size);

/**
 * Throw an exception with the specified class and an optional message.
 *
 * The "className" argument will be passed directly to FindClass, which
 * takes strings with slashes (e.g. "java/lang/Object").
 *
 * If an exception is currently pending, we log a warning message and
 * clear it.
 *
 * Returns 0 on success, nonzero if something failed (e.g. the exception
 * class couldn't be found, so *an* exception will still be pending).
 */
extern int throwException(JNIEnv* env, const char* className, const char* msg);

/**
 * Throw a java.lang.RuntimeException, with an optional message.
 */
extern int throwRuntimeException(JNIEnv* env, const char* msg);

#ifdef CONSCRYPT_CHECK_ERROR_QUEUE
/**
 * Throw a java.lang.AssertionError, with an optional message.
 */
extern int throwAssertionError(JNIEnv* env, const char* msg);
#endif

/*
 * Throw a java.lang.NullPointerException, with an optional message.
 */
extern int throwNullPointerException(JNIEnv* env, const char* msg);

/**
 * Throws a OutOfMemoryError with the given string as a message.
 */
extern int throwOutOfMemory(JNIEnv* env, const char* message);

/**
 * Throws an IllegalArgumentException with the given string as a message.
 */
extern int throwIllegalArgumentException(JNIEnv* env, const char* message);

/**
 * Throws a BadPaddingException with the given string as a message.
 */
extern int throwBadPaddingException(JNIEnv* env, const char* message);

/**
 * Throws a SignatureException with the given string as a message.
 */
extern int throwSignatureException(JNIEnv* env, const char* message);

/**
 * Throws a InvalidKeyException with the given string as a message.
 */
extern int throwInvalidKeyException(JNIEnv* env, const char* message);

/**
 * Throws a SignatureException with the given string as a message.
 */
extern int throwIllegalBlockSizeException(JNIEnv* env, const char* message);

/**
 * Throws a NoSuchAlgorithmException with the given string as a message.
 */
extern int throwNoSuchAlgorithmException(JNIEnv* env, const char* message);

/**
 * Throws an IOException with the given string as a message.
 */
extern int throwIOException(JNIEnv* env, const char* message);

/**
 * Throws a CertificateException with the given string as a message.
 */
extern int throwCertificateException(JNIEnv* env, const char* message);

/**
 * Throws a ParsingException with the given string as a message.
 */
extern int throwParsingException(JNIEnv* env, const char* message);

extern int throwInvalidAlgorithmParameterException(JNIEnv* env, const char* message);

extern int throwForAsn1Error(JNIEnv* env, int reason, const char* message,
                             int (*defaultThrow)(JNIEnv*, const char*));

extern int throwForCipherError(JNIEnv* env, int reason, const char* message,
                               int (*defaultThrow)(JNIEnv*, const char*));

extern int throwForEvpError(JNIEnv* env, int reason, const char* message,
                            int (*defaultThrow)(JNIEnv*, const char*));

extern int throwForRsaError(JNIEnv* env, int reason, const char* message,
                            int (*defaultThrow)(JNIEnv*, const char*));

extern int throwForX509Error(JNIEnv* env, int reason, const char* message,
                             int (*defaultThrow)(JNIEnv*, const char*));

/*
 * Checks this thread's OpenSSL error stack and throws an appropriate exception
 * type based on the type of error found.  If no error is present, throws
 * AssertionError.
 */
extern void throwExceptionFromBoringSSLError(
        JNIEnv* env, const char* location,
        int (*defaultThrow)(JNIEnv*, const char*) = throwRuntimeException);

/**
 * Throws an SocketTimeoutException with the given string as a message.
 */
extern int throwSocketTimeoutException(JNIEnv* env, const char* message);

/**
 * Throws a javax.net.ssl.SSLException with the given string as a message.
 */
extern int throwSSLHandshakeExceptionStr(JNIEnv* env, const char* message);

/**
 * Throws a javax.net.ssl.SSLException with the given string as a message.
 */
extern int throwSSLExceptionStr(JNIEnv* env, const char* message);

/**
 * Throws a javax.net.ssl.SSLProcotolException with the given string as a message.
 */
extern int throwSSLProtocolExceptionStr(JNIEnv* env, const char* message);

/**
 * Throws an SSLException with a message constructed from the current
 * SSL errors. This will also log the errors.
 *
 * @param env the JNI environment
 * @param ssl the possibly null SSL
 * @param sslErrorCode error code returned from SSL_get_error() or
 * SSL_ERROR_NONE to probe with ERR_get_error
 * @param message null-ok; general error message
 */
extern int throwSSLExceptionWithSslErrors(JNIEnv* env, SSL* ssl, int sslErrorCode,
                                          const char* message,
                                          int (*actualThrow)(JNIEnv*,
                                                             const char*) = throwSSLExceptionStr);

#ifdef CONSCRYPT_CHECK_ERROR_QUEUE
/**
 * Class that checks that the error queue is empty on destruction.  It should only be used
 * via the macro CHECK_ERROR_QUEUE_ON_RETURN, which can be placed at the top of a function to
 * ensure that the error queue is empty whenever the function exits.
 */
class ErrorQueueChecker {
 public:
    explicit ErrorQueueChecker(JNIEnv* env) : env(env) {}
    ~ErrorQueueChecker() {
        if (ERR_peek_error() != 0) {
            const char* file;
            int line;
            uint32_t error = ERR_get_error_line(&file, &line);
            char message[256];
            ERR_error_string_n(error, message, sizeof(message));
            char result[500];
            snprintf(result, sizeof(result),
                     "Error queue should have been empty but was (%s:%d) %s", file, line, message);
            // If there's a pending exception, we want to throw the assertion error instead
            env->ExceptionClear();
            throwAssertionError(env, result);
        }
    }

 private:
    JNIEnv* env;
};

#define CHECK_ERROR_QUEUE_ON_RETURN conscrypt::jniutil::ErrorQueueChecker __checker(env)
#else
#define CHECK_ERROR_QUEUE_ON_RETURN UNUSED_ARGUMENT(env)
#endif  // CONSCRYPT_CHECK_ERROR_QUEUE

}  // namespace jniutil
}  // namespace conscrypt

#endif  // CONSCRYPT_JNIUTIL_H_
