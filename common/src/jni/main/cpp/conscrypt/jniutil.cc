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

#include <conscrypt/jniutil.h>

#include <conscrypt/compat.h>
#include <conscrypt/trace.h>
#include <cstdlib>
#include <errno.h>

namespace conscrypt {
namespace jniutil {

JavaVM *gJavaVM;
jclass cryptoUpcallsClass;
jclass openSslInputStreamClass;
jclass nativeRefClass;

jclass byteArrayClass;
jclass calendarClass;
jclass objectClass;
jclass objectArrayClass;
jclass integerClass;
jclass inputStreamClass;
jclass outputStreamClass;
jclass stringClass;

jfieldID nativeRef_address;

jmethodID calendar_setMethod;
jmethodID inputStream_readMethod;
jmethodID integer_valueOfMethod;
jmethodID openSslInputStream_readLineMethod;
jmethodID outputStream_writeMethod;
jmethodID outputStream_flushMethod;

void init(JavaVM* vm, JNIEnv* env) {
    gJavaVM = vm;

    byteArrayClass = findClass(env, "[B");
    calendarClass = findClass(env, "java/util/Calendar");
    inputStreamClass = findClass(env, "java/io/InputStream");
    integerClass = findClass(env, "java/lang/Integer");
    objectClass = findClass(env, "java/lang/Object");
    objectArrayClass = findClass(env, "[Ljava/lang/Object;");
    outputStreamClass = findClass(env, "java/io/OutputStream");
    stringClass = findClass(env, "java/lang/String");

    cryptoUpcallsClass = getGlobalRefToClass(
            env, TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/CryptoUpcalls");
    nativeRefClass = getGlobalRefToClass(
            env, TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef");
    openSslInputStreamClass = getGlobalRefToClass(
            env, TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/OpenSSLBIOInputStream");

    nativeRef_address = getFieldRef(env, nativeRefClass, "address", "J");

    calendar_setMethod = getMethodRef(env, calendarClass, "set", "(IIIIII)V");
    inputStream_readMethod = getMethodRef(env, inputStreamClass, "read", "([B)I");
    integer_valueOfMethod =
            env->GetStaticMethodID(integerClass, "valueOf", "(I)Ljava/lang/Integer;");
    openSslInputStream_readLineMethod =
            getMethodRef(env, openSslInputStreamClass, "gets", "([B)I");
    outputStream_writeMethod = getMethodRef(env, outputStreamClass, "write", "([B)V");
    outputStream_flushMethod = getMethodRef(env, outputStreamClass, "flush", "()V");
}

void jniRegisterNativeMethods(JNIEnv* env, const char* className, const JNINativeMethod* gMethods,
                              int numMethods) {
    CONSCRYPT_LOG_VERBOSE("Registering %s's %d native methods...", className, numMethods);

    ScopedLocalRef<jclass> c(env, env->FindClass(className));
    if (c.get() == nullptr) {
        char* msg;
        (void)asprintf(&msg, "Native registration unable to find class '%s'; aborting...",
                       className);
        env->FatalError(msg);
    }

    if (env->RegisterNatives(c.get(), gMethods, numMethods) < 0) {
        char* msg;
        (void)asprintf(&msg, "RegisterNatives failed for '%s'; aborting...", className);
        env->FatalError(msg);
    }
}

int jniGetFDFromFileDescriptor(JNIEnv* env, jobject fileDescriptor) {
    ScopedLocalRef<jclass> localClass(env, env->FindClass("java/io/FileDescriptor"));
#if defined(ANDROID) && !defined(CONSCRYPT_OPENJDK)
    static jfieldID fid = env->GetFieldID(localClass.get(), "descriptor", "I");
#else /* !ANDROID || CONSCRYPT_OPENJDK */
    static jfieldID fid = env->GetFieldID(localClass.get(), "fd", "I");
#endif
    if (fileDescriptor != nullptr) {
        return env->GetIntField(fileDescriptor, fid);
    } else {
        return -1;
    }
}

bool isGetByteArrayElementsLikelyToReturnACopy(size_t size) {
#if defined(ANDROID) && !defined(CONSCRYPT_OPENJDK)
    // ART's GetByteArrayElements creates copies only for arrays smaller than 12 kB.
    return size <= 12 * 1024;
#else
    (void)size;
    // On OpenJDK based VMs GetByteArrayElements appears to always create a copy.
    return true;
#endif
}

int throwException(JNIEnv* env, const char* className, const char* msg) {
    jclass exceptionClass = env->FindClass(className);

    if (exceptionClass == nullptr) {
        CONSCRYPT_LOG_ERROR("Unable to find exception class %s", className);
        /* ClassNotFoundException now pending */
        return -1;
    }

    if (env->ThrowNew(exceptionClass, msg) != JNI_OK) {
        CONSCRYPT_LOG_ERROR("Failed throwing '%s' '%s'", className, msg);
        /* an exception, most likely OOM, will now be pending */
        return -1;
    }

    env->DeleteLocalRef(exceptionClass);
    return 0;
}

int throwRuntimeException(JNIEnv* env, const char* msg) {
    return conscrypt::jniutil::throwException(env, "java/lang/RuntimeException", msg);
}

int throwAssertionError(JNIEnv* env, const char* msg) {
    return conscrypt::jniutil::throwException(env, "java/lang/AssertionError", msg);
}

int throwNullPointerException(JNIEnv* env, const char* msg) {
    return conscrypt::jniutil::throwException(env, "java/lang/NullPointerException", msg);
}

int throwOutOfMemory(JNIEnv* env, const char* message) {
    return conscrypt::jniutil::throwException(env, "java/lang/OutOfMemoryError", message);
}

int throwBadPaddingException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwBadPaddingException %s", message);
    return conscrypt::jniutil::throwException(env, "javax/crypto/BadPaddingException", message);
}

int throwSignatureException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwSignatureException %s", message);
    return conscrypt::jniutil::throwException(env, "java/security/SignatureException", message);
}

int throwInvalidKeyException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwInvalidKeyException %s", message);
    return conscrypt::jniutil::throwException(env, "java/security/InvalidKeyException", message);
}

int throwIllegalBlockSizeException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwIllegalBlockSizeException %s", message);
    return conscrypt::jniutil::throwException(
            env, "javax/crypto/IllegalBlockSizeException", message);
}

int throwShortBufferException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwShortBufferException %s", message);
    return conscrypt::jniutil::throwException(
            env, "javax/crypto/ShortBufferException", message);
}

int throwNoSuchAlgorithmException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwUnknownAlgorithmException %s", message);
    return conscrypt::jniutil::throwException(
            env, "java/security/NoSuchAlgorithmException", message);
}

int throwIOException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwIOException %s", message);
    return conscrypt::jniutil::throwException(env, "java/io/IOException", message);
}

int throwCertificateException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwCertificateException %s", message);
    return conscrypt::jniutil::throwException(
            env, "java/security/cert/CertificateException", message);
}

int throwParsingException(JNIEnv* env, const char* message) {
    return conscrypt::jniutil::throwException(env, TO_STRING(JNI_JARJAR_PREFIX)
                            "org/conscrypt/OpenSSLX509CertificateFactory$ParsingException",
                            message);
}

int throwInvalidAlgorithmParameterException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwInvalidAlgorithmParameterException %s", message);
    return conscrypt::jniutil::throwException(
            env, "java/security/InvalidAlgorithmParameterException", message);
}

int throwForAsn1Error(JNIEnv* env, int reason, const char* message,
                      int (*defaultThrow)(JNIEnv*, const char*)) {
    switch (reason) {
        case ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE:
        case ASN1_R_WRONG_PUBLIC_KEY_TYPE:
            return throwInvalidKeyException(env, message);
            break;
        case ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM:
        case ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM:
            return throwNoSuchAlgorithmException(env, message);
            break;
    }
    return defaultThrow(env, message);
}

int throwForCipherError(JNIEnv* env, int reason, const char* message,
                        int (*defaultThrow)(JNIEnv*, const char*)) {
    switch (reason) {
        case CIPHER_R_BAD_DECRYPT:
            return throwBadPaddingException(env, message);
            break;
        case CIPHER_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH:
        case CIPHER_R_WRONG_FINAL_BLOCK_LENGTH:
            return throwIllegalBlockSizeException(env, message);
            break;
        // TODO(davidben): Remove these ifdefs after
        // https://boringssl-review.googlesource.com/c/boringssl/+/35565 has
        // rolled out to relevant BoringSSL copies.
#if defined(CIPHER_R_BAD_KEY_LENGTH)
        case CIPHER_R_BAD_KEY_LENGTH:
#endif
#if defined(CIPHER_R_UNSUPPORTED_KEY_SIZE)
        case CIPHER_R_UNSUPPORTED_KEY_SIZE:
#endif
        case CIPHER_R_INVALID_KEY_LENGTH:
            return throwInvalidKeyException(env, message);
            break;
        case CIPHER_R_BUFFER_TOO_SMALL:
            return throwShortBufferException(env, message);
            break;
    }
    return defaultThrow(env, message);
}

int throwForEvpError(JNIEnv* env, int reason, const char* message,
                     int (*defaultThrow)(JNIEnv*, const char*)) {
    switch (reason) {
        case EVP_R_MISSING_PARAMETERS:
            return throwInvalidKeyException(env, message);
            break;
        case EVP_R_UNSUPPORTED_ALGORITHM:
            return throwNoSuchAlgorithmException(env, message);
            break;
        default:
            return defaultThrow(env, message);
            break;
    }
}

int throwForRsaError(JNIEnv* env, int reason, const char* message,
                     int (*defaultThrow)(JNIEnv*, const char*)) {
    switch (reason) {
        case RSA_R_BLOCK_TYPE_IS_NOT_01:
        case RSA_R_PKCS_DECODING_ERROR:
            return throwBadPaddingException(env, message);
            break;
        case RSA_R_BAD_SIGNATURE:
        case RSA_R_INVALID_MESSAGE_LENGTH:
        case RSA_R_WRONG_SIGNATURE_LENGTH:
            return throwSignatureException(env, message);
            break;
        case RSA_R_UNKNOWN_ALGORITHM_TYPE:
            return throwNoSuchAlgorithmException(env, message);
            break;
        case RSA_R_MODULUS_TOO_LARGE:
        case RSA_R_NO_PUBLIC_EXPONENT:
            return throwInvalidKeyException(env, message);
            break;
        case RSA_R_DATA_TOO_LARGE:
        case RSA_R_DATA_TOO_LARGE_FOR_MODULUS:
        case RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE:
            return throwIllegalBlockSizeException(env, message);
            break;
    }
    return defaultThrow(env, message);
}

int throwForX509Error(JNIEnv* env, int reason, const char* message,
                      int (*defaultThrow)(JNIEnv*, const char*)) {
    switch (reason) {
        case X509_R_UNSUPPORTED_ALGORITHM:
            return throwNoSuchAlgorithmException(env, message);
            break;
        default:
            return defaultThrow(env, message);
            break;
    }
}

void throwExceptionFromBoringSSLError(JNIEnv* env, CONSCRYPT_UNUSED const char* location,
                                      int (*defaultThrow)(JNIEnv*, const char*)) {
    const char* file;
    int line;
    const char* data;
    int flags;
    // NOLINTNEXTLINE(runtime/int)
    unsigned long error = ERR_get_error_line_data(&file, &line, &data, &flags);

    if (error == 0) {
        defaultThrow(env, "Unknown BoringSSL error");
        return;
    }

    // If there's an error from BoringSSL it may have been caused by an exception in Java code, so
    // ensure there isn't a pending exception before we throw a new one.
    if (!env->ExceptionCheck()) {
        char message[256];
        ERR_error_string_n(error, message, sizeof(message));
        int library = ERR_GET_LIB(error);
        int reason = ERR_GET_REASON(error);
        JNI_TRACE("BoringSSL error in %s error=%lx library=%x reason=%x (%s:%d): %s %s", location,
                  error, library, reason, file, line, message,
                  (flags & ERR_TXT_STRING) ? data : "(no data)");
        switch (library) {
            case ERR_LIB_RSA:
                throwForRsaError(env, reason, message, defaultThrow);
                break;
            case ERR_LIB_ASN1:
                throwForAsn1Error(env, reason, message, defaultThrow);
                break;
            case ERR_LIB_CIPHER:
                throwForCipherError(env, reason, message, defaultThrow);
                break;
            case ERR_LIB_EVP:
                throwForEvpError(env, reason, message, defaultThrow);
                break;
            case ERR_LIB_X509:
                throwForX509Error(env, reason, message, defaultThrow);
                break;
            case ERR_LIB_DSA:
                throwInvalidKeyException(env, message);
                break;
            default:
                defaultThrow(env, message);
                break;
        }
    }

    ERR_clear_error();
}

int throwSocketTimeoutException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwSocketTimeoutException %s", message);
    return conscrypt::jniutil::throwException(env, "java/net/SocketTimeoutException", message);
}

int throwSSLHandshakeExceptionStr(JNIEnv* env, const char* message) {
    JNI_TRACE("throwSSLExceptionStr %s", message);
    return conscrypt::jniutil::throwException(
            env, "javax/net/ssl/SSLHandshakeException", message);
}

int throwSSLExceptionStr(JNIEnv* env, const char* message) {
    JNI_TRACE("throwSSLExceptionStr %s", message);
    return conscrypt::jniutil::throwException(env, "javax/net/ssl/SSLException", message);
}

int throwSSLProtocolExceptionStr(JNIEnv* env, const char* message) {
    JNI_TRACE("throwSSLProtocolExceptionStr %s", message);
    return conscrypt::jniutil::throwException(
            env, "javax/net/ssl/SSLProtocolException", message);
}

int throwSSLExceptionWithSslErrors(JNIEnv* env, SSL* ssl, int sslErrorCode, const char* message,
                                   int (*actualThrow)(JNIEnv*, const char*)) {
    if (message == nullptr) {
        message = "SSL error";
    }

    // First consult the SSL error code for the general message.
    const char* sslErrorStr = nullptr;
    switch (sslErrorCode) {
        case SSL_ERROR_NONE:
            if (ERR_peek_error() == 0) {
                sslErrorStr = "OK";
            } else {
                sslErrorStr = "";
            }
            break;
        case SSL_ERROR_SSL:
            sslErrorStr = "Failure in SSL library, usually a protocol error";
            break;
        case SSL_ERROR_WANT_READ:
            sslErrorStr = "SSL_ERROR_WANT_READ occurred. You should never see this.";
            break;
        case SSL_ERROR_WANT_WRITE:
            sslErrorStr = "SSL_ERROR_WANT_WRITE occurred. You should never see this.";
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            sslErrorStr = "SSL_ERROR_WANT_X509_LOOKUP occurred. You should never see this.";
            break;
        case SSL_ERROR_SYSCALL:
            sslErrorStr = "I/O error during system call";
            break;
        case SSL_ERROR_ZERO_RETURN:
            sslErrorStr = "SSL_ERROR_ZERO_RETURN occurred. You should never see this.";
            break;
        case SSL_ERROR_WANT_CONNECT:
            sslErrorStr = "SSL_ERROR_WANT_CONNECT occurred. You should never see this.";
            break;
        case SSL_ERROR_WANT_ACCEPT:
            sslErrorStr = "SSL_ERROR_WANT_ACCEPT occurred. You should never see this.";
            break;
        default:
            sslErrorStr = "Unknown SSL error";
    }

    // Prepend either our explicit message or a default one.
    char* str;
    if (asprintf(&str, "%s: ssl=%p: %s", message, ssl, sslErrorStr) <= 0) {
        // problem with asprintf, just throw argument message, log everything
        int ret = actualThrow(env, message);
        CONSCRYPT_LOG_VERBOSE("%s: ssl=%p: %s", message, ssl, sslErrorStr);
        ERR_clear_error();
        return ret;
    }

    char* allocStr = str;

    // For protocol errors, SSL might have more information.
    if (sslErrorCode == SSL_ERROR_NONE || sslErrorCode == SSL_ERROR_SSL) {
        // Append each error as an additional line to the message.
        for (;;) {
            char errStr[256];
            const char* file;
            int line;
            const char* data;
            int flags;
            // NOLINTNEXTLINE(runtime/int)
            unsigned long err = ERR_get_error_line_data(&file, &line, &data, &flags);
            if (err == 0) {
                break;
            }

            ERR_error_string_n(err, errStr, sizeof(errStr));

            int ret = asprintf(&str, "%s\n%s (%s:%d %p:0x%08x)",
                               (allocStr == nullptr) ? "" : allocStr, errStr, file, line,
                               (flags & ERR_TXT_STRING) ? data : "(no data)", flags);

            if (ret < 0) {
                break;
            }

            free(allocStr);
            allocStr = str;
        }
        // For errors during system calls, errno might be our friend.
    } else if (sslErrorCode == SSL_ERROR_SYSCALL) {
        if (asprintf(&str, "%s, %s", allocStr, strerror(errno)) >= 0) {
            free(allocStr);
            allocStr = str;
        }
        // If the error code is invalid, print it.
    } else if (sslErrorCode > SSL_ERROR_WANT_ACCEPT) {
        if (asprintf(&str, ", error code is %d", sslErrorCode) >= 0) {
            free(allocStr);
            allocStr = str;
        }
    }

    int ret;
    if (sslErrorCode == SSL_ERROR_SSL) {
        ret = throwSSLProtocolExceptionStr(env, allocStr);
    } else {
        ret = actualThrow(env, allocStr);
    }

    CONSCRYPT_LOG_VERBOSE("%s", allocStr);
    free(allocStr);
    ERR_clear_error();
    return ret;
}

}  // namespace jniutil
}  // namespace conscrypt
