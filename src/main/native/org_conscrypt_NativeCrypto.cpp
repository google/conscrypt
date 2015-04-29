/*
 * Copyright (C) 2007-2008 The Android Open Source Project
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

/**
 * Native glue for Java class org.conscrypt.NativeCrypto
 */

#define TO_STRING1(x) #x
#define TO_STRING(x) TO_STRING1(x)
#ifndef JNI_JARJAR_PREFIX
    #ifndef CONSCRYPT_NOT_UNBUNDLED
        #define CONSCRYPT_UNBUNDLED
    #endif
    #define JNI_JARJAR_PREFIX
#endif

#define LOG_TAG "NativeCrypto"

#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef CONSCRYPT_UNBUNDLED
#include <dlfcn.h>
#endif

#include <jni.h>

#include <openssl/asn1t.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if !defined(OPENSSL_IS_BORINGSSL)
#include "crypto/ecdsa/ecs_locl.h"
#endif

#ifndef CONSCRYPT_UNBUNDLED
/* If we're compiled unbundled from Android system image, we use the
 * CompatibilityCloseMonitor
 */
#include "AsynchronousCloseMonitor.h"
#endif

#ifndef CONSCRYPT_UNBUNDLED
#include "cutils/log.h"
#else
#include <android/log.h>
#include "log_compat.h"
#endif

#ifndef CONSCRYPT_UNBUNDLED
#include "JNIHelp.h"
#include "JniConstants.h"
#include "JniException.h"
#else
#define NATIVE_METHOD(className, functionName, signature) \
  { #functionName, signature, reinterpret_cast<void*>(className ## _ ## functionName) }
#define REGISTER_NATIVE_METHODS(jni_class_name) \
  RegisterNativeMethods(env, jni_class_name, gMethods, arraysize(gMethods))
#endif

#include "ScopedLocalRef.h"
#include "ScopedPrimitiveArray.h"
#include "ScopedUtfChars.h"
#include "UniquePtr.h"
#include "NetFd.h"

#include "macros.h"

#undef WITH_JNI_TRACE
#undef WITH_JNI_TRACE_MD
#undef WITH_JNI_TRACE_DATA

/*
 * How to use this for debugging with Wireshark:
 *
 * 1. Pull lines from logcat to a file that looks like (without quotes):
 *     "RSA Session-ID:... Master-Key:..." <CR>
 *     "RSA Session-ID:... Master-Key:..." <CR>
 *     <etc>
 * 2. Start Wireshark
 * 3. Go to Edit -> Preferences -> SSL -> (Pre-)Master-Key log and fill in
 *    the file you put the lines in above.
 * 4. Follow the stream that corresponds to the desired "Session-ID" in
 *    the Server Hello.
 */
#undef WITH_JNI_TRACE_KEYS

#ifdef WITH_JNI_TRACE
#define JNI_TRACE(...) \
        ((void)ALOG(LOG_INFO, LOG_TAG "-jni", __VA_ARGS__))
#else
#define JNI_TRACE(...) ((void)0)
#endif
#ifdef WITH_JNI_TRACE_MD
#define JNI_TRACE_MD(...) \
        ((void)ALOG(LOG_INFO, LOG_TAG "-jni", __VA_ARGS__));
#else
#define JNI_TRACE_MD(...) ((void)0)
#endif
// don't overwhelm logcat
#define WITH_JNI_TRACE_DATA_CHUNK_SIZE 512

static JavaVM* gJavaVM;
static jclass cryptoUpcallsClass;
static jclass openSslInputStreamClass;
static jclass nativeRefClass;

static jclass byteArrayClass;
static jclass calendarClass;
static jclass objectClass;
static jclass objectArrayClass;
static jclass integerClass;
static jclass inputStreamClass;
static jclass outputStreamClass;
static jclass stringClass;

static jfieldID nativeRef_context;

static jmethodID calendar_setMethod;
static jmethodID inputStream_readMethod;
static jmethodID integer_valueOfMethod;
static jmethodID openSslInputStream_readLineMethod;
static jmethodID outputStream_writeMethod;
static jmethodID outputStream_flushMethod;

struct OPENSSL_Delete {
    void operator()(void* p) const {
        OPENSSL_free(p);
    }
};
typedef UniquePtr<unsigned char, OPENSSL_Delete> Unique_OPENSSL_str;

struct BIO_Delete {
    void operator()(BIO* p) const {
        BIO_free_all(p);
    }
};
typedef UniquePtr<BIO, BIO_Delete> Unique_BIO;

struct BIGNUM_Delete {
    void operator()(BIGNUM* p) const {
        BN_free(p);
    }
};
typedef UniquePtr<BIGNUM, BIGNUM_Delete> Unique_BIGNUM;

struct ASN1_INTEGER_Delete {
    void operator()(ASN1_INTEGER* p) const {
        ASN1_INTEGER_free(p);
    }
};
typedef UniquePtr<ASN1_INTEGER, ASN1_INTEGER_Delete> Unique_ASN1_INTEGER;

struct DH_Delete {
    void operator()(DH* p) const {
        DH_free(p);
    }
};
typedef UniquePtr<DH, DH_Delete> Unique_DH;

struct DSA_Delete {
    void operator()(DSA* p) const {
        DSA_free(p);
    }
};
typedef UniquePtr<DSA, DSA_Delete> Unique_DSA;

struct EC_GROUP_Delete {
    void operator()(EC_GROUP* p) const {
        EC_GROUP_free(p);
    }
};
typedef UniquePtr<EC_GROUP, EC_GROUP_Delete> Unique_EC_GROUP;

struct EC_POINT_Delete {
    void operator()(EC_POINT* p) const {
        EC_POINT_clear_free(p);
    }
};
typedef UniquePtr<EC_POINT, EC_POINT_Delete> Unique_EC_POINT;

struct EC_KEY_Delete {
    void operator()(EC_KEY* p) const {
        EC_KEY_free(p);
    }
};
typedef UniquePtr<EC_KEY, EC_KEY_Delete> Unique_EC_KEY;

struct EVP_MD_CTX_Delete {
    void operator()(EVP_MD_CTX* p) const {
        EVP_MD_CTX_destroy(p);
    }
};
typedef UniquePtr<EVP_MD_CTX, EVP_MD_CTX_Delete> Unique_EVP_MD_CTX;

struct EVP_CIPHER_CTX_Delete {
    void operator()(EVP_CIPHER_CTX* p) const {
        EVP_CIPHER_CTX_free(p);
    }
};
typedef UniquePtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Delete> Unique_EVP_CIPHER_CTX;

struct EVP_PKEY_Delete {
    void operator()(EVP_PKEY* p) const {
        EVP_PKEY_free(p);
    }
};
typedef UniquePtr<EVP_PKEY, EVP_PKEY_Delete> Unique_EVP_PKEY;

struct PKCS8_PRIV_KEY_INFO_Delete {
    void operator()(PKCS8_PRIV_KEY_INFO* p) const {
        PKCS8_PRIV_KEY_INFO_free(p);
    }
};
typedef UniquePtr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_Delete> Unique_PKCS8_PRIV_KEY_INFO;

struct RSA_Delete {
    void operator()(RSA* p) const {
        RSA_free(p);
    }
};
typedef UniquePtr<RSA, RSA_Delete> Unique_RSA;

struct ASN1_BIT_STRING_Delete {
    void operator()(ASN1_BIT_STRING* p) const {
        ASN1_BIT_STRING_free(p);
    }
};
typedef UniquePtr<ASN1_BIT_STRING, ASN1_BIT_STRING_Delete> Unique_ASN1_BIT_STRING;

struct ASN1_OBJECT_Delete {
    void operator()(ASN1_OBJECT* p) const {
        ASN1_OBJECT_free(p);
    }
};
typedef UniquePtr<ASN1_OBJECT, ASN1_OBJECT_Delete> Unique_ASN1_OBJECT;

struct ASN1_GENERALIZEDTIME_Delete {
    void operator()(ASN1_GENERALIZEDTIME* p) const {
        ASN1_GENERALIZEDTIME_free(p);
    }
};
typedef UniquePtr<ASN1_GENERALIZEDTIME, ASN1_GENERALIZEDTIME_Delete> Unique_ASN1_GENERALIZEDTIME;

struct SSL_Delete {
    void operator()(SSL* p) const {
        SSL_free(p);
    }
};
typedef UniquePtr<SSL, SSL_Delete> Unique_SSL;

struct SSL_CTX_Delete {
    void operator()(SSL_CTX* p) const {
        SSL_CTX_free(p);
    }
};
typedef UniquePtr<SSL_CTX, SSL_CTX_Delete> Unique_SSL_CTX;

struct X509_Delete {
    void operator()(X509* p) const {
        X509_free(p);
    }
};
typedef UniquePtr<X509, X509_Delete> Unique_X509;

struct X509_NAME_Delete {
    void operator()(X509_NAME* p) const {
        X509_NAME_free(p);
    }
};
typedef UniquePtr<X509_NAME, X509_NAME_Delete> Unique_X509_NAME;

#if !defined(OPENSSL_IS_BORINGSSL)
struct PKCS7_Delete {
    void operator()(PKCS7* p) const {
        PKCS7_free(p);
    }
};
typedef UniquePtr<PKCS7, PKCS7_Delete> Unique_PKCS7;
#endif

struct sk_SSL_CIPHER_Delete {
    void operator()(STACK_OF(SSL_CIPHER)* p) const {
        // We don't own SSL_CIPHER references, so no need for pop_free
        sk_SSL_CIPHER_free(p);
    }
};
typedef UniquePtr<STACK_OF(SSL_CIPHER), sk_SSL_CIPHER_Delete> Unique_sk_SSL_CIPHER;

struct sk_X509_Delete {
    void operator()(STACK_OF(X509)* p) const {
        sk_X509_pop_free(p, X509_free);
    }
};
typedef UniquePtr<STACK_OF(X509), sk_X509_Delete> Unique_sk_X509;

#if defined(OPENSSL_IS_BORINGSSL)
struct sk_X509_CRL_Delete {
    void operator()(STACK_OF(X509_CRL)* p) const {
        sk_X509_CRL_pop_free(p, X509_CRL_free);
    }
};
typedef UniquePtr<STACK_OF(X509_CRL), sk_X509_CRL_Delete> Unique_sk_X509_CRL;
#endif

struct sk_X509_NAME_Delete {
    void operator()(STACK_OF(X509_NAME)* p) const {
        sk_X509_NAME_pop_free(p, X509_NAME_free);
    }
};
typedef UniquePtr<STACK_OF(X509_NAME), sk_X509_NAME_Delete> Unique_sk_X509_NAME;

struct sk_ASN1_OBJECT_Delete {
    void operator()(STACK_OF(ASN1_OBJECT)* p) const {
        sk_ASN1_OBJECT_pop_free(p, ASN1_OBJECT_free);
    }
};
typedef UniquePtr<STACK_OF(ASN1_OBJECT), sk_ASN1_OBJECT_Delete> Unique_sk_ASN1_OBJECT;

struct sk_GENERAL_NAME_Delete {
    void operator()(STACK_OF(GENERAL_NAME)* p) const {
        sk_GENERAL_NAME_pop_free(p, GENERAL_NAME_free);
    }
};
typedef UniquePtr<STACK_OF(GENERAL_NAME), sk_GENERAL_NAME_Delete> Unique_sk_GENERAL_NAME;

/**
 * Many OpenSSL APIs take ownership of an argument on success but don't free the argument
 * on failure. This means we need to tell our scoped pointers when we've transferred ownership,
 * without triggering a warning by not using the result of release().
 */
#define OWNERSHIP_TRANSFERRED(obj) \
    do { typeof (obj.release()) _dummy __attribute__((unused)) = obj.release(); } while(0)

/**
 * UNUSED_ARGUMENT can be used to mark an, otherwise unused, argument as "used"
 * for the purposes of -Werror=unused-parameter. This can be needed when an
 * argument's use is based on an #ifdef.
 */
#define UNUSED_ARGUMENT(x) ((void)(x));

/**
 * Frees the SSL error state.
 *
 * OpenSSL keeps an "error stack" per thread, and given that this code
 * can be called from arbitrary threads that we don't keep track of,
 * we err on the side of freeing the error state promptly (instead of,
 * say, at thread death).
 */
static void freeOpenSslErrorState(void) {
    ERR_clear_error();
    ERR_remove_thread_state(NULL);
}

/**
 * Manages the freeing of the OpenSSL error stack. This allows you to
 * instantiate this object during an SSL call that may fail and not worry
 * about manually calling freeOpenSslErrorState() later.
 *
 * As an optimization, you can also call .release() for passing as an
 * argument to things that free the error stack state as a side-effect.
 */
class OpenSslError {
public:
    OpenSslError() : sslError_(SSL_ERROR_NONE), released_(false) {
    }

    OpenSslError(SSL* ssl, int returnCode) : sslError_(SSL_ERROR_NONE), released_(false) {
        reset(ssl, returnCode);
    }

    ~OpenSslError() {
        if (!released_ && sslError_ != SSL_ERROR_NONE) {
            freeOpenSslErrorState();
        }
    }

    int get() const {
        return sslError_;
    }

    void reset(SSL* ssl, int returnCode) {
        if (returnCode <= 0) {
            sslError_ = SSL_get_error(ssl, returnCode);
        } else {
            sslError_ = SSL_ERROR_NONE;
        }
    }

    int release() {
        released_ = true;
        return sslError_;
    }

private:
    int sslError_;
    bool released_;
};

/**
 * Throws a OutOfMemoryError with the given string as a message.
 */
static int jniThrowOutOfMemory(JNIEnv* env, const char* message) {
    return jniThrowException(env, "java/lang/OutOfMemoryError", message);
}

/**
 * Throws a BadPaddingException with the given string as a message.
 */
static int throwBadPaddingException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwBadPaddingException %s", message);
    return jniThrowException(env, "javax/crypto/BadPaddingException", message);
}

/**
 * Throws a SignatureException with the given string as a message.
 */
static int throwSignatureException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwSignatureException %s", message);
    return jniThrowException(env, "java/security/SignatureException", message);
}

/**
 * Throws a InvalidKeyException with the given string as a message.
 */
static int throwInvalidKeyException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwInvalidKeyException %s", message);
    return jniThrowException(env, "java/security/InvalidKeyException", message);
}

/**
 * Throws a SignatureException with the given string as a message.
 */
static int throwIllegalBlockSizeException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwIllegalBlockSizeException %s", message);
    return jniThrowException(env, "javax/crypto/IllegalBlockSizeException", message);
}

/**
 * Throws a NoSuchAlgorithmException with the given string as a message.
 */
static int throwNoSuchAlgorithmException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwUnknownAlgorithmException %s", message);
    return jniThrowException(env, "java/security/NoSuchAlgorithmException", message);
}

static int throwForAsn1Error(JNIEnv* env, int reason, const char *message,
                             int (*defaultThrow)(JNIEnv*, const char*)) {
    switch (reason) {
    case ASN1_R_UNABLE_TO_DECODE_RSA_KEY:
    case ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY:
    case ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE:
    case ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE:
    // These #if sections can be removed once BoringSSL is landed.
#if defined(ASN1_R_WRONG_PUBLIC_KEY_TYPE)
    case ASN1_R_WRONG_PUBLIC_KEY_TYPE:
#endif
        return throwInvalidKeyException(env, message);
        break;
#if defined(ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM)
    case ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM:
        return throwNoSuchAlgorithmException(env, message);
        break;
#endif
    }
    return defaultThrow(env, message);
}

#if defined(OPENSSL_IS_BORINGSSL)
static int throwForCipherError(JNIEnv* env, int reason, const char *message,
                               int (*defaultThrow)(JNIEnv*, const char*)) {
    switch (reason) {
    case CIPHER_R_BAD_DECRYPT:
        return throwBadPaddingException(env, message);
        break;
    case CIPHER_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH:
    case CIPHER_R_WRONG_FINAL_BLOCK_LENGTH:
        return throwIllegalBlockSizeException(env, message);
        break;
    case CIPHER_R_AES_KEY_SETUP_FAILED:
    case CIPHER_R_BAD_KEY_LENGTH:
    case CIPHER_R_UNSUPPORTED_KEY_SIZE:
        return throwInvalidKeyException(env, message);
        break;
    }
    return defaultThrow(env, message);
}

static int throwForEvpError(JNIEnv* env, int reason, const char *message,
                            int (*defaultThrow)(JNIEnv*, const char*)) {
    switch (reason) {
    case EVP_R_MISSING_PARAMETERS:
        return throwInvalidKeyException(env, message);
        break;
    case EVP_R_UNSUPPORTED_ALGORITHM:
    case EVP_R_X931_UNSUPPORTED:
        return throwNoSuchAlgorithmException(env, message);
        break;
    // These #if sections can be make unconditional once BoringSSL is landed.
#if defined(EVP_R_WRONG_PUBLIC_KEY_TYPE)
    case EVP_R_WRONG_PUBLIC_KEY_TYPE:
        return throwInvalidKeyException(env, message);
        break;
#endif
#if defined(EVP_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM)
    case EVP_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM:
        return throwNoSuchAlgorithmException(env, message);
        break;
#endif
    default:
        return defaultThrow(env, message);
        break;
    }
}
#else
static int throwForEvpError(JNIEnv* env, int reason, const char *message,
                            int (*defaultThrow)(JNIEnv*, const char*)) {
    switch (reason) {
    case EVP_R_BAD_DECRYPT:
        return throwBadPaddingException(env, message);
        break;
    case EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH:
    case EVP_R_WRONG_FINAL_BLOCK_LENGTH:
        return throwIllegalBlockSizeException(env, message);
        break;
    case EVP_R_BAD_KEY_LENGTH:
    case EVP_R_BN_DECODE_ERROR:
    case EVP_R_BN_PUBKEY_ERROR:
    case EVP_R_INVALID_KEY_LENGTH:
    case EVP_R_MISSING_PARAMETERS:
    case EVP_R_UNSUPPORTED_KEY_SIZE:
    case EVP_R_UNSUPPORTED_KEYLENGTH:
        return throwInvalidKeyException(env, message);
        break;
    case EVP_R_WRONG_PUBLIC_KEY_TYPE:
        return throwSignatureException(env, message);
        break;
    case EVP_R_UNSUPPORTED_ALGORITHM:
        return throwNoSuchAlgorithmException(env, message);
        break;
    default:
        return defaultThrow(env, message);
        break;
    }
}
#endif

static int throwForRsaError(JNIEnv* env, int reason, const char *message,
                            int (*defaultThrow)(JNIEnv*, const char*)) {
    switch (reason) {
    case RSA_R_BLOCK_TYPE_IS_NOT_01:
    case RSA_R_BLOCK_TYPE_IS_NOT_02:
    case RSA_R_PKCS_DECODING_ERROR:
        return throwBadPaddingException(env, message);
        break;
    case RSA_R_BAD_SIGNATURE:
    case RSA_R_DATA_TOO_LARGE_FOR_MODULUS:
    case RSA_R_INVALID_MESSAGE_LENGTH:
    case RSA_R_WRONG_SIGNATURE_LENGTH:
#if !defined(OPENSSL_IS_BORINGSSL)
    case RSA_R_ALGORITHM_MISMATCH:
    case RSA_R_DATA_GREATER_THAN_MOD_LEN:
#endif
        return throwSignatureException(env, message);
        break;
    case RSA_R_UNKNOWN_ALGORITHM_TYPE:
        return throwNoSuchAlgorithmException(env, message);
        break;
    case RSA_R_MODULUS_TOO_LARGE:
    case RSA_R_NO_PUBLIC_EXPONENT:
        return throwInvalidKeyException(env, message);
        break;
    }
    return defaultThrow(env, message);
}

static int throwForX509Error(JNIEnv* env, int reason, const char *message,
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

/*
 * Checks this thread's OpenSSL error queue and throws a RuntimeException if
 * necessary.
 *
 * @return true if an exception was thrown, false if not.
 */
static bool throwExceptionIfNecessary(JNIEnv* env, const char* location  __attribute__ ((unused)),
        int (*defaultThrow)(JNIEnv*, const char*) = jniThrowRuntimeException) {
    const char* file;
    int line;
    const char* data;
    int flags;
    unsigned long error = ERR_get_error_line_data(&file, &line, &data, &flags);
    int result = false;

    if (error != 0) {
        char message[256];
        ERR_error_string_n(error, message, sizeof(message));
        int library = ERR_GET_LIB(error);
        int reason = ERR_GET_REASON(error);
        JNI_TRACE("OpenSSL error in %s error=%lx library=%x reason=%x (%s:%d): %s %s",
                  location, error, library, reason, file, line, message,
                  (flags & ERR_TXT_STRING) ? data : "(no data)");
        switch (library) {
        case ERR_LIB_RSA:
            throwForRsaError(env, reason, message, defaultThrow);
            break;
        case ERR_LIB_ASN1:
            throwForAsn1Error(env, reason, message, defaultThrow);
            break;
#if defined(OPENSSL_IS_BORINGSSL)
        case ERR_LIB_CIPHER:
            throwForCipherError(env, reason, message, defaultThrow);
            break;
#endif
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
        result = true;
    }

    freeOpenSslErrorState();
    return result;
}

/**
 * Throws an SocketTimeoutException with the given string as a message.
 */
static int throwSocketTimeoutException(JNIEnv* env, const char* message) {
    JNI_TRACE("throwSocketTimeoutException %s", message);
    return jniThrowException(env, "java/net/SocketTimeoutException", message);
}

/**
 * Throws a javax.net.ssl.SSLException with the given string as a message.
 */
static int throwSSLHandshakeExceptionStr(JNIEnv* env, const char* message) {
    JNI_TRACE("throwSSLExceptionStr %s", message);
    return jniThrowException(env, "javax/net/ssl/SSLHandshakeException", message);
}

/**
 * Throws a javax.net.ssl.SSLException with the given string as a message.
 */
static int throwSSLExceptionStr(JNIEnv* env, const char* message) {
    JNI_TRACE("throwSSLExceptionStr %s", message);
    return jniThrowException(env, "javax/net/ssl/SSLException", message);
}

/**
 * Throws a javax.net.ssl.SSLProcotolException with the given string as a message.
 */
static int throwSSLProtocolExceptionStr(JNIEnv* env, const char* message) {
    JNI_TRACE("throwSSLProtocolExceptionStr %s", message);
    return jniThrowException(env, "javax/net/ssl/SSLProtocolException", message);
}

/**
 * Throws an SSLException with a message constructed from the current
 * SSL errors. This will also log the errors.
 *
 * @param env the JNI environment
 * @param ssl the possibly NULL SSL
 * @param sslErrorCode error code returned from SSL_get_error() or
 * SSL_ERROR_NONE to probe with ERR_get_error
 * @param message null-ok; general error message
 */
static int throwSSLExceptionWithSslErrors(JNIEnv* env, SSL* ssl, int sslErrorCode,
        const char* message, int (*actualThrow)(JNIEnv*, const char*) = throwSSLExceptionStr) {

    if (message == NULL) {
        message = "SSL error";
    }

    // First consult the SSL error code for the general message.
    const char* sslErrorStr = NULL;
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
        ALOGV("%s: ssl=%p: %s", message, ssl, sslErrorStr);
        freeOpenSslErrorState();
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
            unsigned long err = ERR_get_error_line_data(&file, &line, &data, &flags);
            if (err == 0) {
                break;
            }

            ERR_error_string_n(err, errStr, sizeof(errStr));

            int ret = asprintf(&str, "%s\n%s (%s:%d %p:0x%08x)",
                               (allocStr == NULL) ? "" : allocStr,
                               errStr,
                               file,
                               line,
                               (flags & ERR_TXT_STRING) ? data : "(no data)",
                               flags);

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

    ALOGV("%s", allocStr);
    free(allocStr);
    freeOpenSslErrorState();
    return ret;
}

/**
 * Helper function that grabs the casts an ssl pointer and then checks for nullness.
 * If this function returns NULL and <code>throwIfNull</code> is
 * passed as <code>true</code>, then this function will call
 * <code>throwSSLExceptionStr</code> before returning, so in this case of
 * NULL, a caller of this function should simply return and allow JNI
 * to do its thing.
 *
 * @param env the JNI environment
 * @param ssl_address; the ssl_address pointer as an integer
 * @param throwIfNull whether to throw if the SSL pointer is NULL
 * @returns the pointer, which may be NULL
 */
static SSL_CTX* to_SSL_CTX(JNIEnv* env, jlong ssl_ctx_address, bool throwIfNull) {
    SSL_CTX* ssl_ctx = reinterpret_cast<SSL_CTX*>(static_cast<uintptr_t>(ssl_ctx_address));
    if ((ssl_ctx == NULL) && throwIfNull) {
        JNI_TRACE("ssl_ctx == null");
        jniThrowNullPointerException(env, "ssl_ctx == null");
    }
    return ssl_ctx;
}

static SSL* to_SSL(JNIEnv* env, jlong ssl_address, bool throwIfNull) {
    SSL* ssl = reinterpret_cast<SSL*>(static_cast<uintptr_t>(ssl_address));
    if ((ssl == NULL) && throwIfNull) {
        JNI_TRACE("ssl == null");
        jniThrowNullPointerException(env, "ssl == null");
    }
    return ssl;
}

static SSL_SESSION* to_SSL_SESSION(JNIEnv* env, jlong ssl_session_address, bool throwIfNull) {
    SSL_SESSION* ssl_session
        = reinterpret_cast<SSL_SESSION*>(static_cast<uintptr_t>(ssl_session_address));
    if ((ssl_session == NULL) && throwIfNull) {
        JNI_TRACE("ssl_session == null");
        jniThrowNullPointerException(env, "ssl_session == null");
    }
    return ssl_session;
}

static SSL_CIPHER* to_SSL_CIPHER(JNIEnv* env, jlong ssl_cipher_address, bool throwIfNull) {
    SSL_CIPHER* ssl_cipher
        = reinterpret_cast<SSL_CIPHER*>(static_cast<uintptr_t>(ssl_cipher_address));
    if ((ssl_cipher == NULL) && throwIfNull) {
        JNI_TRACE("ssl_cipher == null");
        jniThrowNullPointerException(env, "ssl_cipher == null");
    }
    return ssl_cipher;
}

template<typename T>
static T* fromContextObject(JNIEnv* env, jobject contextObject) {
    if (contextObject == NULL) {
        JNI_TRACE("contextObject == null");
        jniThrowNullPointerException(env, "contextObject == null");
        return NULL;
    }
    T* ref = reinterpret_cast<T*>(env->GetLongField(contextObject, nativeRef_context));
    if (ref == NULL) {
        JNI_TRACE("ref == null");
        jniThrowNullPointerException(env, "ref == null");
        return NULL;
    }
    return ref;
}

/**
 * Converts a Java byte[] two's complement to an OpenSSL BIGNUM. This will
 * allocate the BIGNUM if *dest == NULL. Returns true on success. If the
 * return value is false, there is a pending exception.
 */
static bool arrayToBignum(JNIEnv* env, jbyteArray source, BIGNUM** dest) {
    JNI_TRACE("arrayToBignum(%p, %p)", source, dest);
    if (dest == NULL) {
        JNI_TRACE("arrayToBignum(%p, %p) => dest is null!", source, dest);
        jniThrowNullPointerException(env, "dest == null");
        return false;
    }
    JNI_TRACE("arrayToBignum(%p, %p) *dest == %p", source, dest, *dest);

    ScopedByteArrayRO sourceBytes(env, source);
    if (sourceBytes.get() == NULL) {
        JNI_TRACE("arrayToBignum(%p, %p) => NULL", source, dest);
        return false;
    }
    const unsigned char* tmp = reinterpret_cast<const unsigned char*>(sourceBytes.get());
    size_t tmpSize = sourceBytes.size();

    /* if the array is empty, it is zero. */
    if (tmpSize == 0) {
        if (*dest == NULL) {
            *dest = BN_new();
        }
        BN_zero(*dest);
        return true;
    }

    UniquePtr<unsigned char[]> twosComplement;
    bool negative = (tmp[0] & 0x80) != 0;
    if (negative) {
        // Need to convert to two's complement.
        twosComplement.reset(new unsigned char[tmpSize]);
        unsigned char* twosBytes = reinterpret_cast<unsigned char*>(twosComplement.get());
        memcpy(twosBytes, tmp, tmpSize);
        tmp = twosBytes;

        bool carry = true;
        for (ssize_t i = tmpSize - 1; i >= 0; i--) {
            twosBytes[i] ^= 0xFF;
            if (carry) {
                carry = (++twosBytes[i]) == 0;
            }
        }
    }
    BIGNUM *ret = BN_bin2bn(tmp, tmpSize, *dest);
    if (ret == NULL) {
        jniThrowRuntimeException(env, "Conversion to BIGNUM failed");
        JNI_TRACE("arrayToBignum(%p, %p) => threw exception", source, dest);
        return false;
    }
    BN_set_negative(ret, negative ? 1 : 0);

    *dest = ret;
    JNI_TRACE("arrayToBignum(%p, %p) => *dest = %p", source, dest, ret);
    return true;
}

#if defined(OPENSSL_IS_BORINGSSL)
/**
 * arrayToBignumSize sets |*out_size| to the size of the big-endian number
 * contained in |source|. It returns true on success and sets an exception and
 * returns false otherwise.
 */
static bool arrayToBignumSize(JNIEnv* env, jbyteArray source, size_t* out_size) {
    JNI_TRACE("arrayToBignumSize(%p, %p)", source, out_size);

    ScopedByteArrayRO sourceBytes(env, source);
    if (sourceBytes.get() == NULL) {
        JNI_TRACE("arrayToBignum(%p, %p) => NULL", source, out_size);
        return false;
    }
    const uint8_t* tmp = reinterpret_cast<const uint8_t*>(sourceBytes.get());
    size_t tmpSize = sourceBytes.size();

    if (tmpSize == 0) {
        *out_size = 0;
        return true;
    }

    if ((tmp[0] & 0x80) != 0) {
        // Negative numbers are invalid.
        jniThrowRuntimeException(env, "Negative number");
        return false;
    }

    while (tmpSize > 0 && tmp[0] == 0) {
        tmp++;
        tmpSize--;
    }

    *out_size = tmpSize;
    return true;
}
#endif

/**
 * Converts an OpenSSL BIGNUM to a Java byte[] array in two's complement.
 */
static jbyteArray bignumToArray(JNIEnv* env, const BIGNUM* source, const char* sourceName) {
    JNI_TRACE("bignumToArray(%p, %s)", source, sourceName);

    if (source == NULL) {
        jniThrowNullPointerException(env, sourceName);
        return NULL;
    }

    size_t numBytes = BN_num_bytes(source) + 1;
    jbyteArray javaBytes = env->NewByteArray(numBytes);
    ScopedByteArrayRW bytes(env, javaBytes);
    if (bytes.get() == NULL) {
        JNI_TRACE("bignumToArray(%p, %s) => NULL", source, sourceName);
        return NULL;
    }

    unsigned char* tmp = reinterpret_cast<unsigned char*>(bytes.get());
    if (BN_num_bytes(source) > 0 && BN_bn2bin(source, tmp + 1) <= 0) {
        throwExceptionIfNecessary(env, "bignumToArray");
        return NULL;
    }

    // Set the sign and convert to two's complement if necessary for the Java code.
    if (BN_is_negative(source)) {
        bool carry = true;
        for (ssize_t i = numBytes - 1; i >= 0; i--) {
            tmp[i] ^= 0xFF;
            if (carry) {
                carry = (++tmp[i]) == 0;
            }
        }
        *tmp |= 0x80;
    } else {
        *tmp = 0x00;
    }

    JNI_TRACE("bignumToArray(%p, %s) => %p", source, sourceName, javaBytes);
    return javaBytes;
}

/**
 * Converts various OpenSSL ASN.1 types to a jbyteArray with DER-encoded data
 * inside. The "i2d_func" function pointer is a function of the "i2d_<TYPE>"
 * from the OpenSSL ASN.1 API.
 */
template<typename T>
jbyteArray ASN1ToByteArray(JNIEnv* env, T* obj, int (*i2d_func)(T*, unsigned char**)) {
    if (obj == NULL) {
        jniThrowNullPointerException(env, "ASN1 input == null");
        JNI_TRACE("ASN1ToByteArray(%p) => null input", obj);
        return NULL;
    }

    int derLen = i2d_func(obj, NULL);
    if (derLen < 0) {
        throwExceptionIfNecessary(env, "ASN1ToByteArray");
        JNI_TRACE("ASN1ToByteArray(%p) => measurement failed", obj);
        return NULL;
    }

    ScopedLocalRef<jbyteArray> byteArray(env, env->NewByteArray(derLen));
    if (byteArray.get() == NULL) {
        JNI_TRACE("ASN1ToByteArray(%p) => creating byte array failed", obj);
        return NULL;
    }

    ScopedByteArrayRW bytes(env, byteArray.get());
    if (bytes.get() == NULL) {
        JNI_TRACE("ASN1ToByteArray(%p) => using byte array failed", obj);
        return NULL;
    }

    unsigned char* p = reinterpret_cast<unsigned char*>(bytes.get());
    int ret = i2d_func(obj, &p);
    if (ret < 0) {
        throwExceptionIfNecessary(env, "ASN1ToByteArray");
        JNI_TRACE("ASN1ToByteArray(%p) => final conversion failed", obj);
        return NULL;
    }

    JNI_TRACE("ASN1ToByteArray(%p) => success (%d bytes written)", obj, ret);
    return byteArray.release();
}

template<typename T, T* (*d2i_func)(T**, const unsigned char**, long)>
T* ByteArrayToASN1(JNIEnv* env, jbyteArray byteArray) {
    ScopedByteArrayRO bytes(env, byteArray);
    if (bytes.get() == NULL) {
        JNI_TRACE("ByteArrayToASN1(%p) => using byte array failed", byteArray);
        return 0;
    }

    const unsigned char* tmp = reinterpret_cast<const unsigned char*>(bytes.get());
    return d2i_func(NULL, &tmp, bytes.size());
}

/**
 * Converts ASN.1 BIT STRING to a jbooleanArray.
 */
jbooleanArray ASN1BitStringToBooleanArray(JNIEnv* env, ASN1_BIT_STRING* bitStr) {
    int size = bitStr->length * 8;
    if (bitStr->flags & ASN1_STRING_FLAG_BITS_LEFT) {
        size -= bitStr->flags & 0x07;
    }

    ScopedLocalRef<jbooleanArray> bitsRef(env, env->NewBooleanArray(size));
    if (bitsRef.get() == NULL) {
        return NULL;
    }

    ScopedBooleanArrayRW bitsArray(env, bitsRef.get());
    for (int i = 0; i < static_cast<int>(bitsArray.size()); i++) {
        bitsArray[i] = ASN1_BIT_STRING_get_bit(bitStr, i);
    }

    return bitsRef.release();
}

/**
 * Safely clear SSL sessions and throw an error if there was something already
 * in the error stack.
 */
static void safeSslClear(SSL* ssl) {
    if (SSL_clear(ssl) != 1) {
        freeOpenSslErrorState();
    }
}

/**
 * To avoid the round-trip to ASN.1 and back in X509_dup, we just up the reference count.
 */
static X509* X509_dup_nocopy(X509* x509) {
    if (x509 == NULL) {
        return NULL;
    }
    CRYPTO_add(&x509->references, 1, CRYPTO_LOCK_X509);
    return x509;
}

/*
 * Sets the read and write BIO for an SSL connection and removes it when it goes out of scope.
 * We hang on to BIO with a JNI GlobalRef and we want to remove them as soon as possible.
 */
class ScopedSslBio {
public:
    ScopedSslBio(SSL *ssl, BIO* rbio, BIO* wbio) : ssl_(ssl) {
        SSL_set_bio(ssl_, rbio, wbio);
        CRYPTO_add(&rbio->references,1,CRYPTO_LOCK_BIO);
        CRYPTO_add(&wbio->references,1,CRYPTO_LOCK_BIO);
    }

    ~ScopedSslBio() {
        SSL_set_bio(ssl_, NULL, NULL);
    }

private:
    SSL* const ssl_;
};

/**
 * Obtains the current thread's JNIEnv
 */
static JNIEnv* getJNIEnv() {
    JNIEnv* env;
    if (gJavaVM->AttachCurrentThread(&env, NULL) < 0) {
        ALOGE("Could not attach JavaVM to find current JNIEnv");
        return NULL;
    }
    return env;
}

/**
 * BIO for InputStream
 */
class BIO_Stream {
public:
    BIO_Stream(jobject stream) :
            mEof(false) {
        JNIEnv* env = getJNIEnv();
        mStream = env->NewGlobalRef(stream);
    }

    ~BIO_Stream() {
        JNIEnv* env = getJNIEnv();

        env->DeleteGlobalRef(mStream);
    }

    bool isEof() const {
        JNI_TRACE("isEof? %s", mEof ? "yes" : "no");
        return mEof;
    }

    int flush() {
        JNIEnv* env = getJNIEnv();
        if (env == NULL) {
            return -1;
        }

        if (env->ExceptionCheck()) {
            JNI_TRACE("BIO_Stream::flush called with pending exception");
            return -1;
        }

        env->CallVoidMethod(mStream, outputStream_flushMethod);
        if (env->ExceptionCheck()) {
            return -1;
        }

        return 1;
    }

protected:
    jobject getStream() {
        return mStream;
    }

    void setEof(bool eof) {
        mEof = eof;
    }

private:
    jobject mStream;
    bool mEof;
};

class BIO_InputStream : public BIO_Stream {
public:
    BIO_InputStream(jobject stream) :
            BIO_Stream(stream) {
    }

    int read(char *buf, int len) {
        return read_internal(buf, len, inputStream_readMethod);
    }

    int gets(char *buf, int len) {
        if (len > PEM_LINE_LENGTH) {
            len = PEM_LINE_LENGTH;
        }

        int read = read_internal(buf, len - 1, openSslInputStream_readLineMethod);
        buf[read] = '\0';
        JNI_TRACE("BIO::gets \"%s\"", buf);
        return read;
    }

private:
    int read_internal(char *buf, int len, jmethodID method) {
        JNIEnv* env = getJNIEnv();
        if (env == NULL) {
            JNI_TRACE("BIO_InputStream::read could not get JNIEnv");
            return -1;
        }

        if (env->ExceptionCheck()) {
            JNI_TRACE("BIO_InputStream::read called with pending exception");
            return -1;
        }

        ScopedLocalRef<jbyteArray> javaBytes(env, env->NewByteArray(len));
        if (javaBytes.get() == NULL) {
            JNI_TRACE("BIO_InputStream::read failed call to NewByteArray");
            return -1;
        }

        jint read = env->CallIntMethod(getStream(), method, javaBytes.get());
        if (env->ExceptionCheck()) {
            JNI_TRACE("BIO_InputStream::read failed call to InputStream#read");
            return -1;
        }

        /* Java uses -1 to indicate EOF condition. */
        if (read == -1) {
            setEof(true);
            read = 0;
        } else if (read > 0) {
            env->GetByteArrayRegion(javaBytes.get(), 0, read, reinterpret_cast<jbyte*>(buf));
        }

        return read;
    }

public:
    /** Length of PEM-encoded line (64) plus CR plus NULL */
    static const int PEM_LINE_LENGTH = 66;
};

class BIO_OutputStream : public BIO_Stream {
public:
    BIO_OutputStream(jobject stream) :
            BIO_Stream(stream) {
    }

    int write(const char *buf, int len) {
        JNIEnv* env = getJNIEnv();
        if (env == NULL) {
            JNI_TRACE("BIO_OutputStream::write => could not get JNIEnv");
            return -1;
        }

        if (env->ExceptionCheck()) {
            JNI_TRACE("BIO_OutputStream::write => called with pending exception");
            return -1;
        }

        ScopedLocalRef<jbyteArray> javaBytes(env, env->NewByteArray(len));
        if (javaBytes.get() == NULL) {
            JNI_TRACE("BIO_OutputStream::write => failed call to NewByteArray");
            return -1;
        }

        env->SetByteArrayRegion(javaBytes.get(), 0, len, reinterpret_cast<const jbyte*>(buf));

        env->CallVoidMethod(getStream(), outputStream_writeMethod, javaBytes.get());
        if (env->ExceptionCheck()) {
            JNI_TRACE("BIO_OutputStream::write => failed call to OutputStream#write");
            return -1;
        }

        return len;
    }
};

static int bio_stream_create(BIO *b) {
    b->init = 1;
    b->num = 0;
    b->ptr = NULL;
    b->flags = 0;
    return 1;
}

static int bio_stream_destroy(BIO *b) {
    if (b == NULL) {
        return 0;
    }

    if (b->ptr != NULL) {
        delete static_cast<BIO_Stream*>(b->ptr);
        b->ptr = NULL;
    }

    b->init = 0;
    b->flags = 0;
    return 1;
}

static int bio_stream_read(BIO *b, char *buf, int len) {
    BIO_clear_retry_flags(b);
    BIO_InputStream* stream = static_cast<BIO_InputStream*>(b->ptr);
    int ret = stream->read(buf, len);
    if (ret == 0) {
        // EOF is indicated by -1 with a BIO flag.
        BIO_set_retry_read(b);
        return -1;
    }
    return ret;
}

static int bio_stream_write(BIO *b, const char *buf, int len) {
    BIO_clear_retry_flags(b);
    BIO_OutputStream* stream = static_cast<BIO_OutputStream*>(b->ptr);
    return stream->write(buf, len);
}

static int bio_stream_puts(BIO *b, const char *buf) {
    BIO_OutputStream* stream = static_cast<BIO_OutputStream*>(b->ptr);
    return stream->write(buf, strlen(buf));
}

static int bio_stream_gets(BIO *b, char *buf, int len) {
    BIO_InputStream* stream = static_cast<BIO_InputStream*>(b->ptr);
    return stream->gets(buf, len);
}

static void bio_stream_assign(BIO *b, BIO_Stream* stream) {
    b->ptr = static_cast<void*>(stream);
}

static long bio_stream_ctrl(BIO *b, int cmd, long, void *) {
    BIO_Stream* stream = static_cast<BIO_Stream*>(b->ptr);

    switch (cmd) {
    case BIO_CTRL_EOF:
        return stream->isEof() ? 1 : 0;
    case BIO_CTRL_FLUSH:
        return stream->flush();
    default:
        return 0;
    }
}

static BIO_METHOD stream_bio_method = {
        ( 100 | 0x0400 ), /* source/sink BIO */
        "InputStream/OutputStream BIO",
        bio_stream_write, /* bio_write */
        bio_stream_read, /* bio_read */
        bio_stream_puts, /* bio_puts */
        bio_stream_gets, /* bio_gets */
        bio_stream_ctrl, /* bio_ctrl */
        bio_stream_create, /* bio_create */
        bio_stream_destroy, /* bio_free */
        NULL, /* no bio_callback_ctrl */
};

static jbyteArray rawSignDigestWithPrivateKey(JNIEnv* env, jobject privateKey,
        const char* message, size_t message_len) {
    ScopedLocalRef<jbyteArray> messageArray(env, env->NewByteArray(message_len));
    if (env->ExceptionCheck()) {
        JNI_TRACE("rawSignDigestWithPrivateKey(%p) => threw exception", privateKey);
        return NULL;
    }

    {
        ScopedByteArrayRW messageBytes(env, messageArray.get());
        if (messageBytes.get() == NULL) {
            JNI_TRACE("rawSignDigestWithPrivateKey(%p) => using byte array failed", privateKey);
            return NULL;
        }

        memcpy(messageBytes.get(), message, message_len);
    }

    jmethodID rawSignMethod = env->GetStaticMethodID(cryptoUpcallsClass,
            "rawSignDigestWithPrivateKey", "(Ljava/security/PrivateKey;[B)[B");
    if (rawSignMethod == NULL) {
        ALOGE("Could not find rawSignDigestWithPrivateKey");
        return NULL;
    }

    return reinterpret_cast<jbyteArray>(env->CallStaticObjectMethod(
            cryptoUpcallsClass, rawSignMethod, privateKey, messageArray.get()));
}

static jbyteArray rawCipherWithPrivateKey(JNIEnv* env, jobject privateKey, jboolean encrypt,
        const char* ciphertext, size_t ciphertext_len) {
    ScopedLocalRef<jbyteArray> ciphertextArray(env, env->NewByteArray(ciphertext_len));
    if (env->ExceptionCheck()) {
        JNI_TRACE("rawCipherWithPrivateKey(%p) => threw exception", privateKey);
        return NULL;
    }

    {
        ScopedByteArrayRW ciphertextBytes(env, ciphertextArray.get());
        if (ciphertextBytes.get() == NULL) {
            JNI_TRACE("rawCipherWithPrivateKey(%p) => using byte array failed", privateKey);
            return NULL;
        }

        memcpy(ciphertextBytes.get(), ciphertext, ciphertext_len);
    }

    jmethodID rawCipherMethod = env->GetStaticMethodID(cryptoUpcallsClass,
            "rawCipherWithPrivateKey", "(Ljava/security/PrivateKey;Z[B)[B");
    if (rawCipherMethod == NULL) {
        ALOGE("Could not find rawCipherWithPrivateKey");
        return NULL;
    }

    return reinterpret_cast<jbyteArray>(env->CallStaticObjectMethod(
            cryptoUpcallsClass, rawCipherMethod, privateKey, encrypt, ciphertextArray.get()));
}

// *********************************************
// From keystore_openssl.cpp in Chromium source.
// *********************************************

#if !defined(OPENSSL_IS_BORINGSSL)
// Custom RSA_METHOD that uses the platform APIs.
// Note that for now, only signing through RSA_sign() is really supported.
// all other method pointers are either stubs returning errors, or no-ops.
// See <openssl/rsa.h> for exact declaration of RSA_METHOD.

int RsaMethodPubEnc(int /* flen */,
                    const unsigned char* /* from */,
                    unsigned char* /* to */,
                    RSA* /* rsa */,
                    int /* padding */) {
    RSAerr(RSA_F_RSA_PUBLIC_ENCRYPT, RSA_R_RSA_OPERATIONS_NOT_SUPPORTED);
    return -1;
}

int RsaMethodPubDec(int /* flen */,
                    const unsigned char* /* from */,
                    unsigned char* /* to */,
                    RSA* /* rsa */,
                    int /* padding */) {
    RSAerr(RSA_F_RSA_PUBLIC_DECRYPT, RSA_R_RSA_OPERATIONS_NOT_SUPPORTED);
    return -1;
}

// See RSA_eay_private_encrypt in
// third_party/openssl/openssl/crypto/rsa/rsa_eay.c for the default
// implementation of this function.
int RsaMethodPrivEnc(int flen,
                     const unsigned char *from,
                     unsigned char *to,
                     RSA *rsa,
                     int padding) {
    if (padding != RSA_PKCS1_PADDING) {
        // TODO(davidben): If we need to, we can implement RSA_NO_PADDING
        // by using javax.crypto.Cipher and picking either the
        // "RSA/ECB/NoPadding" or "RSA/ECB/PKCS1Padding" transformation as
        // appropriate. I believe support for both of these was added in
        // the same Android version as the "NONEwithRSA"
        // java.security.Signature algorithm, so the same version checks
        // for GetRsaLegacyKey should work.
        RSAerr(RSA_F_RSA_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        return -1;
    }

    // Retrieve private key JNI reference.
    jobject private_key = reinterpret_cast<jobject>(RSA_get_app_data(rsa));
    if (!private_key) {
        ALOGE("Null JNI reference passed to RsaMethodPrivEnc!");
        RSAerr(RSA_F_RSA_PRIVATE_ENCRYPT, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    JNIEnv* env = getJNIEnv();
    if (env == NULL) {
        return -1;
    }

    // For RSA keys, this function behaves as RSA_private_encrypt with
    // PKCS#1 padding.
    ScopedLocalRef<jbyteArray> signature(
            env, rawSignDigestWithPrivateKey(env, private_key,
                                         reinterpret_cast<const char*>(from), flen));
    if (signature.get() == NULL) {
        ALOGE("Could not sign message in RsaMethodPrivEnc!");
        RSAerr(RSA_F_RSA_PRIVATE_ENCRYPT, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    ScopedByteArrayRO signatureBytes(env, signature.get());
    size_t expected_size = static_cast<size_t>(RSA_size(rsa));
    if (signatureBytes.size() > expected_size) {
        ALOGE("RSA Signature size mismatch, actual: %zd, expected <= %zd", signatureBytes.size(),
              expected_size);
        RSAerr(RSA_F_RSA_PRIVATE_ENCRYPT, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    // Copy result to OpenSSL-provided buffer. rawSignDigestWithPrivateKey
    // should pad with leading 0s, but if it doesn't, pad the result.
    size_t zero_pad = expected_size - signatureBytes.size();
    memset(to, 0, zero_pad);
    memcpy(to + zero_pad, signatureBytes.get(), signatureBytes.size());

    return expected_size;
}

int RsaMethodPrivDec(int flen,
                     const unsigned char* from,
                     unsigned char* to,
                     RSA* rsa,
                     int padding) {
    if (padding != RSA_PKCS1_PADDING) {
        RSAerr(RSA_F_RSA_PRIVATE_DECRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        return -1;
    }

    // Retrieve private key JNI reference.
    jobject private_key = reinterpret_cast<jobject>(RSA_get_app_data(rsa));
    if (!private_key) {
        ALOGE("Null JNI reference passed to RsaMethodPrivDec!");
        RSAerr(RSA_F_RSA_PRIVATE_DECRYPT, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    JNIEnv* env = getJNIEnv();
    if (env == NULL) {
        return -1;
    }

    // For RSA keys, this function behaves as RSA_private_decrypt with
    // PKCS#1 padding.
    ScopedLocalRef<jbyteArray> cleartext(env, rawCipherWithPrivateKey(env, private_key, false,
                                         reinterpret_cast<const char*>(from), flen));
    if (cleartext.get() == NULL) {
        ALOGE("Could not decrypt message in RsaMethodPrivDec!");
        RSAerr(RSA_F_RSA_PRIVATE_DECRYPT, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    ScopedByteArrayRO cleartextBytes(env, cleartext.get());
    size_t expected_size = static_cast<size_t>(RSA_size(rsa));
    if (cleartextBytes.size() > expected_size) {
        ALOGE("RSA ciphertext size mismatch, actual: %zd, expected <= %zd", cleartextBytes.size(),
              expected_size);
        RSAerr(RSA_F_RSA_PRIVATE_DECRYPT, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    // Copy result to OpenSSL-provided buffer.
    memcpy(to, cleartextBytes.get(), cleartextBytes.size());

    return cleartextBytes.size();
}

int RsaMethodInit(RSA*) {
    return 0;
}

int RsaMethodFinish(RSA* rsa) {
    // Ensure the global JNI reference created with this wrapper is
    // properly destroyed with it.
    jobject key = reinterpret_cast<jobject>(RSA_get_app_data(rsa));
    if (key != NULL) {
        RSA_set_app_data(rsa, NULL);
        JNIEnv* env = getJNIEnv();
        env->DeleteGlobalRef(key);
    }
    // Actual return value is ignored by OpenSSL. There are no docs
    // explaining what this is supposed to be.
    return 0;
}

const RSA_METHOD android_rsa_method = {
        /* .name = */ "Android signing-only RSA method",
        /* .rsa_pub_enc = */ RsaMethodPubEnc,
        /* .rsa_pub_dec = */ RsaMethodPubDec,
        /* .rsa_priv_enc = */ RsaMethodPrivEnc,
        /* .rsa_priv_dec = */ RsaMethodPrivDec,
        /* .rsa_mod_exp = */ NULL,
        /* .bn_mod_exp = */ NULL,
        /* .init = */ RsaMethodInit,
        /* .finish = */ RsaMethodFinish,
        // This flag is necessary to tell OpenSSL to avoid checking the content
        // (i.e. internal fields) of the private key. Otherwise, it will complain
        // it's not valid for the certificate.
        /* .flags = */ RSA_METHOD_FLAG_NO_CHECK,
        /* .app_data = */ NULL,
        /* .rsa_sign = */ NULL,
        /* .rsa_verify = */ NULL,
        /* .rsa_keygen = */ NULL,
};

// Used to ensure that the global JNI reference associated with a custom
// EC_KEY + ECDSA_METHOD wrapper is released when its EX_DATA is destroyed
// (this function is called when EVP_PKEY_free() is called on the wrapper).
void ExDataFree(void* /* parent */,
                void* ptr,
                CRYPTO_EX_DATA* ad,
                int idx,
                long /* argl */,
                void* /* argp */) {
    jobject private_key = reinterpret_cast<jobject>(ptr);
    if (private_key == NULL) return;

    CRYPTO_set_ex_data(ad, idx, NULL);
    JNIEnv* env = getJNIEnv();
    env->DeleteGlobalRef(private_key);
}

int ExDataDup(CRYPTO_EX_DATA* /* to */,
              CRYPTO_EX_DATA* /* from */,
              void* /* from_d */,
              int /* idx */,
              long /* argl */,
              void* /* argp */) {
    // This callback shall never be called with the current OpenSSL
    // implementation (the library only ever duplicates EX_DATA items
    // for SSL and BIO objects). But provide this to catch regressions
    // in the future.
    // Return value is currently ignored by OpenSSL.
    return 0;
}

class EcdsaExDataIndex {
  public:
    int ex_data_index() { return ex_data_index_; }

    static EcdsaExDataIndex& Instance() {
        static EcdsaExDataIndex singleton;
        return singleton;
    }

  private:
    EcdsaExDataIndex() {
        ex_data_index_ = ECDSA_get_ex_new_index(0, NULL, NULL, ExDataDup, ExDataFree);
    }
    EcdsaExDataIndex(EcdsaExDataIndex const&);
    ~EcdsaExDataIndex() {}
    EcdsaExDataIndex& operator=(EcdsaExDataIndex const&);

    int ex_data_index_;
};

// Returns the index of the custom EX_DATA used to store the JNI reference.
int EcdsaGetExDataIndex(void) {
    EcdsaExDataIndex& exData = EcdsaExDataIndex::Instance();
    return exData.ex_data_index();
}

ECDSA_SIG* EcdsaMethodDoSign(const unsigned char* dgst, int dgst_len, const BIGNUM* /* inv */,
                             const BIGNUM* /* rp */, EC_KEY* eckey) {
    // Retrieve private key JNI reference.
    jobject private_key =
            reinterpret_cast<jobject>(ECDSA_get_ex_data(eckey, EcdsaGetExDataIndex()));
    if (!private_key) {
        ALOGE("Null JNI reference passed to EcdsaMethodDoSign!");
        return NULL;
    }
    JNIEnv* env = getJNIEnv();
    if (env == NULL) {
        return NULL;
    }

    // Sign message with it through JNI.
    ScopedLocalRef<jbyteArray> signature(
            env, rawSignDigestWithPrivateKey(env, private_key, reinterpret_cast<const char*>(dgst),
                                             dgst_len));
    if (signature.get() == NULL) {
        ALOGE("Could not sign message in EcdsaMethodDoSign!");
        return NULL;
    }

    ScopedByteArrayRO signatureBytes(env, signature.get());
    // Note: With ECDSA, the actual signature may be smaller than
    // ECDSA_size().
    size_t max_expected_size = static_cast<size_t>(ECDSA_size(eckey));
    if (signatureBytes.size() > max_expected_size) {
        ALOGE("ECDSA Signature size mismatch, actual: %zd, expected <= %zd", signatureBytes.size(),
              max_expected_size);
        return NULL;
    }

    // Convert signature to ECDSA_SIG object
    const unsigned char* sigbuf = reinterpret_cast<const unsigned char*>(signatureBytes.get());
    long siglen = static_cast<long>(signatureBytes.size());
    return d2i_ECDSA_SIG(NULL, &sigbuf, siglen);
}

int EcdsaMethodSignSetup(EC_KEY* /* eckey */,
                         BN_CTX* /* ctx */,
                         BIGNUM** /* kinv */,
                         BIGNUM** /* r */,
                         const unsigned char*,
                         int) {
    ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ECDSA_R_ERR_EC_LIB);
    return -1;
}

int EcdsaMethodDoVerify(const unsigned char* /* dgst */,
                        int /* dgst_len */,
                        const ECDSA_SIG* /* sig */,
                        EC_KEY* /* eckey */) {
    ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_ERR_EC_LIB);
    return -1;
}

const ECDSA_METHOD android_ecdsa_method = {
        /* .name = */ "Android signing-only ECDSA method",
        /* .ecdsa_do_sign = */ EcdsaMethodDoSign,
        /* .ecdsa_sign_setup = */ EcdsaMethodSignSetup,
        /* .ecdsa_do_verify = */ EcdsaMethodDoVerify,
        /* .flags = */ 0,
        /* .app_data = */ NULL,
};

#else  /* OPENSSL_IS_BORINGSSL */

namespace {

ENGINE *g_engine;
int g_rsa_exdata_index;
int g_ecdsa_exdata_index;
pthread_once_t g_engine_once = PTHREAD_ONCE_INIT;

void init_engine_globals();

void ensure_engine_globals() {
  pthread_once(&g_engine_once, init_engine_globals);
}

// KeyExData contains the data that is contained in the EX_DATA of the RSA
// and ECDSA objects that are created to wrap Android system keys.
struct KeyExData {
  // private_key contains a reference to a Java, private-key object.
  jobject private_key;
  // cached_size contains the "size" of the key. This is the size of the
  // modulus (in bytes) for RSA, or the group order size for ECDSA. This
  // avoids calling into Java to calculate the size.
  size_t cached_size;
};

// ExDataDup is called when one of the RSA or EC_KEY objects is duplicated. We
// don't support this and it should never happen.
int ExDataDup(CRYPTO_EX_DATA* /* to */,
              const CRYPTO_EX_DATA* /* from */,
              void** /* from_d */,
              int /* index */,
              long /* argl */,
              void* /* argp */) {
  return 0;
}

// ExDataFree is called when one of the RSA or EC_KEY objects is freed.
void ExDataFree(void* /* parent */,
                void* ptr,
                CRYPTO_EX_DATA* /* ad */,
                int /* index */,
                long /* argl */,
                void* /* argp */) {
  // Ensure the global JNI reference created with this wrapper is
  // properly destroyed with it.
  KeyExData *ex_data = reinterpret_cast<KeyExData*>(ptr);
  if (ex_data != NULL) {
    JNIEnv* env = getJNIEnv();
    env->DeleteGlobalRef(ex_data->private_key);
    delete ex_data;
  }
}

KeyExData* RsaGetExData(const RSA* rsa) {
  return reinterpret_cast<KeyExData*>(RSA_get_ex_data(rsa, g_rsa_exdata_index));
}

size_t RsaMethodSize(const RSA *rsa) {
  const KeyExData *ex_data = RsaGetExData(rsa);
  return ex_data->cached_size;
}

int RsaMethodEncrypt(RSA* /* rsa */,
                     size_t* /* out_len */,
                     uint8_t* /* out */,
                     size_t /* max_out */,
                     const uint8_t* /* in */,
                     size_t /* in_len */,
                     int /* padding */) {
  OPENSSL_PUT_ERROR(RSA, encrypt, RSA_R_UNKNOWN_ALGORITHM_TYPE);
  return 0;
}

int RsaMethodSignRaw(RSA* rsa,
                     size_t* out_len,
                     uint8_t* out,
                     size_t max_out,
                     const uint8_t* in,
                     size_t in_len,
                     int padding) {
  if (padding != RSA_PKCS1_PADDING) {
    // TODO(davidben): If we need to, we can implement RSA_NO_PADDING
    // by using javax.crypto.Cipher and picking either the
    // "RSA/ECB/NoPadding" or "RSA/ECB/PKCS1Padding" transformation as
    // appropriate. I believe support for both of these was added in
    // the same Android version as the "NONEwithRSA"
    // java.security.Signature algorithm, so the same version checks
    // for GetRsaLegacyKey should work.
    OPENSSL_PUT_ERROR(RSA, sign_raw, RSA_R_UNKNOWN_PADDING_TYPE);
    return 0;
  }

  // Retrieve private key JNI reference.
  const KeyExData *ex_data = RsaGetExData(rsa);
  if (!ex_data || !ex_data->private_key) {
    OPENSSL_PUT_ERROR(RSA, sign_raw, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  JNIEnv* env = getJNIEnv();
  if (env == NULL) {
    OPENSSL_PUT_ERROR(RSA, sign_raw, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  // For RSA keys, this function behaves as RSA_private_decrypt with
  // PKCS#1 v1.5 padding.
  ScopedLocalRef<jbyteArray> cleartext(
      env, rawCipherWithPrivateKey(env, ex_data->private_key, false,
                                   reinterpret_cast<const char*>(in), in_len));

  if (cleartext.get() == NULL) {
    OPENSSL_PUT_ERROR(RSA, sign_raw, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  ScopedByteArrayRO result(env, cleartext.get());

  size_t expected_size = static_cast<size_t>(RSA_size(rsa));
  if (result.size() > expected_size) {
    OPENSSL_PUT_ERROR(RSA, sign_raw, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  if (max_out < expected_size) {
    OPENSSL_PUT_ERROR(RSA, sign_raw, RSA_R_DATA_TOO_LARGE);
    return 0;
  }

  // Copy result to OpenSSL-provided buffer. RawSignDigestWithPrivateKey
  // should pad with leading 0s, but if it doesn't, pad the result.
  size_t zero_pad = expected_size - result.size();
  memset(out, 0, zero_pad);
  memcpy(out + zero_pad, &result[0], result.size());
  *out_len = expected_size;

  return 1;
}

int RsaMethodDecrypt(RSA* /* rsa */,
                     size_t* /* out_len */,
                     uint8_t* /* out */,
                     size_t /* max_out */,
                     const uint8_t* /* in */,
                     size_t /* in_len */,
                     int /* padding */) {
  OPENSSL_PUT_ERROR(RSA, decrypt, RSA_R_UNKNOWN_ALGORITHM_TYPE);
  return 0;
}

int RsaMethodVerifyRaw(RSA* /* rsa */,
                       size_t* /* out_len */,
                       uint8_t* /* out */,
                       size_t /* max_out */,
                       const uint8_t* /* in */,
                       size_t /* in_len */,
                       int /* padding */) {
  OPENSSL_PUT_ERROR(RSA, verify_raw, RSA_R_UNKNOWN_ALGORITHM_TYPE);
  return 0;
}

const RSA_METHOD android_rsa_method = {
    {
     0 /* references */,
     1 /* is_static */
    } /* common */,
    NULL /* app_data */,

    NULL /* init */,
    NULL /* finish */,
    RsaMethodSize,
    NULL /* sign */,
    NULL /* verify */,
    RsaMethodEncrypt,
    RsaMethodSignRaw,
    RsaMethodDecrypt,
    RsaMethodVerifyRaw,
    NULL /* mod_exp */,
    NULL /* bn_mod_exp */,
    NULL /* private_transform */,
    RSA_FLAG_OPAQUE,
    NULL /* keygen */,
    NULL /* supports_digest */,
};

// Custom ECDSA_METHOD that uses the platform APIs.
// Note that for now, only signing through ECDSA_sign() is really supported.
// all other method pointers are either stubs returning errors, or no-ops.

jobject EcKeyGetKey(const EC_KEY* ec_key) {
  KeyExData* ex_data = reinterpret_cast<KeyExData*>(EC_KEY_get_ex_data(
      ec_key, g_ecdsa_exdata_index));
  return ex_data->private_key;
}

size_t EcdsaMethodGroupOrderSize(const EC_KEY* ec_key) {
  KeyExData* ex_data = reinterpret_cast<KeyExData*>(EC_KEY_get_ex_data(
      ec_key, g_ecdsa_exdata_index));
  return ex_data->cached_size;
}

int EcdsaMethodSign(const uint8_t* digest,
                    size_t digest_len,
                    uint8_t* sig,
                    unsigned int* sig_len,
                    EC_KEY* ec_key) {
    // Retrieve private key JNI reference.
    jobject private_key = EcKeyGetKey(ec_key);
    if (!private_key) {
        ALOGE("Null JNI reference passed to EcdsaMethodSign!");
        return 0;
    }

    JNIEnv* env = getJNIEnv();
    if (env == NULL) {
        return 0;
    }

    // Sign message with it through JNI.
    ScopedLocalRef<jbyteArray> signature(
        env, rawSignDigestWithPrivateKey(env, private_key,
                                         reinterpret_cast<const char*>(digest),
                                         digest_len));
    if (signature.get() == NULL) {
        ALOGE("Could not sign message in EcdsaMethodDoSign!");
        return 0;
    }

    ScopedByteArrayRO signatureBytes(env, signature.get());
    // Note: With ECDSA, the actual signature may be smaller than
    // ECDSA_size().
    size_t max_expected_size = ECDSA_size(ec_key);
    if (signatureBytes.size() > max_expected_size) {
        ALOGE("ECDSA Signature size mismatch, actual: %zd, expected <= %zd",
              signatureBytes.size(), max_expected_size);
        return 0;
    }

    memcpy(sig, signatureBytes.get(), signatureBytes.size());
    *sig_len = signatureBytes.size();
    return 1;
}

int EcdsaMethodVerify(const uint8_t* /* digest */,
                      size_t /* digest_len */,
                      const uint8_t* /* sig */,
                      size_t /* sig_len */,
                      EC_KEY* /* ec_key */) {
  OPENSSL_PUT_ERROR(ECDSA, ECDSA_do_verify, ECDSA_R_NOT_IMPLEMENTED);
  return 0;
}

const ECDSA_METHOD android_ecdsa_method = {
    {
     0 /* references */,
     1 /* is_static */
    } /* common */,
    NULL /* app_data */,

    NULL /* init */,
    NULL /* finish */,
    EcdsaMethodGroupOrderSize,
    EcdsaMethodSign,
    EcdsaMethodVerify,
    ECDSA_FLAG_OPAQUE,
};


void init_engine_globals() {
  g_rsa_exdata_index =
      RSA_get_ex_new_index(0 /* argl */, NULL /* argp */, NULL /* new_func */,
                           ExDataDup, ExDataFree);
  g_ecdsa_exdata_index =
      EC_KEY_get_ex_new_index(0 /* argl */, NULL /* argp */,
                              NULL /* new_func */, ExDataDup, ExDataFree);

  g_engine = ENGINE_new();
  ENGINE_set_RSA_method(g_engine, &android_rsa_method,
                        sizeof(android_rsa_method));
  ENGINE_set_ECDSA_method(g_engine, &android_ecdsa_method,
                          sizeof(android_ecdsa_method));
}

}  // anonymous namespace
#endif

#ifdef CONSCRYPT_UNBUNDLED
/*
 * This is a big hack; don't learn from this. Basically what happened is we do
 * not have an API way to insert ourselves into the AsynchronousCloseMonitor
 * that's compiled into the native libraries for libcore when we're unbundled.
 * So we try to look up the symbol from the main library to find it.
 */
typedef void (*acm_ctor_func)(void*, int);
typedef void (*acm_dtor_func)(void*);
static acm_ctor_func async_close_monitor_ctor = NULL;
static acm_dtor_func async_close_monitor_dtor = NULL;

class CompatibilityCloseMonitor {
public:
    CompatibilityCloseMonitor(int fd) {
        if (async_close_monitor_ctor != NULL) {
            async_close_monitor_ctor(objBuffer, fd);
        }
    }

    ~CompatibilityCloseMonitor() {
        if (async_close_monitor_dtor != NULL) {
            async_close_monitor_dtor(objBuffer);
        }
    }
private:
    char objBuffer[256];
#if 0
    static_assert(sizeof(objBuffer) > 2*sizeof(AsynchronousCloseMonitor),
                  "CompatibilityCloseMonitor must be larger than the actual object");
#endif
};

static void findAsynchronousCloseMonitorFuncs() {
    void *lib = dlopen("libjavacore.so", RTLD_NOW);
    if (lib != NULL) {
        async_close_monitor_ctor = (acm_ctor_func) dlsym(lib, "_ZN24AsynchronousCloseMonitorC1Ei");
        async_close_monitor_dtor = (acm_dtor_func) dlsym(lib, "_ZN24AsynchronousCloseMonitorD1Ev");
    }
}
#endif

/**
 * Copied from libnativehelper NetworkUtilites.cpp
 */
static bool setBlocking(int fd, bool blocking) {
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        return false;
    }

    if (!blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }

    int rc = fcntl(fd, F_SETFL, flags);
    return (rc != -1);
}

/**
 * OpenSSL locking support. Taken from the O'Reilly book by Viega et al., but I
 * suppose there are not many other ways to do this on a Linux system (modulo
 * isomorphism).
 */
#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
#define THREAD_ID pthread_self()
#define THROW_SSLEXCEPTION (-2)
#define THROW_SOCKETTIMEOUTEXCEPTION (-3)
#define THROWN_EXCEPTION (-4)

static MUTEX_TYPE* mutex_buf = NULL;

static void locking_function(int mode, int n, const char*, int) {
    if (mode & CRYPTO_LOCK) {
        MUTEX_LOCK(mutex_buf[n]);
    } else {
        MUTEX_UNLOCK(mutex_buf[n]);
    }
}

static void threadid_callback(CRYPTO_THREADID *threadid) {
#if defined(__APPLE__)
    uint64_t owner;
    int rc = pthread_threadid_np(NULL, &owner);  // Requires Mac OS 10.6
    if (rc == 0) {
        CRYPTO_THREADID_set_numeric(threadid, owner);
    } else {
        ALOGE("Error calling pthread_threadid_np");
    }
#else
    // bionic exposes gettid(), but glibc doesn't
    CRYPTO_THREADID_set_numeric(threadid, syscall(__NR_gettid));
#endif
}

int THREAD_setup(void) {
    mutex_buf = new MUTEX_TYPE[CRYPTO_num_locks()];
    if (!mutex_buf) {
        return 0;
    }

    for (int i = 0; i < CRYPTO_num_locks(); ++i) {
        MUTEX_SETUP(mutex_buf[i]);
    }

    CRYPTO_THREADID_set_callback(threadid_callback);
    CRYPTO_set_locking_callback(locking_function);

    return 1;
}

int THREAD_cleanup(void) {
    if (!mutex_buf) {
        return 0;
    }

    CRYPTO_THREADID_set_callback(NULL);
    CRYPTO_set_locking_callback(NULL);

    for (int i = 0; i < CRYPTO_num_locks( ); i++) {
        MUTEX_CLEANUP(mutex_buf[i]);
    }

    free(mutex_buf);
    mutex_buf = NULL;

    return 1;
}

/**
 * Initialization phase for every OpenSSL job: Loads the Error strings, the
 * crypto algorithms and reset the OpenSSL library
 */
static jboolean NativeCrypto_clinit(JNIEnv*, jclass)
{
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    THREAD_setup();
#if !defined(OPENSSL_IS_BORINGSSL)
    return JNI_FALSE;
#else
    return JNI_TRUE;
#endif
}

static void NativeCrypto_ENGINE_load_dynamic(JNIEnv*, jclass) {
#if !defined(OPENSSL_IS_BORINGSSL)
    JNI_TRACE("ENGINE_load_dynamic()");

    ENGINE_load_dynamic();
#endif
}

#if !defined(OPENSSL_IS_BORINGSSL)
static jlong NativeCrypto_ENGINE_by_id(JNIEnv* env, jclass, jstring idJava) {
    JNI_TRACE("ENGINE_by_id(%p)", idJava);

    ScopedUtfChars id(env, idJava);
    if (id.c_str() == NULL) {
        JNI_TRACE("ENGINE_by_id(%p) => id == null", idJava);
        return 0;
    }
    JNI_TRACE("ENGINE_by_id(\"%s\")", id.c_str());

    ENGINE* e = ENGINE_by_id(id.c_str());
    if (e == NULL) {
        freeOpenSslErrorState();
    }

    JNI_TRACE("ENGINE_by_id(\"%s\") => %p", id.c_str(), e);
    return reinterpret_cast<uintptr_t>(e);
}
#else
static jlong NativeCrypto_ENGINE_by_id(JNIEnv*, jclass, jstring) {
    return 0;
}
#endif

#if !defined(OPENSSL_IS_BORINGSSL)
static jint NativeCrypto_ENGINE_add(JNIEnv* env, jclass, jlong engineRef) {
    ENGINE* e = reinterpret_cast<ENGINE*>(static_cast<uintptr_t>(engineRef));
    JNI_TRACE("ENGINE_add(%p)", e);

    if (e == NULL) {
        jniThrowException(env, "java/lang/IllegalArgumentException", "engineRef == 0");
        return 0;
    }

    int ret = ENGINE_add(e);

    /*
     * We tolerate errors, because the most likely error is that
     * the ENGINE is already in the list.
     */
    freeOpenSslErrorState();

    JNI_TRACE("ENGINE_add(%p) => %d", e, ret);
    return ret;
}
#else
static jint NativeCrypto_ENGINE_add(JNIEnv*, jclass, jlong) {
    return 0;
}
#endif

#if !defined(OPENSSL_IS_BORINGSSL)
static jint NativeCrypto_ENGINE_init(JNIEnv* env, jclass, jlong engineRef) {
    ENGINE* e = reinterpret_cast<ENGINE*>(static_cast<uintptr_t>(engineRef));
    JNI_TRACE("ENGINE_init(%p)", e);

    if (e == NULL) {
        jniThrowException(env, "java/lang/IllegalArgumentException", "engineRef == 0");
        return 0;
    }

    int ret = ENGINE_init(e);
    JNI_TRACE("ENGINE_init(%p) => %d", e, ret);
    return ret;
}
#else
static jint NativeCrypto_ENGINE_init(JNIEnv*, jclass, jlong) {
    return 0;
}
#endif

#if !defined(OPENSSL_IS_BORINGSSL)
static jint NativeCrypto_ENGINE_finish(JNIEnv* env, jclass, jlong engineRef) {
    ENGINE* e = reinterpret_cast<ENGINE*>(static_cast<uintptr_t>(engineRef));
    JNI_TRACE("ENGINE_finish(%p)", e);

    if (e == NULL) {
        jniThrowException(env, "java/lang/IllegalArgumentException", "engineRef == 0");
        return 0;
    }

    int ret = ENGINE_finish(e);
    JNI_TRACE("ENGINE_finish(%p) => %d", e, ret);
    return ret;
}
#else
static jint NativeCrypto_ENGINE_finish(JNIEnv*, jclass, jlong) {
    return 0;
}
#endif

#if !defined(OPENSSL_IS_BORINGSSL)
static jint NativeCrypto_ENGINE_free(JNIEnv* env, jclass, jlong engineRef) {
    ENGINE* e = reinterpret_cast<ENGINE*>(static_cast<uintptr_t>(engineRef));
    JNI_TRACE("ENGINE_free(%p)", e);

    if (e == NULL) {
        jniThrowException(env, "java/lang/IllegalArgumentException", "engineRef == 0");
        return 0;
    }

    int ret = ENGINE_free(e);
    JNI_TRACE("ENGINE_free(%p) => %d", e, ret);
    return ret;
}
#else
static jint NativeCrypto_ENGINE_free(JNIEnv*, jclass, jlong) {
    return 0;
}
#endif

#if defined(OPENSSL_IS_BORINGSSL)
extern "C" {
/* EVP_PKEY_from_keystore is from system/security/keystore-engine. */
extern EVP_PKEY* EVP_PKEY_from_keystore(const char *key_id);
}
#endif

static jlong NativeCrypto_ENGINE_load_private_key(JNIEnv* env, jclass, jlong engineRef,
        jstring idJava) {
    ScopedUtfChars id(env, idJava);
    if (id.c_str() == NULL) {
        jniThrowException(env, "java/lang/IllegalArgumentException", "id == NULL");
        return 0;
    }

#if !defined(OPENSSL_IS_BORINGSSL)
    ENGINE* e = reinterpret_cast<ENGINE*>(static_cast<uintptr_t>(engineRef));
    JNI_TRACE("ENGINE_load_private_key(%p, %p)", e, idJava);

    Unique_EVP_PKEY pkey(ENGINE_load_private_key(e, id.c_str(), NULL, NULL));
    if (pkey.get() == NULL) {
        throwExceptionIfNecessary(env, "ENGINE_load_private_key");
        return 0;
    }

    JNI_TRACE("ENGINE_load_private_key(%p, %p) => %p", e, idJava, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
#else
    UNUSED_ARGUMENT(engineRef);
#if defined(NO_KEYSTORE_ENGINE)
    jniThrowRuntimeException(env, "No keystore ENGINE support compiled in");
    return 0;
#else
    Unique_EVP_PKEY pkey(EVP_PKEY_from_keystore(id.c_str()));
    if (pkey.get() == NULL) {
        throwExceptionIfNecessary(env, "ENGINE_load_private_key");
        return 0;
    }
    return reinterpret_cast<uintptr_t>(pkey.release());
#endif
#endif
}

#if !defined(OPENSSL_IS_BORINGSSL)
static jstring NativeCrypto_ENGINE_get_id(JNIEnv* env, jclass, jlong engineRef)
{
    ENGINE* e = reinterpret_cast<ENGINE*>(static_cast<uintptr_t>(engineRef));
    JNI_TRACE("ENGINE_get_id(%p)", e);

    if (e == NULL) {
        jniThrowNullPointerException(env, "engine == null");
        JNI_TRACE("ENGINE_get_id(%p) => engine == null", e);
        return NULL;
    }

    const char *id = ENGINE_get_id(e);
    ScopedLocalRef<jstring> idJava(env, env->NewStringUTF(id));

    JNI_TRACE("ENGINE_get_id(%p) => \"%s\"", e, id);
    return idJava.release();
}
#else
static jstring NativeCrypto_ENGINE_get_id(JNIEnv* env, jclass, jlong)
{
    ScopedLocalRef<jstring> idJava(env, env->NewStringUTF("keystore"));
    return idJava.release();
}
#endif

#if !defined(OPENSSL_IS_BORINGSSL)
static jint NativeCrypto_ENGINE_ctrl_cmd_string(JNIEnv* env, jclass, jlong engineRef,
        jstring cmdJava, jstring argJava, jint cmd_optional)
{
    ENGINE* e = reinterpret_cast<ENGINE*>(static_cast<uintptr_t>(engineRef));
    JNI_TRACE("ENGINE_ctrl_cmd_string(%p, %p, %p, %d)", e, cmdJava, argJava, cmd_optional);

    if (e == NULL) {
        jniThrowNullPointerException(env, "engine == null");
        JNI_TRACE("ENGINE_ctrl_cmd_string(%p, %p, %p, %d) => engine == null", e, cmdJava, argJava,
                cmd_optional);
        return 0;
    }

    ScopedUtfChars cmdChars(env, cmdJava);
    if (cmdChars.c_str() == NULL) {
        return 0;
    }

    UniquePtr<ScopedUtfChars> arg;
    const char* arg_c_str = NULL;
    if (argJava != NULL) {
        arg.reset(new ScopedUtfChars(env, argJava));
        arg_c_str = arg->c_str();
        if (arg_c_str == NULL) {
            return 0;
        }
    }
    JNI_TRACE("ENGINE_ctrl_cmd_string(%p, \"%s\", \"%s\", %d)", e, cmdChars.c_str(), arg_c_str,
            cmd_optional);

    int ret = ENGINE_ctrl_cmd_string(e, cmdChars.c_str(), arg_c_str, cmd_optional);
    if (ret != 1) {
        throwExceptionIfNecessary(env, "ENGINE_ctrl_cmd_string");
        JNI_TRACE("ENGINE_ctrl_cmd_string(%p, \"%s\", \"%s\", %d) => threw error", e,
                cmdChars.c_str(), arg_c_str, cmd_optional);
        return 0;
    }

    JNI_TRACE("ENGINE_ctrl_cmd_string(%p, \"%s\", \"%s\", %d) => %d", e, cmdChars.c_str(),
            arg_c_str, cmd_optional, ret);
    return ret;
}
#else
static jint NativeCrypto_ENGINE_ctrl_cmd_string(JNIEnv*, jclass, jlong, jstring, jstring, jint)
{
    return 0;
}
#endif

static jlong NativeCrypto_EVP_PKEY_new_DH(JNIEnv* env, jclass,
                                               jbyteArray p, jbyteArray g,
                                               jbyteArray pub_key, jbyteArray priv_key) {
    JNI_TRACE("EVP_PKEY_new_DH(p=%p, g=%p, pub_key=%p, priv_key=%p)",
              p, g, pub_key, priv_key);

    Unique_DH dh(DH_new());
    if (dh.get() == NULL) {
        jniThrowRuntimeException(env, "DH_new failed");
        return 0;
    }

    if (!arrayToBignum(env, p, &dh->p)) {
        return 0;
    }

    if (!arrayToBignum(env, g, &dh->g)) {
        return 0;
    }

    if (pub_key != NULL && !arrayToBignum(env, pub_key, &dh->pub_key)) {
        return 0;
    }

    if (priv_key != NULL && !arrayToBignum(env, priv_key, &dh->priv_key)) {
        return 0;
    }

    if (dh->p == NULL || dh->g == NULL
            || (pub_key != NULL && dh->pub_key == NULL)
            || (priv_key != NULL && dh->priv_key == NULL)) {
        jniThrowRuntimeException(env, "Unable to convert BigInteger to BIGNUM");
        return 0;
    }

    /* The public key can be recovered if the private key is available. */
    if (dh->pub_key == NULL && dh->priv_key != NULL) {
        if (!DH_generate_key(dh.get())) {
            jniThrowRuntimeException(env, "EVP_PKEY_new_DH failed during pub_key generation");
            return 0;
        }
    }

    Unique_EVP_PKEY pkey(EVP_PKEY_new());
    if (pkey.get() == NULL) {
        jniThrowRuntimeException(env, "EVP_PKEY_new failed");
        return 0;
    }
    if (EVP_PKEY_assign_DH(pkey.get(), dh.get()) != 1) {
        jniThrowRuntimeException(env, "EVP_PKEY_assign_DH failed");
        return 0;
    }
    OWNERSHIP_TRANSFERRED(dh);
    JNI_TRACE("EVP_PKEY_new_DH(p=%p, g=%p, pub_key=%p, priv_key=%p) => %p",
              p, g, pub_key, priv_key, pkey.get());
    return reinterpret_cast<jlong>(pkey.release());
}

/**
 * private static native int EVP_PKEY_new_RSA(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q);
 */
static jlong NativeCrypto_EVP_PKEY_new_RSA(JNIEnv* env, jclass,
                                               jbyteArray n, jbyteArray e, jbyteArray d,
                                               jbyteArray p, jbyteArray q,
                                               jbyteArray dmp1, jbyteArray dmq1,
                                               jbyteArray iqmp) {
    JNI_TRACE("EVP_PKEY_new_RSA(n=%p, e=%p, d=%p, p=%p, q=%p, dmp1=%p, dmq1=%p, iqmp=%p)",
            n, e, d, p, q, dmp1, dmq1, iqmp);

    Unique_RSA rsa(RSA_new());
    if (rsa.get() == NULL) {
        jniThrowRuntimeException(env, "RSA_new failed");
        return 0;
    }

    if (e == NULL && d == NULL) {
        jniThrowException(env, "java/lang/IllegalArgumentException", "e == NULL && d == NULL");
        JNI_TRACE("NativeCrypto_EVP_PKEY_new_RSA => e == NULL && d == NULL");
        return 0;
    }

    if (!arrayToBignum(env, n, &rsa->n)) {
        return 0;
    }

    if (e != NULL && !arrayToBignum(env, e, &rsa->e)) {
        return 0;
    }

    if (d != NULL && !arrayToBignum(env, d, &rsa->d)) {
        return 0;
    }

    if (p != NULL && !arrayToBignum(env, p, &rsa->p)) {
        return 0;
    }

    if (q != NULL && !arrayToBignum(env, q, &rsa->q)) {
        return 0;
    }

    if (dmp1 != NULL && !arrayToBignum(env, dmp1, &rsa->dmp1)) {
        return 0;
    }

    if (dmq1 != NULL && !arrayToBignum(env, dmq1, &rsa->dmq1)) {
        return 0;
    }

    if (iqmp != NULL && !arrayToBignum(env, iqmp, &rsa->iqmp)) {
        return 0;
    }

#ifdef WITH_JNI_TRACE
    if (p != NULL && q != NULL) {
        int check = RSA_check_key(rsa.get());
        JNI_TRACE("EVP_PKEY_new_RSA(...) RSA_check_key returns %d", check);
    }
#endif

    if (rsa->n == NULL || (rsa->e == NULL && rsa->d == NULL)) {
        jniThrowRuntimeException(env, "Unable to convert BigInteger to BIGNUM");
        return 0;
    }

#if !defined(OPENSSL_IS_BORINGSSL)
    /*
     * If the private exponent is available, there is the potential to do signing
     * operations. If the public exponent is also available, OpenSSL will do RSA
     * blinding. Enable it if possible.
     */
    if (rsa->d != NULL) {
        if (rsa->e != NULL) {
            JNI_TRACE("EVP_PKEY_new_RSA(...) enabling RSA blinding => %p", rsa.get());
            RSA_blinding_on(rsa.get(), NULL);
        } else {
            JNI_TRACE("EVP_PKEY_new_RSA(...) disabling RSA blinding => %p", rsa.get());
            RSA_blinding_off(rsa.get());
        }
    }
#endif

    Unique_EVP_PKEY pkey(EVP_PKEY_new());
    if (pkey.get() == NULL) {
        jniThrowRuntimeException(env, "EVP_PKEY_new failed");
        return 0;
    }
    if (EVP_PKEY_assign_RSA(pkey.get(), rsa.get()) != 1) {
        jniThrowRuntimeException(env, "EVP_PKEY_new failed");
        return 0;
    }
    OWNERSHIP_TRANSFERRED(rsa);
    JNI_TRACE("EVP_PKEY_new_RSA(n=%p, e=%p, d=%p, p=%p, q=%p dmp1=%p, dmq1=%p, iqmp=%p) => %p",
            n, e, d, p, q, dmp1, dmq1, iqmp, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jlong NativeCrypto_EVP_PKEY_new_EC_KEY(JNIEnv* env, jclass, jobject groupRef,
        jobject pubkeyRef, jbyteArray keyJavaBytes) {
    JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p)", groupRef, pubkeyRef, keyJavaBytes);
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    if (group == NULL) {
        return 0;
    }
    const EC_POINT* pubkey = pubkeyRef == NULL ? NULL :
            fromContextObject<EC_POINT>(env, pubkeyRef);
    JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p) <- ptr", group, pubkey, keyJavaBytes);

    Unique_BIGNUM key(NULL);
    if (keyJavaBytes != NULL) {
        BIGNUM* keyRef = NULL;
        if (!arrayToBignum(env, keyJavaBytes, &keyRef)) {
            return 0;
        }
        key.reset(keyRef);
    }

    Unique_EC_KEY eckey(EC_KEY_new());
    if (eckey.get() == NULL) {
        jniThrowRuntimeException(env, "EC_KEY_new failed");
        return 0;
    }

    if (EC_KEY_set_group(eckey.get(), group) != 1) {
        JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p) > EC_KEY_set_group failed", group, pubkey,
                keyJavaBytes);
        throwExceptionIfNecessary(env, "EC_KEY_set_group");
        return 0;
    }

    if (pubkey != NULL) {
        if (EC_KEY_set_public_key(eckey.get(), pubkey) != 1) {
            JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p) => EC_KEY_set_private_key failed", group,
                    pubkey, keyJavaBytes);
            throwExceptionIfNecessary(env, "EC_KEY_set_public_key");
            return 0;
        }
    }

    if (key.get() != NULL) {
        if (EC_KEY_set_private_key(eckey.get(), key.get()) != 1) {
            JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p) => EC_KEY_set_private_key failed", group,
                    pubkey, keyJavaBytes);
            throwExceptionIfNecessary(env, "EC_KEY_set_private_key");
            return 0;
        }
        if (pubkey == NULL) {
            Unique_EC_POINT calcPubkey(EC_POINT_new(group));
            if (!EC_POINT_mul(group, calcPubkey.get(), key.get(), NULL, NULL, NULL)) {
                JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p) => can't calulate public key", group,
                        pubkey, keyJavaBytes);
                throwExceptionIfNecessary(env, "EC_KEY_set_private_key");
                return 0;
            }
            EC_KEY_set_public_key(eckey.get(), calcPubkey.get());
        }
    }

    if (!EC_KEY_check_key(eckey.get())) {
        JNI_TRACE("EVP_KEY_new_EC_KEY(%p, %p, %p) => invalid key created", group, pubkey, keyJavaBytes);
        throwExceptionIfNecessary(env, "EC_KEY_check_key");
        return 0;
    }

    Unique_EVP_PKEY pkey(EVP_PKEY_new());
    if (pkey.get() == NULL) {
        JNI_TRACE("EVP_PKEY_new_EC(%p, %p, %p) => threw error", group, pubkey, keyJavaBytes);
        throwExceptionIfNecessary(env, "EVP_PKEY_new failed");
        return 0;
    }
    if (EVP_PKEY_assign_EC_KEY(pkey.get(), eckey.get()) != 1) {
        JNI_TRACE("EVP_PKEY_new_EC(%p, %p, %p) => threw error", group, pubkey, keyJavaBytes);
        jniThrowRuntimeException(env, "EVP_PKEY_assign_EC_KEY failed");
        return 0;
    }
    OWNERSHIP_TRANSFERRED(eckey);

    JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p) => %p", group, pubkey, keyJavaBytes, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jlong NativeCrypto_EVP_PKEY_new_mac_key(JNIEnv* env, jclass, jint pkeyType,
        jbyteArray keyJavaBytes)
{
    JNI_TRACE("EVP_PKEY_new_mac_key(%d, %p)", pkeyType, keyJavaBytes);

    ScopedByteArrayRO key(env, keyJavaBytes);
    if (key.get() == NULL) {
        return 0;
    }

    const unsigned char* tmp = reinterpret_cast<const unsigned char*>(key.get());
    Unique_EVP_PKEY pkey(EVP_PKEY_new_mac_key(pkeyType, (ENGINE *) NULL, tmp, key.size()));
    if (pkey.get() == NULL) {
        JNI_TRACE("EVP_PKEY_new_mac_key(%d, %p) => threw error", pkeyType, keyJavaBytes);
        throwExceptionIfNecessary(env, "ENGINE_load_private_key");
        return 0;
    }

    JNI_TRACE("EVP_PKEY_new_mac_key(%d, %p) => %p", pkeyType, keyJavaBytes, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static int NativeCrypto_EVP_PKEY_type(JNIEnv* env, jclass, jobject pkeyRef) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EVP_PKEY_type(%p)", pkey);

    if (pkey == NULL) {
        return -1;
    }

    int result = EVP_PKEY_type(pkey->type);
    JNI_TRACE("EVP_PKEY_type(%p) => %d", pkey, result);
    return result;
}

/**
 * private static native int EVP_PKEY_size(int pkey);
 */
static int NativeCrypto_EVP_PKEY_size(JNIEnv* env, jclass, jobject pkeyRef) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EVP_PKEY_size(%p)", pkey);

    if (pkey == NULL) {
        return -1;
    }

    int result = EVP_PKEY_size(pkey);
    JNI_TRACE("EVP_PKEY_size(%p) => %d", pkey, result);
    return result;
}

static jstring NativeCrypto_EVP_PKEY_print_public(JNIEnv* env, jclass, jobject pkeyRef) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EVP_PKEY_print_public(%p)", pkey);

    if (pkey == NULL) {
        return NULL;
    }

    Unique_BIO buffer(BIO_new(BIO_s_mem()));
    if (buffer.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate BIO");
        return NULL;
    }

    if (EVP_PKEY_print_public(buffer.get(), pkey, 0, (ASN1_PCTX*) NULL) != 1) {
        throwExceptionIfNecessary(env, "EVP_PKEY_print_public");
        return NULL;
    }
    // Null terminate this
    BIO_write(buffer.get(), "\0", 1);

    char *tmp;
    BIO_get_mem_data(buffer.get(), &tmp);
    jstring description = env->NewStringUTF(tmp);

    JNI_TRACE("EVP_PKEY_print_public(%p) => \"%s\"", pkey, tmp);
    return description;
}

static jstring NativeCrypto_EVP_PKEY_print_private(JNIEnv* env, jclass, jobject pkeyRef) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EVP_PKEY_print_private(%p)", pkey);

    if (pkey == NULL) {
        return NULL;
    }

    Unique_BIO buffer(BIO_new(BIO_s_mem()));
    if (buffer.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate BIO");
        return NULL;
    }

    if (EVP_PKEY_print_private(buffer.get(), pkey, 0, (ASN1_PCTX*) NULL) != 1) {
        throwExceptionIfNecessary(env, "EVP_PKEY_print_private");
        return NULL;
    }
    // Null terminate this
    BIO_write(buffer.get(), "\0", 1);

    char *tmp;
    BIO_get_mem_data(buffer.get(), &tmp);
    jstring description = env->NewStringUTF(tmp);

    JNI_TRACE("EVP_PKEY_print_private(%p) => \"%s\"", pkey, tmp);
    return description;
}

static void NativeCrypto_EVP_PKEY_free(JNIEnv*, jclass, jlong pkeyRef) {
    EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(pkeyRef);
    JNI_TRACE("EVP_PKEY_free(%p)", pkey);

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
}

static jint NativeCrypto_EVP_PKEY_cmp(JNIEnv* env, jclass, jobject pkey1Ref, jobject pkey2Ref) {
    JNI_TRACE("EVP_PKEY_cmp(%p, %p)", pkey1Ref, pkey2Ref);
    EVP_PKEY* pkey1 = fromContextObject<EVP_PKEY>(env, pkey1Ref);
    if (pkey1 == NULL) {
        JNI_TRACE("EVP_PKEY_cmp => pkey1 == NULL");
        return 0;
    }
    EVP_PKEY* pkey2 = fromContextObject<EVP_PKEY>(env, pkey2Ref);
    if (pkey2 == NULL) {
        JNI_TRACE("EVP_PKEY_cmp => pkey2 == NULL");
        return 0;
    }
    JNI_TRACE("EVP_PKEY_cmp(%p, %p) <- ptr", pkey1, pkey2);

    int result = EVP_PKEY_cmp(pkey1, pkey2);
    JNI_TRACE("EVP_PKEY_cmp(%p, %p) => %d", pkey1, pkey2, result);
    return result;
}

/*
 * static native byte[] i2d_PKCS8_PRIV_KEY_INFO(int, byte[])
 */
static jbyteArray NativeCrypto_i2d_PKCS8_PRIV_KEY_INFO(JNIEnv* env, jclass, jobject pkeyRef) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("i2d_PKCS8_PRIV_KEY_INFO(%p)", pkey);

    if (pkey == NULL) {
        return NULL;
    }

    Unique_PKCS8_PRIV_KEY_INFO pkcs8(EVP_PKEY2PKCS8(pkey));
    if (pkcs8.get() == NULL) {
        throwExceptionIfNecessary(env, "NativeCrypto_i2d_PKCS8_PRIV_KEY_INFO");
        JNI_TRACE("key=%p i2d_PKCS8_PRIV_KEY_INFO => error from key to PKCS8", pkey);
        return NULL;
    }

    return ASN1ToByteArray<PKCS8_PRIV_KEY_INFO>(env, pkcs8.get(), i2d_PKCS8_PRIV_KEY_INFO);
}

/*
 * static native int d2i_PKCS8_PRIV_KEY_INFO(byte[])
 */
static jlong NativeCrypto_d2i_PKCS8_PRIV_KEY_INFO(JNIEnv* env, jclass, jbyteArray keyJavaBytes) {
    JNI_TRACE("d2i_PKCS8_PRIV_KEY_INFO(%p)", keyJavaBytes);

    ScopedByteArrayRO bytes(env, keyJavaBytes);
    if (bytes.get() == NULL) {
        JNI_TRACE("bytes=%p d2i_PKCS8_PRIV_KEY_INFO => threw exception", keyJavaBytes);
        return 0;
    }

    const unsigned char* tmp = reinterpret_cast<const unsigned char*>(bytes.get());
    Unique_PKCS8_PRIV_KEY_INFO pkcs8(d2i_PKCS8_PRIV_KEY_INFO(NULL, &tmp, bytes.size()));
    if (pkcs8.get() == NULL) {
        throwExceptionIfNecessary(env, "d2i_PKCS8_PRIV_KEY_INFO");
        JNI_TRACE("ssl=%p d2i_PKCS8_PRIV_KEY_INFO => error from DER to PKCS8", keyJavaBytes);
        return 0;
    }

    Unique_EVP_PKEY pkey(EVP_PKCS82PKEY(pkcs8.get()));
    if (pkey.get() == NULL) {
        throwExceptionIfNecessary(env, "d2i_PKCS8_PRIV_KEY_INFO");
        JNI_TRACE("ssl=%p d2i_PKCS8_PRIV_KEY_INFO => error from PKCS8 to key", keyJavaBytes);
        return 0;
    }

    JNI_TRACE("bytes=%p d2i_PKCS8_PRIV_KEY_INFO => %p", keyJavaBytes, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

/*
 * static native byte[] i2d_PUBKEY(int)
 */
static jbyteArray NativeCrypto_i2d_PUBKEY(JNIEnv* env, jclass, jobject pkeyRef) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("i2d_PUBKEY(%p)", pkey);
    if (pkey == NULL) {
        return NULL;
    }
    return ASN1ToByteArray<EVP_PKEY>(env, pkey, reinterpret_cast<int (*) (EVP_PKEY*, uint8_t **)>(i2d_PUBKEY));
}

/*
 * static native int d2i_PUBKEY(byte[])
 */
static jlong NativeCrypto_d2i_PUBKEY(JNIEnv* env, jclass, jbyteArray javaBytes) {
    JNI_TRACE("d2i_PUBKEY(%p)", javaBytes);

    ScopedByteArrayRO bytes(env, javaBytes);
    if (bytes.get() == NULL) {
        JNI_TRACE("d2i_PUBKEY(%p) => threw error", javaBytes);
        return 0;
    }

    const unsigned char* tmp = reinterpret_cast<const unsigned char*>(bytes.get());
    Unique_EVP_PKEY pkey(d2i_PUBKEY(NULL, &tmp, bytes.size()));
    if (pkey.get() == NULL) {
        JNI_TRACE("bytes=%p d2i_PUBKEY => threw exception", javaBytes);
        throwExceptionIfNecessary(env, "d2i_PUBKEY");
        return 0;
    }

    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jlong NativeCrypto_getRSAPrivateKeyWrapper(JNIEnv* env, jclass, jobject javaKey,
        jbyteArray modulusBytes) {
    JNI_TRACE("getRSAPrivateKeyWrapper(%p, %p)", javaKey, modulusBytes);

#if !defined(OPENSSL_IS_BORINGSSL)
    Unique_RSA rsa(RSA_new());
    if (rsa.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate RSA key");
        return 0;
    }

    RSA_set_method(rsa.get(), &android_rsa_method);

    if (!arrayToBignum(env, modulusBytes, &rsa->n)) {
        return 0;
    }

    RSA_set_app_data(rsa.get(), env->NewGlobalRef(javaKey));
#else
    size_t cached_size;
    if (!arrayToBignumSize(env, modulusBytes, &cached_size)) {
        JNI_TRACE("getRSAPrivateKeyWrapper failed");
        return 0;
    }

    ensure_engine_globals();

    Unique_RSA rsa(RSA_new_method(g_engine));
    if (rsa.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate RSA key");
        return 0;
    }

    KeyExData* ex_data = new KeyExData;
    ex_data->private_key = env->NewGlobalRef(javaKey);
    ex_data->cached_size = cached_size;
    RSA_set_ex_data(rsa.get(), g_rsa_exdata_index, ex_data);
#endif

    Unique_EVP_PKEY pkey(EVP_PKEY_new());
    if (pkey.get() == NULL) {
        JNI_TRACE("getRSAPrivateKeyWrapper failed");
        jniThrowRuntimeException(env, "NativeCrypto_getRSAPrivateKeyWrapper failed");
        freeOpenSslErrorState();
        return 0;
    }

    if (EVP_PKEY_assign_RSA(pkey.get(), rsa.get()) != 1) {
        jniThrowRuntimeException(env, "getRSAPrivateKeyWrapper failed");
        return 0;
    }
    OWNERSHIP_TRANSFERRED(rsa);
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jlong NativeCrypto_getECPrivateKeyWrapper(JNIEnv* env, jclass, jobject javaKey,
                                                 jobject groupRef) {
    EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("getECPrivateKeyWrapper(%p, %p)", javaKey, group);
    if (group == NULL) {
        return 0;
    }

#if !defined(OPENSSL_IS_BORINGSSL)
    Unique_EC_KEY ecKey(EC_KEY_new());
    if (ecKey.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate EC key");
        return 0;
    }

    JNI_TRACE("EC_GROUP_get_curve_name(%p)", group);

    if (group == NULL) {
        JNI_TRACE("EC_GROUP_get_curve_name => group == NULL");
        jniThrowNullPointerException(env, "group == NULL");
        return 0;
    }

    EC_KEY_set_group(ecKey.get(), group);

    ECDSA_set_method(ecKey.get(), &android_ecdsa_method);
    ECDSA_set_ex_data(ecKey.get(), EcdsaGetExDataIndex(), env->NewGlobalRef(javaKey));
#else
    ensure_engine_globals();

    Unique_EC_KEY ecKey(EC_KEY_new_method(g_engine));
    if (ecKey.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate EC key");
        return 0;
    }

    KeyExData* ex_data = new KeyExData;
    ex_data->private_key = env->NewGlobalRef(javaKey);

    BIGNUM order;
    BN_init(&order);
    if (!EC_GROUP_get_order(group, &order, NULL)) {
        BN_free(&order);
        jniThrowRuntimeException(env, "EC_GROUP_get_order failed");
        return 0;
    }
    ex_data->cached_size = BN_num_bytes(&order);
    BN_free(&order);
#endif

    Unique_EVP_PKEY pkey(EVP_PKEY_new());
    if (pkey.get() == NULL) {
        JNI_TRACE("getECPrivateKeyWrapper failed");
        jniThrowRuntimeException(env, "NativeCrypto_getECPrivateKeyWrapper failed");
        freeOpenSslErrorState();
        return 0;
    }

    if (EVP_PKEY_assign_EC_KEY(pkey.get(), ecKey.get()) != 1) {
        jniThrowRuntimeException(env, "getECPrivateKeyWrapper failed");
        return 0;
    }
    OWNERSHIP_TRANSFERRED(ecKey);
    return reinterpret_cast<uintptr_t>(pkey.release());
}

/*
 * public static native int RSA_generate_key(int modulusBits, byte[] publicExponent);
 */
static jlong NativeCrypto_RSA_generate_key_ex(JNIEnv* env, jclass, jint modulusBits,
        jbyteArray publicExponent) {
    JNI_TRACE("RSA_generate_key_ex(%d, %p)", modulusBits, publicExponent);

    BIGNUM* eRef = NULL;
    if (!arrayToBignum(env, publicExponent, &eRef)) {
        return 0;
    }
    Unique_BIGNUM e(eRef);

    Unique_RSA rsa(RSA_new());
    if (rsa.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate RSA key");
        return 0;
    }

    if (RSA_generate_key_ex(rsa.get(), modulusBits, e.get(), NULL) < 0) {
        throwExceptionIfNecessary(env, "RSA_generate_key_ex");
        return 0;
    }

    Unique_EVP_PKEY pkey(EVP_PKEY_new());
    if (pkey.get() == NULL) {
        jniThrowRuntimeException(env, "RSA_generate_key_ex failed");
        return 0;
    }

    if (EVP_PKEY_assign_RSA(pkey.get(), rsa.get()) != 1) {
        jniThrowRuntimeException(env, "RSA_generate_key_ex failed");
        return 0;
    }

    OWNERSHIP_TRANSFERRED(rsa);
    JNI_TRACE("RSA_generate_key_ex(n=%d, e=%p) => %p", modulusBits, publicExponent, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jint NativeCrypto_RSA_size(JNIEnv* env, jclass, jobject pkeyRef) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("RSA_size(%p)", pkey);

    if (pkey == NULL) {
        return 0;
    }

    Unique_RSA rsa(EVP_PKEY_get1_RSA(pkey));
    if (rsa.get() == NULL) {
        jniThrowRuntimeException(env, "RSA_size failed");
        return 0;
    }

    return static_cast<jint>(RSA_size(rsa.get()));
}

typedef int RSACryptOperation(int flen, const unsigned char* from, unsigned char* to, RSA* rsa,
                              int padding);

static jint RSA_crypt_operation(RSACryptOperation operation,
        const char* caller __attribute__ ((unused)), JNIEnv* env, jint flen,
        jbyteArray fromJavaBytes, jbyteArray toJavaBytes, jobject pkeyRef, jint padding) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("%s(%d, %p, %p, %p)", caller, flen, fromJavaBytes, toJavaBytes, pkey);

    if (pkey == NULL) {
        return -1;
    }

    Unique_RSA rsa(EVP_PKEY_get1_RSA(pkey));
    if (rsa.get() == NULL) {
        return -1;
    }

    ScopedByteArrayRO from(env, fromJavaBytes);
    if (from.get() == NULL) {
        return -1;
    }

    ScopedByteArrayRW to(env, toJavaBytes);
    if (to.get() == NULL) {
        return -1;
    }

    int resultSize = operation(static_cast<int>(flen),
            reinterpret_cast<const unsigned char*>(from.get()),
            reinterpret_cast<unsigned char*>(to.get()), rsa.get(), padding);
    if (resultSize == -1) {
        JNI_TRACE("%s => failed", caller);
        throwExceptionIfNecessary(env, "RSA_crypt_operation");
        return -1;
    }

    JNI_TRACE("%s(%d, %p, %p, %p) => %d", caller, flen, fromJavaBytes, toJavaBytes, pkey,
              resultSize);
    return static_cast<jint>(resultSize);
}

static jint NativeCrypto_RSA_private_encrypt(JNIEnv* env, jclass, jint flen,
        jbyteArray fromJavaBytes, jbyteArray toJavaBytes, jobject pkeyRef, jint padding) {
    return RSA_crypt_operation(RSA_private_encrypt, __FUNCTION__,
                               env, flen, fromJavaBytes, toJavaBytes, pkeyRef, padding);
}
static jint NativeCrypto_RSA_public_decrypt(JNIEnv* env, jclass, jint flen,
        jbyteArray fromJavaBytes, jbyteArray toJavaBytes, jobject pkeyRef, jint padding) {
    return RSA_crypt_operation(RSA_public_decrypt, __FUNCTION__,
                               env, flen, fromJavaBytes, toJavaBytes, pkeyRef, padding);
}
static jint NativeCrypto_RSA_public_encrypt(JNIEnv* env, jclass, jint flen,
        jbyteArray fromJavaBytes, jbyteArray toJavaBytes, jobject pkeyRef, jint padding) {
    return RSA_crypt_operation(RSA_public_encrypt, __FUNCTION__,
                               env, flen, fromJavaBytes, toJavaBytes, pkeyRef, padding);
}
static jint NativeCrypto_RSA_private_decrypt(JNIEnv* env, jclass, jint flen,
        jbyteArray fromJavaBytes, jbyteArray toJavaBytes, jobject pkeyRef, jint padding) {
    return RSA_crypt_operation(RSA_private_decrypt, __FUNCTION__,
                               env, flen, fromJavaBytes, toJavaBytes, pkeyRef, padding);
}

/*
 * public static native byte[][] get_RSA_public_params(long);
 */
static jobjectArray NativeCrypto_get_RSA_public_params(JNIEnv* env, jclass, jobject pkeyRef) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("get_RSA_public_params(%p)", pkey);

    if (pkey == NULL) {
        return 0;
    }

    Unique_RSA rsa(EVP_PKEY_get1_RSA(pkey));
    if (rsa.get() == NULL) {
        throwExceptionIfNecessary(env, "get_RSA_public_params failed");
        return 0;
    }

    jobjectArray joa = env->NewObjectArray(2, byteArrayClass, NULL);
    if (joa == NULL) {
        return NULL;
    }

    jbyteArray n = bignumToArray(env, rsa->n, "n");
    if (env->ExceptionCheck()) {
        return NULL;
    }
    env->SetObjectArrayElement(joa, 0, n);

    jbyteArray e = bignumToArray(env, rsa->e, "e");
    if (env->ExceptionCheck()) {
        return NULL;
    }
    env->SetObjectArrayElement(joa, 1, e);

    return joa;
}

/*
 * public static native byte[][] get_RSA_private_params(long);
 */
static jobjectArray NativeCrypto_get_RSA_private_params(JNIEnv* env, jclass, jobject pkeyRef) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("get_RSA_public_params(%p)", pkey);

    if (pkey == NULL) {
        return 0;
    }

    Unique_RSA rsa(EVP_PKEY_get1_RSA(pkey));
    if (rsa.get() == NULL) {
        throwExceptionIfNecessary(env, "get_RSA_public_params failed");
        return 0;
    }

    jobjectArray joa = env->NewObjectArray(8, byteArrayClass, NULL);
    if (joa == NULL) {
        return NULL;
    }

    jbyteArray n = bignumToArray(env, rsa->n, "n");
    if (env->ExceptionCheck()) {
        return NULL;
    }
    env->SetObjectArrayElement(joa, 0, n);

    if (rsa->e != NULL) {
        jbyteArray e = bignumToArray(env, rsa->e, "e");
        if (env->ExceptionCheck()) {
            return NULL;
        }
        env->SetObjectArrayElement(joa, 1, e);
    }

    if (rsa->d != NULL) {
        jbyteArray d = bignumToArray(env, rsa->d, "d");
        if (env->ExceptionCheck()) {
            return NULL;
        }
        env->SetObjectArrayElement(joa, 2, d);
    }

    if (rsa->p != NULL) {
        jbyteArray p = bignumToArray(env, rsa->p, "p");
        if (env->ExceptionCheck()) {
            return NULL;
        }
        env->SetObjectArrayElement(joa, 3, p);
    }

    if (rsa->q != NULL) {
        jbyteArray q = bignumToArray(env, rsa->q, "q");
        if (env->ExceptionCheck()) {
            return NULL;
        }
        env->SetObjectArrayElement(joa, 4, q);
    }

    if (rsa->dmp1 != NULL) {
        jbyteArray dmp1 = bignumToArray(env, rsa->dmp1, "dmp1");
        if (env->ExceptionCheck()) {
            return NULL;
        }
        env->SetObjectArrayElement(joa, 5, dmp1);
    }

    if (rsa->dmq1 != NULL) {
        jbyteArray dmq1 = bignumToArray(env, rsa->dmq1, "dmq1");
        if (env->ExceptionCheck()) {
            return NULL;
        }
        env->SetObjectArrayElement(joa, 6, dmq1);
    }

    if (rsa->iqmp != NULL) {
        jbyteArray iqmp = bignumToArray(env, rsa->iqmp, "iqmp");
        if (env->ExceptionCheck()) {
            return NULL;
        }
        env->SetObjectArrayElement(joa, 7, iqmp);
    }

    return joa;
}

static jlong NativeCrypto_DH_generate_parameters_ex(JNIEnv* env, jclass, jint primeBits, jlong generator) {
    JNI_TRACE("DH_generate_parameters_ex(%d, %lld)", primeBits, (long long) generator);

    Unique_DH dh(DH_new());
    if (dh.get() == NULL) {
        JNI_TRACE("DH_generate_parameters_ex failed");
        jniThrowOutOfMemory(env, "Unable to allocate DH key");
        freeOpenSslErrorState();
        return 0;
    }

    JNI_TRACE("DH_generate_parameters_ex generating parameters");

    if (!DH_generate_parameters_ex(dh.get(), primeBits, generator, NULL)) {
        JNI_TRACE("DH_generate_parameters_ex => param generation failed");
        throwExceptionIfNecessary(env, "NativeCrypto_DH_generate_parameters_ex failed");
        return 0;
    }

    Unique_EVP_PKEY pkey(EVP_PKEY_new());
    if (pkey.get() == NULL) {
        JNI_TRACE("DH_generate_parameters_ex failed");
        jniThrowRuntimeException(env, "NativeCrypto_DH_generate_parameters_ex failed");
        freeOpenSslErrorState();
        return 0;
    }

    if (EVP_PKEY_assign_DH(pkey.get(), dh.get()) != 1) {
        JNI_TRACE("DH_generate_parameters_ex failed");
        throwExceptionIfNecessary(env, "NativeCrypto_DH_generate_parameters_ex failed");
        return 0;
    }

    OWNERSHIP_TRANSFERRED(dh);
    JNI_TRACE("DH_generate_parameters_ex(n=%d, g=%lld) => %p", primeBits, (long long) generator,
            pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static void NativeCrypto_DH_generate_key(JNIEnv* env, jclass, jobject pkeyRef) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("DH_generate_key(%p)", pkey);

    if (pkey == NULL) {
        return;
    }

    Unique_DH dh(EVP_PKEY_get1_DH(pkey));
    if (dh.get() == NULL) {
        JNI_TRACE("DH_generate_key failed");
        throwExceptionIfNecessary(env, "Unable to get DH key");
        freeOpenSslErrorState();
    }

    if (!DH_generate_key(dh.get())) {
        JNI_TRACE("DH_generate_key failed");
        throwExceptionIfNecessary(env, "NativeCrypto_DH_generate_key failed");
    }
}

static jobjectArray NativeCrypto_get_DH_params(JNIEnv* env, jclass, jobject pkeyRef) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("get_DH_params(%p)", pkey);

    if (pkey == NULL) {
        return NULL;
    }

    Unique_DH dh(EVP_PKEY_get1_DH(pkey));
    if (dh.get() == NULL) {
        throwExceptionIfNecessary(env, "get_DH_params failed");
        return 0;
    }

    jobjectArray joa = env->NewObjectArray(4, byteArrayClass, NULL);
    if (joa == NULL) {
        return NULL;
    }

    if (dh->p != NULL) {
        jbyteArray p = bignumToArray(env, dh->p, "p");
        if (env->ExceptionCheck()) {
            return NULL;
        }
        env->SetObjectArrayElement(joa, 0, p);
    }

    if (dh->g != NULL) {
        jbyteArray g = bignumToArray(env, dh->g, "g");
        if (env->ExceptionCheck()) {
            return NULL;
        }
        env->SetObjectArrayElement(joa, 1, g);
    }

    if (dh->pub_key != NULL) {
        jbyteArray pub_key = bignumToArray(env, dh->pub_key, "pub_key");
        if (env->ExceptionCheck()) {
            return NULL;
        }
        env->SetObjectArrayElement(joa, 2, pub_key);
    }

    if (dh->priv_key != NULL) {
        jbyteArray priv_key = bignumToArray(env, dh->priv_key, "priv_key");
        if (env->ExceptionCheck()) {
            return NULL;
        }
        env->SetObjectArrayElement(joa, 3, priv_key);
    }

    return joa;
}

#define EC_CURVE_GFP 1
#define EC_CURVE_GF2M 2

/**
 * Return group type or 0 if unknown group.
 * EC_GROUP_GFP or EC_GROUP_GF2M
 */
#if !defined(OPENSSL_IS_BORINGSSL)
static int get_EC_GROUP_type(const EC_GROUP* group)
{
    const EC_METHOD* method = EC_GROUP_method_of(group);
    if (method == EC_GFp_nist_method()
                || method == EC_GFp_mont_method()
                || method == EC_GFp_simple_method()) {
        return EC_CURVE_GFP;
    } else if (method == EC_GF2m_simple_method()) {
        return EC_CURVE_GF2M;
    }

    return 0;
}
#else
static int get_EC_GROUP_type(const EC_GROUP*)
{
    return EC_CURVE_GFP;
}
#endif

static jlong NativeCrypto_EC_GROUP_new_by_curve_name(JNIEnv* env, jclass, jstring curveNameJava)
{
    JNI_TRACE("EC_GROUP_new_by_curve_name(%p)", curveNameJava);

    ScopedUtfChars curveName(env, curveNameJava);
    if (curveName.c_str() == NULL) {
        return 0;
    }
    JNI_TRACE("EC_GROUP_new_by_curve_name(%s)", curveName.c_str());

    int nid = OBJ_sn2nid(curveName.c_str());
    if (nid == NID_undef) {
        JNI_TRACE("EC_GROUP_new_by_curve_name(%s) => unknown NID name", curveName.c_str());
        return 0;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        JNI_TRACE("EC_GROUP_new_by_curve_name(%s) => unknown NID %d", curveName.c_str(), nid);
        freeOpenSslErrorState();
        return 0;
    }

    JNI_TRACE("EC_GROUP_new_by_curve_name(%s) => %p", curveName.c_str(), group);
    return reinterpret_cast<uintptr_t>(group);
}

#if !defined(OPENSSL_IS_BORINGSSL)
static void NativeCrypto_EC_GROUP_set_asn1_flag(JNIEnv* env, jclass, jobject groupRef,
        jint flag)
{
    EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_set_asn1_flag(%p, %d)", group, flag);

    if (group == NULL) {
        JNI_TRACE("EC_GROUP_set_asn1_flag => group == NULL");
        return;
    }

    EC_GROUP_set_asn1_flag(group, flag);
    JNI_TRACE("EC_GROUP_set_asn1_flag(%p, %d) => success", group, flag);
}
#else
static void NativeCrypto_EC_GROUP_set_asn1_flag(JNIEnv*, jclass, jobject, jint)
{
}
#endif

#if !defined(OPENSSL_IS_BORINGSSL)
static void NativeCrypto_EC_GROUP_set_point_conversion_form(JNIEnv* env, jclass,
        jobject groupRef, jint form)
{
    EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_set_point_conversion_form(%p, %d)", group, form);

    if (group == NULL) {
        JNI_TRACE("EC_GROUP_set_point_conversion_form => group == NULL");
        return;
    }

    EC_GROUP_set_point_conversion_form(group, static_cast<point_conversion_form_t>(form));
    JNI_TRACE("EC_GROUP_set_point_conversion_form(%p, %d) => success", group, form);
}
#else
static void NativeCrypto_EC_GROUP_set_point_conversion_form(JNIEnv*, jclass, jobject, jint)
{
}
#endif

static jstring NativeCrypto_EC_GROUP_get_curve_name(JNIEnv* env, jclass, jobject groupRef) {
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_get_curve_name(%p)", group);

    if (group == NULL) {
        JNI_TRACE("EC_GROUP_get_curve_name => group == NULL");
        return 0;
    }

    int nid = EC_GROUP_get_curve_name(group);
    if (nid == NID_undef) {
        JNI_TRACE("EC_GROUP_get_curve_name(%p) => unnamed curve", group);
        return NULL;
    }

    const char* shortName = OBJ_nid2sn(nid);
    JNI_TRACE("EC_GROUP_get_curve_name(%p) => \"%s\"", group, shortName);
    return env->NewStringUTF(shortName);
}

static jobjectArray NativeCrypto_EC_GROUP_get_curve(JNIEnv* env, jclass, jobject groupRef)
{
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_get_curve(%p)", group);
    if (group == NULL) {
        JNI_TRACE("EC_GROUP_get_curve => group == NULL");
        return NULL;
    }

    Unique_BIGNUM p(BN_new());
    Unique_BIGNUM a(BN_new());
    Unique_BIGNUM b(BN_new());

    if (get_EC_GROUP_type(group) != EC_CURVE_GFP) {
        jniThrowRuntimeException(env, "invalid group");
        return NULL;
    }

    int ret = EC_GROUP_get_curve_GFp(group, p.get(), a.get(), b.get(), (BN_CTX*) NULL);
    if (ret != 1) {
        throwExceptionIfNecessary(env, "EC_GROUP_get_curve");
        return NULL;
    }

    jobjectArray joa = env->NewObjectArray(3, byteArrayClass, NULL);
    if (joa == NULL) {
        return NULL;
    }

    jbyteArray pArray = bignumToArray(env, p.get(), "p");
    if (env->ExceptionCheck()) {
        return NULL;
    }
    env->SetObjectArrayElement(joa, 0, pArray);

    jbyteArray aArray = bignumToArray(env, a.get(), "a");
    if (env->ExceptionCheck()) {
        return NULL;
    }
    env->SetObjectArrayElement(joa, 1, aArray);

    jbyteArray bArray = bignumToArray(env, b.get(), "b");
    if (env->ExceptionCheck()) {
        return NULL;
    }
    env->SetObjectArrayElement(joa, 2, bArray);

    JNI_TRACE("EC_GROUP_get_curve(%p) => %p", group, joa);
    return joa;
}

static jbyteArray NativeCrypto_EC_GROUP_get_order(JNIEnv* env, jclass, jobject groupRef)
{
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_get_order(%p)", group);
    if (group == NULL) {
        return NULL;
    }

    Unique_BIGNUM order(BN_new());
    if (order.get() == NULL) {
        JNI_TRACE("EC_GROUP_get_order(%p) => can't create BN", group);
        jniThrowOutOfMemory(env, "BN_new");
        return NULL;
    }

    if (EC_GROUP_get_order(group, order.get(), NULL) != 1) {
        JNI_TRACE("EC_GROUP_get_order(%p) => threw error", group);
        throwExceptionIfNecessary(env, "EC_GROUP_get_order");
        return NULL;
    }

    jbyteArray orderArray = bignumToArray(env, order.get(), "order");
    if (env->ExceptionCheck()) {
        return NULL;
    }

    JNI_TRACE("EC_GROUP_get_order(%p) => %p", group, orderArray);
    return orderArray;
}

static jint NativeCrypto_EC_GROUP_get_degree(JNIEnv* env, jclass, jobject groupRef)
{
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_get_degree(%p)", group);
    if (group == NULL) {
        return 0;
    }

    jint degree = EC_GROUP_get_degree(group);
    if (degree == 0) {
      JNI_TRACE("EC_GROUP_get_degree(%p) => unsupported", group);
      jniThrowRuntimeException(env, "not supported");
      return 0;
    }

    JNI_TRACE("EC_GROUP_get_degree(%p) => %d", group, degree);
    return degree;
}

static jbyteArray NativeCrypto_EC_GROUP_get_cofactor(JNIEnv* env, jclass, jobject groupRef)
{
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_get_cofactor(%p)", group);
    if (group == NULL) {
        return NULL;
    }

    Unique_BIGNUM cofactor(BN_new());
    if (cofactor.get() == NULL) {
        JNI_TRACE("EC_GROUP_get_cofactor(%p) => can't create BN", group);
        jniThrowOutOfMemory(env, "BN_new");
        return NULL;
    }

    if (EC_GROUP_get_cofactor(group, cofactor.get(), NULL) != 1) {
        JNI_TRACE("EC_GROUP_get_cofactor(%p) => threw error", group);
        throwExceptionIfNecessary(env, "EC_GROUP_get_cofactor");
        return NULL;
    }

    jbyteArray cofactorArray = bignumToArray(env, cofactor.get(), "cofactor");
    if (env->ExceptionCheck()) {
        return NULL;
    }

    JNI_TRACE("EC_GROUP_get_cofactor(%p) => %p", group, cofactorArray);
    return cofactorArray;
}

static jint NativeCrypto_get_EC_GROUP_type(JNIEnv* env, jclass, jobject groupRef)
{
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("get_EC_GROUP_type(%p)", group);
    if (group == NULL) {
        return 0;
    }

    int type = get_EC_GROUP_type(group);
    if (type == 0) {
        JNI_TRACE("get_EC_GROUP_type(%p) => curve type", group);
        jniThrowRuntimeException(env, "unknown curve type");
    } else {
        JNI_TRACE("get_EC_GROUP_type(%p) => %d", group, type);
    }
    return type;
}

static void NativeCrypto_EC_GROUP_clear_free(JNIEnv* env, jclass, jlong groupRef)
{
    EC_GROUP* group = reinterpret_cast<EC_GROUP*>(groupRef);
    JNI_TRACE("EC_GROUP_clear_free(%p)", group);

    if (group == NULL) {
        JNI_TRACE("EC_GROUP_clear_free => group == NULL");
        jniThrowNullPointerException(env, "group == NULL");
        return;
    }

    EC_GROUP_free(group);
    JNI_TRACE("EC_GROUP_clear_free(%p) => success", group);
}

static jboolean NativeCrypto_EC_GROUP_cmp(JNIEnv* env, jclass, jobject group1Ref,
                                          jobject group2Ref)
{
    JNI_TRACE("EC_GROUP_cmp(%p, %p)", group1Ref, group2Ref);
    const EC_GROUP* group1 = fromContextObject<EC_GROUP>(env, group1Ref);
    if (group1 == NULL) {
        return JNI_FALSE; 
    }
    const EC_GROUP* group2 = fromContextObject<EC_GROUP>(env, group2Ref);
    if (group2 == NULL) {
        return JNI_FALSE;
    }
    JNI_TRACE("EC_GROUP_cmp(%p, %p) <- ptr", group1, group2);

    int ret = EC_GROUP_cmp(group1, group2, NULL);

    JNI_TRACE("ECP_GROUP_cmp(%p, %p) => %d", group1, group2, ret);
    return ret == 0;
}

static jlong NativeCrypto_EC_GROUP_get_generator(JNIEnv* env, jclass, jobject groupRef)
{
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_get_generator(%p)", group);

    if (group == NULL) {
        JNI_TRACE("EC_POINT_get_generator(%p) => group == null", group);
        return 0;
    }

    const EC_POINT* generator = EC_GROUP_get0_generator(group);

    Unique_EC_POINT dup(EC_POINT_dup(generator, group));
    if (dup.get() == NULL) {
        JNI_TRACE("EC_GROUP_get_generator(%p) => oom error", group);
        jniThrowOutOfMemory(env, "unable to dupe generator");
        return 0;
    }

    JNI_TRACE("EC_GROUP_get_generator(%p) => %p", group, dup.get());
    return reinterpret_cast<uintptr_t>(dup.release());
}

static jlong NativeCrypto_EC_POINT_new(JNIEnv* env, jclass, jobject groupRef)
{
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_POINT_new(%p)", group);

    if (group == NULL) {
        JNI_TRACE("EC_POINT_new(%p) => group == null", group);
        return 0;
    }

    EC_POINT* point = EC_POINT_new(group);
    if (point == NULL) {
        jniThrowOutOfMemory(env, "Unable create an EC_POINT");
        return 0;
    }

    return reinterpret_cast<uintptr_t>(point);
}

static void NativeCrypto_EC_POINT_clear_free(JNIEnv* env, jclass, jlong groupRef) {
    EC_POINT* group = reinterpret_cast<EC_POINT*>(groupRef);
    JNI_TRACE("EC_POINT_clear_free(%p)", group);

    if (group == NULL) {
        JNI_TRACE("EC_POINT_clear_free => group == NULL");
        jniThrowNullPointerException(env, "group == NULL");
        return;
    }

    EC_POINT_free(group);
    JNI_TRACE("EC_POINT_clear_free(%p) => success", group);
}

static jboolean NativeCrypto_EC_POINT_cmp(JNIEnv* env, jclass, jobject groupRef, jobject point1Ref,
                                          jobject point2Ref)
{
    JNI_TRACE("EC_POINT_cmp(%p, %p, %p)", groupRef, point1Ref, point2Ref);
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    if (group == NULL) {
        return JNI_FALSE;
    }
    const EC_POINT* point1 = fromContextObject<EC_POINT>(env, point1Ref);
    if (point1 == NULL) {
        return JNI_FALSE;
    }
    const EC_POINT* point2 = fromContextObject<EC_POINT>(env, point2Ref);
    if (point2 == NULL) {
        return JNI_FALSE;
    }
    JNI_TRACE("EC_POINT_cmp(%p, %p, %p) <- ptr", group, point1, point2);

    int ret = EC_POINT_cmp(group, point1, point2, (BN_CTX*)NULL);

    JNI_TRACE("ECP_GROUP_cmp(%p, %p) => %d", point1, point2, ret);
    return ret == 0;
}

static void NativeCrypto_EC_POINT_set_affine_coordinates(JNIEnv* env, jclass,
        jobject groupRef, jobject pointRef, jbyteArray xjavaBytes, jbyteArray yjavaBytes)
{
    JNI_TRACE("EC_POINT_set_affine_coordinates(%p, %p, %p, %p)", groupRef, pointRef, xjavaBytes,
            yjavaBytes);
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    if (group == NULL) {
        return;
    }
    EC_POINT* point = fromContextObject<EC_POINT>(env, pointRef);
    if (point == NULL) {
        return;
    }
    JNI_TRACE("EC_POINT_set_affine_coordinates(%p, %p, %p, %p) <- ptr", group, point, xjavaBytes,
            yjavaBytes);

    BIGNUM* xRef = NULL;
    if (!arrayToBignum(env, xjavaBytes, &xRef)) {
        return;
    }
    Unique_BIGNUM x(xRef);

    BIGNUM* yRef = NULL;
    if (!arrayToBignum(env, yjavaBytes, &yRef)) {
        return;
    }
    Unique_BIGNUM y(yRef);

    int ret;
    switch (get_EC_GROUP_type(group)) {
    case EC_CURVE_GFP:
        ret = EC_POINT_set_affine_coordinates_GFp(group, point, x.get(), y.get(), NULL);
        break;
#if !defined(OPENSSL_IS_BORINGSSL)
    case EC_CURVE_GF2M:
        ret = EC_POINT_set_affine_coordinates_GF2m(group, point, x.get(), y.get(), NULL);
        break;
#endif
    default:
        jniThrowRuntimeException(env, "invalid curve type");
        return;
    }

    if (ret != 1) {
        throwExceptionIfNecessary(env, "EC_POINT_set_affine_coordinates");
    }

    JNI_TRACE("EC_POINT_set_affine_coordinates(%p, %p, %p, %p) => %d", group, point,
            xjavaBytes, yjavaBytes, ret);
}

static jobjectArray NativeCrypto_EC_POINT_get_affine_coordinates(JNIEnv* env, jclass,
        jobject groupRef, jobject pointRef)
{
    JNI_TRACE("EC_POINT_get_affine_coordinates(%p, %p)", groupRef, pointRef);
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    if (group == NULL) {
        return NULL;
    }
    const EC_POINT* point = fromContextObject<EC_POINT>(env, pointRef);
    if (point == NULL) {
        return NULL;
    }
    JNI_TRACE("EC_POINT_get_affine_coordinates(%p, %p) <- ptr", group, point);

    Unique_BIGNUM x(BN_new());
    Unique_BIGNUM y(BN_new());

    int ret;
    switch (get_EC_GROUP_type(group)) {
    case EC_CURVE_GFP:
        ret = EC_POINT_get_affine_coordinates_GFp(group, point, x.get(), y.get(), NULL);
        break;
    default:
        jniThrowRuntimeException(env, "invalid curve type");
        return NULL;
    }
    if (ret != 1) {
        JNI_TRACE("EC_POINT_get_affine_coordinates(%p, %p)", group, point);
        throwExceptionIfNecessary(env, "EC_POINT_get_affine_coordinates");
        return NULL;
    }

    jobjectArray joa = env->NewObjectArray(2, byteArrayClass, NULL);
    if (joa == NULL) {
        return NULL;
    }

    jbyteArray xBytes = bignumToArray(env, x.get(), "x");
    if (env->ExceptionCheck()) {
        return NULL;
    }
    env->SetObjectArrayElement(joa, 0, xBytes);

    jbyteArray yBytes = bignumToArray(env, y.get(), "y");
    if (env->ExceptionCheck()) {
        return NULL;
    }
    env->SetObjectArrayElement(joa, 1, yBytes);

    JNI_TRACE("EC_POINT_get_affine_coordinates(%p, %p) => %p", group, point, joa);
    return joa;
}

static jlong NativeCrypto_EC_KEY_generate_key(JNIEnv* env, jclass, jobject groupRef)
{
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_KEY_generate_key(%p)", group);
    if (group == NULL) {
        return 0;
    }

    Unique_EC_KEY eckey(EC_KEY_new());
    if (eckey.get() == NULL) {
        JNI_TRACE("EC_KEY_generate_key(%p) => EC_KEY_new() oom", group);
        jniThrowOutOfMemory(env, "Unable to create an EC_KEY");
        return 0;
    }

    if (EC_KEY_set_group(eckey.get(), group) != 1) {
        JNI_TRACE("EC_KEY_generate_key(%p) => EC_KEY_set_group error", group);
        throwExceptionIfNecessary(env, "EC_KEY_set_group");
        return 0;
    }

    if (EC_KEY_generate_key(eckey.get()) != 1) {
        JNI_TRACE("EC_KEY_generate_key(%p) => EC_KEY_generate_key error", group);
        throwExceptionIfNecessary(env, "EC_KEY_set_group");
        return 0;
    }

    Unique_EVP_PKEY pkey(EVP_PKEY_new());
    if (pkey.get() == NULL) {
        JNI_TRACE("EC_KEY_generate_key(%p) => threw error", group);
        throwExceptionIfNecessary(env, "EC_KEY_generate_key");
        return 0;
    }
    if (EVP_PKEY_assign_EC_KEY(pkey.get(), eckey.get()) != 1) {
        jniThrowRuntimeException(env, "EVP_PKEY_assign_EC_KEY failed");
        return 0;
    }
    OWNERSHIP_TRANSFERRED(eckey);

    JNI_TRACE("EC_KEY_generate_key(%p) => %p", group, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jlong NativeCrypto_EC_KEY_get1_group(JNIEnv* env, jclass, jobject pkeyRef)
{
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EC_KEY_get1_group(%p)", pkey);

    if (pkey == NULL) {
        JNI_TRACE("EC_KEY_get1_group(%p) => pkey == null", pkey);
        return 0;
    }

    if (EVP_PKEY_type(pkey->type) != EVP_PKEY_EC) {
        jniThrowRuntimeException(env, "not EC key");
        JNI_TRACE("EC_KEY_get1_group(%p) => not EC key (type == %d)", pkey,
                EVP_PKEY_type(pkey->type));
        return 0;
    }

    EC_GROUP* group = EC_GROUP_dup(EC_KEY_get0_group(pkey->pkey.ec));
    JNI_TRACE("EC_KEY_get1_group(%p) => %p", pkey, group);
    return reinterpret_cast<uintptr_t>(group);
}

static jbyteArray NativeCrypto_EC_KEY_get_private_key(JNIEnv* env, jclass, jobject pkeyRef)
{
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EC_KEY_get_private_key(%p)", pkey);

    if (pkey == NULL) {
        JNI_TRACE("EC_KEY_get_private_key => pkey == NULL");
        return NULL;
    }

    Unique_EC_KEY eckey(EVP_PKEY_get1_EC_KEY(pkey));
    if (eckey.get() == NULL) {
        throwExceptionIfNecessary(env, "EVP_PKEY_get1_EC_KEY");
        return NULL;
    }

    const BIGNUM *privkey = EC_KEY_get0_private_key(eckey.get());

    jbyteArray privBytes = bignumToArray(env, privkey, "privkey");
    if (env->ExceptionCheck()) {
        JNI_TRACE("EC_KEY_get_private_key(%p) => threw error", pkey);
        return NULL;
    }

    JNI_TRACE("EC_KEY_get_private_key(%p) => %p", pkey, privBytes);
    return privBytes;
}

static jlong NativeCrypto_EC_KEY_get_public_key(JNIEnv* env, jclass, jobject pkeyRef)
{
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EC_KEY_get_public_key(%p)", pkey);

    if (pkey == NULL) {
        JNI_TRACE("EC_KEY_get_public_key => pkey == NULL");
        return 0;
    }

    Unique_EC_KEY eckey(EVP_PKEY_get1_EC_KEY(pkey));
    if (eckey.get() == NULL) {
        throwExceptionIfNecessary(env, "EVP_PKEY_get1_EC_KEY");
        return 0;
    }

    Unique_EC_POINT dup(EC_POINT_dup(EC_KEY_get0_public_key(eckey.get()),
            EC_KEY_get0_group(eckey.get())));
    if (dup.get() == NULL) {
        JNI_TRACE("EC_KEY_get_public_key(%p) => can't dup public key", pkey);
        jniThrowRuntimeException(env, "EC_POINT_dup");
        return 0;
    }

    JNI_TRACE("EC_KEY_get_public_key(%p) => %p", pkey, dup.get());
    return reinterpret_cast<uintptr_t>(dup.release());
}

#if !defined(OPENSSL_IS_BORINGSSL)
static void NativeCrypto_EC_KEY_set_nonce_from_hash(JNIEnv* env, jclass, jobject pkeyRef,
        jboolean enabled)
{
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EC_KEY_set_nonce_from_hash(%p, %d)", pkey, enabled ? 1 : 0);

    if (pkey == NULL) {
        JNI_TRACE("EC_KEY_set_nonce_from_hash => pkey == NULL");
        return;
    }

    Unique_EC_KEY eckey(EVP_PKEY_get1_EC_KEY(pkey));
    if (eckey.get() == NULL) {
        throwExceptionIfNecessary(env, "EVP_PKEY_get1_EC_KEY");
        return;
    }

    EC_KEY_set_nonce_from_hash(eckey.get(), enabled ? 1 : 0);
}
#else
static void NativeCrypto_EC_KEY_set_nonce_from_hash(JNIEnv*, jclass, jobject, jboolean)
{
}
#endif

static jint NativeCrypto_ECDH_compute_key(JNIEnv* env, jclass,
     jbyteArray outArray, jint outOffset, jobject pubkeyRef, jobject privkeyRef)
{
    JNI_TRACE("ECDH_compute_key(%p, %d, %p, %p)", outArray, outOffset, pubkeyRef, privkeyRef);
    EVP_PKEY* pubPkey = fromContextObject<EVP_PKEY>(env, pubkeyRef);
    if (pubPkey == NULL) {
        JNI_TRACE("ECDH_compute_key => pubPkey == NULL");
        return -1;
    }
    EVP_PKEY* privPkey = fromContextObject<EVP_PKEY>(env, privkeyRef);
    if (privPkey == NULL) {
        JNI_TRACE("ECDH_compute_key => privPkey == NULL");
        return -1;
    }
    JNI_TRACE("ECDH_compute_key(%p, %d, %p, %p) <- ptr", outArray, outOffset, pubPkey, privPkey);

    ScopedByteArrayRW out(env, outArray);
    if (out.get() == NULL) {
        JNI_TRACE("ECDH_compute_key(%p, %d, %p, %p) can't get output buffer",
                outArray, outOffset, pubPkey, privPkey);
        return -1;
    }

    if ((outOffset < 0) || ((size_t) outOffset >= out.size())) {
        jniThrowException(env, "java/lang/ArrayIndexOutOfBoundsException", NULL);
        return -1;
    }

    if (pubPkey == NULL) {
        jniThrowNullPointerException(env, "pubPkey == null");
        return -1;
    }

    Unique_EC_KEY pubkey(EVP_PKEY_get1_EC_KEY(pubPkey));
    if (pubkey.get() == NULL) {
        JNI_TRACE("ECDH_compute_key(%p) => can't get public key", pubPkey);
        throwExceptionIfNecessary(env, "EVP_PKEY_get1_EC_KEY public");
        return -1;
    }

    const EC_POINT* pubkeyPoint = EC_KEY_get0_public_key(pubkey.get());
    if (pubkeyPoint == NULL) {
        JNI_TRACE("ECDH_compute_key(%p) => can't get public key point", pubPkey);
        throwExceptionIfNecessary(env, "EVP_PKEY_get1_EC_KEY public");
        return -1;
    }

    if (privPkey == NULL) {
        jniThrowNullPointerException(env, "privPkey == null");
        return -1;
    }

    Unique_EC_KEY privkey(EVP_PKEY_get1_EC_KEY(privPkey));
    if (privkey.get() == NULL) {
        throwExceptionIfNecessary(env, "EVP_PKEY_get1_EC_KEY private");
        return -1;
    }

    int outputLength = ECDH_compute_key(
            &out[outOffset],
            out.size() - outOffset,
            pubkeyPoint,
            privkey.get(),
            NULL // No KDF
            );
    if (outputLength == -1) {
        throwExceptionIfNecessary(env, "ECDH_compute_key");
        return -1;
    }

    return outputLength;
}

static jlong NativeCrypto_EVP_MD_CTX_create(JNIEnv* env, jclass) {
    JNI_TRACE_MD("EVP_MD_CTX_create()");

    Unique_EVP_MD_CTX ctx(EVP_MD_CTX_create());
    if (ctx.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable create a EVP_MD_CTX");
        return 0;
    }

    JNI_TRACE_MD("EVP_MD_CTX_create() => %p", ctx.get());
    return reinterpret_cast<uintptr_t>(ctx.release());
}

static void NativeCrypto_EVP_MD_CTX_init(JNIEnv* env, jclass, jobject ctxRef) {
    EVP_MD_CTX* ctx = fromContextObject<EVP_MD_CTX>(env, ctxRef);
    JNI_TRACE_MD("EVP_MD_CTX_init(%p)", ctx);

    if (ctx != NULL) {
        EVP_MD_CTX_init(ctx);
    }
}

static void NativeCrypto_EVP_MD_CTX_destroy(JNIEnv*, jclass, jlong ctxRef) {
    EVP_MD_CTX* ctx = reinterpret_cast<EVP_MD_CTX*>(ctxRef);
    JNI_TRACE_MD("EVP_MD_CTX_destroy(%p)", ctx);

    if (ctx != NULL) {
        EVP_MD_CTX_destroy(ctx);
    }
}

static jint NativeCrypto_EVP_MD_CTX_copy(JNIEnv* env, jclass, jobject dstCtxRef, jobject srcCtxRef) {
    JNI_TRACE_MD("EVP_MD_CTX_copy(%p. %p)", dstCtxRef, srcCtxRef);
    EVP_MD_CTX* dst_ctx = fromContextObject<EVP_MD_CTX>(env, dstCtxRef);
    if (dst_ctx == NULL) {
        JNI_TRACE_MD("EVP_MD_CTX_copy => dst_ctx == NULL");
        return 0;
    }
    const EVP_MD_CTX* src_ctx = fromContextObject<EVP_MD_CTX>(env, srcCtxRef);
    if (src_ctx == NULL) {
        JNI_TRACE_MD("EVP_MD_CTX_copy => src_ctx == NULL");
        return 0;
    }
    JNI_TRACE_MD("EVP_MD_CTX_copy(%p. %p) <- ptr", dst_ctx, src_ctx);

    int result = EVP_MD_CTX_copy_ex(dst_ctx, src_ctx);
    if (result == 0) {
        jniThrowRuntimeException(env, "Unable to copy EVP_MD_CTX");
        freeOpenSslErrorState();
    }

    JNI_TRACE_MD("EVP_MD_CTX_copy(%p, %p) => %d", dst_ctx, src_ctx, result);
    return result;
}

/*
 * public static native int EVP_DigestFinal(long, byte[], int)
 */
static jint NativeCrypto_EVP_DigestFinal(JNIEnv* env, jclass, jobject ctxRef, jbyteArray hash,
        jint offset) {
    EVP_MD_CTX* ctx = fromContextObject<EVP_MD_CTX>(env, ctxRef);
    JNI_TRACE_MD("EVP_DigestFinal(%p, %p, %d)", ctx, hash, offset);

    if (ctx == NULL) {
        JNI_TRACE("EVP_DigestFinal => ctx == NULL");
        return -1;
    } else if (hash == NULL) {
        jniThrowNullPointerException(env, "hash == null");
        return -1;
    }

    ScopedByteArrayRW hashBytes(env, hash);
    if (hashBytes.get() == NULL) {
        return -1;
    }
    unsigned int bytesWritten = -1;
    int ok = EVP_DigestFinal_ex(ctx,
                             reinterpret_cast<unsigned char*>(hashBytes.get() + offset),
                             &bytesWritten);
    if (ok == 0) {
        throwExceptionIfNecessary(env, "EVP_DigestFinal");
    }

    JNI_TRACE_MD("EVP_DigestFinal(%p, %p, %d) => %d (%d)", ctx, hash, offset, bytesWritten, ok);
    return bytesWritten;
}

static jint evpInit(JNIEnv* env, jobject evpMdCtxRef, jlong evpMdRef, const char* jniName,
        int (*init_func)(EVP_MD_CTX*, const EVP_MD*, ENGINE*)) {
    EVP_MD_CTX* ctx = fromContextObject<EVP_MD_CTX>(env, evpMdCtxRef);
    const EVP_MD* evp_md = reinterpret_cast<const EVP_MD*>(evpMdRef);
    JNI_TRACE_MD("%s(%p, %p)", jniName, ctx, evp_md);

    if (ctx == NULL) {
        JNI_TRACE("%s(%p) => ctx == NULL", jniName, evp_md);
        return 0;
    } else if (evp_md == NULL) {
        jniThrowNullPointerException(env, "evp_md == null");
        return 0;
    }

    int ok = init_func(ctx, evp_md, NULL);
    if (ok == 0) {
        bool exception = throwExceptionIfNecessary(env, jniName);
        if (exception) {
            JNI_TRACE("%s(%p) => threw exception", jniName, evp_md);
            return 0;
        }
    }
    JNI_TRACE_MD("%s(%p, %p) => %d", jniName, ctx, evp_md, ok);
    return ok;
}

static jint NativeCrypto_EVP_DigestInit(JNIEnv* env, jclass, jobject evpMdCtxRef, jlong evpMdRef) {
    return evpInit(env, evpMdCtxRef, evpMdRef, "EVP_DigestInit", EVP_DigestInit_ex);
}

static jint NativeCrypto_EVP_SignInit(JNIEnv* env, jclass, jobject evpMdCtxRef, jlong evpMdRef) {
    return evpInit(env, evpMdCtxRef, evpMdRef, "EVP_SignInit", EVP_DigestInit_ex);
}

static jint NativeCrypto_EVP_VerifyInit(JNIEnv* env, jclass, jobject evpMdCtxRef, jlong evpMdRef) {
    return evpInit(env, evpMdCtxRef, evpMdRef, "EVP_VerifyInit", EVP_DigestInit_ex);
}

/*
 * public static native int EVP_get_digestbyname(java.lang.String)
 */
static jlong NativeCrypto_EVP_get_digestbyname(JNIEnv* env, jclass, jstring algorithm) {
    JNI_TRACE("NativeCrypto_EVP_get_digestbyname(%p)", algorithm);

    if (algorithm == NULL) {
        jniThrowNullPointerException(env, NULL);
        return -1;
    }

    ScopedUtfChars algorithmChars(env, algorithm);
    if (algorithmChars.c_str() == NULL) {
        return 0;
    }
    JNI_TRACE("NativeCrypto_EVP_get_digestbyname(%s)", algorithmChars.c_str());

#if !defined(OPENSSL_IS_BORINGSSL)
    const EVP_MD* evp_md = EVP_get_digestbyname(algorithmChars.c_str());
    if (evp_md == NULL) {
        jniThrowRuntimeException(env, "Hash algorithm not found");
        return 0;
    }

    JNI_TRACE("NativeCrypto_EVP_get_digestbyname(%s) => %p", algorithmChars.c_str(), evp_md);
    return reinterpret_cast<uintptr_t>(evp_md);
#else
    const char *alg = algorithmChars.c_str();
    const EVP_MD *md;

    if (strcasecmp(alg, "md4") == 0) {
        md = EVP_md4();
    } else if (strcasecmp(alg, "md5") == 0) {
        md = EVP_md5();
    } else if (strcasecmp(alg, "sha1") == 0) {
        md = EVP_sha1();
    } else if (strcasecmp(alg, "sha224") == 0) {
        md = EVP_sha224();
    } else if (strcasecmp(alg, "sha256") == 0) {
        md = EVP_sha256();
    } else if (strcasecmp(alg, "sha384") == 0) {
        md = EVP_sha384();
    } else if (strcasecmp(alg, "sha512") == 0) {
        md = EVP_sha512();
    } else {
        JNI_TRACE("NativeCrypto_EVP_get_digestbyname(%s) => error", alg);
        jniThrowRuntimeException(env, "Hash algorithm not found");
        return 0;
    }

    return reinterpret_cast<uintptr_t>(md);
#endif
}

/*
 * public static native int EVP_MD_size(long)
 */
static jint NativeCrypto_EVP_MD_size(JNIEnv* env, jclass, jlong evpMdRef) {
    EVP_MD* evp_md = reinterpret_cast<EVP_MD*>(evpMdRef);
    JNI_TRACE("NativeCrypto_EVP_MD_size(%p)", evp_md);

    if (evp_md == NULL) {
        jniThrowNullPointerException(env, NULL);
        return -1;
    }

    int result = EVP_MD_size(evp_md);
    JNI_TRACE("NativeCrypto_EVP_MD_size(%p) => %d", evp_md, result);
    return result;
}

/*
 * public static int void EVP_MD_block_size(long)
 */
static jint NativeCrypto_EVP_MD_block_size(JNIEnv* env, jclass, jlong evpMdRef) {
    EVP_MD* evp_md = reinterpret_cast<EVP_MD*>(evpMdRef);
    JNI_TRACE("NativeCrypto_EVP_MD_block_size(%p)", evp_md);

    if (evp_md == NULL) {
        jniThrowNullPointerException(env, NULL);
        return -1;
    }

    int result = EVP_MD_block_size(evp_md);
    JNI_TRACE("NativeCrypto_EVP_MD_block_size(%p) => %d", evp_md, result);
    return result;
}

static void NativeCrypto_EVP_DigestSignInit(JNIEnv* env, jclass, jobject evpMdCtxRef,
        const jlong evpMdRef, jobject pkeyRef) {
    EVP_MD_CTX* mdCtx = fromContextObject<EVP_MD_CTX>(env, evpMdCtxRef);
    if (mdCtx == NULL) {
        JNI_TRACE("EVP_DigestSignInit => mdCtx == NULL");
        return;
    }
    const EVP_MD* md = reinterpret_cast<const EVP_MD*>(evpMdRef);
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    if (pkey == NULL) {
        JNI_TRACE("ctx=%p EVP_DigestSignInit => pkey == NULL", mdCtx);
        return;
    }
    JNI_TRACE("EVP_DigestSignInit(%p, %p, %p) <- ptr", mdCtx, md, pkey);

    if (md == NULL) {
        JNI_TRACE("ctx=%p EVP_DigestSignInit => md == NULL", mdCtx);
        jniThrowNullPointerException(env, "md == null");
        return;
    }

    if (EVP_DigestSignInit(mdCtx, (EVP_PKEY_CTX **) NULL, md, (ENGINE *) NULL, pkey) <= 0) {
        JNI_TRACE("ctx=%p EVP_DigestSignInit => threw exception", mdCtx);
        throwExceptionIfNecessary(env, "EVP_DigestSignInit");
        return;
    }

    JNI_TRACE("EVP_DigestSignInit(%p, %p, %p) => success", mdCtx, md, pkey);
}

static void evpUpdate(JNIEnv* env, jobject evpMdCtxRef, jbyteArray inJavaBytes, jint inOffset,
        jint inLength, const char *jniName, int (*update_func)(EVP_MD_CTX*, const void *,
        size_t))
{
    EVP_MD_CTX* mdCtx = fromContextObject<EVP_MD_CTX>(env, evpMdCtxRef);
    JNI_TRACE_MD("%s(%p, %p, %d, %d)", jniName, mdCtx, inJavaBytes, inOffset, inLength);

    if (mdCtx == NULL) {
         return;
    }

    ScopedByteArrayRO inBytes(env, inJavaBytes);
    if (inBytes.get() == NULL) {
        return;
    }

    if (inOffset < 0 || size_t(inOffset) > inBytes.size()) {
        jniThrowException(env, "java/lang/ArrayIndexOutOfBoundsException", "inOffset");
        return;
    }

    const ssize_t inEnd = inOffset + inLength;
    if (inLength < 0 || inEnd < 0 || size_t(inEnd) > inBytes.size()) {
        jniThrowException(env, "java/lang/ArrayIndexOutOfBoundsException", "inLength");
        return;
    }

    const unsigned char *tmp = reinterpret_cast<const unsigned char *>(inBytes.get());
    if (!update_func(mdCtx, tmp + inOffset, inLength)) {
        JNI_TRACE("ctx=%p %s => threw exception", mdCtx, jniName);
        throwExceptionIfNecessary(env, jniName);
    }

    JNI_TRACE_MD("%s(%p, %p, %d, %d) => success", jniName, mdCtx, inJavaBytes, inOffset, inLength);
}

static void NativeCrypto_EVP_DigestUpdate(JNIEnv* env, jclass, jobject evpMdCtxRef,
        jbyteArray inJavaBytes, jint inOffset, jint inLength) {
    evpUpdate(env, evpMdCtxRef, inJavaBytes, inOffset, inLength, "EVP_DigestUpdate",
            EVP_DigestUpdate);
}

static void NativeCrypto_EVP_DigestSignUpdate(JNIEnv* env, jclass, jobject evpMdCtxRef,
        jbyteArray inJavaBytes, jint inOffset, jint inLength) {
    evpUpdate(env, evpMdCtxRef, inJavaBytes, inOffset, inLength, "EVP_DigestSignUpdate",
            EVP_DigestUpdate);
}

static void NativeCrypto_EVP_SignUpdate(JNIEnv* env, jclass, jobject evpMdCtxRef,
        jbyteArray inJavaBytes, jint inOffset, jint inLength) {
    evpUpdate(env, evpMdCtxRef, inJavaBytes, inOffset, inLength, "EVP_SignUpdate",
            EVP_DigestUpdate);
}

static jbyteArray NativeCrypto_EVP_DigestSignFinal(JNIEnv* env, jclass, jobject evpMdCtxRef)
{
    EVP_MD_CTX* mdCtx = fromContextObject<EVP_MD_CTX>(env, evpMdCtxRef);
    JNI_TRACE("EVP_DigestSignFinal(%p)", mdCtx);

    if (mdCtx == NULL) {
         return NULL;
    }

    size_t len;
    if (EVP_DigestSignFinal(mdCtx, NULL, &len) != 1) {
        JNI_TRACE("ctx=%p EVP_DigestSignFinal => threw exception", mdCtx);
        throwExceptionIfNecessary(env, "EVP_DigestSignFinal");
        return 0;
    }
    ScopedLocalRef<jbyteArray> outJavaBytes(env, env->NewByteArray(len));
    if (outJavaBytes.get() == NULL) {
        return NULL;
    }
    ScopedByteArrayRW outBytes(env, outJavaBytes.get());
    if (outBytes.get() == NULL) {
        return NULL;
    }
    unsigned char *tmp = reinterpret_cast<unsigned char*>(outBytes.get());
    if (EVP_DigestSignFinal(mdCtx, tmp, &len) != 1) {
        JNI_TRACE("ctx=%p EVP_DigestSignFinal => threw exception", mdCtx);
        throwExceptionIfNecessary(env, "EVP_DigestSignFinal");
        return 0;
    }

    JNI_TRACE("EVP_DigestSignFinal(%p) => %p", mdCtx, outJavaBytes.get());
    return outJavaBytes.release();
}

/*
 * public static native int EVP_SignFinal(long, byte[], int, long)
 */
static jint NativeCrypto_EVP_SignFinal(JNIEnv* env, jclass, jobject ctxRef, jbyteArray signature,
        jint offset, jobject pkeyRef) {
    JNI_TRACE("NativeCrypto_EVP_SignFinal(%p, %p, %d, %p)", ctxRef, signature, offset, pkeyRef);
    EVP_MD_CTX* ctx = fromContextObject<EVP_MD_CTX>(env, ctxRef);
    if (ctx == NULL) {
        return -1;
    }
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("NativeCrypto_EVP_SignFinal(%p, %p, %d, %p) <- ptr", ctx, signature, offset, pkey);

    if (pkey == NULL) {
        return -1;
    }

    ScopedByteArrayRW signatureBytes(env, signature);
    if (signatureBytes.get() == NULL) {
        return -1;
    }
    unsigned int bytesWritten = -1;
    int ok = EVP_SignFinal(ctx,
                           reinterpret_cast<unsigned char*>(signatureBytes.get() + offset),
                           &bytesWritten,
                           pkey);
    if (ok == 0) {
        throwExceptionIfNecessary(env, "NativeCrypto_EVP_SignFinal");
    }
    JNI_TRACE("NativeCrypto_EVP_SignFinal(%p, %p, %d, %p) => %u",
              ctx, signature, offset, pkey, bytesWritten);

    return bytesWritten;
}

/*
 * public static native void EVP_VerifyUpdate(long, byte[], int, int)
 */
static void NativeCrypto_EVP_VerifyUpdate(JNIEnv* env, jclass, jobject ctxRef,
                                          jbyteArray buffer, jint offset, jint length) {
    EVP_MD_CTX* ctx = fromContextObject<EVP_MD_CTX>(env, ctxRef);
    JNI_TRACE("NativeCrypto_EVP_VerifyUpdate(%p, %p, %d, %d)", ctx, buffer, offset, length);

    if (ctx == NULL) {
        return;
    } else if (buffer == NULL) {
        jniThrowNullPointerException(env, NULL);
        return;
    }

    if (offset < 0 || length < 0) {
        jniThrowException(env, "java/lang/ArrayIndexOutOfBoundsException", NULL);
        return;
    }

    ScopedByteArrayRO bufferBytes(env, buffer);
    if (bufferBytes.get() == NULL) {
        return;
    }
    if (bufferBytes.size() < static_cast<size_t>(offset + length)) {
        jniThrowException(env, "java/lang/ArrayIndexOutOfBoundsException", NULL);
        return;
    }

    int ok = EVP_VerifyUpdate(ctx,
                              reinterpret_cast<const unsigned char*>(bufferBytes.get() + offset),
                              length);
    if (ok == 0) {
        throwExceptionIfNecessary(env, "NativeCrypto_EVP_VerifyUpdate");
    }
}

/*
 * public static native int EVP_VerifyFinal(long, byte[], int, int, long)
 */
static jint NativeCrypto_EVP_VerifyFinal(JNIEnv* env, jclass, jobject ctxRef, jbyteArray buffer,
                                        jint offset, jint length, jobject pkeyRef) {
    JNI_TRACE("NativeCrypto_EVP_VerifyFinal(%p, %p, %d, %d, %p)",
              ctxRef, buffer, offset, length, pkeyRef);
    EVP_MD_CTX* ctx = fromContextObject<EVP_MD_CTX>(env, ctxRef);
    if (ctx == NULL) {
        return -1;
    }
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    if (pkey == NULL) {
        return -1;
    }
    JNI_TRACE("NativeCrypto_EVP_VerifyFinal(%p, %p, %d, %d, %p) <- ptr",
              ctx, buffer, offset, length, pkey);

    if (buffer == NULL) {
        jniThrowNullPointerException(env, "buffer == null");
        return -1;
    }

    ScopedByteArrayRO bufferBytes(env, buffer);
    if (bufferBytes.get() == NULL) {
        return -1;
    }
    int ok = EVP_VerifyFinal(ctx,
                             reinterpret_cast<const unsigned char*>(bufferBytes.get() + offset),
                             length,
                             pkey);
    if (ok < 0) {
        throwExceptionIfNecessary(env, "NativeCrypto_EVP_VerifyFinal");
    }

    /*
     * For DSA keys, OpenSSL appears to have a bug where it returns
     * errors for any result != 1. See dsa_ossl.c in dsa_do_verify
     */
    freeOpenSslErrorState();

    JNI_TRACE("NativeCrypto_EVP_VerifyFinal(%p, %p, %d, %d, %p) => %d",
              ctx, buffer, offset, length, pkey, ok);

    return ok;
}

static jlong NativeCrypto_EVP_get_cipherbyname(JNIEnv* env, jclass, jstring algorithm) {
    JNI_TRACE("EVP_get_cipherbyname(%p)", algorithm);

#if !defined(OPENSSL_IS_BORINGSSL)
    if (algorithm == NULL) {
        JNI_TRACE("EVP_get_cipherbyname(%p) => threw exception algorithm == null", algorithm);
        jniThrowNullPointerException(env, NULL);
        return -1;
    }

    ScopedUtfChars algorithmChars(env, algorithm);
    if (algorithmChars.c_str() == NULL) {
        return 0;
    }
    JNI_TRACE("EVP_get_cipherbyname(%p) => algorithm = %s", algorithm, algorithmChars.c_str());

    const EVP_CIPHER* evp_cipher = EVP_get_cipherbyname(algorithmChars.c_str());
    if (evp_cipher == NULL) {
        freeOpenSslErrorState();
    }

    JNI_TRACE("EVP_get_cipherbyname(%s) => %p", algorithmChars.c_str(), evp_cipher);
    return reinterpret_cast<uintptr_t>(evp_cipher);
#else
    ScopedUtfChars scoped_alg(env, algorithm);
    const char *alg = scoped_alg.c_str();
    const EVP_CIPHER *cipher;

    if (strcasecmp(alg, "rc4") == 0) {
        cipher = EVP_rc4();
    } else if (strcasecmp(alg, "des-cbc") == 0) {
        cipher = EVP_des_cbc();
    } else if (strcasecmp(alg, "des-ede-cbc") == 0) {
        cipher = EVP_des_cbc();
    } else if (strcasecmp(alg, "des-ede3-cbc") == 0) {
        cipher = EVP_des_ede3_cbc();
    } else if (strcasecmp(alg, "aes-128-ecb") == 0) {
        cipher = EVP_aes_128_ecb();
    } else if (strcasecmp(alg, "aes-128-cbc") == 0) {
        cipher = EVP_aes_128_cbc();
    } else if (strcasecmp(alg, "aes-128-ctr") == 0) {
        cipher = EVP_aes_128_ctr();
    } else if (strcasecmp(alg, "aes-128-gcm") == 0) {
        cipher = EVP_aes_128_gcm();
    } else if (strcasecmp(alg, "aes-192-ecb") == 0) {
        cipher = EVP_aes_192_ecb();
    } else if (strcasecmp(alg, "aes-192-cbc") == 0) {
        cipher = EVP_aes_192_cbc();
    } else if (strcasecmp(alg, "aes-192-ctr") == 0) {
        cipher = EVP_aes_192_ctr();
    } else if (strcasecmp(alg, "aes-192-gcm") == 0) {
        cipher = EVP_aes_192_gcm();
    } else if (strcasecmp(alg, "aes-256-ecb") == 0) {
        cipher = EVP_aes_256_ecb();
    } else if (strcasecmp(alg, "aes-256-cbc") == 0) {
        cipher = EVP_aes_256_cbc();
    } else if (strcasecmp(alg, "aes-256-ctr") == 0) {
        cipher = EVP_aes_256_ctr();
    } else if (strcasecmp(alg, "aes-256-gcm") == 0) {
        cipher = EVP_aes_256_gcm();
    } else {
        JNI_TRACE("NativeCrypto_EVP_get_digestbyname(%s) => error", alg);
        return 0;
    }

    return reinterpret_cast<uintptr_t>(cipher);
#endif
}

static void NativeCrypto_EVP_CipherInit_ex(JNIEnv* env, jclass, jobject ctxRef, jlong evpCipherRef,
        jbyteArray keyArray, jbyteArray ivArray, jboolean encrypting) {
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    const EVP_CIPHER* evpCipher = reinterpret_cast<const EVP_CIPHER*>(evpCipherRef);
    JNI_TRACE("EVP_CipherInit_ex(%p, %p, %p, %p, %d)", ctx, evpCipher, keyArray, ivArray,
            encrypting ? 1 : 0);

    if (ctx == NULL) {
        JNI_TRACE("EVP_CipherUpdate => ctx == null");
        return;
    }

    // The key can be null if we need to set extra parameters.
    UniquePtr<unsigned char[]> keyPtr;
    if (keyArray != NULL) {
        ScopedByteArrayRO keyBytes(env, keyArray);
        if (keyBytes.get() == NULL) {
            return;
        }

        keyPtr.reset(new unsigned char[keyBytes.size()]);
        memcpy(keyPtr.get(), keyBytes.get(), keyBytes.size());
    }

    // The IV can be null if we're using ECB.
    UniquePtr<unsigned char[]> ivPtr;
    if (ivArray != NULL) {
        ScopedByteArrayRO ivBytes(env, ivArray);
        if (ivBytes.get() == NULL) {
            return;
        }

        ivPtr.reset(new unsigned char[ivBytes.size()]);
        memcpy(ivPtr.get(), ivBytes.get(), ivBytes.size());
    }

    if (!EVP_CipherInit_ex(ctx, evpCipher, NULL, keyPtr.get(), ivPtr.get(), encrypting ? 1 : 0)) {
        throwExceptionIfNecessary(env, "EVP_CipherInit_ex");
        JNI_TRACE("EVP_CipherInit_ex => error initializing cipher");
        return;
    }

    JNI_TRACE("EVP_CipherInit_ex(%p, %p, %p, %p, %d) => success", ctx, evpCipher, keyArray, ivArray,
            encrypting ? 1 : 0);
}

/*
 *  public static native int EVP_CipherUpdate(long ctx, byte[] out, int outOffset, byte[] in,
 *          int inOffset, int inLength);
 */
static jint NativeCrypto_EVP_CipherUpdate(JNIEnv* env, jclass, jobject ctxRef, jbyteArray outArray,
        jint outOffset, jbyteArray inArray, jint inOffset, jint inLength) {
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    JNI_TRACE("EVP_CipherUpdate(%p, %p, %d, %p, %d)", ctx, outArray, outOffset, inArray, inOffset);

    if (ctx == NULL) {
        JNI_TRACE("ctx=%p EVP_CipherUpdate => ctx == null", ctx);
        return 0;
    }

    ScopedByteArrayRO inBytes(env, inArray);
    if (inBytes.get() == NULL) {
        return 0;
    }
    const size_t inSize = inBytes.size();
    if (size_t(inOffset + inLength) > inSize) {
        jniThrowException(env, "java/lang/ArrayIndexOutOfBoundsException",
                "in.length < (inSize + inOffset)");
        return 0;
    }

    ScopedByteArrayRW outBytes(env, outArray);
    if (outBytes.get() == NULL) {
        return 0;
    }
    const size_t outSize = outBytes.size();
    if (size_t(outOffset + inLength) > outSize) {
        jniThrowException(env, "java/lang/ArrayIndexOutOfBoundsException",
                "out.length < inSize + outOffset + blockSize - 1");
        return 0;
    }

    JNI_TRACE("ctx=%p EVP_CipherUpdate in=%p in.length=%zd inOffset=%zd inLength=%zd out=%p out.length=%zd outOffset=%zd",
            ctx, inBytes.get(), inBytes.size(), inOffset, inLength, outBytes.get(), outBytes.size(), outOffset);

    unsigned char* out = reinterpret_cast<unsigned char*>(outBytes.get());
    const unsigned char* in = reinterpret_cast<const unsigned char*>(inBytes.get());

    int outl;
    if (!EVP_CipherUpdate(ctx, out + outOffset, &outl, in + inOffset, inLength)) {
        throwExceptionIfNecessary(env, "EVP_CipherUpdate");
        JNI_TRACE("ctx=%p EVP_CipherUpdate => threw error", ctx);
        return 0;
    }

    JNI_TRACE("EVP_CipherUpdate(%p, %p, %d, %p, %d) => %d", ctx, outArray, outOffset, inArray,
            inOffset, outl);
    return outl;
}

static jint NativeCrypto_EVP_CipherFinal_ex(JNIEnv* env, jclass, jobject ctxRef,
                                            jbyteArray outArray, jint outOffset) {
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    JNI_TRACE("EVP_CipherFinal_ex(%p, %p, %d)", ctx, outArray, outOffset);

    if (ctx == NULL) {
        JNI_TRACE("ctx=%p EVP_CipherFinal_ex => ctx == null", ctx);
        return 0;
    }

    ScopedByteArrayRW outBytes(env, outArray);
    if (outBytes.get() == NULL) {
        return 0;
    }

    unsigned char* out = reinterpret_cast<unsigned char*>(outBytes.get());

    int outl;
    if (!EVP_CipherFinal_ex(ctx, out + outOffset, &outl)) {
        if (throwExceptionIfNecessary(env, "EVP_CipherFinal_ex")) {
            JNI_TRACE("ctx=%p EVP_CipherFinal_ex => threw error", ctx);
        } else {
            throwBadPaddingException(env, "EVP_CipherFinal_ex");
            JNI_TRACE("ctx=%p EVP_CipherFinal_ex => threw padding exception", ctx);
        }
        return 0;
    }

    JNI_TRACE("EVP_CipherFinal(%p, %p, %d) => %d", ctx, outArray, outOffset, outl);
    return outl;
}

static jint NativeCrypto_EVP_CIPHER_iv_length(JNIEnv* env, jclass, jlong evpCipherRef) {
    const EVP_CIPHER* evpCipher = reinterpret_cast<const EVP_CIPHER*>(evpCipherRef);
    JNI_TRACE("EVP_CIPHER_iv_length(%p)", evpCipher);

    if (evpCipher == NULL) {
        jniThrowNullPointerException(env, "evpCipher == null");
        JNI_TRACE("EVP_CIPHER_iv_length => evpCipher == null");
        return 0;
    }

    const int ivLength = EVP_CIPHER_iv_length(evpCipher);
    JNI_TRACE("EVP_CIPHER_iv_length(%p) => %d", evpCipher, ivLength);
    return ivLength;
}

static jlong NativeCrypto_EVP_CIPHER_CTX_new(JNIEnv* env, jclass) {
    JNI_TRACE("EVP_CIPHER_CTX_new()");

    Unique_EVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
    if (ctx.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate cipher context");
        JNI_TRACE("EVP_CipherInit_ex => context allocation error");
        return 0;
    }

    JNI_TRACE("EVP_CIPHER_CTX_new() => %p", ctx.get());
    return reinterpret_cast<uintptr_t>(ctx.release());
}

static jint NativeCrypto_EVP_CIPHER_CTX_block_size(JNIEnv* env, jclass, jobject ctxRef) {
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    JNI_TRACE("EVP_CIPHER_CTX_block_size(%p)", ctx);

    if (ctx == NULL) {
        JNI_TRACE("ctx=%p EVP_CIPHER_CTX_block_size => ctx == null", ctx);
        return 0;
    }

    int blockSize = EVP_CIPHER_CTX_block_size(ctx);
    JNI_TRACE("EVP_CIPHER_CTX_block_size(%p) => %d", ctx, blockSize);
    return blockSize;
}

static jint NativeCrypto_get_EVP_CIPHER_CTX_buf_len(JNIEnv* env, jclass, jobject ctxRef) {
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    JNI_TRACE("get_EVP_CIPHER_CTX_buf_len(%p)", ctx);

    if (ctx == NULL) {
        JNI_TRACE("ctx=%p get_EVP_CIPHER_CTX_buf_len => ctx == null", ctx);
        return 0;
    }

    int buf_len = ctx->buf_len;
    JNI_TRACE("get_EVP_CIPHER_CTX_buf_len(%p) => %d", ctx, buf_len);
    return buf_len;
}

static void NativeCrypto_EVP_CIPHER_CTX_set_padding(JNIEnv* env, jclass, jobject ctxRef,
                                                    jboolean enablePaddingBool) {
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    jint enablePadding = enablePaddingBool ? 1 : 0;
    JNI_TRACE("EVP_CIPHER_CTX_set_padding(%p, %d)", ctx, enablePadding);

    if (ctx == NULL) {
        JNI_TRACE("ctx=%p EVP_CIPHER_CTX_set_padding => ctx == null", ctx);
        return;
    }

    EVP_CIPHER_CTX_set_padding(ctx, enablePadding); // Not void, but always returns 1.
    JNI_TRACE("EVP_CIPHER_CTX_set_padding(%p, %d) => success", ctx, enablePadding);
}

static void NativeCrypto_EVP_CIPHER_CTX_set_key_length(JNIEnv* env, jclass, jobject ctxRef,
        jint keySizeBits) {
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    JNI_TRACE("EVP_CIPHER_CTX_set_key_length(%p, %d)", ctx, keySizeBits);

    if (ctx == NULL) {
        JNI_TRACE("ctx=%p EVP_CIPHER_CTX_set_key_length => ctx == null", ctx);
        return;
    }

    if (!EVP_CIPHER_CTX_set_key_length(ctx, keySizeBits)) {
        throwExceptionIfNecessary(env, "NativeCrypto_EVP_CIPHER_CTX_set_key_length");
        JNI_TRACE("NativeCrypto_EVP_CIPHER_CTX_set_key_length => threw error");
        return;
    }
    JNI_TRACE("EVP_CIPHER_CTX_set_key_length(%p, %d) => success", ctx, keySizeBits);
}

static void NativeCrypto_EVP_CIPHER_CTX_free(JNIEnv*, jclass, jlong ctxRef) {
    EVP_CIPHER_CTX* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctxRef);
    JNI_TRACE("EVP_CIPHER_CTX_free(%p)", ctx);

    EVP_CIPHER_CTX_free(ctx);
}

/**
 * public static native void RAND_seed(byte[]);
 */
#if !defined(OPENSSL_IS_BORINGSSL)
static void NativeCrypto_RAND_seed(JNIEnv* env, jclass, jbyteArray seed) {
    JNI_TRACE("NativeCrypto_RAND_seed seed=%p", seed);
    ScopedByteArrayRO randseed(env, seed);
    if (randseed.get() == NULL) {
        return;
    }
    RAND_seed(randseed.get(), randseed.size());
}
#else
static void NativeCrypto_RAND_seed(JNIEnv*, jclass, jbyteArray) {
}
#endif

static jint NativeCrypto_RAND_load_file(JNIEnv* env, jclass, jstring filename, jlong max_bytes) {
    JNI_TRACE("NativeCrypto_RAND_load_file filename=%p max_bytes=%lld", filename, (long long) max_bytes);
#if !defined(OPENSSL_IS_BORINGSSL)
    ScopedUtfChars file(env, filename);
    if (file.c_str() == NULL) {
        return -1;
    }
    int result = RAND_load_file(file.c_str(), max_bytes);
    JNI_TRACE("NativeCrypto_RAND_load_file file=%s => %d", file.c_str(), result);
    return result;
#else
    UNUSED_ARGUMENT(env);
    UNUSED_ARGUMENT(filename);
    // OpenSSLRandom calls this and checks the return value.
    return static_cast<jint>(max_bytes);
#endif
}

static void NativeCrypto_RAND_bytes(JNIEnv* env, jclass, jbyteArray output) {
    JNI_TRACE("NativeCrypto_RAND_bytes(%p)", output);

    ScopedByteArrayRW outputBytes(env, output);
    if (outputBytes.get() == NULL) {
        return;
    }

    unsigned char* tmp = reinterpret_cast<unsigned char*>(outputBytes.get());
    if (RAND_bytes(tmp, outputBytes.size()) <= 0) {
        throwExceptionIfNecessary(env, "NativeCrypto_RAND_bytes");
        JNI_TRACE("tmp=%p NativeCrypto_RAND_bytes => threw error", tmp);
        return;
    }

    JNI_TRACE("NativeCrypto_RAND_bytes(%p) => success", output);
}

static jint NativeCrypto_OBJ_txt2nid(JNIEnv* env, jclass, jstring oidStr) {
    JNI_TRACE("OBJ_txt2nid(%p)", oidStr);

    ScopedUtfChars oid(env, oidStr);
    if (oid.c_str() == NULL) {
        return 0;
    }

    int nid = OBJ_txt2nid(oid.c_str());
    JNI_TRACE("OBJ_txt2nid(%s) => %d", oid.c_str(), nid);
    return nid;
}

static jstring NativeCrypto_OBJ_txt2nid_longName(JNIEnv* env, jclass, jstring oidStr) {
    JNI_TRACE("OBJ_txt2nid_longName(%p)", oidStr);

    ScopedUtfChars oid(env, oidStr);
    if (oid.c_str() == NULL) {
        return NULL;
    }

    JNI_TRACE("OBJ_txt2nid_longName(%s)", oid.c_str());

    int nid = OBJ_txt2nid(oid.c_str());
    if (nid == NID_undef) {
        JNI_TRACE("OBJ_txt2nid_longName(%s) => NID_undef", oid.c_str());
        freeOpenSslErrorState();
        return NULL;
    }

    const char* longName = OBJ_nid2ln(nid);
    JNI_TRACE("OBJ_txt2nid_longName(%s) => %s", oid.c_str(), longName);
    return env->NewStringUTF(longName);
}

static jstring ASN1_OBJECT_to_OID_string(JNIEnv* env, const ASN1_OBJECT* obj) {
    /*
     * The OBJ_obj2txt API doesn't "measure" if you pass in NULL as the buffer.
     * Just make a buffer that's large enough here. The documentation recommends
     * 80 characters.
     */
    char output[128];
    int ret = OBJ_obj2txt(output, sizeof(output), obj, 1);
    if (ret < 0) {
        throwExceptionIfNecessary(env, "ASN1_OBJECT_to_OID_string");
        return NULL;
    } else if (size_t(ret) >= sizeof(output)) {
        jniThrowRuntimeException(env, "ASN1_OBJECT_to_OID_string buffer too small");
        return NULL;
    }

    JNI_TRACE("ASN1_OBJECT_to_OID_string(%p) => %s", obj, output);
    return env->NewStringUTF(output);
}

static jlong NativeCrypto_create_BIO_InputStream(JNIEnv* env, jclass, jobject streamObj) {
    JNI_TRACE("create_BIO_InputStream(%p)", streamObj);

    if (streamObj == NULL) {
        jniThrowNullPointerException(env, "stream == null");
        return 0;
    }

    Unique_BIO bio(BIO_new(&stream_bio_method));
    if (bio.get() == NULL) {
        return 0;
    }

    bio_stream_assign(bio.get(), new BIO_InputStream(streamObj));

    JNI_TRACE("create_BIO_InputStream(%p) => %p", streamObj, bio.get());
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(bio.release()));
}

static jlong NativeCrypto_create_BIO_OutputStream(JNIEnv* env, jclass, jobject streamObj) {
    JNI_TRACE("create_BIO_OutputStream(%p)", streamObj);

    if (streamObj == NULL) {
        jniThrowNullPointerException(env, "stream == null");
        return 0;
    }

    Unique_BIO bio(BIO_new(&stream_bio_method));
    if (bio.get() == NULL) {
        return 0;
    }

    bio_stream_assign(bio.get(), new BIO_OutputStream(streamObj));

    JNI_TRACE("create_BIO_OutputStream(%p) => %p", streamObj, bio.get());
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(bio.release()));
}

static int NativeCrypto_BIO_read(JNIEnv* env, jclass, jlong bioRef, jbyteArray outputJavaBytes) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("BIO_read(%p, %p)", bio, outputJavaBytes);

    if (outputJavaBytes == NULL) {
        jniThrowNullPointerException(env, "output == null");
        JNI_TRACE("BIO_read(%p, %p) => output == null", bio, outputJavaBytes);
        return 0;
    }

    int outputSize = env->GetArrayLength(outputJavaBytes);

    UniquePtr<unsigned char[]> buffer(new unsigned char[outputSize]);
    if (buffer.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate buffer for read");
        return 0;
    }

    int read = BIO_read(bio, buffer.get(), outputSize);
    if (read <= 0) {
        jniThrowException(env, "java/io/IOException", "BIO_read");
        JNI_TRACE("BIO_read(%p, %p) => threw IO exception", bio, outputJavaBytes);
        return 0;
    }

    env->SetByteArrayRegion(outputJavaBytes, 0, read, reinterpret_cast<jbyte*>(buffer.get()));
    JNI_TRACE("BIO_read(%p, %p) => %d", bio, outputJavaBytes, read);
    return read;
}

static void NativeCrypto_BIO_write(JNIEnv* env, jclass, jlong bioRef, jbyteArray inputJavaBytes,
        jint offset, jint length) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("BIO_write(%p, %p, %d, %d)", bio, inputJavaBytes, offset, length);

    if (inputJavaBytes == NULL) {
        jniThrowNullPointerException(env, "input == null");
        return;
    }

    if (offset < 0 || length < 0) {
        jniThrowException(env, "java/lang/ArrayIndexOutOfBoundsException", "offset < 0 || length < 0");
        JNI_TRACE("BIO_write(%p, %p, %d, %d) => IOOB", bio, inputJavaBytes, offset, length);
        return;
    }

    int inputSize = env->GetArrayLength(inputJavaBytes);
    if (inputSize < offset + length) {
        jniThrowException(env, "java/lang/ArrayIndexOutOfBoundsException",
                "input.length < offset + length");
        JNI_TRACE("BIO_write(%p, %p, %d, %d) => IOOB", bio, inputJavaBytes, offset, length);
        return;
    }

    UniquePtr<unsigned char[]> buffer(new unsigned char[length]);
    if (buffer.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate buffer for write");
        return;
    }

    env->GetByteArrayRegion(inputJavaBytes, offset, length, reinterpret_cast<jbyte*>(buffer.get()));
    if (BIO_write(bio, buffer.get(), length) != length) {
        freeOpenSslErrorState();
        jniThrowException(env, "java/io/IOException", "BIO_write");
        JNI_TRACE("BIO_write(%p, %p, %d, %d) => IO error", bio, inputJavaBytes, offset, length);
        return;
    }

    JNI_TRACE("BIO_write(%p, %p, %d, %d) => success", bio, inputJavaBytes, offset, length);
}

static void NativeCrypto_BIO_free_all(JNIEnv* env, jclass, jlong bioRef) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("BIO_free_all(%p)", bio);

    if (bio == NULL) {
        jniThrowNullPointerException(env, "bio == null");
        return;
    }

    BIO_free_all(bio);
}

static jstring X509_NAME_to_jstring(JNIEnv* env, X509_NAME* name, unsigned long flags) {
    JNI_TRACE("X509_NAME_to_jstring(%p)", name);

    Unique_BIO buffer(BIO_new(BIO_s_mem()));
    if (buffer.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate BIO");
        JNI_TRACE("X509_NAME_to_jstring(%p) => threw error", name);
        return NULL;
    }

    /* Don't interpret the string. */
    flags &= ~(ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_ESC_MSB);

    /* Write in given format and null terminate. */
    X509_NAME_print_ex(buffer.get(), name, 0, flags);
    BIO_write(buffer.get(), "\0", 1);

    char *tmp;
    BIO_get_mem_data(buffer.get(), &tmp);
    JNI_TRACE("X509_NAME_to_jstring(%p) => \"%s\"", name, tmp);
    return env->NewStringUTF(tmp);
}


/**
 * Converts GENERAL_NAME items to the output format expected in
 * X509Certificate#getSubjectAlternativeNames and
 * X509Certificate#getIssuerAlternativeNames return.
 */
static jobject GENERAL_NAME_to_jobject(JNIEnv* env, GENERAL_NAME* gen) {
    switch (gen->type) {
    case GEN_EMAIL:
    case GEN_DNS:
    case GEN_URI: {
        // This must not be a T61String and must not contain NULLs.
        const char* data = reinterpret_cast<const char*>(ASN1_STRING_data(gen->d.ia5));
        ssize_t len = ASN1_STRING_length(gen->d.ia5);
        if ((len == static_cast<ssize_t>(strlen(data)))
                && (ASN1_PRINTABLE_type(ASN1_STRING_data(gen->d.ia5), len) != V_ASN1_T61STRING)) {
            JNI_TRACE("GENERAL_NAME_to_jobject(%p) => Email/DNS/URI \"%s\"", gen, data);
            return env->NewStringUTF(data);
        } else {
            jniThrowException(env, "java/security/cert/CertificateParsingException",
                    "Invalid dNSName encoding");
            JNI_TRACE("GENERAL_NAME_to_jobject(%p) => Email/DNS/URI invalid", gen);
            return NULL;
        }
    }
    case GEN_DIRNAME:
        /* Write in RFC 2253 format */
        return X509_NAME_to_jstring(env, gen->d.directoryName, XN_FLAG_RFC2253);
    case GEN_IPADD: {
        const void *ip = reinterpret_cast<const void *>(gen->d.ip->data);
        if (gen->d.ip->length == 4) {
            // IPv4
            UniquePtr<char[]> buffer(new char[INET_ADDRSTRLEN]);
            if (inet_ntop(AF_INET, ip, buffer.get(), INET_ADDRSTRLEN) != NULL) {
                JNI_TRACE("GENERAL_NAME_to_jobject(%p) => IPv4 %s", gen, buffer.get());
                return env->NewStringUTF(buffer.get());
            } else {
                JNI_TRACE("GENERAL_NAME_to_jobject(%p) => IPv4 failed %s", gen, strerror(errno));
            }
        } else if (gen->d.ip->length == 16) {
            // IPv6
            UniquePtr<char[]> buffer(new char[INET6_ADDRSTRLEN]);
            if (inet_ntop(AF_INET6, ip, buffer.get(), INET6_ADDRSTRLEN) != NULL) {
                JNI_TRACE("GENERAL_NAME_to_jobject(%p) => IPv6 %s", gen, buffer.get());
                return env->NewStringUTF(buffer.get());
            } else {
                JNI_TRACE("GENERAL_NAME_to_jobject(%p) => IPv6 failed %s", gen, strerror(errno));
            }
        }

        /* Invalid IP encodings are pruned out without throwing an exception. */
        return NULL;
    }
    case GEN_RID:
        return ASN1_OBJECT_to_OID_string(env, gen->d.registeredID);
    case GEN_OTHERNAME:
    case GEN_X400:
    default:
        return ASN1ToByteArray<GENERAL_NAME>(env, gen, i2d_GENERAL_NAME);
    }

    return NULL;
}

#define GN_STACK_SUBJECT_ALT_NAME 1
#define GN_STACK_ISSUER_ALT_NAME 2

static jobjectArray NativeCrypto_get_X509_GENERAL_NAME_stack(JNIEnv* env, jclass, jlong x509Ref,
        jint type) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d)", x509, type);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) => x509 == null", x509, type);
        return NULL;
    }

    X509_check_ca(x509);

    STACK_OF(GENERAL_NAME)* gn_stack;
    Unique_sk_GENERAL_NAME stackHolder;
    if (type == GN_STACK_SUBJECT_ALT_NAME) {
        gn_stack = x509->altname;
    } else if (type == GN_STACK_ISSUER_ALT_NAME) {
        stackHolder.reset(
                static_cast<STACK_OF(GENERAL_NAME)*>(X509_get_ext_d2i(x509, NID_issuer_alt_name,
                        NULL, NULL)));
        gn_stack = stackHolder.get();
    } else {
        JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) => unknown type", x509, type);
        return NULL;
    }

    int count = sk_GENERAL_NAME_num(gn_stack);
    if (count <= 0) {
        JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) => null (no entries)", x509, type);
        return NULL;
    }

    /*
     * Keep track of how many originally so we can ignore any invalid
     * values later.
     */
    const int origCount = count;

    ScopedLocalRef<jobjectArray> joa(env, env->NewObjectArray(count, objectArrayClass, NULL));
    for (int i = 0, j = 0; i < origCount; i++, j++) {
        GENERAL_NAME* gen = sk_GENERAL_NAME_value(gn_stack, i);
        ScopedLocalRef<jobject> val(env, GENERAL_NAME_to_jobject(env, gen));
        if (env->ExceptionCheck()) {
            JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) => threw exception parsing gen name",
                    x509, type);
            return NULL;
        }

        /*
         * If it's NULL, we'll have to skip this, reduce the number of total
         * entries, and fix up the array later.
         */
        if (val.get() == NULL) {
            j--;
            count--;
            continue;
        }

        ScopedLocalRef<jobjectArray> item(env, env->NewObjectArray(2, objectClass, NULL));

        ScopedLocalRef<jobject> type(env, env->CallStaticObjectMethod(integerClass,
                integer_valueOfMethod, gen->type));
        env->SetObjectArrayElement(item.get(), 0, type.get());
        env->SetObjectArrayElement(item.get(), 1, val.get());

        env->SetObjectArrayElement(joa.get(), j, item.get());
    }

    if (count == 0) {
        JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) shrunk from %d to 0; returning NULL",
                x509, type, origCount);
        joa.reset(NULL);
    } else if (origCount != count) {
        JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) shrunk from %d to %d", x509, type,
                origCount, count);

        ScopedLocalRef<jobjectArray> joa_copy(env, env->NewObjectArray(count, objectArrayClass,
                NULL));

        for (int i = 0; i < count; i++) {
            ScopedLocalRef<jobject> item(env, env->GetObjectArrayElement(joa.get(), i));
            env->SetObjectArrayElement(joa_copy.get(), i, item.get());
        }

        joa.reset(joa_copy.release());
    }

    JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) => %d entries", x509, type, count);
    return joa.release();
}

static jlong NativeCrypto_X509_get_notBefore(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_notBefore(%p)", x509);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_get_notBefore(%p) => x509 == null", x509);
        return 0;
    }

    ASN1_TIME* notBefore = X509_get_notBefore(x509);
    JNI_TRACE("X509_get_notBefore(%p) => %p", x509, notBefore);
    return reinterpret_cast<uintptr_t>(notBefore);
}

static jlong NativeCrypto_X509_get_notAfter(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_notAfter(%p)", x509);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_get_notAfter(%p) => x509 == null", x509);
        return 0;
    }

    ASN1_TIME* notAfter = X509_get_notAfter(x509);
    JNI_TRACE("X509_get_notAfter(%p) => %p", x509, notAfter);
    return reinterpret_cast<uintptr_t>(notAfter);
}

static long NativeCrypto_X509_get_version(JNIEnv*, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_version(%p)", x509);

    long version = X509_get_version(x509);
    JNI_TRACE("X509_get_version(%p) => %ld", x509, version);
    return version;
}

template<typename T>
static jbyteArray get_X509Type_serialNumber(JNIEnv* env, T* x509Type, ASN1_INTEGER* (*get_serial_func)(T*)) {
    JNI_TRACE("get_X509Type_serialNumber(%p)", x509Type);

    if (x509Type == NULL) {
        jniThrowNullPointerException(env, "x509Type == null");
        JNI_TRACE("get_X509Type_serialNumber(%p) => x509Type == null", x509Type);
        return NULL;
    }

    ASN1_INTEGER* serialNumber = get_serial_func(x509Type);
    Unique_BIGNUM serialBn(ASN1_INTEGER_to_BN(serialNumber, NULL));
    if (serialBn.get() == NULL) {
        JNI_TRACE("X509_get_serialNumber(%p) => threw exception", x509Type);
        return NULL;
    }

    ScopedLocalRef<jbyteArray> serialArray(env, bignumToArray(env, serialBn.get(), "serialBn"));
    if (env->ExceptionCheck()) {
        JNI_TRACE("X509_get_serialNumber(%p) => threw exception", x509Type);
        return NULL;
    }

    JNI_TRACE("X509_get_serialNumber(%p) => %p", x509Type, serialArray.get());
    return serialArray.release();
}

/* OpenSSL includes set_serialNumber but not get. */
#if !defined(X509_REVOKED_get_serialNumber)
static ASN1_INTEGER* X509_REVOKED_get_serialNumber(X509_REVOKED* x) {
    return x->serialNumber;
}
#endif

static jbyteArray NativeCrypto_X509_get_serialNumber(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_serialNumber(%p)", x509);
    return get_X509Type_serialNumber<X509>(env, x509, X509_get_serialNumber);
}

static jbyteArray NativeCrypto_X509_REVOKED_get_serialNumber(JNIEnv* env, jclass, jlong x509RevokedRef) {
    X509_REVOKED* revoked = reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("X509_REVOKED_get_serialNumber(%p)", revoked);
    return get_X509Type_serialNumber<X509_REVOKED>(env, revoked, X509_REVOKED_get_serialNumber);
}

static void NativeCrypto_X509_verify(JNIEnv* env, jclass, jlong x509Ref, jobject pkeyRef) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("X509_verify(%p, %p)", x509, pkey);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_verify(%p, %p) => x509 == null", x509, pkey);
        return;
    }

    if (pkey == NULL) {
        JNI_TRACE("X509_verify(%p, %p) => pkey == null", x509, pkey);
        return;
    }

    if (X509_verify(x509, pkey) != 1) {
        throwExceptionIfNecessary(env, "X509_verify");
        JNI_TRACE("X509_verify(%p, %p) => verify failure", x509, pkey);
    } else {
        JNI_TRACE("X509_verify(%p, %p) => verify success", x509, pkey);
    }
}

static jbyteArray NativeCrypto_get_X509_cert_info_enc(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_cert_info_enc(%p)", x509);
    return ASN1ToByteArray<X509_CINF>(env, x509->cert_info, i2d_X509_CINF);
}

static jint NativeCrypto_get_X509_ex_flags(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_ex_flags(%p)", x509);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_ex_flags(%p) => x509 == null", x509);
        return 0;
    }

    X509_check_ca(x509);

    return x509->ex_flags;
}

static jboolean NativeCrypto_X509_check_issued(JNIEnv*, jclass, jlong x509Ref1, jlong x509Ref2) {
    X509* x509_1 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref1));
    X509* x509_2 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref2));
    JNI_TRACE("X509_check_issued(%p, %p)", x509_1, x509_2);

    int ret = X509_check_issued(x509_1, x509_2);
    JNI_TRACE("X509_check_issued(%p, %p) => %d", x509_1, x509_2, ret);
    return ret;
}

static void get_X509_signature(X509 *x509, ASN1_BIT_STRING** signature) {
    *signature = x509->signature;
}

static void get_X509_CRL_signature(X509_CRL *crl, ASN1_BIT_STRING** signature) {
    *signature = crl->signature;
}

template<typename T>
static jbyteArray get_X509Type_signature(JNIEnv* env, T* x509Type, void (*get_signature_func)(T*, ASN1_BIT_STRING**)) {
    JNI_TRACE("get_X509Type_signature(%p)", x509Type);

    if (x509Type == NULL) {
        jniThrowNullPointerException(env, "x509Type == null");
        JNI_TRACE("get_X509Type_signature(%p) => x509Type == null", x509Type);
        return NULL;
    }

    ASN1_BIT_STRING* signature;
    get_signature_func(x509Type, &signature);

    ScopedLocalRef<jbyteArray> signatureArray(env, env->NewByteArray(signature->length));
    if (env->ExceptionCheck()) {
        JNI_TRACE("get_X509Type_signature(%p) => threw exception", x509Type);
        return NULL;
    }

    ScopedByteArrayRW signatureBytes(env, signatureArray.get());
    if (signatureBytes.get() == NULL) {
        JNI_TRACE("get_X509Type_signature(%p) => using byte array failed", x509Type);
        return NULL;
    }

    memcpy(signatureBytes.get(), signature->data, signature->length);

    JNI_TRACE("get_X509Type_signature(%p) => %p (%d bytes)", x509Type, signatureArray.get(),
            signature->length);
    return signatureArray.release();
}

static jbyteArray NativeCrypto_get_X509_signature(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_signature(%p)", x509);
    return get_X509Type_signature<X509>(env, x509, get_X509_signature);
}

static jbyteArray NativeCrypto_get_X509_CRL_signature(JNIEnv* env, jclass, jlong x509CrlRef) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("get_X509_CRL_signature(%p)", crl);
    return get_X509Type_signature<X509_CRL>(env, crl, get_X509_CRL_signature);
}

static jlong NativeCrypto_X509_CRL_get0_by_cert(JNIEnv* env, jclass, jlong x509crlRef, jlong x509Ref) {
    X509_CRL* x509crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509crlRef));
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_CRL_get0_by_cert(%p, %p)", x509crl, x509);

    if (x509crl == NULL) {
        jniThrowNullPointerException(env, "x509crl == null");
        JNI_TRACE("X509_CRL_get0_by_cert(%p, %p) => x509crl == null", x509crl, x509);
        return 0;
    } else if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_CRL_get0_by_cert(%p, %p) => x509 == null", x509crl, x509);
        return 0;
    }

    X509_REVOKED* revoked = NULL;
    int ret = X509_CRL_get0_by_cert(x509crl, &revoked, x509);
    if (ret == 0) {
        JNI_TRACE("X509_CRL_get0_by_cert(%p, %p) => none", x509crl, x509);
        return 0;
    }

    JNI_TRACE("X509_CRL_get0_by_cert(%p, %p) => %p", x509crl, x509, revoked);
    return reinterpret_cast<uintptr_t>(revoked);
}

static jlong NativeCrypto_X509_CRL_get0_by_serial(JNIEnv* env, jclass, jlong x509crlRef, jbyteArray serialArray) {
    X509_CRL* x509crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509crlRef));
    JNI_TRACE("X509_CRL_get0_by_serial(%p, %p)", x509crl, serialArray);

    if (x509crl == NULL) {
        jniThrowNullPointerException(env, "x509crl == null");
        JNI_TRACE("X509_CRL_get0_by_serial(%p, %p) => crl == null", x509crl, serialArray);
        return 0;
    }

    Unique_BIGNUM serialBn(BN_new());
    if (serialBn.get() == NULL) {
        JNI_TRACE("X509_CRL_get0_by_serial(%p, %p) => BN allocation failed", x509crl, serialArray);
        return 0;
    }

    BIGNUM* serialBare = serialBn.get();
    if (!arrayToBignum(env, serialArray, &serialBare)) {
        if (!env->ExceptionCheck()) {
            jniThrowNullPointerException(env, "serial == null");
        }
        JNI_TRACE("X509_CRL_get0_by_serial(%p, %p) => BN conversion failed", x509crl, serialArray);
        return 0;
    }

    Unique_ASN1_INTEGER serialInteger(BN_to_ASN1_INTEGER(serialBn.get(), NULL));
    if (serialInteger.get() == NULL) {
        JNI_TRACE("X509_CRL_get0_by_serial(%p, %p) => BN conversion failed", x509crl, serialArray);
        return 0;
    }

    X509_REVOKED* revoked = NULL;
    int ret = X509_CRL_get0_by_serial(x509crl, &revoked, serialInteger.get());
    if (ret == 0) {
        JNI_TRACE("X509_CRL_get0_by_serial(%p, %p) => none", x509crl, serialArray);
        return 0;
    }

    JNI_TRACE("X509_CRL_get0_by_cert(%p, %p) => %p", x509crl, serialArray, revoked);
    return reinterpret_cast<uintptr_t>(revoked);
}


/* This appears to be missing from OpenSSL. */
#if !defined(X509_REVOKED_dup) && !defined(OPENSSL_IS_BORINGSSL)
X509_REVOKED* X509_REVOKED_dup(X509_REVOKED* x) {
    return reinterpret_cast<X509_REVOKED*>(ASN1_item_dup(ASN1_ITEM_rptr(X509_REVOKED), x));
}
#endif

static jlongArray NativeCrypto_X509_CRL_get_REVOKED(JNIEnv* env, jclass, jlong x509CrlRef) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_REVOKED(%p)", crl);

    if (crl == NULL) {
        jniThrowNullPointerException(env, "crl == null");
        return NULL;
    }

    STACK_OF(X509_REVOKED)* stack = X509_CRL_get_REVOKED(crl);
    if (stack == NULL) {
        JNI_TRACE("X509_CRL_get_REVOKED(%p) => stack is null", crl);
        return NULL;
    }

    size_t size = sk_X509_REVOKED_num(stack);

    ScopedLocalRef<jlongArray> revokedArray(env, env->NewLongArray(size));
    ScopedLongArrayRW revoked(env, revokedArray.get());
    for (size_t i = 0; i < size; i++) {
        X509_REVOKED* item = reinterpret_cast<X509_REVOKED*>(sk_X509_REVOKED_value(stack, i));
        revoked[i] = reinterpret_cast<uintptr_t>(X509_REVOKED_dup(item));
    }

    JNI_TRACE("X509_CRL_get_REVOKED(%p) => %p [size=%zd]", stack, revokedArray.get(), size);
    return revokedArray.release();
}

static jbyteArray NativeCrypto_i2d_X509_CRL(JNIEnv* env, jclass, jlong x509CrlRef) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("i2d_X509_CRL(%p)", crl);
    return ASN1ToByteArray<X509_CRL>(env, crl, i2d_X509_CRL);
}

static void NativeCrypto_X509_CRL_free(JNIEnv* env, jclass, jlong x509CrlRef) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_free(%p)", crl);

    if (crl == NULL) {
        jniThrowNullPointerException(env, "crl == null");
        JNI_TRACE("X509_CRL_free(%p) => crl == null", crl);
        return;
    }

    X509_CRL_free(crl);
}

static void NativeCrypto_X509_CRL_print(JNIEnv* env, jclass, jlong bioRef, jlong x509CrlRef) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_print(%p, %p)", bio, crl);

    if (bio == NULL) {
        jniThrowNullPointerException(env, "bio == null");
        JNI_TRACE("X509_CRL_print(%p, %p) => bio == null", bio, crl);
        return;
    }

    if (crl == NULL) {
        jniThrowNullPointerException(env, "crl == null");
        JNI_TRACE("X509_CRL_print(%p, %p) => crl == null", bio, crl);
        return;
    }

    if (!X509_CRL_print(bio, crl)) {
        throwExceptionIfNecessary(env, "X509_CRL_print");
        JNI_TRACE("X509_CRL_print(%p, %p) => threw error", bio, crl);
    } else {
        JNI_TRACE("X509_CRL_print(%p, %p) => success", bio, crl);
    }
}

static jstring NativeCrypto_get_X509_CRL_sig_alg_oid(JNIEnv* env, jclass, jlong x509CrlRef) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("get_X509_CRL_sig_alg_oid(%p)", crl);

    if (crl == NULL || crl->sig_alg == NULL) {
        jniThrowNullPointerException(env, "crl == NULL || crl->sig_alg == NULL");
        JNI_TRACE("get_X509_CRL_sig_alg_oid(%p) => crl == NULL", crl);
        return NULL;
    }

    return ASN1_OBJECT_to_OID_string(env, crl->sig_alg->algorithm);
}

static jbyteArray NativeCrypto_get_X509_CRL_sig_alg_parameter(JNIEnv* env, jclass, jlong x509CrlRef) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("get_X509_CRL_sig_alg_parameter(%p)", crl);

    if (crl == NULL) {
        jniThrowNullPointerException(env, "crl == null");
        JNI_TRACE("get_X509_CRL_sig_alg_parameter(%p) => crl == null", crl);
        return NULL;
    }

    if (crl->sig_alg->parameter == NULL) {
        JNI_TRACE("get_X509_CRL_sig_alg_parameter(%p) => null", crl);
        return NULL;
    }

    return ASN1ToByteArray<ASN1_TYPE>(env, crl->sig_alg->parameter, i2d_ASN1_TYPE);
}

static jbyteArray NativeCrypto_X509_CRL_get_issuer_name(JNIEnv* env, jclass, jlong x509CrlRef) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_issuer_name(%p)", crl);
    return ASN1ToByteArray<X509_NAME>(env, X509_CRL_get_issuer(crl), i2d_X509_NAME);
}

static long NativeCrypto_X509_CRL_get_version(JNIEnv*, jclass, jlong x509CrlRef) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_version(%p)", crl);

    long version = X509_CRL_get_version(crl);
    JNI_TRACE("X509_CRL_get_version(%p) => %ld", crl, version);
    return version;
}

template<typename T, int (*get_ext_by_OBJ_func)(T*, ASN1_OBJECT*, int),
        X509_EXTENSION* (*get_ext_func)(T*, int)>
static X509_EXTENSION *X509Type_get_ext(JNIEnv* env, T* x509Type, jstring oidString) {
    JNI_TRACE("X509Type_get_ext(%p)", x509Type);

    if (x509Type == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        return NULL;
    }

    ScopedUtfChars oid(env, oidString);
    if (oid.c_str() == NULL) {
        return NULL;
    }

    Unique_ASN1_OBJECT asn1(OBJ_txt2obj(oid.c_str(), 1));
    if (asn1.get() == NULL) {
        JNI_TRACE("X509Type_get_ext(%p, %s) => oid conversion failed", x509Type, oid.c_str());
        freeOpenSslErrorState();
        return NULL;
    }

    int extIndex = get_ext_by_OBJ_func(x509Type, (ASN1_OBJECT*) asn1.get(), -1);
    if (extIndex == -1) {
        JNI_TRACE("X509Type_get_ext(%p, %s) => ext not found", x509Type, oid.c_str());
        return NULL;
    }

    X509_EXTENSION* ext = get_ext_func(x509Type, extIndex);
    JNI_TRACE("X509Type_get_ext(%p, %s) => %p", x509Type, oid.c_str(), ext);
    return ext;
}

template<typename T, int (*get_ext_by_OBJ_func)(T*, ASN1_OBJECT*, int),
        X509_EXTENSION* (*get_ext_func)(T*, int)>
static jbyteArray X509Type_get_ext_oid(JNIEnv* env, T* x509Type, jstring oidString) {
    X509_EXTENSION* ext = X509Type_get_ext<T, get_ext_by_OBJ_func, get_ext_func>(env, x509Type,
            oidString);
    if (ext == NULL) {
        JNI_TRACE("X509Type_get_ext_oid(%p, %p) => fetching extension failed", x509Type, oidString);
        return NULL;
    }

    JNI_TRACE("X509Type_get_ext_oid(%p, %p) => %p", x509Type, oidString, ext->value);
    return ASN1ToByteArray<ASN1_OCTET_STRING>(env, ext->value, i2d_ASN1_OCTET_STRING);
}

static jlong NativeCrypto_X509_CRL_get_ext(JNIEnv* env, jclass, jlong x509CrlRef, jstring oid) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_ext(%p, %p)", crl, oid);
    X509_EXTENSION* ext = X509Type_get_ext<X509_CRL, X509_CRL_get_ext_by_OBJ, X509_CRL_get_ext>(
            env, crl, oid);
    JNI_TRACE("X509_CRL_get_ext(%p, %p) => %p", crl, oid, ext);
    return reinterpret_cast<uintptr_t>(ext);
}

static jlong NativeCrypto_X509_REVOKED_get_ext(JNIEnv* env, jclass, jlong x509RevokedRef,
        jstring oid) {
    X509_REVOKED* revoked = reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("X509_REVOKED_get_ext(%p, %p)", revoked, oid);
    X509_EXTENSION* ext = X509Type_get_ext<X509_REVOKED, X509_REVOKED_get_ext_by_OBJ,
            X509_REVOKED_get_ext>(env, revoked, oid);
    JNI_TRACE("X509_REVOKED_get_ext(%p, %p) => %p", revoked, oid, ext);
    return reinterpret_cast<uintptr_t>(ext);
}

static jlong NativeCrypto_X509_REVOKED_dup(JNIEnv* env, jclass, jlong x509RevokedRef) {
    X509_REVOKED* revoked = reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("X509_REVOKED_dup(%p)", revoked);

    if (revoked == NULL) {
        jniThrowNullPointerException(env, "revoked == null");
        JNI_TRACE("X509_REVOKED_dup(%p) => revoked == null", revoked);
        return 0;
    }

    X509_REVOKED* dup = X509_REVOKED_dup(revoked);
    JNI_TRACE("X509_REVOKED_dup(%p) => %p", revoked, dup);
    return reinterpret_cast<uintptr_t>(dup);
}

static jlong NativeCrypto_get_X509_REVOKED_revocationDate(JNIEnv* env, jclass, jlong x509RevokedRef) {
    X509_REVOKED* revoked = reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("get_X509_REVOKED_revocationDate(%p)", revoked);

    if (revoked == NULL) {
        jniThrowNullPointerException(env, "revoked == null");
        JNI_TRACE("get_X509_REVOKED_revocationDate(%p) => revoked == null", revoked);
        return 0;
    }

    JNI_TRACE("get_X509_REVOKED_revocationDate(%p) => %p", revoked, revoked->revocationDate);
    return reinterpret_cast<uintptr_t>(revoked->revocationDate);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wwrite-strings"
static void NativeCrypto_X509_REVOKED_print(JNIEnv* env, jclass, jlong bioRef, jlong x509RevokedRef) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    X509_REVOKED* revoked = reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("X509_REVOKED_print(%p, %p)", bio, revoked);

    if (bio == NULL) {
        jniThrowNullPointerException(env, "bio == null");
        JNI_TRACE("X509_REVOKED_print(%p, %p) => bio == null", bio, revoked);
        return;
    }

    if (revoked == NULL) {
        jniThrowNullPointerException(env, "revoked == null");
        JNI_TRACE("X509_REVOKED_print(%p, %p) => revoked == null", bio, revoked);
        return;
    }

    BIO_printf(bio, "Serial Number: ");
    i2a_ASN1_INTEGER(bio, revoked->serialNumber);
    BIO_printf(bio, "\nRevocation Date: ");
    ASN1_TIME_print(bio, revoked->revocationDate);
    BIO_printf(bio, "\n");
    X509V3_extensions_print(bio, "CRL entry extensions", revoked->extensions, 0, 0);
}
#pragma GCC diagnostic pop

static jbyteArray NativeCrypto_get_X509_CRL_crl_enc(JNIEnv* env, jclass, jlong x509CrlRef) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("get_X509_CRL_crl_enc(%p)", crl);
    return ASN1ToByteArray<X509_CRL_INFO>(env, crl->crl, i2d_X509_CRL_INFO);
}

static void NativeCrypto_X509_CRL_verify(JNIEnv* env, jclass, jlong x509CrlRef, jobject pkeyRef) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("X509_CRL_verify(%p, %p)", crl, pkey);

    if (crl == NULL) {
        jniThrowNullPointerException(env, "crl == null");
        JNI_TRACE("X509_CRL_verify(%p, %p) => crl == null", crl, pkey);
        return;
    }

    if (pkey == NULL) {
        JNI_TRACE("X509_CRL_verify(%p, %p) => pkey == null", crl, pkey);
        return;
    }

    if (X509_CRL_verify(crl, pkey) != 1) {
        throwExceptionIfNecessary(env, "X509_CRL_verify");
        JNI_TRACE("X509_CRL_verify(%p, %p) => verify failure", crl, pkey);
    } else {
        JNI_TRACE("X509_CRL_verify(%p, %p) => verify success", crl, pkey);
    }
}

static jlong NativeCrypto_X509_CRL_get_lastUpdate(JNIEnv* env, jclass, jlong x509CrlRef) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_lastUpdate(%p)", crl);

    if (crl == NULL) {
        jniThrowNullPointerException(env, "crl == null");
        JNI_TRACE("X509_CRL_get_lastUpdate(%p) => crl == null", crl);
        return 0;
    }

    ASN1_TIME* lastUpdate = X509_CRL_get_lastUpdate(crl);
    JNI_TRACE("X509_CRL_get_lastUpdate(%p) => %p", crl, lastUpdate);
    return reinterpret_cast<uintptr_t>(lastUpdate);
}

static jlong NativeCrypto_X509_CRL_get_nextUpdate(JNIEnv* env, jclass, jlong x509CrlRef) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_nextUpdate(%p)", crl);

    if (crl == NULL) {
        jniThrowNullPointerException(env, "crl == null");
        JNI_TRACE("X509_CRL_get_nextUpdate(%p) => crl == null", crl);
        return 0;
    }

    ASN1_TIME* nextUpdate = X509_CRL_get_nextUpdate(crl);
    JNI_TRACE("X509_CRL_get_nextUpdate(%p) => %p", crl, nextUpdate);
    return reinterpret_cast<uintptr_t>(nextUpdate);
}

static jbyteArray NativeCrypto_i2d_X509_REVOKED(JNIEnv* env, jclass, jlong x509RevokedRef) {
    X509_REVOKED* x509Revoked =
            reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("i2d_X509_REVOKED(%p)", x509Revoked);
    return ASN1ToByteArray<X509_REVOKED>(env, x509Revoked, i2d_X509_REVOKED);
}

static jint NativeCrypto_X509_supported_extension(JNIEnv* env, jclass, jlong x509ExtensionRef) {
    X509_EXTENSION* ext = reinterpret_cast<X509_EXTENSION*>(static_cast<uintptr_t>(x509ExtensionRef));

    if (ext == NULL) {
        jniThrowNullPointerException(env, "ext == NULL");
        return 0;
    }

    return X509_supported_extension(ext);
}

static inline void get_ASN1_TIME_data(char **data, int* output, size_t len) {
    char c = **data;
    **data = '\0';
    *data -= len;
    *output = atoi(*data);
    *(*data + len) = c;
}

static void NativeCrypto_ASN1_TIME_to_Calendar(JNIEnv* env, jclass, jlong asn1TimeRef, jobject calendar) {
    ASN1_TIME* asn1Time = reinterpret_cast<ASN1_TIME*>(static_cast<uintptr_t>(asn1TimeRef));
    JNI_TRACE("ASN1_TIME_to_Calendar(%p, %p)", asn1Time, calendar);

    if (asn1Time == NULL) {
        jniThrowNullPointerException(env, "asn1Time == null");
        return;
    }

    Unique_ASN1_GENERALIZEDTIME gen(ASN1_TIME_to_generalizedtime(asn1Time, NULL));
    if (gen.get() == NULL) {
        jniThrowNullPointerException(env, "asn1Time == null");
        return;
    }

    if (gen->length < 14 || gen->data == NULL) {
        jniThrowNullPointerException(env, "gen->length < 14 || gen->data == NULL");
        return;
    }

    int sec, min, hour, mday, mon, year;

    char *p = (char*) &gen->data[14];

    get_ASN1_TIME_data(&p, &sec, 2);
    get_ASN1_TIME_data(&p, &min, 2);
    get_ASN1_TIME_data(&p, &hour, 2);
    get_ASN1_TIME_data(&p, &mday, 2);
    get_ASN1_TIME_data(&p, &mon, 2);
    get_ASN1_TIME_data(&p, &year, 4);

    env->CallVoidMethod(calendar, calendar_setMethod, year, mon - 1, mday, hour, min, sec);
}

static jstring NativeCrypto_OBJ_txt2nid_oid(JNIEnv* env, jclass, jstring oidStr) {
    JNI_TRACE("OBJ_txt2nid_oid(%p)", oidStr);

    ScopedUtfChars oid(env, oidStr);
    if (oid.c_str() == NULL) {
        return NULL;
    }

    JNI_TRACE("OBJ_txt2nid_oid(%s)", oid.c_str());

    int nid = OBJ_txt2nid(oid.c_str());
    if (nid == NID_undef) {
        JNI_TRACE("OBJ_txt2nid_oid(%s) => NID_undef", oid.c_str());
        freeOpenSslErrorState();
        return NULL;
    }

    const ASN1_OBJECT* obj = OBJ_nid2obj(nid);
    if (obj == NULL) {
        throwExceptionIfNecessary(env, "OBJ_nid2obj");
        return NULL;
    }

    ScopedLocalRef<jstring> ouputStr(env, ASN1_OBJECT_to_OID_string(env, obj));
    JNI_TRACE("OBJ_txt2nid_oid(%s) => %p", oid.c_str(), ouputStr.get());
    return ouputStr.release();
}

static jstring NativeCrypto_X509_NAME_print_ex(JNIEnv* env, jclass, jlong x509NameRef, jlong jflags) {
    X509_NAME* x509name = reinterpret_cast<X509_NAME*>(static_cast<uintptr_t>(x509NameRef));
    unsigned long flags = static_cast<unsigned long>(jflags);
    JNI_TRACE("X509_NAME_print_ex(%p, %ld)", x509name, flags);

    if (x509name == NULL) {
        jniThrowNullPointerException(env, "x509name == null");
        JNI_TRACE("X509_NAME_print_ex(%p, %ld) => x509name == null", x509name, flags);
        return NULL;
    }

    return X509_NAME_to_jstring(env, x509name, flags);
}

template <typename T, T* (*d2i_func)(BIO*, T**)>
static jlong d2i_ASN1Object_to_jlong(JNIEnv* env, jlong bioRef) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("d2i_ASN1Object_to_jlong(%p)", bio);

    if (bio == NULL) {
        jniThrowNullPointerException(env, "bio == null");
        return 0;
    }

    T* x = d2i_func(bio, NULL);
    if (x == NULL) {
        throwExceptionIfNecessary(env, "d2i_ASN1Object_to_jlong");
        return 0;
    }

    return reinterpret_cast<uintptr_t>(x);
}

static jlong NativeCrypto_d2i_X509_CRL_bio(JNIEnv* env, jclass, jlong bioRef) {
    return d2i_ASN1Object_to_jlong<X509_CRL, d2i_X509_CRL_bio>(env, bioRef);
}

static jlong NativeCrypto_d2i_X509_bio(JNIEnv* env, jclass, jlong bioRef) {
    return d2i_ASN1Object_to_jlong<X509, d2i_X509_bio>(env, bioRef);
}

static jlong NativeCrypto_d2i_X509(JNIEnv* env, jclass, jbyteArray certBytes) {
    X509* x = ByteArrayToASN1<X509, d2i_X509>(env, certBytes);
    return reinterpret_cast<uintptr_t>(x);
}

static jbyteArray NativeCrypto_i2d_X509(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("i2d_X509(%p)", x509);
    return ASN1ToByteArray<X509>(env, x509, i2d_X509);
}

static jbyteArray NativeCrypto_i2d_X509_PUBKEY(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("i2d_X509_PUBKEY(%p)", x509);
    return ASN1ToByteArray<X509_PUBKEY>(env, X509_get_X509_PUBKEY(x509), i2d_X509_PUBKEY);
}


template<typename T, T* (*PEM_read_func)(BIO*, T**, pem_password_cb*, void*)>
static jlong PEM_ASN1Object_to_jlong(JNIEnv* env, jlong bioRef) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("PEM_ASN1Object_to_jlong(%p)", bio);

    if (bio == NULL) {
        jniThrowNullPointerException(env, "bio == null");
        JNI_TRACE("PEM_ASN1Object_to_jlong(%p) => bio == null", bio);
        return 0;
    }

    T* x = PEM_read_func(bio, NULL, NULL, NULL);
    if (x == NULL) {
        throwExceptionIfNecessary(env, "PEM_ASN1Object_to_jlong");
        // Sometimes the PEM functions fail without pushing an error
        if (!env->ExceptionCheck()) {
            jniThrowRuntimeException(env, "Failure parsing PEM");
        }
        JNI_TRACE("PEM_ASN1Object_to_jlong(%p) => threw exception", bio);
        return 0;
    }

    JNI_TRACE("PEM_ASN1Object_to_jlong(%p) => %p", bio, x);
    return reinterpret_cast<uintptr_t>(x);
}

static jlong NativeCrypto_PEM_read_bio_X509(JNIEnv* env, jclass, jlong bioRef) {
    JNI_TRACE("PEM_read_bio_X509(0x%llx)", (long long) bioRef);
    return PEM_ASN1Object_to_jlong<X509, PEM_read_bio_X509>(env, bioRef);
}

static jlong NativeCrypto_PEM_read_bio_X509_CRL(JNIEnv* env, jclass, jlong bioRef) {
    JNI_TRACE("PEM_read_bio_X509_CRL(0x%llx)", (long long) bioRef);
    return PEM_ASN1Object_to_jlong<X509_CRL, PEM_read_bio_X509_CRL>(env, bioRef);
}

template <typename T, typename T_stack>
static jlongArray PKCS7_to_ItemArray(JNIEnv* env, T_stack* stack, T* (*dup_func)(T*))
{
    if (stack == NULL) {
        return NULL;
    }

    ScopedLocalRef<jlongArray> ref_array(env, NULL);
    size_t size = sk_num(reinterpret_cast<_STACK*>(stack));
    ref_array.reset(env->NewLongArray(size));
    ScopedLongArrayRW items(env, ref_array.get());
    for (size_t i = 0; i < size; i++) {
        T* item = reinterpret_cast<T*>(sk_value(reinterpret_cast<_STACK*>(stack), i));
        items[i] = reinterpret_cast<uintptr_t>(dup_func(item));
    }

    JNI_TRACE("PKCS7_to_ItemArray(%p) => %p [size=%zd]", stack, ref_array.get(), size);
    return ref_array.release();
}

#define PKCS7_CERTS 1
#define PKCS7_CRLS 2

static jbyteArray NativeCrypto_i2d_PKCS7(JNIEnv* env, jclass, jlongArray certsArray) {
#if !defined(OPENSSL_IS_BORINGSSL)
    JNI_TRACE("i2d_PKCS7(%p)", certsArray);

    Unique_PKCS7 pkcs7(PKCS7_new());
    if (pkcs7.get() == NULL) {
        jniThrowNullPointerException(env, "pkcs7 == null");
        JNI_TRACE("i2d_PKCS7(%p) => pkcs7 == null", certsArray);
        return NULL;
    }

    if (PKCS7_set_type(pkcs7.get(), NID_pkcs7_signed) != 1) {
        throwExceptionIfNecessary(env, "PKCS7_set_type");
        return NULL;
    }

    // The EncapsulatedContentInfo must be present in the output, but OpenSSL
    // will fill in a zero-length OID if you don't call PKCS7_set_content on the
    // outer PKCS7 container. So we construct an empty PKCS7 data container and
    // set it as the content.
    Unique_PKCS7 pkcs7Data(PKCS7_new());
    if (PKCS7_set_type(pkcs7Data.get(), NID_pkcs7_data) != 1) {
        throwExceptionIfNecessary(env, "PKCS7_set_type data");
        return NULL;
    }

    if (PKCS7_set_content(pkcs7.get(), pkcs7Data.get()) != 1) {
        throwExceptionIfNecessary(env, "PKCS7_set_content");
        return NULL;
    }
    OWNERSHIP_TRANSFERRED(pkcs7Data);

    ScopedLongArrayRO certs(env, certsArray);
    for (size_t i = 0; i < certs.size(); i++) {
        X509* item = reinterpret_cast<X509*>(certs[i]);
        if (PKCS7_add_certificate(pkcs7.get(), item) != 1) {
            throwExceptionIfNecessary(env, "i2d_PKCS7");
            return NULL;
        }
    }

    JNI_TRACE("i2d_PKCS7(%p) => %zd certs", certsArray, certs.size());
    return ASN1ToByteArray<PKCS7>(env, pkcs7.get(), i2d_PKCS7);
#else  // OPENSSL_IS_BORINGSSL
    STACK_OF(X509) *stack = sk_X509_new_null();

    ScopedLongArrayRO certs(env, certsArray);
    for (size_t i = 0; i < certs.size(); i++) {
        X509* item = reinterpret_cast<X509*>(certs[i]);
        if (sk_X509_push(stack, item) == 0) {
            sk_X509_free(stack);
            throwExceptionIfNecessary(env, "sk_X509_push");
            return NULL;
        }
    }

    CBB out;
    CBB_init(&out, 1024 * certs.size());
    if (!PKCS7_bundle_certificates(&out, stack)) {
        CBB_cleanup(&out);
        sk_X509_free(stack);
        throwExceptionIfNecessary(env, "PKCS7_bundle_certificates");
        return NULL;
    }

    sk_X509_free(stack);

    uint8_t *derBytes;
    size_t derLen;
    if (!CBB_finish(&out, &derBytes, &derLen)) {
        CBB_cleanup(&out);
        throwExceptionIfNecessary(env, "CBB_finish");
        return NULL;
    }

    ScopedLocalRef<jbyteArray> byteArray(env, env->NewByteArray(derLen));
    if (byteArray.get() == NULL) {
        JNI_TRACE("creating byte array failed");
        return NULL;
    }

    ScopedByteArrayRW bytes(env, byteArray.get());
    if (bytes.get() == NULL) {
        JNI_TRACE("using byte array failed");
        return NULL;
    }

    uint8_t* p = reinterpret_cast<unsigned char*>(bytes.get());
    memcpy(p, derBytes, derLen);

    return byteArray.release();
#endif  // OPENSSL_IS_BORINGSSL
}

#if defined(OPENSSL_IS_BORINGSSL)

/* readAllFromBIO sets |*out_data| to contain an allocated buffer that is
 * large enough to read |bio| to EOF. The number of bytes read is stored in
 * |*out_len|. It returns true on success or false on I/O error. */
static bool readAllFromBIO(BIO *bio, UniquePtr<uint8_t[]> *out_data, size_t *out_len) {
    size_t size = 1024, offset = 0;
    out_data->reset(new uint8_t[size]);

    for (;;) {
        if (offset == size) {
            uint8_t *next = new uint8_t[size*2];
            memcpy(next, out_data->get(), size);
            size *= 2;
            out_data->reset(next);
        }

        int n = BIO_read(bio, &out_data->get()[offset], size - offset);
        if (n < 0) {
            return false;
        } else if (n == 0) {
            break;
        }

        offset += n;
    }

    *out_len = offset;
    return true;
}

#else

static STACK_OF(X509)* PKCS7_get_certs(PKCS7* pkcs7) {
    if (PKCS7_type_is_signed(pkcs7)) {
        return pkcs7->d.sign->cert;
    } else if (PKCS7_type_is_signedAndEnveloped(pkcs7)) {
        return pkcs7->d.signed_and_enveloped->cert;
    } else {
        JNI_TRACE("PKCS7_get_certs(%p) => unknown PKCS7 type", pkcs7);
        return NULL;
    }
}

static STACK_OF(X509_CRL)* PKCS7_get_CRLs(PKCS7* pkcs7) {
    if (PKCS7_type_is_signed(pkcs7)) {
        return pkcs7->d.sign->crl;
    } else if (PKCS7_type_is_signedAndEnveloped(pkcs7)) {
        return pkcs7->d.signed_and_enveloped->crl;
    } else {
        JNI_TRACE("PKCS7_get_CRLs(%p) => unknown PKCS7 type", pkcs7);
        return NULL;
    }
}

#endif

static jlongArray NativeCrypto_PEM_read_bio_PKCS7(JNIEnv* env, jclass, jlong bioRef, jint which) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("PEM_read_bio_PKCS7_CRLs(%p)", bio);

    if (bio == NULL) {
        jniThrowNullPointerException(env, "bio == null");
        JNI_TRACE("PEM_read_bio_PKCS7_CRLs(%p) => bio == null", bio);
        return 0;
    }

#if !defined(OPENSSL_IS_BORINGSSL)
    Unique_PKCS7 pkcs7(PEM_read_bio_PKCS7(bio, NULL, NULL, NULL));
    if (pkcs7.get() == NULL) {
        throwExceptionIfNecessary(env, "PEM_read_bio_PKCS7_CRLs");
        JNI_TRACE("PEM_read_bio_PKCS7_CRLs(%p) => threw exception", bio);
        return 0;
    }

    switch (which) {
    case PKCS7_CERTS:
        return PKCS7_to_ItemArray<X509, STACK_OF(X509)>(env, PKCS7_get_certs(pkcs7.get()), X509_dup);
    case PKCS7_CRLS:
        return PKCS7_to_ItemArray<X509_CRL, STACK_OF(X509_CRL)>(env, PKCS7_get_CRLs(pkcs7.get()),
                X509_CRL_dup);
    default:
        jniThrowRuntimeException(env, "unknown PKCS7 field");
        return NULL;
    }
#else
    if (which == PKCS7_CERTS) {
        Unique_sk_X509 outCerts(sk_X509_new_null());
        if (!PKCS7_get_PEM_certificates(outCerts.get(), bio)) {
            throwExceptionIfNecessary(env, "PKCS7_get_PEM_certificates");
            return 0;
        }
        return PKCS7_to_ItemArray<X509, STACK_OF(X509)>(env, outCerts.get(), X509_dup);
    } else if (which == PKCS7_CRLS) {
        Unique_sk_X509_CRL outCRLs(sk_X509_CRL_new_null());
        if (!PKCS7_get_PEM_CRLs(outCRLs.get(), bio)) {
            throwExceptionIfNecessary(env, "PKCS7_get_PEM_CRLs");
            return 0;
        }
        return PKCS7_to_ItemArray<X509_CRL, STACK_OF(X509_CRL)>(
            env, outCRLs.get(), X509_CRL_dup);
    } else {
        jniThrowRuntimeException(env, "unknown PKCS7 field");
        return 0;
    }
#endif
}

static jlongArray NativeCrypto_d2i_PKCS7_bio(JNIEnv* env, jclass, jlong bioRef, jint which) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("d2i_PKCS7_bio(%p, %d)", bio, which);

    if (bio == NULL) {
        jniThrowNullPointerException(env, "bio == null");
        JNI_TRACE("d2i_PKCS7_bio(%p, %d) => bio == null", bio, which);
        return 0;
    }

#if !defined(OPENSSL_IS_BORINGSSL)
    Unique_PKCS7 pkcs7(d2i_PKCS7_bio(bio, NULL));
    if (pkcs7.get() == NULL) {
        throwExceptionIfNecessary(env, "d2i_PKCS7_bio");
        JNI_TRACE("d2i_PKCS7_bio(%p, %d) => threw exception", bio, which);
        return 0;
    }

    switch (which) {
    case PKCS7_CERTS:
        return PKCS7_to_ItemArray<X509, STACK_OF(X509)>(env, PKCS7_get_certs(pkcs7.get()), X509_dup);
    case PKCS7_CRLS:
        return PKCS7_to_ItemArray<X509_CRL, STACK_OF(X509_CRL)>(env, PKCS7_get_CRLs(pkcs7.get()),
                X509_CRL_dup);
    default:
        jniThrowRuntimeException(env, "unknown PKCS7 field");
        return NULL;
    }
#else
    UniquePtr<uint8_t[]> data;
    size_t len;
    if (!readAllFromBIO(bio, &data, &len)) {
        throwExceptionIfNecessary(env, "Error reading from BIO");
        return 0;
    }

    CBS cbs;
    CBS_init(&cbs, data.get(), len);

    if (which == PKCS7_CERTS) {
        Unique_sk_X509 outCerts(sk_X509_new_null());
        if (!PKCS7_get_certificates(outCerts.get(), &cbs)) {
            throwExceptionIfNecessary(env, "PKCS7_get_certificates");
            return 0;
        }
        return PKCS7_to_ItemArray<X509, STACK_OF(X509)>(env, outCerts.get(), X509_dup);
    } else if (which == PKCS7_CRLS) {
        Unique_sk_X509_CRL outCRLs(sk_X509_CRL_new_null());
        if (!PKCS7_get_CRLs(outCRLs.get(), &cbs)) {
            throwExceptionIfNecessary(env, "PKCS7_get_CRLs");
            return 0;
        }
        return PKCS7_to_ItemArray<X509_CRL, STACK_OF(X509_CRL)>(
            env, outCRLs.get(), X509_CRL_dup);
    } else {
        jniThrowRuntimeException(env, "unknown PKCS7 field");
        return 0;
    }
#endif
}


typedef STACK_OF(X509) PKIPATH;

ASN1_ITEM_TEMPLATE(PKIPATH) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, PkiPath, X509)
ASN1_ITEM_TEMPLATE_END(PKIPATH)

static jlongArray NativeCrypto_ASN1_seq_unpack_X509_bio(JNIEnv* env, jclass, jlong bioRef) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("ASN1_seq_unpack_X509_bio(%p)", bio);

    Unique_sk_X509 path((PKIPATH*) ASN1_item_d2i_bio(ASN1_ITEM_rptr(PKIPATH), bio, NULL));
    if (path.get() == NULL) {
        throwExceptionIfNecessary(env, "ASN1_seq_unpack_X509_bio");
        return NULL;
    }

    size_t size = sk_X509_num(path.get());

    ScopedLocalRef<jlongArray> certArray(env, env->NewLongArray(size));
    ScopedLongArrayRW certs(env, certArray.get());
    for (size_t i = 0; i < size; i++) {
        X509* item = reinterpret_cast<X509*>(sk_X509_shift(path.get()));
        certs[i] = reinterpret_cast<uintptr_t>(item);
    }

    JNI_TRACE("ASN1_seq_unpack_X509_bio(%p) => returns %zd items", bio, size);
    return certArray.release();
}

static jbyteArray NativeCrypto_ASN1_seq_pack_X509(JNIEnv* env, jclass, jlongArray certs) {
    JNI_TRACE("ASN1_seq_pack_X509(%p)", certs);
    ScopedLongArrayRO certsArray(env, certs);
    if (certsArray.get() == NULL) {
        JNI_TRACE("ASN1_seq_pack_X509(%p) => failed to get certs array", certs);
        return NULL;
    }

    Unique_sk_X509 certStack(sk_X509_new_null());
    if (certStack.get() == NULL) {
        JNI_TRACE("ASN1_seq_pack_X509(%p) => failed to make cert stack", certs);
        return NULL;
    }

#if !defined(OPENSSL_IS_BORINGSSL)
    for (size_t i = 0; i < certsArray.size(); i++) {
        X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(certsArray[i]));
        sk_X509_push(certStack.get(), X509_dup_nocopy(x509));
    }

    int len;
    Unique_OPENSSL_str encoded(ASN1_seq_pack(
                    reinterpret_cast<STACK_OF(OPENSSL_BLOCK)*>(
                            reinterpret_cast<uintptr_t>(certStack.get())),
                    reinterpret_cast<int (*)(void*, unsigned char**)>(i2d_X509), NULL, &len));
    if (encoded.get() == NULL || len < 0) {
        JNI_TRACE("ASN1_seq_pack_X509(%p) => trouble encoding", certs);
        return NULL;
    }

    uint8_t *out = encoded.get();
    size_t out_len = len;
#else
    CBB result, seq_contents;
    if (!CBB_init(&result, 2048 * certsArray.size())) {
        JNI_TRACE("ASN1_seq_pack_X509(%p) => CBB_init failed", certs);
        return NULL;
    }
    if (!CBB_add_asn1(&result, &seq_contents, CBS_ASN1_SEQUENCE)) {
        CBB_cleanup(&result);
        return NULL;
    }

    for (size_t i = 0; i < certsArray.size(); i++) {
        X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(certsArray[i]));
        uint8_t *buf;
        int len = i2d_X509(x509, NULL);

        if (len < 0 ||
            !CBB_add_space(&seq_contents, &buf, len) ||
            i2d_X509(x509, &buf) < 0) {
            CBB_cleanup(&result);
            return NULL;
        }
    }

    uint8_t *out;
    size_t out_len;
    if (!CBB_finish(&result, &out, &out_len)) {
        CBB_cleanup(&result);
        return NULL;
    }
    UniquePtr<uint8_t> out_storage(out);
#endif

    ScopedLocalRef<jbyteArray> byteArray(env, env->NewByteArray(out_len));
    if (byteArray.get() == NULL) {
        JNI_TRACE("ASN1_seq_pack_X509(%p) => creating byte array failed", certs);
        return NULL;
    }

    ScopedByteArrayRW bytes(env, byteArray.get());
    if (bytes.get() == NULL) {
        JNI_TRACE("ASN1_seq_pack_X509(%p) => using byte array failed", certs);
        return NULL;
    }

    uint8_t *p = reinterpret_cast<uint8_t*>(bytes.get());
    memcpy(p, out, out_len);

    return byteArray.release();
}

static void NativeCrypto_X509_free(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_free(%p)", x509);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_free(%p) => x509 == null", x509);
        return;
    }

    X509_free(x509);
}

static jint NativeCrypto_X509_cmp(JNIEnv* env, jclass, jlong x509Ref1, jlong x509Ref2) {
    X509* x509_1 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref1));
    X509* x509_2 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref2));
    JNI_TRACE("X509_cmp(%p, %p)", x509_1, x509_2);

    if (x509_1 == NULL) {
        jniThrowNullPointerException(env, "x509_1 == null");
        JNI_TRACE("X509_cmp(%p, %p) => x509_1 == null", x509_1, x509_2);
        return -1;
    }

    if (x509_2 == NULL) {
        jniThrowNullPointerException(env, "x509_2 == null");
        JNI_TRACE("X509_cmp(%p, %p) => x509_2 == null", x509_1, x509_2);
        return -1;
    }

    int ret = X509_cmp(x509_1, x509_2);
    JNI_TRACE("X509_cmp(%p, %p) => %d", x509_1, x509_2, ret);
    return ret;
}

static jint NativeCrypto_get_X509_hashCode(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_hashCode(%p) => x509 == null", x509);
        return 0;
    }

    // Force caching extensions.
    X509_check_ca(x509);

    jint hashCode = 0L;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        hashCode = 31 * hashCode + x509->sha1_hash[i];
    }
    return hashCode;
}

static void NativeCrypto_X509_print_ex(JNIEnv* env, jclass, jlong bioRef, jlong x509Ref,
        jlong nmflagJava, jlong certflagJava) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    long nmflag = static_cast<long>(nmflagJava);
    long certflag = static_cast<long>(certflagJava);
    JNI_TRACE("X509_print_ex(%p, %p, %ld, %ld)", bio, x509, nmflag, certflag);

    if (bio == NULL) {
        jniThrowNullPointerException(env, "bio == null");
        JNI_TRACE("X509_print_ex(%p, %p, %ld, %ld) => bio == null", bio, x509, nmflag, certflag);
        return;
    }

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_print_ex(%p, %p, %ld, %ld) => x509 == null", bio, x509, nmflag, certflag);
        return;
    }

    if (!X509_print_ex(bio, x509, nmflag, certflag)) {
        throwExceptionIfNecessary(env, "X509_print_ex");
        JNI_TRACE("X509_print_ex(%p, %p, %ld, %ld) => threw error", bio, x509, nmflag, certflag);
    } else {
        JNI_TRACE("X509_print_ex(%p, %p, %ld, %ld) => success", bio, x509, nmflag, certflag);
    }
}

static jlong NativeCrypto_X509_get_pubkey(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_pubkey(%p)", x509);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_get_pubkey(%p) => x509 == null", x509);
        return 0;
    }

    Unique_EVP_PKEY pkey(X509_get_pubkey(x509));
    if (pkey.get() == NULL) {
#if defined(OPENSSL_IS_BORINGSSL)
        const uint32_t last_error = ERR_peek_last_error();
        const uint32_t first_error = ERR_peek_error();
        if ((ERR_GET_LIB(last_error) == ERR_LIB_EVP &&
             ERR_GET_REASON(last_error) == EVP_R_UNKNOWN_PUBLIC_KEY_TYPE) ||
            (ERR_GET_LIB(first_error) == ERR_LIB_EC &&
             ERR_GET_REASON(first_error) == EC_R_UNKNOWN_GROUP)) {
            freeOpenSslErrorState();
            throwNoSuchAlgorithmException(env, "X509_get_pubkey");
            return 0;
        }
#endif

        throwExceptionIfNecessary(env, "X509_get_pubkey");
        return 0;
    }

    JNI_TRACE("X509_get_pubkey(%p) => %p", x509, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jbyteArray NativeCrypto_X509_get_issuer_name(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_issuer_name(%p)", x509);
    return ASN1ToByteArray<X509_NAME>(env, X509_get_issuer_name(x509), i2d_X509_NAME);
}

static jbyteArray NativeCrypto_X509_get_subject_name(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_subject_name(%p)", x509);
    return ASN1ToByteArray<X509_NAME>(env, X509_get_subject_name(x509), i2d_X509_NAME);
}

static jstring NativeCrypto_get_X509_pubkey_oid(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_pubkey_oid(%p)", x509);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_pubkey_oid(%p) => x509 == null", x509);
        return NULL;
    }

    X509_PUBKEY* pubkey = X509_get_X509_PUBKEY(x509);
    return ASN1_OBJECT_to_OID_string(env, pubkey->algor->algorithm);
}

static jstring NativeCrypto_get_X509_sig_alg_oid(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_sig_alg_oid(%p)", x509);

    if (x509 == NULL || x509->sig_alg == NULL) {
        jniThrowNullPointerException(env, "x509 == NULL || x509->sig_alg == NULL");
        JNI_TRACE("get_X509_sig_alg_oid(%p) => x509 == NULL", x509);
        return NULL;
    }

    return ASN1_OBJECT_to_OID_string(env, x509->sig_alg->algorithm);
}

static jbyteArray NativeCrypto_get_X509_sig_alg_parameter(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_sig_alg_parameter(%p)", x509);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_sig_alg_parameter(%p) => x509 == null", x509);
        return NULL;
    }

    if (x509->sig_alg->parameter == NULL) {
        JNI_TRACE("get_X509_sig_alg_parameter(%p) => null", x509);
        return NULL;
    }

    return ASN1ToByteArray<ASN1_TYPE>(env, x509->sig_alg->parameter, i2d_ASN1_TYPE);
}

static jbooleanArray NativeCrypto_get_X509_issuerUID(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_issuerUID(%p)", x509);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_issuerUID(%p) => x509 == null", x509);
        return NULL;
    }

    if (x509->cert_info->issuerUID == NULL) {
        JNI_TRACE("get_X509_issuerUID(%p) => null", x509);
        return NULL;
    }

    return ASN1BitStringToBooleanArray(env, x509->cert_info->issuerUID);
}
static jbooleanArray NativeCrypto_get_X509_subjectUID(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_subjectUID(%p)", x509);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_subjectUID(%p) => x509 == null", x509);
        return NULL;
    }

    if (x509->cert_info->subjectUID == NULL) {
        JNI_TRACE("get_X509_subjectUID(%p) => null", x509);
        return NULL;
    }

    return ASN1BitStringToBooleanArray(env, x509->cert_info->subjectUID);
}

static jbooleanArray NativeCrypto_get_X509_ex_kusage(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_ex_kusage(%p)", x509);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_ex_kusage(%p) => x509 == null", x509);
        return NULL;
    }

    Unique_ASN1_BIT_STRING bitStr(static_cast<ASN1_BIT_STRING*>(
            X509_get_ext_d2i(x509, NID_key_usage, NULL, NULL)));
    if (bitStr.get() == NULL) {
        JNI_TRACE("get_X509_ex_kusage(%p) => null", x509);
        return NULL;
    }

    return ASN1BitStringToBooleanArray(env, bitStr.get());
}

static jobjectArray NativeCrypto_get_X509_ex_xkusage(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_ex_xkusage(%p)", x509);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_ex_xkusage(%p) => x509 == null", x509);
        return NULL;
    }

    Unique_sk_ASN1_OBJECT objArray(static_cast<STACK_OF(ASN1_OBJECT)*>(
            X509_get_ext_d2i(x509, NID_ext_key_usage, NULL, NULL)));
    if (objArray.get() == NULL) {
        JNI_TRACE("get_X509_ex_xkusage(%p) => null", x509);
        return NULL;
    }

    size_t size = sk_ASN1_OBJECT_num(objArray.get());
    ScopedLocalRef<jobjectArray> exKeyUsage(env, env->NewObjectArray(size, stringClass, NULL));
    if (exKeyUsage.get() == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < size; i++) {
        ScopedLocalRef<jstring> oidStr(env, ASN1_OBJECT_to_OID_string(env,
                sk_ASN1_OBJECT_value(objArray.get(), i)));
        env->SetObjectArrayElement(exKeyUsage.get(), i, oidStr.get());
    }

    JNI_TRACE("get_X509_ex_xkusage(%p) => success (%zd entries)", x509, size);
    return exKeyUsage.release();
}

static jint NativeCrypto_get_X509_ex_pathlen(JNIEnv* env, jclass, jlong x509Ref) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_ex_pathlen(%p)", x509);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_ex_pathlen(%p) => x509 == null", x509);
        return 0;
    }

    /* Just need to do this to cache the ex_* values. */
    X509_check_ca(x509);

    JNI_TRACE("get_X509_ex_pathlen(%p) => %ld", x509, x509->ex_pathlen);
    return x509->ex_pathlen;
}

static jbyteArray NativeCrypto_X509_get_ext_oid(JNIEnv* env, jclass, jlong x509Ref,
        jstring oidString) {
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_ext_oid(%p, %p)", x509, oidString);
    return X509Type_get_ext_oid<X509, X509_get_ext_by_OBJ, X509_get_ext>(env, x509, oidString);
}

static jbyteArray NativeCrypto_X509_CRL_get_ext_oid(JNIEnv* env, jclass, jlong x509CrlRef,
        jstring oidString) {
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_ext_oid(%p, %p)", crl, oidString);
    return X509Type_get_ext_oid<X509_CRL, X509_CRL_get_ext_by_OBJ, X509_CRL_get_ext>(env, crl,
            oidString);
}

static jbyteArray NativeCrypto_X509_REVOKED_get_ext_oid(JNIEnv* env, jclass, jlong x509RevokedRef,
        jstring oidString) {
    X509_REVOKED* revoked = reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("X509_REVOKED_get_ext_oid(%p, %p)", revoked, oidString);
    return X509Type_get_ext_oid<X509_REVOKED, X509_REVOKED_get_ext_by_OBJ, X509_REVOKED_get_ext>(
            env, revoked, oidString);
}

template<typename T, int (*get_ext_by_critical_func)(T*, int, int), X509_EXTENSION* (*get_ext_func)(T*, int)>
static jobjectArray get_X509Type_ext_oids(JNIEnv* env, jlong x509Ref, jint critical) {
    T* x509 = reinterpret_cast<T*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509Type_ext_oids(%p, %d)", x509, critical);

    if (x509 == NULL) {
        jniThrowNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509Type_ext_oids(%p, %d) => x509 == null", x509, critical);
        return NULL;
    }

    int lastPos = -1;
    int count = 0;
    while ((lastPos = get_ext_by_critical_func(x509, critical, lastPos)) != -1) {
        count++;
    }

    JNI_TRACE("get_X509Type_ext_oids(%p, %d) has %d entries", x509, critical, count);

    ScopedLocalRef<jobjectArray> joa(env, env->NewObjectArray(count, stringClass, NULL));
    if (joa.get() == NULL) {
        JNI_TRACE("get_X509Type_ext_oids(%p, %d) => fail to allocate result array", x509, critical);
        return NULL;
    }

    lastPos = -1;
    count = 0;
    while ((lastPos = get_ext_by_critical_func(x509, critical, lastPos)) != -1) {
        X509_EXTENSION* ext = get_ext_func(x509, lastPos);

        ScopedLocalRef<jstring> extOid(env, ASN1_OBJECT_to_OID_string(env, ext->object));
        if (extOid.get() == NULL) {
            JNI_TRACE("get_X509Type_ext_oids(%p) => couldn't get OID", x509);
            return NULL;
        }

        env->SetObjectArrayElement(joa.get(), count++, extOid.get());
    }

    JNI_TRACE("get_X509Type_ext_oids(%p, %d) => success", x509, critical);
    return joa.release();
}

static jobjectArray NativeCrypto_get_X509_ext_oids(JNIEnv* env, jclass, jlong x509Ref,
        jint critical) {
    JNI_TRACE("get_X509_ext_oids(0x%llx, %d)", (long long) x509Ref, critical);
    return get_X509Type_ext_oids<X509, X509_get_ext_by_critical, X509_get_ext>(env, x509Ref,
            critical);
}

static jobjectArray NativeCrypto_get_X509_CRL_ext_oids(JNIEnv* env, jclass, jlong x509CrlRef,
        jint critical) {
    JNI_TRACE("get_X509_CRL_ext_oids(0x%llx, %d)", (long long) x509CrlRef, critical);
    return get_X509Type_ext_oids<X509_CRL, X509_CRL_get_ext_by_critical, X509_CRL_get_ext>(env,
            x509CrlRef, critical);
}

static jobjectArray NativeCrypto_get_X509_REVOKED_ext_oids(JNIEnv* env, jclass, jlong x509RevokedRef,
        jint critical) {
    JNI_TRACE("get_X509_CRL_ext_oids(0x%llx, %d)", (long long) x509RevokedRef, critical);
    return get_X509Type_ext_oids<X509_REVOKED, X509_REVOKED_get_ext_by_critical,
            X509_REVOKED_get_ext>(env, x509RevokedRef, critical);
}

#ifdef WITH_JNI_TRACE
/**
 * Based on example logging call back from SSL_CTX_set_info_callback man page
 */
static void info_callback_LOG(const SSL* s __attribute__ ((unused)), int where, int ret)
{
    int w = where & ~SSL_ST_MASK;
    const char* str;
    if (w & SSL_ST_CONNECT) {
        str = "SSL_connect";
    } else if (w & SSL_ST_ACCEPT) {
        str = "SSL_accept";
    } else {
        str = "undefined";
    }

    if (where & SSL_CB_LOOP) {
        JNI_TRACE("ssl=%p %s:%s %s", s, str, SSL_state_string(s), SSL_state_string_long(s));
    } else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        JNI_TRACE("ssl=%p SSL3 alert %s:%s:%s %s %s",
                  s,
                  str,
                  SSL_alert_type_string(ret),
                  SSL_alert_desc_string(ret),
                  SSL_alert_type_string_long(ret),
                  SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            JNI_TRACE("ssl=%p %s:failed exit in %s %s",
                      s, str, SSL_state_string(s), SSL_state_string_long(s));
        } else if (ret < 0) {
            JNI_TRACE("ssl=%p %s:error exit in %s %s",
                      s, str, SSL_state_string(s), SSL_state_string_long(s));
        } else if (ret == 1) {
            JNI_TRACE("ssl=%p %s:ok exit in %s %s",
                      s, str, SSL_state_string(s), SSL_state_string_long(s));
        } else {
            JNI_TRACE("ssl=%p %s:unknown exit %d in %s %s",
                      s, str, ret, SSL_state_string(s), SSL_state_string_long(s));
        }
    } else if (where & SSL_CB_HANDSHAKE_START) {
        JNI_TRACE("ssl=%p handshake start in %s %s",
                  s, SSL_state_string(s), SSL_state_string_long(s));
    } else if (where & SSL_CB_HANDSHAKE_DONE) {
        JNI_TRACE("ssl=%p handshake done in %s %s",
                  s, SSL_state_string(s), SSL_state_string_long(s));
    } else {
        JNI_TRACE("ssl=%p %s:unknown where %d in %s %s",
                  s, str, where, SSL_state_string(s), SSL_state_string_long(s));
    }
}
#endif

/**
 * Returns an array containing all the X509 certificate references
 */
static jlongArray getCertificateRefs(JNIEnv* env, const STACK_OF(X509)* chain)
{
    if (chain == NULL) {
        // Chain can be NULL if the associated cipher doesn't do certs.
        return NULL;
    }
    ssize_t count = sk_X509_num(chain);
    if (count <= 0) {
        return NULL;
    }
    ScopedLocalRef<jlongArray> refArray(env, env->NewLongArray(count));
    ScopedLongArrayRW refs(env, refArray.get());
    if (refs.get() == NULL) {
        return NULL;
    }
    for (ssize_t i = 0; i < count; i++) {
        refs[i] = reinterpret_cast<uintptr_t>(X509_dup_nocopy(sk_X509_value(chain, i)));
    }
    return refArray.release();
}

/**
 * Returns an array containing all the X500 principal's bytes.
 */
static jobjectArray getPrincipalBytes(JNIEnv* env, const STACK_OF(X509_NAME)* names)
{
    if (names == NULL) {
        return NULL;
    }

    int count = sk_X509_NAME_num(names);
    if (count <= 0) {
        return NULL;
    }

    ScopedLocalRef<jobjectArray> joa(env, env->NewObjectArray(count, byteArrayClass, NULL));
    if (joa.get() == NULL) {
        return NULL;
    }

    for (int i = 0; i < count; i++) {
        X509_NAME* principal = sk_X509_NAME_value(names, i);

        ScopedLocalRef<jbyteArray> byteArray(env, ASN1ToByteArray<X509_NAME>(env,
                principal, i2d_X509_NAME));
        if (byteArray.get() == NULL) {
            return NULL;
        }
        env->SetObjectArrayElement(joa.get(), i, byteArray.get());
    }

    return joa.release();
}

/**
 * Our additional application data needed for getting synchronization right.
 * This maybe warrants a bit of lengthy prose:
 *
 * (1) We use a flag to reflect whether we consider the SSL connection alive.
 * Any read or write attempt loops will be cancelled once this flag becomes 0.
 *
 * (2) We use an int to count the number of threads that are blocked by the
 * underlying socket. This may be at most two (one reader and one writer), since
 * the Java layer ensures that no more threads will enter the native code at the
 * same time.
 *
 * (3) The pipe is used primarily as a means of cancelling a blocking select()
 * when we want to close the connection (aka "emergency button"). It is also
 * necessary for dealing with a possible race condition situation: There might
 * be cases where both threads see an SSL_ERROR_WANT_READ or
 * SSL_ERROR_WANT_WRITE. Both will enter a select() with the proper argument.
 * If one leaves the select() successfully before the other enters it, the
 * "success" event is already consumed and the second thread will be blocked,
 * possibly forever (depending on network conditions).
 *
 * The idea for solving the problem looks like this: Whenever a thread is
 * successful in moving around data on the network, and it knows there is
 * another thread stuck in a select(), it will write a byte to the pipe, waking
 * up the other thread. A thread that returned from select(), on the other hand,
 * knows whether it's been woken up by the pipe. If so, it will consume the
 * byte, and the original state of affairs has been restored.
 *
 * The pipe may seem like a bit of overhead, but it fits in nicely with the
 * other file descriptors of the select(), so there's only one condition to wait
 * for.
 *
 * (4) Finally, a mutex is needed to make sure that at most one thread is in
 * either SSL_read() or SSL_write() at any given time. This is an OpenSSL
 * requirement. We use the same mutex to guard the field for counting the
 * waiting threads.
 *
 * Note: The current implementation assumes that we don't have to deal with
 * problems induced by multiple cores or processors and their respective
 * memory caches. One possible problem is that of inconsistent views on the
 * "aliveAndKicking" field. This could be worked around by also enclosing all
 * accesses to that field inside a lock/unlock sequence of our mutex, but
 * currently this seems a bit like overkill. Marking volatile at the very least.
 *
 * During handshaking, additional fields are used to up-call into
 * Java to perform certificate verification and handshake
 * completion. These are also used in any renegotiation.
 *
 * (5) the JNIEnv so we can invoke the Java callback
 *
 * (6) a NativeCrypto.SSLHandshakeCallbacks instance for callbacks from native to Java
 *
 * (7) a java.io.FileDescriptor wrapper to check for socket close
 *
 * We store the NPN protocols list so we can either send it (from the server) or
 * select a protocol (on the client). We eagerly acquire a pointer to the array
 * data so the callback doesn't need to acquire resources that it cannot
 * release.
 *
 * Because renegotiation can be requested by the peer at any time,
 * care should be taken to maintain an appropriate JNIEnv on any
 * downcall to openssl since it could result in an upcall to Java. The
 * current code does try to cover these cases by conditionally setting
 * the JNIEnv on calls that can read and write to the SSL such as
 * SSL_do_handshake, SSL_read, SSL_write, and SSL_shutdown.
 *
 * Finally, we have two emphemeral keys setup by OpenSSL callbacks:
 *
 * (8) a set of ephemeral RSA keys that is lazily generated if a peer
 * wants to use an exportable RSA cipher suite.
 *
 * (9) a set of ephemeral EC keys that is lazily generated if a peer
 * wants to use an TLS_ECDHE_* cipher suite.
 *
 */
class AppData {
  public:
    volatile int aliveAndKicking;
    int waitingThreads;
    int fdsEmergency[2];
    MUTEX_TYPE mutex;
    JNIEnv* env;
    jobject sslHandshakeCallbacks;
    jbyteArray npnProtocolsArray;
    jbyte* npnProtocolsData;
    size_t npnProtocolsLength;
    jbyteArray alpnProtocolsArray;
    jbyte* alpnProtocolsData;
    size_t alpnProtocolsLength;
    Unique_RSA ephemeralRsa;
    Unique_EC_KEY ephemeralEc;

    /**
     * Creates the application data context for the SSL*.
     */
  public:
    static AppData* create() {
        UniquePtr<AppData> appData(new AppData());
        if (pipe(appData.get()->fdsEmergency) == -1) {
            ALOGE("AppData::create pipe(2) failed: %s", strerror(errno));
            return NULL;
        }
        if (!setBlocking(appData.get()->fdsEmergency[0], false)) {
            ALOGE("AppData::create fcntl(2) failed: %s", strerror(errno));
            return NULL;
        }
        if (MUTEX_SETUP(appData.get()->mutex) == -1) {
            ALOGE("pthread_mutex_init(3) failed: %s", strerror(errno));
            return NULL;
        }
        return appData.release();
    }

    ~AppData() {
        aliveAndKicking = 0;
        if (fdsEmergency[0] != -1) {
            close(fdsEmergency[0]);
        }
        if (fdsEmergency[1] != -1) {
            close(fdsEmergency[1]);
        }
        clearCallbackState();
        MUTEX_CLEANUP(mutex);
    }

  private:
    AppData() :
            aliveAndKicking(1),
            waitingThreads(0),
            env(NULL),
            sslHandshakeCallbacks(NULL),
            npnProtocolsArray(NULL),
            npnProtocolsData(NULL),
            npnProtocolsLength(-1),
            alpnProtocolsArray(NULL),
            alpnProtocolsData(NULL),
            alpnProtocolsLength(-1),
            ephemeralRsa(NULL),
            ephemeralEc(NULL) {
        fdsEmergency[0] = -1;
        fdsEmergency[1] = -1;
    }

  public:
    /**
     * Used to set the SSL-to-Java callback state before each SSL_*
     * call that may result in a callback. It should be cleared after
     * the operation returns with clearCallbackState.
     *
     * @param env The JNIEnv
     * @param shc The SSLHandshakeCallbacks
     * @param fd The FileDescriptor
     * @param npnProtocols NPN protocols so that they may be advertised (by the
     *                     server) or selected (by the client). Has no effect
     *                     unless NPN is enabled.
     * @param alpnProtocols ALPN protocols so that they may be advertised (by the
     *                     server) or selected (by the client). Passing non-NULL
     *                     enables ALPN.
     */
    bool setCallbackState(JNIEnv* e, jobject shc, jobject fd, jbyteArray npnProtocols,
            jbyteArray alpnProtocols) {
        UniquePtr<NetFd> netFd;
        if (fd != NULL) {
            netFd.reset(new NetFd(e, fd));
            if (netFd->isClosed()) {
                JNI_TRACE("appData=%p setCallbackState => netFd->isClosed() == true", this);
                return false;
            }
        }
        env = e;
        sslHandshakeCallbacks = shc;
        if (npnProtocols != NULL) {
            npnProtocolsData = e->GetByteArrayElements(npnProtocols, NULL);
            if (npnProtocolsData == NULL) {
                clearCallbackState();
                JNI_TRACE("appData=%p setCallbackState => npnProtocolsData == NULL", this);
                return false;
            }
            npnProtocolsArray = npnProtocols;
            npnProtocolsLength = e->GetArrayLength(npnProtocols);
        }
        if (alpnProtocols != NULL) {
            alpnProtocolsData = e->GetByteArrayElements(alpnProtocols, NULL);
            if (alpnProtocolsData == NULL) {
                clearCallbackState();
                JNI_TRACE("appData=%p setCallbackState => alpnProtocolsData == NULL", this);
                return false;
            }
            alpnProtocolsArray = alpnProtocols;
            alpnProtocolsLength = e->GetArrayLength(alpnProtocols);
        }
        return true;
    }

    void clearCallbackState() {
        sslHandshakeCallbacks = NULL;
        if (npnProtocolsArray != NULL) {
            env->ReleaseByteArrayElements(npnProtocolsArray, npnProtocolsData, JNI_ABORT);
            npnProtocolsArray = NULL;
            npnProtocolsData = NULL;
            npnProtocolsLength = -1;
        }
        if (alpnProtocolsArray != NULL) {
            env->ReleaseByteArrayElements(alpnProtocolsArray, alpnProtocolsData, JNI_ABORT);
            alpnProtocolsArray = NULL;
            alpnProtocolsData = NULL;
            alpnProtocolsLength = -1;
        }
        env = NULL;
    }

};

/**
 * Dark magic helper function that checks, for a given SSL session, whether it
 * can SSL_read() or SSL_write() without blocking. Takes into account any
 * concurrent attempts to close the SSLSocket from the Java side. This is
 * needed to get rid of the hangs that occur when thread #1 closes the SSLSocket
 * while thread #2 is sitting in a blocking read or write. The type argument
 * specifies whether we are waiting for readability or writability. It expects
 * to be passed either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, since we
 * only need to wait in case one of these problems occurs.
 *
 * @param env
 * @param type Either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
 * @param fdObject The FileDescriptor, since appData->fileDescriptor should be NULL
 * @param appData The application data structure with mutex info etc.
 * @param timeout_millis The timeout value for select call, with the special value
 *                0 meaning no timeout at all (wait indefinitely). Note: This is
 *                the Java semantics of the timeout value, not the usual
 *                select() semantics.
 * @return The result of the inner select() call,
 * THROW_SOCKETEXCEPTION if a SocketException was thrown, -1 on
 * additional errors
 */
static int sslSelect(JNIEnv* env, int type, jobject fdObject, AppData* appData, int timeout_millis) {
    // This loop is an expanded version of the NET_FAILURE_RETRY
    // macro. It cannot simply be used in this case because select
    // cannot be restarted without recreating the fd_sets and timeout
    // structure.
    int result;
    fd_set rfds;
    fd_set wfds;
    do {
        NetFd fd(env, fdObject);
        if (fd.isClosed()) {
            result = THROWN_EXCEPTION;
            break;
        }
        int intFd = fd.get();
        JNI_TRACE("sslSelect type=%s fd=%d appData=%p timeout_millis=%d",
                  (type == SSL_ERROR_WANT_READ) ? "READ" : "WRITE", intFd, appData, timeout_millis);

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        if (type == SSL_ERROR_WANT_READ) {
            FD_SET(intFd, &rfds);
        } else {
            FD_SET(intFd, &wfds);
        }

        FD_SET(appData->fdsEmergency[0], &rfds);

        int maxFd = (intFd > appData->fdsEmergency[0]) ? intFd : appData->fdsEmergency[0];

        // Build a struct for the timeout data if we actually want a timeout.
        timeval tv;
        timeval* ptv;
        if (timeout_millis > 0) {
            tv.tv_sec = timeout_millis / 1000;
            tv.tv_usec = (timeout_millis % 1000) * 1000;
            ptv = &tv;
        } else {
            ptv = NULL;
        }

#ifndef CONSCRYPT_UNBUNDLED
        AsynchronousCloseMonitor monitor(intFd);
#else
        CompatibilityCloseMonitor monitor(intFd);
#endif
        result = select(maxFd + 1, &rfds, &wfds, NULL, ptv);
        JNI_TRACE("sslSelect %s fd=%d appData=%p timeout_millis=%d => %d",
                  (type == SSL_ERROR_WANT_READ) ? "READ" : "WRITE",
                  fd.get(), appData, timeout_millis, result);
        if (result == -1) {
            if (fd.isClosed()) {
                result = THROWN_EXCEPTION;
                break;
            }
            if (errno != EINTR) {
                break;
            }
        }
    } while (result == -1);

    if (MUTEX_LOCK(appData->mutex) == -1) {
        return -1;
    }

    if (result > 0) {
        // We have been woken up by a token in the emergency pipe. We
        // can't be sure the token is still in the pipe at this point
        // because it could have already been read by the thread that
        // originally wrote it if it entered sslSelect and acquired
        // the mutex before we did. Thus we cannot safely read from
        // the pipe in a blocking way (so we make the pipe
        // non-blocking at creation).
        if (FD_ISSET(appData->fdsEmergency[0], &rfds)) {
            char token;
            do {
                read(appData->fdsEmergency[0], &token, 1);
            } while (errno == EINTR);
        }
    }

    // Tell the world that there is now one thread less waiting for the
    // underlying network.
    appData->waitingThreads--;

    MUTEX_UNLOCK(appData->mutex);

    return result;
}

/**
 * Helper function that wakes up a thread blocked in select(), in case there is
 * one. Is being called by sslRead() and sslWrite() as well as by JNI glue
 * before closing the connection.
 *
 * @param data The application data structure with mutex info etc.
 */
static void sslNotify(AppData* appData) {
    // Write a byte to the emergency pipe, so a concurrent select() can return.
    // Note we have to restore the errno of the original system call, since the
    // caller relies on it for generating error messages.
    int errnoBackup = errno;
    char token = '*';
    do {
        errno = 0;
        write(appData->fdsEmergency[1], &token, 1);
    } while (errno == EINTR);
    errno = errnoBackup;
}

static AppData* toAppData(const SSL* ssl) {
    return reinterpret_cast<AppData*>(SSL_get_app_data(ssl));
}

/**
 * Verify the X509 certificate via SSL_CTX_set_cert_verify_callback
 */
static int cert_verify_callback(X509_STORE_CTX* x509_store_ctx, void* arg __attribute__ ((unused)))
{
    /* Get the correct index to the SSLobject stored into X509_STORE_CTX. */
    SSL* ssl = reinterpret_cast<SSL*>(X509_STORE_CTX_get_ex_data(x509_store_ctx,
            SSL_get_ex_data_X509_STORE_CTX_idx()));
    JNI_TRACE("ssl=%p cert_verify_callback x509_store_ctx=%p arg=%p", ssl, x509_store_ctx, arg);

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == NULL) {
        ALOGE("AppData->env missing in cert_verify_callback");
        JNI_TRACE("ssl=%p cert_verify_callback => 0", ssl);
        return 0;
    }
    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;

    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID
        = env->GetMethodID(cls, "verifyCertificateChain", "(J[JLjava/lang/String;)V");

    jlongArray refArray = getCertificateRefs(env, x509_store_ctx->untrusted);

#if !defined(OPENSSL_IS_BORINGSSL)
    const char* authMethod = SSL_authentication_method(ssl);
#else
    const SSL_CIPHER *cipher = ssl->s3->tmp.new_cipher;
    const char *authMethod = SSL_CIPHER_get_kx_name(cipher);
#endif

    JNI_TRACE("ssl=%p cert_verify_callback calling verifyCertificateChain authMethod=%s",
              ssl, authMethod);
    jstring authMethodString = env->NewStringUTF(authMethod);
    env->CallVoidMethod(sslHandshakeCallbacks, methodID,
            static_cast<jlong>(reinterpret_cast<uintptr_t>(SSL_get1_session(ssl))), refArray,
            authMethodString);

    int result = (env->ExceptionCheck()) ? 0 : 1;
    JNI_TRACE("ssl=%p cert_verify_callback => %d", ssl, result);
    return result;
}

/**
 * Call back to watch for handshake to be completed. This is necessary
 * for SSL_MODE_HANDSHAKE_CUTTHROUGH support, since SSL_do_handshake
 * returns before the handshake is completed in this case.
 */
static void info_callback(const SSL* ssl, int where, int ret) {
    JNI_TRACE("ssl=%p info_callback where=0x%x ret=%d", ssl, where, ret);
#ifdef WITH_JNI_TRACE
    info_callback_LOG(ssl, where, ret);
#endif
    if (!(where & SSL_CB_HANDSHAKE_DONE) && !(where & SSL_CB_HANDSHAKE_START)) {
        JNI_TRACE("ssl=%p info_callback ignored", ssl);
        return;
    }

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == NULL) {
        ALOGE("AppData->env missing in info_callback");
        JNI_TRACE("ssl=%p info_callback env error", ssl);
        return;
    }
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p info_callback already pending exception", ssl);
        return;
    }

    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;

    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID = env->GetMethodID(cls, "onSSLStateChange", "(JII)V");

    JNI_TRACE("ssl=%p info_callback calling onSSLStateChange", ssl);
    env->CallVoidMethod(sslHandshakeCallbacks, methodID, reinterpret_cast<jlong>(ssl), where, ret);

    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p info_callback exception", ssl);
    }
    JNI_TRACE("ssl=%p info_callback completed", ssl);
}

/**
 * Call back to ask for a client certificate. There are three possible exit codes:
 *
 * 1 is success. x509Out and pkeyOut should point to the correct private key and certificate.
 * 0 is unable to find key. x509Out and pkeyOut should be NULL.
 * -1 is error and it doesn't matter what x509Out and pkeyOut are.
 */
static int client_cert_cb(SSL* ssl, X509** x509Out, EVP_PKEY** pkeyOut) {
    JNI_TRACE("ssl=%p client_cert_cb x509Out=%p pkeyOut=%p", ssl, x509Out, pkeyOut);

    /* Clear output of key and certificate in case of early exit due to error. */
    *x509Out = NULL;
    *pkeyOut = NULL;

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == NULL) {
        ALOGE("AppData->env missing in client_cert_cb");
        JNI_TRACE("ssl=%p client_cert_cb env error => 0", ssl);
        return 0;
    }
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p client_cert_cb already pending exception => 0", ssl);
        return -1;
    }
    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;

    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID
        = env->GetMethodID(cls, "clientCertificateRequested", "([B[[B)V");

    // Call Java callback which can use SSL_use_certificate and SSL_use_PrivateKey to set values
    const char* ctype = NULL;
#if !defined(OPENSSL_IS_BORINGSSL)
    char ssl2_ctype = SSL3_CT_RSA_SIGN;
    int ctype_num = 0;
    jobjectArray issuers = NULL;
    switch (ssl->version) {
        case SSL2_VERSION:
            ctype = &ssl2_ctype;
            ctype_num = 1;
            break;
        case SSL3_VERSION:
        case TLS1_VERSION:
        case TLS1_1_VERSION:
        case TLS1_2_VERSION:
        case DTLS1_VERSION:
            ctype = ssl->s3->tmp.ctype;
            ctype_num = ssl->s3->tmp.ctype_num;
            issuers = getPrincipalBytes(env, ssl->s3->tmp.ca_names);
            break;
    }
#else
    int ctype_num = SSL_get0_certificate_types(ssl, &ctype);
    jobjectArray issuers = getPrincipalBytes(env, ssl->s3->tmp.ca_names);
#endif

#ifdef WITH_JNI_TRACE
    for (int i = 0; i < ctype_num; i++) {
        JNI_TRACE("ssl=%p clientCertificateRequested keyTypes[%d]=%d", ssl, i, ctype[i]);
    }
#endif

    jbyteArray keyTypes = env->NewByteArray(ctype_num);
    if (keyTypes == NULL) {
        JNI_TRACE("ssl=%p client_cert_cb bytes == null => 0", ssl);
        return 0;
    }
    env->SetByteArrayRegion(keyTypes, 0, ctype_num, reinterpret_cast<const jbyte*>(ctype));

    JNI_TRACE("ssl=%p clientCertificateRequested calling clientCertificateRequested "
              "keyTypes=%p issuers=%p", ssl, keyTypes, issuers);
    env->CallVoidMethod(sslHandshakeCallbacks, methodID, keyTypes, issuers);

    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p client_cert_cb exception => 0", ssl);
        return -1;
    }

    // Check for values set from Java
    X509*     certificate = SSL_get_certificate(ssl);
    EVP_PKEY* privatekey  = SSL_get_privatekey(ssl);
    int result = 0;
    if (certificate != NULL && privatekey != NULL) {
        *x509Out = certificate;
        *pkeyOut = privatekey;
        result = 1;
    } else {
        // Some error conditions return NULL, so make sure it doesn't linger.
        freeOpenSslErrorState();
    }
    JNI_TRACE("ssl=%p client_cert_cb => *x509=%p *pkey=%p %d", ssl, *x509Out, *pkeyOut, result);
    return result;
}

/**
 * Pre-Shared Key (PSK) client callback.
 */
static unsigned int psk_client_callback(SSL* ssl, const char *hint,
        char *identity, unsigned int max_identity_len,
        unsigned char *psk, unsigned int max_psk_len) {
    JNI_TRACE("ssl=%p psk_client_callback", ssl);

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == NULL) {
        ALOGE("AppData->env missing in psk_client_callback");
        JNI_TRACE("ssl=%p psk_client_callback env error", ssl);
        return 0;
    }
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p psk_client_callback already pending exception", ssl);
        return 0;
    }

    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;
    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID =
            env->GetMethodID(cls, "clientPSKKeyRequested", "(Ljava/lang/String;[B[B)I");
    JNI_TRACE("ssl=%p psk_client_callback calling clientPSKKeyRequested", ssl);
    ScopedLocalRef<jstring> identityHintJava(
            env,
            (hint != NULL) ? env->NewStringUTF(hint) : NULL);
    ScopedLocalRef<jbyteArray> identityJava(env, env->NewByteArray(max_identity_len));
    if (identityJava.get() == NULL) {
        JNI_TRACE("ssl=%p psk_client_callback failed to allocate identity bufffer", ssl);
        return 0;
    }
    ScopedLocalRef<jbyteArray> keyJava(env, env->NewByteArray(max_psk_len));
    if (keyJava.get() == NULL) {
        JNI_TRACE("ssl=%p psk_client_callback failed to allocate key bufffer", ssl);
        return 0;
    }
    jint keyLen = env->CallIntMethod(sslHandshakeCallbacks, methodID,
            identityHintJava.get(), identityJava.get(), keyJava.get());
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p psk_client_callback exception", ssl);
        return 0;
    }
    if (keyLen <= 0) {
        JNI_TRACE("ssl=%p psk_client_callback failed to get key", ssl);
        return 0;
    } else if ((unsigned int) keyLen > max_psk_len) {
        JNI_TRACE("ssl=%p psk_client_callback got key which is too long", ssl);
        return 0;
    }
    ScopedByteArrayRO keyJavaRo(env, keyJava.get());
    if (keyJavaRo.get() == NULL) {
        JNI_TRACE("ssl=%p psk_client_callback failed to get key bytes", ssl);
        return 0;
    }
    memcpy(psk, keyJavaRo.get(), keyLen);

    ScopedByteArrayRO identityJavaRo(env, identityJava.get());
    if (identityJavaRo.get() == NULL) {
        JNI_TRACE("ssl=%p psk_client_callback failed to get identity bytes", ssl);
        return 0;
    }
    memcpy(identity, identityJavaRo.get(), max_identity_len);

    JNI_TRACE("ssl=%p psk_client_callback completed", ssl);
    return keyLen;
}

/**
 * Pre-Shared Key (PSK) server callback.
 */
static unsigned int psk_server_callback(SSL* ssl, const char *identity,
        unsigned char *psk, unsigned int max_psk_len) {
    JNI_TRACE("ssl=%p psk_server_callback", ssl);

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == NULL) {
        ALOGE("AppData->env missing in psk_server_callback");
        JNI_TRACE("ssl=%p psk_server_callback env error", ssl);
        return 0;
    }
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p psk_server_callback already pending exception", ssl);
        return 0;
    }

    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;
    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID = env->GetMethodID(
            cls, "serverPSKKeyRequested", "(Ljava/lang/String;Ljava/lang/String;[B)I");
    JNI_TRACE("ssl=%p psk_server_callback calling serverPSKKeyRequested", ssl);
    const char* identityHint = SSL_get_psk_identity_hint(ssl);
    // identityHint = NULL;
    // identity = NULL;
    ScopedLocalRef<jstring> identityHintJava(
            env,
            (identityHint != NULL) ? env->NewStringUTF(identityHint) : NULL);
    ScopedLocalRef<jstring> identityJava(
            env,
            (identity != NULL) ? env->NewStringUTF(identity) : NULL);
    ScopedLocalRef<jbyteArray> keyJava(env, env->NewByteArray(max_psk_len));
    if (keyJava.get() == NULL) {
        JNI_TRACE("ssl=%p psk_server_callback failed to allocate key bufffer", ssl);
        return 0;
    }
    jint keyLen = env->CallIntMethod(sslHandshakeCallbacks, methodID,
            identityHintJava.get(), identityJava.get(), keyJava.get());
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p psk_server_callback exception", ssl);
        return 0;
    }
    if (keyLen <= 0) {
        JNI_TRACE("ssl=%p psk_server_callback failed to get key", ssl);
        return 0;
    } else if ((unsigned int) keyLen > max_psk_len) {
        JNI_TRACE("ssl=%p psk_server_callback got key which is too long", ssl);
        return 0;
    }
    ScopedByteArrayRO keyJavaRo(env, keyJava.get());
    if (keyJavaRo.get() == NULL) {
        JNI_TRACE("ssl=%p psk_server_callback failed to get key bytes", ssl);
        return 0;
    }
    memcpy(psk, keyJavaRo.get(), keyLen);

    JNI_TRACE("ssl=%p psk_server_callback completed", ssl);
    return keyLen;
}

static RSA* rsaGenerateKey(int keylength) {
    Unique_BIGNUM bn(BN_new());
    if (bn.get() == NULL) {
        return NULL;
    }
    int setWordResult = BN_set_word(bn.get(), RSA_F4);
    if (setWordResult != 1) {
        return NULL;
    }
    Unique_RSA rsa(RSA_new());
    if (rsa.get() == NULL) {
        return NULL;
    }
    int generateResult = RSA_generate_key_ex(rsa.get(), keylength, bn.get(), NULL);
    if (generateResult != 1) {
        return NULL;
    }
    return rsa.release();
}

/**
 * Call back to ask for an ephemeral RSA key for SSL_RSA_EXPORT_WITH_RC4_40_MD5 (aka EXP-RC4-MD5)
 */
static RSA* tmp_rsa_callback(SSL* ssl __attribute__ ((unused)),
                             int is_export __attribute__ ((unused)),
                             int keylength) {
    JNI_TRACE("ssl=%p tmp_rsa_callback is_export=%d keylength=%d", ssl, is_export, keylength);

    AppData* appData = toAppData(ssl);
    if (appData->ephemeralRsa.get() == NULL) {
        JNI_TRACE("ssl=%p tmp_rsa_callback generating ephemeral RSA key", ssl);
        appData->ephemeralRsa.reset(rsaGenerateKey(keylength));
    }
    JNI_TRACE("ssl=%p tmp_rsa_callback => %p", ssl, appData->ephemeralRsa.get());
    return appData->ephemeralRsa.get();
}

static DH* dhGenerateParameters(int keylength) {
#if !defined(OPENSSL_IS_BORINGSSL)
    /*
     * The SSL_CTX_set_tmp_dh_callback(3SSL) man page discusses two
     * different options for generating DH keys. One is generating the
     * keys using a single set of DH parameters. However, generating
     * DH parameters is slow enough (minutes) that they suggest doing
     * it once at install time. The other is to generate DH keys from
     * DSA parameters. Generating DSA parameters is faster than DH
     * parameters, but to prevent small subgroup attacks, they needed
     * to be regenerated for each set of DH keys. Setting the
     * SSL_OP_SINGLE_DH_USE option make sure OpenSSL will call back
     * for new DH parameters every type it needs to generate DH keys.
     */

    // Fast path but must have SSL_OP_SINGLE_DH_USE set
    Unique_DSA dsa(DSA_new());
    if (!DSA_generate_parameters_ex(dsa.get(), keylength, NULL, 0, NULL, NULL, NULL)) {
        return NULL;
    }
    DH* dh = DSA_dup_DH(dsa.get());
    return dh;
#else
    /* At the time of writing, OpenSSL and BoringSSL are hard coded to request
     * a 1024-bit DH. */
    if (keylength <= 1024) {
        return DH_get_1024_160(NULL);
    }

    if (keylength <= 2048) {
        return DH_get_2048_224(NULL);
    }

    /* In the case of a large request, return the strongest DH group that
     * we have predefined. Generating a group takes far too long to be
     * reasonable. */
    return DH_get_2048_256(NULL);
#endif
}

/**
 * Call back to ask for Diffie-Hellman parameters
 */
static DH* tmp_dh_callback(SSL* ssl __attribute__ ((unused)),
                           int is_export __attribute__ ((unused)),
                           int keylength) {
    JNI_TRACE("ssl=%p tmp_dh_callback is_export=%d keylength=%d", ssl, is_export, keylength);
    DH* tmp_dh = dhGenerateParameters(keylength);
    JNI_TRACE("ssl=%p tmp_dh_callback => %p", ssl, tmp_dh);
    return tmp_dh;
}

static EC_KEY* ecGenerateKey(int keylength __attribute__ ((unused))) {
    // TODO selected curve based on keylength
    Unique_EC_KEY ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (ec.get() == NULL) {
        return NULL;
    }
    return ec.release();
}

/**
 * Call back to ask for an ephemeral EC key for TLS_ECDHE_* cipher suites
 */
static EC_KEY* tmp_ecdh_callback(SSL* ssl __attribute__ ((unused)),
                                 int is_export __attribute__ ((unused)),
                                 int keylength) {
    JNI_TRACE("ssl=%p tmp_ecdh_callback is_export=%d keylength=%d", ssl, is_export, keylength);
    AppData* appData = toAppData(ssl);
    if (appData->ephemeralEc.get() == NULL) {
        JNI_TRACE("ssl=%p tmp_ecdh_callback generating ephemeral EC key", ssl);
        appData->ephemeralEc.reset(ecGenerateKey(keylength));
    }
    JNI_TRACE("ssl=%p tmp_ecdh_callback => %p", ssl, appData->ephemeralEc.get());
    return appData->ephemeralEc.get();
}

/*
 * public static native int SSL_CTX_new();
 */
static jlong NativeCrypto_SSL_CTX_new(JNIEnv* env, jclass) {
    Unique_SSL_CTX sslCtx(SSL_CTX_new(SSLv23_method()));
    if (sslCtx.get() == NULL) {
        throwExceptionIfNecessary(env, "SSL_CTX_new");
        return 0;
    }
    SSL_CTX_set_options(sslCtx.get(),
                        SSL_OP_ALL
                        // Note: We explicitly do not allow SSLv2 to be used.
                        | SSL_OP_NO_SSLv2
                        // We also disable session tickets for better compatibility b/2682876
                        | SSL_OP_NO_TICKET
                        // We also disable compression for better compatibility b/2710492 b/2710497
                        | SSL_OP_NO_COMPRESSION
                        // Because dhGenerateParameters uses DSA_generate_parameters_ex
                        | SSL_OP_SINGLE_DH_USE
                        // Because ecGenerateParameters uses a fixed named curve
                        | SSL_OP_SINGLE_ECDH_USE);

    int mode = SSL_CTX_get_mode(sslCtx.get());
    /*
     * Turn on "partial write" mode. This means that SSL_write() will
     * behave like Posix write() and possibly return after only
     * writing a partial buffer. Note: The alternative, perhaps
     * surprisingly, is not that SSL_write() always does full writes
     * but that it will force you to retry write calls having
     * preserved the full state of the original call. (This is icky
     * and undesirable.)
     */
    mode |= SSL_MODE_ENABLE_PARTIAL_WRITE;

    // Reuse empty buffers within the SSL_CTX to save memory
    mode |= SSL_MODE_RELEASE_BUFFERS;

    SSL_CTX_set_mode(sslCtx.get(), mode);

    SSL_CTX_set_cert_verify_callback(sslCtx.get(), cert_verify_callback, NULL);
    SSL_CTX_set_info_callback(sslCtx.get(), info_callback);
    SSL_CTX_set_client_cert_cb(sslCtx.get(), client_cert_cb);
    SSL_CTX_set_tmp_rsa_callback(sslCtx.get(), tmp_rsa_callback);
    SSL_CTX_set_tmp_dh_callback(sslCtx.get(), tmp_dh_callback);
    SSL_CTX_set_tmp_ecdh_callback(sslCtx.get(), tmp_ecdh_callback);

    // When TLS Channel ID extension is used, use the new version of it.
    sslCtx.get()->tlsext_channel_id_enabled_new = 1;

    JNI_TRACE("NativeCrypto_SSL_CTX_new => %p", sslCtx.get());
    return (jlong) sslCtx.release();
}

/**
 * public static native void SSL_CTX_free(long ssl_ctx)
 */
static void NativeCrypto_SSL_CTX_free(JNIEnv* env,
        jclass, jlong ssl_ctx_address)
{
    SSL_CTX* ssl_ctx = to_SSL_CTX(env, ssl_ctx_address, true);
    JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_CTX_free", ssl_ctx);
    if (ssl_ctx == NULL) {
        return;
    }
    SSL_CTX_free(ssl_ctx);
}

static void NativeCrypto_SSL_CTX_set_session_id_context(JNIEnv* env, jclass,
                                                        jlong ssl_ctx_address, jbyteArray sid_ctx)
{
    SSL_CTX* ssl_ctx = to_SSL_CTX(env, ssl_ctx_address, true);
    JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_CTX_set_session_id_context sid_ctx=%p", ssl_ctx, sid_ctx);
    if (ssl_ctx == NULL) {
        return;
    }

    ScopedByteArrayRO buf(env, sid_ctx);
    if (buf.get() == NULL) {
        JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_CTX_set_session_id_context => threw exception", ssl_ctx);
        return;
    }

    unsigned int length = buf.size();
    if (length > SSL_MAX_SSL_SESSION_ID_LENGTH) {
        jniThrowException(env, "java/lang/IllegalArgumentException",
                          "length > SSL_MAX_SSL_SESSION_ID_LENGTH");
        JNI_TRACE("NativeCrypto_SSL_CTX_set_session_id_context => length = %d", length);
        return;
    }
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(buf.get());
    int result = SSL_CTX_set_session_id_context(ssl_ctx, bytes, length);
    if (result == 0) {
        throwExceptionIfNecessary(env, "NativeCrypto_SSL_CTX_set_session_id_context");
        return;
    }
    JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_CTX_set_session_id_context => ok", ssl_ctx);
}

/**
 * public static native int SSL_new(long ssl_ctx) throws SSLException;
 */
static jlong NativeCrypto_SSL_new(JNIEnv* env, jclass, jlong ssl_ctx_address)
{
    SSL_CTX* ssl_ctx = to_SSL_CTX(env, ssl_ctx_address, true);
    JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_new", ssl_ctx);
    if (ssl_ctx == NULL) {
        return 0;
    }
    Unique_SSL ssl(SSL_new(ssl_ctx));
    if (ssl.get() == NULL) {
        throwSSLExceptionWithSslErrors(env, NULL, SSL_ERROR_NONE,
                "Unable to create SSL structure");
        JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_new => NULL", ssl_ctx);
        return 0;
    }

    /*
     * Create our special application data.
     */
    AppData* appData = AppData::create();
    if (appData == NULL) {
        throwSSLExceptionStr(env, "Unable to create application data");
        freeOpenSslErrorState();
        JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_new appData => 0", ssl_ctx);
        return 0;
    }
    SSL_set_app_data(ssl.get(), reinterpret_cast<char*>(appData));

    /*
     * Java code in class OpenSSLSocketImpl does the verification. Since
     * the callbacks do all the verification of the chain, this flag
     * simply controls whether to send protocol-level alerts or not.
     * SSL_VERIFY_NONE means don't send alerts and anything else means send
     * alerts.
     */
    SSL_set_verify(ssl.get(), SSL_VERIFY_PEER, NULL);

    JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_new => ssl=%p appData=%p", ssl_ctx, ssl.get(), appData);
    return (jlong) ssl.release();
}


static void NativeCrypto_SSL_enable_tls_channel_id(JNIEnv* env, jclass, jlong ssl_address)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_NativeCrypto_SSL_enable_tls_channel_id", ssl);
    if (ssl == NULL) {
        return;
    }

    long ret = SSL_enable_tls_channel_id(ssl);
    if (ret != 1L) {
        ALOGE("%s", ERR_error_string(ERR_peek_error(), NULL));
        throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE, "Error enabling Channel ID");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_enable_tls_channel_id => error", ssl);
        return;
    }
}

static jbyteArray NativeCrypto_SSL_get_tls_channel_id(JNIEnv* env, jclass, jlong ssl_address)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_NativeCrypto_SSL_get_tls_channel_id", ssl);
    if (ssl == NULL) {
        return NULL;
    }

    // Channel ID is 64 bytes long. Unfortunately, OpenSSL doesn't declare this length
    // as a constant anywhere.
    jbyteArray javaBytes = env->NewByteArray(64);
    ScopedByteArrayRW bytes(env, javaBytes);
    if (bytes.get() == NULL) {
        JNI_TRACE("NativeCrypto_SSL_get_tls_channel_id(%p) => NULL", ssl);
        return NULL;
    }

    unsigned char* tmp = reinterpret_cast<unsigned char*>(bytes.get());
    // Unfortunately, the SSL_get_tls_channel_id method below always returns 64 (upon success)
    // regardless of the number of bytes copied into the output buffer "tmp". Thus, the correctness
    // of this code currently relies on the "tmp" buffer being exactly 64 bytes long.
    long ret = SSL_get_tls_channel_id(ssl, tmp, 64);
    if (ret == 0) {
        // Channel ID either not set or did not verify
        JNI_TRACE("NativeCrypto_SSL_get_tls_channel_id(%p) => not available", ssl);
        return NULL;
    } else if (ret != 64) {
        ALOGE("%s", ERR_error_string(ERR_peek_error(), NULL));
        throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE, "Error getting Channel ID");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_get_tls_channel_id => error, returned %ld", ssl, ret);
        return NULL;
    }

    JNI_TRACE("ssl=%p NativeCrypto_NativeCrypto_SSL_get_tls_channel_id() => %p", ssl, javaBytes);
    return javaBytes;
}

static void NativeCrypto_SSL_set1_tls_channel_id(JNIEnv* env, jclass,
        jlong ssl_address, jobject pkeyRef)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("ssl=%p SSL_set1_tls_channel_id privatekey=%p", ssl, pkey);
    if (ssl == NULL) {
        return;
    }

    if (pkey == NULL) {
        JNI_TRACE("ssl=%p SSL_set1_tls_channel_id => pkey == null", ssl);
        return;
    }

    // SSL_set1_tls_channel_id requires ssl->server to be set to 0.
    // Unfortunately, the default value is 1 and it's only changed to 0 just
    // before the handshake starts (see NativeCrypto_SSL_do_handshake).
    ssl->server = 0;
    long ret = SSL_set1_tls_channel_id(ssl, pkey);

    if (ret != 1L) {
        ALOGE("%s", ERR_error_string(ERR_peek_error(), NULL));
        throwSSLExceptionWithSslErrors(
                env, ssl, SSL_ERROR_NONE, "Error setting private key for Channel ID");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p SSL_set1_tls_channel_id => error", ssl);
        return;
    }
    // SSL_set1_tls_channel_id expects to take ownership of the EVP_PKEY, but
    // we have an external reference from the caller such as an OpenSSLKey,
    // so we manually increment the reference count here.
    CRYPTO_add(&pkey->references,+1,CRYPTO_LOCK_EVP_PKEY);

    JNI_TRACE("ssl=%p SSL_set1_tls_channel_id => ok", ssl);
}

static void NativeCrypto_SSL_use_PrivateKey(JNIEnv* env, jclass, jlong ssl_address,
                                            jobject pkeyRef) {
    SSL* ssl = to_SSL(env, ssl_address, true);
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("ssl=%p SSL_use_PrivateKey privatekey=%p", ssl, pkey);
    if (ssl == NULL) {
        return;
    }

    if (pkey == NULL) {
        JNI_TRACE("ssl=%p SSL_use_PrivateKey => pkey == null", ssl);
        return;
    }

    int ret = SSL_use_PrivateKey(ssl, pkey);
    if (ret != 1) {
        ALOGE("%s", ERR_error_string(ERR_peek_error(), NULL));
        throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE, "Error setting private key");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p SSL_use_PrivateKey => error", ssl);
        return;
    }
    // SSL_use_PrivateKey expects to take ownership of the EVP_PKEY,
    // but we have an external reference from the caller such as an
    // OpenSSLKey, so we manually increment the reference count here.
    CRYPTO_add(&pkey->references,+1,CRYPTO_LOCK_EVP_PKEY);

    JNI_TRACE("ssl=%p SSL_use_PrivateKey => ok", ssl);
}

static void NativeCrypto_SSL_use_certificate(JNIEnv* env, jclass,
                                             jlong ssl_address, jlongArray certificatesJava)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_use_certificate certificates=%p", ssl, certificatesJava);
    if (ssl == NULL) {
        return;
    }

    if (certificatesJava == NULL) {
        jniThrowNullPointerException(env, "certificates == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_use_certificate => certificates == null", ssl);
        return;
    }

    size_t length = env->GetArrayLength(certificatesJava);
    if (length == 0) {
        jniThrowException(env, "java/lang/IllegalArgumentException", "certificates.length == 0");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_use_certificate => certificates.length == 0", ssl);
        return;
    }

    ScopedLongArrayRO certificates(env, certificatesJava);
    if (certificates.get() == NULL) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_use_certificate => certificates == null", ssl);
        return;
    }

    Unique_X509 serverCert(
            X509_dup_nocopy(reinterpret_cast<X509*>(static_cast<uintptr_t>(certificates[0]))));
    if (serverCert.get() == NULL) {
        // Note this shouldn't happen since we checked the number of certificates above.
        jniThrowOutOfMemory(env, "Unable to allocate local certificate chain");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_use_certificate => chain allocation error", ssl);
        return;
    }

    int ret = SSL_use_certificate(ssl, serverCert.get());
    if (ret != 1) {
        ALOGE("%s", ERR_error_string(ERR_peek_error(), NULL));
        throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE, "Error setting certificate");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_use_certificate => SSL_use_certificate error", ssl);
        return;
    }
    OWNERSHIP_TRANSFERRED(serverCert);

#if !defined(OPENSSL_IS_BORINGSSL)
    Unique_sk_X509 chain(sk_X509_new_null());
    if (chain.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate local certificate chain");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_use_certificate => chain allocation error", ssl);
        return;
    }

    for (size_t i = 1; i < length; i++) {
        Unique_X509 cert(
                X509_dup_nocopy(reinterpret_cast<X509*>(static_cast<uintptr_t>(certificates[i]))));
        if (cert.get() == NULL || !sk_X509_push(chain.get(), cert.get())) {
            ALOGE("%s", ERR_error_string(ERR_peek_error(), NULL));
            throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE, "Error parsing certificate");
            safeSslClear(ssl);
            JNI_TRACE("ssl=%p NativeCrypto_SSL_use_certificate => certificates parsing error", ssl);
            return;
        }
        OWNERSHIP_TRANSFERRED(cert);
    }

    int chainResult = SSL_use_certificate_chain(ssl, chain.get());
    if (chainResult == 0) {
        throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE, "Error setting certificate chain");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_use_certificate => SSL_use_certificate_chain error",
                  ssl);
        return;
    }
    OWNERSHIP_TRANSFERRED(chain);
#else
    for (size_t i = 1; i < length; i++) {
        Unique_X509 cert(
                X509_dup_nocopy(reinterpret_cast<X509*>(static_cast<uintptr_t>(certificates[i]))));
        if (cert.get() == NULL || !SSL_add0_chain_cert(ssl, cert.get())) {
            ALOGE("%s", ERR_error_string(ERR_peek_error(), NULL));
            throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE, "Error parsing certificate");
            safeSslClear(ssl);
            JNI_TRACE("ssl=%p NativeCrypto_SSL_use_certificate => certificates parsing error", ssl);
            return;
        }
        OWNERSHIP_TRANSFERRED(cert);
    }
#endif

    JNI_TRACE("ssl=%p NativeCrypto_SSL_use_certificate => ok", ssl);
}

static void NativeCrypto_SSL_check_private_key(JNIEnv* env, jclass, jlong ssl_address)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_check_private_key", ssl);
    if (ssl == NULL) {
        return;
    }
    int ret = SSL_check_private_key(ssl);
    if (ret != 1) {
        throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE, "Error checking private key");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_check_private_key => error", ssl);
        return;
    }
    JNI_TRACE("ssl=%p NativeCrypto_SSL_check_private_key => ok", ssl);
}

static void NativeCrypto_SSL_set_client_CA_list(JNIEnv* env, jclass,
                                                jlong ssl_address, jobjectArray principals)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list principals=%p", ssl, principals);
    if (ssl == NULL) {
        return;
    }

    if (principals == NULL) {
        jniThrowNullPointerException(env, "principals == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => principals == null", ssl);
        return;
    }

    int length = env->GetArrayLength(principals);
    if (length == 0) {
        jniThrowException(env, "java/lang/IllegalArgumentException", "principals.length == 0");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => principals.length == 0", ssl);
        return;
    }

    Unique_sk_X509_NAME principalsStack(sk_X509_NAME_new_null());
    if (principalsStack.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate principal stack");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => stack allocation error", ssl);
        return;
    }
    for (int i = 0; i < length; i++) {
        ScopedLocalRef<jbyteArray> principal(env,
                reinterpret_cast<jbyteArray>(env->GetObjectArrayElement(principals, i)));
        if (principal.get() == NULL) {
            jniThrowNullPointerException(env, "principals element == null");
            JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => principals element null", ssl);
            return;
        }

        ScopedByteArrayRO buf(env, principal.get());
        if (buf.get() == NULL) {
            JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => threw exception", ssl);
            return;
        }
        const unsigned char* tmp = reinterpret_cast<const unsigned char*>(buf.get());
        Unique_X509_NAME principalX509Name(d2i_X509_NAME(NULL, &tmp, buf.size()));

        if (principalX509Name.get() == NULL) {
            ALOGE("%s", ERR_error_string(ERR_peek_error(), NULL));
            throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE, "Error parsing principal");
            safeSslClear(ssl);
            JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => principals parsing error",
                      ssl);
            return;
        }

        if (!sk_X509_NAME_push(principalsStack.get(), principalX509Name.release())) {
            jniThrowOutOfMemory(env, "Unable to push principal");
            JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => principal push error", ssl);
            return;
        }
    }

    SSL_set_client_CA_list(ssl, principalsStack.release());
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => ok", ssl);
}

/**
 * public static native long SSL_get_mode(long ssl);
 */
static jlong NativeCrypto_SSL_get_mode(JNIEnv* env, jclass, jlong ssl_address) {
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_mode", ssl);
    if (ssl == NULL) {
      return 0;
    }
    long mode = SSL_get_mode(ssl);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_mode => 0x%lx", ssl, mode);
    return mode;
}

/**
 * public static native long SSL_set_mode(long ssl, long mode);
 */
static jlong NativeCrypto_SSL_set_mode(JNIEnv* env, jclass,
        jlong ssl_address, jlong mode) {
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_mode mode=0x%llx", ssl, (long long) mode);
    if (ssl == NULL) {
      return 0;
    }
    long result = SSL_set_mode(ssl, mode);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_mode => 0x%lx", ssl, result);
    return result;
}

/**
 * public static native long SSL_clear_mode(long ssl, long mode);
 */
static jlong NativeCrypto_SSL_clear_mode(JNIEnv* env, jclass,
        jlong ssl_address, jlong mode) {
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_clear_mode mode=0x%llx", ssl, (long long) mode);
    if (ssl == NULL) {
      return 0;
    }
    long result = SSL_clear_mode(ssl, mode);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_clear_mode => 0x%lx", ssl, result);
    return result;
}

/**
 * public static native long SSL_get_options(long ssl);
 */
static jlong NativeCrypto_SSL_get_options(JNIEnv* env, jclass,
        jlong ssl_address) {
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_options", ssl);
    if (ssl == NULL) {
      return 0;
    }
    long options = SSL_get_options(ssl);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_options => 0x%lx", ssl, options);
    return options;
}

/**
 * public static native long SSL_set_options(long ssl, long options);
 */
static jlong NativeCrypto_SSL_set_options(JNIEnv* env, jclass,
        jlong ssl_address, jlong options) {
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_options options=0x%llx", ssl, (long long) options);
    if (ssl == NULL) {
      return 0;
    }
    long result = SSL_set_options(ssl, options);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_options => 0x%lx", ssl, result);
    return result;
}

/**
 * public static native long SSL_clear_options(long ssl, long options);
 */
static jlong NativeCrypto_SSL_clear_options(JNIEnv* env, jclass,
        jlong ssl_address, jlong options) {
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_clear_options options=0x%llx", ssl, (long long) options);
    if (ssl == NULL) {
      return 0;
    }
    long result = SSL_clear_options(ssl, options);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_clear_options => 0x%lx", ssl, result);
    return result;
}


static void NativeCrypto_SSL_use_psk_identity_hint(JNIEnv* env, jclass,
        jlong ssl_address, jstring identityHintJava)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_use_psk_identity_hint identityHint=%p",
            ssl, identityHintJava);
    if (ssl == NULL)  {
        return;
    }

    int ret;
    if (identityHintJava == NULL) {
        ret = SSL_use_psk_identity_hint(ssl, NULL);
    } else {
        ScopedUtfChars identityHint(env, identityHintJava);
        if (identityHint.c_str() == NULL) {
            throwSSLExceptionStr(env, "Failed to obtain identityHint bytes");
            return;
        }
        ret = SSL_use_psk_identity_hint(ssl, identityHint.c_str());
    }

    if (ret != 1) {
        int sslErrorCode = SSL_get_error(ssl, ret);
        throwSSLExceptionWithSslErrors(env, ssl, sslErrorCode, "Failed to set PSK identity hint");
        safeSslClear(ssl);
    }
}

static void NativeCrypto_set_SSL_psk_client_callback_enabled(JNIEnv* env, jclass,
        jlong ssl_address, jboolean enabled)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_set_SSL_psk_client_callback_enabled(%d)",
            ssl, enabled);
    if (ssl == NULL)  {
        return;
    }

    SSL_set_psk_client_callback(ssl, (enabled) ? psk_client_callback : NULL);
}

static void NativeCrypto_set_SSL_psk_server_callback_enabled(JNIEnv* env, jclass,
        jlong ssl_address, jboolean enabled)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_set_SSL_psk_server_callback_enabled(%d)",
            ssl, enabled);
    if (ssl == NULL)  {
        return;
    }

    SSL_set_psk_server_callback(ssl, (enabled) ? psk_server_callback : NULL);
}

static jlongArray NativeCrypto_SSL_get_ciphers(JNIEnv* env, jclass, jlong ssl_address)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_ciphers", ssl);

    STACK_OF(SSL_CIPHER)* cipherStack = SSL_get_ciphers(ssl);
    int count = (cipherStack != NULL) ? sk_SSL_CIPHER_num(cipherStack) : 0;
    ScopedLocalRef<jlongArray> ciphersArray(env, env->NewLongArray(count));
    ScopedLongArrayRW ciphers(env, ciphersArray.get());
    for (int i = 0; i < count; i++) {
        ciphers[i] = reinterpret_cast<jlong>(sk_SSL_CIPHER_value(cipherStack, i));
    }

    JNI_TRACE("NativeCrypto_SSL_get_ciphers(%p) => %p [size=%d]", ssl, ciphersArray.get(), count);
    return ciphersArray.release();
}

static jint NativeCrypto_get_SSL_CIPHER_algorithm_mkey(JNIEnv* env, jclass,
        jlong ssl_cipher_address)
{
    SSL_CIPHER* cipher = to_SSL_CIPHER(env, ssl_cipher_address, true);
    JNI_TRACE("cipher=%p get_SSL_CIPHER_algorithm_mkey => %ld", cipher, cipher->algorithm_mkey);
    return cipher->algorithm_mkey;
}

static jint NativeCrypto_get_SSL_CIPHER_algorithm_auth(JNIEnv* env, jclass,
        jlong ssl_cipher_address)
{
    SSL_CIPHER* cipher = to_SSL_CIPHER(env, ssl_cipher_address, true);
    JNI_TRACE("cipher=%p get_SSL_CIPHER_algorithm_auth => %ld", cipher, cipher->algorithm_auth);
    return cipher->algorithm_auth;
}

/**
 * Sets the ciphers suites that are enabled in the SSL
 */
static void NativeCrypto_SSL_set_cipher_lists(JNIEnv* env, jclass,
        jlong ssl_address, jobjectArray cipherSuites)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_cipher_lists cipherSuites=%p", ssl, cipherSuites);
    if (ssl == NULL) {
        return;
    }
    if (cipherSuites == NULL) {
        jniThrowNullPointerException(env, "cipherSuites == null");
        return;
    }

    int length = env->GetArrayLength(cipherSuites);
    static const char noSSLv2[] = "!SSLv2";
    size_t cipherStringLen = strlen(noSSLv2);

    for (int i = 0; i < length; i++) {
        ScopedLocalRef<jstring> cipherSuite(env,
                reinterpret_cast<jstring>(env->GetObjectArrayElement(cipherSuites, i)));
        ScopedUtfChars c(env, cipherSuite.get());
        if (c.c_str() == NULL) {
            return;
        }

        if (cipherStringLen + 1 < cipherStringLen) {
          jniThrowException(env, "java/lang/IllegalArgumentException",
                            "Overflow in cipher suite strings");
          return;
        }
        cipherStringLen += 1;  /* For the separating colon */

        if (cipherStringLen + c.size() < cipherStringLen) {
          jniThrowException(env, "java/lang/IllegalArgumentException",
                            "Overflow in cipher suite strings");
          return;
        }
        cipherStringLen += c.size();
    }

    if (cipherStringLen + 1 < cipherStringLen) {
      jniThrowException(env, "java/lang/IllegalArgumentException",
                        "Overflow in cipher suite strings");
      return;
    }
    cipherStringLen += 1;  /* For final NUL. */

    UniquePtr<char[]> cipherString(new char[cipherStringLen]);
    if (cipherString.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to alloc cipher string");
        return;
    }
    memcpy(cipherString.get(), noSSLv2, strlen(noSSLv2));
    size_t j = strlen(noSSLv2);

    for (int i = 0; i < length; i++) {
        ScopedLocalRef<jstring> cipherSuite(env,
                reinterpret_cast<jstring>(env->GetObjectArrayElement(cipherSuites, i)));
        ScopedUtfChars c(env, cipherSuite.get());

        cipherString[j++] = ':';
        memcpy(&cipherString[j], c.c_str(), c.size());
        j += c.size();
    }

    cipherString[j++] = 0;
    if (j != cipherStringLen) {
        jniThrowException(env, "java/lang/IllegalArgumentException",
                          "Internal error");
        return;
    }

    if (!SSL_set_cipher_list(ssl, cipherString.get())) {
        freeOpenSslErrorState();
        jniThrowException(env, "java/lang/IllegalArgumentException",
                          "Illegal cipher suite strings.");
        return;
    }
}

static void NativeCrypto_SSL_set_accept_state(JNIEnv* env, jclass, jlong sslRef) {
    SSL* ssl = to_SSL(env, sslRef, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_accept_state", ssl);
    if (ssl == NULL) {
      return;
    }
    SSL_set_accept_state(ssl);
}

static void NativeCrypto_SSL_set_connect_state(JNIEnv* env, jclass, jlong sslRef) {
    SSL* ssl = to_SSL(env, sslRef, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_connect_state", ssl);
    if (ssl == NULL) {
      return;
    }
    SSL_set_connect_state(ssl);
}

/**
 * Sets certificate expectations, especially for server to request client auth
 */
static void NativeCrypto_SSL_set_verify(JNIEnv* env,
        jclass, jlong ssl_address, jint mode)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_verify mode=%x", ssl, mode);
    if (ssl == NULL) {
      return;
    }
    SSL_set_verify(ssl, (int)mode, NULL);
}

/**
 * Sets the ciphers suites that are enabled in the SSL
 */
static void NativeCrypto_SSL_set_session(JNIEnv* env, jclass,
        jlong ssl_address, jlong ssl_session_address)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, false);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_session ssl_session=%p", ssl, ssl_session);
    if (ssl == NULL) {
        return;
    }

    int ret = SSL_set_session(ssl, ssl_session);
    if (ret != 1) {
        /*
         * Translate the error, and throw if it turns out to be a real
         * problem.
         */
        int sslErrorCode = SSL_get_error(ssl, ret);
        if (sslErrorCode != SSL_ERROR_ZERO_RETURN) {
            throwSSLExceptionWithSslErrors(env, ssl, sslErrorCode, "SSL session set");
            safeSslClear(ssl);
        }
    }
}

/**
 * Sets the ciphers suites that are enabled in the SSL
 */
static void NativeCrypto_SSL_set_session_creation_enabled(JNIEnv* env, jclass,
        jlong ssl_address, jboolean creation_enabled)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_session_creation_enabled creation_enabled=%d",
              ssl, creation_enabled);
    if (ssl == NULL) {
        return;
    }

#if !defined(OPENSSL_IS_BORINGSSL)
    SSL_set_session_creation_enabled(ssl, creation_enabled);
#else
    if (creation_enabled) {
        SSL_clear_mode(ssl, SSL_MODE_NO_SESSION_CREATION);
    } else {
        SSL_set_mode(ssl, SSL_MODE_NO_SESSION_CREATION);
    }
#endif
}

static void NativeCrypto_SSL_set_tlsext_host_name(JNIEnv* env, jclass,
        jlong ssl_address, jstring hostname)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_tlsext_host_name hostname=%p",
              ssl, hostname);
    if (ssl == NULL) {
        return;
    }

    ScopedUtfChars hostnameChars(env, hostname);
    if (hostnameChars.c_str() == NULL) {
        return;
    }
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_tlsext_host_name hostnameChars=%s",
              ssl, hostnameChars.c_str());

    int ret = SSL_set_tlsext_host_name(ssl, hostnameChars.c_str());
    if (ret != 1) {
        throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE, "Error setting host name");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_tlsext_host_name => error", ssl);
        return;
    }
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_tlsext_host_name => ok", ssl);
}

static jstring NativeCrypto_SSL_get_servername(JNIEnv* env, jclass, jlong ssl_address) {
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_servername", ssl);
    if (ssl == NULL) {
        return NULL;
    }
    const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_servername => %s", ssl, servername);
    return env->NewStringUTF(servername);
}

/**
 * A common selection path for both NPN and ALPN since they're essentially the
 * same protocol. The list of protocols in "primary" is considered the order
 * which should take precedence.
 */
static int proto_select(SSL* ssl __attribute__ ((unused)),
        unsigned char **out, unsigned char *outLength,
        const unsigned char *primary, const unsigned int primaryLength,
        const unsigned char *secondary, const unsigned int secondaryLength) {
    if (primary != NULL && secondary != NULL) {
        JNI_TRACE("primary=%p, length=%d", primary, primaryLength);

        int status = SSL_select_next_proto(out, outLength, primary, primaryLength, secondary,
                secondaryLength);
        switch (status) {
        case OPENSSL_NPN_NEGOTIATED:
            JNI_TRACE("ssl=%p proto_select NPN/ALPN negotiated", ssl);
            return SSL_TLSEXT_ERR_OK;
            break;
        case OPENSSL_NPN_UNSUPPORTED:
            JNI_TRACE("ssl=%p proto_select NPN/ALPN unsupported", ssl);
            break;
        case OPENSSL_NPN_NO_OVERLAP:
            JNI_TRACE("ssl=%p proto_select NPN/ALPN no overlap", ssl);
            break;
        }
    } else {
        if (out != NULL && outLength != NULL) {
            *out = NULL;
            *outLength = 0;
        }
        JNI_TRACE("protocols=NULL");
    }
    return SSL_TLSEXT_ERR_NOACK;
}

/**
 * Callback for the server to select an ALPN protocol.
 */
static int alpn_select_callback(SSL* ssl, const unsigned char **out, unsigned char *outlen,
        const unsigned char *in, unsigned int inlen, void *) {
    JNI_TRACE("ssl=%p alpn_select_callback", ssl);

    AppData* appData = toAppData(ssl);
    JNI_TRACE("AppData=%p", appData);

    return proto_select(ssl, const_cast<unsigned char **>(out), outlen,
            reinterpret_cast<unsigned char*>(appData->alpnProtocolsData),
            appData->alpnProtocolsLength, in, inlen);
}

/**
 * Callback for the client to select an NPN protocol.
 */
static int next_proto_select_callback(SSL* ssl, unsigned char** out, unsigned char* outlen,
                                      const unsigned char* in, unsigned int inlen, void*)
{
    JNI_TRACE("ssl=%p next_proto_select_callback", ssl);

    AppData* appData = toAppData(ssl);
    JNI_TRACE("AppData=%p", appData);

    // Enable False Start on the client if the server understands NPN
    // http://www.imperialviolet.org/2012/04/11/falsestart.html
    SSL_set_mode(ssl, SSL_MODE_HANDSHAKE_CUTTHROUGH);

    return proto_select(ssl, out, outlen, in, inlen,
            reinterpret_cast<unsigned char*>(appData->npnProtocolsData),
            appData->npnProtocolsLength);
}

/**
 * Callback for the server to advertise available protocols.
 */
static int next_protos_advertised_callback(SSL* ssl,
        const unsigned char **out, unsigned int *outlen, void *)
{
    JNI_TRACE("ssl=%p next_protos_advertised_callback", ssl);
    AppData* appData = toAppData(ssl);
    unsigned char* npnProtocols = reinterpret_cast<unsigned char*>(appData->npnProtocolsData);
    if (npnProtocols != NULL) {
        *out = npnProtocols;
        *outlen = appData->npnProtocolsLength;
        return SSL_TLSEXT_ERR_OK;
    } else {
        *out = NULL;
        *outlen = 0;
        return SSL_TLSEXT_ERR_NOACK;
    }
}

static void NativeCrypto_SSL_CTX_enable_npn(JNIEnv* env, jclass, jlong ssl_ctx_address)
{
    SSL_CTX* ssl_ctx = to_SSL_CTX(env, ssl_ctx_address, true);
    if (ssl_ctx == NULL) {
        return;
    }
    SSL_CTX_set_next_proto_select_cb(ssl_ctx, next_proto_select_callback, NULL); // client
    SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_protos_advertised_callback, NULL); // server
}

static void NativeCrypto_SSL_CTX_disable_npn(JNIEnv* env, jclass, jlong ssl_ctx_address)
{
    SSL_CTX* ssl_ctx = to_SSL_CTX(env, ssl_ctx_address, true);
    if (ssl_ctx == NULL) {
        return;
    }
    SSL_CTX_set_next_proto_select_cb(ssl_ctx, NULL, NULL); // client
    SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, NULL, NULL); // server
}

static jbyteArray NativeCrypto_SSL_get_npn_negotiated_protocol(JNIEnv* env, jclass,
        jlong ssl_address)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_npn_negotiated_protocol", ssl);
    if (ssl == NULL) {
        return NULL;
    }
    const jbyte* npn;
    unsigned npnLength;
    SSL_get0_next_proto_negotiated(ssl, reinterpret_cast<const unsigned char**>(&npn), &npnLength);
    if (npnLength == 0) {
        return NULL;
    }
    jbyteArray result = env->NewByteArray(npnLength);
    if (result != NULL) {
        env->SetByteArrayRegion(result, 0, npnLength, npn);
    }
    return result;
}

static int NativeCrypto_SSL_set_alpn_protos(JNIEnv* env, jclass, jlong ssl_address,
        jbyteArray protos) {
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == NULL) {
        return 0;
    }

    JNI_TRACE("ssl=%p SSL_set_alpn_protos protos=%p", ssl, protos);

    if (protos == NULL) {
        JNI_TRACE("ssl=%p SSL_set_alpn_protos protos=NULL", ssl);
        return 1;
    }

    ScopedByteArrayRO protosBytes(env, protos);
    if (protosBytes.get() == NULL) {
        JNI_TRACE("ssl=%p SSL_set_alpn_protos protos=%p => protosBytes == NULL", ssl,
                protos);
        return 0;
    }

    const unsigned char *tmp = reinterpret_cast<const unsigned char*>(protosBytes.get());
    int ret = SSL_set_alpn_protos(ssl, tmp, protosBytes.size());
    JNI_TRACE("ssl=%p SSL_set_alpn_protos protos=%p => ret=%d", ssl, protos, ret);
    return ret;
}

static jbyteArray NativeCrypto_SSL_get0_alpn_selected(JNIEnv* env, jclass,
        jlong ssl_address)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p SSL_get0_alpn_selected", ssl);
    if (ssl == NULL) {
        return NULL;
    }
    const jbyte* npn;
    unsigned npnLength;
    SSL_get0_alpn_selected(ssl, reinterpret_cast<const unsigned char**>(&npn), &npnLength);
    if (npnLength == 0) {
        return NULL;
    }
    jbyteArray result = env->NewByteArray(npnLength);
    if (result != NULL) {
        env->SetByteArrayRegion(result, 0, npnLength, npn);
    }
    return result;
}

#ifdef WITH_JNI_TRACE_KEYS
static inline char hex_char(unsigned char in)
{
    if (in < 10) {
        return '0' + in;
    } else if (in <= 0xF0) {
        return 'A' + in - 10;
    } else {
        return '?';
    }
}

static void hex_string(char **dest, unsigned char* input, int len)
{
    *dest = (char*) malloc(len * 2 + 1);
    char *output = *dest;
    for (int i = 0; i < len; i++) {
        *output++ = hex_char(input[i] >> 4);
        *output++ = hex_char(input[i] & 0xF);
    }
    *output = '\0';
}

static void debug_print_session_key(SSL_SESSION* session)
{
    char *session_id_str;
    char *master_key_str;
    const char *key_type;
    char *keyline;

    hex_string(&session_id_str, session->session_id, session->session_id_length);
    hex_string(&master_key_str, session->master_key, session->master_key_length);

    X509* peer = SSL_SESSION_get0_peer(session);
    EVP_PKEY* pkey = X509_PUBKEY_get(peer->cert_info->key);
    switch (EVP_PKEY_type(pkey->type)) {
    case EVP_PKEY_RSA:
        key_type = "RSA";
        break;
    case EVP_PKEY_DSA:
        key_type = "DSA";
        break;
    case EVP_PKEY_EC:
        key_type = "EC";
        break;
    default:
        key_type = "Unknown";
        break;
    }

    asprintf(&keyline, "%s Session-ID:%s Master-Key:%s\n", key_type, session_id_str,
            master_key_str);
    JNI_TRACE("ssl_session=%p %s", session, keyline);

    free(session_id_str);
    free(master_key_str);
    free(keyline);
}
#endif /* WITH_JNI_TRACE_KEYS */

/**
 * Perform SSL handshake
 */
static jlong NativeCrypto_SSL_do_handshake_bio(JNIEnv* env, jclass, jlong ssl_address,
        jlong rbioRef, jlong wbioRef, jobject shc, jboolean client_mode, jbyteArray npnProtocols,
        jbyteArray alpnProtocols) {
    SSL* ssl = to_SSL(env, ssl_address, true);
    BIO* rbio = reinterpret_cast<BIO*>(rbioRef);
    BIO* wbio = reinterpret_cast<BIO*>(wbioRef);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake_bio rbio=%p wbio=%p shc=%p client_mode=%d npn=%p",
              ssl, rbio, wbio, shc, client_mode, npnProtocols);
    if (ssl == NULL) {
        return 0;
    }
    if (shc == NULL) {
        jniThrowNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake_bio sslHandshakeCallbacks == null => 0", ssl);
        return 0;
    }

    if (rbio == NULL || wbio == NULL) {
        jniThrowNullPointerException(env, "rbio == null || wbio == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake_bio => rbio == null || wbio == NULL", ssl);
        return 0;
    }

    ScopedSslBio sslBio(ssl, rbio, wbio);

    AppData* appData = toAppData(ssl);
    if (appData == NULL) {
        throwSSLExceptionStr(env, "Unable to retrieve application data");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake appData => 0", ssl);
        return 0;
    }

    if (!client_mode && alpnProtocols != NULL) {
        SSL_CTX_set_alpn_select_cb(SSL_get_SSL_CTX(ssl), alpn_select_callback, NULL);
    }

    int ret = 0;
    errno = 0;

    if (!appData->setCallbackState(env, shc, NULL, npnProtocols, alpnProtocols)) {
        freeOpenSslErrorState();
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake_bio setCallbackState => 0", ssl);
        return 0;
    }
    ret = SSL_do_handshake(ssl);
    appData->clearCallbackState();
    // cert_verify_callback threw exception
    if (env->ExceptionCheck()) {
        freeOpenSslErrorState();
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake_bio exception => 0", ssl);
        return 0;
    }

    if (ret <= 0) { // error. See SSL_do_handshake(3SSL) man page.
        // error case
        OpenSslError sslError(ssl, ret);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake_bio ret=%d errno=%d sslError=%d",
                  ssl, ret, errno, sslError.get());

        /*
         * If SSL_do_handshake doesn't succeed due to the socket being
         * either unreadable or unwritable, we need to exit to allow
         * the SSLEngine code to wrap or unwrap.
         */
        if (sslError.get() == SSL_ERROR_NONE ||
                (sslError.get() == SSL_ERROR_SYSCALL && errno == 0) ||
                (sslError.get() == SSL_ERROR_ZERO_RETURN)) {
            throwSSLHandshakeExceptionStr(env, "Connection closed by peer");
            safeSslClear(ssl);
        } else if (sslError.get() != SSL_ERROR_WANT_READ &&
                sslError.get() != SSL_ERROR_WANT_WRITE) {
            throwSSLExceptionWithSslErrors(env, ssl, sslError.release(),
                    "SSL handshake terminated", throwSSLHandshakeExceptionStr);
            safeSslClear(ssl);
        }
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake_bio error => 0", ssl);
        return 0;
    }

    // success. handshake completed
    SSL_SESSION* ssl_session = SSL_get1_session(ssl);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake_bio => ssl_session=%p", ssl, ssl_session);
#ifdef WITH_JNI_TRACE_KEYS
    debug_print_session_key(ssl_session);
#endif
    return reinterpret_cast<uintptr_t>(ssl_session);
}

/**
 * Perform SSL handshake
 */
static jlong NativeCrypto_SSL_do_handshake(JNIEnv* env, jclass, jlong ssl_address, jobject fdObject,
        jobject shc, jint timeout_millis, jboolean client_mode, jbyteArray npnProtocols,
        jbyteArray alpnProtocols) {
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake fd=%p shc=%p timeout_millis=%d client_mode=%d npn=%p",
              ssl, fdObject, shc, timeout_millis, client_mode, npnProtocols);
    if (ssl == NULL) {
        return 0;
    }
    if (fdObject == NULL) {
        jniThrowNullPointerException(env, "fd == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake fd == null => 0", ssl);
        return 0;
    }
    if (shc == NULL) {
        jniThrowNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake sslHandshakeCallbacks == null => 0", ssl);
        return 0;
    }

    NetFd fd(env, fdObject);
    if (fd.isClosed()) {
        // SocketException thrown by NetFd.isClosed
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake fd.isClosed() => 0", ssl);
        return 0;
    }

    int ret = SSL_set_fd(ssl, fd.get());
    JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake s=%d", ssl, fd.get());

    if (ret != 1) {
        throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE,
                                       "Error setting the file descriptor");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake SSL_set_fd => 0", ssl);
        return 0;
    }

    /*
     * Make socket non-blocking, so SSL_connect SSL_read() and SSL_write() don't hang
     * forever and we can use select() to find out if the socket is ready.
     */
    if (!setBlocking(fd.get(), false)) {
        throwSSLExceptionStr(env, "Unable to make socket non blocking");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake setBlocking => 0", ssl);
        return 0;
    }

    AppData* appData = toAppData(ssl);
    if (appData == NULL) {
        throwSSLExceptionStr(env, "Unable to retrieve application data");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake appData => 0", ssl);
        return 0;
    }

    if (client_mode) {
        SSL_set_connect_state(ssl);
    } else {
        SSL_set_accept_state(ssl);
        if (alpnProtocols != NULL) {
            SSL_CTX_set_alpn_select_cb(SSL_get_SSL_CTX(ssl), alpn_select_callback, NULL);
        }
    }

    ret = 0;
    OpenSslError sslError;
    while (appData->aliveAndKicking) {
        errno = 0;

        if (!appData->setCallbackState(env, shc, fdObject, npnProtocols, alpnProtocols)) {
            // SocketException thrown by NetFd.isClosed
            safeSslClear(ssl);
            JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake setCallbackState => 0", ssl);
            return 0;
        }
        ret = SSL_do_handshake(ssl);
        appData->clearCallbackState();
        // cert_verify_callback threw exception
        if (env->ExceptionCheck()) {
            freeOpenSslErrorState();
            safeSslClear(ssl);
            JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake exception => 0", ssl);
            return 0;
        }
        // success case
        if (ret == 1) {
            break;
        }
        // retry case
        if (errno == EINTR) {
            continue;
        }
        // error case
        sslError.reset(ssl, ret);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake ret=%d errno=%d sslError=%d timeout_millis=%d",
                  ssl, ret, errno, sslError.get(), timeout_millis);

        /*
         * If SSL_do_handshake doesn't succeed due to the socket being
         * either unreadable or unwritable, we use sslSelect to
         * wait for it to become ready. If that doesn't happen
         * before the specified timeout or an error occurs, we
         * cancel the handshake. Otherwise we try the SSL_connect
         * again.
         */
        if (sslError.get() == SSL_ERROR_WANT_READ || sslError.get() == SSL_ERROR_WANT_WRITE) {
            appData->waitingThreads++;
            int selectResult = sslSelect(env, sslError.get(), fdObject, appData, timeout_millis);

            if (selectResult == THROWN_EXCEPTION) {
                // SocketException thrown by NetFd.isClosed
                safeSslClear(ssl);
                JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake sslSelect => 0", ssl);
                return 0;
            }
            if (selectResult == -1) {
                throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_SYSCALL, "handshake error",
                        throwSSLHandshakeExceptionStr);
                safeSslClear(ssl);
                JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake selectResult == -1 => 0", ssl);
                return 0;
            }
            if (selectResult == 0) {
                throwSocketTimeoutException(env, "SSL handshake timed out");
                freeOpenSslErrorState();
                safeSslClear(ssl);
                JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake selectResult == 0 => 0", ssl);
                return 0;
            }
        } else {
            // ALOGE("Unknown error %d during handshake", error);
            break;
        }
    }

    // clean error. See SSL_do_handshake(3SSL) man page.
    if (ret == 0) {
        /*
         * The other side closed the socket before the handshake could be
         * completed, but everything is within the bounds of the TLS protocol.
         * We still might want to find out the real reason of the failure.
         */
        if (sslError.get() == SSL_ERROR_NONE ||
                (sslError.get() == SSL_ERROR_SYSCALL && errno == 0) ||
                (sslError.get() == SSL_ERROR_ZERO_RETURN)) {
            throwSSLHandshakeExceptionStr(env, "Connection closed by peer");
        } else {
            throwSSLExceptionWithSslErrors(env, ssl, sslError.release(),
                    "SSL handshake terminated", throwSSLHandshakeExceptionStr);
        }
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake clean error => 0", ssl);
        return 0;
    }

    // unclean error. See SSL_do_handshake(3SSL) man page.
    if (ret < 0) {
        /*
         * Translate the error and throw exception. We are sure it is an error
         * at this point.
         */
        throwSSLExceptionWithSslErrors(env, ssl, sslError.release(), "SSL handshake aborted",
                throwSSLHandshakeExceptionStr);
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake unclean error => 0", ssl);
        return 0;
    }
    SSL_SESSION* ssl_session = SSL_get1_session(ssl);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake => ssl_session=%p", ssl, ssl_session);
#ifdef WITH_JNI_TRACE_KEYS
    debug_print_session_key(ssl_session);
#endif
    return (jlong) ssl_session;
}

/**
 * Perform SSL renegotiation
 */
static void NativeCrypto_SSL_renegotiate(JNIEnv* env, jclass, jlong ssl_address)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_renegotiate", ssl);
    if (ssl == NULL) {
        return;
    }
    int result = SSL_renegotiate(ssl);
    if (result != 1) {
        throwSSLExceptionStr(env, "Problem with SSL_renegotiate");
        return;
    }
    // first call asks client to perform renegotiation
    int ret = SSL_do_handshake(ssl);
    if (ret != 1) {
        OpenSslError sslError(ssl, ret);
        throwSSLExceptionWithSslErrors(env, ssl, sslError.release(),
                                       "Problem with SSL_do_handshake after SSL_renegotiate");
        return;
    }
    // if client agrees, set ssl state and perform renegotiation
    ssl->state = SSL_ST_ACCEPT;
    SSL_do_handshake(ssl);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_renegotiate =>", ssl);
}

/**
 * public static native byte[][] SSL_get_certificate(long ssl);
 */
static jlongArray NativeCrypto_SSL_get_certificate(JNIEnv* env, jclass, jlong ssl_address)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_certificate", ssl);
    if (ssl == NULL) {
        return NULL;
    }
    X509* certificate = SSL_get_certificate(ssl);
    if (certificate == NULL) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_get_certificate => NULL", ssl);
        // SSL_get_certificate can return NULL during an error as well.
        freeOpenSslErrorState();
        return NULL;
    }

    Unique_sk_X509 chain(sk_X509_new_null());
    if (chain.get() == NULL) {
        jniThrowOutOfMemory(env, "Unable to allocate local certificate chain");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_get_certificate => threw exception", ssl);
        return NULL;
    }
    if (!sk_X509_push(chain.get(), X509_dup_nocopy(certificate))) {
        jniThrowOutOfMemory(env, "Unable to push local certificate");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_get_certificate => NULL", ssl);
        return NULL;
    }

#if !defined(OPENSSL_IS_BORINGSSL)
    STACK_OF(X509)* cert_chain = SSL_get_certificate_chain(ssl, certificate);
    for (int i=0; i<sk_X509_num(cert_chain); i++) {
        if (!sk_X509_push(chain.get(), X509_dup_nocopy(sk_X509_value(cert_chain, i)))) {
            jniThrowOutOfMemory(env, "Unable to push local certificate chain");
            JNI_TRACE("ssl=%p NativeCrypto_SSL_get_certificate => NULL", ssl);
            return NULL;
        }
    }
#else
    STACK_OF(X509) *cert_chain = NULL;
    if (!SSL_get0_chain_certs(ssl, &cert_chain)) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_get0_chain_certs => NULL", ssl);
        freeOpenSslErrorState();
        return NULL;
    }

    for (size_t i=0; i<sk_X509_num(cert_chain); i++) {
        if (!sk_X509_push(chain.get(), X509_dup_nocopy(sk_X509_value(cert_chain, i)))) {
            jniThrowOutOfMemory(env, "Unable to push local certificate chain");
            JNI_TRACE("ssl=%p NativeCrypto_SSL_get_certificate => NULL", ssl);
            return NULL;
        }
    }
#endif

    jlongArray refArray = getCertificateRefs(env, chain.get());
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_certificate => %p", ssl, refArray);
    return refArray;
}

// Fills a long[] with the peer certificates in the chain.
static jlongArray NativeCrypto_SSL_get_peer_cert_chain(JNIEnv* env, jclass, jlong ssl_address)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_peer_cert_chain", ssl);
    if (ssl == NULL) {
        return NULL;
    }
    STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
    Unique_sk_X509 chain_copy(NULL);
    if (ssl->server) {
        X509* x509 = SSL_get_peer_certificate(ssl);
        if (x509 == NULL) {
            JNI_TRACE("ssl=%p NativeCrypto_SSL_get_peer_cert_chain => NULL", ssl);
            return NULL;
        }
        chain_copy.reset(sk_X509_new_null());
        if (chain_copy.get() == NULL) {
            jniThrowOutOfMemory(env, "Unable to allocate peer certificate chain");
            JNI_TRACE("ssl=%p NativeCrypto_SSL_get_peer_cert_chain => certificate dup error", ssl);
            return NULL;
        }
        size_t chain_size = sk_X509_num(chain);
        for (size_t i = 0; i < chain_size; i++) {
            if (!sk_X509_push(chain_copy.get(), X509_dup_nocopy(sk_X509_value(chain, i)))) {
                jniThrowOutOfMemory(env, "Unable to push server's peer certificate chain");
                JNI_TRACE("ssl=%p NativeCrypto_SSL_get_peer_cert_chain => certificate chain push error", ssl);
                return NULL;
            }
        }
        if (!sk_X509_push(chain_copy.get(), X509_dup_nocopy(x509))) {
            jniThrowOutOfMemory(env, "Unable to push server's peer certificate");
            JNI_TRACE("ssl=%p NativeCrypto_SSL_get_peer_cert_chain => certificate push error", ssl);
            return NULL;
        }
        chain = chain_copy.get();
    }
    jlongArray refArray = getCertificateRefs(env, chain);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_peer_cert_chain => %p", ssl, refArray);
    return refArray;
}

static int sslRead(JNIEnv* env, SSL* ssl, jobject fdObject, jobject shc, char* buf, jint len,
                   OpenSslError& sslError, int read_timeout_millis) {
    JNI_TRACE("ssl=%p sslRead buf=%p len=%d", ssl, buf, len);

    if (len == 0) {
        // Don't bother doing anything in this case.
        return 0;
    }

    BIO* rbio = SSL_get_rbio(ssl);
    BIO* wbio = SSL_get_wbio(ssl);

    AppData* appData = toAppData(ssl);
    JNI_TRACE("ssl=%p sslRead appData=%p", ssl, appData);
    if (appData == NULL) {
        return THROW_SSLEXCEPTION;
    }

    while (appData->aliveAndKicking) {
        errno = 0;

        if (MUTEX_LOCK(appData->mutex) == -1) {
            return -1;
        }

        if (!SSL_is_init_finished(ssl) && !SSL_cutthrough_complete(ssl) &&
               !SSL_renegotiate_pending(ssl)) {
            JNI_TRACE("ssl=%p sslRead => init is not finished (state=0x%x)", ssl,
                    SSL_get_state(ssl));
            MUTEX_UNLOCK(appData->mutex);
            return THROW_SSLEXCEPTION;
        }

        unsigned int bytesMoved = BIO_number_read(rbio) + BIO_number_written(wbio);

        if (!appData->setCallbackState(env, shc, fdObject, NULL, NULL)) {
            MUTEX_UNLOCK(appData->mutex);
            return THROWN_EXCEPTION;
        }
        int result = SSL_read(ssl, buf, len);
        appData->clearCallbackState();
        // callbacks can happen if server requests renegotiation
        if (env->ExceptionCheck()) {
            safeSslClear(ssl);
            JNI_TRACE("ssl=%p sslRead => THROWN_EXCEPTION", ssl);
            MUTEX_UNLOCK(appData->mutex);
            return THROWN_EXCEPTION;
        }
        sslError.reset(ssl, result);
        JNI_TRACE("ssl=%p sslRead SSL_read result=%d sslError=%d", ssl, result, sslError.get());
#ifdef WITH_JNI_TRACE_DATA
        for (int i = 0; i < result; i+= WITH_JNI_TRACE_DATA_CHUNK_SIZE) {
            int n = result - i;
            if (n > WITH_JNI_TRACE_DATA_CHUNK_SIZE) {
                n = WITH_JNI_TRACE_DATA_CHUNK_SIZE;
            }
            JNI_TRACE("ssl=%p sslRead data: %d:\n%.*s", ssl, n, n, buf+i);
        }
#endif

        // If we have been successful in moving data around, check whether it
        // might make sense to wake up other blocked threads, so they can give
        // it a try, too.
        if (BIO_number_read(rbio) + BIO_number_written(wbio) != bytesMoved
                && appData->waitingThreads > 0) {
            sslNotify(appData);
        }

        // If we are blocked by the underlying socket, tell the world that
        // there will be one more waiting thread now.
        if (sslError.get() == SSL_ERROR_WANT_READ || sslError.get() == SSL_ERROR_WANT_WRITE) {
            appData->waitingThreads++;
        }

        MUTEX_UNLOCK(appData->mutex);

        switch (sslError.get()) {
            // Successfully read at least one byte.
            case SSL_ERROR_NONE: {
                return result;
            }

            // Read zero bytes. End of stream reached.
            case SSL_ERROR_ZERO_RETURN: {
                return -1;
            }

            // Need to wait for availability of underlying layer, then retry.
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE: {
                int selectResult = sslSelect(env, sslError.get(), fdObject, appData, read_timeout_millis);
                if (selectResult == THROWN_EXCEPTION) {
                    return THROWN_EXCEPTION;
                }
                if (selectResult == -1) {
                    return THROW_SSLEXCEPTION;
                }
                if (selectResult == 0) {
                    return THROW_SOCKETTIMEOUTEXCEPTION;
                }

                break;
            }

            // A problem occurred during a system call, but this is not
            // necessarily an error.
            case SSL_ERROR_SYSCALL: {
                // Connection closed without proper shutdown. Tell caller we
                // have reached end-of-stream.
                if (result == 0) {
                    return -1;
                }

                // System call has been interrupted. Simply retry.
                if (errno == EINTR) {
                    break;
                }

                // Note that for all other system call errors we fall through
                // to the default case, which results in an Exception.
                FALLTHROUGH_INTENDED;
            }

            // Everything else is basically an error.
            default: {
                return THROW_SSLEXCEPTION;
            }
        }
    }

    return -1;
}

static jint NativeCrypto_SSL_read_BIO(JNIEnv* env, jclass, jlong sslRef, jbyteArray destJava,
        jint destOffset, jint destLength, jlong sourceBioRef, jlong sinkBioRef, jobject shc) {
    SSL* ssl = to_SSL(env, sslRef, true);
    BIO* rbio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(sourceBioRef));
    BIO* wbio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(sinkBioRef));
    JNI_TRACE("ssl=%p NativeCrypto_SSL_read_BIO dest=%p sourceBio=%p sinkBio=%p shc=%p",
              ssl, destJava, rbio, wbio, shc);
    if (ssl == NULL) {
        return 0;
    }
    if (rbio == NULL || wbio == NULL) {
        jniThrowNullPointerException(env, "rbio == null || wbio == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read_BIO => rbio == null || wbio == null", ssl);
        return -1;
    }
    if (shc == NULL) {
        jniThrowNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read_BIO => sslHandshakeCallbacks == null", ssl);
        return -1;
    }

    ScopedByteArrayRW dest(env, destJava);
    if (dest.get() == NULL) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read_BIO => threw exception", ssl);
        return -1;
    }
    if (destOffset < 0 || destOffset > ssize_t(dest.size()) || destLength < 0
            || destLength > (ssize_t) dest.size() - destOffset) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read_BIO => destOffset=%d, destLength=%d, size=%zd",
                  ssl, destOffset, destLength, dest.size());
        jniThrowException(env, "java/lang/ArrayIndexOutOfBoundsException", NULL);
        return -1;
    }

    AppData* appData = toAppData(ssl);
    if (appData == NULL) {
        throwSSLExceptionStr(env, "Unable to retrieve application data");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read_BIO => appData == NULL", ssl);
        return -1;
    }

    errno = 0;

    if (MUTEX_LOCK(appData->mutex) == -1) {
        return -1;
    }

    if (!appData->setCallbackState(env, shc, NULL, NULL, NULL)) {
        MUTEX_UNLOCK(appData->mutex);
        throwSSLExceptionStr(env, "Unable to set callback state");
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read_BIO => set callback state failed", ssl);
        return -1;
    }

    ScopedSslBio sslBio(ssl, rbio, wbio);

    int result = SSL_read(ssl, dest.get() + destOffset, destLength);
    appData->clearCallbackState();
    // callbacks can happen if server requests renegotiation
    if (env->ExceptionCheck()) {
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read_BIO => threw exception", ssl);
        return THROWN_EXCEPTION;
    }
    OpenSslError sslError(ssl, result);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_read_BIO SSL_read result=%d sslError=%d", ssl, result,
              sslError.get());
#ifdef WITH_JNI_TRACE_DATA
    for (int i = 0; i < result; i+= WITH_JNI_TRACE_DATA_CHUNK_SIZE) {
        int n = result - i;
        if (n > WITH_JNI_TRACE_DATA_CHUNK_SIZE) {
            n = WITH_JNI_TRACE_DATA_CHUNK_SIZE;
        }
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read_BIO data: %d:\n%.*s", ssl, n, n, buf+i);
    }
#endif

    MUTEX_UNLOCK(appData->mutex);

    switch (sslError.get()) {
        // Successfully read at least one byte.
        case SSL_ERROR_NONE:
            break;

        // Read zero bytes. End of stream reached.
        case SSL_ERROR_ZERO_RETURN:
            result = -1;
            break;

        // Need to wait for availability of underlying layer, then retry.
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            result = 0;
            break;

        // A problem occurred during a system call, but this is not
        // necessarily an error.
        case SSL_ERROR_SYSCALL: {
            // Connection closed without proper shutdown. Tell caller we
            // have reached end-of-stream.
            if (result == 0) {
                result = -1;
                break;
            } else if (errno == EINTR) {
                // System call has been interrupted. Simply retry.
                result = 0;
                break;
            }

            // Note that for all other system call errors we fall through
            // to the default case, which results in an Exception.
            FALLTHROUGH_INTENDED;
        }

        // Everything else is basically an error.
        default: {
            throwSSLExceptionWithSslErrors(env, ssl, sslError.release(), "Read error");
            return -1;
        }
    }
    JNI_TRACE("ssl=%p NativeCrypto_SSL_read_BIO => %d", ssl, result);
    return result;
}

/**
 * OpenSSL read function (2): read into buffer at offset n chunks.
 * Returns 1 (success) or value <= 0 (failure).
 */
static jint NativeCrypto_SSL_read(JNIEnv* env, jclass, jlong ssl_address, jobject fdObject,
                                  jobject shc, jbyteArray b, jint offset, jint len,
                                  jint read_timeout_millis)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_read fd=%p shc=%p b=%p offset=%d len=%d read_timeout_millis=%d",
              ssl, fdObject, shc, b, offset, len, read_timeout_millis);
    if (ssl == NULL) {
        return 0;
    }
    if (fdObject == NULL) {
        jniThrowNullPointerException(env, "fd == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read => fd == null", ssl);
        return 0;
    }
    if (shc == NULL) {
        jniThrowNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read => sslHandshakeCallbacks == null", ssl);
        return 0;
    }

    ScopedByteArrayRW bytes(env, b);
    if (bytes.get() == NULL) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read => threw exception", ssl);
        return 0;
    }

    OpenSslError sslError;
    int ret = sslRead(env, ssl, fdObject, shc, reinterpret_cast<char*>(bytes.get() + offset), len,
                      sslError, read_timeout_millis);

    int result;
    switch (ret) {
        case THROW_SSLEXCEPTION:
            // See sslRead() regarding improper failure to handle normal cases.
            throwSSLExceptionWithSslErrors(env, ssl, sslError.release(), "Read error");
            result = -1;
            break;
        case THROW_SOCKETTIMEOUTEXCEPTION:
            throwSocketTimeoutException(env, "Read timed out");
            result = -1;
            break;
        case THROWN_EXCEPTION:
            // SocketException thrown by NetFd.isClosed
            // or RuntimeException thrown by callback
            result = -1;
            break;
        default:
            result = ret;
            break;
    }

    JNI_TRACE("ssl=%p NativeCrypto_SSL_read => %d", ssl, result);
    return result;
}

static int sslWrite(JNIEnv* env, SSL* ssl, jobject fdObject, jobject shc, const char* buf, jint len,
                    OpenSslError& sslError, int write_timeout_millis) {
    JNI_TRACE("ssl=%p sslWrite buf=%p len=%d write_timeout_millis=%d",
              ssl, buf, len, write_timeout_millis);

    if (len == 0) {
        // Don't bother doing anything in this case.
        return 0;
    }

    BIO* rbio = SSL_get_rbio(ssl);
    BIO* wbio = SSL_get_wbio(ssl);

    AppData* appData = toAppData(ssl);
    JNI_TRACE("ssl=%p sslWrite appData=%p", ssl, appData);
    if (appData == NULL) {
        return THROW_SSLEXCEPTION;
    }

    int count = len;

    while (appData->aliveAndKicking && ((len > 0) || (ssl->s3->wbuf.left > 0))) {
        errno = 0;

        if (MUTEX_LOCK(appData->mutex) == -1) {
            return -1;
        }

        if (!SSL_is_init_finished(ssl) && !SSL_cutthrough_complete(ssl) &&
               !SSL_renegotiate_pending(ssl)) {
            JNI_TRACE("ssl=%p sslWrite => init is not finished (state=0x%x)", ssl,
                    SSL_get_state(ssl));
            MUTEX_UNLOCK(appData->mutex);
            return THROW_SSLEXCEPTION;
        }

        unsigned int bytesMoved = BIO_number_read(rbio) + BIO_number_written(wbio);

        if (!appData->setCallbackState(env, shc, fdObject, NULL, NULL)) {
            MUTEX_UNLOCK(appData->mutex);
            return THROWN_EXCEPTION;
        }
        JNI_TRACE("ssl=%p sslWrite SSL_write len=%d left=%d", ssl, len, ssl->s3->wbuf.left);
        int result = SSL_write(ssl, buf, len);
        appData->clearCallbackState();
        // callbacks can happen if server requests renegotiation
        if (env->ExceptionCheck()) {
            safeSslClear(ssl);
            JNI_TRACE("ssl=%p sslWrite exception => THROWN_EXCEPTION", ssl);
            return THROWN_EXCEPTION;
        }
        sslError.reset(ssl, result);
        JNI_TRACE("ssl=%p sslWrite SSL_write result=%d sslError=%d left=%d",
                  ssl, result, sslError.get(), ssl->s3->wbuf.left);
#ifdef WITH_JNI_TRACE_DATA
        for (int i = 0; i < result; i+= WITH_JNI_TRACE_DATA_CHUNK_SIZE) {
            int n = result - i;
            if (n > WITH_JNI_TRACE_DATA_CHUNK_SIZE) {
                n = WITH_JNI_TRACE_DATA_CHUNK_SIZE;
            }
            JNI_TRACE("ssl=%p sslWrite data: %d:\n%.*s", ssl, n, n, buf+i);
        }
#endif

        // If we have been successful in moving data around, check whether it
        // might make sense to wake up other blocked threads, so they can give
        // it a try, too.
        if (BIO_number_read(rbio) + BIO_number_written(wbio) != bytesMoved
                && appData->waitingThreads > 0) {
            sslNotify(appData);
        }

        // If we are blocked by the underlying socket, tell the world that
        // there will be one more waiting thread now.
        if (sslError.get() == SSL_ERROR_WANT_READ || sslError.get() == SSL_ERROR_WANT_WRITE) {
            appData->waitingThreads++;
        }

        MUTEX_UNLOCK(appData->mutex);

        switch (sslError.get()) {
            // Successfully wrote at least one byte.
            case SSL_ERROR_NONE: {
                buf += result;
                len -= result;
                break;
            }

            // Wrote zero bytes. End of stream reached.
            case SSL_ERROR_ZERO_RETURN: {
                return -1;
            }

            // Need to wait for availability of underlying layer, then retry.
            // The concept of a write timeout doesn't really make sense, and
            // it's also not standard Java behavior, so we wait forever here.
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE: {
                int selectResult = sslSelect(env, sslError.get(), fdObject, appData,
                                             write_timeout_millis);
                if (selectResult == THROWN_EXCEPTION) {
                    return THROWN_EXCEPTION;
                }
                if (selectResult == -1) {
                    return THROW_SSLEXCEPTION;
                }
                if (selectResult == 0) {
                    return THROW_SOCKETTIMEOUTEXCEPTION;
                }

                break;
            }

            // A problem occurred during a system call, but this is not
            // necessarily an error.
            case SSL_ERROR_SYSCALL: {
                // Connection closed without proper shutdown. Tell caller we
                // have reached end-of-stream.
                if (result == 0) {
                    return -1;
                }

                // System call has been interrupted. Simply retry.
                if (errno == EINTR) {
                    break;
                }

                // Note that for all other system call errors we fall through
                // to the default case, which results in an Exception.
                FALLTHROUGH_INTENDED;
            }

            // Everything else is basically an error.
            default: {
                return THROW_SSLEXCEPTION;
            }
        }
    }
    JNI_TRACE("ssl=%p sslWrite => count=%d", ssl, count);

    return count;
}

/**
 * OpenSSL write function (2): write into buffer at offset n chunks.
 */
static int NativeCrypto_SSL_write_BIO(JNIEnv* env, jclass, jlong sslRef, jbyteArray sourceJava, jint len,
        jlong sinkBioRef, jobject shc) {
    SSL* ssl = to_SSL(env, sslRef, true);
    BIO* wbio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(sinkBioRef));
    JNI_TRACE("ssl=%p NativeCrypto_SSL_write_BIO source=%p len=%d wbio=%p shc=%p",
              ssl, sourceJava, len, wbio, shc);
    if (ssl == NULL) {
        return -1;
    }
    if (wbio == NULL) {
        jniThrowNullPointerException(env, "wbio == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write_BIO => wbio == null", ssl);
        return -1;
    }
    if (shc == NULL) {
        jniThrowNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write_BIO => sslHandshakeCallbacks == null", ssl);
        return -1;
    }

    AppData* appData = toAppData(ssl);
    if (appData == NULL) {
        throwSSLExceptionStr(env, "Unable to retrieve application data");
        safeSslClear(ssl);
        freeOpenSslErrorState();
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write_BIO appData => NULL", ssl);
        return -1;
    }

    errno = 0;

    if (MUTEX_LOCK(appData->mutex) == -1) {
        return 0;
    }

    if (!appData->setCallbackState(env, shc, NULL, NULL, NULL)) {
        MUTEX_UNLOCK(appData->mutex);
        throwSSLExceptionStr(env, "Unable to set appdata callback");
        freeOpenSslErrorState();
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write_BIO => appData can't set callback", ssl);
        return -1;
    }

    ScopedByteArrayRO source(env, sourceJava);
    if (source.get() == NULL) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write_BIO => threw exception", ssl);
        return -1;
    }

#if defined(OPENSSL_IS_BORINGSSL)
    Unique_BIO nullBio(BIO_new_mem_buf(NULL, 0));
#else
    Unique_BIO nullBio(BIO_new(BIO_s_null()));
#endif
    ScopedSslBio sslBio(ssl, nullBio.get(), wbio);

    int result = SSL_write(ssl, reinterpret_cast<const char*>(source.get()), len);
    appData->clearCallbackState();
    // callbacks can happen if server requests renegotiation
    if (env->ExceptionCheck()) {
        freeOpenSslErrorState();
        safeSslClear(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write_BIO exception => exception pending (reneg)", ssl);
        return -1;
    }
    OpenSslError sslError(ssl, result);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_write_BIO SSL_write result=%d sslError=%d left=%d",
              ssl, result, sslError.get(), ssl->s3->wbuf.left);
#ifdef WITH_JNI_TRACE_DATA
    for (int i = 0; i < result; i+= WITH_JNI_TRACE_DATA_CHUNK_SIZE) {
        int n = result - i;
        if (n > WITH_JNI_TRACE_DATA_CHUNK_SIZE) {
            n = WITH_JNI_TRACE_DATA_CHUNK_SIZE;
        }
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write_BIO data: %d:\n%.*s", ssl, n, n, buf+i);
    }
#endif

    MUTEX_UNLOCK(appData->mutex);

    switch (sslError.get()) {
        case SSL_ERROR_NONE:
            return result;

        // Wrote zero bytes. End of stream reached.
        case SSL_ERROR_ZERO_RETURN:
            return -1;

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return 0;

        case SSL_ERROR_SYSCALL: {
            // Connection closed without proper shutdown. Tell caller we
            // have reached end-of-stream.
            if (result == 0) {
                return -1;
            }

            // System call has been interrupted. Simply retry.
            if (errno == EINTR) {
                return 0;
            }

            // Note that for all other system call errors we fall through
            // to the default case, which results in an Exception.
            FALLTHROUGH_INTENDED;
        }

        // Everything else is basically an error.
        default: {
            throwSSLExceptionWithSslErrors(env, ssl, sslError.release(), "Write error");
            break;
        }
    }
    return -1;
}

/**
 * OpenSSL write function (2): write into buffer at offset n chunks.
 */
static void NativeCrypto_SSL_write(JNIEnv* env, jclass, jlong ssl_address, jobject fdObject,
                                   jobject shc, jbyteArray b, jint offset, jint len, jint write_timeout_millis)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_write fd=%p shc=%p b=%p offset=%d len=%d write_timeout_millis=%d",
              ssl, fdObject, shc, b, offset, len, write_timeout_millis);
    if (ssl == NULL) {
        return;
    }
    if (fdObject == NULL) {
        jniThrowNullPointerException(env, "fd == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write => fd == null", ssl);
        return;
    }
    if (shc == NULL) {
        jniThrowNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write => sslHandshakeCallbacks == null", ssl);
        return;
    }

    ScopedByteArrayRO bytes(env, b);
    if (bytes.get() == NULL) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write => threw exception", ssl);
        return;
    }
    OpenSslError sslError;
    int ret = sslWrite(env, ssl, fdObject, shc, reinterpret_cast<const char*>(bytes.get() + offset),
                       len, sslError, write_timeout_millis);

    switch (ret) {
        case THROW_SSLEXCEPTION:
            // See sslWrite() regarding improper failure to handle normal cases.
            throwSSLExceptionWithSslErrors(env, ssl, sslError.release(), "Write error");
            break;
        case THROW_SOCKETTIMEOUTEXCEPTION:
            throwSocketTimeoutException(env, "Write timed out");
            break;
        case THROWN_EXCEPTION:
            // SocketException thrown by NetFd.isClosed
            break;
        default:
            break;
    }
}

/**
 * Interrupt any pending I/O before closing the socket.
 */
static void NativeCrypto_SSL_interrupt(
        JNIEnv* env, jclass, jlong ssl_address) {
    SSL* ssl = to_SSL(env, ssl_address, false);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_interrupt", ssl);
    if (ssl == NULL) {
        return;
    }

    /*
     * Mark the connection as quasi-dead, then send something to the emergency
     * file descriptor, so any blocking select() calls are woken up.
     */
    AppData* appData = toAppData(ssl);
    if (appData != NULL) {
        appData->aliveAndKicking = 0;

        // At most two threads can be waiting.
        sslNotify(appData);
        sslNotify(appData);
    }
}

/**
 * OpenSSL close SSL socket function.
 */
static void NativeCrypto_SSL_shutdown(JNIEnv* env, jclass, jlong ssl_address,
                                      jobject fdObject, jobject shc) {
    SSL* ssl = to_SSL(env, ssl_address, false);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_shutdown fd=%p shc=%p", ssl, fdObject, shc);
    if (ssl == NULL) {
        return;
    }
    if (fdObject == NULL) {
        jniThrowNullPointerException(env, "fd == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_shutdown => fd == null", ssl);
        return;
    }
    if (shc == NULL) {
        jniThrowNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_shutdown => sslHandshakeCallbacks == null", ssl);
        return;
    }

    AppData* appData = toAppData(ssl);
    if (appData != NULL) {
        if (!appData->setCallbackState(env, shc, fdObject, NULL, NULL)) {
            // SocketException thrown by NetFd.isClosed
            freeOpenSslErrorState();
            safeSslClear(ssl);
            return;
        }

        /*
         * Try to make socket blocking again. OpenSSL literature recommends this.
         */
        int fd = SSL_get_fd(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_shutdown s=%d", ssl, fd);
        if (fd != -1) {
            setBlocking(fd, true);
        }

        int ret = SSL_shutdown(ssl);
        appData->clearCallbackState();
        // callbacks can happen if server requests renegotiation
        if (env->ExceptionCheck()) {
            safeSslClear(ssl);
            JNI_TRACE("ssl=%p NativeCrypto_SSL_shutdown => exception", ssl);
            return;
        }
        switch (ret) {
            case 0:
                /*
                 * Shutdown was not successful (yet), but there also
                 * is no error. Since we can't know whether the remote
                 * server is actually still there, and we don't want to
                 * get stuck forever in a second SSL_shutdown() call, we
                 * simply return. This is not security a problem as long
                 * as we close the underlying socket, which we actually
                 * do, because that's where we are just coming from.
                 */
                break;
            case 1:
                /*
                 * Shutdown was successful. We can safely return. Hooray!
                 */
                break;
            default:
                /*
                 * Everything else is a real error condition. We should
                 * let the Java layer know about this by throwing an
                 * exception.
                 */
                int sslError = SSL_get_error(ssl, ret);
                throwSSLExceptionWithSslErrors(env, ssl, sslError, "SSL shutdown failed");
                break;
        }
    }

    freeOpenSslErrorState();
    safeSslClear(ssl);
}

/**
 * OpenSSL close SSL socket function.
 */
static void NativeCrypto_SSL_shutdown_BIO(JNIEnv* env, jclass, jlong ssl_address, jlong rbioRef,
        jlong wbioRef, jobject shc) {
    SSL* ssl = to_SSL(env, ssl_address, false);
    BIO* rbio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(rbioRef));
    BIO* wbio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(wbioRef));
    JNI_TRACE("ssl=%p NativeCrypto_SSL_shutdown rbio=%p wbio=%p shc=%p", ssl, rbio, wbio, shc);
    if (ssl == NULL) {
        return;
    }
    if (rbio == NULL || wbio == NULL) {
        jniThrowNullPointerException(env, "rbio == null || wbio == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_shutdown => rbio == null || wbio == null", ssl);
        return;
    }
    if (shc == NULL) {
        jniThrowNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_shutdown => sslHandshakeCallbacks == null", ssl);
        return;
    }

    AppData* appData = toAppData(ssl);
    if (appData != NULL) {
        if (!appData->setCallbackState(env, shc, NULL, NULL, NULL)) {
            // SocketException thrown by NetFd.isClosed
            freeOpenSslErrorState();
            safeSslClear(ssl);
            return;
        }

        ScopedSslBio scopedBio(ssl, rbio, wbio);

        int ret = SSL_shutdown(ssl);
        appData->clearCallbackState();
        // callbacks can happen if server requests renegotiation
        if (env->ExceptionCheck()) {
            safeSslClear(ssl);
            JNI_TRACE("ssl=%p NativeCrypto_SSL_shutdown => exception", ssl);
            return;
        }
        switch (ret) {
            case 0:
                /*
                 * Shutdown was not successful (yet), but there also
                 * is no error. Since we can't know whether the remote
                 * server is actually still there, and we don't want to
                 * get stuck forever in a second SSL_shutdown() call, we
                 * simply return. This is not security a problem as long
                 * as we close the underlying socket, which we actually
                 * do, because that's where we are just coming from.
                 */
                break;
            case 1:
                /*
                 * Shutdown was successful. We can safely return. Hooray!
                 */
                break;
            default:
                /*
                 * Everything else is a real error condition. We should
                 * let the Java layer know about this by throwing an
                 * exception.
                 */
                int sslError = SSL_get_error(ssl, ret);
                throwSSLExceptionWithSslErrors(env, ssl, sslError, "SSL shutdown failed");
                break;
        }
    }

    freeOpenSslErrorState();
    safeSslClear(ssl);
}

static jint NativeCrypto_SSL_get_shutdown(JNIEnv* env, jclass, jlong ssl_address) {
    const SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_shutdown", ssl);
    if (ssl == NULL) {
        jniThrowNullPointerException(env, "ssl == null");
        return 0;
    }

    int status = SSL_get_shutdown(ssl);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_shutdown => %d", ssl, status);
    return static_cast<jint>(status);
}

/**
 * public static native void SSL_free(long ssl);
 */
static void NativeCrypto_SSL_free(JNIEnv* env, jclass, jlong ssl_address)
{
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_free", ssl);
    if (ssl == NULL) {
        return;
    }

    AppData* appData = toAppData(ssl);
    SSL_set_app_data(ssl, NULL);
    delete appData;
    SSL_free(ssl);
}

/**
 * Gets and returns in a byte array the ID of the actual SSL session.
 */
static jbyteArray NativeCrypto_SSL_SESSION_session_id(JNIEnv* env, jclass,
                                                      jlong ssl_session_address) {
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_session_id", ssl_session);
    if (ssl_session == NULL) {
        return NULL;
    }
    jbyteArray result = env->NewByteArray(ssl_session->session_id_length);
    if (result != NULL) {
        jbyte* src = reinterpret_cast<jbyte*>(ssl_session->session_id);
        env->SetByteArrayRegion(result, 0, ssl_session->session_id_length, src);
    }
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_session_id => %p session_id_length=%d",
             ssl_session, result, ssl_session->session_id_length);
    return result;
}

/**
 * Gets and returns in a long integer the creation's time of the
 * actual SSL session.
 */
static jlong NativeCrypto_SSL_SESSION_get_time(JNIEnv* env, jclass, jlong ssl_session_address) {
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_get_time", ssl_session);
    if (ssl_session == NULL) {
        return 0;
    }
    // result must be jlong, not long or *1000 will overflow
    jlong result = SSL_SESSION_get_time(ssl_session);
    result *= 1000; // OpenSSL uses seconds, Java uses milliseconds.
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_get_time => %lld", ssl_session, (long long) result);
    return result;
}

/**
 * Gets and returns in a string the version of the SSL protocol. If it
 * returns the string "unknown" it means that no connection is established.
 */
static jstring NativeCrypto_SSL_SESSION_get_version(JNIEnv* env, jclass, jlong ssl_session_address) {
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_get_version", ssl_session);
    if (ssl_session == NULL) {
        return NULL;
    }
    const char* protocol = SSL_SESSION_get_version(ssl_session);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_get_version => %s", ssl_session, protocol);
    return env->NewStringUTF(protocol);
}

/**
 * Gets and returns in a string the cipher negotiated for the SSL session.
 */
static jstring NativeCrypto_SSL_SESSION_cipher(JNIEnv* env, jclass, jlong ssl_session_address) {
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_cipher", ssl_session);
    if (ssl_session == NULL) {
        return NULL;
    }
    const SSL_CIPHER* cipher = ssl_session->cipher;
    const char* name = SSL_CIPHER_get_name(cipher);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_cipher => %s", ssl_session, name);
    return env->NewStringUTF(name);
}

/**
 * Frees the SSL session.
 */
static void NativeCrypto_SSL_SESSION_free(JNIEnv* env, jclass, jlong ssl_session_address) {
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_free", ssl_session);
    if (ssl_session == NULL) {
        return;
    }
    SSL_SESSION_free(ssl_session);
}


/**
 * Serializes the native state of the session (ID, cipher, and keys but
 * not certificates). Returns a byte[] containing the DER-encoded state.
 * See apache mod_ssl.
 */
static jbyteArray NativeCrypto_i2d_SSL_SESSION(JNIEnv* env, jclass, jlong ssl_session_address) {
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_i2d_SSL_SESSION", ssl_session);
    if (ssl_session == NULL) {
        return NULL;
    }
    return ASN1ToByteArray<SSL_SESSION>(env, ssl_session, i2d_SSL_SESSION);
}

/**
 * Deserialize the session.
 */
static jlong NativeCrypto_d2i_SSL_SESSION(JNIEnv* env, jclass, jbyteArray javaBytes) {
    JNI_TRACE("NativeCrypto_d2i_SSL_SESSION bytes=%p", javaBytes);

    ScopedByteArrayRO bytes(env, javaBytes);
    if (bytes.get() == NULL) {
        JNI_TRACE("NativeCrypto_d2i_SSL_SESSION => threw exception");
        return 0;
    }
    const unsigned char* ucp = reinterpret_cast<const unsigned char*>(bytes.get());
    SSL_SESSION* ssl_session = d2i_SSL_SESSION(NULL, &ucp, bytes.size());

#if !defined(OPENSSL_IS_BORINGSSL)
    // Initialize SSL_SESSION cipher field based on cipher_id http://b/7091840
    if (ssl_session != NULL) {
        // based on ssl_get_prev_session
        uint32_t cipher_id_network_order = htonl(ssl_session->cipher_id);
        uint8_t* cipher_id_byte_pointer = reinterpret_cast<uint8_t*>(&cipher_id_network_order);
        if (ssl_session->ssl_version >= SSL3_VERSION_MAJOR) {
            cipher_id_byte_pointer += 2; // skip first two bytes for SSL3+
        } else {
            cipher_id_byte_pointer += 1; // skip first byte for SSL2
        }
        ssl_session->cipher = SSLv23_method()->get_cipher_by_char(cipher_id_byte_pointer);
        JNI_TRACE("NativeCrypto_d2i_SSL_SESSION cipher_id=%lx hton=%x 0=%x 1=%x cipher=%s",
                  ssl_session->cipher_id, cipher_id_network_order,
                  cipher_id_byte_pointer[0], cipher_id_byte_pointer[1],
                  SSL_CIPHER_get_name(ssl_session->cipher));
    }
#endif

    if (ssl_session == NULL) {
        freeOpenSslErrorState();
    }

    JNI_TRACE("NativeCrypto_d2i_SSL_SESSION => %p", ssl_session);
    return reinterpret_cast<uintptr_t>(ssl_session);
}

static jlong NativeCrypto_ERR_peek_last_error(JNIEnv*, jclass) {
    return ERR_peek_last_error();
}

static jstring NativeCrypto_SSL_CIPHER_get_kx_name(JNIEnv* env, jclass, jlong cipher_address) {
    const SSL_CIPHER* cipher = to_SSL_CIPHER(env, cipher_address, true);
    const char *kx_name = NULL;

#if defined(OPENSSL_IS_BORINGSSL)
    kx_name = SSL_CIPHER_get_kx_name(cipher);
#else
    kx_name = SSL_CIPHER_authentication_method(cipher);
#endif

    return env->NewStringUTF(kx_name);
}

#define FILE_DESCRIPTOR "Ljava/io/FileDescriptor;"
#define SSL_CALLBACKS "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeCrypto$SSLHandshakeCallbacks;"
#define REF_EC_GROUP "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EC_GROUP;"
#define REF_EC_POINT "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EC_POINT;"
#define REF_EVP_CIPHER_CTX "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_CIPHER_CTX;"
#define REF_EVP_PKEY "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_PKEY;"
static JNINativeMethod sNativeCryptoMethods[] = {
    NATIVE_METHOD(NativeCrypto, clinit, "()Z"),
    NATIVE_METHOD(NativeCrypto, ENGINE_load_dynamic, "()V"),
    NATIVE_METHOD(NativeCrypto, ENGINE_by_id, "(Ljava/lang/String;)J"),
    NATIVE_METHOD(NativeCrypto, ENGINE_add, "(J)I"),
    NATIVE_METHOD(NativeCrypto, ENGINE_init, "(J)I"),
    NATIVE_METHOD(NativeCrypto, ENGINE_finish, "(J)I"),
    NATIVE_METHOD(NativeCrypto, ENGINE_free, "(J)I"),
    NATIVE_METHOD(NativeCrypto, ENGINE_load_private_key, "(JLjava/lang/String;)J"),
    NATIVE_METHOD(NativeCrypto, ENGINE_get_id, "(J)Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, ENGINE_ctrl_cmd_string, "(JLjava/lang/String;Ljava/lang/String;I)I"),
    NATIVE_METHOD(NativeCrypto, EVP_PKEY_new_DH, "([B[B[B[B)J"),
    NATIVE_METHOD(NativeCrypto, EVP_PKEY_new_RSA, "([B[B[B[B[B[B[B[B)J"),
    NATIVE_METHOD(NativeCrypto, EVP_PKEY_new_EC_KEY, "(" REF_EC_GROUP REF_EC_POINT "[B)J"),
    NATIVE_METHOD(NativeCrypto, EVP_PKEY_new_mac_key, "(I[B)J"),
    NATIVE_METHOD(NativeCrypto, EVP_PKEY_type, "(" REF_EVP_PKEY ")I"),
    NATIVE_METHOD(NativeCrypto, EVP_PKEY_size, "(" REF_EVP_PKEY ")I"),
    NATIVE_METHOD(NativeCrypto, EVP_PKEY_print_public, "(" REF_EVP_PKEY ")Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, EVP_PKEY_print_private, "(" REF_EVP_PKEY ")Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, EVP_PKEY_free, "(J)V"),
    NATIVE_METHOD(NativeCrypto, EVP_PKEY_cmp, "(" REF_EVP_PKEY REF_EVP_PKEY ")I"),
    NATIVE_METHOD(NativeCrypto, i2d_PKCS8_PRIV_KEY_INFO, "(" REF_EVP_PKEY ")[B"),
    NATIVE_METHOD(NativeCrypto, d2i_PKCS8_PRIV_KEY_INFO, "([B)J"),
    NATIVE_METHOD(NativeCrypto, i2d_PUBKEY, "(" REF_EVP_PKEY ")[B"),
    NATIVE_METHOD(NativeCrypto, d2i_PUBKEY, "([B)J"),
    NATIVE_METHOD(NativeCrypto, getRSAPrivateKeyWrapper, "(Ljava/security/PrivateKey;[B)J"),
    NATIVE_METHOD(NativeCrypto, getECPrivateKeyWrapper, "(Ljava/security/PrivateKey;" REF_EC_GROUP ")J"),
    NATIVE_METHOD(NativeCrypto, RSA_generate_key_ex, "(I[B)J"),
    NATIVE_METHOD(NativeCrypto, RSA_size, "(" REF_EVP_PKEY ")I"),
    NATIVE_METHOD(NativeCrypto, RSA_private_encrypt, "(I[B[B" REF_EVP_PKEY "I)I"),
    NATIVE_METHOD(NativeCrypto, RSA_public_decrypt, "(I[B[B" REF_EVP_PKEY "I)I"),
    NATIVE_METHOD(NativeCrypto, RSA_public_encrypt, "(I[B[B" REF_EVP_PKEY "I)I"),
    NATIVE_METHOD(NativeCrypto, RSA_private_decrypt, "(I[B[B" REF_EVP_PKEY "I)I"),
    NATIVE_METHOD(NativeCrypto, get_RSA_private_params, "(" REF_EVP_PKEY ")[[B"),
    NATIVE_METHOD(NativeCrypto, get_RSA_public_params, "(" REF_EVP_PKEY ")[[B"),
    NATIVE_METHOD(NativeCrypto, DH_generate_parameters_ex, "(IJ)J"),
    NATIVE_METHOD(NativeCrypto, DH_generate_key, "(" REF_EVP_PKEY ")V"),
    NATIVE_METHOD(NativeCrypto, get_DH_params, "(" REF_EVP_PKEY ")[[B"),
    NATIVE_METHOD(NativeCrypto, EC_GROUP_new_by_curve_name, "(Ljava/lang/String;)J"),
    NATIVE_METHOD(NativeCrypto, EC_GROUP_set_asn1_flag, "(" REF_EC_GROUP "I)V"),
    NATIVE_METHOD(NativeCrypto, EC_GROUP_set_point_conversion_form, "(" REF_EC_GROUP "I)V"),
    NATIVE_METHOD(NativeCrypto, EC_GROUP_get_curve_name, "(" REF_EC_GROUP ")Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, EC_GROUP_get_curve, "(" REF_EC_GROUP ")[[B"),
    NATIVE_METHOD(NativeCrypto, EC_GROUP_get_order, "(" REF_EC_GROUP ")[B"),
    NATIVE_METHOD(NativeCrypto, EC_GROUP_get_degree, "(" REF_EC_GROUP ")I"),
    NATIVE_METHOD(NativeCrypto, EC_GROUP_get_cofactor, "(" REF_EC_GROUP ")[B"),
    NATIVE_METHOD(NativeCrypto, EC_GROUP_clear_free, "(J)V"),
    NATIVE_METHOD(NativeCrypto, EC_GROUP_cmp, "(" REF_EC_GROUP REF_EC_GROUP ")Z"),
    NATIVE_METHOD(NativeCrypto, EC_GROUP_get_generator, "(" REF_EC_GROUP ")J"),
    NATIVE_METHOD(NativeCrypto, get_EC_GROUP_type, "(" REF_EC_GROUP ")I"),
    NATIVE_METHOD(NativeCrypto, EC_POINT_new, "(" REF_EC_GROUP ")J"),
    NATIVE_METHOD(NativeCrypto, EC_POINT_clear_free, "(J)V"),
    NATIVE_METHOD(NativeCrypto, EC_POINT_cmp, "(" REF_EC_GROUP REF_EC_POINT REF_EC_POINT ")Z"),
    NATIVE_METHOD(NativeCrypto, EC_POINT_set_affine_coordinates, "(" REF_EC_GROUP REF_EC_POINT "[B[B)V"),
    NATIVE_METHOD(NativeCrypto, EC_POINT_get_affine_coordinates, "(" REF_EC_GROUP REF_EC_POINT ")[[B"),
    NATIVE_METHOD(NativeCrypto, EC_KEY_generate_key, "(" REF_EC_GROUP ")J"),
    NATIVE_METHOD(NativeCrypto, EC_KEY_get1_group, "(" REF_EVP_PKEY ")J"),
    NATIVE_METHOD(NativeCrypto, EC_KEY_get_private_key, "(" REF_EVP_PKEY ")[B"),
    NATIVE_METHOD(NativeCrypto, EC_KEY_get_public_key, "(" REF_EVP_PKEY ")J"),
    NATIVE_METHOD(NativeCrypto, EC_KEY_set_nonce_from_hash, "(" REF_EVP_PKEY "Z)V"),
    NATIVE_METHOD(NativeCrypto, ECDH_compute_key, "([BI" REF_EVP_PKEY REF_EVP_PKEY ")I"),
    NATIVE_METHOD(NativeCrypto, EVP_MD_CTX_create, "()J"),
    NATIVE_METHOD(NativeCrypto, EVP_MD_CTX_init, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;)V"),
    NATIVE_METHOD(NativeCrypto, EVP_MD_CTX_destroy, "(J)V"),
    NATIVE_METHOD(NativeCrypto, EVP_MD_CTX_copy, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;)I"),
    NATIVE_METHOD(NativeCrypto, EVP_DigestInit, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;J)I"),
    NATIVE_METHOD(NativeCrypto, EVP_DigestUpdate, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;[BII)V"),
    NATIVE_METHOD(NativeCrypto, EVP_DigestFinal, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;[BI)I"),
    NATIVE_METHOD(NativeCrypto, EVP_get_digestbyname, "(Ljava/lang/String;)J"),
    NATIVE_METHOD(NativeCrypto, EVP_MD_block_size, "(J)I"),
    NATIVE_METHOD(NativeCrypto, EVP_MD_size, "(J)I"),
    NATIVE_METHOD(NativeCrypto, EVP_SignInit, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;J)I"),
    NATIVE_METHOD(NativeCrypto, EVP_SignUpdate, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;[BII)V"),
    NATIVE_METHOD(NativeCrypto, EVP_SignFinal, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;[BI" REF_EVP_PKEY ")I"),
    NATIVE_METHOD(NativeCrypto, EVP_VerifyInit, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;J)I"),
    NATIVE_METHOD(NativeCrypto, EVP_VerifyUpdate, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;[BII)V"),
    NATIVE_METHOD(NativeCrypto, EVP_VerifyFinal, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;[BII" REF_EVP_PKEY ")I"),
    NATIVE_METHOD(NativeCrypto, EVP_DigestSignInit, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;J" REF_EVP_PKEY ")V"),
    NATIVE_METHOD(NativeCrypto, EVP_DigestSignUpdate, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;[B)V"),
    NATIVE_METHOD(NativeCrypto, EVP_DigestSignFinal, "(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;)[B"),
    NATIVE_METHOD(NativeCrypto, EVP_get_cipherbyname, "(Ljava/lang/String;)J"),
    NATIVE_METHOD(NativeCrypto, EVP_CipherInit_ex, "(" REF_EVP_CIPHER_CTX "J[B[BZ)V"),
    NATIVE_METHOD(NativeCrypto, EVP_CipherUpdate, "(" REF_EVP_CIPHER_CTX "[BI[BII)I"),
    NATIVE_METHOD(NativeCrypto, EVP_CipherFinal_ex, "(" REF_EVP_CIPHER_CTX "[BI)I"),
    NATIVE_METHOD(NativeCrypto, EVP_CIPHER_iv_length, "(J)I"),
    NATIVE_METHOD(NativeCrypto, EVP_CIPHER_CTX_new, "()J"),
    NATIVE_METHOD(NativeCrypto, EVP_CIPHER_CTX_block_size, "(" REF_EVP_CIPHER_CTX ")I"),
    NATIVE_METHOD(NativeCrypto, get_EVP_CIPHER_CTX_buf_len, "(" REF_EVP_CIPHER_CTX ")I"),
    NATIVE_METHOD(NativeCrypto, EVP_CIPHER_CTX_set_padding, "(" REF_EVP_CIPHER_CTX "Z)V"),
    NATIVE_METHOD(NativeCrypto, EVP_CIPHER_CTX_set_key_length, "(" REF_EVP_CIPHER_CTX "I)V"),
    NATIVE_METHOD(NativeCrypto, EVP_CIPHER_CTX_free, "(J)V"),
    NATIVE_METHOD(NativeCrypto, RAND_seed, "([B)V"),
    NATIVE_METHOD(NativeCrypto, RAND_load_file, "(Ljava/lang/String;J)I"),
    NATIVE_METHOD(NativeCrypto, RAND_bytes, "([B)V"),
    NATIVE_METHOD(NativeCrypto, OBJ_txt2nid, "(Ljava/lang/String;)I"),
    NATIVE_METHOD(NativeCrypto, OBJ_txt2nid_longName, "(Ljava/lang/String;)Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, OBJ_txt2nid_oid, "(Ljava/lang/String;)Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, create_BIO_InputStream, ("(L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/OpenSSLBIOInputStream;)J")),
    NATIVE_METHOD(NativeCrypto, create_BIO_OutputStream, "(Ljava/io/OutputStream;)J"),
    NATIVE_METHOD(NativeCrypto, BIO_read, "(J[B)I"),
    NATIVE_METHOD(NativeCrypto, BIO_write, "(J[BII)V"),
    NATIVE_METHOD(NativeCrypto, BIO_free_all, "(J)V"),
    NATIVE_METHOD(NativeCrypto, X509_NAME_print_ex, "(JJ)Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, d2i_X509_bio, "(J)J"),
    NATIVE_METHOD(NativeCrypto, d2i_X509, "([B)J"),
    NATIVE_METHOD(NativeCrypto, i2d_X509, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, i2d_X509_PUBKEY, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, PEM_read_bio_X509, "(J)J"),
    NATIVE_METHOD(NativeCrypto, PEM_read_bio_PKCS7, "(JI)[J"),
    NATIVE_METHOD(NativeCrypto, d2i_PKCS7_bio, "(JI)[J"),
    NATIVE_METHOD(NativeCrypto, i2d_PKCS7, "([J)[B"),
    NATIVE_METHOD(NativeCrypto, ASN1_seq_unpack_X509_bio, "(J)[J"),
    NATIVE_METHOD(NativeCrypto, ASN1_seq_pack_X509, "([J)[B"),
    NATIVE_METHOD(NativeCrypto, X509_free, "(J)V"),
    NATIVE_METHOD(NativeCrypto, X509_cmp, "(JJ)I"),
    NATIVE_METHOD(NativeCrypto, get_X509_hashCode, "(J)I"),
    NATIVE_METHOD(NativeCrypto, X509_print_ex, "(JJJJ)V"),
    NATIVE_METHOD(NativeCrypto, X509_get_pubkey, "(J)J"),
    NATIVE_METHOD(NativeCrypto, X509_get_issuer_name, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, X509_get_subject_name, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, get_X509_pubkey_oid, "(J)Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, get_X509_sig_alg_oid, "(J)Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, get_X509_sig_alg_parameter, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, get_X509_issuerUID, "(J)[Z"),
    NATIVE_METHOD(NativeCrypto, get_X509_subjectUID, "(J)[Z"),
    NATIVE_METHOD(NativeCrypto, get_X509_ex_kusage, "(J)[Z"),
    NATIVE_METHOD(NativeCrypto, get_X509_ex_xkusage, "(J)[Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, get_X509_ex_pathlen, "(J)I"),
    NATIVE_METHOD(NativeCrypto, X509_get_ext_oid, "(JLjava/lang/String;)[B"),
    NATIVE_METHOD(NativeCrypto, X509_CRL_get_ext_oid, "(JLjava/lang/String;)[B"),
    NATIVE_METHOD(NativeCrypto, get_X509_CRL_crl_enc, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, X509_CRL_verify, "(J" REF_EVP_PKEY ")V"),
    NATIVE_METHOD(NativeCrypto, X509_CRL_get_lastUpdate, "(J)J"),
    NATIVE_METHOD(NativeCrypto, X509_CRL_get_nextUpdate, "(J)J"),
    NATIVE_METHOD(NativeCrypto, X509_REVOKED_get_ext_oid, "(JLjava/lang/String;)[B"),
    NATIVE_METHOD(NativeCrypto, X509_REVOKED_get_serialNumber, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, X509_REVOKED_print, "(JJ)V"),
    NATIVE_METHOD(NativeCrypto, get_X509_REVOKED_revocationDate, "(J)J"),
    NATIVE_METHOD(NativeCrypto, get_X509_ext_oids, "(JI)[Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, get_X509_CRL_ext_oids, "(JI)[Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, get_X509_REVOKED_ext_oids, "(JI)[Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, get_X509_GENERAL_NAME_stack, "(JI)[[Ljava/lang/Object;"),
    NATIVE_METHOD(NativeCrypto, X509_get_notBefore, "(J)J"),
    NATIVE_METHOD(NativeCrypto, X509_get_notAfter, "(J)J"),
    NATIVE_METHOD(NativeCrypto, X509_get_version, "(J)J"),
    NATIVE_METHOD(NativeCrypto, X509_get_serialNumber, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, X509_verify, "(J" REF_EVP_PKEY ")V"),
    NATIVE_METHOD(NativeCrypto, get_X509_cert_info_enc, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, get_X509_signature, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, get_X509_CRL_signature, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, get_X509_ex_flags, "(J)I"),
    NATIVE_METHOD(NativeCrypto, X509_check_issued, "(JJ)I"),
    NATIVE_METHOD(NativeCrypto, d2i_X509_CRL_bio, "(J)J"),
    NATIVE_METHOD(NativeCrypto, PEM_read_bio_X509_CRL, "(J)J"),
    NATIVE_METHOD(NativeCrypto, X509_CRL_get0_by_cert, "(JJ)J"),
    NATIVE_METHOD(NativeCrypto, X509_CRL_get0_by_serial, "(J[B)J"),
    NATIVE_METHOD(NativeCrypto, X509_CRL_get_REVOKED, "(J)[J"),
    NATIVE_METHOD(NativeCrypto, i2d_X509_CRL, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, X509_CRL_free, "(J)V"),
    NATIVE_METHOD(NativeCrypto, X509_CRL_print, "(JJ)V"),
    NATIVE_METHOD(NativeCrypto, get_X509_CRL_sig_alg_oid, "(J)Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, get_X509_CRL_sig_alg_parameter, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, X509_CRL_get_issuer_name, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, X509_CRL_get_version, "(J)J"),
    NATIVE_METHOD(NativeCrypto, X509_CRL_get_ext, "(JLjava/lang/String;)J"),
    NATIVE_METHOD(NativeCrypto, X509_REVOKED_get_ext, "(JLjava/lang/String;)J"),
    NATIVE_METHOD(NativeCrypto, X509_REVOKED_dup, "(J)J"),
    NATIVE_METHOD(NativeCrypto, i2d_X509_REVOKED, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, X509_supported_extension, "(J)I"),
    NATIVE_METHOD(NativeCrypto, ASN1_TIME_to_Calendar, "(JLjava/util/Calendar;)V"),
    NATIVE_METHOD(NativeCrypto, SSL_CTX_new, "()J"),
    NATIVE_METHOD(NativeCrypto, SSL_CTX_free, "(J)V"),
    NATIVE_METHOD(NativeCrypto, SSL_CTX_set_session_id_context, "(J[B)V"),
    NATIVE_METHOD(NativeCrypto, SSL_new, "(J)J"),
    NATIVE_METHOD(NativeCrypto, SSL_enable_tls_channel_id, "(J)V"),
    NATIVE_METHOD(NativeCrypto, SSL_get_tls_channel_id, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, SSL_set1_tls_channel_id, "(J" REF_EVP_PKEY ")V"),
    NATIVE_METHOD(NativeCrypto, SSL_use_PrivateKey, "(J" REF_EVP_PKEY ")V"),
    NATIVE_METHOD(NativeCrypto, SSL_use_certificate, "(J[J)V"),
    NATIVE_METHOD(NativeCrypto, SSL_check_private_key, "(J)V"),
    NATIVE_METHOD(NativeCrypto, SSL_set_client_CA_list, "(J[[B)V"),
    NATIVE_METHOD(NativeCrypto, SSL_get_mode, "(J)J"),
    NATIVE_METHOD(NativeCrypto, SSL_set_mode, "(JJ)J"),
    NATIVE_METHOD(NativeCrypto, SSL_clear_mode, "(JJ)J"),
    NATIVE_METHOD(NativeCrypto, SSL_get_options, "(J)J"),
    NATIVE_METHOD(NativeCrypto, SSL_set_options, "(JJ)J"),
    NATIVE_METHOD(NativeCrypto, SSL_clear_options, "(JJ)J"),
    NATIVE_METHOD(NativeCrypto, SSL_use_psk_identity_hint, "(JLjava/lang/String;)V"),
    NATIVE_METHOD(NativeCrypto, set_SSL_psk_client_callback_enabled, "(JZ)V"),
    NATIVE_METHOD(NativeCrypto, set_SSL_psk_server_callback_enabled, "(JZ)V"),
    NATIVE_METHOD(NativeCrypto, SSL_set_cipher_lists, "(J[Ljava/lang/String;)V"),
    NATIVE_METHOD(NativeCrypto, SSL_get_ciphers, "(J)[J"),
    NATIVE_METHOD(NativeCrypto, get_SSL_CIPHER_algorithm_auth, "(J)I"),
    NATIVE_METHOD(NativeCrypto, get_SSL_CIPHER_algorithm_mkey, "(J)I"),
    NATIVE_METHOD(NativeCrypto, SSL_set_accept_state, "(J)V"),
    NATIVE_METHOD(NativeCrypto, SSL_set_connect_state, "(J)V"),
    NATIVE_METHOD(NativeCrypto, SSL_set_verify, "(JI)V"),
    NATIVE_METHOD(NativeCrypto, SSL_set_session, "(JJ)V"),
    NATIVE_METHOD(NativeCrypto, SSL_set_session_creation_enabled, "(JZ)V"),
    NATIVE_METHOD(NativeCrypto, SSL_set_tlsext_host_name, "(JLjava/lang/String;)V"),
    NATIVE_METHOD(NativeCrypto, SSL_get_servername, "(J)Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, SSL_do_handshake, "(J" FILE_DESCRIPTOR SSL_CALLBACKS "IZ[B[B)J"),
    NATIVE_METHOD(NativeCrypto, SSL_do_handshake_bio, "(JJJ" SSL_CALLBACKS "Z[B[B)J"),
    NATIVE_METHOD(NativeCrypto, SSL_renegotiate, "(J)V"),
    NATIVE_METHOD(NativeCrypto, SSL_get_certificate, "(J)[J"),
    NATIVE_METHOD(NativeCrypto, SSL_get_peer_cert_chain, "(J)[J"),
    NATIVE_METHOD(NativeCrypto, SSL_read, "(J" FILE_DESCRIPTOR SSL_CALLBACKS "[BIII)I"),
    NATIVE_METHOD(NativeCrypto, SSL_read_BIO, "(J[BIIJJ" SSL_CALLBACKS ")I"),
    NATIVE_METHOD(NativeCrypto, SSL_write, "(J" FILE_DESCRIPTOR SSL_CALLBACKS "[BIII)V"),
    NATIVE_METHOD(NativeCrypto, SSL_write_BIO, "(J[BIJ" SSL_CALLBACKS ")I"),
    NATIVE_METHOD(NativeCrypto, SSL_interrupt, "(J)V"),
    NATIVE_METHOD(NativeCrypto, SSL_shutdown, "(J" FILE_DESCRIPTOR SSL_CALLBACKS ")V"),
    NATIVE_METHOD(NativeCrypto, SSL_shutdown_BIO, "(JJJ" SSL_CALLBACKS ")V"),
    NATIVE_METHOD(NativeCrypto, SSL_get_shutdown, "(J)I"),
    NATIVE_METHOD(NativeCrypto, SSL_free, "(J)V"),
    NATIVE_METHOD(NativeCrypto, SSL_SESSION_session_id, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, SSL_SESSION_get_time, "(J)J"),
    NATIVE_METHOD(NativeCrypto, SSL_SESSION_get_version, "(J)Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, SSL_SESSION_cipher, "(J)Ljava/lang/String;"),
    NATIVE_METHOD(NativeCrypto, SSL_SESSION_free, "(J)V"),
    NATIVE_METHOD(NativeCrypto, i2d_SSL_SESSION, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, d2i_SSL_SESSION, "([B)J"),
    NATIVE_METHOD(NativeCrypto, SSL_CTX_enable_npn, "(J)V"),
    NATIVE_METHOD(NativeCrypto, SSL_CTX_disable_npn, "(J)V"),
    NATIVE_METHOD(NativeCrypto, SSL_get_npn_negotiated_protocol, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, SSL_set_alpn_protos, "(J[B)I"),
    NATIVE_METHOD(NativeCrypto, SSL_get0_alpn_selected, "(J)[B"),
    NATIVE_METHOD(NativeCrypto, ERR_peek_last_error, "()J"),
    NATIVE_METHOD(NativeCrypto, SSL_CIPHER_get_kx_name, "(J)Ljava/lang/String;"),
};

static jclass getGlobalRefToClass(JNIEnv* env, const char* className) {
    ScopedLocalRef<jclass> localClass(env, env->FindClass(className));
    jclass globalRef = reinterpret_cast<jclass>(env->NewGlobalRef(localClass.get()));
    if (globalRef == NULL) {
        ALOGE("failed to find class %s", className);
        abort();
    }
    return globalRef;
}

static jmethodID getMethodRef(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jmethodID localMethod = env->GetMethodID(clazz, name, sig);
    if (localMethod == NULL) {
        ALOGE("could not find method %s", name);
        abort();
    }
    return localMethod;
}

static jfieldID getFieldRef(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jfieldID localField = env->GetFieldID(clazz, name, sig);
    if (localField == NULL) {
        ALOGE("could not find field %s", name);
        abort();
    }
    return localField;
}

static void initialize_conscrypt(JNIEnv* env) {
    jniRegisterNativeMethods(env, TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeCrypto",
                             sNativeCryptoMethods, NELEM(sNativeCryptoMethods));

    cryptoUpcallsClass = getGlobalRefToClass(env,
            TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/CryptoUpcalls");
    nativeRefClass = getGlobalRefToClass(env,
            TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef");
    openSslInputStreamClass = getGlobalRefToClass(env,
            TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/OpenSSLBIOInputStream");

    nativeRef_context = getFieldRef(env, nativeRefClass, "context", "J");

    calendar_setMethod = getMethodRef(env, calendarClass, "set", "(IIIIII)V");
    inputStream_readMethod = getMethodRef(env, inputStreamClass, "read", "([B)I");
    integer_valueOfMethod = env->GetStaticMethodID(integerClass, "valueOf",
            "(I)Ljava/lang/Integer;");
    openSslInputStream_readLineMethod = getMethodRef(env, openSslInputStreamClass, "gets",
            "([B)I");
    outputStream_writeMethod = getMethodRef(env, outputStreamClass, "write", "([B)V");
    outputStream_flushMethod = getMethodRef(env, outputStreamClass, "flush", "()V");

#ifdef CONSCRYPT_UNBUNDLED
    findAsynchronousCloseMonitorFuncs();
#endif
}

static jclass findClass(JNIEnv* env, const char* name) {
    ScopedLocalRef<jclass> localClass(env, env->FindClass(name));
    jclass result = reinterpret_cast<jclass>(env->NewGlobalRef(localClass.get()));
    if (result == NULL) {
        ALOGE("failed to find class '%s'", name);
        abort();
    }
    return result;
}

#ifdef STATIC_LIB
// Give client libs everything they need to initialize our JNI
int libconscrypt_JNI_OnLoad(JavaVM *vm, void*) {
#else
// Use JNI_OnLoad for when we're standalone
int JNI_OnLoad(JavaVM *vm, void*) {
    JNI_TRACE("JNI_OnLoad NativeCrypto");
#endif
    gJavaVM = vm;

    JNIEnv *env;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        ALOGE("Could not get JNIEnv");
        return JNI_ERR;
    }

    byteArrayClass = findClass(env, "[B");
    calendarClass = findClass(env, "java/util/Calendar");
    inputStreamClass = findClass(env, "java/io/InputStream");
    integerClass = findClass(env, "java/lang/Integer");
    objectClass = findClass(env, "java/lang/Object");
    objectArrayClass = findClass(env, "[Ljava/lang/Object;");
    outputStreamClass = findClass(env, "java/io/OutputStream");
    stringClass = findClass(env, "java/lang/String");

    initialize_conscrypt(env);
    return JNI_VERSION_1_6;
}
