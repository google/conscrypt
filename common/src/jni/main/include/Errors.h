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

#ifndef CONSCRYPT_ERRORS_H_
#define CONSCRYPT_ERRORS_H_

#include "compat.h"
#include "Trace.h"

#include <errno.h>
#include <jni.h>
#include <openssl/ssl.h>

namespace conscrypt {

/**
 * Utility methods for throwing JNI errors.
 */
class Errors {
private:
    Errors() {}
    ~Errors() {}

public:
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
     *
     * Currently aborts the VM if it can't throw the exception.
     */
    static int jniThrowException(JNIEnv* env, const char* className, const char* msg) {
        jclass exceptionClass = env->FindClass(className);

        if (exceptionClass == nullptr) {
            ALOGD("Unable to find exception class %s", className);
            /* ClassNotFoundException now pending */
            return -1;
        }

        if (env->ThrowNew(exceptionClass, msg) != JNI_OK) {
            ALOGD("Failed throwing '%s' '%s'", className, msg);
            /* an exception, most likely OOM, will now be pending */
            return -1;
        }

        env->DeleteLocalRef(exceptionClass);
        return 0;
    }

    /**
     * Throw a java.lang.RuntimeException, with an optional message.
     */
    static int jniThrowRuntimeException(JNIEnv* env, const char* msg) {
        return jniThrowException(env, "java/lang/RuntimeException", msg);
    }

    /*
     * Throw a java.lang.NullPointerException, with an optional message.
     */
    static int jniThrowNullPointerException(JNIEnv* env, const char* msg) {
        return jniThrowException(env, "java/lang/NullPointerException", msg);
    }

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

    /**
     * Throws an IOException with the given string as a message.
     */
    static int throwIOException(JNIEnv* env, const char* message) {
        JNI_TRACE("throwIOException %s", message);
        return jniThrowException(env, "java/io/IOException", message);
    }

    /**
     * Throws a ParsingException with the given string as a message.
     */
    static int throwParsingException(JNIEnv* env, const char* message) {
        return jniThrowException(env, TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/OpenSSLX509CertificateFactory$ParsingException",
                                 message);
    }

    static int throwInvalidAlgorithmParameterException(JNIEnv* env, const char* message) {
        JNI_TRACE("throwInvalidAlgorithmParameterException %s", message);
        return jniThrowException(env, "java/security/InvalidAlgorithmParameterException", message);
    }

    static int throwForAsn1Error(JNIEnv* env, int reason, const char* message,
                                 int (*defaultThrow)(JNIEnv*, const char*)) {
        switch (reason) {
            case ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE:
#if defined(ASN1_R_UNABLE_TO_DECODE_RSA_KEY)
            case ASN1_R_UNABLE_TO_DECODE_RSA_KEY:
#endif
#if defined(ASN1_R_WRONG_PUBLIC_KEY_TYPE)
            case ASN1_R_WRONG_PUBLIC_KEY_TYPE:
#endif
#if defined(ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY)
            case ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY:
#endif
#if defined(ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE)
            case ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE:
#endif
                return throwInvalidKeyException(env, message);
                break;
            case ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM:
            case ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM:
                return throwNoSuchAlgorithmException(env, message);
                break;
        }
        return defaultThrow(env, message);
    }

    static int throwForCipherError(JNIEnv* env, int reason, const char* message,
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

    static int throwForEvpError(JNIEnv* env, int reason, const char* message,
                                int (*defaultThrow)(JNIEnv*, const char*)) {
        switch (reason) {
            case EVP_R_MISSING_PARAMETERS:
                return throwInvalidKeyException(env, message);
                break;
            case EVP_R_UNSUPPORTED_ALGORITHM:
#if defined(EVP_R_X931_UNSUPPORTED)
            case EVP_R_X931_UNSUPPORTED:
#endif
                return throwNoSuchAlgorithmException(env, message);
                break;
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

    static int throwForRsaError(JNIEnv* env, int reason, const char* message,
                                int (*defaultThrow)(JNIEnv*, const char*)) {
        switch (reason) {
            case RSA_R_BLOCK_TYPE_IS_NOT_01:
            case RSA_R_PKCS_DECODING_ERROR:
#if defined(RSA_R_BLOCK_TYPE_IS_NOT_02)
            case RSA_R_BLOCK_TYPE_IS_NOT_02:
#endif
                return throwBadPaddingException(env, message);
                break;
            case RSA_R_BAD_SIGNATURE:
            case RSA_R_DATA_TOO_LARGE_FOR_MODULUS:
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
            case RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE:
                return throwIllegalBlockSizeException(env, message);
                break;
        }
        return defaultThrow(env, message);
    }

    static int throwForX509Error(JNIEnv* env, int reason, const char* message,
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
    static bool throwExceptionIfNecessary(
            JNIEnv* env, CONSCRYPT_UNUSED const char* location,
            int (*defaultThrow)(JNIEnv*, const char*) = jniThrowRuntimeException) {
        const char* file;
        int line;
        const char* data;
        int flags;
        unsigned long error = ERR_get_error_line_data(&file, &line, &data, &flags);
        bool result = false;

        if (error != 0) {
            char message[256];
            ERR_error_string_n(error, message, sizeof(message));
            int library = ERR_GET_LIB(error);
            int reason = ERR_GET_REASON(error);
            JNI_TRACE("OpenSSL error in %s error=%lx library=%x reason=%x (%s:%d): %s %s", location,
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
            result = true;
        }

        ERR_clear_error();
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
     * @param ssl the possibly null SSL
     * @param sslErrorCode error code returned from SSL_get_error() or
     * SSL_ERROR_NONE to probe with ERR_get_error
     * @param message null-ok; general error message
     */
    static int throwSSLExceptionWithSslErrors(
            JNIEnv* env, SSL* ssl, int sslErrorCode, const char* message,
            int (*actualThrow)(JNIEnv*, const char*) = throwSSLExceptionStr) {
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
            ALOGV("%s: ssl=%p: %s", message, ssl, sslErrorStr);
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

        ALOGV("%s", allocStr);
        free(allocStr);
        ERR_clear_error();
        return ret;
    }
};

}  // namespace conscrypt

#endif  // CONSCRYPT_ERRORS_H_
