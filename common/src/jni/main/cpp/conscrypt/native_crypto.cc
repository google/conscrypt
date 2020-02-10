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

#include <conscrypt/NetFd.h>
#include <conscrypt/app_data.h>
#include <conscrypt/bio_input_stream.h>
#include <conscrypt/bio_output_stream.h>
#include <conscrypt/bio_stream.h>
#include <conscrypt/compat.h>
#include <conscrypt/compatibility_close_monitor.h>
#include <conscrypt/jniutil.h>
#include <conscrypt/logging.h>
#include <conscrypt/macros.h>
#include <conscrypt/native_crypto.h>
#include <conscrypt/netutil.h>
#include <conscrypt/scoped_ssl_bio.h>
#include <conscrypt/ssl_error.h>

#include <nativehelper/scoped_primitive_array.h>
#include <nativehelper/scoped_utf_chars.h>

#include <limits.h>

#include <openssl/aead.h>
#include <openssl/asn1.h>
#include <openssl/chacha.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs8.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <limits>
#include <vector>

using conscrypt::AppData;
using conscrypt::BioInputStream;
using conscrypt::BioOutputStream;
using conscrypt::BioStream;
using conscrypt::CompatibilityCloseMonitor;
using conscrypt::NativeCrypto;
using conscrypt::SslError;

/**
 * Helper function that grabs the casts an ssl pointer and then checks for nullness.
 * If this function returns nullptr and <code>throwIfNull</code> is
 * passed as <code>true</code>, then this function will call
 * <code>throwSSLExceptionStr</code> before returning, so in this case of
 * nullptr, a caller of this function should simply return and allow JNI
 * to do its thing.
 *
 * @param env the JNI environment
 * @param ssl_address; the ssl_address pointer as an integer
 * @param throwIfNull whether to throw if the SSL pointer is nullptr
 * @returns the pointer, which may be nullptr
 */
static SSL_CTX* to_SSL_CTX(JNIEnv* env, jlong ssl_ctx_address, bool throwIfNull) {
    SSL_CTX* ssl_ctx = reinterpret_cast<SSL_CTX*>(static_cast<uintptr_t>(ssl_ctx_address));
    if ((ssl_ctx == nullptr) && throwIfNull) {
        JNI_TRACE("ssl_ctx == null");
        conscrypt::jniutil::throwNullPointerException(env, "ssl_ctx == null");
    }
    return ssl_ctx;
}

static SSL* to_SSL(JNIEnv* env, jlong ssl_address, bool throwIfNull) {
    SSL* ssl = reinterpret_cast<SSL*>(static_cast<uintptr_t>(ssl_address));
    if ((ssl == nullptr) && throwIfNull) {
        JNI_TRACE("ssl == null");
        conscrypt::jniutil::throwNullPointerException(env, "ssl == null");
    }
    return ssl;
}

static BIO* to_SSL_BIO(JNIEnv* env, jlong bio_address, bool throwIfNull) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bio_address));
    if ((bio == nullptr) && throwIfNull) {
        JNI_TRACE("bio == null");
        conscrypt::jniutil::throwNullPointerException(env, "bio == null");
    }
    return bio;
}

static SSL_SESSION* to_SSL_SESSION(JNIEnv* env, jlong ssl_session_address, bool throwIfNull) {
    SSL_SESSION* ssl_session =
            reinterpret_cast<SSL_SESSION*>(static_cast<uintptr_t>(ssl_session_address));
    if ((ssl_session == nullptr) && throwIfNull) {
        JNI_TRACE("ssl_session == null");
        conscrypt::jniutil::throwNullPointerException(env, "ssl_session == null");
    }
    return ssl_session;
}

static SSL_CIPHER* to_SSL_CIPHER(JNIEnv* env, jlong ssl_cipher_address, bool throwIfNull) {
    SSL_CIPHER* ssl_cipher =
            reinterpret_cast<SSL_CIPHER*>(static_cast<uintptr_t>(ssl_cipher_address));
    if ((ssl_cipher == nullptr) && throwIfNull) {
        JNI_TRACE("ssl_cipher == null");
        conscrypt::jniutil::throwNullPointerException(env, "ssl_cipher == null");
    }
    return ssl_cipher;
}

template <typename T>
static T* fromContextObject(JNIEnv* env, jobject contextObject) {
    if (contextObject == nullptr) {
        JNI_TRACE("contextObject == null");
        conscrypt::jniutil::throwNullPointerException(env, "contextObject == null");
        return nullptr;
    }
    T* ref = reinterpret_cast<T*>(
            env->GetLongField(contextObject, conscrypt::jniutil::nativeRef_address));
    if (ref == nullptr) {
        JNI_TRACE("ref == null");
        conscrypt::jniutil::throwNullPointerException(env, "ref == null");
        return nullptr;
    }
    return ref;
}

/**
 * Converts a Java byte[] two's complement to an OpenSSL BIGNUM. This will
 * allocate the BIGNUM if *dest == nullptr. Returns true on success. If the
 * return value is false, there is a pending exception.
 */
static bool arrayToBignum(JNIEnv* env, jbyteArray source, BIGNUM** dest) {
    JNI_TRACE("arrayToBignum(%p, %p)", source, dest);
    if (dest == nullptr) {
        JNI_TRACE("arrayToBignum(%p, %p) => dest is null!", source, dest);
        conscrypt::jniutil::throwNullPointerException(env, "dest == null");
        return false;
    }
    JNI_TRACE("arrayToBignum(%p, %p) *dest == %p", source, dest, *dest);

    ScopedByteArrayRO sourceBytes(env, source);
    if (sourceBytes.get() == nullptr) {
        JNI_TRACE("arrayToBignum(%p, %p) => null", source, dest);
        return false;
    }
    const unsigned char* tmp = reinterpret_cast<const unsigned char*>(sourceBytes.get());
    size_t tmpSize = sourceBytes.size();

    /* if the array is empty, it is zero. */
    if (tmpSize == 0) {
        if (*dest == nullptr) {
            *dest = BN_new();
        }
        BN_zero(*dest);
        return true;
    }

    std::unique_ptr<unsigned char[]> twosComplement;
    bool negative = (tmp[0] & 0x80) != 0;
    if (negative) {
        // Need to convert to two's complement.
        twosComplement.reset(new unsigned char[tmpSize]);
        unsigned char* twosBytes = reinterpret_cast<unsigned char*>(twosComplement.get());
        memcpy(twosBytes, tmp, tmpSize);
        tmp = twosBytes;

        bool carry = true;
        for (ssize_t i = static_cast<ssize_t>(tmpSize - 1); i >= 0; i--) {
            twosBytes[i] ^= 0xFF;
            if (carry) {
                carry = (++twosBytes[i]) == 0;
            }
        }
    }
    BIGNUM* ret = BN_bin2bn(tmp, tmpSize, *dest);
    if (ret == nullptr) {
        conscrypt::jniutil::throwRuntimeException(env, "Conversion to BIGNUM failed");
        ERR_clear_error();
        JNI_TRACE("arrayToBignum(%p, %p) => threw exception", source, dest);
        return false;
    }
    BN_set_negative(ret, negative ? 1 : 0);

    *dest = ret;
    JNI_TRACE("arrayToBignum(%p, %p) => *dest = %p", source, dest, ret);
    return true;
}

/**
 * arrayToBignumSize sets |*out_size| to the size of the big-endian number
 * contained in |source|. It returns true on success and sets an exception and
 * returns false otherwise.
 */
static bool arrayToBignumSize(JNIEnv* env, jbyteArray source, size_t* out_size) {
    JNI_TRACE("arrayToBignumSize(%p, %p)", source, out_size);

    ScopedByteArrayRO sourceBytes(env, source);
    if (sourceBytes.get() == nullptr) {
        JNI_TRACE("arrayToBignum(%p, %p) => null", source, out_size);
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
        conscrypt::jniutil::throwRuntimeException(env, "Negative number");
        return false;
    }

    while (tmpSize > 0 && tmp[0] == 0) {
        tmp++;
        tmpSize--;
    }

    *out_size = tmpSize;
    return true;
}

/**
 * Converts an OpenSSL BIGNUM to a Java byte[] array in two's complement.
 */
static jbyteArray bignumToArray(JNIEnv* env, const BIGNUM* source, const char* sourceName) {
    JNI_TRACE("bignumToArray(%p, %s)", source, sourceName);

    if (source == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, sourceName);
        return nullptr;
    }

    size_t numBytes = BN_num_bytes(source) + 1;
    jbyteArray javaBytes = env->NewByteArray(static_cast<jsize>(numBytes));
    ScopedByteArrayRW bytes(env, javaBytes);
    if (bytes.get() == nullptr) {
        JNI_TRACE("bignumToArray(%p, %s) => null", source, sourceName);
        return nullptr;
    }

    unsigned char* tmp = reinterpret_cast<unsigned char*>(bytes.get());
    if (BN_num_bytes(source) > 0 && BN_bn2bin(source, tmp + 1) <= 0) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "bignumToArray");
        return nullptr;
    }

    // Set the sign and convert to two's complement if necessary for the Java code.
    if (BN_is_negative(source)) {
        bool carry = true;
        for (ssize_t i = static_cast<ssize_t>(numBytes - 1); i >= 0; i--) {
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
template <typename T>
jbyteArray ASN1ToByteArray(JNIEnv* env, T* obj, int (*i2d_func)(T*, unsigned char**)) {
    if (obj == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "ASN1 input == null");
        JNI_TRACE("ASN1ToByteArray(%p) => null input", obj);
        return nullptr;
    }

    int derLen = i2d_func(obj, nullptr);
    if (derLen < 0) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "ASN1ToByteArray");
        JNI_TRACE("ASN1ToByteArray(%p) => measurement failed", obj);
        return nullptr;
    }

    ScopedLocalRef<jbyteArray> byteArray(env, env->NewByteArray(derLen));
    if (byteArray.get() == nullptr) {
        JNI_TRACE("ASN1ToByteArray(%p) => creating byte array failed", obj);
        return nullptr;
    }

    ScopedByteArrayRW bytes(env, byteArray.get());
    if (bytes.get() == nullptr) {
        JNI_TRACE("ASN1ToByteArray(%p) => using byte array failed", obj);
        return nullptr;
    }

    unsigned char* p = reinterpret_cast<unsigned char*>(bytes.get());
    int ret = i2d_func(obj, &p);
    if (ret < 0) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "ASN1ToByteArray");
        JNI_TRACE("ASN1ToByteArray(%p) => final conversion failed", obj);
        return nullptr;
    }

    JNI_TRACE("ASN1ToByteArray(%p) => success (%d bytes written)", obj, ret);
    return byteArray.release();
}

/**
 * Finishes a pending CBB and returns a jbyteArray with the contents.
 */
jbyteArray CBBToByteArray(JNIEnv* env, CBB* cbb) {
    uint8_t* data;
    size_t len;
    if (!CBB_finish(cbb, &data, &len)) {
        conscrypt::jniutil::throwRuntimeException(env, "CBB_finish failed");
        ERR_clear_error();
        JNI_TRACE("creating byte array failed");
        return nullptr;
    }
    bssl::UniquePtr<uint8_t> free_data(data);

    ScopedLocalRef<jbyteArray> byteArray(env, env->NewByteArray(static_cast<jsize>(len)));
    if (byteArray.get() == nullptr) {
        JNI_TRACE("creating byte array failed");
        return nullptr;
    }

    ScopedByteArrayRW bytes(env, byteArray.get());
    if (bytes.get() == nullptr) {
        JNI_TRACE("using byte array failed");
        return nullptr;
    }

    memcpy(bytes.get(), data, len);
    return byteArray.release();
}

jbyteArray CryptoBufferToByteArray(JNIEnv* env, const CRYPTO_BUFFER* buf) {
    if (CRYPTO_BUFFER_len(buf) > INT_MAX) {
        JNI_TRACE("buffer too large");
        conscrypt::jniutil::throwRuntimeException(env, "buffer too large");
        return nullptr;
    }

    int length = static_cast<int>(CRYPTO_BUFFER_len(buf));
    jbyteArray ret = env->NewByteArray(length);
    if (ret == nullptr) {
        JNI_TRACE("allocating byte array failed");
        return nullptr;
    }

    env->SetByteArrayRegion(ret, 0, length,
                            reinterpret_cast<const int8_t*>(CRYPTO_BUFFER_data(buf)));
    return ret;
}

bssl::UniquePtr<CRYPTO_BUFFER> ByteArrayToCryptoBuffer(JNIEnv* env, const jbyteArray array,
                                                       CONSCRYPT_UNUSED CRYPTO_BUFFER_POOL* pool) {
    if (array == nullptr) {
        JNI_TRACE("array was null");
        conscrypt::jniutil::throwNullPointerException(env, "array == null");
        return nullptr;
    }

    ScopedByteArrayRO arrayRo(env, array);
    if (arrayRo.get() == nullptr) {
        JNI_TRACE("failed to get bytes");
        return nullptr;
    }

    bssl::UniquePtr<CRYPTO_BUFFER> ret(CRYPTO_BUFFER_new(
            reinterpret_cast<const uint8_t*>(arrayRo.get()), arrayRo.size(), nullptr));
    if (!ret) {
        JNI_TRACE("failed to allocate CRYPTO_BUFFER");
        conscrypt::jniutil::throwOutOfMemory(env, "failed to allocate CRYPTO_BUFFER");
        return nullptr;
    }

    return ret;
}

static jobjectArray CryptoBuffersToObjectArray(JNIEnv* env,
                                               const STACK_OF(CRYPTO_BUFFER) * buffers) {
    size_t numBuffers = sk_CRYPTO_BUFFER_num(buffers);
    if (numBuffers > INT_MAX) {
        JNI_TRACE("too many buffers");
        conscrypt::jniutil::throwRuntimeException(env, "too many buffers");
        return nullptr;
    }

    ScopedLocalRef<jobjectArray> array(
            env, env->NewObjectArray(static_cast<int>(numBuffers),
                                     conscrypt::jniutil::byteArrayClass, nullptr));
    if (array.get() == nullptr) {
        JNI_TRACE("failed to allocate array");
        return nullptr;
    }

    for (size_t i = 0; i < numBuffers; ++i) {
        CRYPTO_BUFFER* buffer = sk_CRYPTO_BUFFER_value(buffers, i);
        ScopedLocalRef<jbyteArray> bArray(env, CryptoBufferToByteArray(env, buffer));
        if (bArray.get() == nullptr) {
            return nullptr;
        }
        env->SetObjectArrayElement(array.get(), i, bArray.get());
    }

    return array.release();
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
    if (bitsRef.get() == nullptr) {
        return nullptr;
    }

    ScopedBooleanArrayRW bitsArray(env, bitsRef.get());
    for (size_t i = 0; i < bitsArray.size(); i++) {
        bitsArray[i] = static_cast<jboolean>(ASN1_BIT_STRING_get_bit(bitStr, static_cast<int>(i)));
    }

    return bitsRef.release();
}

static int bio_stream_create(BIO* b) {
    b->init = 1;
    b->num = 0;
    b->ptr = nullptr;
    b->flags = 0;
    return 1;
}

static int bio_stream_destroy(BIO* b) {
    if (b == nullptr) {
        return 0;
    }

    if (b->ptr != nullptr) {
        delete static_cast<BioStream*>(b->ptr);
        b->ptr = nullptr;
    }

    b->init = 0;
    b->flags = 0;
    return 1;
}

static int bio_stream_read(BIO* b, char* buf, int len) {
    BIO_clear_retry_flags(b);
    BioInputStream* stream = static_cast<BioInputStream*>(b->ptr);
    int ret = stream->read(buf, len);
    if (ret == 0) {
        if (stream->isFinite()) {
            return 0;
        }
        // If the BioInputStream is not finite then EOF doesn't mean that
        // there's nothing more coming.
        BIO_set_retry_read(b);
        return -1;
    }
    return ret;
}

static int bio_stream_write(BIO* b, const char* buf, int len) {
    BIO_clear_retry_flags(b);
    BioOutputStream* stream = static_cast<BioOutputStream*>(b->ptr);
    return stream->write(buf, len);
}

static int bio_stream_puts(BIO* b, const char* buf) {
    BioOutputStream* stream = static_cast<BioOutputStream*>(b->ptr);
    return stream->write(buf, static_cast<int>(strlen(buf)));
}

static int bio_stream_gets(BIO* b, char* buf, int len) {
    BioInputStream* stream = static_cast<BioInputStream*>(b->ptr);
    return stream->gets(buf, len);
}

static void bio_stream_assign(BIO* b, BioStream* stream) {
    b->ptr = static_cast<void*>(stream);
}

// NOLINTNEXTLINE(runtime/int)
static long bio_stream_ctrl(BIO* b, int cmd, long, void*) {
    BioStream* stream = static_cast<BioStream*>(b->ptr);

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
        (100 | 0x0400), /* source/sink BIO */
        "InputStream/OutputStream BIO",
        bio_stream_write,   /* bio_write */
        bio_stream_read,    /* bio_read */
        bio_stream_puts,    /* bio_puts */
        bio_stream_gets,    /* bio_gets */
        bio_stream_ctrl,    /* bio_ctrl */
        bio_stream_create,  /* bio_create */
        bio_stream_destroy, /* bio_free */
        nullptr,            /* no bio_callback_ctrl */
};

static jbyteArray ecSignDigestWithPrivateKey(JNIEnv* env, jobject privateKey, const char* message,
                                             size_t message_len) {
    JNI_TRACE("ecSignDigestWithPrivateKey(%p)", privateKey);
    if (message_len > std::numeric_limits<jsize>::max()) {
        JNI_TRACE("ecSignDigestWithPrivateKey(%p) => argument too large", privateKey);
        return nullptr;
    }
    ScopedLocalRef<jbyteArray> messageArray(env,
                                            env->NewByteArray(static_cast<jsize>(message_len)));
    if (env->ExceptionCheck()) {
        JNI_TRACE("ecSignDigestWithPrivateKey(%p) => threw exception", privateKey);
        return nullptr;
    }

    {
        ScopedByteArrayRW messageBytes(env, messageArray.get());
        if (messageBytes.get() == nullptr) {
            JNI_TRACE("ecSignDigestWithPrivateKey(%p) => using byte array failed", privateKey);
            return nullptr;
        }

        memcpy(messageBytes.get(), message, message_len);
    }

    jmethodID rawSignMethod = env->GetStaticMethodID(conscrypt::jniutil::cryptoUpcallsClass,
                                                     "ecSignDigestWithPrivateKey",
                                                     "(Ljava/security/PrivateKey;[B)[B");
    if (rawSignMethod == nullptr) {
        CONSCRYPT_LOG_ERROR("Could not find ecSignDigestWithPrivateKey");
        return nullptr;
    }

    return reinterpret_cast<jbyteArray>(env->CallStaticObjectMethod(
            conscrypt::jniutil::cryptoUpcallsClass, rawSignMethod, privateKey, messageArray.get()));
}

static jbyteArray rsaSignDigestWithPrivateKey(JNIEnv* env, jobject privateKey, jint padding,
                                              const char* message, size_t message_len) {
    if (message_len > std::numeric_limits<jsize>::max()) {
        JNI_TRACE("rsaSignDigestWithPrivateKey(%p) => argument too large", privateKey);
        return nullptr;
    }
    ScopedLocalRef<jbyteArray> messageArray(env,
                                            env->NewByteArray(static_cast<jsize>(message_len)));
    if (env->ExceptionCheck()) {
        JNI_TRACE("rsaSignDigestWithPrivateKey(%p) => threw exception", privateKey);
        return nullptr;
    }

    {
        ScopedByteArrayRW messageBytes(env, messageArray.get());
        if (messageBytes.get() == nullptr) {
            JNI_TRACE("rsaSignDigestWithPrivateKey(%p) => using byte array failed", privateKey);
            return nullptr;
        }

        memcpy(messageBytes.get(), message, message_len);
    }

    jmethodID rsaSignMethod = env->GetStaticMethodID(conscrypt::jniutil::cryptoUpcallsClass,
                                                     "rsaSignDigestWithPrivateKey",
                                                     "(Ljava/security/PrivateKey;I[B)[B");
    if (rsaSignMethod == nullptr) {
        CONSCRYPT_LOG_ERROR("Could not find rsaSignDigestWithPrivateKey");
        return nullptr;
    }

    return reinterpret_cast<jbyteArray>(
            env->CallStaticObjectMethod(conscrypt::jniutil::cryptoUpcallsClass, rsaSignMethod,
                                        privateKey, padding, messageArray.get()));
}

// rsaDecryptWithPrivateKey uses privateKey to decrypt |ciphertext_len| bytes
// from |ciphertext|. The ciphertext is expected to be padded using the scheme
// given in |padding|, which must be one of |RSA_*_PADDING| constants from
// OpenSSL.
static jbyteArray rsaDecryptWithPrivateKey(JNIEnv* env, jobject privateKey, jint padding,
                                           const char* ciphertext, size_t ciphertext_len) {
    if (ciphertext_len > std::numeric_limits<jsize>::max()) {
        JNI_TRACE("rsaDecryptWithPrivateKey(%p) => argument too large", privateKey);
        return nullptr;
    }
    ScopedLocalRef<jbyteArray> ciphertextArray(
            env, env->NewByteArray(static_cast<jsize>(ciphertext_len)));
    if (env->ExceptionCheck()) {
        JNI_TRACE("rsaDecryptWithPrivateKey(%p) => threw exception", privateKey);
        return nullptr;
    }

    {
        ScopedByteArrayRW ciphertextBytes(env, ciphertextArray.get());
        if (ciphertextBytes.get() == nullptr) {
            JNI_TRACE("rsaDecryptWithPrivateKey(%p) => using byte array failed", privateKey);
            return nullptr;
        }

        memcpy(ciphertextBytes.get(), ciphertext, ciphertext_len);
    }

    jmethodID rsaDecryptMethod =
            env->GetStaticMethodID(conscrypt::jniutil::cryptoUpcallsClass,
                                   "rsaDecryptWithPrivateKey", "(Ljava/security/PrivateKey;I[B)[B");
    if (rsaDecryptMethod == nullptr) {
        CONSCRYPT_LOG_ERROR("Could not find rsaDecryptWithPrivateKey");
        return nullptr;
    }

    return reinterpret_cast<jbyteArray>(
            env->CallStaticObjectMethod(conscrypt::jniutil::cryptoUpcallsClass, rsaDecryptMethod,
                                        privateKey, padding, ciphertextArray.get()));
}

// *********************************************
// From keystore_openssl.cpp in Chromium source.
// *********************************************

namespace {

ENGINE* g_engine;
int g_rsa_exdata_index;
int g_ecdsa_exdata_index;
RSA_METHOD g_rsa_method;
ECDSA_METHOD g_ecdsa_method;
std::once_flag g_engine_once;

void init_engine_globals();

void ensure_engine_globals() {
    std::call_once(g_engine_once, init_engine_globals);
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
              long /* argl */ /* NOLINT(runtime/int) */,
              void* /* argp */) {
  return 0;
}

// ExDataFree is called when one of the RSA or EC_KEY objects is freed.
void ExDataFree(void* /* parent */,
                void* ptr,
                CRYPTO_EX_DATA* /* ad */,
                int /* index */,
                long /* argl */ /* NOLINT(runtime/int) */,
                void* /* argp */) {
    // Ensure the global JNI reference created with this wrapper is
    // properly destroyed with it.
    KeyExData* ex_data = reinterpret_cast<KeyExData*>(ptr);
    if (ex_data != nullptr) {
        JNIEnv* env = conscrypt::jniutil::getJNIEnv();
        env->DeleteGlobalRef(ex_data->private_key);
        delete ex_data;
    }
}

KeyExData* RsaGetExData(const RSA* rsa) {
    return reinterpret_cast<KeyExData*>(RSA_get_ex_data(rsa, g_rsa_exdata_index));
}

size_t RsaMethodSize(const RSA* rsa) {
    const KeyExData* ex_data = RsaGetExData(rsa);
    return ex_data->cached_size;
}

int RsaMethodSignRaw(RSA* rsa, size_t* out_len, uint8_t* out, size_t max_out, const uint8_t* in,
                     size_t in_len, int padding) {
    if (padding != RSA_PKCS1_PADDING && padding != RSA_NO_PADDING) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_UNKNOWN_PADDING_TYPE);
        return 0;
    }

    // Retrieve private key JNI reference.
    const KeyExData* ex_data = RsaGetExData(rsa);
    if (!ex_data || !ex_data->private_key) {
        OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    JNIEnv* env = conscrypt::jniutil::getJNIEnv();
    if (env == nullptr) {
        OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    // For RSA keys, this function behaves as RSA_private_encrypt with
    // the specified padding.
    ScopedLocalRef<jbyteArray> signature(
            env, rsaSignDigestWithPrivateKey(env, ex_data->private_key, padding,
                                             reinterpret_cast<const char*>(in), in_len));

    if (signature.get() == nullptr) {
        OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    ScopedByteArrayRO result(env, signature.get());

    size_t expected_size = static_cast<size_t>(RSA_size(rsa));
    if (result.size() > expected_size) {
        OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (max_out < expected_size) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE);
        return 0;
    }

    // Copy result to OpenSSL-provided buffer. rsaSignDigestWithPrivateKey
    // should pad with leading 0s, but if it doesn't, pad the result.
    size_t zero_pad = expected_size - result.size();
    memset(out, 0, zero_pad);
    memcpy(out + zero_pad, &result[0], result.size());
    *out_len = expected_size;

    return 1;
}

int RsaMethodDecrypt(RSA* rsa, size_t* out_len, uint8_t* out, size_t max_out, const uint8_t* in,
                     size_t in_len, int padding) {
    // Retrieve private key JNI reference.
    const KeyExData* ex_data = RsaGetExData(rsa);
    if (!ex_data || !ex_data->private_key) {
        OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    JNIEnv* env = conscrypt::jniutil::getJNIEnv();
    if (env == nullptr) {
        OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    // This function behaves as RSA_private_decrypt.
    ScopedLocalRef<jbyteArray> cleartext(
            env, rsaDecryptWithPrivateKey(env, ex_data->private_key, padding,
                                          reinterpret_cast<const char*>(in), in_len));
    if (cleartext.get() == nullptr) {
        OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    ScopedByteArrayRO cleartextBytes(env, cleartext.get());

    if (max_out < cleartextBytes.size()) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE);
        return 0;
    }

    // Copy result to OpenSSL-provided buffer.
    memcpy(out, cleartextBytes.get(), cleartextBytes.size());
    *out_len = cleartextBytes.size();

    return 1;
}

// Custom ECDSA_METHOD that uses the platform APIs.
// Note that for now, only signing through ECDSA_sign() is really supported.
// all other method pointers are either stubs returning errors, or no-ops.

jobject EcKeyGetKey(const EC_KEY* ec_key) {
    KeyExData* ex_data =
            reinterpret_cast<KeyExData*>(EC_KEY_get_ex_data(ec_key, g_ecdsa_exdata_index));
    return ex_data->private_key;
}

int EcdsaMethodSign(const uint8_t* digest, size_t digest_len, uint8_t* sig, unsigned int* sig_len,
                    EC_KEY* ec_key) {
    // Retrieve private key JNI reference.
    jobject private_key = EcKeyGetKey(ec_key);
    if (!private_key) {
        CONSCRYPT_LOG_ERROR("Null JNI reference passed to EcdsaMethodSign!");
        return 0;
    }

    JNIEnv* env = conscrypt::jniutil::getJNIEnv();
    if (env == nullptr) {
        return 0;
    }

    // Sign message with it through JNI.
    ScopedLocalRef<jbyteArray> signature(
            env, ecSignDigestWithPrivateKey(env, private_key,
                                             reinterpret_cast<const char*>(digest), digest_len));
    if (signature.get() == nullptr) {
        CONSCRYPT_LOG_ERROR("Could not sign message in EcdsaMethodDoSign!");
        return 0;
    }

    ScopedByteArrayRO signatureBytes(env, signature.get());
    // Note: With ECDSA, the actual signature may be smaller than
    // ECDSA_size().
    size_t max_expected_size = ECDSA_size(ec_key);
    if (signatureBytes.size() > max_expected_size) {
        CONSCRYPT_LOG_ERROR("ECDSA Signature size mismatch, actual: %zd, expected <= %zd",
                            signatureBytes.size(), max_expected_size);
        return 0;
    }

    memcpy(sig, signatureBytes.get(), signatureBytes.size());
    *sig_len = static_cast<unsigned int>(signatureBytes.size());
    return 1;
}

void init_engine_globals() {
    g_rsa_exdata_index = RSA_get_ex_new_index(0 /* argl */, nullptr /* argp */,
                                              nullptr /* new_func */, ExDataDup, ExDataFree);
    g_ecdsa_exdata_index = EC_KEY_get_ex_new_index(0 /* argl */, nullptr /* argp */,
                                                   nullptr /* new_func */, ExDataDup, ExDataFree);

    g_rsa_method.common.is_static = 1;
    g_rsa_method.size = RsaMethodSize;
    g_rsa_method.sign_raw = RsaMethodSignRaw;
    g_rsa_method.decrypt = RsaMethodDecrypt;
    g_rsa_method.flags = RSA_FLAG_OPAQUE;

    g_ecdsa_method.common.is_static = 1;
    g_ecdsa_method.sign = EcdsaMethodSign;
    g_ecdsa_method.flags = ECDSA_FLAG_OPAQUE;

    g_engine = ENGINE_new();
    ENGINE_set_RSA_method(g_engine, &g_rsa_method, sizeof(g_rsa_method));
    ENGINE_set_ECDSA_method(g_engine, &g_ecdsa_method, sizeof(g_ecdsa_method));
}

}  // anonymous namespace

#define THROW_SSLEXCEPTION (-2)
#define THROW_SOCKETTIMEOUTEXCEPTION (-3)
#define THROWN_EXCEPTION (-4)

/**
 * Initialization phase for every OpenSSL job: Loads the Error strings, the
 * crypto algorithms and reset the OpenSSL library
 */
static void NativeCrypto_clinit(JNIEnv*, jclass) {
    CRYPTO_library_init();
}

/**
 * private static native int EVP_PKEY_new_RSA(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q);
 */
static jlong NativeCrypto_EVP_PKEY_new_RSA(JNIEnv* env, jclass, jbyteArray n, jbyteArray e,
                                           jbyteArray d, jbyteArray p, jbyteArray q,
                                           jbyteArray dmp1, jbyteArray dmq1, jbyteArray iqmp) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("EVP_PKEY_new_RSA(n=%p, e=%p, d=%p, p=%p, q=%p, dmp1=%p, dmq1=%p, iqmp=%p)", n, e, d,
              p, q, dmp1, dmq1, iqmp);

    bssl::UniquePtr<RSA> rsa(RSA_new());
    if (rsa.get() == nullptr) {
        conscrypt::jniutil::throwRuntimeException(env, "RSA_new failed");
        return 0;
    }

    if (e == nullptr && d == nullptr) {
        conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                           "e == null && d == null");
        JNI_TRACE("NativeCrypto_EVP_PKEY_new_RSA => e == null && d == null");
        return 0;
    }

    if (!arrayToBignum(env, n, &rsa->n)) {
        return 0;
    }

    if (e != nullptr && !arrayToBignum(env, e, &rsa->e)) {
        return 0;
    }

    if (d != nullptr && !arrayToBignum(env, d, &rsa->d)) {
        return 0;
    }

    if (p != nullptr && !arrayToBignum(env, p, &rsa->p)) {
        return 0;
    }

    if (q != nullptr && !arrayToBignum(env, q, &rsa->q)) {
        return 0;
    }

    if (dmp1 != nullptr && !arrayToBignum(env, dmp1, &rsa->dmp1)) {
        return 0;
    }

    if (dmq1 != nullptr && !arrayToBignum(env, dmq1, &rsa->dmq1)) {
        return 0;
    }

    if (iqmp != nullptr && !arrayToBignum(env, iqmp, &rsa->iqmp)) {
        return 0;
    }

    if (conscrypt::trace::kWithJniTrace) {
        if (p != nullptr && q != nullptr) {
            int check = RSA_check_key(rsa.get());
            JNI_TRACE("EVP_PKEY_new_RSA(...) RSA_check_key returns %d", check);
        }
    }

    if (rsa->n == nullptr || (rsa->e == nullptr && rsa->d == nullptr)) {
        conscrypt::jniutil::throwRuntimeException(env, "Unable to convert BigInteger to BIGNUM");
        return 0;
    }

    /*
     * If the private exponent is available, there is the potential to do signing
     * operations. However, we can only do blinding if the public exponent is also
     * available. Disable blinding if the public exponent isn't available.
     *
     * TODO[kroot]: We should try to recover the public exponent by trying
     *              some common ones such 3, 17, or 65537.
     */
    if (rsa->d != nullptr && rsa->e == nullptr) {
        JNI_TRACE("EVP_PKEY_new_RSA(...) disabling RSA blinding => %p", rsa.get());
        rsa->flags |= RSA_FLAG_NO_BLINDING;
    }

    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    if (pkey.get() == nullptr) {
        conscrypt::jniutil::throwRuntimeException(env, "EVP_PKEY_new failed");
        return 0;
    }
    if (EVP_PKEY_assign_RSA(pkey.get(), rsa.get()) != 1) {
        conscrypt::jniutil::throwRuntimeException(env, "EVP_PKEY_new failed");
        ERR_clear_error();
        return 0;
    }
    OWNERSHIP_TRANSFERRED(rsa);
    JNI_TRACE("EVP_PKEY_new_RSA(n=%p, e=%p, d=%p, p=%p, q=%p dmp1=%p, dmq1=%p, iqmp=%p) => %p", n,
              e, d, p, q, dmp1, dmq1, iqmp, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jlong NativeCrypto_EVP_PKEY_new_EC_KEY(JNIEnv* env, jclass, jobject groupRef,
                                              jobject pubkeyRef, jbyteArray keyJavaBytes) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p)", groupRef, pubkeyRef, keyJavaBytes);
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    if (group == nullptr) {
        return 0;
    }
    const EC_POINT* pubkey =
            pubkeyRef == nullptr ? nullptr : fromContextObject<EC_POINT>(env, pubkeyRef);
    JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p) <- ptr", group, pubkey, keyJavaBytes);

    bssl::UniquePtr<BIGNUM> key(nullptr);
    if (keyJavaBytes != nullptr) {
        BIGNUM* keyRef = nullptr;
        if (!arrayToBignum(env, keyJavaBytes, &keyRef)) {
            return 0;
        }
        key.reset(keyRef);
    }

    bssl::UniquePtr<EC_KEY> eckey(EC_KEY_new());
    if (eckey.get() == nullptr) {
        conscrypt::jniutil::throwRuntimeException(env, "EC_KEY_new failed");
        return 0;
    }

    if (EC_KEY_set_group(eckey.get(), group) != 1) {
        JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p) > EC_KEY_set_group failed", group, pubkey,
                  keyJavaBytes);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_KEY_set_group");
        return 0;
    }

    if (pubkey != nullptr) {
        if (EC_KEY_set_public_key(eckey.get(), pubkey) != 1) {
            JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p) => EC_KEY_set_private_key failed", group,
                      pubkey, keyJavaBytes);
            conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_KEY_set_public_key");
            return 0;
        }
    }

    if (key.get() != nullptr) {
        if (EC_KEY_set_private_key(eckey.get(), key.get()) != 1) {
            JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p) => EC_KEY_set_private_key failed", group,
                      pubkey, keyJavaBytes);
            conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_KEY_set_private_key");
            return 0;
        }
        if (pubkey == nullptr) {
            bssl::UniquePtr<EC_POINT> calcPubkey(EC_POINT_new(group));
            if (!EC_POINT_mul(group, calcPubkey.get(), key.get(), nullptr, nullptr, nullptr)) {
                JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p) => can't calculate public key", group,
                          pubkey, keyJavaBytes);
                conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_KEY_set_private_key");
                return 0;
            }
            EC_KEY_set_public_key(eckey.get(), calcPubkey.get());
        }
    }

    if (!EC_KEY_check_key(eckey.get())) {
        JNI_TRACE("EVP_KEY_new_EC_KEY(%p, %p, %p) => invalid key created", group, pubkey,
                  keyJavaBytes);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_KEY_check_key");
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    if (pkey.get() == nullptr) {
        JNI_TRACE("EVP_PKEY_new_EC(%p, %p, %p) => threw error", group, pubkey, keyJavaBytes);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_PKEY_new failed");
        return 0;
    }
    if (EVP_PKEY_assign_EC_KEY(pkey.get(), eckey.get()) != 1) {
        JNI_TRACE("EVP_PKEY_new_EC(%p, %p, %p) => threw error", group, pubkey, keyJavaBytes);
        conscrypt::jniutil::throwRuntimeException(env, "EVP_PKEY_assign_EC_KEY failed");
        ERR_clear_error();
        return 0;
    }
    OWNERSHIP_TRANSFERRED(eckey);

    JNI_TRACE("EVP_PKEY_new_EC_KEY(%p, %p, %p) => %p", group, pubkey, keyJavaBytes, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static int NativeCrypto_EVP_PKEY_type(JNIEnv* env, jclass, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EVP_PKEY_type(%p)", pkey);

    if (pkey == nullptr) {
        return -1;
    }

    int result = EVP_PKEY_type(pkey->type);
    JNI_TRACE("EVP_PKEY_type(%p) => %d", pkey, result);
    return result;
}

typedef int print_func(BIO*, const EVP_PKEY*, int, ASN1_PCTX*);

static jstring evp_print_func(JNIEnv* env, jobject pkeyRef, print_func* func,
                              const char* debug_name) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("%s(%p)", debug_name, pkey);

    if (pkey == nullptr) {
        return nullptr;
    }

    bssl::UniquePtr<BIO> buffer(BIO_new(BIO_s_mem()));
    if (buffer.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate BIO");
        return nullptr;
    }

    if (func(buffer.get(), pkey, 0, nullptr) != 1) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, debug_name);
        return nullptr;
    }
    // Null terminate this
    BIO_write(buffer.get(), "\0", 1);

    char* tmp;
    BIO_get_mem_data(buffer.get(), &tmp);
    jstring description = env->NewStringUTF(tmp);

    JNI_TRACE("%s(%p) => \"%s\"", debug_name, pkey, tmp);
    return description;
}

static jstring NativeCrypto_EVP_PKEY_print_public(JNIEnv* env, jclass, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return evp_print_func(env, pkeyRef, EVP_PKEY_print_public, "EVP_PKEY_print_public");
}

static jstring NativeCrypto_EVP_PKEY_print_params(JNIEnv* env, jclass, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return evp_print_func(env, pkeyRef, EVP_PKEY_print_params, "EVP_PKEY_print_params");
}

static void NativeCrypto_EVP_PKEY_free(JNIEnv* env, jclass, jlong pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(pkeyRef);
    JNI_TRACE("EVP_PKEY_free(%p)", pkey);

    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
}

static jint NativeCrypto_EVP_PKEY_cmp(JNIEnv* env, jclass, jobject pkey1Ref, jobject pkey2Ref) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("EVP_PKEY_cmp(%p, %p)", pkey1Ref, pkey2Ref);
    EVP_PKEY* pkey1 = fromContextObject<EVP_PKEY>(env, pkey1Ref);
    if (pkey1 == nullptr) {
        JNI_TRACE("EVP_PKEY_cmp => pkey1 == null");
        return 0;
    }
    EVP_PKEY* pkey2 = fromContextObject<EVP_PKEY>(env, pkey2Ref);
    if (pkey2 == nullptr) {
        JNI_TRACE("EVP_PKEY_cmp => pkey2 == null");
        return 0;
    }
    JNI_TRACE("EVP_PKEY_cmp(%p, %p) <- ptr", pkey1, pkey2);

    int result = EVP_PKEY_cmp(pkey1, pkey2);
    JNI_TRACE("EVP_PKEY_cmp(%p, %p) => %d", pkey1, pkey2, result);
    return result;
}

/*
 * static native byte[] EVP_marshal_private_key(long)
 */
static jbyteArray NativeCrypto_EVP_marshal_private_key(JNIEnv* env, jclass, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EVP_marshal_private_key(%p)", pkey);

    if (pkey == nullptr) {
        return nullptr;
    }

    bssl::ScopedCBB cbb;
    if (!CBB_init(cbb.get(), 64)) {
        conscrypt::jniutil::throwOutOfMemory(env, "CBB_init failed");
        JNI_TRACE("CBB_init failed");
        return nullptr;
    }

    if (!EVP_marshal_private_key(cbb.get(), pkey)) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_marshal_private_key");
        JNI_TRACE("key=%p EVP_marshal_private_key => error", pkey);
        return nullptr;
    }

    return CBBToByteArray(env, cbb.get());
}

/*
 * static native long EVP_parse_private_key(byte[])
 */
static jlong NativeCrypto_EVP_parse_private_key(JNIEnv* env, jclass, jbyteArray keyJavaBytes) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("EVP_parse_private_key(%p)", keyJavaBytes);

    ScopedByteArrayRO bytes(env, keyJavaBytes);
    if (bytes.get() == nullptr) {
        JNI_TRACE("bytes=%p EVP_parse_private_key => threw exception", keyJavaBytes);
        return 0;
    }

    CBS cbs;
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(bytes.get()), bytes.size());
    bssl::UniquePtr<EVP_PKEY> pkey(EVP_parse_private_key(&cbs));
    // We intentionally do not check that cbs is exhausted, as JCA providers typically
    // allow parsing keys from buffers that are larger than the contained key structure
    // so we do the same for compatibility.
    if (!pkey) {
        conscrypt::jniutil::throwParsingException(env, "Error parsing private key");
        ERR_clear_error();
        JNI_TRACE("bytes=%p EVP_parse_private_key => threw exception", keyJavaBytes);
        return 0;
    }

    JNI_TRACE("bytes=%p EVP_parse_private_key => %p", keyJavaBytes, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

/*
 * static native byte[] EVP_marshal_public_key(long)
 */
static jbyteArray NativeCrypto_EVP_marshal_public_key(JNIEnv* env, jclass, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EVP_marshal_public_key(%p)", pkey);

    if (pkey == nullptr) {
        return nullptr;
    }

    bssl::ScopedCBB cbb;
    if (!CBB_init(cbb.get(), 64)) {
        conscrypt::jniutil::throwOutOfMemory(env, "CBB_init failed");
        JNI_TRACE("CBB_init failed");
        return nullptr;
    }

    if (!EVP_marshal_public_key(cbb.get(), pkey)) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_marshal_public_key");
        JNI_TRACE("key=%p EVP_marshal_public_key => error", pkey);
        return nullptr;
    }

    return CBBToByteArray(env, cbb.get());
}

/*
 * static native long EVP_parse_public_key(byte[])
 */
static jlong NativeCrypto_EVP_parse_public_key(JNIEnv* env, jclass, jbyteArray keyJavaBytes) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("EVP_parse_public_key(%p)", keyJavaBytes);

    ScopedByteArrayRO bytes(env, keyJavaBytes);
    if (bytes.get() == nullptr) {
        JNI_TRACE("bytes=%p EVP_parse_public_key => threw exception", keyJavaBytes);
        return 0;
    }

    CBS cbs;
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(bytes.get()), bytes.size());
    bssl::UniquePtr<EVP_PKEY> pkey(EVP_parse_public_key(&cbs));
    // We intentionally do not check that cbs is exhausted, as JCA providers typically
    // allow parsing keys from buffers that are larger than the contained key structure
    // so we do the same for compatibility.
    if (!pkey) {
        conscrypt::jniutil::throwParsingException(env, "Error parsing public key");
        ERR_clear_error();
        JNI_TRACE("bytes=%p EVP_parse_public_key => threw exception", keyJavaBytes);
        return 0;
    }

    JNI_TRACE("bytes=%p EVP_parse_public_key => %p", keyJavaBytes, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jlong NativeCrypto_getRSAPrivateKeyWrapper(JNIEnv* env, jclass, jobject javaKey,
                                                  jbyteArray modulusBytes) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("getRSAPrivateKeyWrapper(%p, %p)", javaKey, modulusBytes);

    size_t cached_size;
    if (!arrayToBignumSize(env, modulusBytes, &cached_size)) {
        JNI_TRACE("getRSAPrivateKeyWrapper failed");
        return 0;
    }

    ensure_engine_globals();

    bssl::UniquePtr<RSA> rsa(RSA_new_method(g_engine));
    if (rsa.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate RSA key");
        return 0;
    }

    // The PSS padding code needs access to the actual n, so set it even though we
    // don't set any other parts of the key
    if (!arrayToBignum(env, modulusBytes, &rsa->n)) {
        return 0;
    }

    auto ex_data = new KeyExData;
    ex_data->private_key = env->NewGlobalRef(javaKey);
    ex_data->cached_size = cached_size;
    RSA_set_ex_data(rsa.get(), g_rsa_exdata_index, ex_data);

    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    if (pkey.get() == nullptr) {
        JNI_TRACE("getRSAPrivateKeyWrapper failed");
        conscrypt::jniutil::throwRuntimeException(env,
                                                  "NativeCrypto_getRSAPrivateKeyWrapper failed");
        ERR_clear_error();
        return 0;
    }

    if (EVP_PKEY_assign_RSA(pkey.get(), rsa.get()) != 1) {
        conscrypt::jniutil::throwRuntimeException(env, "getRSAPrivateKeyWrapper failed");
        ERR_clear_error();
        return 0;
    }
    OWNERSHIP_TRANSFERRED(rsa);
    JNI_TRACE("getRSAPrivateKeyWrapper(%p, %p) => %p", javaKey, modulusBytes, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jlong NativeCrypto_getECPrivateKeyWrapper(JNIEnv* env, jclass, jobject javaKey,
                                                 jobject groupRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("getECPrivateKeyWrapper(%p, %p)", javaKey, group);
    if (group == nullptr) {
        return 0;
    }

    ensure_engine_globals();

    bssl::UniquePtr<EC_KEY> ecKey(EC_KEY_new_method(g_engine));
    if (ecKey.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate EC key");
        return 0;
    }

    if (EC_KEY_set_group(ecKey.get(), group) != 1) {
        JNI_TRACE("getECPrivateKeyWrapper(%p, %p) => EC_KEY_set_group error", javaKey, group);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_KEY_set_group");
        return 0;
    }

    auto ex_data = new KeyExData;
    ex_data->private_key = env->NewGlobalRef(javaKey);

    if (!EC_KEY_set_ex_data(ecKey.get(), g_ecdsa_exdata_index, ex_data)) {
        env->DeleteGlobalRef(ex_data->private_key);
        delete ex_data;
        conscrypt::jniutil::throwRuntimeException(env, "EC_KEY_set_ex_data");
        ERR_clear_error();
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    if (pkey.get() == nullptr) {
        JNI_TRACE("getECPrivateKeyWrapper failed");
        conscrypt::jniutil::throwRuntimeException(env,
                                                  "NativeCrypto_getECPrivateKeyWrapper failed");
        ERR_clear_error();
        return 0;
    }

    if (EVP_PKEY_assign_EC_KEY(pkey.get(), ecKey.get()) != 1) {
        conscrypt::jniutil::throwRuntimeException(env, "getECPrivateKeyWrapper failed");
        ERR_clear_error();
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
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("RSA_generate_key_ex(%d, %p)", modulusBits, publicExponent);

    BIGNUM* eRef = nullptr;
    if (!arrayToBignum(env, publicExponent, &eRef)) {
        return 0;
    }
    bssl::UniquePtr<BIGNUM> e(eRef);

    bssl::UniquePtr<RSA> rsa(RSA_new());
    if (rsa.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate RSA key");
        return 0;
    }

    if (RSA_generate_key_ex(rsa.get(), modulusBits, e.get(), nullptr) != 1) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "RSA_generate_key_ex failed");
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    if (pkey.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate RSA key");
        return 0;
    }

    if (EVP_PKEY_assign_RSA(pkey.get(), rsa.get()) != 1) {
        conscrypt::jniutil::throwRuntimeException(env, "RSA_generate_key_ex failed");
        ERR_clear_error();
        return 0;
    }

    OWNERSHIP_TRANSFERRED(rsa);
    JNI_TRACE("RSA_generate_key_ex(n=%d, e=%p) => %p", modulusBits, publicExponent, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jint NativeCrypto_RSA_size(JNIEnv* env, jclass, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("RSA_size(%p)", pkey);

    if (pkey == nullptr) {
        return 0;
    }

    bssl::UniquePtr<RSA> rsa(EVP_PKEY_get1_RSA(pkey));
    if (rsa.get() == nullptr) {
        conscrypt::jniutil::throwRuntimeException(env, "RSA_size failed");
        ERR_clear_error();
        return 0;
    }

    return static_cast<jint>(RSA_size(rsa.get()));
}

typedef int RSACryptOperation(size_t flen, const unsigned char* from, unsigned char* to, RSA* rsa,
                              int padding);

static jint RSA_crypt_operation(RSACryptOperation operation, const char* caller, JNIEnv* env,
                                jint flen, jbyteArray fromJavaBytes, jbyteArray toJavaBytes,
                                jobject pkeyRef, jint padding) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("%s(%d, %p, %p, %p)", caller, flen, fromJavaBytes, toJavaBytes, pkey);

    if (pkey == nullptr) {
        return -1;
    }

    bssl::UniquePtr<RSA> rsa(EVP_PKEY_get1_RSA(pkey));
    if (rsa.get() == nullptr) {
        return -1;
    }

    ScopedByteArrayRO from(env, fromJavaBytes);
    if (from.get() == nullptr) {
        return -1;
    }

    ScopedByteArrayRW to(env, toJavaBytes);
    if (to.get() == nullptr) {
        return -1;
    }

    int resultSize =
            operation(static_cast<size_t>(flen), reinterpret_cast<const unsigned char*>(from.get()),
                      reinterpret_cast<unsigned char*>(to.get()), rsa.get(), padding);
    if (resultSize == -1) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, caller,
                conscrypt::jniutil::throwBadPaddingException);
        JNI_TRACE("%s => threw error", caller);
        return -1;
    }

    JNI_TRACE("%s(%d, %p, %p, %p) => %d", caller, flen, fromJavaBytes, toJavaBytes, pkey,
              resultSize);
    return static_cast<jint>(resultSize);
}

static jint NativeCrypto_RSA_private_encrypt(JNIEnv* env, jclass, jint flen,
                                             jbyteArray fromJavaBytes, jbyteArray toJavaBytes,
                                             jobject pkeyRef, jint padding) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return RSA_crypt_operation(RSA_private_encrypt, __FUNCTION__, env, flen, fromJavaBytes,
                               toJavaBytes, pkeyRef, padding);
}
static jint NativeCrypto_RSA_public_decrypt(JNIEnv* env, jclass, jint flen,
                                            jbyteArray fromJavaBytes, jbyteArray toJavaBytes,
                                            jobject pkeyRef, jint padding) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return RSA_crypt_operation(RSA_public_decrypt, __FUNCTION__, env, flen, fromJavaBytes,
                               toJavaBytes, pkeyRef, padding);
}
static jint NativeCrypto_RSA_public_encrypt(JNIEnv* env, jclass, jint flen,
                                            jbyteArray fromJavaBytes, jbyteArray toJavaBytes,
                                            jobject pkeyRef, jint padding) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return RSA_crypt_operation(RSA_public_encrypt, __FUNCTION__, env, flen, fromJavaBytes,
                               toJavaBytes, pkeyRef, padding);
}
static jint NativeCrypto_RSA_private_decrypt(JNIEnv* env, jclass, jint flen,
                                             jbyteArray fromJavaBytes, jbyteArray toJavaBytes,
                                             jobject pkeyRef, jint padding) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return RSA_crypt_operation(RSA_private_decrypt, __FUNCTION__, env, flen, fromJavaBytes,
                               toJavaBytes, pkeyRef, padding);
}

/*
 * public static native byte[][] get_RSA_public_params(long);
 */
static jobjectArray NativeCrypto_get_RSA_public_params(JNIEnv* env, jclass, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("get_RSA_public_params(%p)", pkey);

    if (pkey == nullptr) {
        return nullptr;
    }

    bssl::UniquePtr<RSA> rsa(EVP_PKEY_get1_RSA(pkey));
    if (rsa.get() == nullptr) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "get_RSA_public_params failed");
        return nullptr;
    }

    jobjectArray joa = env->NewObjectArray(2, conscrypt::jniutil::byteArrayClass, nullptr);
    if (joa == nullptr) {
        return nullptr;
    }

    jbyteArray n = bignumToArray(env, rsa->n, "n");
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    env->SetObjectArrayElement(joa, 0, n);

    jbyteArray e = bignumToArray(env, rsa->e, "e");
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    env->SetObjectArrayElement(joa, 1, e);

    return joa;
}

/*
 * public static native byte[][] get_RSA_private_params(long);
 */
static jobjectArray NativeCrypto_get_RSA_private_params(JNIEnv* env, jclass, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("get_RSA_public_params(%p)", pkey);

    if (pkey == nullptr) {
        return nullptr;
    }

    bssl::UniquePtr<RSA> rsa(EVP_PKEY_get1_RSA(pkey));
    if (rsa.get() == nullptr) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "get_RSA_public_params failed");
        return nullptr;
    }

    jobjectArray joa = env->NewObjectArray(8, conscrypt::jniutil::byteArrayClass, nullptr);
    if (joa == nullptr) {
        return nullptr;
    }

    jbyteArray n = bignumToArray(env, rsa->n, "n");
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    env->SetObjectArrayElement(joa, 0, n);

    if (rsa->e != nullptr) {
        jbyteArray e = bignumToArray(env, rsa->e, "e");
        if (env->ExceptionCheck()) {
            return nullptr;
        }
        env->SetObjectArrayElement(joa, 1, e);
    }

    if (rsa->d != nullptr) {
        jbyteArray d = bignumToArray(env, rsa->d, "d");
        if (env->ExceptionCheck()) {
            return nullptr;
        }
        env->SetObjectArrayElement(joa, 2, d);
    }

    if (rsa->p != nullptr) {
        jbyteArray p = bignumToArray(env, rsa->p, "p");
        if (env->ExceptionCheck()) {
            return nullptr;
        }
        env->SetObjectArrayElement(joa, 3, p);
    }

    if (rsa->q != nullptr) {
        jbyteArray q = bignumToArray(env, rsa->q, "q");
        if (env->ExceptionCheck()) {
            return nullptr;
        }
        env->SetObjectArrayElement(joa, 4, q);
    }

    if (rsa->dmp1 != nullptr) {
        jbyteArray dmp1 = bignumToArray(env, rsa->dmp1, "dmp1");
        if (env->ExceptionCheck()) {
            return nullptr;
        }
        env->SetObjectArrayElement(joa, 5, dmp1);
    }

    if (rsa->dmq1 != nullptr) {
        jbyteArray dmq1 = bignumToArray(env, rsa->dmq1, "dmq1");
        if (env->ExceptionCheck()) {
            return nullptr;
        }
        env->SetObjectArrayElement(joa, 6, dmq1);
    }

    if (rsa->iqmp != nullptr) {
        jbyteArray iqmp = bignumToArray(env, rsa->iqmp, "iqmp");
        if (env->ExceptionCheck()) {
            return nullptr;
        }
        env->SetObjectArrayElement(joa, 7, iqmp);
    }

    return joa;
}

static void NativeCrypto_chacha20_encrypt_decrypt(JNIEnv* env, jclass, jbyteArray inBytes,
        jint inOffset, jbyteArray outBytes, jint outOffset, jint length, jbyteArray keyBytes,
        jbyteArray nonceBytes, jint blockCounter) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("chacha20_encrypt_decrypt");
    ScopedByteArrayRO in(env, inBytes);
    if (in.get() == nullptr) {
        JNI_TRACE("chacha20_encrypt_decrypt => threw exception: could not read input bytes");
        return;
    }
    ScopedByteArrayRW out(env, outBytes);
    if (out.get() == nullptr) {
        JNI_TRACE("chacha20_encrypt_decrypt => threw exception: could not read output bytes");
        return;
    }
    ScopedByteArrayRO key(env, keyBytes);
    if (key.get() == nullptr) {
        JNI_TRACE("chacha20_encrypt_decrypt => threw exception: could not read key bytes");
        return;
    }
    ScopedByteArrayRO nonce(env, nonceBytes);
    if (nonce.get() == nullptr) {
        JNI_TRACE("chacha20_encrypt_decrypt => threw exception: could not read nonce bytes");
        return;
    }

    CRYPTO_chacha_20(
            reinterpret_cast<unsigned char*>(out.get()) + outOffset,
            reinterpret_cast<const unsigned char*>(in.get()) + inOffset,
            length,
            reinterpret_cast<const unsigned char*>(key.get()),
            reinterpret_cast<const unsigned char*>(nonce.get()),
            blockCounter);
}

static jlong NativeCrypto_EC_GROUP_new_by_curve_name(JNIEnv* env, jclass, jstring curveNameJava) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("EC_GROUP_new_by_curve_name(%p)", curveNameJava);

    ScopedUtfChars curveName(env, curveNameJava);
    if (curveName.c_str() == nullptr) {
        return 0;
    }
    JNI_TRACE("EC_GROUP_new_by_curve_name(%s)", curveName.c_str());

    int nid = OBJ_sn2nid(curveName.c_str());
    if (nid == NID_undef) {
        JNI_TRACE("EC_GROUP_new_by_curve_name(%s) => unknown NID name", curveName.c_str());
        return 0;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
    if (group == nullptr) {
        JNI_TRACE("EC_GROUP_new_by_curve_name(%s) => unknown NID %d", curveName.c_str(), nid);
        ERR_clear_error();
        return 0;
    }

    JNI_TRACE("EC_GROUP_new_by_curve_name(%s) => %p", curveName.c_str(), group);
    return reinterpret_cast<uintptr_t>(group);
}

static jlong NativeCrypto_EC_GROUP_new_arbitrary(JNIEnv* env, jclass, jbyteArray pBytes,
                                                 jbyteArray aBytes, jbyteArray bBytes,
                                                 jbyteArray xBytes, jbyteArray yBytes,
                                                 jbyteArray orderBytes, jint cofactorInt) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    BIGNUM *p = nullptr, *a = nullptr, *b = nullptr, *x = nullptr, *y = nullptr;
    BIGNUM *order = nullptr, *cofactor = nullptr;

    JNI_TRACE("EC_GROUP_new_arbitrary");

    if (cofactorInt < 1) {
        conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                           "cofactor < 1");
        return 0;
    }

    cofactor = BN_new();
    if (cofactor == nullptr) {
        return 0;
    }

    int ok = 1;

    if (!arrayToBignum(env, pBytes, &p) || !arrayToBignum(env, aBytes, &a) ||
        !arrayToBignum(env, bBytes, &b) || !arrayToBignum(env, xBytes, &x) ||
        !arrayToBignum(env, yBytes, &y) || !arrayToBignum(env, orderBytes, &order) ||
        !BN_set_word(cofactor, static_cast<uint32_t>(cofactorInt))) {
        ok = 0;
    }

    bssl::UniquePtr<BIGNUM> pStorage(p);
    bssl::UniquePtr<BIGNUM> aStorage(a);
    bssl::UniquePtr<BIGNUM> bStorage(b);
    bssl::UniquePtr<BIGNUM> xStorage(x);
    bssl::UniquePtr<BIGNUM> yStorage(y);
    bssl::UniquePtr<BIGNUM> orderStorage(order);
    bssl::UniquePtr<BIGNUM> cofactorStorage(cofactor);

    if (!ok) {
        return 0;
    }

    bssl::UniquePtr<BN_CTX> ctx(BN_CTX_new());
    bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_curve_GFp(p, a, b, ctx.get()));
    if (group.get() == nullptr) {
        JNI_TRACE("EC_GROUP_new_curve_GFp => null");
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_GROUP_new_curve_GFp");
        return 0;
    }

    bssl::UniquePtr<EC_POINT> generator(EC_POINT_new(group.get()));
    if (generator.get() == nullptr) {
        JNI_TRACE("EC_POINT_new => null");
        ERR_clear_error();
        return 0;
    }

    if (!EC_POINT_set_affine_coordinates_GFp(group.get(), generator.get(), x, y, ctx.get())) {
        JNI_TRACE("EC_POINT_set_affine_coordinates_GFp => error");
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env,
                                                             "EC_POINT_set_affine_coordinates_GFp");
        return 0;
    }

    if (!EC_GROUP_set_generator(group.get(), generator.get(), order, cofactor)) {
        JNI_TRACE("EC_GROUP_set_generator => error");
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_GROUP_set_generator");
        return 0;
    }

    JNI_TRACE("EC_GROUP_new_arbitrary => %p", group.get());
    return reinterpret_cast<uintptr_t>(group.release());
}

static jstring NativeCrypto_EC_GROUP_get_curve_name(JNIEnv* env, jclass, jobject groupRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_get_curve_name(%p)", group);

    if (group == nullptr) {
        JNI_TRACE("EC_GROUP_get_curve_name => group == null");
        return nullptr;
    }

    int nid = EC_GROUP_get_curve_name(group);
    if (nid == NID_undef) {
        JNI_TRACE("EC_GROUP_get_curve_name(%p) => unnamed curve", group);
        return nullptr;
    }

    const char* shortName = OBJ_nid2sn(nid);
    JNI_TRACE("EC_GROUP_get_curve_name(%p) => \"%s\"", group, shortName);
    return env->NewStringUTF(shortName);
}

static jobjectArray NativeCrypto_EC_GROUP_get_curve(JNIEnv* env, jclass, jobject groupRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_get_curve(%p)", group);
    if (group == nullptr) {
        JNI_TRACE("EC_GROUP_get_curve => group == null");
        return nullptr;
    }

    bssl::UniquePtr<BIGNUM> p(BN_new());
    bssl::UniquePtr<BIGNUM> a(BN_new());
    bssl::UniquePtr<BIGNUM> b(BN_new());

    int ret = EC_GROUP_get_curve_GFp(group, p.get(), a.get(), b.get(), nullptr);
    if (ret != 1) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_GROUP_get_curve");
        return nullptr;
    }

    jobjectArray joa = env->NewObjectArray(3, conscrypt::jniutil::byteArrayClass, nullptr);
    if (joa == nullptr) {
        return nullptr;
    }

    jbyteArray pArray = bignumToArray(env, p.get(), "p");
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    env->SetObjectArrayElement(joa, 0, pArray);

    jbyteArray aArray = bignumToArray(env, a.get(), "a");
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    env->SetObjectArrayElement(joa, 1, aArray);

    jbyteArray bArray = bignumToArray(env, b.get(), "b");
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    env->SetObjectArrayElement(joa, 2, bArray);

    JNI_TRACE("EC_GROUP_get_curve(%p) => %p", group, joa);
    return joa;
}

static jbyteArray NativeCrypto_EC_GROUP_get_order(JNIEnv* env, jclass, jobject groupRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_get_order(%p)", group);
    if (group == nullptr) {
        return nullptr;
    }

    bssl::UniquePtr<BIGNUM> order(BN_new());
    if (order.get() == nullptr) {
        JNI_TRACE("EC_GROUP_get_order(%p) => can't create BN", group);
        conscrypt::jniutil::throwOutOfMemory(env, "BN_new");
        return nullptr;
    }

    if (EC_GROUP_get_order(group, order.get(), nullptr) != 1) {
        JNI_TRACE("EC_GROUP_get_order(%p) => threw error", group);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_GROUP_get_order");
        return nullptr;
    }

    jbyteArray orderArray = bignumToArray(env, order.get(), "order");
    if (env->ExceptionCheck()) {
        return nullptr;
    }

    JNI_TRACE("EC_GROUP_get_order(%p) => %p", group, orderArray);
    return orderArray;
}

static jint NativeCrypto_EC_GROUP_get_degree(JNIEnv* env, jclass, jobject groupRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_get_degree(%p)", group);
    if (group == nullptr) {
        return 0;
    }

    jint degree = static_cast<jint>(EC_GROUP_get_degree(group));
    if (degree == 0) {
        JNI_TRACE("EC_GROUP_get_degree(%p) => unsupported", group);
        conscrypt::jniutil::throwRuntimeException(env, "not supported");
        ERR_clear_error();
        return 0;
    }

    JNI_TRACE("EC_GROUP_get_degree(%p) => %d", group, degree);
    return degree;
}

static jbyteArray NativeCrypto_EC_GROUP_get_cofactor(JNIEnv* env, jclass, jobject groupRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_get_cofactor(%p)", group);
    if (group == nullptr) {
        return nullptr;
    }

    bssl::UniquePtr<BIGNUM> cofactor(BN_new());
    if (cofactor.get() == nullptr) {
        JNI_TRACE("EC_GROUP_get_cofactor(%p) => can't create BN", group);
        conscrypt::jniutil::throwOutOfMemory(env, "BN_new");
        return nullptr;
    }

    if (EC_GROUP_get_cofactor(group, cofactor.get(), nullptr) != 1) {
        JNI_TRACE("EC_GROUP_get_cofactor(%p) => threw error", group);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_GROUP_get_cofactor");
        return nullptr;
    }

    jbyteArray cofactorArray = bignumToArray(env, cofactor.get(), "cofactor");
    if (env->ExceptionCheck()) {
        return nullptr;
    }

    JNI_TRACE("EC_GROUP_get_cofactor(%p) => %p", group, cofactorArray);
    return cofactorArray;
}

static void NativeCrypto_EC_GROUP_clear_free(JNIEnv* env, jclass, jlong groupRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EC_GROUP* group = reinterpret_cast<EC_GROUP*>(groupRef);
    JNI_TRACE("EC_GROUP_clear_free(%p)", group);

    if (group == nullptr) {
        JNI_TRACE("EC_GROUP_clear_free => group == null");
        conscrypt::jniutil::throwNullPointerException(env, "group == null");
        return;
    }

    EC_GROUP_free(group);
    JNI_TRACE("EC_GROUP_clear_free(%p) => success", group);
}

static jlong NativeCrypto_EC_GROUP_get_generator(JNIEnv* env, jclass, jobject groupRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_GROUP_get_generator(%p)", group);

    if (group == nullptr) {
        JNI_TRACE("EC_POINT_get_generator(%p) => group == null", group);
        return 0;
    }

    const EC_POINT* generator = EC_GROUP_get0_generator(group);

    bssl::UniquePtr<EC_POINT> dup(EC_POINT_dup(generator, group));
    if (dup.get() == nullptr) {
        JNI_TRACE("EC_GROUP_get_generator(%p) => oom error", group);
        conscrypt::jniutil::throwOutOfMemory(env, "unable to dupe generator");
        return 0;
    }

    JNI_TRACE("EC_GROUP_get_generator(%p) => %p", group, dup.get());
    return reinterpret_cast<uintptr_t>(dup.release());
}

static jlong NativeCrypto_EC_POINT_new(JNIEnv* env, jclass, jobject groupRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_POINT_new(%p)", group);

    if (group == nullptr) {
        JNI_TRACE("EC_POINT_new(%p) => group == null", group);
        return 0;
    }

    EC_POINT* point = EC_POINT_new(group);
    if (point == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable create an EC_POINT");
        return 0;
    }

    return reinterpret_cast<uintptr_t>(point);
}

static void NativeCrypto_EC_POINT_clear_free(JNIEnv* env, jclass, jlong groupRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EC_POINT* group = reinterpret_cast<EC_POINT*>(groupRef);
    JNI_TRACE("EC_POINT_clear_free(%p)", group);

    if (group == nullptr) {
        JNI_TRACE("EC_POINT_clear_free => group == null");
        conscrypt::jniutil::throwNullPointerException(env, "group == null");
        return;
    }

    EC_POINT_free(group);
    JNI_TRACE("EC_POINT_clear_free(%p) => success", group);
}

static void NativeCrypto_EC_POINT_set_affine_coordinates(JNIEnv* env, jclass, jobject groupRef,
                                                         jobject pointRef, jbyteArray xjavaBytes,
                                                         jbyteArray yjavaBytes) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("EC_POINT_set_affine_coordinates(%p, %p, %p, %p)", groupRef, pointRef, xjavaBytes,
              yjavaBytes);
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    if (group == nullptr) {
        return;
    }
    EC_POINT* point = fromContextObject<EC_POINT>(env, pointRef);
    if (point == nullptr) {
        return;
    }
    JNI_TRACE("EC_POINT_set_affine_coordinates(%p, %p, %p, %p) <- ptr", group, point, xjavaBytes,
              yjavaBytes);

    BIGNUM* xRef = nullptr;
    if (!arrayToBignum(env, xjavaBytes, &xRef)) {
        return;
    }
    bssl::UniquePtr<BIGNUM> x(xRef);

    BIGNUM* yRef = nullptr;
    if (!arrayToBignum(env, yjavaBytes, &yRef)) {
        return;
    }
    bssl::UniquePtr<BIGNUM> y(yRef);

    int ret = EC_POINT_set_affine_coordinates_GFp(group, point, x.get(), y.get(), nullptr);
    if (ret != 1) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env,
                                                             "EC_POINT_set_affine_coordinates");
        return;
    }

    JNI_TRACE("EC_POINT_set_affine_coordinates(%p, %p, %p, %p) => %d", group, point, xjavaBytes,
              yjavaBytes, ret);
}

static jobjectArray NativeCrypto_EC_POINT_get_affine_coordinates(JNIEnv* env, jclass,
                                                                 jobject groupRef,
                                                                 jobject pointRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("EC_POINT_get_affine_coordinates(%p, %p)", groupRef, pointRef);
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    if (group == nullptr) {
        return nullptr;
    }
    const EC_POINT* point = fromContextObject<EC_POINT>(env, pointRef);
    if (point == nullptr) {
        return nullptr;
    }
    JNI_TRACE("EC_POINT_get_affine_coordinates(%p, %p) <- ptr", group, point);

    bssl::UniquePtr<BIGNUM> x(BN_new());
    bssl::UniquePtr<BIGNUM> y(BN_new());

    int ret = EC_POINT_get_affine_coordinates_GFp(group, point, x.get(), y.get(), nullptr);
    if (ret != 1) {
        JNI_TRACE("EC_POINT_get_affine_coordinates(%p, %p)", group, point);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env,
                                                             "EC_POINT_get_affine_coordinates");
        return nullptr;
    }

    jobjectArray joa = env->NewObjectArray(2, conscrypt::jniutil::byteArrayClass, nullptr);
    if (joa == nullptr) {
        return nullptr;
    }

    jbyteArray xBytes = bignumToArray(env, x.get(), "x");
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    env->SetObjectArrayElement(joa, 0, xBytes);

    jbyteArray yBytes = bignumToArray(env, y.get(), "y");
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    env->SetObjectArrayElement(joa, 1, yBytes);

    JNI_TRACE("EC_POINT_get_affine_coordinates(%p, %p) => %p", group, point, joa);
    return joa;
}

static jlong NativeCrypto_EC_KEY_generate_key(JNIEnv* env, jclass, jobject groupRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_KEY_generate_key(%p)", group);
    if (group == nullptr) {
        return 0;
    }

    bssl::UniquePtr<EC_KEY> eckey(EC_KEY_new());
    if (eckey.get() == nullptr) {
        JNI_TRACE("EC_KEY_generate_key(%p) => EC_KEY_new() oom", group);
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to create an EC_KEY");
        return 0;
    }

    if (EC_KEY_set_group(eckey.get(), group) != 1) {
        JNI_TRACE("EC_KEY_generate_key(%p) => EC_KEY_set_group error", group);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_KEY_set_group");
        return 0;
    }

    if (EC_KEY_generate_key(eckey.get()) != 1) {
        JNI_TRACE("EC_KEY_generate_key(%p) => EC_KEY_generate_key error", group);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_KEY_set_group");
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    if (pkey.get() == nullptr) {
        JNI_TRACE("EC_KEY_generate_key(%p) => threw error", group);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EC_KEY_generate_key");
        return 0;
    }
    if (EVP_PKEY_assign_EC_KEY(pkey.get(), eckey.get()) != 1) {
        conscrypt::jniutil::throwRuntimeException(env, "EVP_PKEY_assign_EC_KEY failed");
        ERR_clear_error();
        return 0;
    }
    OWNERSHIP_TRANSFERRED(eckey);

    JNI_TRACE("EC_KEY_generate_key(%p) => %p", group, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jlong NativeCrypto_EC_KEY_get1_group(JNIEnv* env, jclass, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EC_KEY_get1_group(%p)", pkey);

    if (pkey == nullptr) {
        JNI_TRACE("EC_KEY_get1_group(%p) => pkey == null", pkey);
        return 0;
    }

    if (EVP_PKEY_type(pkey->type) != EVP_PKEY_EC) {
        conscrypt::jniutil::throwRuntimeException(env, "not EC key");
        JNI_TRACE("EC_KEY_get1_group(%p) => not EC key (type == %d)", pkey,
                  EVP_PKEY_type(pkey->type));
        return 0;
    }

    EC_GROUP* group = EC_GROUP_dup(EC_KEY_get0_group(pkey->pkey.ec));
    JNI_TRACE("EC_KEY_get1_group(%p) => %p", pkey, group);
    return reinterpret_cast<uintptr_t>(group);
}

static jbyteArray NativeCrypto_EC_KEY_get_private_key(JNIEnv* env, jclass, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EC_KEY_get_private_key(%p)", pkey);

    if (pkey == nullptr) {
        JNI_TRACE("EC_KEY_get_private_key => pkey == null");
        return nullptr;
    }

    bssl::UniquePtr<EC_KEY> eckey(EVP_PKEY_get1_EC_KEY(pkey));
    if (eckey.get() == nullptr) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_PKEY_get1_EC_KEY");
        return nullptr;
    }

    const BIGNUM* privkey = EC_KEY_get0_private_key(eckey.get());

    jbyteArray privBytes = bignumToArray(env, privkey, "privkey");
    if (env->ExceptionCheck()) {
        JNI_TRACE("EC_KEY_get_private_key(%p) => threw error", pkey);
        return nullptr;
    }

    JNI_TRACE("EC_KEY_get_private_key(%p) => %p", pkey, privBytes);
    return privBytes;
}

static jlong NativeCrypto_EC_KEY_get_public_key(JNIEnv* env, jclass, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("EC_KEY_get_public_key(%p)", pkey);

    if (pkey == nullptr) {
        JNI_TRACE("EC_KEY_get_public_key => pkey == null");
        return 0;
    }

    bssl::UniquePtr<EC_KEY> eckey(EVP_PKEY_get1_EC_KEY(pkey));
    if (eckey.get() == nullptr) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_PKEY_get1_EC_KEY");
        return 0;
    }

    bssl::UniquePtr<EC_POINT> dup(
            EC_POINT_dup(EC_KEY_get0_public_key(eckey.get()), EC_KEY_get0_group(eckey.get())));
    if (dup.get() == nullptr) {
        JNI_TRACE("EC_KEY_get_public_key(%p) => can't dup public key", pkey);
        conscrypt::jniutil::throwRuntimeException(env, "EC_POINT_dup");
        ERR_clear_error();
        return 0;
    }

    JNI_TRACE("EC_KEY_get_public_key(%p) => %p", pkey, dup.get());
    return reinterpret_cast<uintptr_t>(dup.release());
}

static jbyteArray NativeCrypto_EC_KEY_marshal_curve_name(JNIEnv* env, jclass, jobject groupRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EC_GROUP* group = fromContextObject<EC_GROUP>(env, groupRef);
    JNI_TRACE("EC_KEY_marshal_curve_name(%p)", group);
    if (group == nullptr) {
        conscrypt::jniutil::throwIOException(env, "Invalid group pointer");
        return nullptr;
    }

    bssl::ScopedCBB cbb;
    if (!CBB_init(cbb.get(), 64)) {
        conscrypt::jniutil::throwOutOfMemory(env, "CBB_init failed");
        JNI_TRACE("CBB_init failed");
        return nullptr;
    }

    if (!EC_KEY_marshal_curve_name(cbb.get(), group)) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        ERR_clear_error();
        JNI_TRACE("group=%p EC_KEY_marshal_curve_name => error", group);
        return nullptr;
    }

    return CBBToByteArray(env, cbb.get());
}

static jlong NativeCrypto_EC_KEY_parse_curve_name(JNIEnv* env, jclass, jbyteArray curveNameBytes) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("EC_KEY_parse_curve_name(%p)", curveNameBytes);

    ScopedByteArrayRO bytes(env, curveNameBytes);
    if (bytes.get() == nullptr) {
        conscrypt::jniutil::throwIOException(env, "Error reading ASN.1 encoding");
        JNI_TRACE("bytes=%p EC_KEY_parse_curve_name => threw exception", curveNameBytes);
        return 0;
    }

    CBS cbs;
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(bytes.get()), bytes.size());
    bssl::UniquePtr<EC_GROUP> group(EC_KEY_parse_curve_name(&cbs));
    if (!group || CBS_len(&cbs) != 0) {
        conscrypt::jniutil::throwIOException(env, "Error reading ASN.1 encoding");
        ERR_clear_error();
        JNI_TRACE("bytes=%p EC_KEY_parse_curve_name => threw exception", curveNameBytes);
        return 0;
    }

    JNI_TRACE("bytes=%p EC_KEY_parse_curve_name => %p", curveNameBytes, group.get());
    return reinterpret_cast<uintptr_t>(group.release());
}

static jint NativeCrypto_ECDH_compute_key(JNIEnv* env, jclass, jbyteArray outArray, jint outOffset,
                                          jobject pubkeyRef, jobject privkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("ECDH_compute_key(%p, %d, %p, %p)", outArray, outOffset, pubkeyRef, privkeyRef);
    EVP_PKEY* pubPkey = fromContextObject<EVP_PKEY>(env, pubkeyRef);
    if (pubPkey == nullptr) {
        JNI_TRACE("ECDH_compute_key => pubPkey == null");
        return -1;
    }
    EVP_PKEY* privPkey = fromContextObject<EVP_PKEY>(env, privkeyRef);
    if (privPkey == nullptr) {
        JNI_TRACE("ECDH_compute_key => privPkey == null");
        return -1;
    }
    JNI_TRACE("ECDH_compute_key(%p, %d, %p, %p) <- ptr", outArray, outOffset, pubPkey, privPkey);

    ScopedByteArrayRW out(env, outArray);
    if (out.get() == nullptr) {
        JNI_TRACE("ECDH_compute_key(%p, %d, %p, %p) can't get output buffer", outArray, outOffset,
                  pubPkey, privPkey);
        return -1;
    }

    if (ARRAY_OFFSET_INVALID(out, outOffset)) {
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
                                           nullptr);
        return -1;
    }

    if (pubPkey == nullptr) {
        JNI_TRACE("ECDH_compute_key(%p) => pubPkey == null", pubPkey);
        conscrypt::jniutil::throwNullPointerException(env, "pubPkey == null");
        return -1;
    }

    bssl::UniquePtr<EC_KEY> pubkey(EVP_PKEY_get1_EC_KEY(pubPkey));
    if (pubkey.get() == nullptr) {
        JNI_TRACE("ECDH_compute_key(%p) => can't get public key", pubPkey);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_PKEY_get1_EC_KEY public",
                                                      conscrypt::jniutil::throwInvalidKeyException);
        return -1;
    }

    const EC_POINT* pubkeyPoint = EC_KEY_get0_public_key(pubkey.get());
    if (pubkeyPoint == nullptr) {
        JNI_TRACE("ECDH_compute_key(%p) => can't get public key point", pubPkey);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_PKEY_get1_EC_KEY public",
                                                      conscrypt::jniutil::throwInvalidKeyException);
        return -1;
    }

    if (privPkey == nullptr) {
        JNI_TRACE("ECDH_compute_key(%p) => privKey == null", pubPkey);
        conscrypt::jniutil::throwNullPointerException(env, "privPkey == null");
        return -1;
    }

    bssl::UniquePtr<EC_KEY> privkey(EVP_PKEY_get1_EC_KEY(privPkey));
    if (privkey.get() == nullptr) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_PKEY_get1_EC_KEY private",
                                                      conscrypt::jniutil::throwInvalidKeyException);
        return -1;
    }

    std::size_t stdOutOffset = static_cast<std::size_t>(outOffset);
    int outputLength = ECDH_compute_key(&out[stdOutOffset], out.size() - stdOutOffset, pubkeyPoint,
                                        privkey.get(), nullptr /* No KDF */);
    if (outputLength == -1) {
        JNI_TRACE("ECDH_compute_key(%p) => outputLength = -1", pubPkey);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "ECDH_compute_key",
                                                      conscrypt::jniutil::throwInvalidKeyException);
        return -1;
    }

    JNI_TRACE("ECDH_compute_key(%p) => outputLength=%d", pubPkey, outputLength);
    return outputLength;
}

static jint NativeCrypto_ECDSA_size(JNIEnv* env, jclass, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("ECDSA_size(%p)", pkey);

    if (pkey == nullptr) {
        return 0;
    }

    bssl::UniquePtr<EC_KEY> ec_key(EVP_PKEY_get1_EC_KEY(pkey));
    if (ec_key.get() == nullptr) {
        conscrypt::jniutil::throwRuntimeException(env, "ECDSA_size failed");
        ERR_clear_error();
        return 0;
    }

    size_t size = ECDSA_size(ec_key.get());

    JNI_TRACE("ECDSA_size(%p) => %zu", pkey, size);
    return static_cast<jint>(size);
}

static jint NativeCrypto_ECDSA_sign(JNIEnv* env, jclass, jbyteArray data, jbyteArray sig,
                                    jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("ECDSA_sign(%p, %p, %p)", data, sig, pkey);

    if (pkey == nullptr) {
        return -1;
    }

    bssl::UniquePtr<EC_KEY> ec_key(EVP_PKEY_get1_EC_KEY(pkey));
    if (ec_key.get() == nullptr) {
        return -1;
    }

    ScopedByteArrayRO data_array(env, data);
    if (data_array.get() == nullptr) {
        return -1;
    }

    ScopedByteArrayRW sig_array(env, sig);
    if (sig_array.get() == nullptr) {
        return -1;
    }

    unsigned int sig_size;
    int result = ECDSA_sign(0, reinterpret_cast<const unsigned char*>(data_array.get()),
                            data_array.size(), reinterpret_cast<unsigned char*>(sig_array.get()),
                            &sig_size, ec_key.get());
    if (result == 0) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "ECDSA_sign");
        JNI_TRACE("ECDSA_sign => threw error");
        return -1;
    }

    JNI_TRACE("ECDSA_sign(%p, %p, %p) => %d", data, sig, pkey, sig_size);
    return static_cast<jint>(sig_size);
}

static jint NativeCrypto_ECDSA_verify(JNIEnv* env, jclass, jbyteArray data, jbyteArray sig,
                                      jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("ECDSA_verify(%p, %p, %p)", data, sig, pkey);

    if (pkey == nullptr) {
        return -1;
    }

    bssl::UniquePtr<EC_KEY> ec_key(EVP_PKEY_get1_EC_KEY(pkey));
    if (ec_key.get() == nullptr) {
        return -1;
    }

    ScopedByteArrayRO data_array(env, data);
    if (data_array.get() == nullptr) {
        return -1;
    }

    ScopedByteArrayRO sig_array(env, sig);
    if (sig_array.get() == nullptr) {
        return -1;
    }

    int result =
            ECDSA_verify(0, reinterpret_cast<const unsigned char*>(data_array.get()),
                         data_array.size(), reinterpret_cast<const unsigned char*>(sig_array.get()),
                         sig_array.size(), ec_key.get());

    if (result == 0) {
        // NOLINTNEXTLINE(runtime/int)
        unsigned long error = ERR_peek_last_error();
        if ((ERR_GET_LIB(error) == ERR_LIB_ECDSA) &&
            (ERR_GET_REASON(error) == ECDSA_R_BAD_SIGNATURE)) {
            // This error just means the signature didn't verify, so clear the error and return
            // a failed verification
            ERR_clear_error();
            JNI_TRACE("ECDSA_verify(%p, %p, %p) => %d", data, sig, pkey, result);
            return 0;
        }
        if (error != 0) {
            conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "ECDSA_verify");
            JNI_TRACE("ECDSA_verify => threw error");
            return -1;
        }
        return 0;
    }

    JNI_TRACE("ECDSA_verify(%p, %p, %p) => %d", data, sig, pkey, result);
    return static_cast<jint>(result);
}

static jlong NativeCrypto_EVP_MD_CTX_create(JNIEnv* env, jclass) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE_MD("EVP_MD_CTX_create()");

    bssl::UniquePtr<EVP_MD_CTX> ctx(EVP_MD_CTX_create());
    if (ctx.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable create a EVP_MD_CTX");
        return 0;
    }

    JNI_TRACE_MD("EVP_MD_CTX_create() => %p", ctx.get());
    return reinterpret_cast<uintptr_t>(ctx.release());
}

static void NativeCrypto_EVP_MD_CTX_cleanup(JNIEnv* env, jclass, jobject ctxRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_MD_CTX* ctx = fromContextObject<EVP_MD_CTX>(env, ctxRef);
    JNI_TRACE_MD("EVP_MD_CTX_cleanup(%p)", ctx);

    if (ctx != nullptr) {
        EVP_MD_CTX_cleanup(ctx);
    }
}

static void NativeCrypto_EVP_MD_CTX_destroy(JNIEnv* env, jclass, jlong ctxRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_MD_CTX* ctx = reinterpret_cast<EVP_MD_CTX*>(ctxRef);
    JNI_TRACE_MD("EVP_MD_CTX_destroy(%p)", ctx);

    if (ctx != nullptr) {
        EVP_MD_CTX_destroy(ctx);
    }
}

static jint NativeCrypto_EVP_MD_CTX_copy_ex(JNIEnv* env, jclass, jobject dstCtxRef,
                                            jobject srcCtxRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE_MD("EVP_MD_CTX_copy_ex(%p. %p)", dstCtxRef, srcCtxRef);
    EVP_MD_CTX* dst_ctx = fromContextObject<EVP_MD_CTX>(env, dstCtxRef);
    if (dst_ctx == nullptr) {
        JNI_TRACE_MD("EVP_MD_CTX_copy_ex => dst_ctx == null");
        return 0;
    }
    const EVP_MD_CTX* src_ctx = fromContextObject<EVP_MD_CTX>(env, srcCtxRef);
    if (src_ctx == nullptr) {
        JNI_TRACE_MD("EVP_MD_CTX_copy_ex => src_ctx == null");
        return 0;
    }
    JNI_TRACE_MD("EVP_MD_CTX_copy_ex(%p. %p) <- ptr", dst_ctx, src_ctx);

    int result = EVP_MD_CTX_copy_ex(dst_ctx, src_ctx);
    if (result == 0) {
        conscrypt::jniutil::throwRuntimeException(env, "Unable to copy EVP_MD_CTX");
        ERR_clear_error();
    }

    JNI_TRACE_MD("EVP_MD_CTX_copy_ex(%p, %p) => %d", dst_ctx, src_ctx, result);
    return result;
}

/*
 * public static native int EVP_DigestFinal_ex(long, byte[], int)
 */
static jint NativeCrypto_EVP_DigestFinal_ex(JNIEnv* env, jclass, jobject ctxRef, jbyteArray hash,
                                            jint offset) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_MD_CTX* ctx = fromContextObject<EVP_MD_CTX>(env, ctxRef);
    JNI_TRACE_MD("EVP_DigestFinal_ex(%p, %p, %d)", ctx, hash, offset);

    if (ctx == nullptr) {
        JNI_TRACE("EVP_DigestFinal_ex => ctx == null");
        return -1;
    } else if (hash == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "hash == null");
        return -1;
    }

    ScopedByteArrayRW hashBytes(env, hash);
    if (hashBytes.get() == nullptr) {
        return -1;
    }
    unsigned int bytesWritten = static_cast<unsigned int>(-1);
    int ok = EVP_DigestFinal_ex(ctx, reinterpret_cast<unsigned char*>(hashBytes.get() + offset),
                                &bytesWritten);
    if (ok == 0) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_DigestFinal_ex");
        return -1;
    }

    JNI_TRACE_MD("EVP_DigestFinal_ex(%p, %p, %d) => %d (%d)", ctx, hash, offset, bytesWritten, ok);
    return static_cast<jint>(bytesWritten);
}

static jint NativeCrypto_EVP_DigestInit_ex(JNIEnv* env, jclass, jobject evpMdCtxRef,
                                           jlong evpMdRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_MD_CTX* ctx = fromContextObject<EVP_MD_CTX>(env, evpMdCtxRef);
    const EVP_MD* evp_md = reinterpret_cast<const EVP_MD*>(evpMdRef);
    JNI_TRACE_MD("EVP_DigestInit_ex(%p, %p)", ctx, evp_md);

    if (ctx == nullptr) {
        JNI_TRACE("EVP_DigestInit_ex(%p) => ctx == null", evp_md);
        return 0;
    } else if (evp_md == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "evp_md == null");
        return 0;
    }

    int ok = EVP_DigestInit_ex(ctx, evp_md, nullptr);
    if (ok == 0) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_DigestInit_ex");
        JNI_TRACE("EVP_DigestInit_ex(%p) => threw exception", evp_md);
        return 0;
    }
    JNI_TRACE_MD("EVP_DigestInit_ex(%p, %p) => %d", ctx, evp_md, ok);
    return ok;
}

/*
 * public static native int EVP_get_digestbyname(java.lang.String)
 */
static jlong NativeCrypto_EVP_get_digestbyname(JNIEnv* env, jclass, jstring algorithm) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("NativeCrypto_EVP_get_digestbyname(%p)", algorithm);

    if (algorithm == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, nullptr);
        return -1;
    }

    ScopedUtfChars algorithmChars(env, algorithm);
    if (algorithmChars.c_str() == nullptr) {
        return 0;
    }
    JNI_TRACE("NativeCrypto_EVP_get_digestbyname(%s)", algorithmChars.c_str());

    const char* alg = algorithmChars.c_str();
    const EVP_MD* md;

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
        conscrypt::jniutil::throwRuntimeException(env, "Hash algorithm not found");
        return 0;
    }

    return reinterpret_cast<uintptr_t>(md);
}

/*
 * public static native int EVP_MD_size(long)
 */
static jint NativeCrypto_EVP_MD_size(JNIEnv* env, jclass, jlong evpMdRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_MD* evp_md = reinterpret_cast<EVP_MD*>(evpMdRef);
    JNI_TRACE("NativeCrypto_EVP_MD_size(%p)", evp_md);

    if (evp_md == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, nullptr);
        return -1;
    }

    jint result = static_cast<jint>(EVP_MD_size(evp_md));
    JNI_TRACE("NativeCrypto_EVP_MD_size(%p) => %d", evp_md, result);
    return result;
}

static jlong evpDigestSignVerifyInit(JNIEnv* env,
                                     int (*init_func)(EVP_MD_CTX*, EVP_PKEY_CTX**, const EVP_MD*,
                                                      ENGINE*, EVP_PKEY*),
                                     const char* jniName, jobject evpMdCtxRef, jlong evpMdRef,
                                     jobject pkeyRef) {
    EVP_MD_CTX* mdCtx = fromContextObject<EVP_MD_CTX>(env, evpMdCtxRef);
    if (mdCtx == nullptr) {
        JNI_TRACE("%s => mdCtx == null", jniName);
        return 0;
    }
    const EVP_MD* md = reinterpret_cast<const EVP_MD*>(evpMdRef);
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    if (pkey == nullptr) {
        JNI_TRACE("ctx=%p %s => pkey == null", mdCtx, jniName);
        return 0;
    }
    JNI_TRACE("%s(%p, %p, %p) <- ptr", jniName, mdCtx, md, pkey);

    if (md == nullptr) {
        JNI_TRACE("ctx=%p %s => md == null", mdCtx, jniName);
        conscrypt::jniutil::throwNullPointerException(env, "md == null");
        return 0;
    }

    EVP_PKEY_CTX* pctx = nullptr;
    if (init_func(mdCtx, &pctx, md, nullptr, pkey) <= 0) {
        JNI_TRACE("ctx=%p %s => threw exception", mdCtx, jniName);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, jniName);
        return 0;
    }

    JNI_TRACE("%s(%p, %p, %p) => success", jniName, mdCtx, md, pkey);
    return reinterpret_cast<jlong>(pctx);
}

static jlong NativeCrypto_EVP_DigestSignInit(JNIEnv* env, jclass, jobject evpMdCtxRef,
                                             const jlong evpMdRef, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return evpDigestSignVerifyInit(env, EVP_DigestSignInit, "EVP_DigestSignInit", evpMdCtxRef,
                                   evpMdRef, pkeyRef);
}

static jlong NativeCrypto_EVP_DigestVerifyInit(JNIEnv* env, jclass, jobject evpMdCtxRef,
                                               const jlong evpMdRef, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return evpDigestSignVerifyInit(env, EVP_DigestVerifyInit, "EVP_DigestVerifyInit", evpMdCtxRef,
                                   evpMdRef, pkeyRef);
}

static void evpUpdate(JNIEnv* env, jobject evpMdCtxRef, jlong inPtr, jint inLength,
                      const char* jniName, int (*update_func)(EVP_MD_CTX*, const void*, size_t)) {
    EVP_MD_CTX* mdCtx = fromContextObject<EVP_MD_CTX>(env, evpMdCtxRef);
    const void* p = reinterpret_cast<const void*>(inPtr);
    JNI_TRACE_MD("%s(%p, %p, %d)", jniName, mdCtx, p, inLength);

    if (mdCtx == nullptr) {
        return;
    }

    if (p == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, nullptr);
        return;
    }

    if (!update_func(mdCtx, p, static_cast<std::size_t>(inLength))) {
        JNI_TRACE("ctx=%p %s => threw exception", mdCtx, jniName);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, jniName);
        return;
    }

    JNI_TRACE_MD("%s(%p, %p, %d) => success", jniName, mdCtx, p, inLength);
}

static void evpUpdate(JNIEnv* env, jobject evpMdCtxRef, jbyteArray inJavaBytes, jint inOffset,
                      jint inLength, const char* jniName,
                      int (*update_func)(EVP_MD_CTX*, const void*, size_t)) {
    EVP_MD_CTX* mdCtx = fromContextObject<EVP_MD_CTX>(env, evpMdCtxRef);
    JNI_TRACE_MD("%s(%p, %p, %d, %d)", jniName, mdCtx, inJavaBytes, inOffset, inLength);

    if (mdCtx == nullptr) {
        return;
    }

    if (inJavaBytes == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "inBytes");
        return;
    }

    size_t array_size = static_cast<size_t>(env->GetArrayLength(inJavaBytes));
    if (ARRAY_CHUNK_INVALID(array_size, inOffset, inLength)) {
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
                                           "inBytes");
        return;
    }
    if (inLength == 0) {
        return;
    }
    jint in_offset = inOffset;
    jint in_size = inLength;

    int update_func_result = -1;
    if (conscrypt::jniutil::isGetByteArrayElementsLikelyToReturnACopy(array_size)) {
        // GetByteArrayElements is expected to return a copy. Use GetByteArrayRegion instead, to
        // avoid copying the whole array.
        if (in_size <= 1024) {
            // For small chunk, it's more efficient to use a bit more space on the stack instead of
            // allocating a new buffer.
            jbyte buf[1024];
            env->GetByteArrayRegion(inJavaBytes, in_offset, in_size, buf);
            update_func_result = update_func(mdCtx, reinterpret_cast<const unsigned char*>(buf),
                                             static_cast<size_t>(in_size));
        } else {
            // For large chunk, allocate a 64 kB buffer and stream the chunk into update_func
            // through the buffer, stopping as soon as update_func fails.
            jint remaining = in_size;
            jint buf_size = (remaining >= 65536) ? 65536 : remaining;
            std::unique_ptr<jbyte[]> buf(new jbyte[static_cast<unsigned int>(buf_size)]);
            if (buf.get() == nullptr) {
                conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate chunk buffer");
                return;
            }
            while (remaining > 0) {
                jint chunk_size = (remaining >= buf_size) ? buf_size : remaining;
                env->GetByteArrayRegion(inJavaBytes, in_offset, chunk_size, buf.get());
                update_func_result =
                        update_func(mdCtx, reinterpret_cast<const unsigned char*>(buf.get()),
                                    static_cast<size_t>(chunk_size));
                if (!update_func_result) {
                    // update_func failed. This will be handled later in this method.
                    break;
                }
                in_offset += chunk_size;
                remaining -= chunk_size;
            }
        }
    } else {
        // GetByteArrayElements is expected to not return a copy. Use GetByteArrayElements.
        // We're not using ScopedByteArrayRO here because its an implementation detail whether it'll
        // use GetByteArrayElements or another approach.
        jbyte* array_elements = env->GetByteArrayElements(inJavaBytes, nullptr);
        if (array_elements == nullptr) {
            conscrypt::jniutil::throwOutOfMemory(env, "Unable to obtain elements of inBytes");
            return;
        }
        const unsigned char* buf = reinterpret_cast<const unsigned char*>(array_elements);
        update_func_result = update_func(mdCtx, buf + in_offset, static_cast<size_t>(in_size));
        env->ReleaseByteArrayElements(inJavaBytes, array_elements, JNI_ABORT);
    }

    if (!update_func_result) {
        JNI_TRACE("ctx=%p %s => threw exception", mdCtx, jniName);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, jniName);
        return;
    }

    JNI_TRACE_MD("%s(%p, %p, %d, %d) => success", jniName, mdCtx, inJavaBytes, inOffset, inLength);
}

static void NativeCrypto_EVP_DigestUpdateDirect(JNIEnv* env, jclass, jobject evpMdCtxRef,
                                                jlong inPtr, jint inLength) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    evpUpdate(env, evpMdCtxRef, inPtr, inLength, "EVP_DigestUpdateDirect", EVP_DigestUpdate);
}

static void NativeCrypto_EVP_DigestUpdate(JNIEnv* env, jclass, jobject evpMdCtxRef,
                                          jbyteArray inJavaBytes, jint inOffset, jint inLength) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    evpUpdate(env, evpMdCtxRef, inJavaBytes, inOffset, inLength, "EVP_DigestUpdate",
              EVP_DigestUpdate);
}

static void NativeCrypto_EVP_DigestSignUpdate(JNIEnv* env, jclass, jobject evpMdCtxRef,
                                              jbyteArray inJavaBytes, jint inOffset,
                                              jint inLength) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    evpUpdate(env, evpMdCtxRef, inJavaBytes, inOffset, inLength, "EVP_DigestSignUpdate",
            EVP_DigestSignUpdate);
}

static void NativeCrypto_EVP_DigestSignUpdateDirect(JNIEnv* env, jclass, jobject evpMdCtxRef,
        jlong inPtr, jint inLength) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    evpUpdate(env, evpMdCtxRef, inPtr, inLength, "EVP_DigestSignUpdateDirect",
            EVP_DigestSignUpdate);
}

static void NativeCrypto_EVP_DigestVerifyUpdate(JNIEnv* env, jclass, jobject evpMdCtxRef,
                                                jbyteArray inJavaBytes, jint inOffset,
                                                jint inLength) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    evpUpdate(env, evpMdCtxRef, inJavaBytes, inOffset, inLength, "EVP_DigestVerifyUpdate",
              EVP_DigestVerifyUpdate);
}

static void NativeCrypto_EVP_DigestVerifyUpdateDirect(JNIEnv* env, jclass, jobject evpMdCtxRef,
                                                      jlong inPtr, jint inLength) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    evpUpdate(env, evpMdCtxRef, inPtr, inLength, "EVP_DigestVerifyUpdateDirect",
              EVP_DigestVerifyUpdate);
}

static jbyteArray NativeCrypto_EVP_DigestSignFinal(JNIEnv* env, jclass, jobject evpMdCtxRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_MD_CTX* mdCtx = fromContextObject<EVP_MD_CTX>(env, evpMdCtxRef);
    JNI_TRACE("EVP_DigestSignFinal(%p)", mdCtx);

    if (mdCtx == nullptr) {
        return nullptr;
    }

    size_t maxLen;
    if (EVP_DigestSignFinal(mdCtx, nullptr, &maxLen) != 1) {
        JNI_TRACE("ctx=%p EVP_DigestSignFinal => threw exception", mdCtx);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_DigestSignFinal");
        return nullptr;
    }

    std::unique_ptr<unsigned char[]> buffer(new unsigned char[maxLen]);
    if (buffer.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate signature buffer");
        return nullptr;
    }
    size_t actualLen(maxLen);
    if (EVP_DigestSignFinal(mdCtx, buffer.get(), &actualLen) != 1) {
        JNI_TRACE("ctx=%p EVP_DigestSignFinal => threw exception", mdCtx);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_DigestSignFinal");
        return nullptr;
    }
    if (actualLen > maxLen) {
        JNI_TRACE("ctx=%p EVP_DigestSignFinal => signature too long: %zd vs %zd", mdCtx, actualLen,
                  maxLen);
        conscrypt::jniutil::throwRuntimeException(env, "EVP_DigestSignFinal signature too long");
        return nullptr;
    }

    ScopedLocalRef<jbyteArray> sigJavaBytes(env, env->NewByteArray(static_cast<jint>(actualLen)));
    if (sigJavaBytes.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Failed to allocate signature byte[]");
        return nullptr;
    }
    env->SetByteArrayRegion(sigJavaBytes.get(), 0, static_cast<jint>(actualLen),
                            reinterpret_cast<jbyte*>(buffer.get()));

    JNI_TRACE("EVP_DigestSignFinal(%p) => %p", mdCtx, sigJavaBytes.get());
    return sigJavaBytes.release();
}

static jboolean NativeCrypto_EVP_DigestVerifyFinal(JNIEnv* env, jclass, jobject evpMdCtxRef,
                                                   jbyteArray signature, jint offset, jint len) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_MD_CTX* mdCtx = fromContextObject<EVP_MD_CTX>(env, evpMdCtxRef);
    JNI_TRACE("EVP_DigestVerifyFinal(%p)", mdCtx);

    if (mdCtx == nullptr) {
        return 0;
    }

    ScopedByteArrayRO sigBytes(env, signature);
    if (sigBytes.get() == nullptr) {
        return 0;
    }

    if (ARRAY_OFFSET_LENGTH_INVALID(sigBytes, offset, len)) {
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
                                           "signature");
        return 0;
    }

    const unsigned char* sigBuf = reinterpret_cast<const unsigned char*>(sigBytes.get());
    int err = EVP_DigestVerifyFinal(mdCtx, sigBuf + offset, static_cast<size_t>(len));
    jboolean result;
    if (err == 1) {
        // Signature verified
        result = 1;
    } else if (err == 0) {
        // Signature did not verify
        result = 0;
    } else {
        // Error while verifying signature
        JNI_TRACE("ctx=%p EVP_DigestVerifyFinal => threw exception", mdCtx);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_DigestVerifyFinal");
        return 0;
    }

    // If the signature did not verify, BoringSSL error queue contains an error (BAD_SIGNATURE).
    // Clear the error queue to prevent its state from affecting future operations.
    ERR_clear_error();

    JNI_TRACE("EVP_DigestVerifyFinal(%p) => %d", mdCtx, result);
    return result;
}

static jint evpPkeyEncryptDecrypt(JNIEnv* env,
                                  int (*encrypt_decrypt_func)(EVP_PKEY_CTX*, uint8_t*, size_t*,
                                                              const uint8_t*, size_t),
                                  const char* jniName, jobject evpPkeyCtxRef,
                                  jbyteArray outJavaBytes, jint outOffset, jbyteArray inJavaBytes,
                                  jint inOffset, jint inLength) {
    EVP_PKEY_CTX* pkeyCtx = fromContextObject<EVP_PKEY_CTX>(env, evpPkeyCtxRef);
    JNI_TRACE_MD("%s(%p, %p, %d, %p, %d, %d)", jniName, pkeyCtx, outJavaBytes, outOffset,
                 inJavaBytes, inOffset, inLength);

    if (pkeyCtx == nullptr) {
        return 0;
    }

    ScopedByteArrayRW outBytes(env, outJavaBytes);
    if (outBytes.get() == nullptr) {
        return 0;
    }

    ScopedByteArrayRO inBytes(env, inJavaBytes);
    if (inBytes.get() == nullptr) {
        return 0;
    }

    if (ARRAY_OFFSET_INVALID(outBytes, outOffset)) {
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
                                           "outBytes");
        return 0;
    }

    if (ARRAY_OFFSET_LENGTH_INVALID(inBytes, inOffset, inLength)) {
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
                                           "inBytes");
        return 0;
    }

    uint8_t* outBuf = reinterpret_cast<uint8_t*>(outBytes.get());
    const uint8_t* inBuf = reinterpret_cast<const uint8_t*>(inBytes.get());
    size_t outLength = outBytes.size() - outOffset;
    if (!encrypt_decrypt_func(pkeyCtx, outBuf + outOffset, &outLength, inBuf + inOffset,
                              static_cast<size_t>(inLength))) {
        JNI_TRACE("ctx=%p %s => threw exception", pkeyCtx, jniName);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(
                env, jniName, conscrypt::jniutil::throwBadPaddingException);
        return 0;
    }

    JNI_TRACE("%s(%p, %p, %d, %p, %d, %d) => success (%zd bytes)", jniName, pkeyCtx, outJavaBytes,
              outOffset, inJavaBytes, inOffset, inLength, outLength);
    return static_cast<jint>(outLength);
}

static jint NativeCrypto_EVP_PKEY_encrypt(JNIEnv* env, jclass, jobject evpPkeyCtxRef,
                                          jbyteArray out, jint outOffset, jbyteArray inBytes,
                                          jint inOffset, jint inLength) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return evpPkeyEncryptDecrypt(env, EVP_PKEY_encrypt, "EVP_PKEY_encrypt", evpPkeyCtxRef, out,
                                 outOffset, inBytes, inOffset, inLength);
}

static jint NativeCrypto_EVP_PKEY_decrypt(JNIEnv* env, jclass, jobject evpPkeyCtxRef,
                                          jbyteArray out, jint outOffset, jbyteArray inBytes,
                                          jint inOffset, jint inLength) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return evpPkeyEncryptDecrypt(env, EVP_PKEY_decrypt, "EVP_PKEY_decrypt", evpPkeyCtxRef, out,
                                 outOffset, inBytes, inOffset, inLength);
}

static jlong evpPkeyEcryptDecryptInit(JNIEnv* env, jobject evpPkeyRef,
                                      int (*real_func)(EVP_PKEY_CTX*), const char* opType) {
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, evpPkeyRef);
    JNI_TRACE("EVP_PKEY_%s_init(%p)", opType, pkey);
    if (pkey == nullptr) {
        JNI_TRACE("EVP_PKEY_%s_init(%p) => pkey == null", opType, pkey);
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY_CTX> pkeyCtx(EVP_PKEY_CTX_new(pkey, nullptr));
    if (pkeyCtx.get() == nullptr) {
        JNI_TRACE("EVP_PKEY_%s_init(%p) => threw exception", opType, pkey);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(
                env, "EVP_PKEY_CTX_new", conscrypt::jniutil::throwInvalidKeyException);
        return 0;
    }

    if (!real_func(pkeyCtx.get())) {
        JNI_TRACE("EVP_PKEY_%s_init(%p) => threw exception", opType, pkey);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(
                env, opType, conscrypt::jniutil::throwInvalidKeyException);
        return 0;
    }

    JNI_TRACE("EVP_PKEY_%s_init(%p) => pkeyCtx=%p", opType, pkey, pkeyCtx.get());
    return reinterpret_cast<uintptr_t>(pkeyCtx.release());
}

static jlong NativeCrypto_EVP_PKEY_encrypt_init(JNIEnv* env, jclass, jobject evpPkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return evpPkeyEcryptDecryptInit(env, evpPkeyRef, EVP_PKEY_encrypt_init, "encrypt");
}

static jlong NativeCrypto_EVP_PKEY_decrypt_init(JNIEnv* env, jclass, jobject evpPkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return evpPkeyEcryptDecryptInit(env, evpPkeyRef, EVP_PKEY_decrypt_init, "decrypt");
}

static void NativeCrypto_EVP_PKEY_CTX_free(JNIEnv* env, jclass, jlong pkeyCtxRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY_CTX* pkeyCtx = reinterpret_cast<EVP_PKEY_CTX*>(pkeyCtxRef);
    JNI_TRACE("EVP_PKEY_CTX_free(%p)", pkeyCtx);

    if (pkeyCtx != nullptr) {
        EVP_PKEY_CTX_free(pkeyCtx);
    }
}

static void NativeCrypto_EVP_PKEY_CTX_set_rsa_padding(JNIEnv* env, jclass, jlong ctx, jint pad) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY_CTX* pkeyCtx = reinterpret_cast<EVP_PKEY_CTX*>(ctx);
    JNI_TRACE("EVP_PKEY_CTX_set_rsa_padding(%p, %d)", pkeyCtx, pad);
    if (pkeyCtx == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "ctx == null");
        return;
    }

    int result = EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, static_cast<int>(pad));
    if (result <= 0) {
        JNI_TRACE("ctx=%p EVP_PKEY_CTX_set_rsa_padding => threw exception", pkeyCtx);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(
                env, "EVP_PKEY_CTX_set_rsa_padding",
                conscrypt::jniutil::throwInvalidAlgorithmParameterException);
        return;
    }

    JNI_TRACE("EVP_PKEY_CTX_set_rsa_padding(%p, %d) => success", pkeyCtx, pad);
}

static void NativeCrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen(JNIEnv* env, jclass, jlong ctx,
                                                          jint len) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY_CTX* pkeyCtx = reinterpret_cast<EVP_PKEY_CTX*>(ctx);
    JNI_TRACE("EVP_PKEY_CTX_set_rsa_pss_saltlen(%p, %d)", pkeyCtx, len);
    if (pkeyCtx == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "ctx == null");
        return;
    }

    int result = EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, static_cast<int>(len));
    if (result <= 0) {
        JNI_TRACE("ctx=%p EVP_PKEY_CTX_set_rsa_pss_saltlen => threw exception", pkeyCtx);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(
                env, "EVP_PKEY_CTX_set_rsa_pss_saltlen",
                conscrypt::jniutil::throwInvalidAlgorithmParameterException);
        return;
    }

    JNI_TRACE("EVP_PKEY_CTX_set_rsa_pss_saltlen(%p, %d) => success", pkeyCtx, len);
}

static void evpPkeyCtxCtrlMdOp(JNIEnv* env, jlong pkeyCtxRef, jlong mdRef, const char* jniName,
                               int (*ctrl_func)(EVP_PKEY_CTX*, const EVP_MD*)) {
    EVP_PKEY_CTX* pkeyCtx = reinterpret_cast<EVP_PKEY_CTX*>(pkeyCtxRef);
    EVP_MD* md = reinterpret_cast<EVP_MD*>(mdRef);
    JNI_TRACE("%s(%p, %p)", jniName, pkeyCtx, md);
    if (pkeyCtx == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "pkeyCtx == null");
        return;
    }
    if (md == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "md == null");
        return;
    }

    int result = ctrl_func(pkeyCtx, md);
    if (result <= 0) {
        JNI_TRACE("ctx=%p %s => threw exception", pkeyCtx, jniName);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(
                env, jniName, conscrypt::jniutil::throwInvalidAlgorithmParameterException);
        return;
    }

    JNI_TRACE("%s(%p, %p) => success", jniName, pkeyCtx, md);
}

static void NativeCrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(JNIEnv* env, jclass, jlong pkeyCtxRef,
                                                      jlong mdRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    evpPkeyCtxCtrlMdOp(env, pkeyCtxRef, mdRef, "EVP_PKEY_CTX_set_rsa_mgf1_md",
                       EVP_PKEY_CTX_set_rsa_mgf1_md);
}

static void NativeCrypto_EVP_PKEY_CTX_set_rsa_oaep_md(JNIEnv* env, jclass, jlong pkeyCtxRef,
                                                      jlong mdRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    evpPkeyCtxCtrlMdOp(env, pkeyCtxRef, mdRef, "EVP_PKEY_CTX_set_rsa_oaep_md",
                       EVP_PKEY_CTX_set_rsa_oaep_md);
}

static void NativeCrypto_EVP_PKEY_CTX_set_rsa_oaep_label(JNIEnv* env, jclass, jlong pkeyCtxRef,
                                                         jbyteArray labelJava) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_PKEY_CTX* pkeyCtx = reinterpret_cast<EVP_PKEY_CTX*>(pkeyCtxRef);
    JNI_TRACE("EVP_PKEY_CTX_set_rsa_oaep_label(%p, %p)", pkeyCtx, labelJava);
    if (pkeyCtx == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "pkeyCtx == null");
        return;
    }

    ScopedByteArrayRO labelBytes(env, labelJava);
    if (labelBytes.get() == nullptr) {
        return;
    }

    bssl::UniquePtr<uint8_t> label(reinterpret_cast<uint8_t*>(OPENSSL_malloc(labelBytes.size())));
    memcpy(label.get(), labelBytes.get(), labelBytes.size());

    int result = EVP_PKEY_CTX_set0_rsa_oaep_label(pkeyCtx, label.get(), labelBytes.size());
    if (result <= 0) {
        JNI_TRACE("ctx=%p EVP_PKEY_CTX_set_rsa_oaep_label => threw exception", pkeyCtx);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(
                env, "EVP_PKEY_CTX_set_rsa_oaep_label",
                conscrypt::jniutil::throwInvalidAlgorithmParameterException);
        return;
    }
    OWNERSHIP_TRANSFERRED(label);

    JNI_TRACE("EVP_PKEY_CTX_set_rsa_oaep_label(%p, %p) => success", pkeyCtx, labelJava);
}

static jlong NativeCrypto_EVP_get_cipherbyname(JNIEnv* env, jclass, jstring algorithm) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("EVP_get_cipherbyname(%p)", algorithm);

    ScopedUtfChars scoped_alg(env, algorithm);
    const char* alg = scoped_alg.c_str();
    const EVP_CIPHER* cipher;

    if (strcasecmp(alg, "rc4") == 0) {
        cipher = EVP_rc4();
    } else if (strcasecmp(alg, "des-cbc") == 0) {
        cipher = EVP_des_cbc();
    } else if (strcasecmp(alg, "des-ede-cbc") == 0) {
        cipher = EVP_des_ede_cbc();
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
}

static void NativeCrypto_EVP_CipherInit_ex(JNIEnv* env, jclass, jobject ctxRef, jlong evpCipherRef,
                                           jbyteArray keyArray, jbyteArray ivArray,
                                           jboolean encrypting) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    const EVP_CIPHER* evpCipher = reinterpret_cast<const EVP_CIPHER*>(evpCipherRef);
    JNI_TRACE("EVP_CipherInit_ex(%p, %p, %p, %p, %d)", ctx, evpCipher, keyArray, ivArray,
              encrypting ? 1 : 0);

    if (ctx == nullptr) {
        JNI_TRACE("EVP_CipherUpdate => ctx == null");
        return;
    }

    // The key can be null if we need to set extra parameters.
    std::unique_ptr<unsigned char[]> keyPtr;
    if (keyArray != nullptr) {
        ScopedByteArrayRO keyBytes(env, keyArray);
        if (keyBytes.get() == nullptr) {
            return;
        }

        keyPtr.reset(new unsigned char[keyBytes.size()]);
        memcpy(keyPtr.get(), keyBytes.get(), keyBytes.size());
    }

    // The IV can be null if we're using ECB.
    std::unique_ptr<unsigned char[]> ivPtr;
    if (ivArray != nullptr) {
        ScopedByteArrayRO ivBytes(env, ivArray);
        if (ivBytes.get() == nullptr) {
            return;
        }

        ivPtr.reset(new unsigned char[ivBytes.size()]);
        memcpy(ivPtr.get(), ivBytes.get(), ivBytes.size());
    }

    if (!EVP_CipherInit_ex(ctx, evpCipher, nullptr, keyPtr.get(), ivPtr.get(),
                           encrypting ? 1 : 0)) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_CipherInit_ex");
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
                                          jint outOffset, jbyteArray inArray, jint inOffset,
                                          jint inLength) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    JNI_TRACE("EVP_CipherUpdate(%p, %p, %d, %p, %d)", ctx, outArray, outOffset, inArray, inOffset);

    if (ctx == nullptr) {
        JNI_TRACE("ctx=%p EVP_CipherUpdate => ctx == null", ctx);
        return 0;
    }

    ScopedByteArrayRO inBytes(env, inArray);
    if (inBytes.get() == nullptr) {
        return 0;
    }
    if (ARRAY_OFFSET_LENGTH_INVALID(inBytes, inOffset, inLength)) {
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
                                           "inBytes");
        return 0;
    }

    ScopedByteArrayRW outBytes(env, outArray);
    if (outBytes.get() == nullptr) {
        return 0;
    }
    if (ARRAY_OFFSET_LENGTH_INVALID(outBytes, outOffset, inLength)) {
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
                                           "outBytes");
        return 0;
    }

    JNI_TRACE(
            "ctx=%p EVP_CipherUpdate in=%p in.length=%zd inOffset=%d inLength=%d out=%p "
            "out.length=%zd outOffset=%d",
            ctx, inBytes.get(), inBytes.size(), inOffset, inLength, outBytes.get(), outBytes.size(),
            outOffset);

    unsigned char* out = reinterpret_cast<unsigned char*>(outBytes.get());
    const unsigned char* in = reinterpret_cast<const unsigned char*>(inBytes.get());

    int outl;
    if (!EVP_CipherUpdate(ctx, out + outOffset, &outl, in + inOffset, inLength)) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_CipherUpdate");
        JNI_TRACE("ctx=%p EVP_CipherUpdate => threw error", ctx);
        return 0;
    }

    JNI_TRACE("EVP_CipherUpdate(%p, %p, %d, %p, %d) => %d", ctx, outArray, outOffset, inArray,
              inOffset, outl);
    return outl;
}

static jint NativeCrypto_EVP_CipherFinal_ex(JNIEnv* env, jclass, jobject ctxRef,
                                            jbyteArray outArray, jint outOffset) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    JNI_TRACE("EVP_CipherFinal_ex(%p, %p, %d)", ctx, outArray, outOffset);

    if (ctx == nullptr) {
        JNI_TRACE("ctx=%p EVP_CipherFinal_ex => ctx == null", ctx);
        return 0;
    }

    ScopedByteArrayRW outBytes(env, outArray);
    if (outBytes.get() == nullptr) {
        return 0;
    }

    unsigned char* out = reinterpret_cast<unsigned char*>(outBytes.get());

    int outl;
    if (!EVP_CipherFinal_ex(ctx, out + outOffset, &outl)) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "EVP_CipherFinal_ex",
                conscrypt::jniutil::throwBadPaddingException);
        JNI_TRACE("ctx=%p EVP_CipherFinal_ex => threw error", ctx);
        return 0;
    }

    JNI_TRACE("EVP_CipherFinal(%p, %p, %d) => %d", ctx, outArray, outOffset, outl);
    return outl;
}

static jint NativeCrypto_EVP_CIPHER_iv_length(JNIEnv* env, jclass, jlong evpCipherRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EVP_CIPHER* evpCipher = reinterpret_cast<const EVP_CIPHER*>(evpCipherRef);
    JNI_TRACE("EVP_CIPHER_iv_length(%p)", evpCipher);

    if (evpCipher == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "evpCipher == null");
        JNI_TRACE("EVP_CIPHER_iv_length => evpCipher == null");
        return 0;
    }

    jint ivLength = static_cast<jint>(EVP_CIPHER_iv_length(evpCipher));
    JNI_TRACE("EVP_CIPHER_iv_length(%p) => %d", evpCipher, ivLength);
    return ivLength;
}

static jlong NativeCrypto_EVP_CIPHER_CTX_new(JNIEnv* env, jclass) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("EVP_CIPHER_CTX_new()");

    bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
    if (ctx.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate cipher context");
        JNI_TRACE("EVP_CipherInit_ex => context allocation error");
        return 0;
    }

    JNI_TRACE("EVP_CIPHER_CTX_new() => %p", ctx.get());
    return reinterpret_cast<uintptr_t>(ctx.release());
}

static jint NativeCrypto_EVP_CIPHER_CTX_block_size(JNIEnv* env, jclass, jobject ctxRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    JNI_TRACE("EVP_CIPHER_CTX_block_size(%p)", ctx);

    if (ctx == nullptr) {
        JNI_TRACE("ctx=%p EVP_CIPHER_CTX_block_size => ctx == null", ctx);
        return 0;
    }

    jint blockSize = static_cast<jint>(EVP_CIPHER_CTX_block_size(ctx));
    JNI_TRACE("EVP_CIPHER_CTX_block_size(%p) => %d", ctx, blockSize);
    return blockSize;
}

static jint NativeCrypto_get_EVP_CIPHER_CTX_buf_len(JNIEnv* env, jclass, jobject ctxRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    JNI_TRACE("get_EVP_CIPHER_CTX_buf_len(%p)", ctx);

    if (ctx == nullptr) {
        JNI_TRACE("ctx=%p get_EVP_CIPHER_CTX_buf_len => ctx == null", ctx);
        return 0;
    }

    int buf_len = ctx->buf_len;
    JNI_TRACE("get_EVP_CIPHER_CTX_buf_len(%p) => %d", ctx, buf_len);
    return buf_len;
}

static jboolean NativeCrypto_get_EVP_CIPHER_CTX_final_used(JNIEnv* env, jclass, jobject ctxRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    JNI_TRACE("get_EVP_CIPHER_CTX_final_used(%p)", ctx);

    if (ctx == nullptr) {
        JNI_TRACE("ctx=%p get_EVP_CIPHER_CTX_final_used => ctx == null", ctx);
        return 0;
    }

    bool final_used = ctx->final_used != 0;
    JNI_TRACE("get_EVP_CIPHER_CTX_final_used(%p) => %d", ctx, final_used);
    return static_cast<jboolean>(final_used);
}

static void NativeCrypto_EVP_CIPHER_CTX_set_padding(JNIEnv* env, jclass, jobject ctxRef,
                                                    jboolean enablePaddingBool) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    jint enablePadding = enablePaddingBool ? 1 : 0;
    JNI_TRACE("EVP_CIPHER_CTX_set_padding(%p, %d)", ctx, enablePadding);

    if (ctx == nullptr) {
        JNI_TRACE("ctx=%p EVP_CIPHER_CTX_set_padding => ctx == null", ctx);
        return;
    }

    EVP_CIPHER_CTX_set_padding(ctx, enablePadding);  // Not void, but always returns 1.
    JNI_TRACE("EVP_CIPHER_CTX_set_padding(%p, %d) => success", ctx, enablePadding);
}

static void NativeCrypto_EVP_CIPHER_CTX_set_key_length(JNIEnv* env, jclass, jobject ctxRef,
                                                       jint keySizeBits) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_CIPHER_CTX* ctx = fromContextObject<EVP_CIPHER_CTX>(env, ctxRef);
    JNI_TRACE("EVP_CIPHER_CTX_set_key_length(%p, %d)", ctx, keySizeBits);

    if (ctx == nullptr) {
        JNI_TRACE("ctx=%p EVP_CIPHER_CTX_set_key_length => ctx == null", ctx);
        return;
    }

    if (!EVP_CIPHER_CTX_set_key_length(ctx, static_cast<unsigned int>(keySizeBits))) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(
                env, "NativeCrypto_EVP_CIPHER_CTX_set_key_length");
        JNI_TRACE("NativeCrypto_EVP_CIPHER_CTX_set_key_length => threw error");
        return;
    }
    JNI_TRACE("EVP_CIPHER_CTX_set_key_length(%p, %d) => success", ctx, keySizeBits);
}

static void NativeCrypto_EVP_CIPHER_CTX_free(JNIEnv* env, jclass, jlong ctxRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    EVP_CIPHER_CTX* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctxRef);
    JNI_TRACE("EVP_CIPHER_CTX_free(%p)", ctx);

    EVP_CIPHER_CTX_free(ctx);
}

static jlong NativeCrypto_EVP_aead_aes_128_gcm(JNIEnv* env, jclass) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EVP_AEAD* ctx = EVP_aead_aes_128_gcm();
    JNI_TRACE("EVP_aead_aes_128_gcm => ctx=%p", ctx);
    return reinterpret_cast<jlong>(ctx);
}

static jlong NativeCrypto_EVP_aead_aes_256_gcm(JNIEnv* env, jclass) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EVP_AEAD* ctx = EVP_aead_aes_256_gcm();
    JNI_TRACE("EVP_aead_aes_256_gcm => ctx=%p", ctx);
    return reinterpret_cast<jlong>(ctx);
}

static jlong NativeCrypto_EVP_aead_chacha20_poly1305(JNIEnv* env, jclass) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EVP_AEAD* ctx = EVP_aead_chacha20_poly1305();
    JNI_TRACE("EVP_aead_chacha20_poly1305 => ctx=%p", ctx);
    return reinterpret_cast<jlong>(ctx);
}

static jlong NativeCrypto_EVP_aead_aes_128_gcm_siv(JNIEnv* env, jclass) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EVP_AEAD* ctx = EVP_aead_aes_128_gcm_siv();
    JNI_TRACE("EVP_aead_aes_128_gcm_siv => ctx=%p", ctx);
    return reinterpret_cast<jlong>(ctx);
}

static jlong NativeCrypto_EVP_aead_aes_256_gcm_siv(JNIEnv* env, jclass) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EVP_AEAD* ctx = EVP_aead_aes_256_gcm_siv();
    JNI_TRACE("EVP_aead_aes_256_gcm_siv => ctx=%p", ctx);
    return reinterpret_cast<jlong>(ctx);
}

static jint NativeCrypto_EVP_AEAD_max_overhead(JNIEnv* env, jclass, jlong evpAeadRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EVP_AEAD* evpAead = reinterpret_cast<const EVP_AEAD*>(evpAeadRef);
    JNI_TRACE("EVP_AEAD_max_overhead(%p)", evpAead);
    if (evpAead == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "evpAead == null");
        return 0;
    }
    jint maxOverhead = static_cast<jint>(EVP_AEAD_max_overhead(evpAead));
    JNI_TRACE("EVP_AEAD_max_overhead(%p) => %d", evpAead, maxOverhead);
    return maxOverhead;
}

static jint NativeCrypto_EVP_AEAD_nonce_length(JNIEnv* env, jclass, jlong evpAeadRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const EVP_AEAD* evpAead = reinterpret_cast<const EVP_AEAD*>(evpAeadRef);
    JNI_TRACE("EVP_AEAD_nonce_length(%p)", evpAead);
    if (evpAead == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "evpAead == null");
        return 0;
    }
    jint nonceLength = static_cast<jint>(EVP_AEAD_nonce_length(evpAead));
    JNI_TRACE("EVP_AEAD_nonce_length(%p) => %d", evpAead, nonceLength);
    return nonceLength;
}

typedef int (*evp_aead_ctx_op_func)(const EVP_AEAD_CTX* ctx, uint8_t* out, size_t* out_len,
                                    size_t max_out_len, const uint8_t* nonce, size_t nonce_len,
                                    const uint8_t* in, size_t in_len, const uint8_t* ad,
                                    size_t ad_len);

static jint evp_aead_ctx_op(JNIEnv* env, jlong evpAeadRef, jbyteArray keyArray, jint tagLen,
                            jbyteArray outArray, jint outOffset, jbyteArray nonceArray,
                            jbyteArray inArray, jint inOffset, jint inLength, jbyteArray aadArray,
                            evp_aead_ctx_op_func realFunc) {
    const EVP_AEAD* evpAead = reinterpret_cast<const EVP_AEAD*>(evpAeadRef);
    JNI_TRACE("evp_aead_ctx_op(%p, %p, %d, %p, %d, %p, %p, %d, %d, %p)", evpAead, keyArray, tagLen,
              outArray, outOffset, nonceArray, inArray, inOffset, inLength, aadArray);

    ScopedByteArrayRO keyBytes(env, keyArray);
    if (keyBytes.get() == nullptr) {
        return 0;
    }

    ScopedByteArrayRW outBytes(env, outArray);
    if (outBytes.get() == nullptr) {
        return 0;
    }

    if (ARRAY_OFFSET_INVALID(outBytes, outOffset)) {
        JNI_TRACE("evp_aead_ctx_op(%p, %p, %d, %p, %d, %p, %p, %d, %d, %p) => out offset invalid",
                  evpAead, keyArray, tagLen, outArray, outOffset, nonceArray, inArray, inOffset,
                  inLength, aadArray);
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException", "out");
        return 0;
    }

    ScopedByteArrayRO inBytes(env, inArray);
    if (inBytes.get() == nullptr) {
        return 0;
    }

    if (ARRAY_OFFSET_LENGTH_INVALID(inBytes, inOffset, inLength)) {
        JNI_TRACE(
                "evp_aead_ctx_op(%p, %p, %d, %p, %d, %p, %p, %d, %d, %p) => in offset/length "
                "invalid",
                evpAead, keyArray, tagLen, outArray, outOffset, nonceArray, inArray, inOffset,
                inLength, aadArray);
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException", "in");
        return 0;
    }

    std::unique_ptr<ScopedByteArrayRO> aad;
    const uint8_t* aad_chars = nullptr;
    size_t aad_chars_size = 0;
    if (aadArray != nullptr) {
        aad.reset(new ScopedByteArrayRO(env, aadArray));
        aad_chars = reinterpret_cast<const uint8_t*>(aad->get());
        if (aad_chars == nullptr) {
            return 0;
        }
        aad_chars_size = aad->size();
    }

    ScopedByteArrayRO nonceBytes(env, nonceArray);
    if (nonceBytes.get() == nullptr) {
        return 0;
    }

    bssl::ScopedEVP_AEAD_CTX aeadCtx;
    const uint8_t* keyTmp = reinterpret_cast<const uint8_t*>(keyBytes.get());
    if (!EVP_AEAD_CTX_init(aeadCtx.get(), evpAead, keyTmp, keyBytes.size(),
                           static_cast<size_t>(tagLen), nullptr)) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env,
                                                             "failure initializing AEAD context");
        JNI_TRACE(
                "evp_aead_ctx_op(%p, %p, %d, %p, %d, %p, %p, %d, %d, %p) => fail EVP_AEAD_CTX_init",
                evpAead, keyArray, tagLen, outArray, outOffset, nonceArray, inArray, inOffset,
                inLength, aadArray);
        return 0;
    }

    uint8_t* outTmp = reinterpret_cast<uint8_t*>(outBytes.get());
    const uint8_t* inTmp = reinterpret_cast<const uint8_t*>(inBytes.get());
    const uint8_t* nonceTmp = reinterpret_cast<const uint8_t*>(nonceBytes.get());
    size_t actualOutLength;
    if (!realFunc(aeadCtx.get(), outTmp + outOffset, &actualOutLength, outBytes.size() - outOffset,
                  nonceTmp, nonceBytes.size(), inTmp + inOffset, static_cast<size_t>(inLength),
                  aad_chars, aad_chars_size)) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "evp_aead_ctx_op");
        return 0;
    }

    JNI_TRACE("evp_aead_ctx_op(%p, %p, %d, %p, %d, %p, %p, %d, %d, %p) => success outlength=%zd",
              evpAead, keyArray, tagLen, outArray, outOffset, nonceArray, inArray, inOffset,
              inLength, aadArray, actualOutLength);
    return static_cast<jint>(actualOutLength);
}

static jint NativeCrypto_EVP_AEAD_CTX_seal(JNIEnv* env, jclass, jlong evpAeadRef,
                                           jbyteArray keyArray, jint tagLen, jbyteArray outArray,
                                           jint outOffset, jbyteArray nonceArray,
                                           jbyteArray inArray, jint inOffset, jint inLength,
                                           jbyteArray aadArray) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return evp_aead_ctx_op(env, evpAeadRef, keyArray, tagLen, outArray, outOffset, nonceArray,
                           inArray, inOffset, inLength, aadArray, EVP_AEAD_CTX_seal);
}

static jint NativeCrypto_EVP_AEAD_CTX_open(JNIEnv* env, jclass, jlong evpAeadRef,
                                           jbyteArray keyArray, jint tagLen, jbyteArray outArray,
                                           jint outOffset, jbyteArray nonceArray,
                                           jbyteArray inArray, jint inOffset, jint inLength,
                                           jbyteArray aadArray) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return evp_aead_ctx_op(env, evpAeadRef, keyArray, tagLen, outArray, outOffset, nonceArray,
                           inArray, inOffset, inLength, aadArray, EVP_AEAD_CTX_open);
}

static jlong NativeCrypto_HMAC_CTX_new(JNIEnv* env, jclass) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("HMAC_CTX_new");
    auto hmacCtx = new HMAC_CTX;
    if (hmacCtx == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate HMAC_CTX");
        return 0;
    }

    HMAC_CTX_init(hmacCtx);
    return reinterpret_cast<jlong>(hmacCtx);
}

static void NativeCrypto_HMAC_CTX_free(JNIEnv* env, jclass, jlong hmacCtxRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    HMAC_CTX* hmacCtx = reinterpret_cast<HMAC_CTX*>(hmacCtxRef);
    JNI_TRACE("HMAC_CTX_free(%p)", hmacCtx);
    if (hmacCtx == nullptr) {
        return;
    }
    HMAC_CTX_cleanup(hmacCtx);
    delete hmacCtx;
}

static void NativeCrypto_HMAC_Init_ex(JNIEnv* env, jclass, jobject hmacCtxRef, jbyteArray keyArray,
                                      jobject evpMdRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    HMAC_CTX* hmacCtx = fromContextObject<HMAC_CTX>(env, hmacCtxRef);
    const EVP_MD* md = reinterpret_cast<const EVP_MD*>(evpMdRef);
    JNI_TRACE("HMAC_Init_ex(%p, %p, %p)", hmacCtx, keyArray, md);
    if (hmacCtx == nullptr) {
        return;
    }
    ScopedByteArrayRO keyBytes(env, keyArray);
    if (keyBytes.get() == nullptr) {
        return;
    }

    const uint8_t* keyPtr = reinterpret_cast<const uint8_t*>(keyBytes.get());
    if (!HMAC_Init_ex(hmacCtx, keyPtr, keyBytes.size(), md, nullptr)) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "HMAC_Init_ex");
        JNI_TRACE("HMAC_Init_ex(%p, %p, %p) => fail HMAC_Init_ex", hmacCtx, keyArray, md);
        return;
    }
}

static void NativeCrypto_HMAC_UpdateDirect(JNIEnv* env, jclass, jobject hmacCtxRef, jlong inPtr,
                                           int inLength) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    HMAC_CTX* hmacCtx = fromContextObject<HMAC_CTX>(env, hmacCtxRef);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(inPtr);
    JNI_TRACE("HMAC_UpdateDirect(%p, %p, %d)", hmacCtx, p, inLength);

    if (hmacCtx == nullptr) {
        return;
    }

    if (p == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, nullptr);
        return;
    }

    if (!HMAC_Update(hmacCtx, p, static_cast<size_t>(inLength))) {
        JNI_TRACE("HMAC_UpdateDirect(%p, %p, %d) => threw exception", hmacCtx, p, inLength);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "HMAC_UpdateDirect");
        return;
    }
}

static void NativeCrypto_HMAC_Update(JNIEnv* env, jclass, jobject hmacCtxRef, jbyteArray inArray,
                                     jint inOffset, int inLength) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    HMAC_CTX* hmacCtx = fromContextObject<HMAC_CTX>(env, hmacCtxRef);
    JNI_TRACE("HMAC_Update(%p, %p, %d, %d)", hmacCtx, inArray, inOffset, inLength);

    if (hmacCtx == nullptr) {
        return;
    }

    ScopedByteArrayRO inBytes(env, inArray);
    if (inBytes.get() == nullptr) {
        return;
    }

    if (ARRAY_OFFSET_LENGTH_INVALID(inBytes, inOffset, inLength)) {
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
                                           "inBytes");
        return;
    }

    const uint8_t* inPtr = reinterpret_cast<const uint8_t*>(inBytes.get());
    if (!HMAC_Update(hmacCtx, inPtr + inOffset, static_cast<size_t>(inLength))) {
        JNI_TRACE("HMAC_Update(%p, %p, %d, %d) => threw exception", hmacCtx, inArray, inOffset,
                  inLength);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "HMAC_Update");
        return;
    }
}

static jbyteArray NativeCrypto_HMAC_Final(JNIEnv* env, jclass, jobject hmacCtxRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    HMAC_CTX* hmacCtx = fromContextObject<HMAC_CTX>(env, hmacCtxRef);
    JNI_TRACE("HMAC_Final(%p)", hmacCtx);

    if (hmacCtx == nullptr) {
        return nullptr;
    }

    uint8_t result[EVP_MAX_MD_SIZE];
    unsigned len;
    if (!HMAC_Final(hmacCtx, result, &len)) {
        JNI_TRACE("HMAC_Final(%p) => threw exception", hmacCtx);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "HMAC_Final");
        return nullptr;
    }

    ScopedLocalRef<jbyteArray> resultArray(env, env->NewByteArray(static_cast<jsize>(len)));
    if (resultArray.get() == nullptr) {
        return nullptr;
    }
    ScopedByteArrayRW resultBytes(env, resultArray.get());
    if (resultBytes.get() == nullptr) {
        return nullptr;
    }
    memcpy(resultBytes.get(), result, len);
    return resultArray.release();
}

static void NativeCrypto_RAND_bytes(JNIEnv* env, jclass, jbyteArray output) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("NativeCrypto_RAND_bytes(%p)", output);

    ScopedByteArrayRW outputBytes(env, output);
    if (outputBytes.get() == nullptr) {
        return;
    }

    unsigned char* tmp = reinterpret_cast<unsigned char*>(outputBytes.get());
    if (RAND_bytes(tmp, outputBytes.size()) <= 0) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "NativeCrypto_RAND_bytes");
        JNI_TRACE("tmp=%p NativeCrypto_RAND_bytes => threw error", tmp);
        return;
    }

    JNI_TRACE("NativeCrypto_RAND_bytes(%p) => success", output);
}

static jstring ASN1_OBJECT_to_OID_string(JNIEnv* env, const ASN1_OBJECT* obj) {
    /*
     * The OBJ_obj2txt API doesn't "measure" if you pass in nullptr as the buffer.
     * Just make a buffer that's large enough here. The documentation recommends
     * 80 characters.
     */
    char output[128];
    int ret = OBJ_obj2txt(output, sizeof(output), obj, 1);
    if (ret < 0) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "ASN1_OBJECT_to_OID_string");
        return nullptr;
    } else if (size_t(ret) >= sizeof(output)) {
        conscrypt::jniutil::throwRuntimeException(env,
                                                  "ASN1_OBJECT_to_OID_string buffer too small");
        return nullptr;
    }

    JNI_TRACE("ASN1_OBJECT_to_OID_string(%p) => %s", obj, output);
    return env->NewStringUTF(output);
}

static jlong NativeCrypto_create_BIO_InputStream(JNIEnv* env, jclass, jobject streamObj,
                                                 jboolean isFinite) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("create_BIO_InputStream(%p)", streamObj);

    if (streamObj == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "stream == null");
        return 0;
    }

    bssl::UniquePtr<BIO> bio(BIO_new(&stream_bio_method));
    if (bio.get() == nullptr) {
        return 0;
    }

    bio_stream_assign(bio.get(), new BioInputStream(streamObj, isFinite == JNI_TRUE));

    JNI_TRACE("create_BIO_InputStream(%p) => %p", streamObj, bio.get());
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(bio.release()));
}

static jlong NativeCrypto_create_BIO_OutputStream(JNIEnv* env, jclass, jobject streamObj) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("create_BIO_OutputStream(%p)", streamObj);

    if (streamObj == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "stream == null");
        return 0;
    }

    bssl::UniquePtr<BIO> bio(BIO_new(&stream_bio_method));
    if (bio.get() == nullptr) {
        return 0;
    }

    bio_stream_assign(bio.get(), new BioOutputStream(streamObj));

    JNI_TRACE("create_BIO_OutputStream(%p) => %p", streamObj, bio.get());
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(bio.release()));
}

static void NativeCrypto_BIO_free_all(JNIEnv* env, jclass, jlong bioRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("BIO_free_all(%p)", bio);

    if (bio == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "bio == null");
        return;
    }

    BIO_free_all(bio);
}

// NOLINTNEXTLINE(runtime/int)
static jstring X509_NAME_to_jstring(JNIEnv* env, X509_NAME* name, unsigned long flags) {
    JNI_TRACE("X509_NAME_to_jstring(%p)", name);

    bssl::UniquePtr<BIO> buffer(BIO_new(BIO_s_mem()));
    if (buffer.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate BIO");
        JNI_TRACE("X509_NAME_to_jstring(%p) => threw error", name);
        return nullptr;
    }

    /* Don't interpret the string. */
    flags &= ~(ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_ESC_MSB);

    /* Write in given format and null terminate. */
    X509_NAME_print_ex(buffer.get(), name, 0, flags);
    BIO_write(buffer.get(), "\0", 1);

    char* tmp;
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
            // This must not be a T61String and must not contain NULs.
            const char* data = reinterpret_cast<const char*>(ASN1_STRING_data(gen->d.ia5));
            ssize_t len = ASN1_STRING_length(gen->d.ia5);
            if ((len == static_cast<ssize_t>(strlen(data))) &&
                (ASN1_PRINTABLE_type(ASN1_STRING_data(gen->d.ia5), len) != V_ASN1_T61STRING)) {
                JNI_TRACE("GENERAL_NAME_to_jobject(%p) => Email/DNS/URI \"%s\"", gen, data);
                return env->NewStringUTF(data);
            } else {
                JNI_TRACE("GENERAL_NAME_to_jobject(%p) => Email/DNS/URI invalid", gen);
                return nullptr;
            }
        }
        case GEN_DIRNAME:
            /* Write in RFC 2253 format */
            return X509_NAME_to_jstring(env, gen->d.directoryName, XN_FLAG_RFC2253);
        case GEN_IPADD: {
#ifdef _WIN32
            void* ip = reinterpret_cast<void*>(gen->d.ip->data);
#else
            const void* ip = reinterpret_cast<const void*>(gen->d.ip->data);
#endif
            if (gen->d.ip->length == 4) {
                // IPv4
                std::unique_ptr<char[]> buffer(new char[INET_ADDRSTRLEN]);
                if (inet_ntop(AF_INET, ip, buffer.get(), INET_ADDRSTRLEN) != nullptr) {
                    JNI_TRACE("GENERAL_NAME_to_jobject(%p) => IPv4 %s", gen, buffer.get());
                    return env->NewStringUTF(buffer.get());
                } else {
                    JNI_TRACE("GENERAL_NAME_to_jobject(%p) => IPv4 failed %s", gen,
                              strerror(errno));
                }
            } else if (gen->d.ip->length == 16) {
                // IPv6
                std::unique_ptr<char[]> buffer(new char[INET6_ADDRSTRLEN]);
                if (inet_ntop(AF_INET6, ip, buffer.get(), INET6_ADDRSTRLEN) != nullptr) {
                    JNI_TRACE("GENERAL_NAME_to_jobject(%p) => IPv6 %s", gen, buffer.get());
                    return env->NewStringUTF(buffer.get());
                } else {
                    JNI_TRACE("GENERAL_NAME_to_jobject(%p) => IPv6 failed %s", gen,
                              strerror(errno));
                }
            }

            /* Invalid IP encodings are pruned out without throwing an exception. */
            return nullptr;
        }
        case GEN_RID:
            return ASN1_OBJECT_to_OID_string(env, gen->d.registeredID);
        case GEN_OTHERNAME:
        case GEN_X400:
        default:
            return ASN1ToByteArray<GENERAL_NAME>(env, gen, i2d_GENERAL_NAME);
    }

    return nullptr;
}

#define GN_STACK_SUBJECT_ALT_NAME 1
#define GN_STACK_ISSUER_ALT_NAME 2

static jobjectArray NativeCrypto_get_X509_GENERAL_NAME_stack(JNIEnv* env, jclass, jlong x509Ref,
                                                             CONSCRYPT_UNUSED jobject holder,
                                                             jint type) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d)", x509, type);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) => x509 == null", x509, type);
        return nullptr;
    }

    X509_check_ca(x509);

    STACK_OF(GENERAL_NAME) * gn_stack;
    bssl::UniquePtr<STACK_OF(GENERAL_NAME)> stackHolder;
    if (type == GN_STACK_SUBJECT_ALT_NAME) {
        gn_stack = x509->altname;
    } else if (type == GN_STACK_ISSUER_ALT_NAME) {
        stackHolder.reset(static_cast<STACK_OF(GENERAL_NAME)*>(
                X509_get_ext_d2i(x509, NID_issuer_alt_name, nullptr, nullptr)));
        gn_stack = stackHolder.get();
    } else {
        JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) => unknown type", x509, type);
        return nullptr;
    }

    int count = static_cast<int>(sk_GENERAL_NAME_num(gn_stack));
    if (count <= 0) {
        JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) => null (no entries)", x509, type);
        return nullptr;
    }

    /*
     * Keep track of how many originally so we can ignore any invalid
     * values later.
     */
    const int origCount = count;

    ScopedLocalRef<jobjectArray> joa(
            env, env->NewObjectArray(count, conscrypt::jniutil::objectArrayClass, nullptr));
    for (int i = 0, j = 0; i < origCount; i++, j++) {
        GENERAL_NAME* gen = sk_GENERAL_NAME_value(gn_stack, static_cast<size_t>(i));
        ScopedLocalRef<jobject> val(env, GENERAL_NAME_to_jobject(env, gen));
        if (env->ExceptionCheck()) {
            JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) => threw exception parsing gen name",
                      x509, type);
            return nullptr;
        }

        /*
         * If it's nullptr, we'll have to skip this, reduce the number of total
         * entries, and fix up the array later.
         */
        if (val.get() == nullptr) {
            j--;
            count--;
            continue;
        }

        ScopedLocalRef<jobjectArray> item(
                env, env->NewObjectArray(2, conscrypt::jniutil::objectClass, nullptr));

        ScopedLocalRef<jobject> parsedType(
                env,
                env->CallStaticObjectMethod(conscrypt::jniutil::integerClass,
                                            conscrypt::jniutil::integer_valueOfMethod, gen->type));
        env->SetObjectArrayElement(item.get(), 0, parsedType.get());
        env->SetObjectArrayElement(item.get(), 1, val.get());

        env->SetObjectArrayElement(joa.get(), j, item.get());
    }

    if (count == 0) {
        JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) shrunk from %d to 0; returning nullptr",
                  x509, type, origCount);
        joa.reset(nullptr);
    } else if (origCount != count) {
        JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) shrunk from %d to %d", x509, type, origCount,
                  count);

        ScopedLocalRef<jobjectArray> joa_copy(
                env, env->NewObjectArray(count, conscrypt::jniutil::objectArrayClass, nullptr));

        for (int i = 0; i < count; i++) {
            ScopedLocalRef<jobject> item(env, env->GetObjectArrayElement(joa.get(), i));
            env->SetObjectArrayElement(joa_copy.get(), i, item.get());
        }

        joa.reset(joa_copy.release());
    }

    JNI_TRACE("get_X509_GENERAL_NAME_stack(%p, %d) => %d entries", x509, type, count);
    return joa.release();
}

static jlong NativeCrypto_X509_get_notBefore(JNIEnv* env, jclass, jlong x509Ref,
                                             CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_notBefore(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_get_notBefore(%p) => x509 == null", x509);
        return 0;
    }

    ASN1_TIME* notBefore = X509_get_notBefore(x509);
    JNI_TRACE("X509_get_notBefore(%p) => %p", x509, notBefore);
    return reinterpret_cast<uintptr_t>(notBefore);
}

static jlong NativeCrypto_X509_get_notAfter(JNIEnv* env, jclass, jlong x509Ref,
                                            CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_notAfter(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_get_notAfter(%p) => x509 == null", x509);
        return 0;
    }

    ASN1_TIME* notAfter = X509_get_notAfter(x509);
    JNI_TRACE("X509_get_notAfter(%p) => %p", x509, notAfter);
    return reinterpret_cast<uintptr_t>(notAfter);
}

// NOLINTNEXTLINE(runtime/int)
static long NativeCrypto_X509_get_version(JNIEnv* env, jclass, jlong x509Ref,
                                          CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_version(%p)", x509);

    // NOLINTNEXTLINE(runtime/int)
    long version = X509_get_version(x509);
    JNI_TRACE("X509_get_version(%p) => %ld", x509, version);
    return version;
}

template <typename T>
static jbyteArray get_X509Type_serialNumber(JNIEnv* env, T* x509Type,
                                            ASN1_INTEGER* (*get_serial_func)(T*)) {
    JNI_TRACE("get_X509Type_serialNumber(%p)", x509Type);

    if (x509Type == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509Type == null");
        JNI_TRACE("get_X509Type_serialNumber(%p) => x509Type == null", x509Type);
        return nullptr;
    }

    ASN1_INTEGER* serialNumber = get_serial_func(x509Type);
    bssl::UniquePtr<BIGNUM> serialBn(ASN1_INTEGER_to_BN(serialNumber, nullptr));
    if (serialBn.get() == nullptr) {
        JNI_TRACE("X509_get_serialNumber(%p) => threw exception", x509Type);
        return nullptr;
    }

    ScopedLocalRef<jbyteArray> serialArray(env, bignumToArray(env, serialBn.get(), "serialBn"));
    if (env->ExceptionCheck()) {
        JNI_TRACE("X509_get_serialNumber(%p) => threw exception", x509Type);
        return nullptr;
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

static jbyteArray NativeCrypto_X509_get_serialNumber(JNIEnv* env, jclass, jlong x509Ref,
                                                     CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_serialNumber(%p)", x509);
    return get_X509Type_serialNumber<X509>(env, x509, X509_get_serialNumber);
}

static jbyteArray NativeCrypto_X509_REVOKED_get_serialNumber(JNIEnv* env, jclass,
                                                             jlong x509RevokedRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_REVOKED* revoked = reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("X509_REVOKED_get_serialNumber(%p)", revoked);
    return get_X509Type_serialNumber<X509_REVOKED>(env, revoked, X509_REVOKED_get_serialNumber);
}

static void NativeCrypto_X509_verify(JNIEnv* env, jclass, jlong x509Ref,
                                     CONSCRYPT_UNUSED jobject holder, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("X509_verify(%p, %p)", x509, pkey);

    if (pkey == nullptr) {
        JNI_TRACE("X509_verify(%p, %p) => pkey == null", x509, pkey);
        return;
    }

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_verify(%p, %p) => x509 == null", x509, pkey);
        return;
    }

    if (X509_ALGOR_cmp(x509->sig_alg, X509_CINF_get_signature(X509_get_cert_info(x509)))) {
        conscrypt::jniutil::throwCertificateException(env,
                "Certificate signature algorithms do not match");
        JNI_TRACE("X509_verify(%p, %p) => signature alg mismatch", x509, pkey);
        return;
    }

    if (X509_verify(x509, pkey) != 1) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(
                env, "X509_verify", conscrypt::jniutil::throwCertificateException);
        JNI_TRACE("X509_verify(%p, %p) => verify failure", x509, pkey);
        return;
    }
    JNI_TRACE("X509_verify(%p, %p) => verify success", x509, pkey);
}

static jbyteArray NativeCrypto_get_X509_cert_info_enc(JNIEnv* env, jclass, jlong x509Ref,
                                                      CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_cert_info_enc(%p)", x509);
    return ASN1ToByteArray<X509_CINF>(env, x509->cert_info, i2d_X509_CINF);
}

static jint NativeCrypto_get_X509_ex_flags(JNIEnv* env, jclass, jlong x509Ref,
                                           CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_ex_flags(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_ex_flags(%p) => x509 == null", x509);
        return 0;
    }

    X509_check_ca(x509);

    return static_cast<jint>(x509->ex_flags);
}

static jboolean NativeCrypto_X509_check_issued(JNIEnv* env, jclass, jlong x509Ref1,
                                               CONSCRYPT_UNUSED jobject holder, jlong x509Ref2,
                                               CONSCRYPT_UNUSED jobject holder2) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509_1 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref1));
    X509* x509_2 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref2));
    JNI_TRACE("X509_check_issued(%p, %p)", x509_1, x509_2);

    int ret = X509_check_issued(x509_1, x509_2);
    JNI_TRACE("X509_check_issued(%p, %p) => %d", x509_1, x509_2, ret);
    return static_cast<jboolean>(ret);
}

static void get_X509_signature(X509* x509, ASN1_BIT_STRING** signature) {
    *signature = x509->signature;
}

static void get_X509_CRL_signature(X509_CRL* crl, ASN1_BIT_STRING** signature) {
    *signature = crl->signature;
}

template <typename T>
static jbyteArray get_X509Type_signature(JNIEnv* env, T* x509Type,
                                         void (*get_signature_func)(T*, ASN1_BIT_STRING**)) {
    JNI_TRACE("get_X509Type_signature(%p)", x509Type);

    if (x509Type == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509Type == null");
        JNI_TRACE("get_X509Type_signature(%p) => x509Type == null", x509Type);
        return nullptr;
    }

    ASN1_BIT_STRING* signature;
    get_signature_func(x509Type, &signature);

    ScopedLocalRef<jbyteArray> signatureArray(env, env->NewByteArray(signature->length));
    if (env->ExceptionCheck()) {
        JNI_TRACE("get_X509Type_signature(%p) => threw exception", x509Type);
        return nullptr;
    }

    ScopedByteArrayRW signatureBytes(env, signatureArray.get());
    if (signatureBytes.get() == nullptr) {
        JNI_TRACE("get_X509Type_signature(%p) => using byte array failed", x509Type);
        return nullptr;
    }

    memcpy(signatureBytes.get(), signature->data, signature->length);

    JNI_TRACE("get_X509Type_signature(%p) => %p (%d bytes)", x509Type, signatureArray.get(),
              signature->length);
    return signatureArray.release();
}

static jbyteArray NativeCrypto_get_X509_signature(JNIEnv* env, jclass, jlong x509Ref,
                                                  CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_signature(%p)", x509);
    return get_X509Type_signature<X509>(env, x509, get_X509_signature);
}

static jbyteArray NativeCrypto_get_X509_CRL_signature(JNIEnv* env, jclass, jlong x509CrlRef,
                                                      CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("get_X509_CRL_signature(%p)", crl);
    return get_X509Type_signature<X509_CRL>(env, crl, get_X509_CRL_signature);
}

static jlong NativeCrypto_X509_CRL_get0_by_cert(JNIEnv* env, jclass, jlong x509crlRef,
                                                CONSCRYPT_UNUSED jobject holder, jlong x509Ref,
                                                CONSCRYPT_UNUSED jobject holder2) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* x509crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509crlRef));
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_CRL_get0_by_cert(%p, %p)", x509crl, x509);

    if (x509crl == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509crl == null");
        JNI_TRACE("X509_CRL_get0_by_cert(%p, %p) => x509crl == null", x509crl, x509);
        return 0;
    } else if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_CRL_get0_by_cert(%p, %p) => x509 == null", x509crl, x509);
        return 0;
    }

    X509_REVOKED* revoked = nullptr;
    int ret = X509_CRL_get0_by_cert(x509crl, &revoked, x509);
    if (ret == 0) {
        JNI_TRACE("X509_CRL_get0_by_cert(%p, %p) => none", x509crl, x509);
        return 0;
    }

    JNI_TRACE("X509_CRL_get0_by_cert(%p, %p) => %p", x509crl, x509, revoked);
    return reinterpret_cast<uintptr_t>(revoked);
}

static jlong NativeCrypto_X509_CRL_get0_by_serial(JNIEnv* env, jclass, jlong x509crlRef,
                                                  CONSCRYPT_UNUSED jobject holder,
                                                  jbyteArray serialArray) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* x509crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509crlRef));
    JNI_TRACE("X509_CRL_get0_by_serial(%p, %p)", x509crl, serialArray);

    if (x509crl == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509crl == null");
        JNI_TRACE("X509_CRL_get0_by_serial(%p, %p) => crl == null", x509crl, serialArray);
        return 0;
    }

    bssl::UniquePtr<BIGNUM> serialBn(BN_new());
    if (serialBn.get() == nullptr) {
        JNI_TRACE("X509_CRL_get0_by_serial(%p, %p) => BN allocation failed", x509crl, serialArray);
        return 0;
    }

    BIGNUM* serialBare = serialBn.get();
    if (!arrayToBignum(env, serialArray, &serialBare)) {
        if (!env->ExceptionCheck()) {
            conscrypt::jniutil::throwNullPointerException(env, "serial == null");
        }
        JNI_TRACE("X509_CRL_get0_by_serial(%p, %p) => BN conversion failed", x509crl, serialArray);
        return 0;
    }

    bssl::UniquePtr<ASN1_INTEGER> serialInteger(BN_to_ASN1_INTEGER(serialBn.get(), nullptr));
    if (serialInteger.get() == nullptr) {
        JNI_TRACE("X509_CRL_get0_by_serial(%p, %p) => BN conversion failed", x509crl, serialArray);
        return 0;
    }

    X509_REVOKED* revoked = nullptr;
    int ret = X509_CRL_get0_by_serial(x509crl, &revoked, serialInteger.get());
    if (ret == 0) {
        JNI_TRACE("X509_CRL_get0_by_serial(%p, %p) => none", x509crl, serialArray);
        return 0;
    }

    JNI_TRACE("X509_CRL_get0_by_cert(%p, %p) => %p", x509crl, serialArray, revoked);
    return reinterpret_cast<uintptr_t>(revoked);
}

static jlongArray NativeCrypto_X509_CRL_get_REVOKED(JNIEnv* env, jclass, jlong x509CrlRef,
                                                    CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_REVOKED(%p)", crl);

    if (crl == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "crl == null");
        return nullptr;
    }

    STACK_OF(X509_REVOKED)* stack = X509_CRL_get_REVOKED(crl);
    if (stack == nullptr) {
        JNI_TRACE("X509_CRL_get_REVOKED(%p) => stack is null", crl);
        return nullptr;
    }

    size_t size = sk_X509_REVOKED_num(stack);

    ScopedLocalRef<jlongArray> revokedArray(env, env->NewLongArray(static_cast<jsize>(size)));
    ScopedLongArrayRW revoked(env, revokedArray.get());
    for (size_t i = 0; i < size; i++) {
        X509_REVOKED* item = reinterpret_cast<X509_REVOKED*>(sk_X509_REVOKED_value(stack, i));
        revoked[i] = reinterpret_cast<uintptr_t>(X509_REVOKED_dup(item));
    }

    JNI_TRACE("X509_CRL_get_REVOKED(%p) => %p [size=%zd]", stack, revokedArray.get(), size);
    return revokedArray.release();
}

static jbyteArray NativeCrypto_i2d_X509_CRL(JNIEnv* env, jclass, jlong x509CrlRef,
                                            CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("i2d_X509_CRL(%p)", crl);
    return ASN1ToByteArray<X509_CRL>(env, crl, i2d_X509_CRL);
}

static void NativeCrypto_X509_CRL_free(JNIEnv* env, jclass, jlong x509CrlRef,
                                       CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_free(%p)", crl);

    if (crl == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "crl == null");
        JNI_TRACE("X509_CRL_free(%p) => crl == null", crl);
        return;
    }

    X509_CRL_free(crl);
}

static void NativeCrypto_X509_CRL_print(JNIEnv* env, jclass, jlong bioRef, jlong x509CrlRef,
                                        CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_print(%p, %p)", bio, crl);

    if (bio == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "bio == null");
        JNI_TRACE("X509_CRL_print(%p, %p) => bio == null", bio, crl);
        return;
    }

    if (crl == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "crl == null");
        JNI_TRACE("X509_CRL_print(%p, %p) => crl == null", bio, crl);
        return;
    }

    if (!X509_CRL_print(bio, crl)) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "X509_CRL_print");
        JNI_TRACE("X509_CRL_print(%p, %p) => threw error", bio, crl);
        return;
    }
    JNI_TRACE("X509_CRL_print(%p, %p) => success", bio, crl);
}

static jstring NativeCrypto_get_X509_CRL_sig_alg_oid(JNIEnv* env, jclass, jlong x509CrlRef,
                                                     CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("get_X509_CRL_sig_alg_oid(%p)", crl);

    if (crl == nullptr || crl->sig_alg == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "crl == null || crl->sig_alg == null");
        JNI_TRACE("get_X509_CRL_sig_alg_oid(%p) => crl == null", crl);
        return nullptr;
    }

    return ASN1_OBJECT_to_OID_string(env, crl->sig_alg->algorithm);
}

static jbyteArray NativeCrypto_get_X509_CRL_sig_alg_parameter(JNIEnv* env, jclass, jlong x509CrlRef,
                                                              CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("get_X509_CRL_sig_alg_parameter(%p)", crl);

    if (crl == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "crl == null");
        JNI_TRACE("get_X509_CRL_sig_alg_parameter(%p) => crl == null", crl);
        return nullptr;
    }

    if (crl->sig_alg->parameter == nullptr) {
        JNI_TRACE("get_X509_CRL_sig_alg_parameter(%p) => null", crl);
        return nullptr;
    }

    return ASN1ToByteArray<ASN1_TYPE>(env, crl->sig_alg->parameter, i2d_ASN1_TYPE);
}

static jbyteArray NativeCrypto_X509_CRL_get_issuer_name(JNIEnv* env, jclass, jlong x509CrlRef,
                                                        CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_issuer_name(%p)", crl);
    return ASN1ToByteArray<X509_NAME>(env, X509_CRL_get_issuer(crl), i2d_X509_NAME);
}

// NOLINTNEXTLINE(runtime/int)
static long NativeCrypto_X509_CRL_get_version(JNIEnv* env, jclass, jlong x509CrlRef,
                                              CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_version(%p)", crl);

    // NOLINTNEXTLINE(runtime/int)
    long version = X509_CRL_get_version(crl);
    JNI_TRACE("X509_CRL_get_version(%p) => %ld", crl, version);
    return version;
}

template <typename T, int (*get_ext_by_OBJ_func)(T*, ASN1_OBJECT*, int),
          X509_EXTENSION* (*get_ext_func)(T*, int)>
static X509_EXTENSION* X509Type_get_ext(JNIEnv* env, T* x509Type, jstring oidString) {
    JNI_TRACE("X509Type_get_ext(%p)", x509Type);

    if (x509Type == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        return nullptr;
    }

    ScopedUtfChars oid(env, oidString);
    if (oid.c_str() == nullptr) {
        return nullptr;
    }

    bssl::UniquePtr<ASN1_OBJECT> asn1(OBJ_txt2obj(oid.c_str(), 1));
    if (asn1.get() == nullptr) {
        JNI_TRACE("X509Type_get_ext(%p, %s) => oid conversion failed", x509Type, oid.c_str());
        ERR_clear_error();
        return nullptr;
    }

    int extIndex = get_ext_by_OBJ_func(x509Type, asn1.get(), -1);
    if (extIndex == -1) {
        JNI_TRACE("X509Type_get_ext(%p, %s) => ext not found", x509Type, oid.c_str());
        return nullptr;
    }

    X509_EXTENSION* ext = get_ext_func(x509Type, extIndex);
    JNI_TRACE("X509Type_get_ext(%p, %s) => %p", x509Type, oid.c_str(), ext);
    return ext;
}

template <typename T, int (*get_ext_by_OBJ_func)(T*, ASN1_OBJECT*, int),
          X509_EXTENSION* (*get_ext_func)(T*, int)>
static jbyteArray X509Type_get_ext_oid(JNIEnv* env, T* x509Type, jstring oidString) {
    X509_EXTENSION* ext =
            X509Type_get_ext<T, get_ext_by_OBJ_func, get_ext_func>(env, x509Type, oidString);
    if (ext == nullptr) {
        JNI_TRACE("X509Type_get_ext_oid(%p, %p) => fetching extension failed", x509Type, oidString);
        return nullptr;
    }

    JNI_TRACE("X509Type_get_ext_oid(%p, %p) => %p", x509Type, oidString, ext->value);
    return ASN1ToByteArray<ASN1_OCTET_STRING>(env, ext->value, i2d_ASN1_OCTET_STRING);
}

static jlong NativeCrypto_X509_CRL_get_ext(JNIEnv* env, jclass, jlong x509CrlRef,
                                           CONSCRYPT_UNUSED jobject holder, jstring oid) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_ext(%p, %p)", crl, oid);
    X509_EXTENSION* ext =
            X509Type_get_ext<X509_CRL, X509_CRL_get_ext_by_OBJ, X509_CRL_get_ext>(env, crl, oid);
    JNI_TRACE("X509_CRL_get_ext(%p, %p) => %p", crl, oid, ext);
    return reinterpret_cast<uintptr_t>(ext);
}

static jlong NativeCrypto_X509_REVOKED_get_ext(JNIEnv* env, jclass, jlong x509RevokedRef,
                                               jstring oid) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_REVOKED* revoked = reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("X509_REVOKED_get_ext(%p, %p)", revoked, oid);
    X509_EXTENSION* ext =
            X509Type_get_ext<X509_REVOKED, X509_REVOKED_get_ext_by_OBJ, X509_REVOKED_get_ext>(
                    env, revoked, oid);
    JNI_TRACE("X509_REVOKED_get_ext(%p, %p) => %p", revoked, oid, ext);
    return reinterpret_cast<uintptr_t>(ext);
}

static jlong NativeCrypto_X509_REVOKED_dup(JNIEnv* env, jclass, jlong x509RevokedRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_REVOKED* revoked = reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("X509_REVOKED_dup(%p)", revoked);

    if (revoked == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "revoked == null");
        JNI_TRACE("X509_REVOKED_dup(%p) => revoked == null", revoked);
        return 0;
    }

    X509_REVOKED* dup = X509_REVOKED_dup(revoked);
    JNI_TRACE("X509_REVOKED_dup(%p) => %p", revoked, dup);
    return reinterpret_cast<uintptr_t>(dup);
}

static jlong NativeCrypto_get_X509_REVOKED_revocationDate(JNIEnv* env, jclass,
                                                          jlong x509RevokedRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_REVOKED* revoked = reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("get_X509_REVOKED_revocationDate(%p)", revoked);

    if (revoked == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "revoked == null");
        JNI_TRACE("get_X509_REVOKED_revocationDate(%p) => revoked == null", revoked);
        return 0;
    }

    JNI_TRACE("get_X509_REVOKED_revocationDate(%p) => %p", revoked, revoked->revocationDate);
    return reinterpret_cast<uintptr_t>(revoked->revocationDate);
}

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wwrite-strings"
#endif
static void NativeCrypto_X509_REVOKED_print(JNIEnv* env, jclass, jlong bioRef,
                                            jlong x509RevokedRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    X509_REVOKED* revoked = reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("X509_REVOKED_print(%p, %p)", bio, revoked);

    if (bio == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "bio == null");
        JNI_TRACE("X509_REVOKED_print(%p, %p) => bio == null", bio, revoked);
        return;
    }

    if (revoked == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "revoked == null");
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
#ifndef _WIN32
#pragma GCC diagnostic pop
#endif

static jbyteArray NativeCrypto_get_X509_CRL_crl_enc(JNIEnv* env, jclass, jlong x509CrlRef,
                                                    CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("get_X509_CRL_crl_enc(%p)", crl);
    return ASN1ToByteArray<X509_CRL_INFO>(env, crl->crl, i2d_X509_CRL_INFO);
}

static void NativeCrypto_X509_CRL_verify(JNIEnv* env, jclass, jlong x509CrlRef,
                                         CONSCRYPT_UNUSED jobject holder, jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    JNI_TRACE("X509_CRL_verify(%p, %p)", crl, pkey);

    if (pkey == nullptr) {
        JNI_TRACE("X509_CRL_verify(%p, %p) => pkey == null", crl, pkey);
        return;
    }

    if (crl == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "crl == null");
        JNI_TRACE("X509_CRL_verify(%p, %p) => crl == null", crl, pkey);
        return;
    }

    if (X509_CRL_verify(crl, pkey) != 1) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "X509_CRL_verify");
        JNI_TRACE("X509_CRL_verify(%p, %p) => verify failure", crl, pkey);
        return;
    }
    JNI_TRACE("X509_CRL_verify(%p, %p) => verify success", crl, pkey);
}

static jlong NativeCrypto_X509_CRL_get_lastUpdate(JNIEnv* env, jclass, jlong x509CrlRef,
                                                  CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_lastUpdate(%p)", crl);

    if (crl == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "crl == null");
        JNI_TRACE("X509_CRL_get_lastUpdate(%p) => crl == null", crl);
        return 0;
    }

    ASN1_TIME* lastUpdate = X509_CRL_get_lastUpdate(crl);
    JNI_TRACE("X509_CRL_get_lastUpdate(%p) => %p", crl, lastUpdate);
    return reinterpret_cast<uintptr_t>(lastUpdate);
}

static jlong NativeCrypto_X509_CRL_get_nextUpdate(JNIEnv* env, jclass, jlong x509CrlRef,
                                                  CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_nextUpdate(%p)", crl);

    if (crl == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "crl == null");
        JNI_TRACE("X509_CRL_get_nextUpdate(%p) => crl == null", crl);
        return 0;
    }

    ASN1_TIME* nextUpdate = X509_CRL_get_nextUpdate(crl);
    JNI_TRACE("X509_CRL_get_nextUpdate(%p) => %p", crl, nextUpdate);
    return reinterpret_cast<uintptr_t>(nextUpdate);
}

static jbyteArray NativeCrypto_i2d_X509_REVOKED(JNIEnv* env, jclass, jlong x509RevokedRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_REVOKED* x509Revoked =
            reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("i2d_X509_REVOKED(%p)", x509Revoked);
    return ASN1ToByteArray<X509_REVOKED>(env, x509Revoked, i2d_X509_REVOKED);
}

static jint NativeCrypto_X509_supported_extension(JNIEnv* env, jclass, jlong x509ExtensionRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_EXTENSION* ext =
            reinterpret_cast<X509_EXTENSION*>(static_cast<uintptr_t>(x509ExtensionRef));

    if (ext == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "ext == null");
        return 0;
    }

    return X509_supported_extension(ext);
}

static inline void get_ASN1_TIME_data(char** data, int* output, size_t len) {
    char c = **data;
    **data = '\0';
    *data -= len;
    *output = atoi(*data);
    *(*data + len) = c;
}

static void NativeCrypto_ASN1_TIME_to_Calendar(JNIEnv* env, jclass, jlong asn1TimeRef,
                                               jobject calendar) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    ASN1_TIME* asn1Time = reinterpret_cast<ASN1_TIME*>(static_cast<uintptr_t>(asn1TimeRef));
    JNI_TRACE("ASN1_TIME_to_Calendar(%p, %p)", asn1Time, calendar);

    if (asn1Time == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "asn1Time == null");
        return;
    }

    if (!ASN1_TIME_check(asn1Time)) {
        conscrypt::jniutil::throwParsingException(env, "Invalid date format");
        return;
    }

    bssl::UniquePtr<ASN1_GENERALIZEDTIME> gen(ASN1_TIME_to_generalizedtime(asn1Time, nullptr));
    if (gen.get() == nullptr) {
        conscrypt::jniutil::throwParsingException(env,
                                                  "ASN1_TIME_to_generalizedtime returned null");
        return;
    }

    if (gen->length < 14 || gen->data == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "gen->length < 14 || gen->data == null");
        return;
    }

    int sec, min, hour, mday, mon, year;

    char* p = reinterpret_cast<char*>(&gen->data[14]);

    get_ASN1_TIME_data(&p, &sec, 2);
    get_ASN1_TIME_data(&p, &min, 2);
    get_ASN1_TIME_data(&p, &hour, 2);
    get_ASN1_TIME_data(&p, &mday, 2);
    get_ASN1_TIME_data(&p, &mon, 2);
    get_ASN1_TIME_data(&p, &year, 4);

    env->CallVoidMethod(calendar, conscrypt::jniutil::calendar_setMethod, year, mon - 1, mday, hour,
                        min, sec);
}

// A CbsHandle is a structure used to manage resources allocated by asn1_read-*
// functions so that they can be freed properly when finished.  This struct owns
// all objects pointed to by its members.
struct CbsHandle {
    // A pointer to the CBS.
    std::unique_ptr<CBS> cbs;
    // A pointer to the data held by the CBS.  If the data held by the CBS
    // is owned by a different CbsHandle, data will be null.
    std::unique_ptr<unsigned char[]> data;
};

static jlong NativeCrypto_asn1_read_init(JNIEnv* env, jclass, jbyteArray data) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("asn1_read_init(%p)", data);

    ScopedByteArrayRO bytes(env, data);
    if (bytes.get() == nullptr) {
        conscrypt::jniutil::throwIOException(env, "Error reading ASN.1 encoding");
        return 0;
    }

    std::unique_ptr<CbsHandle> cbs(new CbsHandle());
    cbs->data.reset(new unsigned char[bytes.size()]);
    memcpy(cbs->data.get(), bytes.get(), bytes.size());

    cbs->cbs.reset(new CBS());
    CBS_init(cbs->cbs.get(), cbs->data.get(), bytes.size());
    JNI_TRACE("asn1_read_init(%p) => %p", data, cbs.get());
    return reinterpret_cast<uintptr_t>(cbs.release());
}

static jlong NativeCrypto_asn1_read_sequence(JNIEnv* env, jclass, jlong cbsRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CbsHandle* cbs = reinterpret_cast<CbsHandle*>(static_cast<uintptr_t>(cbsRef));
    JNI_TRACE("asn1_read_sequence(%p)", cbs);

    std::unique_ptr<CbsHandle> seq(new CbsHandle());
    seq->cbs.reset(new CBS());
    if (!CBS_get_asn1(cbs->cbs.get(), seq->cbs.get(), CBS_ASN1_SEQUENCE)) {
        conscrypt::jniutil::throwIOException(env, "Error reading ASN.1 encoding");
        return 0;
    }
    JNI_TRACE("asn1_read_sequence(%p) => %p", cbs, seq.get());
    return reinterpret_cast<uintptr_t>(seq.release());
}

static jboolean NativeCrypto_asn1_read_next_tag_is(CONSCRYPT_UNUSED JNIEnv* env, jclass,
                                                   jlong cbsRef, jint tag) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CbsHandle* cbs = reinterpret_cast<CbsHandle*>(static_cast<uintptr_t>(cbsRef));
    JNI_TRACE("asn1_read_next_tag_is(%p)", cbs);

    int result = CBS_peek_asn1_tag(cbs->cbs.get(),
                                   CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | tag);
    JNI_TRACE("asn1_read_next_tag_is(%p) => %s", cbs, result ? "true" : "false");
    return result ? JNI_TRUE : JNI_FALSE;
}

static jlong NativeCrypto_asn1_read_tagged(JNIEnv* env, jclass, jlong cbsRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CbsHandle* cbs = reinterpret_cast<CbsHandle*>(static_cast<uintptr_t>(cbsRef));
    JNI_TRACE("asn1_read_tagged(%p)", cbs);

    std::unique_ptr<CbsHandle> tag(new CbsHandle());
    tag->cbs.reset(new CBS());
    if (!CBS_get_any_asn1(cbs->cbs.get(), tag->cbs.get(), nullptr)) {
        conscrypt::jniutil::throwIOException(env, "Error reading ASN.1 encoding");
        return 0;
    }
    JNI_TRACE("asn1_read_tagged(%p) => %p", cbs, tag.get());
    return reinterpret_cast<uintptr_t>(tag.release());
}

static jbyteArray NativeCrypto_asn1_read_octetstring(JNIEnv* env, jclass, jlong cbsRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CbsHandle* cbs = reinterpret_cast<CbsHandle*>(static_cast<uintptr_t>(cbsRef));
    JNI_TRACE("asn1_read_octetstring(%p)", cbs);

    std::unique_ptr<CBS> str(new CBS());
    if (!CBS_get_asn1(cbs->cbs.get(), str.get(), CBS_ASN1_OCTETSTRING)) {
        conscrypt::jniutil::throwIOException(env, "Error reading ASN.1 encoding");
        return 0;
    }
    ScopedLocalRef<jbyteArray> out(env, env->NewByteArray(static_cast<jsize>(CBS_len(str.get()))));
    if (out.get() == nullptr) {
        conscrypt::jniutil::throwIOException(env, "Error reading ASN.1 encoding");
        return 0;
    }
    ScopedByteArrayRW outBytes(env, out.get());
    if (outBytes.get() == nullptr) {
        conscrypt::jniutil::throwIOException(env, "Error reading ASN.1 encoding");
        return 0;
    }
    memcpy(outBytes.get(), CBS_data(str.get()), CBS_len(str.get()));
    JNI_TRACE("asn1_read_octetstring(%p) => %p", cbs, out.get());
    return out.release();
}

static jlong NativeCrypto_asn1_read_uint64(JNIEnv* env, jclass, jlong cbsRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CbsHandle* cbs = reinterpret_cast<CbsHandle*>(static_cast<uintptr_t>(cbsRef));
    JNI_TRACE("asn1_read_uint64(%p)", cbs);

    // NOLINTNEXTLINE(runtime/int)
    uint64_t value;
    if (!CBS_get_asn1_uint64(cbs->cbs.get(), &value)) {
        conscrypt::jniutil::throwIOException(env, "Error reading ASN.1 encoding");
        return 0;
    }
    return value;
}

static void NativeCrypto_asn1_read_null(JNIEnv* env, jclass, jlong cbsRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CbsHandle* cbs = reinterpret_cast<CbsHandle*>(static_cast<uintptr_t>(cbsRef));
    JNI_TRACE("asn1_read_null(%p)", cbs);

    CBS null_holder;
    if (!CBS_get_asn1(cbs->cbs.get(), &null_holder, CBS_ASN1_NULL)) {
        conscrypt::jniutil::throwIOException(env, "Error reading ASN.1 encoding");
    }
}

static jstring NativeCrypto_asn1_read_oid(JNIEnv* env, jclass, jlong cbsRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CbsHandle* cbs = reinterpret_cast<CbsHandle*>(static_cast<uintptr_t>(cbsRef));
    JNI_TRACE("asn1_read_oid(%p)", cbs);

    CBS oid_cbs;
    if (!CBS_get_asn1(cbs->cbs.get(), &oid_cbs, CBS_ASN1_OBJECT)) {
        conscrypt::jniutil::throwIOException(env, "Error reading ASN.1 encoding");
        return nullptr;
    }
    int nid = OBJ_cbs2nid(&oid_cbs);
    if (nid == NID_undef) {
        conscrypt::jniutil::throwIOException(env, "Error reading ASN.1 encoding: OID not found");
        return nullptr;
    }
    const ASN1_OBJECT* obj(OBJ_nid2obj(nid));
    if (obj == nullptr) {
        conscrypt::jniutil::throwIOException(env,
                                             "Error reading ASN.1 encoding: "
                                             "Could not find ASN1_OBJECT for NID");
        return nullptr;
    }
    return ASN1_OBJECT_to_OID_string(env, obj);
}

static jboolean NativeCrypto_asn1_read_is_empty(CONSCRYPT_UNUSED JNIEnv* env, jclass,
                                                jlong cbsRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CbsHandle* cbs = reinterpret_cast<CbsHandle*>(static_cast<uintptr_t>(cbsRef));
    JNI_TRACE("asn1_read_is_empty(%p)", cbs);

    bool empty = (CBS_len(cbs->cbs.get()) == 0);
    JNI_TRACE("asn1_read_is_empty(%p) => %s", cbs, empty ? "true" : "false");
    return empty;
}

static void NativeCrypto_asn1_read_free(CONSCRYPT_UNUSED JNIEnv* env, jclass, jlong cbsRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    if (cbsRef == 0) {
        JNI_TRACE("asn1_read_free(0)");
        return;
    }
    CbsHandle* cbs = reinterpret_cast<CbsHandle*>(static_cast<uintptr_t>(cbsRef));
    JNI_TRACE("asn1_read_free(%p)", cbs);
    delete cbs;
}

static jlong NativeCrypto_asn1_write_init(JNIEnv* env, jclass) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("asn1_write_init");
    std::unique_ptr<CBB> cbb(new CBB());
    if (!CBB_init(cbb.get(), 128)) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return 0;
    }
    JNI_TRACE("asn1_write_init => %p", cbb.get());
    return reinterpret_cast<uintptr_t>(cbb.release());
}

static jlong NativeCrypto_asn1_write_sequence(JNIEnv* env, jclass, jlong cbbRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CBB* cbb = reinterpret_cast<CBB*>(static_cast<uintptr_t>(cbbRef));
    JNI_TRACE("asn1_write_sequence(%p)", cbb);

    std::unique_ptr<CBB> seq(new CBB());
    if (!CBB_add_asn1(cbb, seq.get(), CBS_ASN1_SEQUENCE)) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return 0;
    }
    JNI_TRACE("asn1_write_sequence(%p) => %p", cbb, seq.get());
    return reinterpret_cast<uintptr_t>(seq.release());
}

static jlong NativeCrypto_asn1_write_tag(JNIEnv* env, jclass, jlong cbbRef, jint tag) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CBB* cbb = reinterpret_cast<CBB*>(static_cast<uintptr_t>(cbbRef));
    JNI_TRACE("asn1_write_tag(%p)", cbb);

    std::unique_ptr<CBB> tag_holder(new CBB());
    if (!CBB_add_asn1(cbb, tag_holder.get(),
                      CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | tag)) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return 0;
    }
    JNI_TRACE("asn1_write_tag(%p) => %p", cbb, tag_holder.get());
    return reinterpret_cast<uintptr_t>(tag_holder.release());
}

static void NativeCrypto_asn1_write_octetstring(JNIEnv* env, jclass, jlong cbbRef,
                                                jbyteArray data) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CBB* cbb = reinterpret_cast<CBB*>(static_cast<uintptr_t>(cbbRef));
    JNI_TRACE("asn1_write_octetstring(%p, %p)", cbb, data);

    ScopedByteArrayRO bytes(env, data);
    if (bytes.get() == nullptr) {
        JNI_TRACE("asn1_write_octetstring(%p, %p) => using byte array failed", cbb, data);
        return;
    }

    std::unique_ptr<CBB> octetstring(new CBB());
    if (!CBB_add_asn1(cbb, octetstring.get(), CBS_ASN1_OCTETSTRING)) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return;
    }
    if (!CBB_add_bytes(octetstring.get(), reinterpret_cast<const uint8_t*>(bytes.get()),
                       bytes.size())) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return;
    }
    if (!CBB_flush(cbb)) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return;
    }
}

static void NativeCrypto_asn1_write_uint64(JNIEnv* env, jclass, jlong cbbRef, jlong data) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CBB* cbb = reinterpret_cast<CBB*>(static_cast<uintptr_t>(cbbRef));
    JNI_TRACE("asn1_write_uint64(%p)", cbb);

    if (!CBB_add_asn1_uint64(cbb, static_cast<uint64_t>(data))) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return;
    }
}

static void NativeCrypto_asn1_write_null(JNIEnv* env, jclass, jlong cbbRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CBB* cbb = reinterpret_cast<CBB*>(static_cast<uintptr_t>(cbbRef));
    JNI_TRACE("asn1_write_null(%p)", cbb);

    CBB null_holder;
    if (!CBB_add_asn1(cbb, &null_holder, CBS_ASN1_NULL)) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return;
    }
    if (!CBB_flush(cbb)) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return;
    }
}

static void NativeCrypto_asn1_write_oid(JNIEnv* env, jclass, jlong cbbRef, jstring oid) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CBB* cbb = reinterpret_cast<CBB*>(static_cast<uintptr_t>(cbbRef));
    JNI_TRACE("asn1_write_oid(%p)", cbb);

    ScopedUtfChars oid_chars(env, oid);
    if (oid_chars.c_str() == nullptr) {
        return;
    }

    int nid = OBJ_txt2nid(oid_chars.c_str());
    if (nid == NID_undef) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return;
    }

    if (!OBJ_nid2cbb(cbb, nid)) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return;
    }
}

static void NativeCrypto_asn1_write_flush(JNIEnv* env, jclass, jlong cbbRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CBB* cbb = reinterpret_cast<CBB*>(static_cast<uintptr_t>(cbbRef));
    JNI_TRACE("asn1_write_flush(%p)", cbb);

    if (!CBB_flush(cbb)) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return;
    }
}

static jbyteArray NativeCrypto_asn1_write_finish(JNIEnv* env, jclass, jlong cbbRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CBB* cbb = reinterpret_cast<CBB*>(static_cast<uintptr_t>(cbbRef));
    JNI_TRACE("asn1_write_finish(%p)", cbb);

    uint8_t* data;
    size_t data_len;
    if (!CBB_finish(cbb, &data, &data_len)) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return 0;
    }
    bssl::UniquePtr<uint8_t> data_storage(data);
    ScopedLocalRef<jbyteArray> out(env, env->NewByteArray(static_cast<jsize>(data_len)));
    if (out.get() == nullptr) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return 0;
    }
    ScopedByteArrayRW outBytes(env, out.get());
    if (outBytes.get() == nullptr) {
        conscrypt::jniutil::throwIOException(env, "Error writing ASN.1 encoding");
        return 0;
    }
    memcpy(outBytes.get(), data, data_len);
    return out.release();
}

static void NativeCrypto_asn1_write_cleanup(CONSCRYPT_UNUSED JNIEnv* env, jclass, jlong cbbRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    CBB* cbb = reinterpret_cast<CBB*>(static_cast<uintptr_t>(cbbRef));
    JNI_TRACE("asn1_write_cleanup(%p)", cbb);

    CBB_cleanup(cbb);
}

static void NativeCrypto_asn1_write_free(CONSCRYPT_UNUSED JNIEnv* env, jclass, jlong cbbRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    if (cbbRef == 0) {
        JNI_TRACE("asn1_write_free(0)");
        return;
    }
    CBB* cbb = reinterpret_cast<CBB*>(static_cast<uintptr_t>(cbbRef));
    JNI_TRACE("asn1_write_free(%p)", cbb);
    delete cbb;
}

template <typename T, T* (*d2i_func)(BIO*, T**)>
static jlong d2i_ASN1Object_to_jlong(JNIEnv* env, jlong bioRef) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("d2i_ASN1Object_to_jlong(%p)", bio);

    if (bio == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "bio == null");
        return 0;
    }

    T* x = d2i_func(bio, nullptr);
    if (x == nullptr) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "d2i_ASN1Object_to_jlong");
        return 0;
    }

    return reinterpret_cast<uintptr_t>(x);
}

static jlong NativeCrypto_d2i_X509_CRL_bio(JNIEnv* env, jclass, jlong bioRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return d2i_ASN1Object_to_jlong<X509_CRL, d2i_X509_CRL_bio>(env, bioRef);
}

static jlong NativeCrypto_d2i_X509_bio(JNIEnv* env, jclass, jlong bioRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return d2i_ASN1Object_to_jlong<X509, d2i_X509_bio>(env, bioRef);
}

static jlong NativeCrypto_d2i_X509(JNIEnv* env, jclass, jbyteArray certBytes) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    ScopedByteArrayRO bytes(env, certBytes);
    if (bytes.get() == nullptr) {
        JNI_TRACE("NativeCrypto_d2i_X509(%p) => using byte array failed", certBytes);
        return 0;
    }

    const unsigned char* tmp = reinterpret_cast<const unsigned char*>(bytes.get());
    // NOLINTNEXTLINE(runtime/int)
    X509* x = d2i_X509(nullptr, &tmp, static_cast<long>(bytes.size()));
    if (x == nullptr) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(
                env, "Error reading X.509 data", conscrypt::jniutil::throwParsingException);
        return 0;
    }
    return reinterpret_cast<uintptr_t>(x);
}

static jbyteArray NativeCrypto_i2d_X509(JNIEnv* env, jclass, jlong x509Ref,
                                        CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("i2d_X509(%p)", x509);
    return ASN1ToByteArray<X509>(env, x509, i2d_X509);
}

static jbyteArray NativeCrypto_i2d_X509_PUBKEY(JNIEnv* env, jclass, jlong x509Ref,
                                               CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("i2d_X509_PUBKEY(%p)", x509);
    return ASN1ToByteArray<X509_PUBKEY>(env, X509_get_X509_PUBKEY(x509), i2d_X509_PUBKEY);
}

template <typename T, T* (*PEM_read_func)(BIO*, T**, pem_password_cb*, void*)>
static jlong PEM_to_jlong(JNIEnv* env, jlong bioRef) {
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("PEM_to_jlong(%p)", bio);

    if (bio == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "bio == null");
        JNI_TRACE("PEM_to_jlong(%p) => bio == null", bio);
        return 0;
    }

    T* x = PEM_read_func(bio, nullptr, nullptr, nullptr);
    if (x == nullptr) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "PEM_to_jlong");
        JNI_TRACE("PEM_to_jlong(%p) => threw exception", bio);
        return 0;
    }

    JNI_TRACE("PEM_to_jlong(%p) => %p", bio, x);
    return reinterpret_cast<uintptr_t>(x);
}

static jlong NativeCrypto_PEM_read_bio_X509(JNIEnv* env, jclass, jlong bioRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("PEM_read_bio_X509(0x%llx)", (long long)bioRef);
    return PEM_to_jlong<X509, PEM_read_bio_X509>(env, bioRef);
}

static jlong NativeCrypto_PEM_read_bio_X509_CRL(JNIEnv* env, jclass, jlong bioRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("PEM_read_bio_X509_CRL(0x%llx)", (long long)bioRef);
    return PEM_to_jlong<X509_CRL, PEM_read_bio_X509_CRL>(env, bioRef);
}

static jlong NativeCrypto_PEM_read_bio_PUBKEY(JNIEnv* env, jclass, jlong bioRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("PEM_read_bio_PUBKEY(0x%llx)", (long long)bioRef);
    return PEM_to_jlong<EVP_PKEY, PEM_read_bio_PUBKEY>(env, bioRef);
}

static jlong NativeCrypto_PEM_read_bio_PrivateKey(JNIEnv* env, jclass, jlong bioRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("PEM_read_bio_PrivateKey(0x%llx)", (long long)bioRef);
    return PEM_to_jlong<EVP_PKEY, PEM_read_bio_PrivateKey>(env, bioRef);
}

template <typename T, typename T_stack>
static jlongArray PKCS7_to_ItemArray(JNIEnv* env, T_stack* stack, T* (*dup_func)(T*)) {
    if (stack == nullptr) {
        return nullptr;
    }

    ScopedLocalRef<jlongArray> ref_array(env, nullptr);
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
    CHECK_ERROR_QUEUE_ON_RETURN;
    STACK_OF(X509)* stack = sk_X509_new_null();

    ScopedLongArrayRO certs(env, certsArray);
    for (size_t i = 0; i < certs.size(); i++) {
        X509* item = reinterpret_cast<X509*>(certs[i]);
        if (sk_X509_push(stack, item) == 0) {
            sk_X509_free(stack);
            conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "sk_X509_push");
            return nullptr;
        }
    }

    bssl::ScopedCBB out;
    CBB_init(out.get(), 1024 * certs.size());
    if (!PKCS7_bundle_certificates(out.get(), stack)) {
        sk_X509_free(stack);
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "PKCS7_bundle_certificates");
        return nullptr;
    }

    sk_X509_free(stack);

    return CBBToByteArray(env, out.get());
}

static jlongArray NativeCrypto_PEM_read_bio_PKCS7(JNIEnv* env, jclass, jlong bioRef, jint which) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("PEM_read_bio_PKCS7_CRLs(%p)", bio);

    if (bio == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "bio == null");
        JNI_TRACE("PEM_read_bio_PKCS7_CRLs(%p) => bio == null", bio);
        return nullptr;
    }

    if (which == PKCS7_CERTS) {
        bssl::UniquePtr<STACK_OF(X509)> outCerts(sk_X509_new_null());
        if (!PKCS7_get_PEM_certificates(outCerts.get(), bio)) {
            conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "PKCS7_get_PEM_certificates");
            return nullptr;
        }
        return PKCS7_to_ItemArray<X509, STACK_OF(X509)>(env, outCerts.get(), X509_dup);
    } else if (which == PKCS7_CRLS) {
        bssl::UniquePtr<STACK_OF(X509_CRL)> outCRLs(sk_X509_CRL_new_null());
        if (!PKCS7_get_PEM_CRLs(outCRLs.get(), bio)) {
            conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "PKCS7_get_PEM_CRLs");
            return nullptr;
        }
        return PKCS7_to_ItemArray<X509_CRL, STACK_OF(X509_CRL)>(env, outCRLs.get(), X509_CRL_dup);
    } else {
        conscrypt::jniutil::throwRuntimeException(env, "unknown PKCS7 field");
        return nullptr;
    }
}

static jlongArray NativeCrypto_d2i_PKCS7_bio(JNIEnv* env, jclass, jlong bioRef, jint which) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("d2i_PKCS7_bio(%p, %d)", bio, which);

    if (bio == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "bio == null");
        JNI_TRACE("d2i_PKCS7_bio(%p, %d) => bio == null", bio, which);
        return nullptr;
    }

    uint8_t* data;
    size_t len;
    if (!BIO_read_asn1(bio, &data, &len, 256 * 1024 * 1024 /* max length, 256MB for sanity */)) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "Error reading PKCS#7 data",
                conscrypt::jniutil::throwParsingException);
        JNI_TRACE("d2i_PKCS7_bio(%p, %d) => error reading BIO", bio, which);
        return nullptr;
    }
    bssl::UniquePtr<uint8_t> data_storage(data);

    CBS cbs;
    CBS_init(&cbs, data, len);

    if (which == PKCS7_CERTS) {
        bssl::UniquePtr<STACK_OF(X509)> outCerts(sk_X509_new_null());
        if (!PKCS7_get_certificates(outCerts.get(), &cbs)) {
            conscrypt::jniutil::throwExceptionFromBoringSSLError(env,
                    "PKCS7_get_certificates", conscrypt::jniutil::throwParsingException);
            JNI_TRACE("d2i_PKCS7_bio(%p, %d) => error reading certs", bio, which);
            return nullptr;
        }
        JNI_TRACE("d2i_PKCS7_bio(%p, %d) => success certs", bio, which);
        return PKCS7_to_ItemArray<X509, STACK_OF(X509)>(env, outCerts.get(), X509_dup);
    } else if (which == PKCS7_CRLS) {
        bssl::UniquePtr<STACK_OF(X509_CRL)> outCRLs(sk_X509_CRL_new_null());
        if (!PKCS7_get_CRLs(outCRLs.get(), &cbs)) {
            conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "PKCS7_get_CRLs",
                    conscrypt::jniutil::throwParsingException);
            JNI_TRACE("d2i_PKCS7_bio(%p, %d) => error reading CRLs", bio, which);
            return nullptr;
        }
        JNI_TRACE("d2i_PKCS7_bio(%p, %d) => success CRLs", bio, which);
        return PKCS7_to_ItemArray<X509_CRL, STACK_OF(X509_CRL)>(env, outCRLs.get(), X509_CRL_dup);
    } else {
        conscrypt::jniutil::throwRuntimeException(env, "unknown PKCS7 field");
        return nullptr;
    }
}

static jlongArray NativeCrypto_ASN1_seq_unpack_X509_bio(JNIEnv* env, jclass, jlong bioRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("ASN1_seq_unpack_X509_bio(%p)", bio);

    uint8_t* data;
    size_t len;
    if (!BIO_read_asn1(bio, &data, &len, 256 * 1024 * 1024 /* max length, 256MB for sanity */)) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "Error reading X.509 data",
                conscrypt::jniutil::throwParsingException);
        JNI_TRACE("ASN1_seq_unpack_X509_bio(%p) => error reading BIO", bio);
        return nullptr;
    }
    bssl::UniquePtr<uint8_t> data_storage(data);

    bssl::UniquePtr<STACK_OF(X509)> path(sk_X509_new_null());
    if (path.get() == nullptr) {
        JNI_TRACE("ASN1_seq_unpack_X509_bio(%p) => failed to make cert stack", bio);
        return nullptr;
    }

    CBS cbs, sequence;
    CBS_init(&cbs, data, len);
    if (!CBS_get_asn1(&cbs, &sequence, CBS_ASN1_SEQUENCE)) {
        conscrypt::jniutil::throwParsingException(env, "Error reading X.509 data");
        ERR_clear_error();
        return nullptr;
    }

    while (CBS_len(&sequence) > 0) {
        CBS child;
        if (!CBS_get_asn1_element(&sequence, &child, CBS_ASN1_SEQUENCE)) {
            conscrypt::jniutil::throwParsingException(env, "Error reading X.509 data");
            ERR_clear_error();
            return nullptr;
        }

        const uint8_t* tmp = CBS_data(&child);
        // NOLINTNEXTLINE(runtime/int)
        bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &tmp, static_cast<long>(CBS_len(&child))));
        if (!cert || tmp != CBS_data(&child) + CBS_len(&child)) {
            conscrypt::jniutil::throwParsingException(env, "Error reading X.509 data");
            ERR_clear_error();
            return nullptr;
        }

        if (!sk_X509_push(path.get(), cert.get())) {
            conscrypt::jniutil::throwOutOfMemory(env, "Unable to push local certificate");
            return nullptr;
        }
        OWNERSHIP_TRANSFERRED(cert);
    }

    size_t size = sk_X509_num(path.get());

    ScopedLocalRef<jlongArray> certArray(env, env->NewLongArray(static_cast<jsize>(size)));
    ScopedLongArrayRW certs(env, certArray.get());
    for (size_t i = 0; i < size; i++) {
        X509* item = reinterpret_cast<X509*>(sk_X509_shift(path.get()));
        certs[i] = reinterpret_cast<uintptr_t>(item);
    }

    JNI_TRACE("ASN1_seq_unpack_X509_bio(%p) => returns %zd items", bio, size);
    return certArray.release();
}

static jbyteArray NativeCrypto_ASN1_seq_pack_X509(JNIEnv* env, jclass, jlongArray certs) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("ASN1_seq_pack_X509(%p)", certs);
    ScopedLongArrayRO certsArray(env, certs);
    if (certsArray.get() == nullptr) {
        JNI_TRACE("ASN1_seq_pack_X509(%p) => failed to get certs array", certs);
        return nullptr;
    }

    bssl::ScopedCBB result;
    CBB seq_contents;
    if (!CBB_init(result.get(), 2048 * certsArray.size())) {
        JNI_TRACE("ASN1_seq_pack_X509(%p) => CBB_init failed", certs);
        return nullptr;
    }
    if (!CBB_add_asn1(result.get(), &seq_contents, CBS_ASN1_SEQUENCE)) {
        return nullptr;
    }

    for (size_t i = 0; i < certsArray.size(); i++) {
        X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(certsArray[i]));
        uint8_t* buf;
        int len = i2d_X509(x509, nullptr);

        if (len < 0 || !CBB_add_space(&seq_contents, &buf, static_cast<size_t>(len)) ||
            i2d_X509(x509, &buf) < 0) {
            return nullptr;
        }
    }

    return CBBToByteArray(env, result.get());
}

static void NativeCrypto_X509_free(JNIEnv* env, jclass, jlong x509Ref,
                                   CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_free(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_free(%p) => x509 == null", x509);
        return;
    }

    X509_free(x509);
}

static jlong NativeCrypto_X509_dup(JNIEnv* env, jclass, jlong x509Ref,
                                   CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_dup(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_dup(%p) => x509 == null", x509);
        return 0;
    }

    return reinterpret_cast<uintptr_t>(X509_dup(x509));
}

static jint NativeCrypto_X509_cmp(JNIEnv* env, jclass, jlong x509Ref1,
                                  CONSCRYPT_UNUSED jobject holder, jlong x509Ref2,
                                  CONSCRYPT_UNUSED jobject holder2) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509_1 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref1));
    X509* x509_2 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref2));
    JNI_TRACE("X509_cmp(%p, %p)", x509_1, x509_2);

    if (x509_1 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509_1 == null");
        JNI_TRACE("X509_cmp(%p, %p) => x509_1 == null", x509_1, x509_2);
        return -1;
    }

    if (x509_2 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509_2 == null");
        JNI_TRACE("X509_cmp(%p, %p) => x509_2 == null", x509_1, x509_2);
        return -1;
    }

    int ret = X509_cmp(x509_1, x509_2);
    JNI_TRACE("X509_cmp(%p, %p) => %d", x509_1, x509_2, ret);
    return ret;
}

static void NativeCrypto_X509_delete_ext(JNIEnv* env, jclass, jlong x509Ref,
                                         CONSCRYPT_UNUSED jobject holder, jstring oidString) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_delete_ext(%p, %p)", x509, oidString);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_delete_ext(%p, %p) => x509 == null", x509, oidString);
        return;
    }

    ScopedUtfChars oid(env, oidString);
    if (oid.c_str() == nullptr) {
        JNI_TRACE("X509_delete_ext(%p, %p) => oidString == null", x509, oidString);
        return;
    }

    bssl::UniquePtr<ASN1_OBJECT> obj(OBJ_txt2obj(oid.c_str(), 1 /* allow numerical form only */));
    if (obj.get() == nullptr) {
        JNI_TRACE("X509_delete_ext(%p, %s) => oid conversion failed", x509, oid.c_str());
        conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                           "Invalid OID.");
        ERR_clear_error();
        return;
    }

    int extIndex = X509_get_ext_by_OBJ(x509, obj.get(), -1);
    if (extIndex == -1) {
        JNI_TRACE("X509_delete_ext(%p, %s) => ext not found", x509, oid.c_str());
        return;
    }

    X509_EXTENSION* ext = X509_delete_ext(x509, extIndex);
    if (ext != nullptr) {
        X509_EXTENSION_free(ext);

        // Invalidate the cached encoding
        X509_CINF_set_modified(X509_get_cert_info(x509));
    }
}

static void NativeCrypto_X509_print_ex(JNIEnv* env, jclass, jlong bioRef, jlong x509Ref,
                                       CONSCRYPT_UNUSED jobject holder, jlong nmflagJava,
                                       jlong certflagJava) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    // NOLINTNEXTLINE(runtime/int)
    unsigned long nmflag = static_cast<unsigned long>(nmflagJava);
    // NOLINTNEXTLINE(runtime/int)
    unsigned long certflag = static_cast<unsigned long>(certflagJava);
    JNI_TRACE("X509_print_ex(%p, %p, %ld, %ld)", bio, x509, nmflag, certflag);

    if (bio == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "bio == null");
        JNI_TRACE("X509_print_ex(%p, %p, %ld, %ld) => bio == null", bio, x509, nmflag, certflag);
        return;
    }

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_print_ex(%p, %p, %ld, %ld) => x509 == null", bio, x509, nmflag, certflag);
        return;
    }

    if (!X509_print_ex(bio, x509, nmflag, certflag)) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "X509_print_ex");
        JNI_TRACE("X509_print_ex(%p, %p, %ld, %ld) => threw error", bio, x509, nmflag, certflag);
        return;
    }
    JNI_TRACE("X509_print_ex(%p, %p, %ld, %ld) => success", bio, x509, nmflag, certflag);
}

static jlong NativeCrypto_X509_get_pubkey(JNIEnv* env, jclass, jlong x509Ref,
                                          CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_pubkey(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("X509_get_pubkey(%p) => x509 == null", x509);
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY> pkey(X509_get_pubkey(x509));
    if (pkey.get() == nullptr) {
        const uint32_t last_error = ERR_peek_last_error();
        const uint32_t first_error = ERR_peek_error();
        if ((ERR_GET_LIB(last_error) == ERR_LIB_EVP &&
             ERR_GET_REASON(last_error) == EVP_R_UNKNOWN_PUBLIC_KEY_TYPE) ||
            (ERR_GET_LIB(first_error) == ERR_LIB_EC &&
             ERR_GET_REASON(first_error) == EC_R_UNKNOWN_GROUP)) {
            ERR_clear_error();
            conscrypt::jniutil::throwNoSuchAlgorithmException(env, "X509_get_pubkey");
            return 0;
        }

        conscrypt::jniutil::throwExceptionFromBoringSSLError(
                env, "X509_get_pubkey", conscrypt::jniutil::throwInvalidKeyException);
        return 0;
    }

    JNI_TRACE("X509_get_pubkey(%p) => %p", x509, pkey.get());
    return reinterpret_cast<uintptr_t>(pkey.release());
}

static jbyteArray NativeCrypto_X509_get_issuer_name(JNIEnv* env, jclass, jlong x509Ref,
                                                    CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_issuer_name(%p)", x509);
    return ASN1ToByteArray<X509_NAME>(env, X509_get_issuer_name(x509), i2d_X509_NAME);
}

static jbyteArray NativeCrypto_X509_get_subject_name(JNIEnv* env, jclass, jlong x509Ref,
                                                     CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_subject_name(%p)", x509);
    return ASN1ToByteArray<X509_NAME>(env, X509_get_subject_name(x509), i2d_X509_NAME);
}

static jstring NativeCrypto_get_X509_pubkey_oid(JNIEnv* env, jclass, jlong x509Ref,
                                                CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_pubkey_oid(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_pubkey_oid(%p) => x509 == null", x509);
        return nullptr;
    }

    X509_PUBKEY* pubkey = X509_get_X509_PUBKEY(x509);
    return ASN1_OBJECT_to_OID_string(env, pubkey->algor->algorithm);
}

static jstring NativeCrypto_get_X509_sig_alg_oid(JNIEnv* env, jclass, jlong x509Ref,
                                                 CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_sig_alg_oid(%p)", x509);

    if (x509 == nullptr || x509->sig_alg == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null || x509->sig_alg == null");
        JNI_TRACE("get_X509_sig_alg_oid(%p) => x509 == null", x509);
        return nullptr;
    }

    return ASN1_OBJECT_to_OID_string(env, x509->sig_alg->algorithm);
}

static jbyteArray NativeCrypto_get_X509_sig_alg_parameter(JNIEnv* env, jclass, jlong x509Ref,
                                                          CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_sig_alg_parameter(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_sig_alg_parameter(%p) => x509 == null", x509);
        return nullptr;
    }

    if (x509->sig_alg->parameter == nullptr) {
        JNI_TRACE("get_X509_sig_alg_parameter(%p) => null", x509);
        return nullptr;
    }

    return ASN1ToByteArray<ASN1_TYPE>(env, x509->sig_alg->parameter, i2d_ASN1_TYPE);
}

static jbooleanArray NativeCrypto_get_X509_issuerUID(JNIEnv* env, jclass, jlong x509Ref,
                                                     CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_issuerUID(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_issuerUID(%p) => x509 == null", x509);
        return nullptr;
    }

    if (x509->cert_info->issuerUID == nullptr) {
        JNI_TRACE("get_X509_issuerUID(%p) => null", x509);
        return nullptr;
    }

    return ASN1BitStringToBooleanArray(env, x509->cert_info->issuerUID);
}

static jbooleanArray NativeCrypto_get_X509_subjectUID(JNIEnv* env, jclass, jlong x509Ref,
                                                      CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_subjectUID(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_subjectUID(%p) => x509 == null", x509);
        return nullptr;
    }

    if (x509->cert_info->subjectUID == nullptr) {
        JNI_TRACE("get_X509_subjectUID(%p) => null", x509);
        return nullptr;
    }

    return ASN1BitStringToBooleanArray(env, x509->cert_info->subjectUID);
}

static jbooleanArray NativeCrypto_get_X509_ex_kusage(JNIEnv* env, jclass, jlong x509Ref,
                                                     CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_ex_kusage(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_ex_kusage(%p) => x509 == null", x509);
        return nullptr;
    }

    bssl::UniquePtr<ASN1_BIT_STRING> bitStr(
            static_cast<ASN1_BIT_STRING*>(X509_get_ext_d2i(x509, NID_key_usage, nullptr, nullptr)));
    if (bitStr.get() == nullptr) {
        JNI_TRACE("get_X509_ex_kusage(%p) => null", x509);
        return nullptr;
    }

    return ASN1BitStringToBooleanArray(env, bitStr.get());
}

static jobjectArray NativeCrypto_get_X509_ex_xkusage(JNIEnv* env, jclass, jlong x509Ref,
                                                     CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_ex_xkusage(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_ex_xkusage(%p) => x509 == null", x509);
        return nullptr;
    }

    bssl::UniquePtr<STACK_OF(ASN1_OBJECT)> objArray(static_cast<STACK_OF(ASN1_OBJECT)*>(
            X509_get_ext_d2i(x509, NID_ext_key_usage, nullptr, nullptr)));
    if (objArray.get() == nullptr) {
        JNI_TRACE("get_X509_ex_xkusage(%p) => null", x509);
        return nullptr;
    }

    size_t size = sk_ASN1_OBJECT_num(objArray.get());
    ScopedLocalRef<jobjectArray> exKeyUsage(
            env, env->NewObjectArray(static_cast<jsize>(size), conscrypt::jniutil::stringClass,
                                     nullptr));
    if (exKeyUsage.get() == nullptr) {
        return nullptr;
    }

    for (size_t i = 0; i < size; i++) {
        ScopedLocalRef<jstring> oidStr(
                env, ASN1_OBJECT_to_OID_string(env, sk_ASN1_OBJECT_value(objArray.get(), i)));
        env->SetObjectArrayElement(exKeyUsage.get(), static_cast<jsize>(i), oidStr.get());
    }

    JNI_TRACE("get_X509_ex_xkusage(%p) => success (%zd entries)", x509, size);
    return exKeyUsage.release();
}

static jint NativeCrypto_get_X509_ex_pathlen(JNIEnv* env, jclass, jlong x509Ref,
                                             CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509_ex_pathlen(%p)", x509);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509_ex_pathlen(%p) => x509 == null", x509);
        return 0;
    }

    /* Just need to do this to cache the ex_* values. */
    X509_check_ca(x509);

    JNI_TRACE("get_X509_ex_pathlen(%p) => %ld", x509, x509->ex_pathlen);
    return x509->ex_pathlen;
}

static jbyteArray NativeCrypto_X509_get_ext_oid(JNIEnv* env, jclass, jlong x509Ref,
                                                CONSCRYPT_UNUSED jobject holder,
                                                jstring oidString) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("X509_get_ext_oid(%p, %p)", x509, oidString);
    return X509Type_get_ext_oid<X509, X509_get_ext_by_OBJ, X509_get_ext>(env, x509, oidString);
}

static jbyteArray NativeCrypto_X509_CRL_get_ext_oid(JNIEnv* env, jclass, jlong x509CrlRef,
                                                    CONSCRYPT_UNUSED jobject holder,
                                                    jstring oidString) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_CRL* crl = reinterpret_cast<X509_CRL*>(static_cast<uintptr_t>(x509CrlRef));
    JNI_TRACE("X509_CRL_get_ext_oid(%p, %p)", crl, oidString);
    return X509Type_get_ext_oid<X509_CRL, X509_CRL_get_ext_by_OBJ, X509_CRL_get_ext>(env, crl,
                                                                                     oidString);
}

static jbyteArray NativeCrypto_X509_REVOKED_get_ext_oid(JNIEnv* env, jclass, jlong x509RevokedRef,
                                                        jstring oidString) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    X509_REVOKED* revoked = reinterpret_cast<X509_REVOKED*>(static_cast<uintptr_t>(x509RevokedRef));
    JNI_TRACE("X509_REVOKED_get_ext_oid(%p, %p)", revoked, oidString);
    return X509Type_get_ext_oid<X509_REVOKED, X509_REVOKED_get_ext_by_OBJ, X509_REVOKED_get_ext>(
            env, revoked, oidString);
}

template <typename T, typename C, C T::*member, int (*get_ext_by_critical_func)(T*, int, int),
          X509_EXTENSION* (*get_ext_func)(T*, int)>
static jobjectArray get_X509Type_ext_oids(JNIEnv* env, jlong x509Ref, jint critical) {
    T* x509 = reinterpret_cast<T*>(static_cast<uintptr_t>(x509Ref));
    JNI_TRACE("get_X509Type_ext_oids(%p, %d)", x509, critical);

    if (x509 == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509 == null");
        JNI_TRACE("get_X509Type_ext_oids(%p, %d) => x509 == null", x509, critical);
        return nullptr;
    }
    if (member != nullptr && x509->*member == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "x509->*member == null");
        JNI_TRACE("get_X509Type_ext_oids(%p, %d) => x509->*member == null", x509, critical);
        return nullptr;
    }

    int lastPos = -1;
    int count = 0;
    while ((lastPos = get_ext_by_critical_func(x509, critical, lastPos)) != -1) {
        count++;
    }

    JNI_TRACE("get_X509Type_ext_oids(%p, %d) has %d entries", x509, critical, count);

    ScopedLocalRef<jobjectArray> joa(
            env, env->NewObjectArray(count, conscrypt::jniutil::stringClass, nullptr));
    if (joa.get() == nullptr) {
        JNI_TRACE("get_X509Type_ext_oids(%p, %d) => fail to allocate result array", x509, critical);
        return nullptr;
    }

    lastPos = -1;
    count = 0;
    while ((lastPos = get_ext_by_critical_func(x509, critical, lastPos)) != -1) {
        X509_EXTENSION* ext = get_ext_func(x509, lastPos);

        ScopedLocalRef<jstring> extOid(env, ASN1_OBJECT_to_OID_string(env, ext->object));
        if (extOid.get() == nullptr) {
            JNI_TRACE("get_X509Type_ext_oids(%p) => couldn't get OID", x509);
            return nullptr;
        }

        env->SetObjectArrayElement(joa.get(), count++, extOid.get());
    }

    JNI_TRACE("get_X509Type_ext_oids(%p, %d) => success", x509, critical);
    return joa.release();
}

static jobjectArray NativeCrypto_get_X509_ext_oids(JNIEnv* env, jclass, jlong x509Ref,
                                                   CONSCRYPT_UNUSED jobject holder, jint critical) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("get_X509_ext_oids(0x%llx, %d)", (long long)x509Ref, critical);
    return get_X509Type_ext_oids<X509, decltype(X509::cert_info), &X509::cert_info,
            X509_get_ext_by_critical, X509_get_ext>(env, x509Ref, critical);
}

static jobjectArray NativeCrypto_get_X509_CRL_ext_oids(JNIEnv* env, jclass, jlong x509CrlRef,
                                                       CONSCRYPT_UNUSED jobject holder,
                                                       jint critical) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("get_X509_CRL_ext_oids(0x%llx, %d)", (long long)x509CrlRef, critical);
    return get_X509Type_ext_oids<X509_CRL, decltype(X509_CRL::crl), &X509_CRL::crl,
            X509_CRL_get_ext_by_critical, X509_CRL_get_ext>(env, x509CrlRef, critical);
}

static jobjectArray NativeCrypto_get_X509_REVOKED_ext_oids(JNIEnv* env, jclass,
                                                           jlong x509RevokedRef, jint critical) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("get_X509_CRL_ext_oids(0x%llx, %d)", (long long)x509RevokedRef, critical);
    return get_X509Type_ext_oids<X509_REVOKED, decltype(X509_REVOKED::extensions), nullptr,
            X509_REVOKED_get_ext_by_critical, X509_REVOKED_get_ext>(env, x509RevokedRef, critical);
}

/**
 * Based on example logging call back from SSL_CTX_set_info_callback man page
 */
static void info_callback_LOG(const SSL* s, int where, int ret) {
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
        JNI_TRACE("ssl=%p SSL3 alert %s %s %s", s, str, SSL_alert_type_string_long(ret),
                  SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            JNI_TRACE("ssl=%p %s:failed exit in %s %s", s, str, SSL_state_string(s),
                      SSL_state_string_long(s));
        } else if (ret < 0) {
            JNI_TRACE("ssl=%p %s:error exit in %s %s", s, str, SSL_state_string(s),
                      SSL_state_string_long(s));
        } else if (ret == 1) {
            JNI_TRACE("ssl=%p %s:ok exit in %s %s", s, str, SSL_state_string(s),
                      SSL_state_string_long(s));
        } else {
            JNI_TRACE("ssl=%p %s:unknown exit %d in %s %s", s, str, ret, SSL_state_string(s),
                      SSL_state_string_long(s));
        }
    } else if (where & SSL_CB_HANDSHAKE_START) {
        JNI_TRACE("ssl=%p handshake start in %s %s", s, SSL_state_string(s),
                  SSL_state_string_long(s));
    } else if (where & SSL_CB_HANDSHAKE_DONE) {
        JNI_TRACE("ssl=%p handshake done in %s %s", s, SSL_state_string(s),
                  SSL_state_string_long(s));
    } else {
        JNI_TRACE("ssl=%p %s:unknown where %d in %s %s", s, str, where, SSL_state_string(s),
                  SSL_state_string_long(s));
    }
}

#ifdef _WIN32

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
 * @return THROWN_EXCEPTION on close socket, 0 on timeout, -1 on error, and 1 on success
 */
static int sslSelect(JNIEnv* env, int type, jobject fdObject, AppData* appData,
                     int timeout_millis) {
    int result = -1;

    NetFd fd(env, fdObject);
    do {
        if (fd.isClosed()) {
            result = THROWN_EXCEPTION;
            break;
        }

        WSAEVENT events[2];
        events[0] = appData->interruptEvent;
        events[1] = WSACreateEvent();
        if (events[1] == WSA_INVALID_EVENT) {
            JNI_TRACE("sslSelect failure in WSACreateEvent: %d", WSAGetLastError());
            break;
        }

        if (WSAEventSelect(fd.get(), events[1], (type == SSL_ERROR_WANT_READ ? FD_READ : FD_WRITE) |
                                                        FD_CLOSE) == SOCKET_ERROR) {
            JNI_TRACE("sslSelect failure in WSAEventSelect: %d", WSAGetLastError());
            break;
        }

        JNI_TRACE("sslSelect type=%s fd=%d appData=%p timeout_millis=%d",
                  (type == SSL_ERROR_WANT_READ) ? "READ" : "WRITE", fd.get(), appData,
                  timeout_millis);

        int rc = WSAWaitForMultipleEvents(
                2, events, FALSE, timeout_millis == 0 ? WSA_INFINITE : timeout_millis, FALSE);
        if (rc == WSA_WAIT_FAILED) {
            JNI_TRACE("WSAWaitForMultipleEvents failed: %d", WSAGetLastError());
            result = -1;
        } else if (rc == WSA_WAIT_TIMEOUT) {
            result = 0;
        } else {
            result = 1;
        }
        WSACloseEvent(events[1]);
    } while (0);

    JNI_TRACE("sslSelect type=%s fd=%d appData=%p timeout_millis=%d => %d",
              (type == SSL_ERROR_WANT_READ) ? "READ" : "WRITE", fd.get(), appData, timeout_millis,
              result);

    std::lock_guard<std::mutex> appDataLock(appData->mutex);
    appData->waitingThreads--;

    return result;
}

#else   // !defined(_WIN32)

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
 * @param fdObject The FileDescriptor, since appData->fileDescriptor should be nullptr
 * @param appData The application data structure with mutex info etc.
 * @param timeout_millis The timeout value for poll call, with the special value
 *                0 meaning no timeout at all (wait indefinitely). Note: This is
 *                the Java semantics of the timeout value, not the usual
 *                poll() semantics.
 * @return The result of the inner poll() call,
 * THROW_SOCKETEXCEPTION if a SocketException was thrown, -1 on
 * additional errors
 */
static int sslSelect(JNIEnv* env, int type, jobject fdObject, AppData* appData,
                     int timeout_millis) {
    // This loop is an expanded version of the NET_FAILURE_RETRY
    // macro. It cannot simply be used in this case because poll
    // cannot be restarted without recreating the pollfd structure.
    int result;
    struct pollfd fds[2];
    do {
        NetFd fd(env, fdObject);
        if (fd.isClosed()) {
            result = THROWN_EXCEPTION;
            break;
        }
        int intFd = fd.get();
        JNI_TRACE("sslSelect type=%s fd=%d appData=%p timeout_millis=%d",
                  (type == SSL_ERROR_WANT_READ) ? "READ" : "WRITE", intFd, appData, timeout_millis);

        memset(&fds, 0, sizeof(fds));
        fds[0].fd = intFd;
        if (type == SSL_ERROR_WANT_READ) {
            fds[0].events = POLLIN | POLLPRI;
        } else {
            fds[0].events = POLLOUT | POLLPRI;
        }

        fds[1].fd = appData->fdsEmergency[0];
        fds[1].events = POLLIN | POLLPRI;

        // Converting from Java semantics to Posix semantics.
        if (timeout_millis <= 0) {
            timeout_millis = -1;
        }

        CompatibilityCloseMonitor monitor(intFd);

        result = poll(fds, sizeof(fds) / sizeof(fds[0]), timeout_millis);
        JNI_TRACE("sslSelect %s fd=%d appData=%p timeout_millis=%d => %d",
                  (type == SSL_ERROR_WANT_READ) ? "READ" : "WRITE", fd.get(), appData,
                  timeout_millis, result);
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

    std::lock_guard<std::mutex> appDataLock(appData->mutex);

    if (result > 0) {
        // We have been woken up by a token in the emergency pipe. We
        // can't be sure the token is still in the pipe at this point
        // because it could have already been read by the thread that
        // originally wrote it if it entered sslSelect and acquired
        // the mutex before we did. Thus we cannot safely read from
        // the pipe in a blocking way (so we make the pipe
        // non-blocking at creation).
        if (fds[1].revents & POLLIN) {
            char token;
            do {
                (void)read(appData->fdsEmergency[0], &token, 1);
            } while (errno == EINTR);
        }
    }

    // Tell the world that there is now one thread less waiting for the
    // underlying network.
    appData->waitingThreads--;

    return result;
}
#endif  // !defined(_WIN32)

/**
 * Helper function that wakes up a thread blocked in select(), in case there is
 * one. Is being called by sslRead() and sslWrite() as well as by JNI glue
 * before closing the connection.
 *
 * @param data The application data structure with mutex info etc.
 */
static void sslNotify(AppData* appData) {
#ifdef _WIN32
    SetEvent(appData->interruptEvent);
#else
    // Write a byte to the emergency pipe, so a concurrent select() can return.
    // Note we have to restore the errno of the original system call, since the
    // caller relies on it for generating error messages.
    int errnoBackup = errno;
    char token = '*';
    do {
        errno = 0;
        (void)write(appData->fdsEmergency[1], &token, 1);
    } while (errno == EINTR);
    errno = errnoBackup;
#endif
}

static AppData* toAppData(const SSL* ssl) {
    return reinterpret_cast<AppData*>(SSL_get_app_data(ssl));
}

static ssl_verify_result_t cert_verify_callback(SSL* ssl, CONSCRYPT_UNUSED uint8_t* out_alert) {
    JNI_TRACE("ssl=%p cert_verify_callback", ssl);

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        CONSCRYPT_LOG_ERROR("AppData->env missing in cert_verify_callback");
        JNI_TRACE("ssl=%p cert_verify_callback => 0", ssl);
        return ssl_verify_invalid;
    }

    // Create the byte[][] array that holds all the certs
    ScopedLocalRef<jobjectArray> array(
            env, CryptoBuffersToObjectArray(env, SSL_get0_peer_certificates(ssl)));
    if (array.get() == nullptr) {
        return ssl_verify_invalid;
    }

    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;
    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID =
            env->GetMethodID(cls, "verifyCertificateChain", "([[BLjava/lang/String;)V");

    const SSL_CIPHER* cipher = SSL_get_pending_cipher(ssl);
    const char* authMethod = SSL_CIPHER_get_kx_name(cipher);

    JNI_TRACE("ssl=%p cert_verify_callback calling verifyCertificateChain authMethod=%s", ssl,
              authMethod);
    ScopedLocalRef<jstring> authMethodString(env, env->NewStringUTF(authMethod));
    env->CallVoidMethod(sslHandshakeCallbacks, methodID, array.get(), authMethodString.get());

    ssl_verify_result_t result = env->ExceptionCheck() ? ssl_verify_invalid : ssl_verify_ok;
    JNI_TRACE("ssl=%p cert_verify_callback => %d", ssl, result);
    return result;
}

/**
 * Call back to watch for handshake to be completed. This is necessary for
 * False Start support, since SSL_do_handshake returns before the handshake is
 * completed in this case.
 */
static void info_callback(const SSL* ssl, int type, int value) {
    JNI_TRACE("ssl=%p info_callback type=0x%x value=%d", ssl, type, value);
    if (conscrypt::trace::kWithJniTrace) {
        info_callback_LOG(ssl, type, value);
    }
    if (!(type & SSL_CB_HANDSHAKE_DONE) && !(type & SSL_CB_HANDSHAKE_START)) {
        JNI_TRACE("ssl=%p info_callback ignored", ssl);
        return;
    }

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        CONSCRYPT_LOG_ERROR("AppData->env missing in info_callback");
        JNI_TRACE("ssl=%p info_callback env error", ssl);
        return;
    }
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p info_callback already pending exception", ssl);
        return;
    }

    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;

    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID = env->GetMethodID(cls, "onSSLStateChange", "(II)V");

    JNI_TRACE("ssl=%p info_callback calling onSSLStateChange", ssl);
    env->CallVoidMethod(sslHandshakeCallbacks, methodID, type, value);

    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p info_callback exception", ssl);
    }
    JNI_TRACE("ssl=%p info_callback completed", ssl);
}

/**
 * Call back to ask for a certificate. There are three possible exit codes:
 *
 * 1 is success.
 * 0 is error.
 * -1 is to pause the handshake to continue from the same place later.
 */
static int cert_cb(SSL* ssl, CONSCRYPT_UNUSED void* arg) {
    JNI_TRACE("ssl=%p cert_cb", ssl);

    // cert_cb is called for both clients and servers, but we are only
    // interested in client certificates.
    if (SSL_is_server(ssl)) {
        JNI_TRACE("ssl=%p cert_cb not a client => 1", ssl);
        return 1;
    }

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        CONSCRYPT_LOG_ERROR("AppData->env missing in cert_cb");
        JNI_TRACE("ssl=%p cert_cb env error => 0", ssl);
        return 0;
    }
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p cert_cb already pending exception => 0", ssl);
        return 0;
    }
    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;

    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID = env->GetMethodID(cls, "clientCertificateRequested", "([B[I[[B)V");

    // Call Java callback which can reconfigure the client certificate.
    const uint8_t* ctype = nullptr;
    size_t ctype_num = SSL_get0_certificate_types(ssl, &ctype);
    const uint16_t* sigalgs = nullptr;
    size_t sigalgs_num = SSL_get0_peer_verify_algorithms(ssl, &sigalgs);
    ScopedLocalRef<jobjectArray> issuers(
            env, CryptoBuffersToObjectArray(env, SSL_get0_server_requested_CAs(ssl)));
    if (issuers.get() == nullptr) {
        return 0;
    }

    if (conscrypt::trace::kWithJniTrace) {
        for (size_t i = 0; i < ctype_num; i++) {
            JNI_TRACE("ssl=%p clientCertificateRequested keyTypes[%zu]=%d", ssl, i, ctype[i]);
        }
        for (size_t i = 0; i < sigalgs_num; i++) {
            JNI_TRACE("ssl=%p clientCertificateRequested sigAlgs[%zu]=%d", ssl, i, sigalgs[i]);
        }
    }

    jbyteArray keyTypes = env->NewByteArray(static_cast<jsize>(ctype_num));
    if (keyTypes == nullptr) {
        JNI_TRACE("ssl=%p cert_cb keyTypes == null => 0", ssl);
        return 0;
    }
    env->SetByteArrayRegion(keyTypes, 0, static_cast<jsize>(ctype_num),
                            reinterpret_cast<const jbyte*>(ctype));

    jintArray signatureAlgs = env->NewIntArray(static_cast<jsize>(sigalgs_num));
    if (signatureAlgs == nullptr) {
        JNI_TRACE("ssl=%p cert_cb signatureAlgs == null => 0", ssl);
        return 0;
    }
    {
        ScopedIntArrayRW sigAlgsRW(env, signatureAlgs);
        for (size_t i = 0; i < sigalgs_num; i++) {
            sigAlgsRW[i] = sigalgs[i];
        }
    }

    JNI_TRACE(
            "ssl=%p clientCertificateRequested calling clientCertificateRequested "
            "keyTypes=%p signatureAlgs=%p issuers=%p",
            ssl, keyTypes, signatureAlgs, issuers.get());
    env->CallVoidMethod(sslHandshakeCallbacks, methodID, keyTypes, signatureAlgs, issuers.get());

    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p cert_cb exception => 0", ssl);
        return 0;
    }

    JNI_TRACE("ssl=%p cert_cb => 1", ssl);
    return 1;
}

static enum ssl_select_cert_result_t select_certificate_cb(const SSL_CLIENT_HELLO* client_hello) {
    SSL* ssl = client_hello->ssl;
    JNI_TRACE("ssl=%p select_certificate_cb_callback", ssl);

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        CONSCRYPT_LOG_ERROR("AppData->env missing in select_certificate_cb");
        JNI_TRACE("ssl=%p select_certificate_cb env error", ssl);
        return ssl_select_cert_error;
    }
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p select_certificate_cb already pending exception", ssl);
        return ssl_select_cert_error;
    }

    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;
    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID = env->GetMethodID(cls, "serverCertificateRequested", "()V");

    JNI_TRACE("ssl=%p select_certificate_cb calling serverCertificateRequested", ssl);
    env->CallVoidMethod(sslHandshakeCallbacks, methodID);

    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p select_certificate_cb exception", ssl);
        return ssl_select_cert_error;
    }
    JNI_TRACE("ssl=%p select_certificate_cb completed", ssl);
    return ssl_select_cert_success;
}

/**
 * Pre-Shared Key (PSK) client callback.
 */
static unsigned int psk_client_callback(SSL* ssl, const char* hint, char* identity,
                                        unsigned int max_identity_len, unsigned char* psk,
                                        unsigned int max_psk_len) {
    JNI_TRACE("ssl=%p psk_client_callback", ssl);

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        CONSCRYPT_LOG_ERROR("AppData->env missing in psk_client_callback");
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
    ScopedLocalRef<jstring> identityHintJava(env,
                                             (hint != nullptr) ? env->NewStringUTF(hint) : nullptr);
    ScopedLocalRef<jbyteArray> identityJava(
            env, env->NewByteArray(static_cast<jsize>(max_identity_len)));
    if (identityJava.get() == nullptr) {
        JNI_TRACE("ssl=%p psk_client_callback failed to allocate identity bufffer", ssl);
        return 0;
    }
    ScopedLocalRef<jbyteArray> keyJava(env, env->NewByteArray(static_cast<jsize>(max_psk_len)));
    if (keyJava.get() == nullptr) {
        JNI_TRACE("ssl=%p psk_client_callback failed to allocate key bufffer", ssl);
        return 0;
    }
    jint keyLen = env->CallIntMethod(sslHandshakeCallbacks, methodID, identityHintJava.get(),
                                     identityJava.get(), keyJava.get());
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p psk_client_callback exception", ssl);
        return 0;
    }
    if (keyLen <= 0) {
        JNI_TRACE("ssl=%p psk_client_callback failed to get key", ssl);
        return 0;
    } else if ((unsigned int)keyLen > max_psk_len) {
        JNI_TRACE("ssl=%p psk_client_callback got key which is too long", ssl);
        return 0;
    }
    ScopedByteArrayRO keyJavaRo(env, keyJava.get());
    if (keyJavaRo.get() == nullptr) {
        JNI_TRACE("ssl=%p psk_client_callback failed to get key bytes", ssl);
        return 0;
    }
    memcpy(psk, keyJavaRo.get(), static_cast<size_t>(keyLen));

    ScopedByteArrayRO identityJavaRo(env, identityJava.get());
    if (identityJavaRo.get() == nullptr) {
        JNI_TRACE("ssl=%p psk_client_callback failed to get identity bytes", ssl);
        return 0;
    }
    memcpy(identity, identityJavaRo.get(), max_identity_len);

    JNI_TRACE("ssl=%p psk_client_callback completed", ssl);
    return static_cast<unsigned int>(keyLen);
}

/**
 * Pre-Shared Key (PSK) server callback.
 */
static unsigned int psk_server_callback(SSL* ssl, const char* identity, unsigned char* psk,
                                        unsigned int max_psk_len) {
    JNI_TRACE("ssl=%p psk_server_callback", ssl);

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        CONSCRYPT_LOG_ERROR("AppData->env missing in psk_server_callback");
        JNI_TRACE("ssl=%p psk_server_callback env error", ssl);
        return 0;
    }
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p psk_server_callback already pending exception", ssl);
        return 0;
    }

    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;
    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID = env->GetMethodID(cls, "serverPSKKeyRequested",
                                          "(Ljava/lang/String;Ljava/lang/String;[B)I");
    JNI_TRACE("ssl=%p psk_server_callback calling serverPSKKeyRequested", ssl);
    const char* identityHint = SSL_get_psk_identity_hint(ssl);
    ScopedLocalRef<jstring> identityHintJava(
            env, (identityHint != nullptr) ? env->NewStringUTF(identityHint) : nullptr);
    ScopedLocalRef<jstring> identityJava(
            env, (identity != nullptr) ? env->NewStringUTF(identity) : nullptr);
    ScopedLocalRef<jbyteArray> keyJava(env, env->NewByteArray(static_cast<jsize>(max_psk_len)));
    if (keyJava.get() == nullptr) {
        JNI_TRACE("ssl=%p psk_server_callback failed to allocate key bufffer", ssl);
        return 0;
    }
    jint keyLen = env->CallIntMethod(sslHandshakeCallbacks, methodID, identityHintJava.get(),
                                     identityJava.get(), keyJava.get());
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p psk_server_callback exception", ssl);
        return 0;
    }
    if (keyLen <= 0) {
        JNI_TRACE("ssl=%p psk_server_callback failed to get key", ssl);
        return 0;
    } else if ((unsigned int)keyLen > max_psk_len) {
        JNI_TRACE("ssl=%p psk_server_callback got key which is too long", ssl);
        return 0;
    }
    ScopedByteArrayRO keyJavaRo(env, keyJava.get());
    if (keyJavaRo.get() == nullptr) {
        JNI_TRACE("ssl=%p psk_server_callback failed to get key bytes", ssl);
        return 0;
    }
    memcpy(psk, keyJavaRo.get(), static_cast<size_t>(keyLen));

    JNI_TRACE("ssl=%p psk_server_callback completed", ssl);
    return static_cast<unsigned int>(keyLen);
}

static int new_session_callback(SSL* ssl, SSL_SESSION* session) {
    JNI_TRACE("ssl=%p new_session_callback session=%p", ssl, session);

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        CONSCRYPT_LOG_ERROR("AppData->env missing in new_session_callback");
        JNI_TRACE("ssl=%p new_session_callback env error", ssl);
        return 0;
    }
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p new_session_callback already pending exception", ssl);
        return 0;
    }

    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;
    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID = env->GetMethodID(cls, "onNewSessionEstablished", "(J)V");
    JNI_TRACE("ssl=%p new_session_callback calling onNewSessionEstablished", ssl);
    env->CallVoidMethod(sslHandshakeCallbacks, methodID, reinterpret_cast<jlong>(session));
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p new_session_callback exception cleared", ssl);
        env->ExceptionClear();
    }
    JNI_TRACE("ssl=%p new_session_callback completed", ssl);

    // Always returning 0 (not taking ownership). The Java code is responsible for incrementing
    // the reference count.
    return 0;
}

static SSL_SESSION* server_session_requested_callback(SSL* ssl, const uint8_t* id, int id_len,
                                                      int* out_copy) {
    JNI_TRACE("ssl=%p server_session_requested_callback", ssl);

    // Always set to out_copy to zero. The Java callback will be responsible for incrementing
    // the reference count (and any required synchronization).
    *out_copy = 0;

    AppData* appData = toAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        CONSCRYPT_LOG_ERROR("AppData->env missing in server_session_requested_callback");
        JNI_TRACE("ssl=%p server_session_requested_callback env error", ssl);
        return 0;
    }
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p server_session_requested_callback already pending exception", ssl);
        return 0;
    }

    // Copy the ID to a byte[].
    jbyteArray id_array = env->NewByteArray(static_cast<jsize>(id_len));
    if (id_array == nullptr) {
        JNI_TRACE("ssl=%p id_array bytes == null => 0", ssl);
        return 0;
    }
    env->SetByteArrayRegion(id_array, 0, static_cast<jsize>(id_len),
                            reinterpret_cast<const jbyte*>(id));

    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;
    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID = env->GetMethodID(cls, "serverSessionRequested", "([B)J");
    JNI_TRACE("ssl=%p server_session_requested_callback calling serverSessionRequested", ssl);
    jlong ssl_session_address = env->CallLongMethod(sslHandshakeCallbacks, methodID, id_array);
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p server_session_requested_callback exception cleared", ssl);
        env->ExceptionClear();
    }
    SSL_SESSION* ssl_session_ptr =
            reinterpret_cast<SSL_SESSION*>(static_cast<uintptr_t>(ssl_session_address));
    JNI_TRACE("ssl=%p server_session_requested_callback completed => %p", ssl, ssl_session_ptr);
    return ssl_session_ptr;
}

static jint NativeCrypto_EVP_has_aes_hardware(JNIEnv* env, jclass) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    int ret = 0;
    ret = EVP_has_aes_hardware();
    JNI_TRACE("EVP_has_aes_hardware => %d", ret);
    return ret;
}

static void debug_print_session_key(const SSL* ssl, const char* line) {
    JNI_TRACE_KEYS("ssl=%p KEY_LINE: %s", ssl, line);
}

static void debug_print_packet_data(const SSL* ssl, char direction, const char* data, size_t len) {
    static constexpr size_t kDataWidth = 16;

    struct timeval tv;
    if (gettimeofday(&tv, NULL)) {
        CONSCRYPT_LOG(LOG_INFO, LOG_TAG "-jni",
                      "debug_print_packet_data: could not get time of day");
        return;
    }

    // Packet preamble for text2pcap
    CONSCRYPT_LOG(LOG_INFO, LOG_TAG "-jni", "ssl=%p SSL_DATA: %c %ld.%06ld", ssl, direction,
                  tv.tv_sec, static_cast<long>(tv.tv_usec));  // NOLINT(runtime/int)

    char out[kDataWidth * 3 + 1];
    for (size_t i = 0; i < len; i += kDataWidth) {
        size_t n = len - i < kDataWidth ? len - i : kDataWidth;

        for (size_t j = 0, offset = 0; j < n; j++, offset += 3) {
            int ret = snprintf(out + offset, sizeof(out) - offset, "%02x ", data[i + j] & 0xFF);
            if (ret < 0 || static_cast<size_t>(ret) >= sizeof(out) - offset) {
                CONSCRYPT_LOG(LOG_INFO, LOG_TAG "-jni",
                              "debug_print_packet_data failed to output %d", ret);
                return;
            }
        }

        // Print out packet data in format understood by text2pcap
        CONSCRYPT_LOG(LOG_INFO, LOG_TAG "-jni", "ssl=%p SSL_DATA: %06zx %s", ssl, i, out);
    }

    // Conclude the packet data
    CONSCRYPT_LOG(LOG_INFO, LOG_TAG "-jni", "ssl=%p SSL_DATA: %06zx", ssl, len);
}

/*
 * public static native int SSL_CTX_new();
 */
static jlong NativeCrypto_SSL_CTX_new(JNIEnv* env, jclass) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    bssl::UniquePtr<SSL_CTX> sslCtx(SSL_CTX_new(TLS_with_buffers_method()));
    if (sslCtx.get() == nullptr) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "SSL_CTX_new");
        return 0;
    }
    SSL_CTX_set_options(
            sslCtx.get(),
            SSL_OP_ALL
                    // We also disable session tickets for better compatibility b/2682876
                    | SSL_OP_NO_TICKET
                    // We also disable compression for better compatibility b/2710492 b/2710497
                    | SSL_OP_NO_COMPRESSION
                    // Generate a fresh ECDH keypair for each key exchange.
                    | SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_min_proto_version(sslCtx.get(), TLS1_VERSION);
    SSL_CTX_set_max_proto_version(sslCtx.get(), TLS1_2_VERSION);

    uint32_t mode = SSL_CTX_get_mode(sslCtx.get());
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

    // Enable False Start.
    mode |= SSL_MODE_ENABLE_FALSE_START;

    // We need to enable SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER as the memory address may change
    // between
    // calls to wrap(...).
    // See https://github.com/netty/netty-tcnative/issues/100
    mode |= SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;

    SSL_CTX_set_mode(sslCtx.get(), mode);

    SSL_CTX_set_info_callback(sslCtx.get(), info_callback);
    SSL_CTX_set_cert_cb(sslCtx.get(), cert_cb, nullptr);
    SSL_CTX_set_select_certificate_cb(sslCtx.get(), select_certificate_cb);
    if (conscrypt::trace::kWithJniTraceKeys) {
        SSL_CTX_set_keylog_callback(sslCtx.get(), debug_print_session_key);
    }

    // By default BoringSSL will cache in server mode, but we want to get
    // notified of new sessions being created in client mode. We set
    // SSL_SESS_CACHE_BOTH in order to get the callback in client mode, but
    // ignore it in server mode in favor of the internal cache.
    SSL_CTX_set_session_cache_mode(sslCtx.get(), SSL_SESS_CACHE_BOTH);
    SSL_CTX_sess_set_new_cb(sslCtx.get(), new_session_callback);
    SSL_CTX_sess_set_get_cb(sslCtx.get(), server_session_requested_callback);

    JNI_TRACE("NativeCrypto_SSL_CTX_new => %p", sslCtx.get());
    return (jlong)sslCtx.release();
}

/**
 * public static native void SSL_CTX_free(long ssl_ctx)
 */
static void NativeCrypto_SSL_CTX_free(JNIEnv* env, jclass, jlong ssl_ctx_address,
                                      CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_CTX* ssl_ctx = to_SSL_CTX(env, ssl_ctx_address, true);
    JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_CTX_free", ssl_ctx);
    if (ssl_ctx == nullptr) {
        return;
    }
    SSL_CTX_free(ssl_ctx);
}

static void NativeCrypto_SSL_CTX_set_session_id_context(JNIEnv* env, jclass, jlong ssl_ctx_address,
                                                        CONSCRYPT_UNUSED jobject holder,
                                                        jbyteArray sid_ctx) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_CTX* ssl_ctx = to_SSL_CTX(env, ssl_ctx_address, true);
    JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_CTX_set_session_id_context sid_ctx=%p", ssl_ctx,
              sid_ctx);
    if (ssl_ctx == nullptr) {
        return;
    }

    ScopedByteArrayRO buf(env, sid_ctx);
    if (buf.get() == nullptr) {
        JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_CTX_set_session_id_context => threw exception",
                  ssl_ctx);
        return;
    }

    unsigned int length = static_cast<unsigned int>(buf.size());
    if (length > SSL_MAX_SSL_SESSION_ID_LENGTH) {
        conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                           "length > SSL_MAX_SSL_SESSION_ID_LENGTH");
        JNI_TRACE("NativeCrypto_SSL_CTX_set_session_id_context => length = %d", length);
        return;
    }
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(buf.get());
    int result = SSL_CTX_set_session_id_context(ssl_ctx, bytes, length);
    if (result == 0) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(
                env, "NativeCrypto_SSL_CTX_set_session_id_context");
        return;
    }
    JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_CTX_set_session_id_context => ok", ssl_ctx);
}

static jlong NativeCrypto_SSL_CTX_set_timeout(JNIEnv* env, jclass, jlong ssl_ctx_address,
                                              CONSCRYPT_UNUSED jobject holder, jlong seconds) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_CTX* ssl_ctx = to_SSL_CTX(env, ssl_ctx_address, true);
    JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_CTX_set_timeout seconds=%d", ssl_ctx, (int)seconds);
    if (ssl_ctx == nullptr) {
        return 0L;
    }

    return SSL_CTX_set_timeout(ssl_ctx, static_cast<uint32_t>(seconds));
}

/**
 * public static native int SSL_new(long ssl_ctx) throws SSLException;
 */
static jlong NativeCrypto_SSL_new(JNIEnv* env, jclass, jlong ssl_ctx_address,
                                  CONSCRYPT_UNUSED jobject holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_CTX* ssl_ctx = to_SSL_CTX(env, ssl_ctx_address, true);
    JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_new", ssl_ctx);
    if (ssl_ctx == nullptr) {
        return 0;
    }
    bssl::UniquePtr<SSL> ssl(SSL_new(ssl_ctx));
    if (ssl.get() == nullptr) {
        conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, nullptr, SSL_ERROR_NONE,
                                                           "Unable to create SSL structure");
        JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_new => null", ssl_ctx);
        return 0;
    }

    /*
     * Create our special application data.
     */
    AppData* appData = AppData::create();
    if (appData == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to create application data");
        ERR_clear_error();
        JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_new appData => 0", ssl_ctx);
        return 0;
    }
    SSL_set_app_data(ssl.get(), reinterpret_cast<char*>(appData));

    SSL_set_custom_verify(ssl.get(), SSL_VERIFY_PEER, cert_verify_callback);

    JNI_TRACE("ssl_ctx=%p NativeCrypto_SSL_new => ssl=%p appData=%p", ssl_ctx, ssl.get(), appData);
    return (jlong)ssl.release();
}

static void NativeCrypto_SSL_enable_tls_channel_id(JNIEnv* env, jclass, jlong ssl_address,
                                                   CONSCRYPT_UNUSED CONSCRYPT_UNUSED jobject
                                                           ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_enable_tls_channel_id", ssl);
    if (ssl == nullptr) {
        return;
    }

    // NOLINTNEXTLINE(runtime/int)
    long ret = SSL_enable_tls_channel_id(ssl);
    if (ret != 1L) {
        CONSCRYPT_LOG_ERROR("%s", ERR_error_string(ERR_peek_error(), nullptr));
        conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE,
                                                           "Error enabling Channel ID");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_enable_tls_channel_id => error", ssl);
        return;
    }
}

static jbyteArray NativeCrypto_SSL_get_tls_channel_id(JNIEnv* env, jclass, jlong ssl_address,
                                                      CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_tls_channel_id", ssl);
    if (ssl == nullptr) {
        return nullptr;
    }

    // Channel ID is 64 bytes long. Unfortunately, OpenSSL doesn't declare this length
    // as a constant anywhere.
    jbyteArray javaBytes = env->NewByteArray(64);
    ScopedByteArrayRW bytes(env, javaBytes);
    if (bytes.get() == nullptr) {
        JNI_TRACE("NativeCrypto_SSL_get_tls_channel_id(%p) => null", ssl);
        return nullptr;
    }

    unsigned char* tmp = reinterpret_cast<unsigned char*>(bytes.get());
    // Unfortunately, the SSL_get_tls_channel_id method below always returns 64 (upon success)
    // regardless of the number of bytes copied into the output buffer "tmp". Thus, the correctness
    // of this code currently relies on the "tmp" buffer being exactly 64 bytes long.
    size_t ret = SSL_get_tls_channel_id(ssl, tmp, 64);
    if (ret == 0) {
        // Channel ID either not set or did not verify
        JNI_TRACE("NativeCrypto_SSL_get_tls_channel_id(%p) => not available", ssl);
        return nullptr;
    } else if (ret != 64) {
        CONSCRYPT_LOG_ERROR("%s", ERR_error_string(ERR_peek_error(), nullptr));
        conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE,
                                                           "Error getting Channel ID");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_get_tls_channel_id => error, returned %zd", ssl, ret);
        return nullptr;
    }

    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_tls_channel_id() => %p", ssl, javaBytes);
    return javaBytes;
}

static void NativeCrypto_SSL_set1_tls_channel_id(JNIEnv* env, jclass, jlong ssl_address,
                                                 CONSCRYPT_UNUSED jobject ssl_holder,
                                                 jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p SSL_set1_tls_channel_id privatekey=%p", ssl, pkeyRef);
    if (ssl == nullptr) {
        return;
    }

    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    if (pkey == nullptr) {
        JNI_TRACE("ssl=%p SSL_set1_tls_channel_id => pkey == null", ssl);
        return;
    }

    // NOLINTNEXTLINE(runtime/int)
    long ret = SSL_set1_tls_channel_id(ssl, pkey);

    if (ret != 1L) {
        CONSCRYPT_LOG_ERROR("%s", ERR_error_string(ERR_peek_error(), nullptr));
        conscrypt::jniutil::throwSSLExceptionWithSslErrors(
                env, ssl, SSL_ERROR_NONE, "Error setting private key for Channel ID");
        JNI_TRACE("ssl=%p SSL_set1_tls_channel_id => error", ssl);
        return;
    }

    JNI_TRACE("ssl=%p SSL_set1_tls_channel_id => ok", ssl);
}

static void NativeCrypto_setLocalCertsAndPrivateKey(JNIEnv* env, jclass, jlong ssl_address,
                                                    CONSCRYPT_UNUSED jobject ssl_holder,
                                                    jobjectArray encodedCertificatesJava,
                                                    jobject pkeyRef) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_chain_and_key certificates=%p, privateKey=%p", ssl,
              encodedCertificatesJava, pkeyRef);
    if (ssl == nullptr) {
        return;
    }
    if (encodedCertificatesJava == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "certificates == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_chain_and_key => certificates == null", ssl);
        return;
    }
    size_t numCerts = static_cast<size_t>(env->GetArrayLength(encodedCertificatesJava));
    if (numCerts == 0) {
        conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                           "certificates.length == 0");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_chain_and_key => certificates.length == 0", ssl);
        return;
    }
    if (pkeyRef == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "privateKey == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_chain_and_key => privateKey == null", ssl);
        return;
    }

    // Get the private key.
    EVP_PKEY* pkey = fromContextObject<EVP_PKEY>(env, pkeyRef);
    if (pkey == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "pkey == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_chain_and_key => pkey == null", ssl);
        return;
    }

    // Copy the certificates.
    std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> certBufferRefs(numCerts);
    std::vector<CRYPTO_BUFFER*> certBuffers(numCerts);
    for (size_t i = 0; i < numCerts; ++i) {
        ScopedLocalRef<jbyteArray> certArray(
                env, reinterpret_cast<jbyteArray>(
                             env->GetObjectArrayElement(encodedCertificatesJava, i)));
        certBufferRefs[i] = ByteArrayToCryptoBuffer(env, certArray.get(), nullptr);
        if (!certBufferRefs[i]) {
            return;
        }
        certBuffers[i] = certBufferRefs[i].get();
    }

    if (!SSL_set_chain_and_key(ssl, certBuffers.data(), numCerts, pkey, nullptr)) {
        conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE,
                                                           "Error configuring certificate");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_chain_and_key => error", ssl);
        return;
    }
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_chain_and_key => ok", ssl);
}

static void NativeCrypto_SSL_set_client_CA_list(JNIEnv* env, jclass, jlong ssl_address,
                                                CONSCRYPT_UNUSED jobject ssl_holder,
                                                jobjectArray principals) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list principals=%p", ssl, principals);
    if (ssl == nullptr) {
        return;
    }

    if (principals == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "principals == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => principals == null", ssl);
        return;
    }

    int length = env->GetArrayLength(principals);
    if (length == 0) {
        conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                           "principals.length == 0");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => principals.length == 0", ssl);
        return;
    }

    bssl::UniquePtr<STACK_OF(CRYPTO_BUFFER)> principalsStack(sk_CRYPTO_BUFFER_new_null());
    if (principalsStack.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate principal stack");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => stack allocation error", ssl);
        return;
    }
    for (int i = 0; i < length; i++) {
        ScopedLocalRef<jbyteArray> principal(
                env, reinterpret_cast<jbyteArray>(env->GetObjectArrayElement(principals, i)));
        bssl::UniquePtr<CRYPTO_BUFFER> buf = ByteArrayToCryptoBuffer(env, principal.get(), nullptr);
        if (!buf) {
            return;
        }
        if (!sk_CRYPTO_BUFFER_push(principalsStack.get(), buf.get())) {
            conscrypt::jniutil::throwOutOfMemory(env, "Unable to push principal");
            JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => principal push error", ssl);
            return;
        }
        OWNERSHIP_TRANSFERRED(buf);
    }

    SSL_set0_client_CAs(ssl, principalsStack.release());
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_client_CA_list => ok", ssl);
}

/**
 * public static native long SSL_set_mode(long ssl, long mode);
 */
static jlong NativeCrypto_SSL_set_mode(JNIEnv* env, jclass, jlong ssl_address,
                                       CONSCRYPT_UNUSED jobject ssl_holder, jlong mode) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_mode mode=0x%llx", ssl, (long long)mode);
    if (ssl == nullptr) {
        return 0;
    }
    jlong result = static_cast<jlong>(SSL_set_mode(ssl, static_cast<uint32_t>(mode)));
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_mode => 0x%lx", ssl, (long)result);
    return result;
}

/**
 * public static native long SSL_set_options(long ssl, long options);
 */
static jlong NativeCrypto_SSL_set_options(JNIEnv* env, jclass, jlong ssl_address,
                                          CONSCRYPT_UNUSED jobject ssl_holder, jlong options) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_options options=0x%llx", ssl, (long long)options);
    if (ssl == nullptr) {
        return 0;
    }
    jlong result = static_cast<jlong>(SSL_set_options(ssl, static_cast<uint32_t>(options)));
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_options => 0x%lx", ssl, (long)result);
    return result;
}

/**
 * public static native long SSL_clear_options(long ssl, long options);
 */
static jlong NativeCrypto_SSL_clear_options(JNIEnv* env, jclass, jlong ssl_address,
                                            CONSCRYPT_UNUSED jobject ssl_holder, jlong options) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("ssl=%p NativeCrypto_SSL_clear_options options=0x%llx", ssl, (long long)options);
    if (ssl == nullptr) {
        return 0;
    }
    jlong result = static_cast<jlong>(SSL_clear_options(ssl, static_cast<uint32_t>(options)));
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("ssl=%p NativeCrypto_SSL_clear_options => 0x%lx", ssl, (long)result);
    return result;
}

static jint NativeCrypto_SSL_set_protocol_versions(JNIEnv* env, jclass, jlong ssl_address,
                                                   CONSCRYPT_UNUSED jobject ssl_holder,
                                                   jint min_version, jint max_version) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_protocol_versions min=0x%x max=0x%x", ssl, min_version,
              max_version);
    if (ssl == nullptr) {
        return 0;
    }
    int min_result = SSL_set_min_proto_version(ssl, static_cast<uint16_t>(min_version));
    int max_result = SSL_set_max_proto_version(ssl, static_cast<uint16_t>(max_version));
    // Return failure if either call failed.
    int result = 1;
    if (!min_result || !max_result) {
        result = 0;
        // The only possible error is an invalid version, so we don't need the details.
        ERR_clear_error();
    }
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_protocol_versions => (min: %d, max: %d) == %d", ssl,
              min_result, max_result, result);
    return result;
}

/**
 * public static native void SSL_enable_signed_cert_timestamps(long ssl);
 */
static void NativeCrypto_SSL_enable_signed_cert_timestamps(JNIEnv* env, jclass, jlong ssl_address,
                                                           CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_enable_signed_cert_timestamps", ssl);
    if (ssl == nullptr) {
        return;
    }

    SSL_enable_signed_cert_timestamps(ssl);
}

/**
 * public static native byte[] SSL_get_signed_cert_timestamp_list(long ssl);
 */
static jbyteArray NativeCrypto_SSL_get_signed_cert_timestamp_list(
        JNIEnv* env, jclass, jlong ssl_address, CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_signed_cert_timestamp_list", ssl);
    if (ssl == nullptr) {
        return nullptr;
    }

    const uint8_t* data;
    size_t data_len;
    SSL_get0_signed_cert_timestamp_list(ssl, &data, &data_len);

    if (data_len == 0) {
        JNI_TRACE("NativeCrypto_SSL_get_signed_cert_timestamp_list(%p) => null", ssl);
        return nullptr;
    }

    jbyteArray result = env->NewByteArray(static_cast<jsize>(data_len));
    if (result != nullptr) {
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(data_len), (const jbyte*)data);
    }
    return result;
}

/*
 * public static native void SSL_set_signed_cert_timestamp_list(long ssl, byte[] response);
 */
static void NativeCrypto_SSL_set_signed_cert_timestamp_list(JNIEnv* env, jclass, jlong ssl_address,
                                                            CONSCRYPT_UNUSED jobject ssl_holder,
                                                            jbyteArray list) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_signed_cert_timestamp_list", ssl);
    if (ssl == nullptr) {
        return;
    }

    ScopedByteArrayRO listBytes(env, list);
    if (listBytes.get() == nullptr) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_signed_cert_timestamp_list => list == null", ssl);
        return;
    }

    if (!SSL_set_signed_cert_timestamp_list(ssl, reinterpret_cast<const uint8_t*>(listBytes.get()),
                                            listBytes.size())) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_signed_cert_timestamp_list => fail", ssl);
    } else {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_signed_cert_timestamp_list => ok", ssl);
    }
}

/*
 * public static native void SSL_enable_ocsp_stapling(long ssl);
 */
static void NativeCrypto_SSL_enable_ocsp_stapling(JNIEnv* env, jclass, jlong ssl_address,
                                                  CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_enable_ocsp_stapling", ssl);
    if (ssl == nullptr) {
        return;
    }

    SSL_enable_ocsp_stapling(ssl);
}

/*
 * public static native byte[] SSL_get_ocsp_response(long ssl);
 */
static jbyteArray NativeCrypto_SSL_get_ocsp_response(JNIEnv* env, jclass, jlong ssl_address,
                                                     CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_ocsp_response", ssl);
    if (ssl == nullptr) {
        return nullptr;
    }

    const uint8_t* data;
    size_t data_len;
    SSL_get0_ocsp_response(ssl, &data, &data_len);

    if (data_len == 0) {
        JNI_TRACE("NativeCrypto_SSL_get_ocsp_response(%p) => null", ssl);
        return nullptr;
    }

    ScopedLocalRef<jbyteArray> byteArray(env, env->NewByteArray(static_cast<jsize>(data_len)));
    if (byteArray.get() == nullptr) {
        JNI_TRACE("NativeCrypto_SSL_get_ocsp_response(%p) => creating byte array failed", ssl);
        return nullptr;
    }

    env->SetByteArrayRegion(byteArray.get(), 0, static_cast<jsize>(data_len), (const jbyte*)data);
    JNI_TRACE("NativeCrypto_SSL_get_ocsp_response(%p) => %p [size=%zd]", ssl, byteArray.get(),
              data_len);

    return byteArray.release();
}

/*
 * public static native void SSL_set_ocsp_response(long ssl, byte[] response);
 */
static void NativeCrypto_SSL_set_ocsp_response(JNIEnv* env, jclass, jlong ssl_address,
                                               CONSCRYPT_UNUSED jobject ssl_holder,
                                               jbyteArray response) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_ocsp_response", ssl);
    if (ssl == nullptr) {
        return;
    }

    ScopedByteArrayRO responseBytes(env, response);
    if (responseBytes.get() == nullptr) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_ocsp_response => response == null", ssl);
        return;
    }

    if (!SSL_set_ocsp_response(ssl, reinterpret_cast<const uint8_t*>(responseBytes.get()),
                               responseBytes.size())) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_ocsp_response => fail", ssl);
    } else {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_ocsp_response => ok", ssl);
    }
}

// All verify_data values are currently 12 bytes long, but cipher suites are allowed
// to customize the length of their verify_data (with a default of 12 bytes).  We accept
// up to 16 bytes so that we can check that the results are actually 12 bytes long in
// tests and update this value if necessary.
const size_t MAX_TLS_UNIQUE_LENGTH = 16;

static jbyteArray NativeCrypto_SSL_get_tls_unique(JNIEnv* env, jclass, jlong ssl_address,
                                                  CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_tls_unique", ssl);
    if (ssl == nullptr) {
        return nullptr;
    }

    uint8_t data[MAX_TLS_UNIQUE_LENGTH];
    size_t data_len;
    int ret = SSL_get_tls_unique(ssl, data, &data_len, MAX_TLS_UNIQUE_LENGTH);

    if (!ret || data_len == 0) {
        JNI_TRACE("NativeCrypto_SSL_get_tls_unique(%p) => null", ssl);
        return nullptr;
    }

    ScopedLocalRef<jbyteArray> byteArray(env, env->NewByteArray(static_cast<jsize>(data_len)));
    if (byteArray.get() == nullptr) {
        JNI_TRACE("NativeCrypto_SSL_get_tls_unique(%p) => creating byte array failed", ssl);
        return nullptr;
    }

    env->SetByteArrayRegion(byteArray.get(), 0, static_cast<jsize>(data_len), (const jbyte*)data);
    JNI_TRACE("NativeCrypto_SSL_get_tls_unique(%p) => %p [size=%zd]", ssl, byteArray.get(),
              data_len);

    return byteArray.release();
}

static jbyteArray NativeCrypto_SSL_export_keying_material(JNIEnv* env, jclass, jlong ssl_address,
                                                          CONSCRYPT_UNUSED jobject ssl_holder,
                                                          jbyteArray label, jbyteArray context,
                                                          jint num_bytes) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_export_keying_material", ssl);
    if (ssl == nullptr) {
        return nullptr;
    }
    ScopedByteArrayRO labelBytes(env, label);
    if (labelBytes.get() == nullptr) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_export_keying_material label == null => exception", ssl);
        return nullptr;
    }
    std::unique_ptr<uint8_t[]> out(new uint8_t[num_bytes]);
    int ret;
    if (context == nullptr) {
        ret = SSL_export_keying_material(ssl, out.get(), num_bytes,
                        reinterpret_cast<const char*>(labelBytes.get()), labelBytes.size(),
                        nullptr, 0, 0);
    } else {
        ScopedByteArrayRO contextBytes(env, context);
        if (contextBytes.get() == nullptr) {
            JNI_TRACE("ssl=%p NativeCrypto_SSL_export_keying_material context == null => exception",
                      ssl);
            return nullptr;
        }
        ret = SSL_export_keying_material(
                ssl, out.get(), num_bytes, reinterpret_cast<const char*>(labelBytes.get()),
                labelBytes.size(), reinterpret_cast<const uint8_t*>(contextBytes.get()),
                contextBytes.size(), 1);
    }
    if (!ret) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "SSL_export_keying_material",
                conscrypt::jniutil::throwSSLExceptionStr);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_export_keying_material => exception", ssl);
        return nullptr;
    }
    jbyteArray result = env->NewByteArray(static_cast<jsize>(num_bytes));
    if (result == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Could not create result array");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_export_keying_material => could not create array", ssl);
        return nullptr;
    }
    const jbyte* src = reinterpret_cast<jbyte*>(out.get());
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(num_bytes), src);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_export_keying_material => success", ssl);
    return result;
}

static void NativeCrypto_SSL_use_psk_identity_hint(JNIEnv* env, jclass, jlong ssl_address,
                                                   CONSCRYPT_UNUSED jobject ssl_holder,
                                                   jstring identityHintJava) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_use_psk_identity_hint identityHint=%p", ssl,
              identityHintJava);
    if (ssl == nullptr) {
        return;
    }

    int ret;
    if (identityHintJava == nullptr) {
        ret = SSL_use_psk_identity_hint(ssl, nullptr);
    } else {
        ScopedUtfChars identityHint(env, identityHintJava);
        if (identityHint.c_str() == nullptr) {
            conscrypt::jniutil::throwSSLExceptionStr(env, "Failed to obtain identityHint bytes");
            return;
        }
        ret = SSL_use_psk_identity_hint(ssl, identityHint.c_str());
    }

    if (ret != 1) {
        int sslErrorCode = SSL_get_error(ssl, ret);
        conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, sslErrorCode,
                                                           "Failed to set PSK identity hint");
    }
}

static void NativeCrypto_set_SSL_psk_client_callback_enabled(JNIEnv* env, jclass, jlong ssl_address,
                                                             CONSCRYPT_UNUSED jobject ssl_holder,
                                                             jboolean enabled) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_set_SSL_psk_client_callback_enabled(%d)", ssl, enabled);
    if (ssl == nullptr) {
        return;
    }

    SSL_set_psk_client_callback(ssl, (enabled) ? psk_client_callback : nullptr);
}

static void NativeCrypto_set_SSL_psk_server_callback_enabled(JNIEnv* env, jclass, jlong ssl_address,
                                                             CONSCRYPT_UNUSED jobject ssl_holder,
                                                             jboolean enabled) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_set_SSL_psk_server_callback_enabled(%d)", ssl, enabled);
    if (ssl == nullptr) {
        return;
    }

    SSL_set_psk_server_callback(ssl, (enabled) ? psk_server_callback : nullptr);
}

static jlongArray NativeCrypto_SSL_get_ciphers(JNIEnv* env, jclass, jlong ssl_address,
                                               CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_ciphers", ssl);
    if (ssl == nullptr) {
        return nullptr;
    }

    STACK_OF(SSL_CIPHER)* cipherStack = SSL_get_ciphers(ssl);
    size_t count = (cipherStack != nullptr) ? sk_SSL_CIPHER_num(cipherStack) : 0;
    ScopedLocalRef<jlongArray> ciphersArray(env, env->NewLongArray(static_cast<jsize>(count)));
    ScopedLongArrayRW ciphers(env, ciphersArray.get());
    for (size_t i = 0; i < count; i++) {
        ciphers[i] = reinterpret_cast<jlong>(sk_SSL_CIPHER_value(cipherStack, i));
    }

    JNI_TRACE("NativeCrypto_SSL_get_ciphers(%p) => %p [size=%zu]", ssl, ciphersArray.get(), count);
    return ciphersArray.release();
}

/**
 * Sets the ciphers suites that are enabled in the SSL
 */
static void NativeCrypto_SSL_set_cipher_lists(JNIEnv* env, jclass, jlong ssl_address,
                                              CONSCRYPT_UNUSED jobject ssl_holder,
                                              jobjectArray cipherSuites) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_cipher_lists cipherSuites=%p", ssl, cipherSuites);
    if (ssl == nullptr) {
        return;
    }
    if (cipherSuites == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "cipherSuites == null");
        return;
    }

    int length = env->GetArrayLength(cipherSuites);

    /*
     * Special case for empty cipher list. This is considered an error by the
     * SSL_set_cipher_list API, but Java allows this silly configuration.
     * However, the SSL cipher list is still set even when SSL_set_cipher_list
     * returns 0 in this case. Just to make sure, we check the resulting cipher
     * list to make sure it's zero length.
     */
    if (length == 0) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_cipher_lists cipherSuites=empty", ssl);
        SSL_set_cipher_list(ssl, "");
        ERR_clear_error();
        if (sk_SSL_CIPHER_num(SSL_get_ciphers(ssl)) != 0) {
            JNI_TRACE("ssl=%p NativeCrypto_SSL_set_cipher_lists cipherSuites=empty => error", ssl);
            conscrypt::jniutil::throwRuntimeException(
                    env, "SSL_set_cipher_list did not update ciphers!");
            ERR_clear_error();
        }
        return;
    }

    static const char noSSLv2[] = "!SSLv2";
    size_t cipherStringLen = strlen(noSSLv2);

    for (int i = 0; i < length; i++) {
        ScopedLocalRef<jstring> cipherSuite(
                env, reinterpret_cast<jstring>(env->GetObjectArrayElement(cipherSuites, i)));
        ScopedUtfChars c(env, cipherSuite.get());
        if (c.c_str() == nullptr) {
            return;
        }

        if (cipherStringLen + 1 < cipherStringLen) {
            conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                               "Overflow in cipher suite strings");
            return;
        }
        cipherStringLen += 1; /* For the separating colon */

        if (cipherStringLen + c.size() < cipherStringLen) {
            conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                               "Overflow in cipher suite strings");
            return;
        }
        cipherStringLen += c.size();
    }

    if (cipherStringLen + 1 < cipherStringLen) {
        conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                           "Overflow in cipher suite strings");
        return;
    }
    cipherStringLen += 1; /* For final NUL. */

    std::unique_ptr<char[]> cipherString(new char[cipherStringLen]);
    if (cipherString.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to alloc cipher string");
        return;
    }
    memcpy(cipherString.get(), noSSLv2, strlen(noSSLv2));
    size_t j = strlen(noSSLv2);

    for (int i = 0; i < length; i++) {
        ScopedLocalRef<jstring> cipherSuite(
                env, reinterpret_cast<jstring>(env->GetObjectArrayElement(cipherSuites, i)));
        ScopedUtfChars c(env, cipherSuite.get());

        cipherString[j++] = ':';
        memcpy(&cipherString[j], c.c_str(), c.size());
        j += c.size();
    }

    cipherString[j++] = 0;
    if (j != cipherStringLen) {
        conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                           "Internal error");
        return;
    }

    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_cipher_lists cipherSuites=%s", ssl, cipherString.get());
    if (!SSL_set_cipher_list(ssl, cipherString.get())) {
        ERR_clear_error();
        conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                           "Illegal cipher suite strings.");
        return;
    }
}

static void NativeCrypto_SSL_set_accept_state(JNIEnv* env, jclass, jlong ssl_address,
                                              CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_accept_state", ssl);
    if (ssl == nullptr) {
        return;
    }
    SSL_set_accept_state(ssl);
}

static void NativeCrypto_SSL_set_connect_state(JNIEnv* env, jclass, jlong ssl_address,
                                               CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_connect_state", ssl);
    if (ssl == nullptr) {
        return;
    }
    SSL_set_connect_state(ssl);
}

/**
 * Sets certificate expectations, especially for server to request client auth
 */
static void NativeCrypto_SSL_set_verify(JNIEnv* env, jclass, jlong ssl_address,
                                        CONSCRYPT_UNUSED jobject ssl_holder, jint mode) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_verify mode=%x", ssl, mode);
    if (ssl == nullptr) {
        return;
    }
    SSL_set_custom_verify(ssl, static_cast<int>(mode), cert_verify_callback);
}

/**
 * Sets the ciphers suites that are enabled in the SSL
 */
static void NativeCrypto_SSL_set_session(JNIEnv* env, jclass, jlong ssl_address,
                                         CONSCRYPT_UNUSED jobject ssl_holder,
                                         jlong ssl_session_address) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == nullptr) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_session => exception", ssl);
        return;
    }

    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, false);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_session ssl_session=%p", ssl, ssl_session);
    if (ssl_session == nullptr) {
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
            conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, sslErrorCode,
                                                               "SSL session set");
        }
    }
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_session ssl_session=%p => ret=%d", ssl, ssl_session,
              ret);
}

/**
 * Sets the ciphers suites that are enabled in the SSL
 */
static void NativeCrypto_SSL_set_session_creation_enabled(JNIEnv* env, jclass, jlong ssl_address,
                                                          CONSCRYPT_UNUSED jobject ssl_holder,
                                                          jboolean creation_enabled) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_session_creation_enabled creation_enabled=%d", ssl,
              creation_enabled);
    if (ssl == nullptr) {
        return;
    }

    if (creation_enabled) {
        SSL_clear_mode(ssl, SSL_MODE_NO_SESSION_CREATION);
    } else {
        SSL_set_mode(ssl, SSL_MODE_NO_SESSION_CREATION);
    }
}

static jboolean NativeCrypto_SSL_session_reused(JNIEnv* env, jclass, jlong ssl_address,
                                                CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_session_reused", ssl);
    if (ssl == nullptr) {
        return JNI_FALSE;
    }

    int reused = SSL_session_reused(ssl);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_session_reused => %d", ssl, reused);
    return static_cast<jboolean>(reused);
}

static void NativeCrypto_SSL_accept_renegotiations(JNIEnv* env, jclass, jlong ssl_address,
                                                   CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_accept_renegotiations", ssl);
    if (ssl == nullptr) {
        return;
    }

    SSL_set_renegotiate_mode(ssl, ssl_renegotiate_freely);
}

static void NativeCrypto_SSL_set_tlsext_host_name(JNIEnv* env, jclass, jlong ssl_address,
                                                  CONSCRYPT_UNUSED jobject ssl_holder,
                                                  jstring hostname) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_tlsext_host_name hostname=%p", ssl, hostname);
    if (ssl == nullptr) {
        return;
    }

    ScopedUtfChars hostnameChars(env, hostname);
    if (hostnameChars.c_str() == nullptr) {
        return;
    }
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_tlsext_host_name hostnameChars=%s", ssl,
              hostnameChars.c_str());

    int ret = SSL_set_tlsext_host_name(ssl, hostnameChars.c_str());
    if (ret != 1) {
        conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE,
                                                           "Error setting host name");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_set_tlsext_host_name => error", ssl);
        return;
    }
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_tlsext_host_name => ok", ssl);
}

static jstring NativeCrypto_SSL_get_servername(JNIEnv* env, jclass, jlong ssl_address,
                                               CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_servername", ssl);
    if (ssl == nullptr) {
        return nullptr;
    }
    const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_servername => %s", ssl, servername);
    return env->NewStringUTF(servername);
}

/**
 * Selects the ALPN protocol to use. The list of protocols in "primary" is considered the order
 * which should take precedence.
 */
static int selectApplicationProtocol(SSL* ssl, unsigned char** out, unsigned char* outLength,
                                     const unsigned char* primary,
                                     const unsigned int primaryLength,
                                     const unsigned char* secondary,
                                     const unsigned int secondaryLength) {
    JNI_TRACE("primary=%p, length=%d", primary, primaryLength);

    int status = SSL_select_next_proto(out, outLength, primary, primaryLength, secondary,
                                       secondaryLength);
    switch (status) {
        case OPENSSL_NPN_NEGOTIATED:
            JNI_TRACE("ssl=%p selectApplicationProtocol ALPN negotiated", ssl);
            return SSL_TLSEXT_ERR_OK;
            break;
        case OPENSSL_NPN_UNSUPPORTED:
            JNI_TRACE("ssl=%p selectApplicationProtocol ALPN unsupported", ssl);
            break;
        case OPENSSL_NPN_NO_OVERLAP:
            JNI_TRACE("ssl=%p selectApplicationProtocol ALPN no overlap", ssl);
            break;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

/**
 * Calls out to an application-provided selector to choose the ALPN protocol.
 */
static int selectApplicationProtocol(SSL* ssl, JNIEnv* env, jobject sslHandshakeCallbacks,
                                     unsigned char** out,
                                     unsigned char* outLen, const unsigned char* in,
                                     const unsigned int inLen) {
    // Copy the input array.
    ScopedLocalRef<jbyteArray> protocols(env, env->NewByteArray(static_cast<jsize>(inLen)));
    if (protocols.get() == nullptr) {
        JNI_TRACE("ssl=%p selectApplicationProtocol failed allocating array", ssl);
        return SSL_TLSEXT_ERR_NOACK;
    }
    env->SetByteArrayRegion(protocols.get(), 0, (static_cast<jsize>(inLen)),
                            reinterpret_cast<const jbyte*>(in));

    // Invoke the selection method.
    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID = env->GetMethodID(cls, "selectApplicationProtocol", "([B)I");
    jint offset = env->CallIntMethod(sslHandshakeCallbacks, methodID, protocols.get());

    if (offset < 0) {
        JNI_TRACE("ssl=%p selectApplicationProtocol selection failed", ssl);
        return SSL_TLSEXT_ERR_NOACK;
    }

    // Point the output to the selected protocol.
    *outLen = *(in + offset);
    *out = const_cast<unsigned char*>(in + offset + 1);

    return SSL_TLSEXT_ERR_OK;
}

/**
 * Callback for the server to select an ALPN protocol.
 */
static int alpn_select_callback(SSL* ssl, const unsigned char** out, unsigned char* outLen,
                                const unsigned char* in, unsigned int inLen, void*) {
    JNI_TRACE("ssl=%p alpn_select_callback in=%p inLen=%d", ssl, in, inLen);

    AppData* appData = toAppData(ssl);
    if (appData == nullptr) {
        JNI_TRACE("ssl=%p alpn_select_callback appData => 0", ssl);
        return SSL_TLSEXT_ERR_NOACK;
    }
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        CONSCRYPT_LOG_ERROR("AppData->env missing in alpn_select_callback");
        JNI_TRACE("ssl=%p alpn_select_callback => 0", ssl);
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (in == nullptr || (appData->applicationProtocolsData == nullptr &&
                          !appData->hasApplicationProtocolSelector)) {
        if (out != nullptr && outLen != nullptr) {
            *out = nullptr;
            *outLen = 0;
        }
        JNI_TRACE("ssl=%p alpn_select_callback protocols => 0", ssl);
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (appData->hasApplicationProtocolSelector) {
        return selectApplicationProtocol(ssl, env, appData->sslHandshakeCallbacks,
                                         const_cast<unsigned char**>(out), outLen, in, inLen);
    }

    return selectApplicationProtocol(ssl, const_cast<unsigned char**>(out), outLen,
                              reinterpret_cast<unsigned char*>(appData->applicationProtocolsData),
                              static_cast<unsigned int>(appData->applicationProtocolsLength),
                              in, inLen);
}

static jbyteArray NativeCrypto_getApplicationProtocol(JNIEnv* env, jclass, jlong ssl_address,
                                                      CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_getApplicationProtocol", ssl);
    if (ssl == nullptr) {
        return nullptr;
    }
    const jbyte* protocol;
    unsigned int protocolLength;
    SSL_get0_alpn_selected(ssl, reinterpret_cast<const unsigned char**>(&protocol),
                           &protocolLength);
    if (protocolLength == 0) {
        return nullptr;
    }
    jbyteArray result = env->NewByteArray(static_cast<jsize>(protocolLength));
    if (result != nullptr) {
        env->SetByteArrayRegion(result, 0, (static_cast<jsize>(protocolLength)), protocol);
    }
    return result;
}

static void NativeCrypto_setApplicationProtocols(JNIEnv* env, jclass, jlong ssl_address,
                                                 CONSCRYPT_UNUSED jobject ssl_holder,
                                                 jboolean client_mode, jbyteArray protocols) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == nullptr) {
        return;
    }
    AppData* appData = toAppData(ssl);
    if (appData == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to retrieve application data");
        JNI_TRACE("ssl=%p NativeCrypto_setApplicationProtocols appData => 0", ssl);
        return;
    }

    if (protocols != nullptr) {
        if (client_mode) {
            ScopedByteArrayRO protosBytes(env, protocols);
            if (protosBytes.get() == nullptr) {
                JNI_TRACE(
                        "ssl=%p NativeCrypto_setApplicationProtocols protocols=%p => "
                        "protosBytes == null",
                        ssl, protocols);
                return;
            }

            const unsigned char* tmp = reinterpret_cast<const unsigned char*>(protosBytes.get());
            int ret = SSL_set_alpn_protos(ssl, tmp, static_cast<unsigned int>(protosBytes.size()));
            if (ret != 0) {
                conscrypt::jniutil::throwSSLExceptionStr(env,
                                                         "Unable to set ALPN protocols for client");
                JNI_TRACE("ssl=%p NativeCrypto_setApplicationProtocols => exception", ssl);
                return;
            }
        } else {
            // Server mode - configure the ALPN protocol selection callback.
            if (!appData->setApplicationProtocols(env, protocols)) {
                conscrypt::jniutil::throwSSLExceptionStr(env,
                                                         "Unable to set ALPN protocols for server");
                JNI_TRACE("ssl=%p NativeCrypto_setApplicationProtocols => exception", ssl);
                return;
            }
            SSL_CTX_set_alpn_select_cb(SSL_get_SSL_CTX(ssl), alpn_select_callback, nullptr);
        }
    }
}

static void NativeCrypto_setHasApplicationProtocolSelector(JNIEnv* env, jclass, jlong ssl_address,
                                                           CONSCRYPT_UNUSED jobject ssl_holder,
                                                           jboolean hasSelector) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_setHasApplicationProtocolSelector selector=%d", ssl,
              hasSelector);
    if (ssl == nullptr) {
        return;
    }
    AppData* appData = toAppData(ssl);
    if (appData == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to retrieve application data");
        JNI_TRACE("ssl=%p NativeCrypto_setHasApplicationProtocolSelector appData => 0", ssl);
        return;
    }

    appData->hasApplicationProtocolSelector = hasSelector;
    if (hasSelector) {
        SSL_CTX_set_alpn_select_cb(SSL_get_SSL_CTX(ssl), alpn_select_callback, nullptr);
    }
}

/**
 * Perform SSL handshake
 */
static void NativeCrypto_SSL_do_handshake(JNIEnv* env, jclass, jlong ssl_address,
                                          CONSCRYPT_UNUSED jobject ssl_holder, jobject fdObject,
                                          jobject shc, jint timeout_millis) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake fd=%p shc=%p timeout_millis=%d", ssl, fdObject,
              shc, timeout_millis);
    if (ssl == nullptr) {
        return;
    }
    if (fdObject == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "fd == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake fd == null => exception", ssl);
        return;
    }
    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake sslHandshakeCallbacks == null => exception",
                  ssl);
        return;
    }

    NetFd fd(env, fdObject);
    if (fd.isClosed()) {
        // SocketException thrown by NetFd.isClosed
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake fd.isClosed() => exception", ssl);
        return;
    }

    int ret = SSL_set_fd(ssl, fd.get());
    JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake s=%d", ssl, fd.get());

    if (ret != 1) {
        conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE,
                                                           "Error setting the file descriptor");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake SSL_set_fd => exception", ssl);
        return;
    }

    /*
     * Make socket non-blocking, so SSL_connect SSL_read() and SSL_write() don't hang
     * forever and we can use select() to find out if the socket is ready.
     */
    if (!conscrypt::netutil::setBlocking(fd.get(), false)) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to make socket non blocking");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake setBlocking => exception", ssl);
        return;
    }

    AppData* appData = toAppData(ssl);
    if (appData == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to retrieve application data");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake appData => exception", ssl);
        return;
    }

    ret = 0;
    SslError sslError;
    while (appData->aliveAndKicking) {
        errno = 0;

        if (!appData->setCallbackState(env, shc, fdObject)) {
            // SocketException thrown by NetFd.isClosed
            JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake setCallbackState => exception", ssl);
            return;
        }
        ret = SSL_do_handshake(ssl);
        appData->clearCallbackState();
        // cert_verify_callback threw exception
        if (env->ExceptionCheck()) {
            ERR_clear_error();
            JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake exception => exception", ssl);
            return;
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
        JNI_TRACE(
                "ssl=%p NativeCrypto_SSL_do_handshake ret=%d errno=%d sslError=%d "
                "timeout_millis=%d",
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
                JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake sslSelect => exception", ssl);
                return;
            }
            if (selectResult == -1) {
                conscrypt::jniutil::throwSSLExceptionWithSslErrors(
                        env, ssl, SSL_ERROR_SYSCALL, "handshake error",
                        conscrypt::jniutil::throwSSLHandshakeExceptionStr);
                JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake selectResult == -1 => exception",
                          ssl);
                return;
            }
            if (selectResult == 0) {
                conscrypt::jniutil::throwSocketTimeoutException(env, "SSL handshake timed out");
                ERR_clear_error();
                JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake selectResult == 0 => exception",
                          ssl);
                return;
            }
        } else {
            // CONSCRYPT_LOG_ERROR("Unknown error %d during handshake", error);
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
            conscrypt::jniutil::throwSSLHandshakeExceptionStr(env, "Connection closed by peer");
        } else {
            conscrypt::jniutil::throwSSLExceptionWithSslErrors(
                    env, ssl, sslError.release(), "SSL handshake terminated",
                    conscrypt::jniutil::throwSSLHandshakeExceptionStr);
        }
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake clean error => exception", ssl);
        return;
    }

    // unclean error. See SSL_do_handshake(3SSL) man page.
    if (ret < 0) {
        /*
         * Translate the error and throw exception. We are sure it is an error
         * at this point.
         */
        conscrypt::jniutil::throwSSLExceptionWithSslErrors(
                env, ssl, sslError.release(), "SSL handshake aborted",
                conscrypt::jniutil::throwSSLHandshakeExceptionStr);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake unclean error => exception", ssl);
        return;
    }
    JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake => success", ssl);
}

static jstring NativeCrypto_SSL_get_current_cipher(JNIEnv* env, jclass, jlong ssl_address,
                                                   CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_current_cipher", ssl);
    if (ssl == nullptr) {
        return nullptr;
    }
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    if (cipher == nullptr) {
        JNI_TRACE("ssl=%p NativeCrypto_SSL_get_current_cipher cipher => null", ssl);
        return nullptr;
    }
    const char* name = SSL_CIPHER_standard_name(cipher);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_current_cipher => %s", ssl, name);
    return env->NewStringUTF(name);
}

static jstring NativeCrypto_SSL_get_version(JNIEnv* env, jclass, jlong ssl_address,
                                            CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_version", ssl);
    if (ssl == nullptr) {
        return nullptr;
    }
    const char* protocol = SSL_get_version(ssl);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_version => %s", ssl, protocol);
    return env->NewStringUTF(protocol);
}

static jobjectArray NativeCrypto_SSL_get0_peer_certificates(JNIEnv* env, jclass, jlong ssl_address,
                                                            CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get0_peer_certificates", ssl);
    if (ssl == nullptr) {
        return nullptr;
    }

    const STACK_OF(CRYPTO_BUFFER)* chain = SSL_get0_peer_certificates(ssl);
    if (chain == nullptr) {
        return nullptr;
    }

    ScopedLocalRef<jobjectArray> array(env, CryptoBuffersToObjectArray(env, chain));
    if (array.get() == nullptr) {
        return nullptr;
    }

    JNI_TRACE("ssl=%p NativeCrypto_SSL_get0_peer_certificates => %p", ssl, array.get());
    return array.release();
}

static int sslRead(JNIEnv* env, SSL* ssl, jobject fdObject, jobject shc, char* buf, jint len,
                   SslError* sslError, int read_timeout_millis) {
    JNI_TRACE("ssl=%p sslRead buf=%p len=%d", ssl, buf, len);

    if (len == 0) {
        // Don't bother doing anything in this case.
        return 0;
    }

    BIO* rbio = SSL_get_rbio(ssl);
    BIO* wbio = SSL_get_wbio(ssl);

    AppData* appData = toAppData(ssl);
    JNI_TRACE("ssl=%p sslRead appData=%p", ssl, appData);
    if (appData == nullptr) {
        return THROW_SSLEXCEPTION;
    }

    while (appData->aliveAndKicking) {
        errno = 0;

        std::unique_lock<std::mutex> appDataLock(appData->mutex);

        if (!SSL_is_init_finished(ssl) && !SSL_in_false_start(ssl) &&
            !SSL_renegotiate_pending(ssl)) {
            JNI_TRACE("ssl=%p sslRead => init is not finished (state: %s)", ssl,
                      SSL_state_string_long(ssl));
            return THROW_SSLEXCEPTION;
        }

        size_t bytesMoved = BIO_number_read(rbio) + BIO_number_written(wbio);

        if (!appData->setCallbackState(env, shc, fdObject)) {
            return THROWN_EXCEPTION;
        }
        int result = SSL_read(ssl, buf, len);
        appData->clearCallbackState();
        // callbacks can happen if server requests renegotiation
        if (env->ExceptionCheck()) {
            JNI_TRACE("ssl=%p sslRead => THROWN_EXCEPTION", ssl);
            return THROWN_EXCEPTION;
        }
        sslError->reset(ssl, result);

        JNI_TRACE("ssl=%p sslRead SSL_read result=%d sslError=%d", ssl, result, sslError->get());
        if (conscrypt::trace::kWithJniTraceData) {
            for (size_t i = 0; result > 0 && i < static_cast<size_t>(result);
                 i += conscrypt::trace::kWithJniTraceDataChunkSize) {
                size_t n = result - i;
                if (n > conscrypt::trace::kWithJniTraceDataChunkSize) {
                    n = conscrypt::trace::kWithJniTraceDataChunkSize;
                }
                JNI_TRACE("ssl=%p sslRead data: %zu:\n%.*s", ssl, n, (int)n, buf + i);
            }
        }

        // If we have been successful in moving data around, check whether it
        // might make sense to wake up other blocked threads, so they can give
        // it a try, too.
        if (BIO_number_read(rbio) + BIO_number_written(wbio) != bytesMoved &&
            appData->waitingThreads > 0) {
            sslNotify(appData);
        }

        // If we are blocked by the underlying socket, tell the world that
        // there will be one more waiting thread now.
        if (sslError->get() == SSL_ERROR_WANT_READ || sslError->get() == SSL_ERROR_WANT_WRITE) {
            appData->waitingThreads++;
        }

        appDataLock.unlock();

        switch (sslError->get()) {
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
                int selectResult =
                        sslSelect(env, sslError->get(), fdObject, appData, read_timeout_millis);
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
            default: { return THROW_SSLEXCEPTION; }
        }
    }

    return -1;
}

/**
 * OpenSSL read function (2): read into buffer at offset n chunks.
 * Returns the number of bytes read (success) or value <= 0 (failure).
 */
static jint NativeCrypto_SSL_read(JNIEnv* env, jclass, jlong ssl_address,
                                  CONSCRYPT_UNUSED jobject ssl_holder, jobject fdObject,
                                  jobject shc, jbyteArray b, jint offset, jint len,
                                  jint read_timeout_millis) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE(
            "ssl=%p NativeCrypto_SSL_read fd=%p shc=%p b=%p offset=%d len=%d "
            "read_timeout_millis=%d",
            ssl, fdObject, shc, b, offset, len, read_timeout_millis);
    if (ssl == nullptr) {
        return 0;
    }
    if (fdObject == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "fd == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read => fd == null", ssl);
        return 0;
    }
    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read => sslHandshakeCallbacks == null", ssl);
        return 0;
    }
    if (b == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "b == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read => b == null", ssl);
        return 0;
    }

    size_t array_size = static_cast<size_t>(env->GetArrayLength(b));
    if (ARRAY_CHUNK_INVALID(array_size, offset, len)) {
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException", "b");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_read => ArrayIndexOutOfBoundsException", ssl);
        return 0;
    }

    SslError sslError;
    int ret;
    if (conscrypt::jniutil::isGetByteArrayElementsLikelyToReturnACopy(array_size)) {
        if (len <= 1024) {
            // Allocate small buffers on the stack for performance.
            jbyte buf[1024];
            ret = sslRead(env, ssl, fdObject, shc, reinterpret_cast<char*>(&buf[0]), len, &sslError,
                          read_timeout_millis);
            if (ret > 0) {
                // Don't bother applying changes if issues were encountered.
                env->SetByteArrayRegion(b, offset, ret, &buf[0]);
            }
        } else {
            // Allocate larger buffers on the heap.
            // ARRAY_CHUNK_INVALID above ensures that len >= 0.
            jint remaining = len;
            jint buf_size = (remaining >= 65536) ? 65536 : remaining;
            std::unique_ptr<jbyte[]> buf(new jbyte[static_cast<unsigned int>(buf_size)]);
            // TODO(flooey): Use new(std::nothrow).
            if (buf.get() == nullptr) {
                conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate chunk buffer");
                return 0;
            }
            // TODO(flooey): Fix cumulative read timeout? The effective timeout is the multiplied
            // by the number of internal calls to sslRead() below.
            ret = 0;
            while (remaining > 0) {
                jint temp_ret;
                jint chunk_size = (remaining >= buf_size) ? buf_size : remaining;
                temp_ret = sslRead(env, ssl, fdObject, shc, reinterpret_cast<char*>(buf.get()),
                                   chunk_size, &sslError, read_timeout_millis);
                if (temp_ret < 0) {
                    if (ret > 0) {
                        // We've already read some bytes; attempt to preserve them if this is an
                        // "expected" error.
                        if (temp_ret == -1) {
                            // EOF
                            break;
                        } else if (temp_ret == THROWN_EXCEPTION) {
                            // FD closed. Subsequent calls to sslRead should reproduce the
                            // exception.
                            env->ExceptionClear();
                            break;
                        }
                    }
                    // An error was encountered. Handle below.
                    ret = temp_ret;
                    break;
                }
                env->SetByteArrayRegion(b, offset, temp_ret, buf.get());
                if (env->ExceptionCheck()) {
                    // Error committing changes to JVM.
                    return -1;
                }
                // Accumulate bytes read.
                ret += temp_ret;
                offset += temp_ret;
                remaining -= temp_ret;
                if (temp_ret < chunk_size) {
                    // sslRead isn't able to fulfill our request right now.
                    break;
                }
            }
        }
    } else {
        ScopedByteArrayRW bytes(env, b);
        if (bytes.get() == nullptr) {
            JNI_TRACE("ssl=%p NativeCrypto_SSL_read => threw exception", ssl);
            return 0;
        }

        ret = sslRead(env, ssl, fdObject, shc, reinterpret_cast<char*>(bytes.get() + offset), len,
                      &sslError, read_timeout_millis);
    }

    int result;
    switch (ret) {
        case THROW_SSLEXCEPTION:
            // See sslRead() regarding improper failure to handle normal cases.
            conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, sslError.release(),
                                                               "Read error");
            result = -1;
            break;
        case THROW_SOCKETTIMEOUTEXCEPTION:
            conscrypt::jniutil::throwSocketTimeoutException(env, "Read timed out");
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
                    SslError* sslError, int write_timeout_millis) {
    JNI_TRACE("ssl=%p sslWrite buf=%p len=%d write_timeout_millis=%d", ssl, buf, len,
              write_timeout_millis);

    if (len == 0) {
        // Don't bother doing anything in this case.
        return 0;
    }

    BIO* rbio = SSL_get_rbio(ssl);
    BIO* wbio = SSL_get_wbio(ssl);

    AppData* appData = toAppData(ssl);
    JNI_TRACE("ssl=%p sslWrite appData=%p", ssl, appData);
    if (appData == nullptr) {
        return THROW_SSLEXCEPTION;
    }

    int count = len;

    while (appData->aliveAndKicking && len > 0) {
        errno = 0;

        std::unique_lock<std::mutex> appDataLock(appData->mutex);

        if (!SSL_is_init_finished(ssl) && !SSL_in_false_start(ssl) &&
            !SSL_renegotiate_pending(ssl)) {
            JNI_TRACE("ssl=%p sslWrite => init is not finished (state: %s)", ssl,
                      SSL_state_string_long(ssl));
            return THROW_SSLEXCEPTION;
        }

        size_t bytesMoved = BIO_number_read(rbio) + BIO_number_written(wbio);

        if (!appData->setCallbackState(env, shc, fdObject)) {
            return THROWN_EXCEPTION;
        }
        JNI_TRACE("ssl=%p sslWrite SSL_write len=%d", ssl, len);
        int result = SSL_write(ssl, buf, len);
        appData->clearCallbackState();
        // callbacks can happen if server requests renegotiation
        if (env->ExceptionCheck()) {
            JNI_TRACE("ssl=%p sslWrite exception => THROWN_EXCEPTION", ssl);
            return THROWN_EXCEPTION;
        }
        sslError->reset(ssl, result);

        JNI_TRACE("ssl=%p sslWrite SSL_write result=%d sslError=%d", ssl, result, sslError->get());
        if (conscrypt::trace::kWithJniTraceData) {
            for (size_t i = 0; result > 0 && i < static_cast<size_t>(result);
                 i += conscrypt::trace::kWithJniTraceDataChunkSize) {
                size_t n = result - i;
                if (n > conscrypt::trace::kWithJniTraceDataChunkSize) {
                    n = conscrypt::trace::kWithJniTraceDataChunkSize;
                }
                JNI_TRACE("ssl=%p sslWrite data: %zu:\n%.*s", ssl, n, (int)n, buf + i);
            }
        }

        // If we have been successful in moving data around, check whether it
        // might make sense to wake up other blocked threads, so they can give
        // it a try, too.
        if (BIO_number_read(rbio) + BIO_number_written(wbio) != bytesMoved &&
            appData->waitingThreads > 0) {
            sslNotify(appData);
        }

        // If we are blocked by the underlying socket, tell the world that
        // there will be one more waiting thread now.
        if (sslError->get() == SSL_ERROR_WANT_READ || sslError->get() == SSL_ERROR_WANT_WRITE) {
            appData->waitingThreads++;
        }

        appDataLock.unlock();

        switch (sslError->get()) {
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
                int selectResult =
                        sslSelect(env, sslError->get(), fdObject, appData, write_timeout_millis);
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
            default: { return THROW_SSLEXCEPTION; }
        }
    }
    JNI_TRACE("ssl=%p sslWrite => count=%d", ssl, count);

    return count;
}

/**
 * OpenSSL write function (2): write into buffer at offset n chunks.
 */
static void NativeCrypto_SSL_write(JNIEnv* env, jclass, jlong ssl_address,
                                   CONSCRYPT_UNUSED jobject ssl_holder, jobject fdObject,
                                   jobject shc, jbyteArray b, jint offset, jint len,
                                   jint write_timeout_millis) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE(
            "ssl=%p NativeCrypto_SSL_write fd=%p shc=%p b=%p offset=%d len=%d "
            "write_timeout_millis=%d",
            ssl, fdObject, shc, b, offset, len, write_timeout_millis);
    if (ssl == nullptr) {
        return;
    }
    if (fdObject == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "fd == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write => fd == null", ssl);
        return;
    }
    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write => sslHandshakeCallbacks == null", ssl);
        return;
    }
    if (b == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "b == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write => b == null", ssl);
        return;
    }

    size_t array_size = static_cast<size_t>(env->GetArrayLength(b));
    if (ARRAY_CHUNK_INVALID(array_size, offset, len)) {
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException", "b");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_write => ArrayIndexOutOfBoundsException", ssl);
        return;
    }

    SslError sslError;
    int ret;
    if (conscrypt::jniutil::isGetByteArrayElementsLikelyToReturnACopy(array_size)) {
        if (len <= 1024) {
            jbyte buf[1024];
            env->GetByteArrayRegion(b, offset, len, buf);
            ret = sslWrite(env, ssl, fdObject, shc, reinterpret_cast<const char*>(&buf[0]), len,
                           &sslError, write_timeout_millis);
        } else {
            // TODO(flooey): Similar safety concerns and questions here as in SSL_read.
            jint remaining = len;
            jint buf_size = (remaining >= 65536) ? 65536 : remaining;
            std::unique_ptr<jbyte[]> buf(new jbyte[static_cast<unsigned int>(buf_size)]);
            if (buf.get() == nullptr) {
                conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate chunk buffer");
                return;
            }
            while (remaining > 0) {
                jint chunk_size = (remaining >= buf_size) ? buf_size : remaining;
                env->GetByteArrayRegion(b, offset, chunk_size, buf.get());
                ret = sslWrite(env, ssl, fdObject, shc, reinterpret_cast<const char*>(buf.get()),
                               chunk_size, &sslError, write_timeout_millis);
                if (ret == THROW_SSLEXCEPTION || ret == THROW_SOCKETTIMEOUTEXCEPTION ||
                    ret == THROWN_EXCEPTION) {
                    // Encountered an error. Terminate early and handle below.
                    break;
                }
                offset += ret;
                remaining -= ret;
            }
        }
    } else {
        ScopedByteArrayRO bytes(env, b);
        if (bytes.get() == nullptr) {
            JNI_TRACE("ssl=%p NativeCrypto_SSL_write => threw exception", ssl);
            return;
        }
        ret = sslWrite(env, ssl, fdObject, shc, reinterpret_cast<const char*>(bytes.get() + offset),
                       len, &sslError, write_timeout_millis);
    }

    switch (ret) {
        case THROW_SSLEXCEPTION:
            // See sslWrite() regarding improper failure to handle normal cases.
            conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, sslError.release(),
                                                               "Write error");
            break;
        case THROW_SOCKETTIMEOUTEXCEPTION:
            conscrypt::jniutil::throwSocketTimeoutException(env, "Write timed out");
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
static void NativeCrypto_SSL_interrupt(JNIEnv* env, jclass, jlong ssl_address,
                                       CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, false);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_interrupt", ssl);
    if (ssl == nullptr) {
        return;
    }

    /*
     * Mark the connection as quasi-dead, then send something to the emergency
     * file descriptor, so any blocking select() calls are woken up.
     */
    AppData* appData = toAppData(ssl);
    if (appData != nullptr) {
        appData->aliveAndKicking = false;

        // At most two threads can be waiting.
        sslNotify(appData);
        sslNotify(appData);
    }
}

/**
 * OpenSSL close SSL socket function.
 */
static void NativeCrypto_SSL_shutdown(JNIEnv* env, jclass, jlong ssl_address,
                                      CONSCRYPT_UNUSED jobject ssl_holder, jobject fdObject,
                                      jobject shc) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, false);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_shutdown fd=%p shc=%p", ssl, fdObject, shc);
    if (ssl == nullptr) {
        return;
    }
    if (fdObject == nullptr) {
        return;
    }
    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_shutdown => sslHandshakeCallbacks == null", ssl);
        return;
    }

    AppData* appData = toAppData(ssl);
    if (appData != nullptr) {
        if (!appData->setCallbackState(env, shc, fdObject)) {
            // SocketException thrown by NetFd.isClosed
            ERR_clear_error();
            return;
        }

        /*
         * Try to make socket blocking again. OpenSSL literature recommends this.
         */
        int fd = SSL_get_fd(ssl);
        JNI_TRACE("ssl=%p NativeCrypto_SSL_shutdown s=%d", ssl, fd);
#ifndef _WIN32
        if (fd != -1) {
            conscrypt::netutil::setBlocking(fd, true);
        }
#endif

        int ret = SSL_shutdown(ssl);
        appData->clearCallbackState();
        // callbacks can happen if server requests renegotiation
        if (env->ExceptionCheck()) {
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
                conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, sslError,
                                                                   "SSL shutdown failed");
                break;
        }
    }

    ERR_clear_error();
}

static jint NativeCrypto_SSL_get_shutdown(JNIEnv* env, jclass, jlong ssl_address,
                                          CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_shutdown", ssl);
    if (ssl == nullptr) {
        return 0;
    }

    int status = SSL_get_shutdown(ssl);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_shutdown => %d", ssl, status);
    return static_cast<jint>(status);
}

/**
 * public static native void SSL_free(long ssl);
 */
static void NativeCrypto_SSL_free(JNIEnv* env, jclass, jlong ssl_address,
                                  CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_free", ssl);
    if (ssl == nullptr) {
        return;
    }

    AppData* appData = toAppData(ssl);
    SSL_set_app_data(ssl, nullptr);
    delete appData;
    SSL_free(ssl);
}

static jbyteArray get_session_id(JNIEnv* env, SSL_SESSION* ssl_session) {
    unsigned int length;
    const uint8_t* id = SSL_SESSION_get_id(ssl_session, &length);
    JNI_TRACE("ssl_session=%p get_session_id id=%p length=%u", ssl_session, id, length);
    if (id && length > 0) {
        jbyteArray result = env->NewByteArray(static_cast<jsize>(length));
        if (result != nullptr) {
            const jbyte* src = reinterpret_cast<const jbyte*>(id);
            env->SetByteArrayRegion(result, 0, static_cast<jsize>(length), src);
        }
        return result;
    }
    return nullptr;
}

/**
 * Gets and returns in a byte array the ID of the actual SSL session.
 */
static jbyteArray NativeCrypto_SSL_SESSION_session_id(JNIEnv* env, jclass,
                                                      jlong ssl_session_address) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_session_id", ssl_session);
    if (ssl_session == nullptr) {
        return nullptr;
    }
    jbyteArray result = get_session_id(env, ssl_session);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_session_id => %p", ssl_session, result);
    return result;
}

/**
 * Gets and returns in a long integer the creation's time of the
 * actual SSL session.
 */
static jlong NativeCrypto_SSL_SESSION_get_time(JNIEnv* env, jclass, jlong ssl_session_address) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_get_time", ssl_session);
    if (ssl_session == nullptr) {
        return 0;
    }
    // result must be jlong, not long or *1000 will overflow
    jlong result = SSL_SESSION_get_time(ssl_session);
    result *= 1000;  // OpenSSL uses seconds, Java uses milliseconds.
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_get_time => %lld", ssl_session,
              (long long)result);  // NOLINT(runtime/int)
    return result;
}

/**
 * Gets and returns in a long integer the creation's time of the
 * actual SSL session.
 */
static jlong NativeCrypto_SSL_get_time(JNIEnv* env, jclass, jlong ssl_address,
                                       CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_time", ssl);
    if (ssl == nullptr) {
        return 0;
    }

    SSL_SESSION* ssl_session = SSL_get_session(ssl);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_get_time", ssl_session);
    if (ssl_session == nullptr) {
        // BoringSSL does not protect against a NULL session.
        return 0;
    }
    // result must be jlong, not long or *1000 will overflow
    jlong result = SSL_SESSION_get_time(ssl_session);
    result *= 1000;  // OpenSSL uses seconds, Java uses milliseconds.
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_get_time => %lld", ssl_session, (long long)result);
    return result;
}

/**
 * Sets the timeout on the SSL session.
 */
static jlong NativeCrypto_SSL_set_timeout(JNIEnv* env, jclass, jlong ssl_address,
                                          CONSCRYPT_UNUSED jobject ssl_holder, jlong millis) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_set_timeout", ssl);
    if (ssl == nullptr) {
        return 0;
    }

    SSL_SESSION* ssl_session = SSL_get_session(ssl);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_set_timeout", ssl_session);
    if (ssl_session == nullptr) {
        // BoringSSL does not protect against a NULL session.
        return 0;
    }

    // Convert to seconds
    static const jlong INT_MAX_AS_JLONG = static_cast<jlong>(INT_MAX);
    uint32_t timeout = static_cast<uint32_t>(
            std::max(0, static_cast<int>(std::min(INT_MAX_AS_JLONG, millis / 1000))));
    return SSL_set_timeout(ssl_session, timeout);
}

/**
 * Gets the timeout for the SSL session.
 */
static jlong NativeCrypto_SSL_get_timeout(JNIEnv* env, jclass, jlong ssl_address,
                                          CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_timeout", ssl);
    if (ssl == nullptr) {
        return 0;
    }

    SSL_SESSION* ssl_session = SSL_get_session(ssl);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_get_timeout", ssl_session);
    if (ssl_session == nullptr) {
        // BoringSSL does not protect against a NULL session.
        return 0;
    }

    jlong result = SSL_get_timeout(ssl_session);
    result *= 1000;  // OpenSSL uses seconds, Java uses milliseconds.
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_get_timeout => %lld", ssl_session,
              (long long)result)  // NOLINT(runtime/int);
    return result;
}

static jint NativeCrypto_SSL_get_signature_algorithm_key_type(JNIEnv* env, jclass,
                                                              jint signatureAlg) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    return SSL_get_signature_algorithm_key_type(signatureAlg);
}

/**
 * Gets the timeout for the SSL session.
 */
static jlong NativeCrypto_SSL_SESSION_get_timeout(JNIEnv* env, jclass, jlong ssl_session_address) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_get_timeout", ssl_session);
    if (ssl_session == nullptr) {
        return 0;
    }

    return SSL_get_timeout(ssl_session);
}

/**
 * Gets the ID for the SSL session, or null if no session is currently available.
 */
static jbyteArray NativeCrypto_SSL_session_id(JNIEnv* env, jclass, jlong ssl_address,
                                              CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_session_id", ssl);
    if (ssl == nullptr) {
        return nullptr;
    }

    SSL_SESSION* ssl_session = SSL_get_session(ssl);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_session_id", ssl_session);
    if (ssl_session == nullptr) {
        return nullptr;
    }
    jbyteArray result = get_session_id(env, ssl_session);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_session_id => %p", ssl_session, result);
    return result;
}

/**
 * Gets and returns in a string the version of the SSL protocol. If it
 * returns the string "unknown" it means that no connection is established.
 */
static jstring NativeCrypto_SSL_SESSION_get_version(JNIEnv* env, jclass,
                                                    jlong ssl_session_address) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_get_version", ssl_session);
    if (ssl_session == nullptr) {
        return nullptr;
    }
    const char* protocol = SSL_SESSION_get_version(ssl_session);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_get_version => %s", ssl_session, protocol);
    return env->NewStringUTF(protocol);
}

/**
 * Gets and returns in a string the cipher negotiated for the SSL session.
 */
static jstring NativeCrypto_SSL_SESSION_cipher(JNIEnv* env, jclass, jlong ssl_session_address) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_cipher", ssl_session);
    if (ssl_session == nullptr) {
        return nullptr;
    }
    const SSL_CIPHER* cipher = SSL_SESSION_get0_cipher(ssl_session);
    const char* name = SSL_CIPHER_standard_name(cipher);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_cipher => %s", ssl_session, name);
    return env->NewStringUTF(name);
}

static jboolean NativeCrypto_SSL_SESSION_should_be_single_use(JNIEnv* env, jclass,
                                                              jlong ssl_session_address) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_should_be_single_use", ssl_session);
    if (ssl_session == nullptr) {
        return JNI_FALSE;
    }
    int single_use = SSL_SESSION_should_be_single_use(ssl_session);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_should_be_single_use => %d", ssl_session,
              single_use);
    return single_use ? JNI_TRUE : JNI_FALSE;
}

/**
 * Increments the reference count of the session.
 */
static void NativeCrypto_SSL_SESSION_up_ref(JNIEnv* env, jclass, jlong ssl_session_address) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_up_ref", ssl_session);
    if (ssl_session == nullptr) {
        return;
    }
    SSL_SESSION_up_ref(ssl_session);
}

/**
 * Frees the SSL session.
 */
static void NativeCrypto_SSL_SESSION_free(JNIEnv* env, jclass, jlong ssl_session_address) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_SSL_SESSION_free", ssl_session);
    if (ssl_session == nullptr) {
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
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL_SESSION* ssl_session = to_SSL_SESSION(env, ssl_session_address, true);
    JNI_TRACE("ssl_session=%p NativeCrypto_i2d_SSL_SESSION", ssl_session);
    if (ssl_session == nullptr) {
        return nullptr;
    }
    return ASN1ToByteArray<SSL_SESSION>(env, ssl_session, i2d_SSL_SESSION);
}

/**
 * Deserialize the session.
 */
static jlong NativeCrypto_d2i_SSL_SESSION(JNIEnv* env, jclass, jbyteArray javaBytes) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    JNI_TRACE("NativeCrypto_d2i_SSL_SESSION bytes=%p", javaBytes);

    ScopedByteArrayRO bytes(env, javaBytes);
    if (bytes.get() == nullptr) {
        JNI_TRACE("NativeCrypto_d2i_SSL_SESSION => threw exception");
        return 0;
    }
    const unsigned char* ucp = reinterpret_cast<const unsigned char*>(bytes.get());
    // NOLINTNEXTLINE(runtime/int)
    SSL_SESSION* ssl_session = d2i_SSL_SESSION(nullptr, &ucp, static_cast<long>(bytes.size()));

    if (ssl_session == nullptr ||
        ucp != (reinterpret_cast<const unsigned char*>(bytes.get()) + bytes.size())) {
        conscrypt::jniutil::throwExceptionFromBoringSSLError(env, "d2i_SSL_SESSION",
                                                             conscrypt::jniutil::throwIOException);
        JNI_TRACE("NativeCrypto_d2i_SSL_SESSION => failure to convert");
        return 0L;
    }

    JNI_TRACE("NativeCrypto_d2i_SSL_SESSION => %p", ssl_session);
    return reinterpret_cast<uintptr_t>(ssl_session);
}

static jstring NativeCrypto_SSL_CIPHER_get_kx_name(JNIEnv* env, jclass, jlong cipher_address) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    const SSL_CIPHER* cipher = to_SSL_CIPHER(env, cipher_address, true);
    const char* kx_name = nullptr;

    kx_name = SSL_CIPHER_get_kx_name(cipher);

    return env->NewStringUTF(kx_name);
}

static jobjectArray NativeCrypto_get_cipher_names(JNIEnv* env, jclass, jstring selectorJava) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    ScopedUtfChars selector(env, selectorJava);
    if (selector.c_str() == nullptr) {
        conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                           "selector == null");
        return nullptr;
    }

    JNI_TRACE("NativeCrypto_get_cipher_names %s", selector.c_str());

    bssl::UniquePtr<SSL_CTX> sslCtx(SSL_CTX_new(TLS_with_buffers_method()));
    bssl::UniquePtr<SSL> ssl(SSL_new(sslCtx.get()));

    if (!SSL_set_cipher_list(ssl.get(), selector.c_str())) {
        conscrypt::jniutil::throwException(env, "java/lang/IllegalArgumentException",
                                           "Unable to set SSL cipher list");
        return nullptr;
    }
    STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(ssl.get());

    size_t size = sk_SSL_CIPHER_num(ciphers);
    ScopedLocalRef<jobjectArray> cipherNamesArray(
            env, env->NewObjectArray(static_cast<jsize>(2 * size), conscrypt::jniutil::stringClass,
                                     nullptr));
    if (cipherNamesArray.get() == nullptr) {
        return nullptr;
    }

    // Return an array of standard and OpenSSL name pairs.
    for (size_t i = 0; i < size; i++) {
        const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
        ScopedLocalRef<jstring> cipherName(env,
                                           env->NewStringUTF(SSL_CIPHER_standard_name(cipher)));
        env->SetObjectArrayElement(cipherNamesArray.get(), static_cast<jsize>(2 * i),
                                   cipherName.get());

        ScopedLocalRef<jstring> opensslName(env, env->NewStringUTF(SSL_CIPHER_get_name(cipher)));
        env->SetObjectArrayElement(cipherNamesArray.get(), static_cast<jsize>(2 * i + 1),
                                   opensslName.get());
    }

    JNI_TRACE("NativeCrypto_get_cipher_names(%s) => success (%zd entries)", selector.c_str(),
              2 * size);
    return cipherNamesArray.release();
}

/**
 * Compare the given CertID with a certificate and it's issuer.
 * True is returned if the CertID matches.
 */
static bool ocsp_cert_id_matches_certificate(CBS* cert_id, X509* x509, X509* issuerX509) {
    // Get the hash algorithm used by this CertID
    CBS hash_algorithm, hash;
    if (!CBS_get_asn1(cert_id, &hash_algorithm, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&hash_algorithm, &hash, CBS_ASN1_OBJECT)) {
        return false;
    }

    // Get the issuer's name hash from the CertID
    CBS issuer_name_hash;
    if (!CBS_get_asn1(cert_id, &issuer_name_hash, CBS_ASN1_OCTETSTRING)) {
        return false;
    }

    // Get the issuer's key hash from the CertID
    CBS issuer_key_hash;
    if (!CBS_get_asn1(cert_id, &issuer_key_hash, CBS_ASN1_OCTETSTRING)) {
        return false;
    }

    // Get the serial number from the CertID
    CBS serial;
    if (!CBS_get_asn1(cert_id, &serial, CBS_ASN1_INTEGER)) {
        return false;
    }

    // Compare the certificate's serial number with the one from the Cert ID
    const uint8_t* p = CBS_data(&serial);
    bssl::UniquePtr<ASN1_INTEGER> serial_number(
            c2i_ASN1_INTEGER(nullptr, &p,
                             static_cast<long>(CBS_len(&serial))));  // NOLINT(runtime/int)
    ASN1_INTEGER* expected_serial_number = X509_get_serialNumber(x509);
    if (serial_number.get() == nullptr ||
        ASN1_INTEGER_cmp(expected_serial_number, serial_number.get()) != 0) {
        return false;
    }

    // Find the hash algorithm to be used
    const EVP_MD* digest = EVP_get_digestbynid(OBJ_cbs2nid(&hash));
    if (digest == nullptr) {
        return false;
    }

    // Hash the issuer's name and compare the hash with the one from the Cert ID
    uint8_t md[EVP_MAX_MD_SIZE];
    X509_NAME* issuer_name = X509_get_subject_name(issuerX509);
    if (!X509_NAME_digest(issuer_name, digest, md, nullptr) ||
        !CBS_mem_equal(&issuer_name_hash, md, EVP_MD_size(digest))) {
        return false;
    }

    // Same thing with the issuer's key
    ASN1_BIT_STRING* issuer_key = X509_get0_pubkey_bitstr(issuerX509);
    if (!EVP_Digest(issuer_key->data, static_cast<size_t>(issuer_key->length), md, nullptr, digest,
                    nullptr) ||
        !CBS_mem_equal(&issuer_key_hash, md, EVP_MD_size(digest))) {
        return false;
    }

    return true;
}

/**
 * Get a SingleResponse whose CertID matches the given certificate and issuer from a
 * SEQUENCE OF SingleResponse.
 *
 * If found, |out_single_response| is set to the response, and true is returned. Otherwise if an
 * error occured or no response matches the certificate, false is returned and |out_single_response|
 * is unchanged.
 */
static bool find_ocsp_single_response(CBS* responses, X509* x509, X509* issuerX509,
                                      CBS* out_single_response) {
    // Iterate over all the SingleResponses, until one matches the certificate
    while (CBS_len(responses) > 0) {
        // Get the next available SingleResponse from the sequence
        CBS single_response;
        if (!CBS_get_asn1(responses, &single_response, CBS_ASN1_SEQUENCE)) {
            return false;
        }

        // Make a copy of the stream so we pass it back to the caller
        CBS single_response_original = single_response;

        // Get the SingleResponse's CertID
        // If this fails ignore the current response and move to the next one
        CBS cert_id;
        if (!CBS_get_asn1(&single_response, &cert_id, CBS_ASN1_SEQUENCE)) {
            continue;
        }

        // Compare the CertID with the given certificate and issuer
        if (ocsp_cert_id_matches_certificate(&cert_id, x509, issuerX509)) {
            *out_single_response = single_response_original;
            return true;
        }
    }

    return false;
}

/**
 * Get the BasicOCSPResponse from an OCSPResponse.
 * If parsing succeeds and the response is of type basic, |basic_response| is set to it, and true is
 * returned.
 */
static bool get_ocsp_basic_response(CBS* ocsp_response, CBS* basic_response) {
    CBS tagged_response_bytes, response_bytes, response_type, response;

    // Get the ResponseBytes out of the OCSPResponse
    if (!CBS_get_asn1(ocsp_response, nullptr /* responseStatus */, CBS_ASN1_ENUMERATED) ||
        !CBS_get_asn1(ocsp_response, &tagged_response_bytes,
                      CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
        !CBS_get_asn1(&tagged_response_bytes, &response_bytes, CBS_ASN1_SEQUENCE)) {
        return false;
    }

    // Parse the response type and data out of the ResponseBytes
    if (!CBS_get_asn1(&response_bytes, &response_type, CBS_ASN1_OBJECT) ||
        !CBS_get_asn1(&response_bytes, &response, CBS_ASN1_OCTETSTRING)) {
        return false;
    }

    // Only basic OCSP responses are supported
    if (OBJ_cbs2nid(&response_type) != NID_id_pkix_OCSP_basic) {
        return false;
    }

    // Parse the octet string as a BasicOCSPResponse
    return CBS_get_asn1(&response, basic_response, CBS_ASN1_SEQUENCE) == 1;
}

/**
 * Get the SEQUENCE OF SingleResponse from a BasicOCSPResponse.
 * If parsing succeeds, |single_responses| is set to point to the sequence of SingleResponse, and
 * true is returned.
 */
static bool get_ocsp_single_responses(CBS* basic_response, CBS* single_responses) {
    // Parse the ResponseData out of the BasicOCSPResponse. Ignore the rest.
    CBS response_data;
    if (!CBS_get_asn1(basic_response, &response_data, CBS_ASN1_SEQUENCE)) {
        return false;
    }

    // Skip the version, responderID and producedAt fields
    if (!CBS_get_optional_asn1(&response_data, nullptr /* version */, nullptr,
                               CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
        !CBS_get_any_asn1_element(&response_data, nullptr /* responderID */, nullptr, nullptr) ||
        !CBS_get_any_asn1_element(&response_data, nullptr /* producedAt */, nullptr, nullptr)) {
        return false;
    }

    // Extract the list of SingleResponse.
    return CBS_get_asn1(&response_data, single_responses, CBS_ASN1_SEQUENCE) == 1;
}

/**
 * Get the SEQUENCE OF Extension from a SingleResponse.
 * If parsing succeeds, |extensions| is set to point the the extension sequence and true is
 * returned.
 */
static bool get_ocsp_single_response_extensions(CBS* single_response, CBS* extensions) {
    // Skip the certID, certStatus, thisUpdate and optional nextUpdate fields.
    if (!CBS_get_any_asn1_element(single_response, nullptr /* certID */, nullptr, nullptr) ||
        !CBS_get_any_asn1_element(single_response, nullptr /* certStatus */, nullptr, nullptr) ||
        !CBS_get_any_asn1_element(single_response, nullptr /* thisUpdate */, nullptr, nullptr) ||
        !CBS_get_optional_asn1(single_response, nullptr /* nextUpdate */, nullptr,
                               CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
        return false;
    }

    // Get the list of Extension
    return CBS_get_asn1(single_response, extensions,
                        CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1) == 1;
}

/*
 * X509v3_get_ext_by_OBJ and X509v3_get_ext take const arguments, unlike the other *_get_ext
 * functions.
 * This means they cannot be used with X509Type_get_ext_oid, so these wrapper functions are used
 * instead.
 */
static int _X509v3_get_ext_by_OBJ(X509_EXTENSIONS* exts, ASN1_OBJECT* obj, int lastpos) {
    return X509v3_get_ext_by_OBJ(exts, obj, lastpos);
}

static X509_EXTENSION* _X509v3_get_ext(X509_EXTENSIONS* exts, int loc) {
    return X509v3_get_ext(exts, loc);
}

/*
    public static native byte[] get_ocsp_single_extension(byte[] ocspData, String oid,
                                                          long x509Ref, long issuerX509Ref);
*/
static jbyteArray NativeCrypto_get_ocsp_single_extension(
        JNIEnv* env, jclass, jbyteArray ocspDataBytes, jstring oid, jlong x509Ref,
        CONSCRYPT_UNUSED jobject holder, jlong issuerX509Ref, CONSCRYPT_UNUSED jobject holder2) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    ScopedByteArrayRO ocspData(env, ocspDataBytes);
    if (ocspData.get() == nullptr) {
        return nullptr;
    }

    CBS cbs;
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(ocspData.get()), ocspData.size());

    // Start parsing the OCSPResponse
    CBS ocsp_response;
    if (!CBS_get_asn1(&cbs, &ocsp_response, CBS_ASN1_SEQUENCE)) {
        return nullptr;
    }

    // Get the BasicOCSPResponse from the OCSP Response
    CBS basic_response;
    if (!get_ocsp_basic_response(&ocsp_response, &basic_response)) {
        return nullptr;
    }

    // Get the list of SingleResponses from the BasicOCSPResponse
    CBS responses;
    if (!get_ocsp_single_responses(&basic_response, &responses)) {
        return nullptr;
    }

    // Find the response matching the certificate
    X509* x509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(x509Ref));
    X509* issuerX509 = reinterpret_cast<X509*>(static_cast<uintptr_t>(issuerX509Ref));
    CBS single_response;
    if (!find_ocsp_single_response(&responses, x509, issuerX509, &single_response)) {
        return nullptr;
    }

    // Get the extensions from the SingleResponse
    CBS extensions;
    if (!get_ocsp_single_response_extensions(&single_response, &extensions)) {
        return nullptr;
    }

    const uint8_t* ptr = CBS_data(&extensions);
    bssl::UniquePtr<X509_EXTENSIONS> x509_exts(
            d2i_X509_EXTENSIONS(nullptr, &ptr,
                                static_cast<long>(CBS_len(&extensions))));  // NOLINT(runtime/int)
    if (x509_exts.get() == nullptr) {
        return nullptr;
    }

    return X509Type_get_ext_oid<X509_EXTENSIONS, _X509v3_get_ext_by_OBJ, _X509v3_get_ext>(
            env, x509_exts.get(), oid);
}

static jlong NativeCrypto_getDirectBufferAddress(JNIEnv* env, jclass, jobject buffer) {
    return reinterpret_cast<jlong>(env->GetDirectBufferAddress(buffer));
}

static jint NativeCrypto_SSL_get_error(JNIEnv* env, jclass, jlong ssl_address,
                                       CONSCRYPT_UNUSED jobject ssl_holder, jint ret) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == nullptr) {
        return 0;
    }
    return SSL_get_error(ssl, ret);
}

static void NativeCrypto_SSL_clear_error(JNIEnv*, jclass) {
    ERR_clear_error();
}

static jint NativeCrypto_SSL_pending_readable_bytes(JNIEnv* env, jclass, jlong ssl_address,
                                                    CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == nullptr) {
        return 0;
    }
    return SSL_pending(ssl);
}

static jint NativeCrypto_SSL_pending_written_bytes_in_BIO(JNIEnv* env, jclass, jlong bio_address) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    BIO* bio = to_SSL_BIO(env, bio_address, true);
    if (bio == nullptr) {
        return 0;
    }
    return static_cast<jint>(BIO_ctrl_pending(bio));
}

static jint NativeCrypto_SSL_max_seal_overhead(JNIEnv* env, jclass, jlong ssl_address,
                                               CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == nullptr) {
        return 0;
    }
    return (jint)SSL_max_seal_overhead(ssl);
}

/**
 * public static native int SSL_new_BIO(long ssl) throws SSLException;
 */
static jlong NativeCrypto_SSL_BIO_new(JNIEnv* env, jclass, jlong ssl_address,
                                      CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_BIO_new", ssl);
    if (ssl == nullptr) {
        return 0;
    }

    BIO* internal_bio;
    BIO* network_bio;
    if (BIO_new_bio_pair(&internal_bio, 0, &network_bio, 0) != 1) {
        conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, SSL_ERROR_NONE,
                                                           "BIO_new_bio_pair failed");
        JNI_TRACE("ssl=%p NativeCrypto_SSL_BIO_new => BIO_new_bio_pair exception", ssl);
        return 0;
    }

    SSL_set_bio(ssl, internal_bio, internal_bio);

    JNI_TRACE("ssl=%p NativeCrypto_SSL_BIO_new => network_bio=%p", ssl, network_bio);
    return reinterpret_cast<uintptr_t>(network_bio);
}

static jint NativeCrypto_ENGINE_SSL_do_handshake(JNIEnv* env, jclass, jlong ssl_address,
                                                 CONSCRYPT_UNUSED jobject ssl_holder, jobject shc) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == nullptr) {
        return 0;
    }
    JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_do_handshake shc=%p", ssl, shc);

    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_do_handshake => sslHandshakeCallbacks == null",
                  ssl);
        return 0;
    }

    AppData* appData = toAppData(ssl);
    if (appData == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to retrieve application data");
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_do_handshake appData => 0", ssl);
        return 0;
    }

    errno = 0;

    if (!appData->setCallbackState(env, shc, nullptr)) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to set appdata callback");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_do_handshake => exception", ssl);
        return 0;
    }

    int ret = SSL_do_handshake(ssl);
    appData->clearCallbackState();
    if (env->ExceptionCheck()) {
        // cert_verify_callback threw exception
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_do_handshake => exception", ssl);
        return 0;
    }

    SslError sslError(ssl, ret);
    int code = sslError.get();

    if (ret > 0 || code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE) {
        // Non-exceptional case.
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_do_handshake shc=%p => ret=%d", ssl, shc, code);
        return code;
    }

    // Exceptional case...
    if (ret == 0) {
        // TODO(nmittler): Can this happen with memory BIOs?
        /*
         * Clean error. See SSL_do_handshake(3SSL) man page.
         * The other side closed the socket before the handshake could be
         * completed, but everything is within the bounds of the TLS protocol.
         * We still might want to find out the real reason of the failure.
         */
        if (code == SSL_ERROR_NONE || (code == SSL_ERROR_SYSCALL && errno == 0) ||
            (code == SSL_ERROR_ZERO_RETURN)) {
            conscrypt::jniutil::throwSSLHandshakeExceptionStr(env, "Connection closed by peer");
        } else {
            conscrypt::jniutil::throwSSLExceptionWithSslErrors(
                    env, ssl, sslError.release(), "SSL handshake terminated",
                    conscrypt::jniutil::throwSSLHandshakeExceptionStr);
        }
        JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake clean error => exception", ssl);
        return code;
    }

    /*
     * Unclean error. See SSL_do_handshake(3SSL) man page.
     * Translate the error and throw exception. We are sure it is an error
     * at this point.
     */
    conscrypt::jniutil::throwSSLExceptionWithSslErrors(
            env, ssl, sslError.release(), "SSL handshake aborted",
            conscrypt::jniutil::throwSSLHandshakeExceptionStr);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_do_handshake unclean error => exception", ssl);
    return code;
}

static void NativeCrypto_ENGINE_SSL_shutdown(JNIEnv* env, jclass, jlong ssl_address,
                                             CONSCRYPT_UNUSED jobject ssl_holder, jobject shc) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, false);
    if (ssl == nullptr) {
        return;
    }
    JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_shutdown", ssl);

    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_shutdown => sslHandshakeCallbacks == null", ssl);
        return;
    }

    AppData* appData = toAppData(ssl);
    if (appData != nullptr) {
        if (!appData->setCallbackState(env, shc, nullptr)) {
            conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to set appdata callback");
            ERR_clear_error();
            JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_shutdown => exception", ssl);
            return;
        }
        int ret = SSL_shutdown(ssl);
        appData->clearCallbackState();
        // callbacks can happen if server requests renegotiation
        if (env->ExceptionCheck()) {
            JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_shutdown => exception", ssl);
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
                JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_shutdown => 0", ssl);
                break;
            case 1:
                /*
                 * Shutdown was successful. We can safely return. Hooray!
                 */
                JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_shutdown => 1", ssl);
                break;
            default:
                /*
                 * Everything else is a real error condition. We should
                 * let the Java layer know about this by throwing an
                 * exception.
                 */
                int sslError = SSL_get_error(ssl, ret);
                JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_shutdown => sslError=%d", ssl, sslError);
                conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, sslError,
                                                                   "SSL shutdown failed");
                break;
        }
    }

    ERR_clear_error();
}

static jint NativeCrypto_ENGINE_SSL_read_direct(JNIEnv* env, jclass, jlong ssl_address,
                                                CONSCRYPT_UNUSED jobject ssl_holder, jlong address,
                                                jint length, jobject shc) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    char* destPtr = reinterpret_cast<char*>(address);
    if (ssl == nullptr) {
        return -1;
    }
    JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_direct address=%p length=%d shc=%p", ssl,
              destPtr, length, shc);

    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_direct => sslHandshakeCallbacks == null",
                  ssl);
        return -1;
    }
    AppData* appData = toAppData(ssl);
    if (appData == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to retrieve application data");
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_direct => appData == null", ssl);
        return -1;
    }
    if (!appData->setCallbackState(env, shc, nullptr)) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to set appdata callback");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_direct => exception", ssl);
        return -1;
    }

    errno = 0;

    int result = SSL_read(ssl, destPtr, length);
    appData->clearCallbackState();
    if (env->ExceptionCheck()) {
        // An exception was thrown by one of the callbacks. Just propagate that exception.
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_direct => THROWN_EXCEPTION", ssl);
        return -1;
    }

    SslError sslError(ssl, result);
    switch (sslError.get()) {
        case SSL_ERROR_NONE: {
            // Successfully read at least one byte. Just return the result.
            break;
        }
        case SSL_ERROR_ZERO_RETURN: {
            // A close_notify was received, this stream is finished.
            return -SSL_ERROR_ZERO_RETURN;
        }
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE: {
            // Return the negative of these values.
            result = -sslError.get();
            break;
        }
        case SSL_ERROR_SYSCALL: {
            // A problem occurred during a system call, but this is not
            // necessarily an error.
            if (result == 0) {
                // TODO(nmittler): Can this happen with memory BIOs?
                // Connection closed without proper shutdown. Tell caller we
                // have reached end-of-stream.
                conscrypt::jniutil::throwException(env, "java/io/EOFException", "Read error");
                break;
            }

            if (errno == EINTR) {
                // TODO(nmittler): Can this happen with memory BIOs?
                // System call has been interrupted. Simply retry.
                conscrypt::jniutil::throwException(env, "java/io/InterruptedIOException",
                                                   "Read error");
                break;
            }

            // Note that for all other system call errors we fall through
            // to the default case, which results in an Exception.
            FALLTHROUGH_INTENDED;
        }
        default: {
            // Everything else is basically an error.
            conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, sslError.release(),
                                                               "Read error");
            break;
        }
    }

    JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_direct address=%p length=%d shc=%p result=%d",
              ssl, destPtr, length, shc, result);
    return result;
}

static int NativeCrypto_ENGINE_SSL_write_BIO_direct(JNIEnv* env, jclass, jlong ssl_address,
                                                    CONSCRYPT_UNUSED jobject ssl_holder,
                                                    jlong bioRef, jlong address, jint len,
                                                    jobject shc) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == nullptr) {
        return -1;
    }
    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE(
                "ssl=%p NativeCrypto_ENGINE_SSL_write_BIO_direct => "
                "sslHandshakeCallbacks == null",
                ssl);
        return -1;
    }
    BIO* bio = to_SSL_BIO(env, bioRef, true);
    if (bio == nullptr) {
        return -1;
    }
    if (len < 0 || BIO_ctrl_get_write_guarantee(bio) < static_cast<size_t>(len)) {
        // The network BIO couldn't handle the entire write. Don't write anything, so that we
        // only process one packet at a time.
        return 0;
    }
    const char* sourcePtr = reinterpret_cast<const char*>(address);

    AppData* appData = toAppData(ssl);
    if (appData == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to retrieve application data");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_write_BIO_direct appData => null", ssl);
        return -1;
    }
    if (!appData->setCallbackState(env, shc, nullptr)) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to set appdata callback");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_write_BIO_direct => exception", ssl);
        return -1;
    }

    errno = 0;

    int result = BIO_write(bio, reinterpret_cast<const char*>(sourcePtr), len);
    appData->clearCallbackState();
    JNI_TRACE(
            "ssl=%p NativeCrypto_ENGINE_SSL_write_BIO_direct bio=%p sourcePtr=%p len=%d shc=%p => "
            "ret=%d",
            ssl, bio, sourcePtr, len, shc, result);
    JNI_TRACE_PACKET_DATA(ssl, 'O', reinterpret_cast<const char*>(sourcePtr),
                          static_cast<size_t>(result));
    return result;
}

static int NativeCrypto_ENGINE_SSL_write_BIO_heap(JNIEnv* env, jclass, jlong ssl_address,
                                                  CONSCRYPT_UNUSED jobject ssl_holder, jlong bioRef,
                                                  jbyteArray sourceJava, jint sourceOffset,
                                                  jint sourceLength, jobject shc) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == nullptr) {
        return -1;
    }
    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_write_BIO_heap => sslHandshakeCallbacks == null",
                  ssl);
        return -1;
    }
    BIO* bio = to_SSL_BIO(env, bioRef, true);
    if (bio == nullptr) {
        return -1;
    }
    if (sourceLength < 0 || BIO_ctrl_get_write_guarantee(bio) < static_cast<size_t>(sourceLength)) {
        // The network BIO couldn't handle the entire write. Don't write anything, so that we
        // only process one packet at a time.
        return 0;
    }
    ScopedByteArrayRO source(env, sourceJava);
    if (source.get() == nullptr) {
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_write_BIO_heap => threw exception", ssl);
        return -1;
    }
    if (ARRAY_OFFSET_LENGTH_INVALID(source, sourceOffset, sourceLength)) {
        JNI_TRACE(
                "ssl=%p NativeCrypto_ENGINE_SSL_write_BIO_heap => sourceOffset=%d, "
                "sourceLength=%d, size=%zd",
                ssl, sourceOffset, sourceLength, source.size());
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
                                           nullptr);
        return -1;
    }

    AppData* appData = toAppData(ssl);
    if (appData == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to retrieve application data");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_write_BIO_heap appData => null", ssl);
        return -1;
    }
    if (!appData->setCallbackState(env, shc, nullptr)) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to set appdata callback");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_write_BIO_heap => exception", ssl);
        return -1;
    }

    errno = 0;

    int result = BIO_write(bio, reinterpret_cast<const char*>(source.get()) + sourceOffset,
                           sourceLength);
    appData->clearCallbackState();
    JNI_TRACE(
            "ssl=%p NativeCrypto_ENGINE_SSL_write_BIO_heap bio=%p source=%p sourceOffset=%d "
            "sourceLength=%d shc=%p => ret=%d",
            ssl, bio, source.get(), sourceOffset, sourceLength, shc, result);
    JNI_TRACE_PACKET_DATA(ssl, 'O', reinterpret_cast<const char*>(source.get()) + sourceOffset,
                          static_cast<size_t>(result));
    return result;
}

static int NativeCrypto_ENGINE_SSL_read_BIO_direct(JNIEnv* env, jclass, jlong ssl_address,
                                                   CONSCRYPT_UNUSED jobject ssl_holder,
                                                   jlong bioRef, jlong address, jint outputSize,
                                                   jobject shc) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == nullptr) {
        return -1;
    }
    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_BIO_direct => sslHandshakeCallbacks == null",
                  ssl);
        return -1;
    }
    BIO* bio = to_SSL_BIO(env, bioRef, true);
    if (bio == nullptr) {
        return -1;
    }
    char* destPtr = reinterpret_cast<char*>(address);
    if (destPtr == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "destPtr == null");
        return -1;
    }

    AppData* appData = toAppData(ssl);
    if (appData == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to retrieve application data");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_BIO_direct appData => null", ssl);
        return -1;
    }
    if (!appData->setCallbackState(env, shc, nullptr)) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to set appdata callback");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_BIO_direct => exception", ssl);
        return -1;
    }

    errno = 0;

    int result = BIO_read(bio, destPtr, outputSize);
    appData->clearCallbackState();
    JNI_TRACE(
            "ssl=%p NativeCrypto_ENGINE_SSL_read_BIO_direct bio=%p destPtr=%p outputSize=%d shc=%p "
            "=> ret=%d",
            ssl, bio, destPtr, outputSize, shc, result);
    JNI_TRACE_PACKET_DATA(ssl, 'I', destPtr, static_cast<size_t>(result));
    return result;
}

static int NativeCrypto_ENGINE_SSL_read_BIO_heap(JNIEnv* env, jclass, jlong ssl_address,
                                                 CONSCRYPT_UNUSED jobject ssl_holder, jlong bioRef,
                                                 jbyteArray destJava, jint destOffset,
                                                 jint destLength, jobject shc) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == nullptr) {
        return -1;
    }
    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_BIO_heap => sslHandshakeCallbacks == null",
                  ssl);
        return -1;
    }
    BIO* bio = to_SSL_BIO(env, bioRef, true);
    if (bio == nullptr) {
        return -1;
    }
    ScopedByteArrayRW dest(env, destJava);
    if (dest.get() == nullptr) {
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_BIO_heap => threw exception", ssl);
        return -1;
    }
    if (ARRAY_OFFSET_LENGTH_INVALID(dest, destOffset, destLength)) {
        JNI_TRACE(
                "ssl=%p NativeCrypto_ENGINE_SSL_read_BIO_heap => destOffset=%d, destLength=%d, "
                "size=%zd",
                ssl, destOffset, destLength, dest.size());
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
                                           nullptr);
        return -1;
    }

    AppData* appData = toAppData(ssl);
    if (appData == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to retrieve application data");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_BIO_heap appData => null", ssl);
        return -1;
    }
    if (!appData->setCallbackState(env, shc, nullptr)) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to set appdata callback");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_read_BIO_heap => exception", ssl);
        return -1;
    }

    errno = 0;

    int result = BIO_read(bio, reinterpret_cast<char*>(dest.get()) + destOffset, destLength);
    appData->clearCallbackState();
    JNI_TRACE(
            "ssl=%p NativeCrypto_ENGINE_SSL_read_BIO_heap bio=%p dest=%p destOffset=%d "
            "destLength=%d shc=%p => ret=%d",
            ssl, bio, dest.get(), destOffset, destLength, shc, result);
    JNI_TRACE_PACKET_DATA(ssl, 'I', reinterpret_cast<char*>(dest.get()) + destOffset,
                          static_cast<size_t>(result));
    return result;
}

static void NativeCrypto_ENGINE_SSL_force_read(JNIEnv* env, jclass, jlong ssl_address,
                                               CONSCRYPT_UNUSED jobject ssl_holder, jobject shc) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == nullptr) {
        return;
    }
    JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_force_read shc=%p", ssl, shc);
    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_force_read => sslHandshakeCallbacks == null",
                  ssl);
        return;
    }
    AppData* appData = toAppData(ssl);
    if (appData == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to retrieve application data");
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_force_read => appData == null", ssl);
        return;
    }
    if (!appData->setCallbackState(env, shc, nullptr)) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to set appdata callback");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_force_read => exception", ssl);
        return;
    }
    char c;
    int result = SSL_peek(ssl, &c, 1);
    appData->clearCallbackState();
    if (env->ExceptionCheck()) {
        // An exception was thrown by one of the callbacks. Just propagate that exception.
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_force_read => THROWN_EXCEPTION", ssl);
        return;
    }

    SslError sslError(ssl, result);
    switch (sslError.get()) {
        case SSL_ERROR_NONE:
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE: {
            // The call succeeded, lacked data, or the SSL is closed.  All is well.
            break;
        }
        case SSL_ERROR_SYSCALL: {
            // A problem occurred during a system call, but this is not
            // necessarily an error.
            if (result == 0) {
                // TODO(nmittler): Can this happen with memory BIOs?
                // Connection closed without proper shutdown. Tell caller we
                // have reached end-of-stream.
                conscrypt::jniutil::throwException(env, "java/io/EOFException", "Read error");
                break;
            }

            if (errno == EINTR) {
                // TODO(nmittler): Can this happen with memory BIOs?
                // System call has been interrupted. Simply retry.
                conscrypt::jniutil::throwException(env, "java/io/InterruptedIOException",
                                                   "Read error");
                break;
            }

            // Note that for all other system call errors we fall through
            // to the default case, which results in an Exception.
            FALLTHROUGH_INTENDED;
        }
        default: {
            // Everything else is basically an error.
            conscrypt::jniutil::throwSSLExceptionWithSslErrors(env, ssl, sslError.release(),
                                                               "Read error");
            break;
        }
    }

    JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_force_read shc=%p", ssl, shc);
}

/**
 * OpenSSL write function (2): write into buffer at offset n chunks.
 */
static int NativeCrypto_ENGINE_SSL_write_direct(JNIEnv* env, jclass, jlong ssl_address,
                                                CONSCRYPT_UNUSED jobject ssl_holder, jlong address,
                                                jint len, jobject shc) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    const char* sourcePtr = reinterpret_cast<const char*>(address);
    if (ssl == nullptr) {
        return -1;
    }
    JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_write_direct address=%p length=%d shc=%p", ssl,
              sourcePtr, len, shc);
    if (shc == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "sslHandshakeCallbacks == null");
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_write_direct => sslHandshakeCallbacks == null",
                  ssl);
        return -1;
    }

    AppData* appData = toAppData(ssl);
    if (appData == nullptr) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to retrieve application data");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_write_direct appData => null", ssl);
        return -1;
    }
    if (!appData->setCallbackState(env, shc, nullptr)) {
        conscrypt::jniutil::throwSSLExceptionStr(env, "Unable to set appdata callback");
        ERR_clear_error();
        JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_write_direct => exception", ssl);
        return -1;
    }

    errno = 0;

    int result = SSL_write(ssl, sourcePtr, len);
    appData->clearCallbackState();
    JNI_TRACE("ssl=%p NativeCrypto_ENGINE_SSL_write_direct address=%p length=%d shc=%p => ret=%d",
              ssl, sourcePtr, len, shc, result);
    return result;
}

// TESTING METHODS BEGIN

static int NativeCrypto_BIO_read(JNIEnv* env, jclass, jlong bioRef, jbyteArray outputJavaBytes) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("BIO_read(%p, %p)", bio, outputJavaBytes);

    if (outputJavaBytes == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "output == null");
        JNI_TRACE("BIO_read(%p, %p) => output == null", bio, outputJavaBytes);
        return 0;
    }

    jsize outputSize = env->GetArrayLength(outputJavaBytes);

    std::unique_ptr<unsigned char[]> buffer(
            new unsigned char[static_cast<unsigned int>(outputSize)]);
    if (buffer.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate buffer for read");
        return 0;
    }

    int read = BIO_read(bio, buffer.get(), static_cast<int>(outputSize));
    if (read <= 0) {
        conscrypt::jniutil::throwIOException(env, "BIO_read");
        JNI_TRACE("BIO_read(%p, %p) => threw IO exception", bio, outputJavaBytes);
        return 0;
    }

    env->SetByteArrayRegion(outputJavaBytes, 0, read, reinterpret_cast<jbyte*>(buffer.get()));
    JNI_TRACE("BIO_read(%p, %p) => %d", bio, outputJavaBytes, read);
    return read;
}

static void NativeCrypto_BIO_write(JNIEnv* env, jclass, jlong bioRef, jbyteArray inputJavaBytes,
                                   jint offset, jint length) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    BIO* bio = reinterpret_cast<BIO*>(static_cast<uintptr_t>(bioRef));
    JNI_TRACE("BIO_write(%p, %p, %d, %d)", bio, inputJavaBytes, offset, length);

    if (inputJavaBytes == nullptr) {
        conscrypt::jniutil::throwNullPointerException(env, "input == null");
        return;
    }

    int inputSize = env->GetArrayLength(inputJavaBytes);
    if (offset < 0 || offset > inputSize || length < 0 || length > inputSize - offset) {
        conscrypt::jniutil::throwException(env, "java/lang/ArrayIndexOutOfBoundsException",
                                           "inputJavaBytes");
        JNI_TRACE("BIO_write(%p, %p, %d, %d) => IOOB", bio, inputJavaBytes, offset, length);
        return;
    }

    std::unique_ptr<unsigned char[]> buffer(new unsigned char[static_cast<unsigned int>(length)]);
    if (buffer.get() == nullptr) {
        conscrypt::jniutil::throwOutOfMemory(env, "Unable to allocate buffer for write");
        return;
    }

    env->GetByteArrayRegion(inputJavaBytes, offset, length, reinterpret_cast<jbyte*>(buffer.get()));
    if (BIO_write(bio, buffer.get(), length) != length) {
        ERR_clear_error();
        conscrypt::jniutil::throwIOException(env, "BIO_write");
        JNI_TRACE("BIO_write(%p, %p, %d, %d) => IO error", bio, inputJavaBytes, offset, length);
        return;
    }

    JNI_TRACE("BIO_write(%p, %p, %d, %d) => success", bio, inputJavaBytes, offset, length);
}

/**
 * public static native long SSL_clear_mode(long ssl, long mode);
 */
static jlong NativeCrypto_SSL_clear_mode(JNIEnv* env, jclass, jlong ssl_address,
                                         CONSCRYPT_UNUSED jobject ssl_holder, jlong mode) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("ssl=%p NativeCrypto_SSL_clear_mode mode=0x%llx", ssl, (long long)mode);
    if (ssl == nullptr) {
        return 0;
    }
    jlong result = static_cast<jlong>(SSL_clear_mode(ssl, static_cast<uint32_t>(mode)));
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("ssl=%p NativeCrypto_SSL_clear_mode => 0x%lx", ssl, (long)result);
    return result;
}

/**
 * public static native long SSL_get_mode(long ssl);
 */
static jlong NativeCrypto_SSL_get_mode(JNIEnv* env, jclass, jlong ssl_address,
                                       CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_mode", ssl);
    if (ssl == nullptr) {
        return 0;
    }
    jlong mode = static_cast<jlong>(SSL_get_mode(ssl));
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_mode => 0x%lx", ssl, (long)mode);
    return mode;
}

/**
 * public static native long SSL_get_options(long ssl);
 */
static jlong NativeCrypto_SSL_get_options(JNIEnv* env, jclass, jlong ssl_address,
                                          CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_options", ssl);
    if (ssl == nullptr) {
        return 0;
    }
    jlong options = static_cast<jlong>(SSL_get_options(ssl));
    // NOLINTNEXTLINE(runtime/int)
    JNI_TRACE("ssl=%p NativeCrypto_SSL_get_options => 0x%lx", ssl, (long)options);
    return options;
}

static jlong NativeCrypto_SSL_get1_session(JNIEnv* env, jclass, jlong ssl_address,
                                           CONSCRYPT_UNUSED jobject ssl_holder) {
    CHECK_ERROR_QUEUE_ON_RETURN;
    SSL* ssl = to_SSL(env, ssl_address, true);
    if (ssl == nullptr) {
        return 0;
    }
    return reinterpret_cast<uintptr_t>(SSL_get1_session(ssl));
}

// TESTING METHODS END

#define CONSCRYPT_NATIVE_METHOD(functionName, signature)             \
    {                                                                \
        /* NOLINTNEXTLINE */                                         \
        (char*)#functionName, (char*)(signature),                    \
                reinterpret_cast<void*>(NativeCrypto_##functionName) \
    }

#define FILE_DESCRIPTOR "Ljava/io/FileDescriptor;"
#define SSL_CALLBACKS \
    "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeCrypto$SSLHandshakeCallbacks;"
#define REF_EC_GROUP "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EC_GROUP;"
#define REF_EC_POINT "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EC_POINT;"
#define REF_EVP_CIPHER_CTX \
    "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_CIPHER_CTX;"
#define REF_EVP_MD_CTX "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_MD_CTX;"
#define REF_EVP_PKEY "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_PKEY;"
#define REF_EVP_PKEY_CTX "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$EVP_PKEY_CTX;"
#define REF_HMAC_CTX "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeRef$HMAC_CTX;"
#define REF_BIO_IN_STREAM "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/OpenSSLBIOInputStream;"
#define REF_X509 "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/OpenSSLX509Certificate;"
#define REF_X509_CRL "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/OpenSSLX509CRL;"
#define REF_SSL "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeSsl;"
#define REF_SSL_CTX "L" TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/AbstractSessionContext;"
static JNINativeMethod sNativeCryptoMethods[] = {
        CONSCRYPT_NATIVE_METHOD(clinit, "()V"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_new_RSA, "([B[B[B[B[B[B[B[B)J"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_new_EC_KEY, "(" REF_EC_GROUP REF_EC_POINT "[B)J"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_type, "(" REF_EVP_PKEY ")I"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_print_public, "(" REF_EVP_PKEY ")Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_print_params, "(" REF_EVP_PKEY ")Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_free, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_cmp, "(" REF_EVP_PKEY REF_EVP_PKEY ")I"),
        CONSCRYPT_NATIVE_METHOD(EVP_marshal_private_key, "(" REF_EVP_PKEY ")[B"),
        CONSCRYPT_NATIVE_METHOD(EVP_parse_private_key, "([B)J"),
        CONSCRYPT_NATIVE_METHOD(EVP_marshal_public_key, "(" REF_EVP_PKEY ")[B"),
        CONSCRYPT_NATIVE_METHOD(EVP_parse_public_key, "([B)J"),
        CONSCRYPT_NATIVE_METHOD(PEM_read_bio_PUBKEY, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(PEM_read_bio_PrivateKey, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(getRSAPrivateKeyWrapper, "(Ljava/security/PrivateKey;[B)J"),
        CONSCRYPT_NATIVE_METHOD(getECPrivateKeyWrapper,
                                "(Ljava/security/PrivateKey;" REF_EC_GROUP ")J"),
        CONSCRYPT_NATIVE_METHOD(RSA_generate_key_ex, "(I[B)J"),
        CONSCRYPT_NATIVE_METHOD(RSA_size, "(" REF_EVP_PKEY ")I"),
        CONSCRYPT_NATIVE_METHOD(RSA_private_encrypt, "(I[B[B" REF_EVP_PKEY "I)I"),
        CONSCRYPT_NATIVE_METHOD(RSA_public_decrypt, "(I[B[B" REF_EVP_PKEY "I)I"),
        CONSCRYPT_NATIVE_METHOD(RSA_public_encrypt, "(I[B[B" REF_EVP_PKEY "I)I"),
        CONSCRYPT_NATIVE_METHOD(RSA_private_decrypt, "(I[B[B" REF_EVP_PKEY "I)I"),
        CONSCRYPT_NATIVE_METHOD(get_RSA_private_params, "(" REF_EVP_PKEY ")[[B"),
        CONSCRYPT_NATIVE_METHOD(get_RSA_public_params, "(" REF_EVP_PKEY ")[[B"),
        CONSCRYPT_NATIVE_METHOD(chacha20_encrypt_decrypt, "([BI[BII[B[BI)V"),
        CONSCRYPT_NATIVE_METHOD(EC_GROUP_new_by_curve_name, "(Ljava/lang/String;)J"),
        CONSCRYPT_NATIVE_METHOD(EC_GROUP_new_arbitrary, "([B[B[B[B[B[BI)J"),
        CONSCRYPT_NATIVE_METHOD(EC_GROUP_get_curve_name, "(" REF_EC_GROUP ")Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(EC_GROUP_get_curve, "(" REF_EC_GROUP ")[[B"),
        CONSCRYPT_NATIVE_METHOD(EC_GROUP_get_order, "(" REF_EC_GROUP ")[B"),
        CONSCRYPT_NATIVE_METHOD(EC_GROUP_get_degree, "(" REF_EC_GROUP ")I"),
        CONSCRYPT_NATIVE_METHOD(EC_GROUP_get_cofactor, "(" REF_EC_GROUP ")[B"),
        CONSCRYPT_NATIVE_METHOD(EC_GROUP_clear_free, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(EC_GROUP_get_generator, "(" REF_EC_GROUP ")J"),
        CONSCRYPT_NATIVE_METHOD(EC_POINT_new, "(" REF_EC_GROUP ")J"),
        CONSCRYPT_NATIVE_METHOD(EC_POINT_clear_free, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(EC_POINT_set_affine_coordinates,
                                "(" REF_EC_GROUP REF_EC_POINT "[B[B)V"),
        CONSCRYPT_NATIVE_METHOD(EC_POINT_get_affine_coordinates,
                                "(" REF_EC_GROUP REF_EC_POINT ")[[B"),
        CONSCRYPT_NATIVE_METHOD(EC_KEY_generate_key, "(" REF_EC_GROUP ")J"),
        CONSCRYPT_NATIVE_METHOD(EC_KEY_get1_group, "(" REF_EVP_PKEY ")J"),
        CONSCRYPT_NATIVE_METHOD(EC_KEY_get_private_key, "(" REF_EVP_PKEY ")[B"),
        CONSCRYPT_NATIVE_METHOD(EC_KEY_get_public_key, "(" REF_EVP_PKEY ")J"),
        CONSCRYPT_NATIVE_METHOD(EC_KEY_marshal_curve_name, "(" REF_EC_GROUP ")[B"),
        CONSCRYPT_NATIVE_METHOD(EC_KEY_parse_curve_name, "([B)J"),
        CONSCRYPT_NATIVE_METHOD(ECDH_compute_key, "([BI" REF_EVP_PKEY REF_EVP_PKEY ")I"),
        CONSCRYPT_NATIVE_METHOD(ECDSA_size, "(" REF_EVP_PKEY ")I"),
        CONSCRYPT_NATIVE_METHOD(ECDSA_sign, "([B[B" REF_EVP_PKEY ")I"),
        CONSCRYPT_NATIVE_METHOD(ECDSA_verify, "([B[B" REF_EVP_PKEY ")I"),
        CONSCRYPT_NATIVE_METHOD(EVP_MD_CTX_create, "()J"),
        CONSCRYPT_NATIVE_METHOD(EVP_MD_CTX_cleanup, "(" REF_EVP_MD_CTX ")V"),
        CONSCRYPT_NATIVE_METHOD(EVP_MD_CTX_destroy, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_MD_CTX_copy_ex, "(" REF_EVP_MD_CTX REF_EVP_MD_CTX ")I"),
        CONSCRYPT_NATIVE_METHOD(EVP_DigestInit_ex, "(" REF_EVP_MD_CTX "J)I"),
        CONSCRYPT_NATIVE_METHOD(EVP_DigestUpdate, "(" REF_EVP_MD_CTX "[BII)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_DigestUpdateDirect, "(" REF_EVP_MD_CTX "JI)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_DigestFinal_ex, "(" REF_EVP_MD_CTX "[BI)I"),
        CONSCRYPT_NATIVE_METHOD(EVP_get_digestbyname, "(Ljava/lang/String;)J"),
        CONSCRYPT_NATIVE_METHOD(EVP_MD_size, "(J)I"),
        CONSCRYPT_NATIVE_METHOD(EVP_DigestSignInit, "(" REF_EVP_MD_CTX "J" REF_EVP_PKEY ")J"),
        CONSCRYPT_NATIVE_METHOD(EVP_DigestSignUpdate, "(" REF_EVP_MD_CTX "[BII)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_DigestSignUpdateDirect, "(" REF_EVP_MD_CTX "JI)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_DigestSignFinal, "(" REF_EVP_MD_CTX ")[B"),
        CONSCRYPT_NATIVE_METHOD(EVP_DigestVerifyInit, "(" REF_EVP_MD_CTX "J" REF_EVP_PKEY ")J"),
        CONSCRYPT_NATIVE_METHOD(EVP_DigestVerifyUpdate, "(" REF_EVP_MD_CTX "[BII)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_DigestVerifyUpdateDirect, "(" REF_EVP_MD_CTX "JI)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_DigestVerifyFinal, "(" REF_EVP_MD_CTX "[BII)Z"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_encrypt_init, "(" REF_EVP_PKEY ")J"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_encrypt, "(" REF_EVP_PKEY_CTX "[BI[BII)I"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_decrypt_init, "(" REF_EVP_PKEY ")J"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_decrypt, "(" REF_EVP_PKEY_CTX "[BI[BII)I"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_CTX_free, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_CTX_set_rsa_padding, "(JI)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_CTX_set_rsa_pss_saltlen, "(JI)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_CTX_set_rsa_mgf1_md, "(JJ)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_CTX_set_rsa_oaep_md, "(JJ)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_PKEY_CTX_set_rsa_oaep_label, "(J[B)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_get_cipherbyname, "(Ljava/lang/String;)J"),
        CONSCRYPT_NATIVE_METHOD(EVP_CipherInit_ex, "(" REF_EVP_CIPHER_CTX "J[B[BZ)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_CipherUpdate, "(" REF_EVP_CIPHER_CTX "[BI[BII)I"),
        CONSCRYPT_NATIVE_METHOD(EVP_CipherFinal_ex, "(" REF_EVP_CIPHER_CTX "[BI)I"),
        CONSCRYPT_NATIVE_METHOD(EVP_CIPHER_iv_length, "(J)I"),
        CONSCRYPT_NATIVE_METHOD(EVP_CIPHER_CTX_new, "()J"),
        CONSCRYPT_NATIVE_METHOD(EVP_CIPHER_CTX_block_size, "(" REF_EVP_CIPHER_CTX ")I"),
        CONSCRYPT_NATIVE_METHOD(get_EVP_CIPHER_CTX_buf_len, "(" REF_EVP_CIPHER_CTX ")I"),
        CONSCRYPT_NATIVE_METHOD(get_EVP_CIPHER_CTX_final_used, "(" REF_EVP_CIPHER_CTX ")Z"),
        CONSCRYPT_NATIVE_METHOD(EVP_CIPHER_CTX_set_padding, "(" REF_EVP_CIPHER_CTX "Z)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_CIPHER_CTX_set_key_length, "(" REF_EVP_CIPHER_CTX "I)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_CIPHER_CTX_free, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_aead_aes_128_gcm, "()J"),
        CONSCRYPT_NATIVE_METHOD(EVP_aead_aes_256_gcm, "()J"),
        CONSCRYPT_NATIVE_METHOD(EVP_aead_chacha20_poly1305, "()J"),
        CONSCRYPT_NATIVE_METHOD(EVP_aead_aes_128_gcm_siv, "()J"),
        CONSCRYPT_NATIVE_METHOD(EVP_aead_aes_256_gcm_siv, "()J"),
        CONSCRYPT_NATIVE_METHOD(EVP_AEAD_max_overhead, "(J)I"),
        CONSCRYPT_NATIVE_METHOD(EVP_AEAD_nonce_length, "(J)I"),
        CONSCRYPT_NATIVE_METHOD(EVP_AEAD_CTX_seal, "(J[BI[BI[B[BII[B)I"),
        CONSCRYPT_NATIVE_METHOD(EVP_AEAD_CTX_open, "(J[BI[BI[B[BII[B)I"),
        CONSCRYPT_NATIVE_METHOD(HMAC_CTX_new, "()J"),
        CONSCRYPT_NATIVE_METHOD(HMAC_CTX_free, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(HMAC_Init_ex, "(" REF_HMAC_CTX "[BJ)V"),
        CONSCRYPT_NATIVE_METHOD(HMAC_Update, "(" REF_HMAC_CTX "[BII)V"),
        CONSCRYPT_NATIVE_METHOD(HMAC_UpdateDirect, "(" REF_HMAC_CTX "JI)V"),
        CONSCRYPT_NATIVE_METHOD(HMAC_Final, "(" REF_HMAC_CTX ")[B"),
        CONSCRYPT_NATIVE_METHOD(RAND_bytes, "([B)V"),
        CONSCRYPT_NATIVE_METHOD(create_BIO_InputStream, ("(" REF_BIO_IN_STREAM "Z)J")),
        CONSCRYPT_NATIVE_METHOD(create_BIO_OutputStream, "(Ljava/io/OutputStream;)J"),
        CONSCRYPT_NATIVE_METHOD(BIO_free_all, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(d2i_X509_bio, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(d2i_X509, "([B)J"),
        CONSCRYPT_NATIVE_METHOD(i2d_X509, "(J" REF_X509 ")[B"),
        CONSCRYPT_NATIVE_METHOD(i2d_X509_PUBKEY, "(J" REF_X509 ")[B"),
        CONSCRYPT_NATIVE_METHOD(PEM_read_bio_X509, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(PEM_read_bio_PKCS7, "(JI)[J"),
        CONSCRYPT_NATIVE_METHOD(d2i_PKCS7_bio, "(JI)[J"),
        CONSCRYPT_NATIVE_METHOD(i2d_PKCS7, "([J)[B"),
        CONSCRYPT_NATIVE_METHOD(ASN1_seq_unpack_X509_bio, "(J)[J"),
        CONSCRYPT_NATIVE_METHOD(ASN1_seq_pack_X509, "([J)[B"),
        CONSCRYPT_NATIVE_METHOD(X509_free, "(J" REF_X509 ")V"),
        CONSCRYPT_NATIVE_METHOD(X509_dup, "(J" REF_X509 ")J"),
        CONSCRYPT_NATIVE_METHOD(X509_cmp, "(J" REF_X509 "J" REF_X509 ")I"),
        CONSCRYPT_NATIVE_METHOD(X509_print_ex, "(JJ" REF_X509 "JJ)V"),
        CONSCRYPT_NATIVE_METHOD(X509_get_pubkey, "(J" REF_X509 ")J"),
        CONSCRYPT_NATIVE_METHOD(X509_get_issuer_name, "(J" REF_X509 ")[B"),
        CONSCRYPT_NATIVE_METHOD(X509_get_subject_name, "(J" REF_X509 ")[B"),
        CONSCRYPT_NATIVE_METHOD(get_X509_pubkey_oid, "(J" REF_X509 ")Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(get_X509_sig_alg_oid, "(J" REF_X509 ")Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(get_X509_sig_alg_parameter, "(J" REF_X509 ")[B"),
        CONSCRYPT_NATIVE_METHOD(get_X509_issuerUID, "(J" REF_X509 ")[Z"),
        CONSCRYPT_NATIVE_METHOD(get_X509_subjectUID, "(J" REF_X509 ")[Z"),
        CONSCRYPT_NATIVE_METHOD(get_X509_ex_kusage, "(J" REF_X509 ")[Z"),
        CONSCRYPT_NATIVE_METHOD(get_X509_ex_xkusage, "(J" REF_X509 ")[Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(get_X509_ex_pathlen, "(J" REF_X509 ")I"),
        CONSCRYPT_NATIVE_METHOD(X509_get_ext_oid, "(J" REF_X509 "Ljava/lang/String;)[B"),
        CONSCRYPT_NATIVE_METHOD(X509_CRL_get_ext_oid, "(J" REF_X509_CRL "Ljava/lang/String;)[B"),
        CONSCRYPT_NATIVE_METHOD(X509_delete_ext, "(J" REF_X509 "Ljava/lang/String;)V"),
        CONSCRYPT_NATIVE_METHOD(get_X509_CRL_crl_enc, "(J" REF_X509_CRL ")[B"),
        CONSCRYPT_NATIVE_METHOD(X509_CRL_verify, "(J" REF_X509_CRL REF_EVP_PKEY ")V"),
        CONSCRYPT_NATIVE_METHOD(X509_CRL_get_lastUpdate, "(J" REF_X509_CRL ")J"),
        CONSCRYPT_NATIVE_METHOD(X509_CRL_get_nextUpdate, "(J" REF_X509_CRL ")J"),
        CONSCRYPT_NATIVE_METHOD(X509_REVOKED_get_ext_oid, "(JLjava/lang/String;)[B"),
        CONSCRYPT_NATIVE_METHOD(X509_REVOKED_get_serialNumber, "(J)[B"),
        CONSCRYPT_NATIVE_METHOD(X509_REVOKED_print, "(JJ)V"),
        CONSCRYPT_NATIVE_METHOD(get_X509_REVOKED_revocationDate, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(get_X509_ext_oids, "(J" REF_X509 "I)[Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(get_X509_CRL_ext_oids, "(J" REF_X509_CRL "I)[Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(get_X509_REVOKED_ext_oids, "(JI)[Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(get_X509_GENERAL_NAME_stack,
                                "(J" REF_X509 "I)[[Ljava/lang/Object;"),
        CONSCRYPT_NATIVE_METHOD(X509_get_notBefore, "(J" REF_X509 ")J"),
        CONSCRYPT_NATIVE_METHOD(X509_get_notAfter, "(J" REF_X509 ")J"),
        CONSCRYPT_NATIVE_METHOD(X509_get_version, "(J" REF_X509 ")J"),
        CONSCRYPT_NATIVE_METHOD(X509_get_serialNumber, "(J" REF_X509 ")[B"),
        CONSCRYPT_NATIVE_METHOD(X509_verify, "(J" REF_X509 REF_EVP_PKEY ")V"),
        CONSCRYPT_NATIVE_METHOD(get_X509_cert_info_enc, "(J" REF_X509 ")[B"),
        CONSCRYPT_NATIVE_METHOD(get_X509_signature, "(J" REF_X509 ")[B"),
        CONSCRYPT_NATIVE_METHOD(get_X509_CRL_signature, "(J" REF_X509_CRL ")[B"),
        CONSCRYPT_NATIVE_METHOD(get_X509_ex_flags, "(J" REF_X509 ")I"),
        CONSCRYPT_NATIVE_METHOD(X509_check_issued, "(J" REF_X509 "J" REF_X509 ")I"),
        CONSCRYPT_NATIVE_METHOD(d2i_X509_CRL_bio, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(PEM_read_bio_X509_CRL, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(X509_CRL_get0_by_cert, "(J" REF_X509_CRL "J" REF_X509 ")J"),
        CONSCRYPT_NATIVE_METHOD(X509_CRL_get0_by_serial, "(J" REF_X509_CRL "[B)J"),
        CONSCRYPT_NATIVE_METHOD(X509_CRL_get_REVOKED, "(J" REF_X509_CRL ")[J"),
        CONSCRYPT_NATIVE_METHOD(i2d_X509_CRL, "(J" REF_X509_CRL ")[B"),
        CONSCRYPT_NATIVE_METHOD(X509_CRL_free, "(J" REF_X509_CRL ")V"),
        CONSCRYPT_NATIVE_METHOD(X509_CRL_print, "(JJ" REF_X509_CRL ")V"),
        CONSCRYPT_NATIVE_METHOD(get_X509_CRL_sig_alg_oid, "(J" REF_X509_CRL ")Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(get_X509_CRL_sig_alg_parameter, "(J" REF_X509_CRL ")[B"),
        CONSCRYPT_NATIVE_METHOD(X509_CRL_get_issuer_name, "(J" REF_X509_CRL ")[B"),
        CONSCRYPT_NATIVE_METHOD(X509_CRL_get_version, "(J" REF_X509_CRL ")J"),
        CONSCRYPT_NATIVE_METHOD(X509_CRL_get_ext, "(J" REF_X509_CRL "Ljava/lang/String;)J"),
        CONSCRYPT_NATIVE_METHOD(X509_REVOKED_get_ext, "(JLjava/lang/String;)J"),
        CONSCRYPT_NATIVE_METHOD(X509_REVOKED_dup, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(i2d_X509_REVOKED, "(J)[B"),
        CONSCRYPT_NATIVE_METHOD(X509_supported_extension, "(J)I"),
        CONSCRYPT_NATIVE_METHOD(ASN1_TIME_to_Calendar, "(JLjava/util/Calendar;)V"),
        CONSCRYPT_NATIVE_METHOD(asn1_read_init, "([B)J"),
        CONSCRYPT_NATIVE_METHOD(asn1_read_sequence, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(asn1_read_next_tag_is, "(JI)Z"),
        CONSCRYPT_NATIVE_METHOD(asn1_read_tagged, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(asn1_read_octetstring, "(J)[B"),
        CONSCRYPT_NATIVE_METHOD(asn1_read_uint64, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(asn1_read_null, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(asn1_read_oid, "(J)Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(asn1_read_is_empty, "(J)Z"),
        CONSCRYPT_NATIVE_METHOD(asn1_read_free, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(asn1_write_init, "()J"),
        CONSCRYPT_NATIVE_METHOD(asn1_write_sequence, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(asn1_write_tag, "(JI)J"),
        CONSCRYPT_NATIVE_METHOD(asn1_write_octetstring, "(J[B)V"),
        CONSCRYPT_NATIVE_METHOD(asn1_write_uint64, "(JJ)V"),
        CONSCRYPT_NATIVE_METHOD(asn1_write_null, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(asn1_write_oid, "(JLjava/lang/String;)V"),
        CONSCRYPT_NATIVE_METHOD(asn1_write_flush, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(asn1_write_cleanup, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(asn1_write_finish, "(J)[B"),
        CONSCRYPT_NATIVE_METHOD(asn1_write_free, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(EVP_has_aes_hardware, "()I"),
        CONSCRYPT_NATIVE_METHOD(SSL_CTX_new, "()J"),
        CONSCRYPT_NATIVE_METHOD(SSL_CTX_free, "(J" REF_SSL_CTX ")V"),
        CONSCRYPT_NATIVE_METHOD(SSL_CTX_set_session_id_context, "(J" REF_SSL_CTX "[B)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_CTX_set_timeout, "(J" REF_SSL_CTX "J)J"),
        CONSCRYPT_NATIVE_METHOD(SSL_new, "(J" REF_SSL_CTX ")J"),
        CONSCRYPT_NATIVE_METHOD(SSL_enable_tls_channel_id, "(J" REF_SSL ")V"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_tls_channel_id, "(J" REF_SSL ")[B"),
        CONSCRYPT_NATIVE_METHOD(SSL_set1_tls_channel_id, "(J" REF_SSL REF_EVP_PKEY ")V"),
        CONSCRYPT_NATIVE_METHOD(setLocalCertsAndPrivateKey, "(J" REF_SSL "[[B" REF_EVP_PKEY ")V"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_client_CA_list, "(J" REF_SSL "[[B)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_mode, "(J" REF_SSL "J)J"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_options, "(J" REF_SSL "J)J"),
        CONSCRYPT_NATIVE_METHOD(SSL_clear_options, "(J" REF_SSL "J)J"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_protocol_versions, "(J" REF_SSL "II)I"),
        CONSCRYPT_NATIVE_METHOD(SSL_enable_signed_cert_timestamps, "(J" REF_SSL ")V"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_signed_cert_timestamp_list, "(J" REF_SSL ")[B"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_signed_cert_timestamp_list, "(J" REF_SSL "[B)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_enable_ocsp_stapling, "(J" REF_SSL ")V"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_ocsp_response, "(J" REF_SSL ")[B"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_ocsp_response, "(J" REF_SSL "[B)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_tls_unique, "(J" REF_SSL ")[B"),
        CONSCRYPT_NATIVE_METHOD(SSL_export_keying_material, "(J" REF_SSL "[B[BI)[B"),
        CONSCRYPT_NATIVE_METHOD(SSL_use_psk_identity_hint, "(J" REF_SSL "Ljava/lang/String;)V"),
        CONSCRYPT_NATIVE_METHOD(set_SSL_psk_client_callback_enabled, "(J" REF_SSL "Z)V"),
        CONSCRYPT_NATIVE_METHOD(set_SSL_psk_server_callback_enabled, "(J" REF_SSL "Z)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_cipher_lists, "(J" REF_SSL "[Ljava/lang/String;)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_ciphers, "(J" REF_SSL ")[J"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_accept_state, "(J" REF_SSL ")V"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_connect_state, "(J" REF_SSL ")V"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_verify, "(J" REF_SSL "I)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_session, "(J" REF_SSL "J)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_session_creation_enabled, "(J" REF_SSL "Z)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_session_reused, "(J" REF_SSL ")Z"),
        CONSCRYPT_NATIVE_METHOD(SSL_accept_renegotiations, "(J" REF_SSL ")V"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_tlsext_host_name, "(J" REF_SSL "Ljava/lang/String;)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_servername, "(J" REF_SSL ")Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(SSL_do_handshake, "(J" REF_SSL FILE_DESCRIPTOR SSL_CALLBACKS "I)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_current_cipher, "(J" REF_SSL ")Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_version, "(J" REF_SSL ")Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(SSL_get0_peer_certificates, "(J" REF_SSL ")[[B"),
        CONSCRYPT_NATIVE_METHOD(SSL_read, "(J" REF_SSL FILE_DESCRIPTOR SSL_CALLBACKS "[BIII)I"),
        CONSCRYPT_NATIVE_METHOD(SSL_write, "(J" REF_SSL FILE_DESCRIPTOR SSL_CALLBACKS "[BIII)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_interrupt, "(J" REF_SSL ")V"),
        CONSCRYPT_NATIVE_METHOD(SSL_shutdown, "(J" REF_SSL FILE_DESCRIPTOR SSL_CALLBACKS ")V"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_shutdown, "(J" REF_SSL ")I"),
        CONSCRYPT_NATIVE_METHOD(SSL_free, "(J" REF_SSL ")V"),
        CONSCRYPT_NATIVE_METHOD(SSL_SESSION_session_id, "(J)[B"),
        CONSCRYPT_NATIVE_METHOD(SSL_SESSION_get_time, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_time, "(J" REF_SSL ")J"),
        CONSCRYPT_NATIVE_METHOD(SSL_set_timeout, "(J" REF_SSL "J)J"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_timeout, "(J" REF_SSL ")J"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_signature_algorithm_key_type, "(I)I"),
        CONSCRYPT_NATIVE_METHOD(SSL_SESSION_get_timeout, "(J)J"),
        CONSCRYPT_NATIVE_METHOD(SSL_session_id, "(J" REF_SSL ")[B"),
        CONSCRYPT_NATIVE_METHOD(SSL_SESSION_get_version, "(J)Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(SSL_SESSION_cipher, "(J)Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(SSL_SESSION_should_be_single_use, "(J)Z"),
        CONSCRYPT_NATIVE_METHOD(SSL_SESSION_up_ref, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_SESSION_free, "(J)V"),
        CONSCRYPT_NATIVE_METHOD(i2d_SSL_SESSION, "(J)[B"),
        CONSCRYPT_NATIVE_METHOD(d2i_SSL_SESSION, "([B)J"),
        CONSCRYPT_NATIVE_METHOD(getApplicationProtocol, "(J" REF_SSL ")[B"),
        CONSCRYPT_NATIVE_METHOD(setApplicationProtocols, "(J" REF_SSL "Z[B)V"),
        CONSCRYPT_NATIVE_METHOD(setHasApplicationProtocolSelector, "(J" REF_SSL "Z)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_CIPHER_get_kx_name, "(J)Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(get_cipher_names, "(Ljava/lang/String;)[Ljava/lang/String;"),
        CONSCRYPT_NATIVE_METHOD(get_ocsp_single_extension,
                                "([BLjava/lang/String;J" REF_X509 "J" REF_X509 ")[B"),
        CONSCRYPT_NATIVE_METHOD(getDirectBufferAddress, "(Ljava/nio/Buffer;)J"),
        CONSCRYPT_NATIVE_METHOD(SSL_BIO_new, "(J" REF_SSL ")J"),
        CONSCRYPT_NATIVE_METHOD(SSL_max_seal_overhead, "(J" REF_SSL ")I"),
        CONSCRYPT_NATIVE_METHOD(SSL_clear_error, "()V"),
        CONSCRYPT_NATIVE_METHOD(SSL_pending_readable_bytes, "(J" REF_SSL ")I"),
        CONSCRYPT_NATIVE_METHOD(SSL_pending_written_bytes_in_BIO, "(J)I"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_error, "(J" REF_SSL "I)I"),
        CONSCRYPT_NATIVE_METHOD(ENGINE_SSL_do_handshake, "(J" REF_SSL SSL_CALLBACKS ")I"),
        CONSCRYPT_NATIVE_METHOD(ENGINE_SSL_read_direct, "(J" REF_SSL "JI" SSL_CALLBACKS ")I"),
        CONSCRYPT_NATIVE_METHOD(ENGINE_SSL_write_direct, "(J" REF_SSL "JI" SSL_CALLBACKS ")I"),
        CONSCRYPT_NATIVE_METHOD(ENGINE_SSL_write_BIO_direct, "(J" REF_SSL "JJI" SSL_CALLBACKS ")I"),
        CONSCRYPT_NATIVE_METHOD(ENGINE_SSL_read_BIO_direct, "(J" REF_SSL "JJI" SSL_CALLBACKS ")I"),
        CONSCRYPT_NATIVE_METHOD(ENGINE_SSL_write_BIO_heap, "(J" REF_SSL "J[BII" SSL_CALLBACKS ")I"),
        CONSCRYPT_NATIVE_METHOD(ENGINE_SSL_read_BIO_heap, "(J" REF_SSL "J[BII" SSL_CALLBACKS ")I"),
        CONSCRYPT_NATIVE_METHOD(ENGINE_SSL_force_read, "(J" REF_SSL SSL_CALLBACKS ")V"),
        CONSCRYPT_NATIVE_METHOD(ENGINE_SSL_shutdown, "(J" REF_SSL SSL_CALLBACKS ")V"),

        // Used for testing only.
        CONSCRYPT_NATIVE_METHOD(BIO_read, "(J[B)I"),
        CONSCRYPT_NATIVE_METHOD(BIO_write, "(J[BII)V"),
        CONSCRYPT_NATIVE_METHOD(SSL_clear_mode, "(J" REF_SSL "J)J"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_mode, "(J" REF_SSL ")J"),
        CONSCRYPT_NATIVE_METHOD(SSL_get_options, "(J" REF_SSL ")J"),
        CONSCRYPT_NATIVE_METHOD(SSL_get1_session, "(J" REF_SSL ")J"),
};

void NativeCrypto::registerNativeMethods(JNIEnv* env) {
    conscrypt::jniutil::jniRegisterNativeMethods(
            env, TO_STRING(JNI_JARJAR_PREFIX) "org/conscrypt/NativeCrypto", sNativeCryptoMethods,
            NELEM(sNativeCryptoMethods));
}

/* Local Variables: */
/* mode: c++ */
/* tab-width: 4 */
/* indent-tabs-mode: nil */
/* c-basic-offset: 4 */
/* End: */
/* vim: set softtabstop=4 shiftwidth=4 expandtab: */
