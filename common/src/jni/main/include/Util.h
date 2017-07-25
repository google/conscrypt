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

#ifndef CONSCRYPT_UTIL_H_
#define CONSCRYPT_UTIL_H_

namespace conscrypt {

/**
 * Various utility methods used by the native API.
 */
class Util {
private:
    Util() {}
    ~Util() {}

public:

    /**
     * Converts a Java byte[] two's complement to an OpenSSL BIGNUM. This will
     * allocate the BIGNUM if *dest == nullptr. Returns true on success. If the
     * return value is false, there is a pending exception.
     */
    static bool arrayToBignum(JNIEnv* env, jbyteArray source, BIGNUM** dest) {
        JNI_TRACE("arrayToBignum(%p, %p)", source, dest);
        if (dest == nullptr) {
            JNI_TRACE("arrayToBignum(%p, %p) => dest is null!", source, dest);
            Errors::jniThrowNullPointerException(env, "dest == null");
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
        BIGNUM *ret = BN_bin2bn(tmp, tmpSize, *dest);
        if (ret == nullptr) {
            Errors::jniThrowRuntimeException(env, "Conversion to BIGNUM failed");
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
            Errors::jniThrowRuntimeException(env, "Negative number");
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
            Errors::jniThrowNullPointerException(env, sourceName);
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
            Errors::throwExceptionIfNecessary(env, "bignumToArray");
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
    static jbyteArray ASN1ToByteArray(JNIEnv* env, T* obj, int (*i2d_func)(T*, unsigned char**)) {
        if (obj == nullptr) {
            Errors::jniThrowNullPointerException(env, "ASN1 input == null");
            JNI_TRACE("ASN1ToByteArray(%p) => null input", obj);
            return nullptr;
        }

        int derLen = i2d_func(obj, nullptr);
        if (derLen < 0) {
            Errors::throwExceptionIfNecessary(env, "ASN1ToByteArray");
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
            Errors::throwExceptionIfNecessary(env, "ASN1ToByteArray");
            JNI_TRACE("ASN1ToByteArray(%p) => final conversion failed", obj);
            return nullptr;
        }

        JNI_TRACE("ASN1ToByteArray(%p) => success (%d bytes written)", obj, ret);
        return byteArray.release();
    }

    /**
     * Finishes a pending CBB and returns a jbyteArray with the contents.
     */
    static jbyteArray CBBToByteArray(JNIEnv* env, CBB* cbb) {
        uint8_t* data;
        size_t len;
        if (!CBB_finish(cbb, &data, &len)) {
            Errors::jniThrowRuntimeException(env, "CBB_finish failed");
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

    /**
     * Converts ASN.1 BIT STRING to a jbooleanArray.
     */
    static jbooleanArray ASN1BitStringToBooleanArray(JNIEnv* env, ASN1_BIT_STRING* bitStr) {
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
            bitsArray[i] =
                    static_cast<jboolean>(ASN1_BIT_STRING_get_bit(bitStr, static_cast<int>(i)));
        }

        return bitsRef.release();
    }
};

}  // namespace conscrypt

#endif  // CONSCRYPT_UTIL_H_
