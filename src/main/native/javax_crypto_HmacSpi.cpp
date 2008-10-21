/*
 * Copyright (C) 2006 The Android Open Source Project
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

#include <jni.h>
#include <JNIHelp.h>
//#include <android_runtime/AndroidRuntime.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <string.h>


jbyteArray native_compute_sha1_hmac(JNIEnv* env, jobject object,
                                    jbyteArray keyArray, jbyteArray dataArray)
{
    uint8_t * output = (uint8_t *)malloc(EVP_MAX_MD_SIZE);
    if (!output) {
        jniThrowException(env, "java/lang/OutOfMemoryError", NULL);
        return NULL;
    }
    uint32_t outputSize;

    jbyte * key = env->GetByteArrayElements(keyArray, NULL);
    int keySize = env->GetArrayLength(keyArray);

    jbyte * data = env->GetByteArrayElements(dataArray, NULL);
    int dataSize = env->GetArrayLength(dataArray);

    HMAC(EVP_sha1(),
        (unsigned char const *)key, keySize,
        (unsigned char const *)data, dataSize,
        output, &outputSize);

    env->ReleaseByteArrayElements(keyArray, key, 0);
    env->ReleaseByteArrayElements(dataArray, data, 0);

    jbyteArray outputArray = env->NewByteArray(outputSize);
    if (!output) {
        jniThrowException(env, "java/lang/OutOfMemoryError", NULL);
        free(output);
        return NULL;
    }    

    jbyte * outputBytes = env->GetByteArrayElements(outputArray, NULL);
    memcpy(outputBytes, output, outputSize);
    env->ReleaseByteArrayElements(outputArray, outputBytes, 0);

    free(output);

    return outputArray;
}

/*
 * JNI registration.
 */
static JNINativeMethod sMethods[] = {
    /* name, signature, funcPtr */
    { "native_compute_sha1_hmac", "([B[B)[B", (void*)native_compute_sha1_hmac },
};

extern "C" int register_javax_crypto_HmacSpi(JNIEnv* env)
{
    return jniRegisterNativeMethods(env, "javax/crypto/HmacSpi", sMethods, NELEM(sMethods));
}


