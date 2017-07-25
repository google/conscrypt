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

#include "TlsCallbacks.h"

#include "AppData.h"
#include "JniConstants.h"
#include "ScopedPrimitiveArray.h"
#include "Util.h"

using namespace conscrypt;

int TlsCallbacks::cert_verify_callback(X509_STORE_CTX *x509_store_ctx, void *arg) {
    /* Get the correct index to the SSLobject stored into X509_STORE_CTX. */
    SSL* ssl = reinterpret_cast<SSL*>(X509_STORE_CTX_get_ex_data(x509_store_ctx,
            SSL_get_ex_data_X509_STORE_CTX_idx()));
    JNI_TRACE("ssl=%p cert_verify_callback x509_store_ctx=%p arg=%p", ssl, x509_store_ctx, arg);

    AppData* appData = AppData::getAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        ALOGE("AppData->env missing in cert_verify_callback");
        JNI_TRACE("ssl=%p cert_verify_callback => 0", ssl);
        return 0;
    }
    // Get a stack of all certs in the chain
    STACK_OF(CRYPTO_BUFFER)* buffers = SSL_get0_peer_certificates(ssl);

    int numBuffers = sk_CRYPTO_BUFFER_num(buffers);

    // Create the byte[][] array that holds all the certs
    ScopedLocalRef<jobjectArray> array(env,
        env->NewObjectArray(numBuffers, JniConstants::byteArrayClass, nullptr));

    for(unsigned i = 0; i < numBuffers; ++i) {
        CRYPTO_BUFFER* buffer = sk_CRYPTO_BUFFER_value(buffers, i);
        int length = CRYPTO_BUFFER_len(buffer);
        ScopedLocalRef<jbyteArray> bArray(env, env->NewByteArray(length));
        env->SetByteArrayRegion(bArray.get(), 0, length, (jbyte*) CRYPTO_BUFFER_data(buffer));
        env->SetObjectArrayElement(array.get(), i, bArray.get());
    }

    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;
    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID = env->GetMethodID(cls, "verifyCertificateChain",
                                          "([[BLjava/lang/String;)V");

    const SSL_CIPHER *cipher = SSL_get_pending_cipher(ssl);
    const char *authMethod = SSL_CIPHER_get_kx_name(cipher);

    JNI_TRACE("ssl=%p cert_verify_callback calling verifyCertificateChain authMethod=%s",
              ssl, authMethod);
    jstring authMethodString = env->NewStringUTF(authMethod);
    env->CallVoidMethod(sslHandshakeCallbacks, methodID, array.get(), authMethodString);

    // We need to delete the local references so we not leak memory as this method is called
    // via callback.
    env->DeleteLocalRef(authMethodString);

    int result = (env->ExceptionCheck()) ? 0 : 1;
    JNI_TRACE("ssl=%p cert_verify_callback => %d", ssl, result);
    return result;
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

void TlsCallbacks::info_callback(const SSL* ssl, int where, int ret) {
    JNI_TRACE("ssl=%p info_callback where=0x%x ret=%d", ssl, where, ret);
    if (Trace::kWithJniTrace) {
        info_callback_LOG(ssl, where, ret);
    }
    if (!(where & SSL_CB_HANDSHAKE_DONE) && !(where & SSL_CB_HANDSHAKE_START)) {
        JNI_TRACE("ssl=%p info_callback ignored", ssl);
        return;
    }

    AppData* appData = AppData::getAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
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
    jmethodID methodID = env->GetMethodID(cls, "onSSLStateChange", "(II)V");

    JNI_TRACE("ssl=%p info_callback calling onSSLStateChange", ssl);
    env->CallVoidMethod(sslHandshakeCallbacks, methodID, where, ret);

    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p info_callback exception", ssl);
    }
    JNI_TRACE("ssl=%p info_callback completed", ssl);
}

/**
 * Returns an array containing all the X500 principal's bytes.
 */
static jobjectArray getPrincipalBytes(JNIEnv* env, const STACK_OF(X509_NAME)* names)
{
    if (names == nullptr) {
        return nullptr;
    }

    int count = static_cast<int>(sk_X509_NAME_num(names));
    if (count <= 0) {
        return nullptr;
    }

    ScopedLocalRef<jobjectArray> joa(
            env, env->NewObjectArray(count, JniConstants::byteArrayClass, nullptr));
    if (joa.get() == nullptr) {
        return nullptr;
    }

    for (int i = 0; i < count; i++) {
        X509_NAME* principal = sk_X509_NAME_value(names, static_cast<size_t>(i));

        ScopedLocalRef<jbyteArray> byteArray(env, Util::ASN1ToByteArray<X509_NAME>(env,
                principal, i2d_X509_NAME));
        if (byteArray.get() == nullptr) {
            return nullptr;
        }
        env->SetObjectArrayElement(joa.get(), i, byteArray.get());
    }

    return joa.release();
}

int TlsCallbacks::cert_cb(SSL* ssl, void*) {
    JNI_TRACE("ssl=%p cert_cb", ssl);

    // cert_cb is called for both clients and servers, but we are only
    // interested in client certificates.
    if (SSL_is_server(ssl)) {
        JNI_TRACE("ssl=%p cert_cb not a client => 1", ssl);
        return 1;
    }

    AppData* appData = AppData::getAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        ALOGE("AppData->env missing in cert_cb");
        JNI_TRACE("ssl=%p cert_cb env error => 0", ssl);
        return 0;
    }
    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p cert_cb already pending exception => 0", ssl);
        return 0;
    }
    jobject sslHandshakeCallbacks = appData->sslHandshakeCallbacks;

    jclass cls = env->GetObjectClass(sslHandshakeCallbacks);
    jmethodID methodID
        = env->GetMethodID(cls, "clientCertificateRequested", "([B[[B)V");

    // Call Java callback which can reconfigure the client certificate.
    const uint8_t* ctype = nullptr;
    size_t ctype_num = SSL_get0_certificate_types(ssl, &ctype);
    jobjectArray issuers = getPrincipalBytes(env, SSL_get_client_CA_list(ssl));

    if (Trace::kWithJniTrace) {
        for (size_t i = 0; i < ctype_num; i++) {
            JNI_TRACE("ssl=%p clientCertificateRequested keyTypes[%zu]=%d", ssl, i, ctype[i]);
        }
    }

    jbyteArray keyTypes = env->NewByteArray(static_cast<jsize>(ctype_num));
    if (keyTypes == nullptr) {
        JNI_TRACE("ssl=%p cert_cb bytes == null => 0", ssl);
        return 0;
    }
    env->SetByteArrayRegion(keyTypes, 0, static_cast<jsize>(ctype_num),
                            reinterpret_cast<const jbyte*>(ctype));

    JNI_TRACE("ssl=%p clientCertificateRequested calling clientCertificateRequested "
              "keyTypes=%p issuers=%p", ssl, keyTypes, issuers);
    env->CallVoidMethod(sslHandshakeCallbacks, methodID, keyTypes, issuers);

    if (env->ExceptionCheck()) {
        JNI_TRACE("ssl=%p cert_cb exception => 0", ssl);
        return 0;
    }

    JNI_TRACE("ssl=%p cert_cb => 1", ssl);
    return 1;
}

unsigned int TlsCallbacks::psk_client_callback(SSL* ssl, const char *hint,
        char *identity, unsigned int max_identity_len,
        unsigned char *psk, unsigned int max_psk_len) {
    JNI_TRACE("ssl=%p psk_client_callback", ssl);

    AppData* appData = AppData::getAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
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

unsigned int TlsCallbacks::psk_server_callback(SSL* ssl, const char *identity,
        unsigned char *psk, unsigned int max_psk_len) {
    JNI_TRACE("ssl=%p psk_server_callback", ssl);

    AppData* appData = AppData::getAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
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
    ScopedLocalRef<jstring> identityHintJava(
            env, (identityHint != nullptr) ? env->NewStringUTF(identityHint) : nullptr);
    ScopedLocalRef<jstring> identityJava(
            env, (identity != nullptr) ? env->NewStringUTF(identity) : nullptr);
    ScopedLocalRef<jbyteArray> keyJava(env, env->NewByteArray(static_cast<jsize>(max_psk_len)));
    if (keyJava.get() == nullptr) {
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
    if (keyJavaRo.get() == nullptr) {
        JNI_TRACE("ssl=%p psk_server_callback failed to get key bytes", ssl);
        return 0;
    }
    memcpy(psk, keyJavaRo.get(), static_cast<size_t>(keyLen));

    JNI_TRACE("ssl=%p psk_server_callback completed", ssl);
    return static_cast<unsigned int>(keyLen);
}

int TlsCallbacks::new_session_callback(SSL* ssl, SSL_SESSION* session) {
    JNI_TRACE("ssl=%p new_session_callback session=%p", ssl, session);

    AppData* appData = AppData::getAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        ALOGE("AppData->env missing in new_session_callback");
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

SSL_SESSION* TlsCallbacks::server_session_requested_callback(SSL* ssl, uint8_t* id, int id_len,
                                                      int* out_copy) {
    JNI_TRACE("ssl=%p server_session_requested_callback", ssl);

    // Always set to out_copy to zero. The Java callback will be responsible for incrementing
    // the reference count (and any required synchronization).
    *out_copy = 0;

    AppData* appData = AppData::getAppData(ssl);
    JNIEnv* env = appData->env;
    if (env == nullptr) {
        ALOGE("AppData->env missing in server_session_requested_callback");
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
    SSL_SESSION* ssl_session_ptr = reinterpret_cast<SSL_SESSION*>(
            static_cast<uintptr_t>(ssl_session_address));
    JNI_TRACE("ssl=%p server_session_requested_callback completed => %p", ssl, ssl_session_ptr);
    return ssl_session_ptr;
}

/**
 * Selects the ALPN protocol to use. The list of protocols in "primary" is considered the order
 * which should take precedence.
 */
static int proto_select(SSL* ssl, unsigned char** out, unsigned char* outLength,
                        const unsigned char* primary, const unsigned int primaryLength,
                        const unsigned char* secondary, const unsigned int secondaryLength) {
    if (primary != nullptr && secondary != nullptr) {
        JNI_TRACE("primary=%p, length=%d", primary, primaryLength);

        int status = SSL_select_next_proto(out, outLength, primary, primaryLength, secondary,
                secondaryLength);
        switch (status) {
        case OPENSSL_NPN_NEGOTIATED:
            JNI_TRACE("ssl=%p proto_select ALPN negotiated", ssl);
            return SSL_TLSEXT_ERR_OK;
            break;
        case OPENSSL_NPN_UNSUPPORTED:
            JNI_TRACE("ssl=%p proto_select ALPN unsupported", ssl);
            break;
        case OPENSSL_NPN_NO_OVERLAP:
            JNI_TRACE("ssl=%p proto_select ALPN no overlap", ssl);
            break;
        }
    } else {
        if (out != nullptr && outLength != nullptr) {
            *out = nullptr;
            *outLength = 0;
        }
        JNI_TRACE("protocols=null");
    }
    return SSL_TLSEXT_ERR_NOACK;
}

/**
 * Callback for the server to select an ALPN protocol.
 */
int TlsCallbacks::alpn_select_callback(SSL* ssl, const unsigned char **out, unsigned char *outlen,
        const unsigned char *in, unsigned int inlen, void *) {
    JNI_TRACE("ssl=%p alpn_select_callback", ssl);

    AppData* appData = AppData::getAppData(ssl);
    JNI_TRACE("AppData=%p", appData);

    return proto_select(ssl, const_cast<unsigned char**>(out), outlen,
                        reinterpret_cast<unsigned char*>(appData->alpnProtocolsData),
                        static_cast<unsigned int>(appData->alpnProtocolsLength), in, inlen);
}