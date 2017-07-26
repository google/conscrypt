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

#ifndef CONSCRYPT_TLSCALLBACKS_H_
#define CONSCRYPT_TLSCALLBACKS_H_

#include <openssl/x509v3.h>

namespace conscrypt {

/**
 * Callbacks for processing various TLS events.
 */
class TlsCallbacks {
private:
  TlsCallbacks(){}
  ~TlsCallbacks(){}

public:

  /**
   * Verifies the peer certificates received during the TLS handshake.
   */
  static int cert_verify_callback(X509_STORE_CTX *x509_store_ctx, void *arg);

  /**
   * Call back to watch for handshake to be completed. This is necessary for
   * False Start support, since SSL_do_handshake returns before the handshake is
   * completed in this case.
   */
  static void info_callback(const SSL* ssl, int where, int ret);

  /**
   * Call back to ask for a certificate. There are three possible exit codes:
   *
   * 1 is success.
   * 0 is error.
   * -1 is to pause the handshake to continue from the same place later.
   */
  static int cert_cb(SSL* ssl, void* arg);

  /**
   * Pre-Shared Key (PSK) client callback.
   */
  static unsigned int psk_client_callback(SSL* ssl, const char *hint,
          char *identity, unsigned int max_identity_len,
          unsigned char *psk, unsigned int max_psk_len);

  /**
   * Pre-Shared Key (PSK) server callback.
   */
  static unsigned int psk_server_callback(SSL* ssl, const char *identity,
          unsigned char *psk, unsigned int max_psk_len);

  /**
   * Client-side callback that is invoked upon successful creation of a new session. Allows the
   * client to cache session state externally (e.g. persistent storage).
   */
  static int new_session_callback(SSL* ssl, SSL_SESSION* session);

  /**
   * Callback to allow the server application to provide cached sessions.
   */
  static SSL_SESSION* server_session_requested_callback(SSL* ssl, uint8_t* id, int id_len,
                                                        int* out_copy);

  /**
   * Callback for the server to select an ALPN protocol.
   */
  static int alpn_select_callback(SSL* ssl, const unsigned char **out, unsigned char *outlen,
          const unsigned char *in, unsigned int inlen, void *);
};

}  // namespace conscrypt

#endif  // CONSCRYPT_TLSCALLBACKS_H_
