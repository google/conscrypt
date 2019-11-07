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

package org.conscrypt;

import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

/**
 * Extends the default interface for {@link SSLSession} to provide additional properties exposed
 * by Conscrypt.
 */
interface ConscryptSession extends SSLSession {

  String getRequestedServerName();

  /**
   * Returns the OCSP stapled response. Returns a copy of the internal arrays.
   *
   * The method signature matches
   * <a
   * href="http://download.java.net/java/jdk9/docs/api/javax/net/ssl/ExtendedSSLSession.html#getStatusResponses--">Java
   * 9</a>.
   *
   * @see <a href="https://tools.ietf.org/html/rfc6066">RFC 6066</a>
   * @see <a href="https://tools.ietf.org/html/rfc6961">RFC 6961</a>
   */
  List<byte[]> getStatusResponses();

  /**
   * Returns the signed certificate timestamp (SCT) received from the peer. Returns a
   * copy of the internal array.
   *
   * @see <a href="https://tools.ietf.org/html/rfc6962">RFC 6962</a>
   */
  byte[] getPeerSignedCertificateTimestamp();

  @Override
  X509Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException;

  String getApplicationProtocol();
}
