/*
 * Copyright 2019 The Android Open Source Project
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

import javax.net.ssl.SSLSession;

/**
 * This interface is used to implement hostname verification in Conscrypt.  Unlike with
 * {@link javax.net.ssl.HostnameVerifier}, the hostname verifier is called whenever hostname
 * verification is needed, without any use of default rules.
 */
public interface ConscryptHostnameVerifier {

  /**
   * Returns whether the given hostname is allowable given the peer's authentication information
   * from the given session.
   */
  boolean verify(String hostname, SSLSession session);

}
