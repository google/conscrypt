/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.conscrypt;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.KeyManager;
import java.security.Principal;

/**
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public class SpakeKeyManager implements KeyManager {
  byte[] password;
  byte[] idProver;
  byte[] idVerifier;
  byte[] context;

  SpakeKeyManager(byte[] password, byte[] idProver,
      byte[] idVerifier, byte[] context) {
    this.password = password;
    this.idProver = idProver;
    this.idVerifier = idVerifier;
    this.context = context;
  }

  public String chooseEngineAlias(String keyType,
          Principal[] issuers, SSLEngine engine) {
      return null;
  }

  public String chooseEngineClientAlias(String[] keyType,
          Principal[] issuers, SSLEngine engine) {
    throw new UnsupportedOperationException("Not implemented");
  }

  public byte[] getContext() {
    return context;
  }

  public byte[] getPassword() {
    return password;
  }

  public byte[] getIdProver() {
    return idProver;
  }

  public byte[] getIdVerifier() {
    return idVerifier;
  }
}