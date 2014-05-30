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

import java.security.Provider;

/**
 * JSSE Provider implementation.
 *
 * The current JSSE provider implementation uses the following
 * crypto algorithms:
 *
 * Algorithms that MUST be provided by crypto provider:
 *     Mac    HmacMD5
 *     Mac    HmacSHA1
 *     MessageDigest    MD5
 *     MessageDigest    SHA-1
 *     CertificateFactory    X509
 *
 * Trust manager implementation requires:
 *     CertPathValidator    PKIX
 *     CertificateFactory    X509
 *
 */
public final class JSSEProvider extends Provider {

    private static final long serialVersionUID = 3075686092260669675L;

    public JSSEProvider() {
        super("HarmonyJSSE", 1.0, "Harmony JSSE Provider");

        put("KeyManagerFactory.PKIX", KeyManagerFactoryImpl.class.getName());
        put("Alg.Alias.KeyManagerFactory.X509", "PKIX");

        put("TrustManagerFactory.PKIX", TrustManagerFactoryImpl.class.getName());
        put("Alg.Alias.TrustManagerFactory.X509", "PKIX");

        put("KeyStore.AndroidCAStore", TrustedCertificateKeyStoreSpi.class.getName());
    }
}
