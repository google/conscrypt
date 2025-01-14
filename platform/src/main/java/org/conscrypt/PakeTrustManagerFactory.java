/*
 * Copyright (C) 2024 The Android Open Source Project
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

import static java.util.Objects.requireNonNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;

/**
 * A factory for creating {@link SpakeTrustManager} instances that use SPAKE2.
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public class PakeTrustManagerFactory extends TrustManagerFactorySpi {
    /**
     * @see javax.net.ssl.TrustManagerFactorySpi#engineInit(KeyStore)
     */
    @Override
    public void engineInit(KeyStore ks) throws KeyStoreException {
        if (ks != null) {
            throw new KeyStoreException("KeyStore not supported");
        }
    }

    /**
     * @see javax.net.ssl#engineInit(ManagerFactoryParameters)
     */
    @Override
    public void engineInit(ManagerFactoryParameters spec)
            throws InvalidAlgorithmParameterException {
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("ManagerFactoryParameters not supported");
        }
    }

    /**
     * @see javax.net.ssl#engineGetTrustManagers()
     */
    @Override
    public TrustManager[] engineGetTrustManagers() {
        return new TrustManager[] { new Spake2PlusTrustManager() };
    }
}
