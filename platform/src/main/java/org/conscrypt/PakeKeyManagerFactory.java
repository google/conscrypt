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

import static android.net.ssl.PakeServerKeyManagerParameters.Link;

import static java.util.Objects.requireNonNull;

import android.net.ssl.PakeClientKeyManagerParameters;
import android.net.ssl.PakeOption;
import android.net.ssl.PakeServerKeyManagerParameters;

import org.conscrypt.io.IoUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

/**
 * PakeKeyManagerFactory implementation.
 * @see KeyManagerFactorySpi
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public class PakeKeyManagerFactory extends KeyManagerFactorySpi {
    PakeClientKeyManagerParameters clientParams;
    PakeServerKeyManagerParameters serverParams;

    /**
     * @see KeyManagerFactorySpi#engineInit(KeyStore ks, char[] password)
     */
    @Override
    public void engineInit(KeyStore ks, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        throw new KeyStoreException("KeyStore not supported");
    }

    /**
     * @see KeyManagerFactorySpi#engineInit(ManagerFactoryParameters spec)
     */
    @Override
    public void engineInit(ManagerFactoryParameters spec)
            throws InvalidAlgorithmParameterException {
        if (clientParams != null || serverParams != null) {
            throw new IllegalStateException("PakeKeyManagerFactory is already initialized");
        }
        if (spec == null) {
            throw new InvalidAlgorithmParameterException("ManagerFactoryParameters cannot be null");
        }
        if (spec instanceof PakeClientKeyManagerParameters) {
            clientParams = (PakeClientKeyManagerParameters) spec;
        } else if (spec instanceof PakeServerKeyManagerParameters) {
            serverParams = (PakeServerKeyManagerParameters) spec;
        } else {
            throw new InvalidAlgorithmParameterException("ManagerFactoryParameters not supported");
        }
    }

    /**
     * @see KeyManagerFactorySpi#engineGetKeyManagers()
     */
    @Override
    public KeyManager[] engineGetKeyManagers() {
        if (clientParams == null && serverParams == null) {
            throw new IllegalStateException("PakeKeyManagerFactory is not initialized");
        }
        if (clientParams != null) {
            return initClient();
        } else {
            return initServer();
        }
    }

    private KeyManager[] initClient() {
        List<PakeOption> options = clientParams.getOptions();
        for (PakeOption option : options) {
            if (!option.getAlgorithm().equals("SPAKE2PLUS_PRERELEASE")) {
                continue;
            }
            byte[] idProver = clientParams.getClientId();
            byte[] idVerifier = clientParams.getServerId();
            byte[] context = option.getMessageComponent("context");
            byte[] password = option.getMessageComponent("password");
            if (password != null) {
                return new KeyManager[] {new Spake2PlusKeyManager(
                        context, password, null, null, null, idProver, idVerifier, true)};
            }
            byte[] w0 = option.getMessageComponent("w0");
            byte[] w1 = option.getMessageComponent("w1");
            if (w0 != null && w1 != null) {
                return new KeyManager[] {new Spake2PlusKeyManager(
                        context, null, w0, w1, null, idProver, idVerifier, true)};
            }
            break;
        }
        return new KeyManager[] {};
    }

    private KeyManager[] initServer() {
        Set<Link> links = serverParams.getLinks();
        for (Link link : links) {
            List<PakeOption> options = serverParams.getOptions(link);
            for (PakeOption option : options) {
                if (!option.getAlgorithm().equals("SPAKE2PLUS_PRERELEASE")) {
                    continue;
                }
                byte[] idProver = link.getClientId();
                byte[] idVerifier = link.getServerId();
                byte[] context = option.getMessageComponent("context");
                byte[] password = option.getMessageComponent("password");
                if (password != null) {
                    return new KeyManager[] {new Spake2PlusKeyManager(
                            context, password, null, null, null, idProver, idVerifier, false)};
                }
                byte[] w0 = option.getMessageComponent("w0");
                byte[] l = option.getMessageComponent("L");
                if (w0 != null && l != null) {
                    return new KeyManager[] {new Spake2PlusKeyManager(
                            context, null, w0, null, l, idProver, idVerifier, false)};
                }
                break;
            }
        }
        return new KeyManager[] {};
    }
}
