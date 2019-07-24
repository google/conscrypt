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

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

/**
 * KeyManager implementation.
 *
 * This implementation uses hashed key store information. It works faster than retrieving all of the
 * data from the key store. Any key store changes, that happen after key manager was created, have
 * no effect. The implementation does not use peer information (host, port) that may be obtained
 * from socket or engine.
 *
 * @see javax.net.ssl.KeyManager
 */
class KeyManagerImpl extends X509ExtendedKeyManager {

    // hashed key store information
    private final HashMap<String, PrivateKeyEntry> hash;

    /**
     * Creates Key manager
     */
    KeyManagerImpl(KeyStore keyStore, char[] pwd) {
        this.hash = new HashMap<String, PrivateKeyEntry>();
        final Enumeration<String> aliases;
        try {
            aliases = keyStore.aliases();
        } catch (KeyStoreException e) {
            return;
        }
        for (; aliases.hasMoreElements();) {
            final String alias = aliases.nextElement();
            try {
                if (keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                    KeyStore.PrivateKeyEntry entry;
                    try {
                        entry = (KeyStore.PrivateKeyEntry) keyStore
                            .getEntry(alias, new KeyStore.PasswordProtection(pwd));
                    } catch (UnsupportedOperationException e) {
                        // If the KeyStore doesn't support getEntry(), as Android Keystore
                        // doesn't, fall back to reading the two values separately.
                        PrivateKey key = (PrivateKey) keyStore.getKey(alias, pwd);
                        Certificate[] certs = keyStore.getCertificateChain(alias);
                        entry = new KeyStore.PrivateKeyEntry(key, certs);
                    }
                    hash.put(alias, entry);
                }
            } catch (KeyStoreException ignored) {
                // Ignored.
            } catch (UnrecoverableEntryException ignored) {
                // Ignored.
            } catch (NoSuchAlgorithmException ignored) {
                // Ignored.
            }
        }
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        final String[] al = chooseAlias(keyTypes, issuers);
        return (al == null ? null : al[0]);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        final String[] al = chooseAlias(new String[] { keyType }, issuers);
        return (al == null ? null : al[0]);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (alias == null) {
            return null;
        }
        if (hash.containsKey(alias)) {
            Certificate[] certs = hash.get(alias).getCertificateChain();
            if (certs[0] instanceof X509Certificate) {
                X509Certificate[] xcerts = new X509Certificate[certs.length];
                for (int i = 0; i < certs.length; i++) {
                    xcerts[i] = (X509Certificate) certs[i];
                }
                return xcerts;
            }
        }
        return null;

    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return chooseAlias(new String[] { keyType }, issuers);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return chooseAlias(new String[] { keyType }, issuers);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        if (alias == null) {
            return null;
        }
        if (hash.containsKey(alias)) {
            return hash.get(alias).getPrivateKey();
        }
        return null;
    }

    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        final String[] al = chooseAlias(keyTypes, issuers);
        return (al == null ? null : al[0]);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        final String[] al = chooseAlias(new String[] { keyType }, issuers);
        return (al == null ? null : al[0]);
    }

    private String[] chooseAlias(String[] keyTypes, Principal[] issuers) {
        if (keyTypes == null || keyTypes.length == 0) {
            return null;
        }
        List<Principal> issuersList = (issuers == null) ? null : Arrays.asList(issuers);
        ArrayList<String> found = new ArrayList<String>();
        for (final Map.Entry<String, PrivateKeyEntry> entry : hash.entrySet()) {
            final String alias = entry.getKey();
            final Certificate[] chain = entry.getValue().getCertificateChain();
            final Certificate cert = chain[0];
            final String certKeyAlg = cert.getPublicKey().getAlgorithm();
            final String certSigAlg = (cert instanceof X509Certificate
                                       ? ((X509Certificate) cert).getSigAlgName().toUpperCase(Locale.US)
                                       : null);
            for (String keyAlgorithm : keyTypes) {
                if (keyAlgorithm == null) {
                    continue;
                }
                final String sigAlgorithm;
                // handle cases like EC_EC and EC_RSA
                int index = keyAlgorithm.indexOf('_');
                if (index == -1) {
                    sigAlgorithm = null;
                } else {
                    sigAlgorithm = keyAlgorithm.substring(index + 1);
                    keyAlgorithm = keyAlgorithm.substring(0, index);
                }
                // key algorithm does not match
                if (!certKeyAlg.equals(keyAlgorithm)) {
                    continue;
                }
                /*
                 * TODO find a more reliable test for signature
                 * algorithm. Unfortunately value varies with
                 * provider. For example for "EC" it could be
                 * "SHA1WithECDSA" or simply "ECDSA".
                 */
                // sig algorithm does not match
                if (sigAlgorithm != null && certSigAlg != null
                        && !certSigAlg.contains(sigAlgorithm)) {
                    continue;
                }
                // no issuers to match, just add to return list and continue
                if (issuers == null || issuers.length == 0) {
                    found.add(alias);
                    continue;
                }
                // check that a certificate in the chain was issued by one of the specified issuers
                for (Certificate certFromChain : chain) {
                    if (!(certFromChain instanceof X509Certificate)) {
                        // skip non-X509Certificates
                        continue;
                    }
                    X509Certificate xcertFromChain = (X509Certificate) certFromChain;
                    /*
                     * Note use of X500Principal from
                     * getIssuerX500Principal as opposed to Principal
                     * from getIssuerDN. Principal.equals test does
                     * not work in the case where
                     * xcertFromChain.getIssuerDN is a bouncycastle
                     * org.bouncycastle.jce.X509Principal.
                     */
                    X500Principal issuerFromChain = xcertFromChain.getIssuerX500Principal();
                    if (issuersList.contains(issuerFromChain)) {
                        found.add(alias);
                    }
                }
            }
        }
        if (!found.isEmpty()) {
            return found.toArray(new String[found.size()]);
        }
        return null;
    }
}
