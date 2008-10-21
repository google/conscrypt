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

/**
 * @author Boris Kuznetsov
 * @version $Revision$
 */
package org.apache.harmony.xnet.provider.jsse;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

/**
 * KeyManager implementation.
 * This implementation uses hashed key store information.
 * It works faster than retrieving all of the data from the key store.
 * Any key store changes, that happen after key manager was created, have no effect.
 * The implementation does not use peer information (host, port)
 * that may be obtained from socket or engine.
 * 
 * @see javax.net.ssl.KeyManager
 * 
 */
public class KeyManagerImpl extends X509ExtendedKeyManager {

    // hashed key store information
    private final Hashtable hash = new Hashtable();

    /**
     * Creates Key manager
     * 
     * @param keyStore
     * @param pwd
     */
    public KeyManagerImpl(KeyStore keyStore, char[] pwd) {
        String alias;
        KeyStore.PrivateKeyEntry entry;
        Enumeration aliases;
        try {
            aliases = keyStore.aliases();
        } catch (KeyStoreException e) {
            return;
        }
        for (; aliases.hasMoreElements();) {
            alias = (String) aliases.nextElement();          
            try {
                if (keyStore.entryInstanceOf(alias,
                        KeyStore.PrivateKeyEntry.class)) {
                    entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
                            new KeyStore.PasswordProtection(pwd));
                    hash.put(alias, entry);
                }
            } catch (KeyStoreException e) {
                continue;
            } catch (UnrecoverableEntryException e) {
                continue;
            } catch (NoSuchAlgorithmException e) {
                continue;
            }
        }

    }

    /**
     * @see javax.net.ssl.X509ExtendedKeyManager#chooseClientAlias(String[]
     *      keyType, Principal[] issuers, Socket socket)
     */
    public String chooseClientAlias(String[] keyType, Principal[] issuers,
            Socket socket) {
        String[] al = chooseAlias(keyType, issuers);
        if (al != null) {
            return al[0];
        } else {
            return null;
        }
    }

    /**
     * @see javax.net.ssl.X509ExtendedKeyManager#chooseServerAlias(String
     *      keyType, Principal[] issuers, Socket socket)
     */
    public String chooseServerAlias(String keyType, Principal[] issuers,
            Socket socket) {
        String[] al = chooseAlias(new String[] { keyType }, issuers);
        if (al != null) {
            return al[0];
        } else {
            return null;
        }
    }

    /**
     * @see javax.net.ssl.X509ExtendedKeyManager#getCertificateChain(String
     *      alias)
     */
    public X509Certificate[] getCertificateChain(String alias) {
        if (hash.containsKey(alias)) {
            Certificate[] certs = ((KeyStore.PrivateKeyEntry) hash.get(alias))
                    .getCertificateChain();
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

    /**
     * @see javax.net.ssl.X509ExtendedKeyManager#getClientAliases(String
     *      keyType, Principal[] issuers)
     */
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return chooseAlias(new String[] { keyType }, issuers);
    }

    /**
     * @see javax.net.ssl.X509ExtendedKeyManager#getServerAliases(String
     *      keyType, Principal[] issuers)
     */
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return chooseAlias(new String[] { keyType }, issuers);
    }

    /**
     * @see javax.net.ssl.X509ExtendedKeyManager#getPrivateKey(String alias)
     */
    public PrivateKey getPrivateKey(String alias) {
        if (hash.containsKey(alias)) {
            return ((KeyStore.PrivateKeyEntry) hash.get(alias)).getPrivateKey();
        }
        return null;
    }

    /**
     * @see javax.net.ssl.X509ExtendedKeyManager#chooseEngineClientAlias(String[]
     *      keyType, Principal[] issuers, SSLEngine engine)
     */
    public String chooseEngineClientAlias(String[] keyType,
            Principal[] issuers, SSLEngine engine) {
        String[] al = chooseAlias(keyType, issuers);
        if (al != null) {
            return al[0];
        } else {
            return null;
        }
    }

    /**
     * @see javax.net.ssl.X509ExtendedKeyManager#chooseEngineServerAlias(String
     *      keyType, Principal[] issuers, SSLEngine engine)
     */
    public String chooseEngineServerAlias(String keyType, Principal[] issuers,
            SSLEngine engine) {
        String[] al = chooseAlias(new String[] { keyType }, issuers);
        if (al != null) {
            return al[0];
        } else {
            return null;
        }
    }

    private String[] chooseAlias(String[] keyType, Principal[] issuers) {
        String alias;
        KeyStore.PrivateKeyEntry entry;
        
        if (keyType == null || keyType.length == 0) {
            return null;
        }
        Vector found = new Vector();
        int count = 0;
        for (Enumeration aliases = hash.keys(); aliases.hasMoreElements();) {
            alias = (String) aliases.nextElement();
            entry = (KeyStore.PrivateKeyEntry) hash.get(alias);
            Certificate[] certs = entry.getCertificateChain();
            String alg = certs[0].getPublicKey().getAlgorithm();
            for (int i = 0; i < keyType.length; i++) {
                if (alg.equals(keyType[i])) {
                    if (issuers != null && issuers.length != 0) {
                        // check that certificate was issued by specified issuer
                        loop: for (int ii = 0; ii < certs.length; ii++) {
                            if (certs[ii] instanceof X509Certificate) {
                                X500Principal issuer = ((X509Certificate) certs[ii])
                                        .getIssuerX500Principal();
                                for (int iii = 0; iii < issuers.length; iii++) {
                                    if (issuer.equals(issuers[iii])) {
                                        found.add(alias);
                                        count++;
                                        break loop;
                                    }
                                }
                            }

                        }
                    } else {
                        found.add(alias);
                        count++;
                    }
                }
            }
        }
        if (count > 0) {
            String[] result = new String[count];
            found.toArray(result);
            return result;
        } else {
            return null;
        }
    }

}
