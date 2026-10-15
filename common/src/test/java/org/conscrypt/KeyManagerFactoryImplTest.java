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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.conscrypt.java.security.TestKeyStore;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.ManagerFactoryParameters;

@RunWith(JUnit4.class)
public class KeyManagerFactoryImplTest {
    private TestKeyStore testKeyStore;

    @Before
    public void setUp() {
        testKeyStore = TestKeyStore.getClient();
    }

    private TestKeyStore getTestKeyStore() {
        return testKeyStore;
    }

    @Test
    public void test_KeyManagerFactory_Conscrypt() throws Exception {
        KeyManagerFactory kmf =
                new KeyManagerFactory(new KeyManagerFactoryImpl(), TestUtils.getConscryptProvider(),
                                      KeyManagerFactory.getDefaultAlgorithm()) {};
        test_KeyManagerFactory(kmf);

        // Test that using a KeyStore that doesn't implement getEntry(), like Android Keystore
        // doesn't, still produces a functional KeyManager.
        kmf.init(new NoGetEntryKeyStore(getTestKeyStore().keyStore),
                 getTestKeyStore().storePassword);
        test_KeyManagerFactory_getKeyManagers(kmf, false);
    }

    private void test_KeyManagerFactory(KeyManagerFactory kmf) throws Exception {
        try {
            kmf.getKeyManagers();
            fail();
        } catch (IllegalStateException expected) {
        }

        kmf.init(null, null);
        test_KeyManagerFactory_getKeyManagers(kmf, true);

        kmf.init(getTestKeyStore().keyStore, null);
        test_KeyManagerFactory_getKeyManagers(kmf, true);

        kmf.init(getTestKeyStore().keyStore, getTestKeyStore().storePassword);
        test_KeyManagerFactory_getKeyManagers(kmf, false);

        try {
            kmf.init((ManagerFactoryParameters) null);
            fail();
        } catch (InvalidAlgorithmParameterException expected) {
        }
    }

    private static void test_KeyManagerFactory_getKeyManagers(KeyManagerFactory kmf,
                                                              boolean isDefault) {
        KeyManager[] keyManagers = kmf.getKeyManagers();
        assertNotNull(keyManagers);
        for (KeyManager keyManager : keyManagers) {
            assertNotNull(keyManager);
        }
    }

    private static class NoGetEntryKeyStore extends KeyStore {
        public NoGetEntryKeyStore(KeyStore keyStore) throws Exception {
            super(new NoGetEntryKeyStoreSpi(keyStore), keyStore.getProvider(), keyStore.getType());
            load(null, null);
        }
    }

    private static class NoGetEntryKeyStoreSpi extends KeyStoreSpi {
        private final KeyStore keyStore;

        public NoGetEntryKeyStoreSpi(KeyStore keyStore) {
            this.keyStore = keyStore;
        }

        @Override
        public KeyStore.Entry engineGetEntry(String alias, KeyStore.ProtectionParameter protParam) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Key engineGetKey(String s, char[] chars)
                throws NoSuchAlgorithmException, UnrecoverableKeyException {
            try {
                return keyStore.getKey(s, chars);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public Certificate[] engineGetCertificateChain(String s) {
            try {
                return keyStore.getCertificateChain(s);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public Certificate engineGetCertificate(String s) {
            try {
                return keyStore.getCertificate(s);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public Date engineGetCreationDate(String s) {
            try {
                return keyStore.getCreationDate(s);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public void engineSetKeyEntry(String s, Key key, char[] chars, Certificate[] certificates)
                throws KeyStoreException {
            try {
                keyStore.setKeyEntry(s, key, chars, certificates);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public void engineSetKeyEntry(String s, byte[] bytes, Certificate[] certificates)
                throws KeyStoreException {
            try {
                keyStore.setKeyEntry(s, bytes, certificates);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public void engineSetCertificateEntry(String s, Certificate certificate)
                throws KeyStoreException {
            try {
                keyStore.setCertificateEntry(s, certificate);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public void engineDeleteEntry(String s) throws KeyStoreException {
            try {
                keyStore.deleteEntry(s);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public Enumeration<String> engineAliases() {
            try {
                return keyStore.aliases();
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public boolean engineContainsAlias(String s) {
            try {
                return keyStore.containsAlias(s);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public int engineSize() {
            try {
                return keyStore.size();
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public boolean engineIsKeyEntry(String s) {
            try {
                return keyStore.isKeyEntry(s);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public boolean engineIsCertificateEntry(String s) {
            try {
                return keyStore.isCertificateEntry(s);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public String engineGetCertificateAlias(Certificate certificate) {
            try {
                return keyStore.getCertificateAlias(certificate);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public void engineStore(OutputStream outputStream, char[] chars)
                throws IOException, NoSuchAlgorithmException, CertificateException {
            try {
                keyStore.store(outputStream, chars);
            } catch (KeyStoreException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public void engineLoad(InputStream inputStream, char[] chars)
                throws IOException, NoSuchAlgorithmException, CertificateException {
            // Do nothing, the keystore is already loaded
        }
    }
}
