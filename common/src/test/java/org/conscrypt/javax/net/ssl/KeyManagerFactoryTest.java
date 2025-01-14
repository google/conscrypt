/*
 * Copyright (C) 2010 The Android Open Source Project
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

package org.conscrypt.javax.net.ssl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import org.conscrypt.KeyManagerFactoryImpl;
import org.conscrypt.TestUtils;
import org.conscrypt.PakeKeyManagerFactory;
import org.conscrypt.java.security.StandardNames;
import org.conscrypt.java.security.TestKeyStore;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class KeyManagerFactoryTest {
    private TestKeyStore testKeyStore;

    @Before
    public void setUp() throws Exception {
        // note the rare usage of DSA keys here in addition to RSA
        String[] keyAlgorithms = StandardNames.IS_RI
                ? new String[] { "RSA", "DSA", "EC", "EC_RSA" }
                : new String[] { "RSA", "DH_RSA", "DSA", "DH_DSA", "EC", "EC_RSA" };
        testKeyStore = new TestKeyStore.Builder()
                               .keyAlgorithms(keyAlgorithms)
                               .aliasPrefix("rsa-dsa-ec-dh")
                               .build();
    }

    private TestKeyStore getTestKeyStore() throws Exception {
        return testKeyStore;
    }

    @Test
    public void test_KeyManagerFactory_getDefaultAlgorithm() throws Exception {
        String algorithm = KeyManagerFactory.getDefaultAlgorithm();
        assertEquals(StandardNames.KEY_MANAGER_FACTORY_DEFAULT, algorithm);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
        test_KeyManagerFactory(kmf);
    }

    private static class UselessManagerFactoryParameters implements ManagerFactoryParameters {}

    private static boolean supportsManagerFactoryParameters(String algorithm) {
        // Only the "New" one supports ManagerFactoryParameters
        return algorithm.equals("NewSunX509");
    }

    private static String[] keyTypes(String algorithm) {
        // Although the "New" one supports ManagerFactoryParameters,
        // it can't handle nulls in the key types array.
        return (algorithm.equals("NewSunX509") ? KEY_TYPES_WITH_EMPTY
                                               : KEY_TYPES_WITH_EMPTY_AND_NULL);
    }

    private void test_KeyManagerFactory(KeyManagerFactory kmf) throws Exception {
        assertNotNull(kmf);
        assertNotNull(kmf.getAlgorithm());
        assertNotNull(kmf.getProvider());

        if (kmf.getAlgorithm() == "PAKE") {
            return;
        }

        // before init
        try {
            kmf.getKeyManagers();
            fail();
        } catch (IllegalStateException expected) {
            // Ignore
        }

        // init with null ManagerFactoryParameters
        try {
            kmf.init(null);
            fail();
        } catch (InvalidAlgorithmParameterException expected) {
            // Ignore
        }

        // init with useless ManagerFactoryParameters
        try {
            kmf.init(new UselessManagerFactoryParameters());
            fail();
        } catch (InvalidAlgorithmParameterException expected) {
            // Ignore
        }

        // init with KeyStoreBuilderParameters ManagerFactoryParameters
        PasswordProtection pp = new PasswordProtection(getTestKeyStore().storePassword);
        KeyStore.Builder builder = KeyStore.Builder.newInstance(getTestKeyStore().keyStore, pp);
        KeyStoreBuilderParameters ksbp = new KeyStoreBuilderParameters(builder);
        if (supportsManagerFactoryParameters(kmf.getAlgorithm())) {
            kmf.init(ksbp);
            test_KeyManagerFactory_getKeyManagers(kmf, false);
        } else {
            try {
                kmf.init(ksbp);
                fail();
            } catch (InvalidAlgorithmParameterException expected) {
                // Ignore
            }
        }

        // init with null for default behavior
        kmf.init(null, null);
        test_KeyManagerFactory_getKeyManagers(kmf, true);

        // init with specific key store and password
        kmf.init(getTestKeyStore().keyStore, getTestKeyStore().storePassword);
        test_KeyManagerFactory_getKeyManagers(kmf, false);
    }

    private void test_KeyManagerFactory_getKeyManagers(KeyManagerFactory kmf, boolean empty)
            throws Exception {
        KeyManager[] keyManagers = kmf.getKeyManagers();
        assertNotNull(keyManagers);
        assertTrue(keyManagers.length > 0);
        for (KeyManager keyManager : keyManagers) {
            assertNotNull(keyManager);
            if (keyManager instanceof X509KeyManager) {
                test_X509KeyManager((X509KeyManager) keyManager, empty, kmf.getAlgorithm());
            }
        }
    }

    private static final String[] KEY_TYPES_ONLY =
            StandardNames.KEY_TYPES.toArray(new String[StandardNames.KEY_TYPES.size()]);
    private static final String[] KEY_TYPES_WITH_EMPTY = new String[KEY_TYPES_ONLY.length + 1];
    private static final String[] KEY_TYPES_WITH_EMPTY_AND_NULL =
            new String[KEY_TYPES_ONLY.length + 2];
    static {
        System.arraycopy(KEY_TYPES_ONLY, 0, KEY_TYPES_WITH_EMPTY, 0, KEY_TYPES_ONLY.length);
        KEY_TYPES_WITH_EMPTY[KEY_TYPES_WITH_EMPTY.length - 1] = "";

        System.arraycopy(KEY_TYPES_WITH_EMPTY, 0, KEY_TYPES_WITH_EMPTY_AND_NULL, 0,
                KEY_TYPES_WITH_EMPTY.length);
        // extra null at end requires no initialization
    }

    private void test_X509KeyManager(X509KeyManager km, boolean empty, String algorithm)
            throws Exception {
        String[] keyTypes = keyTypes(algorithm);
        for (String keyType : keyTypes) {
            String[] aliases = km.getClientAliases(keyType, null);
            if (empty || keyType == null || keyType.isEmpty()) {
                assertNull(keyType, aliases);
                continue;
            }
            assertNotNull(keyType, aliases);
            for (String alias : aliases) {
                test_X509KeyManager_alias(km, alias, keyType, false, empty);
            }
        }
        for (String keyType : keyTypes) {
            String[] aliases = km.getServerAliases(keyType, null);
            if (empty || keyType == null || keyType.isEmpty()) {
                assertNull(keyType, aliases);
                continue;
            }
            assertNotNull(keyType, aliases);
            for (String alias : aliases) {
                test_X509KeyManager_alias(km, alias, keyType, false, empty);
            }
        }

        String[][] rotatedTypes = rotate(nonEmpty(keyTypes));
        for (String[] keyList : rotatedTypes) {
            String alias = km.chooseClientAlias(keyList, null, null);
            test_X509KeyManager_alias(km, alias, null, true, empty);
        }

        for (String keyType : keyTypes) {
            String[] array = new String[] {keyType};
            String alias = km.chooseClientAlias(array, null, null);
            test_X509KeyManager_alias(km, alias, keyType, false, empty);
        }
        for (String keyType : keyTypes) {
            String alias = km.chooseServerAlias(keyType, null, null);
            test_X509KeyManager_alias(km, alias, keyType, false, empty);
        }
        if (km instanceof X509ExtendedKeyManager) {
            test_X509ExtendedKeyManager((X509ExtendedKeyManager) km, empty, algorithm);
        }
    }

    private void test_X509ExtendedKeyManager(
            X509ExtendedKeyManager km, boolean empty, String algorithm) throws Exception {
        String[] keyTypes = keyTypes(algorithm);
        String[][] rotatedTypes = rotate(nonEmpty(keyTypes));
        for (String[] keyList : rotatedTypes) {
            String alias = km.chooseEngineClientAlias(keyList, null, null);
            test_X509KeyManager_alias(km, alias, null, true, empty);
        }

        for (String keyType : keyTypes) {
            String[] array = new String[] {keyType};
            String alias = km.chooseEngineClientAlias(array, null, null);
            test_X509KeyManager_alias(km, alias, keyType, false, empty);
        }
        for (String keyType : keyTypes) {
            String alias = km.chooseEngineServerAlias(keyType, null, null);
            test_X509KeyManager_alias(km, alias, keyType, false, empty);
        }
    }

    // Filters null or empty values from a String array and returns a new array with the results.
    private static String[] nonEmpty(String[] input) {
        String[] nonEmpty = new String[input.length];
        int size = 0;
        for (String keyType : input) {
            if (keyType != null && !keyType.isEmpty()) {
                nonEmpty[size++] = keyType;
            }
        }
        return Arrays.copyOfRange(nonEmpty, 0, size);
    }

    // Generates an array of arrays of all the rotational permutations of its input.
    private static String[][] rotate(String[] input) {
        int size = input.length;
        String[][] result = new String[size][size];
        for (int i = 0; i < size; i++) {
            for (int j = 0; j < size; j++) {
                result[i][j] = input[(i + j) % size];
            }
        }
        return result;
    }

    private void test_X509KeyManager_alias(X509KeyManager km, String alias, String keyType,
            boolean many, boolean empty) throws Exception {
        if (empty || (!many && (keyType == null || keyType.isEmpty()))) {
            assertNull(keyType, alias);
            assertNull(keyType, km.getCertificateChain(alias));
            assertNull(keyType, km.getPrivateKey(alias));
            return;
        }
        assertNotNull(alias);
        X509Certificate[] certificateChain = km.getCertificateChain(alias);
        PrivateKey privateKey = km.getPrivateKey(alias);

        String keyAlgName = privateKey.getAlgorithm();

        X509Certificate certificate = certificateChain[0];
        assertEquals(keyType, keyAlgName, certificate.getPublicKey().getAlgorithm());

        String sigAlgName = certificate.getSigAlgName();

        PrivateKeyEntry privateKeyEntry = getTestKeyStore().getPrivateKey(keyAlgName, sigAlgName);

        assertEquals(keyType, Arrays.asList(privateKeyEntry.getCertificateChain()),
                Arrays.<Certificate>asList(certificateChain));
        assertEquals(keyType, privateKeyEntry.getPrivateKey(), privateKey);

        if (keyType != null) {
            assertEquals(TestKeyStore.keyAlgorithm(keyType), keyAlgName);

            // Skip this when we're given only "DH" or "EC" instead of "DH_DSA",
            // "EC_RSA", etc. since we don't know what the expected
            // algorithm was.
            if (!keyType.equals("DH") && !keyType.equals("EC")) {
                assertTrue("SigAlg: " + sigAlgName + ", KeyType: " + keyType,
                    sigAlgName.contains(TestKeyStore.signatureAlgorithm(keyType)));
            }
        }
    }

    @Test
    public void test_KeyManagerFactory_getInstance() throws Exception {
        ServiceTester.test("KeyManagerFactory")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider provider, String algorithm) throws Exception {
                    KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
                    assertEquals(algorithm, kmf.getAlgorithm());
                    test_KeyManagerFactory(kmf);

                    kmf = KeyManagerFactory.getInstance(algorithm, provider);
                    assertEquals(algorithm, kmf.getAlgorithm());
                    assertEquals(provider, kmf.getProvider());
                    test_KeyManagerFactory(kmf);

                    kmf = KeyManagerFactory.getInstance(algorithm, provider.getName());
                    assertEquals(algorithm, kmf.getAlgorithm());
                    assertEquals(provider, kmf.getProvider());
                    test_KeyManagerFactory(kmf);
                }
            });
    }

    // The Conscrypt provider on OpenJDK doesn't provide the KeyManagerFactory, but we want
    // to test it on OpenJDK anyway
    @Test
    public void test_KeyManagerFactory_Conscrypt() throws Exception {
        KeyManagerFactory kmf = new KeyManagerFactory(new KeyManagerFactoryImpl(),
            TestUtils.getConscryptProvider(), KeyManagerFactory.getDefaultAlgorithm()) { };
        test_KeyManagerFactory(kmf);

        // Test that using a KeyStore that doesn't implement getEntry(), like Android Keystore
        // doesn't, still produces a functional KeyManager.
        kmf.init(new NoGetEntryKeyStore(getTestKeyStore().keyStore),
            getTestKeyStore().storePassword);
        test_KeyManagerFactory_getKeyManagers(kmf, false);
    }

    private static class NoGetEntryKeyStore extends KeyStore {
        public NoGetEntryKeyStore(KeyStore keyStore) throws Exception {
            super(new NoGetEntryKeyStoreSpi(keyStore), keyStore.getProvider(), keyStore.getType());
            load(null, null);
        }
    }

    // Android Keystore's KeyStore doesn't support getEntry(), so we replicate that here
    // for testing by throwing UnsupportedOperationException and passing everything else through
    // to a working implementation.
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
