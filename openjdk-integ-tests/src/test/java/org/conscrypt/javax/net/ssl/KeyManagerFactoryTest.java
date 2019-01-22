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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import org.conscrypt.java.security.StandardNames;
import org.conscrypt.java.security.TestKeyStore;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

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
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                String type = service.getType();
                if (!type.equals("KeyManagerFactory")) {
                    continue;
                }
                String algorithm = service.getAlgorithm();
                try {
                    {
                        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
                        assertEquals(algorithm, kmf.getAlgorithm());
                        test_KeyManagerFactory(kmf);
                    }

                    {
                        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm, provider);
                        assertEquals(algorithm, kmf.getAlgorithm());
                        assertEquals(provider, kmf.getProvider());
                        test_KeyManagerFactory(kmf);
                    }

                    {
                        KeyManagerFactory kmf =
                                KeyManagerFactory.getInstance(algorithm, provider.getName());
                        assertEquals(algorithm, kmf.getAlgorithm());
                        assertEquals(provider, kmf.getProvider());
                        test_KeyManagerFactory(kmf);
                    }
                } catch (Exception e) {
                    throw new Exception("Problem with algorithm " + algorithm, e);
                }
            }
        }
    }
}
