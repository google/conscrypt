/*
 * Copyright (C) 2011 The Android Open Source Project
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import libcore.java.security.TestKeyStore;

public class TrustedCertificateStoreTest extends TestCase {
    private static final Random tempFileRandom = new Random();

    private final File dirTest = new File(System.getProperty("java.io.tmpdir", "."),
            "cert-store-test" + tempFileRandom.nextInt());
    private final File dirSystem = new File(dirTest, "system");
    private final File dirAdded = new File(dirTest, "added");
    private final File dirDeleted = new File(dirTest, "removed");

    private static X509Certificate CA1;
    private static X509Certificate CA2;

    private static KeyStore.PrivateKeyEntry PRIVATE;
    private static X509Certificate[] CHAIN;

    private static X509Certificate CA3_WITH_CA1_SUBJECT;
    private static String ALIAS_SYSTEM_CA1;
    private static String ALIAS_SYSTEM_CA2;
    private static String ALIAS_USER_CA1;
    private static String ALIAS_USER_CA2;

    private static String ALIAS_SYSTEM_CHAIN0;
    private static String ALIAS_SYSTEM_CHAIN1;
    private static String ALIAS_SYSTEM_CHAIN2;
    private static String ALIAS_USER_CHAIN0;
    private static String ALIAS_USER_CHAIN1;
    private static String ALIAS_USER_CHAIN2;

    private static String ALIAS_SYSTEM_CA3;
    private static String ALIAS_SYSTEM_CA3_COLLISION;
    private static String ALIAS_USER_CA3;
    private static String ALIAS_USER_CA3_COLLISION;

    private static X509Certificate CERTLOOP_EE;
    private static X509Certificate CERTLOOP_CA1;
    private static X509Certificate CERTLOOP_CA2;
    private static String ALIAS_USER_CERTLOOP_EE;
    private static String ALIAS_USER_CERTLOOP_CA1;
    private static String ALIAS_USER_CERTLOOP_CA2;

    private static X509Certificate getCa1() {
        initCerts();
        return CA1;
    }
    private static X509Certificate getCa2() {
        initCerts();
        return CA2;
    }

    private static KeyStore.PrivateKeyEntry getPrivate() {
        initCerts();
        return PRIVATE;
    }
    private static X509Certificate[] getChain() {
        initCerts();
        return CHAIN;
    }

    private static X509Certificate getCa3WithCa1Subject() {
        initCerts();
        return CA3_WITH_CA1_SUBJECT;
    }

    private static String getAliasSystemCa1() {
        initCerts();
        return ALIAS_SYSTEM_CA1;
    }
    private static String getAliasSystemCa2() {
        initCerts();
        return ALIAS_SYSTEM_CA2;
    }
    private static String getAliasUserCa1() {
        initCerts();
        return ALIAS_USER_CA1;
    }
    private static String getAliasUserCa2() {
        initCerts();
        return ALIAS_USER_CA2;
    }

    private static String getAliasSystemChain0() {
        initCerts();
        return ALIAS_SYSTEM_CHAIN0;
    }
    private static String getAliasSystemChain1() {
        initCerts();
        return ALIAS_SYSTEM_CHAIN1;
    }
    private static String getAliasSystemChain2() {
        initCerts();
        return ALIAS_SYSTEM_CHAIN2;
    }
    private static String getAliasUserChain0() {
        initCerts();
        return ALIAS_USER_CHAIN0;
    }
    private static String getAliasUserChain1() {
        initCerts();
        return ALIAS_USER_CHAIN1;
    }
    private static String getAliasUserChain2() {
        initCerts();
        return ALIAS_USER_CHAIN2;
    }

    private static String getAliasSystemCa3() {
        initCerts();
        return ALIAS_SYSTEM_CA3;
    }
    private static String getAliasSystemCa3Collision() {
        initCerts();
        return ALIAS_SYSTEM_CA3_COLLISION;
    }
    private static String getAliasUserCa3() {
        initCerts();
        return ALIAS_USER_CA3;
    }
    private static String getAliasUserCa3Collision() {
        initCerts();
        return ALIAS_USER_CA3_COLLISION;
    }
    private static X509Certificate getCertLoopEe() {
        initCerts();
        return CERTLOOP_EE;
    }
    private static X509Certificate getCertLoopCa1() {
        initCerts();
        return CERTLOOP_CA1;
    }
    private static X509Certificate getCertLoopCa2() {
        initCerts();
        return CERTLOOP_CA2;
    }
    private static String getAliasCertLoopEe() {
        initCerts();
        return ALIAS_USER_CERTLOOP_EE;
    }
    private static String getAliasCertLoopCa1() {
        initCerts();
        return ALIAS_USER_CERTLOOP_CA1;
    }
    private static String getAliasCertLoopCa2() {
        initCerts();
        return ALIAS_USER_CERTLOOP_CA2;
    }

    /**
     * Lazily create shared test certificates.
     */
    private static synchronized void initCerts() {
        if (CA1 != null) {
            return;
        }
        try {
            CA1 = TestKeyStore.getClient().getRootCertificate("RSA");
            CA2 = TestKeyStore.getClientCA2().getRootCertificate("RSA");
            PRIVATE = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
            CHAIN = (X509Certificate[]) PRIVATE.getCertificateChain();
            CA3_WITH_CA1_SUBJECT = new TestKeyStore.Builder()
                    .aliasPrefix("unused")
                    .subject(CA1.getSubjectX500Principal())
                    .ca(true)
                    .build().getRootCertificate("RSA");


            ALIAS_SYSTEM_CA1 = alias(false, CA1, 0);
            ALIAS_SYSTEM_CA2 = alias(false, CA2, 0);
            ALIAS_USER_CA1 = alias(true, CA1, 0);
            ALIAS_USER_CA2 = alias(true, CA2, 0);

            ALIAS_SYSTEM_CHAIN0 = alias(false, getChain()[0], 0);
            ALIAS_SYSTEM_CHAIN1 = alias(false, getChain()[1], 0);
            ALIAS_SYSTEM_CHAIN2 = alias(false, getChain()[2], 0);
            ALIAS_USER_CHAIN0 = alias(true, getChain()[0], 0);
            ALIAS_USER_CHAIN1 = alias(true, getChain()[1], 0);
            ALIAS_USER_CHAIN2 = alias(true, getChain()[2], 0);

            ALIAS_SYSTEM_CA3 = alias(false, CA3_WITH_CA1_SUBJECT, 0);
            ALIAS_SYSTEM_CA3_COLLISION = alias(false, CA3_WITH_CA1_SUBJECT, 1);
            ALIAS_USER_CA3 = alias(true, CA3_WITH_CA1_SUBJECT, 0);
            ALIAS_USER_CA3_COLLISION = alias(true, CA3_WITH_CA1_SUBJECT, 1);

            /*
             * The construction below is to build a certificate chain that has a loop
             * in it:
             *
             *   EE ---> CA1 ---> CA2 ---+
             *            ^              |
             *            |              |
             *            +--------------+
             */
            TestKeyStore certLoopTempCa1 = new TestKeyStore.Builder()
                    .keyAlgorithms("RSA")
                    .aliasPrefix("certloop-ca1")
                    .subject("CN=certloop-ca1")
                    .ca(true)
                    .build();
            Certificate certLoopTempCaCert1 = ((TrustedCertificateEntry) certLoopTempCa1
                    .getEntryByAlias("certloop-ca1-public-RSA")).getTrustedCertificate();
            PrivateKeyEntry certLoopCaKey1 = (PrivateKeyEntry) certLoopTempCa1
                    .getEntryByAlias("certloop-ca1-private-RSA");

            TestKeyStore certLoopCa2 = new TestKeyStore.Builder()
                    .keyAlgorithms("RSA")
                    .aliasPrefix("certloop-ca2")
                    .subject("CN=certloop-ca2")
                    .rootCa(certLoopTempCaCert1)
                    .signer(certLoopCaKey1)
                    .ca(true)
                    .build();
            CERTLOOP_CA2 = (X509Certificate) ((TrustedCertificateEntry) certLoopCa2
                    .getEntryByAlias("certloop-ca2-public-RSA")).getTrustedCertificate();
            ALIAS_USER_CERTLOOP_CA2 = alias(true, CERTLOOP_CA2, 0);
            PrivateKeyEntry certLoopCaKey2 = (PrivateKeyEntry) certLoopCa2
                    .getEntryByAlias("certloop-ca2-private-RSA");

            TestKeyStore certLoopCa1 = new TestKeyStore.Builder()
                    .keyAlgorithms("RSA")
                    .aliasPrefix("certloop-ca1")
                    .subject("CN=certloop-ca1")
                    .privateEntry(certLoopCaKey1)
                    .rootCa(CERTLOOP_CA2)
                    .signer(certLoopCaKey2)
                    .ca(true)
                    .build();
            CERTLOOP_CA1 = (X509Certificate) ((TrustedCertificateEntry) certLoopCa1
                    .getEntryByAlias("certloop-ca1-public-RSA")).getTrustedCertificate();
            ALIAS_USER_CERTLOOP_CA1 = alias(true, CERTLOOP_CA1, 0);

            TestKeyStore certLoopEe = new TestKeyStore.Builder()
                    .keyAlgorithms("RSA")
                    .aliasPrefix("certloop-ee")
                    .subject("CN=certloop-ee")
                    .rootCa(CERTLOOP_CA1)
                    .signer(certLoopCaKey1)
                    .build();
            CERTLOOP_EE = (X509Certificate) ((TrustedCertificateEntry) certLoopEe
                    .getEntryByAlias("certloop-ee-public-RSA")).getTrustedCertificate();
            ALIAS_USER_CERTLOOP_EE = alias(true, CERTLOOP_EE, 0);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private TrustedCertificateStore store;

    @Override protected void setUp() {
        setupStore();
    }

    private void setupStore() {
        dirSystem.mkdirs();
        cleanStore();
        createStore();
    }

    private void createStore() {
        store = new TrustedCertificateStore(dirSystem, dirAdded, dirDeleted);
    }

    @Override protected void tearDown() {
        cleanStore();
    }

    private void cleanStore() {
        for (File dir : new File[] { dirSystem, dirAdded, dirDeleted, dirTest }) {
            File[] files = dir.listFiles();
            if (files == null) {
                continue;
            }
            for (File file : files) {
                assertTrue("Should delete " + file.getPath(), file.delete());
            }
        }
        store = null;
    }

    private void resetStore() {
        cleanStore();
        setupStore();
    }

    public void testEmptyDirectories() throws Exception {
        assertEmpty();
    }

    public void testOneSystemOneDeleted() throws Exception {
        install(getCa1(), getAliasSystemCa1());
        store.deleteCertificateEntry(getAliasSystemCa1());
        assertEmpty();
        assertDeleted(getCa1(), getAliasSystemCa1());
    }

    public void testTwoSystemTwoDeleted() throws Exception {
        install(getCa1(), getAliasSystemCa1());
        store.deleteCertificateEntry(getAliasSystemCa1());
        install(getCa2(), getAliasSystemCa2());
        store.deleteCertificateEntry(getAliasSystemCa2());
        assertEmpty();
        assertDeleted(getCa1(), getAliasSystemCa1());
        assertDeleted(getCa2(), getAliasSystemCa2());
    }

    public void testPartialFileIsIgnored() throws Exception {
        File file = file(getAliasSystemCa1());
        file.getParentFile().mkdirs();
        OutputStream os = new FileOutputStream(file);
        os.write(0);
        os.close();
        assertTrue(file.exists());
        assertEmpty();
        assertTrue(file.exists());
    }

    private void assertEmpty() throws Exception {
        try {
            store.getCertificate(null);
            fail();
        } catch (NullPointerException expected) {
        }
        assertNull(store.getCertificate(""));

        try {
            store.getCreationDate(null);
            fail();
        } catch (NullPointerException expected) {
        }
        assertNull(store.getCreationDate(""));

        Set<String> s = store.aliases();
        assertNotNull(s);
        assertTrue(s.isEmpty());
        assertAliases();

        Set<String> u = store.userAliases();
        assertNotNull(u);
        assertTrue(u.isEmpty());

        try {
            store.containsAlias(null);
            fail();
        } catch (NullPointerException expected) {
        }
        assertFalse(store.containsAlias(""));

        assertNull(store.getCertificateAlias(null));
        assertNull(store.getCertificateAlias(getCa1()));

        try {
            store.getTrustAnchor(null);
            fail();
        } catch (NullPointerException expected) {
        }
        assertNull(store.getTrustAnchor(getCa1()));

        try {
            store.findIssuer(null);
            fail();
        } catch (NullPointerException expected) {
        }
        assertNull(store.findIssuer(getCa1()));

        try {
            store.installCertificate(null);
            fail();
        } catch (NullPointerException expected) {
        }

        store.deleteCertificateEntry(null);
        store.deleteCertificateEntry("");

        String[] userFiles = dirAdded.list();
        assertTrue(userFiles == null || userFiles.length == 0);
    }

    public void testTwoSystem() throws Exception {
        testTwo(getCa1(), getAliasSystemCa1(),
                getCa2(), getAliasSystemCa2());
    }

    public void testTwoUser() throws Exception {
        testTwo(getCa1(), getAliasUserCa1(),
                getCa2(), getAliasUserCa2());
    }

    public void testOneSystemOneUser() throws Exception {
        testTwo(getCa1(), getAliasSystemCa1(),
                getCa2(), getAliasUserCa2());
    }

    public void testTwoSystemSameSubject() throws Exception {
        testTwo(getCa1(), getAliasSystemCa1(),
                getCa3WithCa1Subject(), getAliasSystemCa3Collision());
    }

    public void testTwoUserSameSubject() throws Exception {
        testTwo(getCa1(), getAliasUserCa1(),
                getCa3WithCa1Subject(), getAliasUserCa3Collision());

        store.deleteCertificateEntry(getAliasUserCa1());
        assertDeleted(getCa1(), getAliasUserCa1());
        assertTombstone(getAliasUserCa1());
        assertRootCa(getCa3WithCa1Subject(), getAliasUserCa3Collision());
        assertAliases(getAliasUserCa3Collision());

        store.deleteCertificateEntry(getAliasUserCa3Collision());
        assertDeleted(getCa3WithCa1Subject(), getAliasUserCa3Collision());
        assertNoTombstone(getAliasUserCa3Collision());
        assertNoTombstone(getAliasUserCa1());
        assertEmpty();
    }

    public void testOneSystemOneUserSameSubject() throws Exception {
        testTwo(getCa1(), getAliasSystemCa1(),
                getCa3WithCa1Subject(), getAliasUserCa3());
        testTwo(getCa1(), getAliasUserCa1(),
                getCa3WithCa1Subject(), getAliasSystemCa3());
    }

    private void testTwo(X509Certificate x1, String alias1,
                         X509Certificate x2, String alias2) {
        install(x1, alias1);
        install(x2, alias2);
        assertRootCa(x1, alias1);
        assertRootCa(x2, alias2);
        assertAliases(alias1, alias2);
    }


    public void testOneSystemOneUserOneDeleted() throws Exception {
        install(getCa1(), getAliasSystemCa1());
        store.installCertificate(getCa2());
        store.deleteCertificateEntry(getAliasSystemCa1());
        assertDeleted(getCa1(), getAliasSystemCa1());
        assertRootCa(getCa2(), getAliasUserCa2());
        assertAliases(getAliasUserCa2());
    }

    public void testOneSystemOneUserOneDeletedSameSubject() throws Exception {
        install(getCa1(), getAliasSystemCa1());
        store.installCertificate(getCa3WithCa1Subject());
        store.deleteCertificateEntry(getAliasSystemCa1());
        assertDeleted(getCa1(), getAliasSystemCa1());
        assertRootCa(getCa3WithCa1Subject(), getAliasUserCa3());
        assertAliases(getAliasUserCa3());
    }

    public void testUserMaskingSystem() throws Exception {
        install(getCa1(), getAliasSystemCa1());
        install(getCa1(), getAliasUserCa1());
        assertMasked(getCa1(), getAliasSystemCa1());
        assertRootCa(getCa1(), getAliasUserCa1());
        assertAliases(getAliasSystemCa1(), getAliasUserCa1());
    }

    public void testChain() throws Exception {
        testChain(getAliasSystemChain1(), getAliasSystemChain2());
        testChain(getAliasSystemChain1(), getAliasUserChain2());
        testChain(getAliasUserChain1(), getAliasSystemCa1());
        testChain(getAliasUserChain1(), getAliasUserChain2());
    }

    private void testChain(String alias1, String alias2) throws Exception {
        install(getChain()[1], alias1);
        install(getChain()[2], alias2);
        assertIntermediateCa(getChain()[1], alias1);
        assertRootCa(getChain()[2], alias2);
        assertAliases(alias1, alias2);
        assertEquals(getChain()[2], store.findIssuer(getChain()[1]));
        assertEquals(getChain()[1], store.findIssuer(getChain()[0]));

        X509Certificate[] expected = getChain();
        List<X509Certificate> actualList = store.getCertificateChain(expected[0]);

        assertEquals("Generated CA list should be same length", expected.length, actualList.size());
        for (int i = 0; i < expected.length; i++) {
            assertEquals("Chain value should be the same for position " + i, expected[i],
                    actualList.get(i));
        }
        resetStore();
    }

    public void testMissingSystemDirectory() throws Exception {
        cleanStore();
        createStore();
        assertEmpty();
    }

    public void testWithExistingUserDirectories() throws Exception {
        dirAdded.mkdirs();
        dirDeleted.mkdirs();
        install(getCa1(), getAliasSystemCa1());
        assertRootCa(getCa1(), getAliasSystemCa1());
        assertAliases(getAliasSystemCa1());
    }

    public void testIsTrustAnchorWithReissuedgetCa() throws Exception {
        PublicKey publicKey = getPrivate().getCertificate().getPublicKey();
        PrivateKey privateKey = getPrivate().getPrivateKey();
        String name = "CN=CA4";
        X509Certificate ca1 = TestKeyStore.createCa(publicKey, privateKey, name);
        Thread.sleep(1 * 1000); // wait to ensure CAs vary by expiration
        X509Certificate ca2 = TestKeyStore.createCa(publicKey, privateKey, name);
        assertFalse(ca1.equals(ca2));

        String systemAlias = alias(false, ca1, 0);
        install(ca1, systemAlias);
        assertRootCa(ca1, systemAlias);
        assertEquals(ca1, store.getTrustAnchor(ca2));
        assertEquals(ca1, store.findIssuer(ca2));
        resetStore();

        String userAlias = alias(true, ca1, 0);
        store.installCertificate(ca1);
        assertRootCa(ca1, userAlias);
        assertNotNull(store.getTrustAnchor(ca2));
        assertEquals(ca1, store.findIssuer(ca2));
        resetStore();
    }

    public void testInstallEmpty() throws Exception {
        store.installCertificate(getCa1());
        assertRootCa(getCa1(), getAliasUserCa1());
        assertAliases(getAliasUserCa1());

        // reinstalling should not change anything
        store.installCertificate(getCa1());
        assertRootCa(getCa1(), getAliasUserCa1());
        assertAliases(getAliasUserCa1());
    }

    public void testInstallEmptySystemExists() throws Exception {
        install(getCa1(), getAliasSystemCa1());
        assertRootCa(getCa1(), getAliasSystemCa1());
        assertAliases(getAliasSystemCa1());

        // reinstalling should not affect system CA
        store.installCertificate(getCa1());
        assertRootCa(getCa1(), getAliasSystemCa1());
        assertAliases(getAliasSystemCa1());

    }

    public void testInstallEmptyDeletedSystemExists() throws Exception {
        install(getCa1(), getAliasSystemCa1());
        store.deleteCertificateEntry(getAliasSystemCa1());
        assertEmpty();
        assertDeleted(getCa1(), getAliasSystemCa1());

        // installing should restore deleted system CA
        store.installCertificate(getCa1());
        assertRootCa(getCa1(), getAliasSystemCa1());
        assertAliases(getAliasSystemCa1());
    }

    public void testDeleteEmpty() throws Exception {
        store.deleteCertificateEntry(getAliasSystemCa1());
        assertEmpty();
        assertDeleted(getCa1(), getAliasSystemCa1());
    }

    public void testDeleteUser() throws Exception {
        store.installCertificate(getCa1());
        assertRootCa(getCa1(), getAliasUserCa1());
        assertAliases(getAliasUserCa1());

        store.deleteCertificateEntry(getAliasUserCa1());
        assertEmpty();
        assertDeleted(getCa1(), getAliasUserCa1());
        assertNoTombstone(getAliasUserCa1());
    }

    public void testDeleteSystem() throws Exception {
        install(getCa1(), getAliasSystemCa1());
        assertRootCa(getCa1(), getAliasSystemCa1());
        assertAliases(getAliasSystemCa1());

        store.deleteCertificateEntry(getAliasSystemCa1());
        assertEmpty();
        assertDeleted(getCa1(), getAliasSystemCa1());

        // deleting again should not change anything
        store.deleteCertificateEntry(getAliasSystemCa1());
        assertEmpty();
        assertDeleted(getCa1(), getAliasSystemCa1());
    }

    public void testGetLoopedCert() throws Exception {
        install(getCertLoopEe(), getAliasCertLoopEe());
        install(getCertLoopCa1(), getAliasCertLoopCa1());
        install(getCertLoopCa2(), getAliasCertLoopCa2());

        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<List<X509Certificate>> future = executor
                .submit(new Callable<List<X509Certificate>>() {
                    @Override
                    public List<X509Certificate> call() throws Exception {
                        return store.getCertificateChain(getCertLoopEe());
                    }
                });
        executor.shutdown();
        final List<X509Certificate> certs;
        try {
            certs = future.get(10, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            fail("Could not finish building chain; possibly confused by loops");
            return; // Not actually reached.
        }
        assertEquals(3, certs.size());
        assertEquals(getCertLoopEe(), certs.get(0));
        assertEquals(getCertLoopCa1(), certs.get(1));
        assertEquals(getCertLoopCa2(), certs.get(2));
    }

    public void testIsUserAddedCertificate() throws Exception {
        assertFalse(store.isUserAddedCertificate(getCa1()));
        assertFalse(store.isUserAddedCertificate(getCa2()));
        install(getCa1(), getAliasSystemCa1());
        assertFalse(store.isUserAddedCertificate(getCa1()));
        assertFalse(store.isUserAddedCertificate(getCa2()));
        install(getCa1(), getAliasUserCa1());
        assertTrue(store.isUserAddedCertificate(getCa1()));
        assertFalse(store.isUserAddedCertificate(getCa2()));
        install(getCa2(), getAliasUserCa2());
        assertTrue(store.isUserAddedCertificate(getCa1()));
        assertTrue(store.isUserAddedCertificate(getCa2()));
        store.deleteCertificateEntry(getAliasUserCa1());
        assertFalse(store.isUserAddedCertificate(getCa1()));
        assertTrue(store.isUserAddedCertificate(getCa2()));
        store.deleteCertificateEntry(getAliasUserCa2());
        assertFalse(store.isUserAddedCertificate(getCa1()));
        assertFalse(store.isUserAddedCertificate(getCa2()));
    }

    public void testSystemCaCertsUseCorrectFileNames() throws Exception {
        TrustedCertificateStore store = new TrustedCertificateStore();

        // Assert that all the certificates in the system cacerts directory are stored in files with
        // expected names.
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        File dir = new File(System.getenv("ANDROID_ROOT") + "/etc/security/cacerts");
        int systemCertFileCount = 0;
        for (File actualFile : listFilesNoNull(dir)) {
            if (!actualFile.isFile()) {
                continue;
            }
            systemCertFileCount++;
            X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(
                    new ByteArrayInputStream(readFully(actualFile)));

            File expectedFile = store.getCertificateFile(dir, cert);
            assertEquals("System certificate stored in the wrong file",
                    expectedFile.getAbsolutePath(), actualFile.getAbsolutePath());

            // The two statements below indirectly assert that the certificate can be looked up
            // from a file (hopefully the same one as the expectedFile above). As opposed to
            // getCertifiacteFile above, these are the actual methods used when verifying chain of
            // trust. Thus, we assert that they work as expected for all system certificates.
            assertNotNull("Issuer certificate not found for system certificate " + actualFile,
                    store.findIssuer(cert));
            assertNotNull("Trust anchor not found for system certificate " + actualFile,
                    store.getTrustAnchor(cert));
        }

        // Assert that all files corresponding to all system certs/aliases known to the store are
        // present.
        int systemCertAliasCount = 0;
        for (String alias : store.aliases()) {
            if (!TrustedCertificateStore.isSystem(alias)) {
                continue;
            }
            systemCertAliasCount++;
            // Checking that the certificate is stored in a file is extraneous given the current
            // implementation of the class under test. We do it just in case the implementation
            // changes.
            X509Certificate cert = (X509Certificate) store.getCertificate(alias);
            File expectedFile = store.getCertificateFile(dir, cert);
            if (!expectedFile.isFile()) {
                fail("Missing certificate file for alias " + alias
                        + ": " + expectedFile.getAbsolutePath());
            }
        }

        assertEquals("Number of system cert files and aliases doesn't match",
                systemCertFileCount, systemCertAliasCount);
    }

    private static File[] listFilesNoNull(File dir) {
        File[] files = dir.listFiles();
        return (files != null) ? files : new File[0];
    }

    private static byte[] readFully(File file) throws IOException {
        InputStream in = null;
        try {
            in = new FileInputStream(file);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[16384];
            int chunkSize;
            while ((chunkSize = in.read(buf)) != -1) {
                out.write(buf, 0, chunkSize);
            }
            return out.toByteArray();
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    private void assertRootCa(X509Certificate x, String alias) {
        assertIntermediateCa(x, alias);
        assertEquals(x, store.findIssuer(x));
    }

    private void assertTrusted(X509Certificate x, String alias) {
        assertEquals(x, store.getCertificate(alias));
        assertEquals(file(alias).lastModified(), store.getCreationDate(alias).getTime());
        assertTrue(store.containsAlias(alias));
        assertEquals(x, store.getTrustAnchor(x));
    }

    private void assertIntermediateCa(X509Certificate x, String alias) {
        assertTrusted(x, alias);
        assertEquals(alias, store.getCertificateAlias(x));
    }

    private void assertMasked(X509Certificate x, String alias) {
        assertTrusted(x, alias);
        assertFalse(alias.equals(store.getCertificateAlias(x)));
    }

    private void assertDeleted(X509Certificate x, String alias) {
        assertNull(store.getCertificate(alias));
        assertFalse(store.containsAlias(alias));
        assertNull(store.getCertificateAlias(x));
        assertNull(store.getTrustAnchor(x));
        assertEquals(store.allSystemAliases().contains(alias),
                     store.getCertificate(alias, true) != null);
    }

    private void assertTombstone(String alias) {
        assertTrue(TrustedCertificateStore.isUser(alias));
        File file = file(alias);
        assertTrue(file.exists());
        assertEquals(0, file.length());
    }

    private void assertNoTombstone(String alias) {
        assertTrue(TrustedCertificateStore.isUser(alias));
        assertFalse(file(alias).exists());
    }

    private void assertAliases(String... aliases) {
        Set<String> expected = new HashSet<String>(Arrays.asList(aliases));
        Set<String> actual = new HashSet<String>();
        for (String alias : store.aliases()) {
            boolean system = TrustedCertificateStore.isSystem(alias);
            boolean user = TrustedCertificateStore.isUser(alias);
            if (system || user) {
                assertEquals(system, store.allSystemAliases().contains(alias));
                assertEquals(user, store.userAliases().contains(alias));
                actual.add(alias);
            } else {
                throw new AssertionError(alias);
            }
        }
        assertEquals(expected, actual);
    }

    /**
     * format a certificate alias
     */
    private static String alias(boolean user, X509Certificate x, int index) {
        String prefix = user ? "user:" : "system:";

        X500Principal subject = x.getSubjectX500Principal();
        int intHash = NativeCrypto.X509_NAME_hash_old(subject);
        String strHash = IntegralToString.intToHexString(intHash, false, 8);

        return prefix + strHash + '.' + index;
    }

    /**
     * Install certificate under specified alias
     */
    private void install(X509Certificate x, String alias) {
        try {
            File file = file(alias);
            file.getParentFile().mkdirs();
            OutputStream out = new FileOutputStream(file);
            out.write(x.getEncoded());
            out.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Compute file for an alias
     */
    private File file(String alias) {
        File dir;
        if (TrustedCertificateStore.isSystem(alias)) {
            dir = dirSystem;
        } else if (TrustedCertificateStore.isUser(alias)) {
            dir = dirAdded;
        } else {
            throw new IllegalArgumentException(alias);
        }

        int index = alias.lastIndexOf(":");
        if (index == -1) {
            throw new IllegalArgumentException(alias);
        }
        String filename = alias.substring(index+1);

        return new File(dir, filename);
    }
}
