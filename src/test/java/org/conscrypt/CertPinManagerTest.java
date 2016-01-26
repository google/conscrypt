/*
 * Copyright (C) 2012 The Android Open Source Project
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

import java.io.File;
import java.io.FileWriter;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import junit.framework.TestCase;
import libcore.java.security.TestKeyStore;

public class CertPinManagerTest extends TestCase {

    private X509Certificate[] chain;
    private List<X509Certificate> shortChain;
    private List<X509Certificate> longChain;
    private String shortPin;
    private String longPin;
    private List<File> tmpFiles = new ArrayList<File>();

    private String writeTmpPinFile(String text) throws Exception {
        File tmp = File.createTempFile("pins", null);
        FileWriter fstream = new FileWriter(tmp);
        fstream.write(text);
        fstream.close();
        tmpFiles.add(tmp);
        return tmp.getPath();
    }

    private static String getFingerprint(X509Certificate cert) throws NoSuchAlgorithmException {
        MessageDigest dgst = MessageDigest.getInstance("SHA512");
        byte[] encoded = cert.getPublicKey().getEncoded();
        byte[] fingerprint = dgst.digest(encoded);
        return IntegralToString.bytesToHexString(fingerprint, false);
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();
        // build some valid chains
        KeyStore.PrivateKeyEntry pke = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
        chain = (X509Certificate[]) pke.getCertificateChain();
        X509Certificate root = chain[2];
        X509Certificate server = chain[0];

        // build the short and long chains
        shortChain = new ArrayList<X509Certificate>();
        shortChain.add(root);
        longChain = new ArrayList<X509Certificate>();
        longChain.add(server);

        // we'll use the root as the pin for the short entry and the server as the pin for the long
        shortPin = getFingerprint(root);
        longPin = getFingerprint(server);
    }

    @Override
    public void tearDown() throws Exception {
        try {
            for (File f : tmpFiles) {
                f.delete();
            }
            tmpFiles.clear();
        } finally {
            super.tearDown();
        }
    }

    public void testPinFileMaximumLookup() throws Exception {

        // Hostnames to match
        String longHostname = "android.clients.google.com";
        String shortHostname = "android.google.com";

        // Write a pinfile with two entries, one longer than the other.
        // NOTE: "shortChain", "longChain", "shortPin", and "longPin"
        // does not have any bearing on the test. It's simply used to
        // distinguish the following pin entries.
        String shortHostnameEntry = "*.google.com=true|" + shortPin;
        String longHostnameEntry = "*.clients.google.com=true|" + longPin;

        // create the pinFile
        String path = writeTmpPinFile(shortHostnameEntry + "\n" + longHostnameEntry);
        CertPinManager pf = new CertPinManager(path, new TrustedCertificateStore());

        assertFalse("Short entry should NOT match longer hostname",
                pf.isChainValid(longHostname, shortChain));
        assertFalse("Long entry should NOT match shorter hostname",
                pf.isChainValid(shortHostname, longChain));
        assertTrue("Short entry should match short hostname",
                pf.isChainValid(shortHostname, shortChain));
        assertTrue("Long entry should match long name",
                pf.isChainValid(longHostname, longChain));
    }

    public void testPinEntryMalformedEntry() throws Exception {
        // set up the pinEntry with a bogus entry
        String entry = "*.google.com=";
        try {
            new PinListEntry(entry, new TrustedCertificateStore());
            fail("Accepted an empty pin list entry.");
        } catch (PinEntryException expected) {
        }
    }

    public void testPinEntryNull() throws Exception {
        // set up the pinEntry with a bogus entry
        String entry = null;
        try {
            new PinListEntry(entry, new TrustedCertificateStore());
            fail("Accepted a basically wholly bogus entry.");
        } catch (NullPointerException expected) {
        }
    }

    public void testPinEntryEmpty() throws Exception {
        // set up the pinEntry with a bogus entry
        try {
            new PinListEntry("", new TrustedCertificateStore());
            fail("Accepted an empty entry.");
        } catch (PinEntryException expected) {
        }
    }

    public void testPinEntryPinFailure() throws Exception {
        // write a pinfile with two entries, one longer than the other
        String shortEntry = "*.google.com=true|" + shortPin;

        // set up the pinEntry with a pinlist that doesn't match what we'll give it
        PinListEntry e = new PinListEntry(shortEntry, new TrustedCertificateStore());
        assertTrue("Not enforcing!", e.getEnforcing());
        // verify that it doesn't accept
        boolean retval = e.isChainValid(longChain);
        assertFalse("Accepted an incorrect pinning, this is very bad", retval);
    }

    public void testPinEntryPinSuccess() throws Exception {
        // write a pinfile with two entries, one longer than the other
        String shortEntry = "*.google.com=true|" + shortPin;

        // set up the pinEntry with a pinlist that matches what we'll give it
        PinListEntry e = new PinListEntry(shortEntry, new TrustedCertificateStore());
        assertTrue("Not enforcing!", e.getEnforcing());
        // verify that it accepts
        boolean retval = e.isChainValid(shortChain);
        assertTrue("Failed on a correct pinning, this is very bad", retval);
    }

    public void testPinEntryNonEnforcing() throws Exception {
        // write a pinfile with two entries, one longer than the other
        String shortEntry = "*.google.com=false|" + shortPin;

        // set up the pinEntry with a pinlist that matches what we'll give it
        PinListEntry e = new PinListEntry(shortEntry, new TrustedCertificateStore());
        assertFalse("Enforcing!", e.getEnforcing());
        // verify that it accepts
        boolean retval = e.isChainValid(shortChain);
        assertTrue("Failed on an unenforced pinning, this is bad-ish", retval);
    }
}
