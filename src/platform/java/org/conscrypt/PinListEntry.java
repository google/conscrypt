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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * This class represents a single entry in the pin file.
 */
// public for testing by CertPinManagerTest
public class PinListEntry {

    /** The Common Name (CN) as used on the SSL certificate */
    private final String cn;

    /**
     * Determines whether a failed match here will prevent the chain from being accepted. If true,
     *  an unpinned chain will log and cause a match failure. If false, it will merely log.
     */
    private final boolean enforcing;

    private final Set<String> pinnedFingerprints = new HashSet<String>();

    private final TrustedCertificateStore certStore;

    public String getCommonName() {
        return cn;
    }

    public boolean getEnforcing() {
        return enforcing;
    }

    public PinListEntry(String entry, TrustedCertificateStore store) throws PinEntryException {
        if (entry == null) {
            throw new NullPointerException("entry == null");
        }
        certStore = store;
        // Examples:
        // *.google.com=true|34c8a0d...9e04ca05f,9e04ca05f...34c8a0d
        // *.android.com=true|ca05f...8a0d34c
        // clients.google.com=false|9e04ca05f...34c8a0d,34c8a0d...9e04ca05f
        String[] values = entry.split("[=,|]");
        // entry must have a CN, an enforcement value, and at least one pin
        if (values.length < 3) {
            throw new PinEntryException("Received malformed pin entry");
        }
        // get the cn
        cn = values[0];        // is there more validation we can do here?
        enforcing = enforcementValueFromString(values[1]);
        // the remainder should be pins
        addPins(Arrays.copyOfRange(values, 2, values.length));
    }

    private static boolean enforcementValueFromString(String val) throws PinEntryException {
        if (val.equals("true")) {
            return true;
        } else if (val.equals("false")) {
            return false;
        } else {
            throw new PinEntryException("Enforcement status is not a valid value");
        }
    }

    /**
     * Checks the given chain against the pin list corresponding to this entry.
     *
     * <p>If enforcing is on and the given {@code chain} does not include the
     * expected pinned certificate, this will return {@code false} indicating
     * the chain is not valid unless the {@code chain} chains up to an user-installed
     * CA cert. Otherwise this will return {@code true} indicating the {@code chain}
     * is valid.
     */
    public boolean isChainValid(List<X509Certificate> chain) {
        boolean containsUserCert = chainContainsUserCert(chain);
        if (!containsUserCert) {
            for (X509Certificate cert : chain) {
                String fingerprint = getFingerprint(cert);
                if (pinnedFingerprints.contains(fingerprint)) {
                    return true;
                }
            }
        }
        logPinFailure(chain, containsUserCert);
        return !enforcing || containsUserCert;
    }

    private static String getFingerprint(X509Certificate cert) {
        try {
            MessageDigest dgst = MessageDigest.getInstance("SHA512");
            byte[] encoded = cert.getPublicKey().getEncoded();
            byte[] fingerprint = dgst.digest(encoded);
            return IntegralToString.bytesToHexString(fingerprint, false);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    private void addPins(String[] pins) {
        for (String pin : pins) {
            validatePin(pin);
        }
        Collections.addAll(pinnedFingerprints, pins);
    }

    private static void validatePin(String pin) {
        // check to make sure the length is correct
        if (pin.length() != 128) {
            throw new IllegalArgumentException("Pin is not a valid length");
        }
        // check to make sure that it's a valid hex string
        try {
            new BigInteger(pin, 16);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Pin is not a valid hex string", e);
        }
    }

    private boolean chainContainsUserCert(List<X509Certificate> chain) {
        if (certStore == null) {
            return false;
        }
        for (X509Certificate cert : chain) {
            if (certStore.isUserAddedCertificate(cert)) {
                return true;
            }
        }
        return false;
    }

    private void logPinFailure(List<X509Certificate> chain, boolean containsUserCert) {
        PinFailureLogger.log(cn, containsUserCert, enforcing, chain);
    }
}

