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

package org.apache.harmony.xnet.provider.jsse;

import java.security.GeneralSecurityException;
import java.util.Hashtable;

import javax.crypto.Cipher;

/**
 * Represents Cipher Suite as defined in TLS 1.0 spec.,
 * A.5. The CipherSuite;
 * C. CipherSuite definitions.
 * @see <a href="http://www.ietf.org/rfc/rfc2246.txt">TLS 1.0 spec.</a>
 *
 */
public class CipherSuite {

    /**
     * true if this cipher suite is supported
     */
    boolean supported = true;

    /**
     * cipher suite key exchange
     */
    final int keyExchange;

    /**
     * cipher
     */
    final String cipherName;

    /**
     * Cipher information
     */
    final int keyMaterial;
    final int expandedKeyMaterial;
    final int effectiveKeyBytes;
    final int IVSize;
    final private int blockSize;

    // cipher suite code
    private final byte[] cipherSuiteCode;

    // cipher suite name
    private final String name;

    // true if cipher suite is exportable
    private final boolean isExportable;

    // Hash algorithm
    final private String hashName;

    // MAC algorithm
    final private String hmacName;

    // Hash size
    final private int hashSize;

    /**
     * key exchange values
     */
    static final int KeyExchange_RSA = 1;
    static final int KeyExchange_RSA_EXPORT = 2;
    static final int KeyExchange_DHE_DSS = 3;
    static final int KeyExchange_DHE_DSS_EXPORT = 4;
    static final int KeyExchange_DHE_RSA = 5;
    static final int KeyExchange_DHE_RSA_EXPORT = 6;
    static final int KeyExchange_DH_DSS = 7;
    static final int KeyExchange_DH_RSA = 8;
    static final int KeyExchange_DH_anon = 9;
    static final int KeyExchange_DH_anon_EXPORT = 10;
    static final int KeyExchange_DH_DSS_EXPORT = 11;
    static final int KeyExchange_DH_RSA_EXPORT = 12;

    /**
     * TLS cipher suite codes
     */
    static final byte[] code_TLS_NULL_WITH_NULL_NULL = { 0x00, 0x00 };
    static final byte[] code_TLS_RSA_WITH_NULL_MD5 = { 0x00, 0x01 };
    static final byte[] code_TLS_RSA_WITH_NULL_SHA = { 0x00, 0x02 };
    static final byte[] code_TLS_RSA_EXPORT_WITH_RC4_40_MD5 = { 0x00, 0x03 };
    static final byte[] code_TLS_RSA_WITH_RC4_128_MD5 = { 0x00, 0x04 };
    static final byte[] code_TLS_RSA_WITH_RC4_128_SHA = { 0x00, 0x05 };
    static final byte[] code_TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = { 0x00, 0x06 };
    static final byte[] code_TLS_RSA_WITH_IDEA_CBC_SHA = { 0x00, 0x07 };
    static final byte[] code_TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x08 };
    static final byte[] code_TLS_RSA_WITH_DES_CBC_SHA = { 0x00, 0x09 };
    static final byte[] code_TLS_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x0A };
    static final byte[] code_TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x0B };
    static final byte[] code_TLS_DH_DSS_WITH_DES_CBC_SHA = { 0x00, 0x0C };
    static final byte[] code_TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x0D };
    static final byte[] code_TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x0E };
    static final byte[] code_TLS_DH_RSA_WITH_DES_CBC_SHA = { 0x00, 0x0F };
    static final byte[] code_TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x10 };
    static final byte[] code_TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x11 };
    static final byte[] code_TLS_DHE_DSS_WITH_DES_CBC_SHA = { 0x00, 0x12 };
    static final byte[] code_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x13 };
    static final byte[] code_TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x14 };
    static final byte[] code_TLS_DHE_RSA_WITH_DES_CBC_SHA = { 0x00, 0x15 };
    static final byte[] code_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x16 };
    static final byte[] code_TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = { 0x00, 0x17 };
    static final byte[] code_TLS_DH_anon_WITH_RC4_128_MD5 = { 0x00, 0x18 };
    static final byte[] code_TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x19 };
    static final byte[] code_TLS_DH_anon_WITH_DES_CBC_SHA = { 0x00, 0x1A };
    static final byte[] code_TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x1B };

    static final CipherSuite TLS_NULL_WITH_NULL_NULL = new CipherSuite(
            "SSL_NULL_WITH_NULL_NULL", true, 0, null, null,
            code_TLS_NULL_WITH_NULL_NULL);

    static final CipherSuite TLS_RSA_WITH_NULL_MD5 = new CipherSuite(
            "SSL_RSA_WITH_NULL_MD5", true, KeyExchange_RSA, null, "MD5",
            code_TLS_RSA_WITH_NULL_MD5);

    static final CipherSuite TLS_RSA_WITH_NULL_SHA = new CipherSuite(
            "SSL_RSA_WITH_NULL_SHA", true, KeyExchange_RSA, null, "SHA",
            code_TLS_RSA_WITH_NULL_SHA);

    static final CipherSuite TLS_RSA_EXPORT_WITH_RC4_40_MD5 = new CipherSuite(
            "SSL_RSA_EXPORT_WITH_RC4_40_MD5", true, KeyExchange_RSA_EXPORT,
            "RC4_40", "MD5", code_TLS_RSA_EXPORT_WITH_RC4_40_MD5);

    static final CipherSuite TLS_RSA_WITH_RC4_128_MD5 = new CipherSuite(
            "SSL_RSA_WITH_RC4_128_MD5", false, KeyExchange_RSA, "RC4_128",
            "MD5", code_TLS_RSA_WITH_RC4_128_MD5);

    static final CipherSuite TLS_RSA_WITH_RC4_128_SHA = new CipherSuite(
            "SSL_RSA_WITH_RC4_128_SHA", false, KeyExchange_RSA, "RC4_128",
            "SHA", code_TLS_RSA_WITH_RC4_128_SHA);

    static final CipherSuite TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = new CipherSuite(
            "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5", true, KeyExchange_RSA_EXPORT,
            "RC2_CBC_40", "MD5", code_TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5);

    static final CipherSuite TLS_RSA_WITH_IDEA_CBC_SHA = new CipherSuite(
            "TLS_RSA_WITH_IDEA_CBC_SHA", false, KeyExchange_RSA, "IDEA_CBC",
            "SHA", code_TLS_RSA_WITH_IDEA_CBC_SHA);

    static final CipherSuite TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite(
            "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA", true, KeyExchange_RSA_EXPORT,
            "DES40_CBC", "SHA", code_TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);

    static final CipherSuite TLS_RSA_WITH_DES_CBC_SHA = new CipherSuite(
            "SSL_RSA_WITH_DES_CBC_SHA", false, KeyExchange_RSA, "DES_CBC",
            "SHA", code_TLS_RSA_WITH_DES_CBC_SHA);

    static final CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA = new CipherSuite(
            "SSL_RSA_WITH_3DES_EDE_CBC_SHA", false, KeyExchange_RSA,
            "3DES_EDE_CBC", "SHA", code_TLS_RSA_WITH_3DES_EDE_CBC_SHA);

    static final CipherSuite TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite(
            "SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", true,
            KeyExchange_DH_DSS_EXPORT, "DES40_CBC", "SHA",
            code_TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA);

    static final CipherSuite TLS_DH_DSS_WITH_DES_CBC_SHA = new CipherSuite(
            "TLS_DH_DSS_WITH_DES_CBC_SHA", false, KeyExchange_DH_DSS,
            "DES_CBC", "SHA", code_TLS_DH_DSS_WITH_DES_CBC_SHA);

    static final CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = new CipherSuite(
            "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", false, KeyExchange_DH_DSS,
            "3DES_EDE_CBC", "SHA", code_TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA);

    static final CipherSuite TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite(
            "SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", true,
            KeyExchange_DH_RSA_EXPORT, "DES40_CBC", "SHA",
            code_TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);

    static final CipherSuite TLS_DH_RSA_WITH_DES_CBC_SHA = new CipherSuite(
            "TLS_DH_RSA_WITH_DES_CBC_SHA", false, KeyExchange_DH_RSA,
            "DES_CBC", "SHA", code_TLS_DH_RSA_WITH_DES_CBC_SHA);

    static final CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = new CipherSuite(
            "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", false, KeyExchange_DH_RSA,
            "3DES_EDE_CBC", "SHA", code_TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA);

    static final CipherSuite TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite(
            "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", true,
            KeyExchange_DHE_DSS_EXPORT, "DES40_CBC", "SHA",
            code_TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);

    static final CipherSuite TLS_DHE_DSS_WITH_DES_CBC_SHA = new CipherSuite(
            "SSL_DHE_DSS_WITH_DES_CBC_SHA", false, KeyExchange_DHE_DSS,
            "DES_CBC", "SHA", code_TLS_DHE_DSS_WITH_DES_CBC_SHA);

    static final CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = new CipherSuite(
            "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA", false, KeyExchange_DHE_DSS,
            "3DES_EDE_CBC", "SHA", code_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);

    static final CipherSuite TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite(
            "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", true,
            KeyExchange_DHE_RSA_EXPORT, "DES40_CBC", "SHA",
            code_TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);

    static final CipherSuite TLS_DHE_RSA_WITH_DES_CBC_SHA = new CipherSuite(
            "SSL_DHE_RSA_WITH_DES_CBC_SHA", false, KeyExchange_DHE_RSA,
            "DES_CBC", "SHA", code_TLS_DHE_RSA_WITH_DES_CBC_SHA);

    static final CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = new CipherSuite(
            "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA", false, KeyExchange_DHE_RSA,
            "3DES_EDE_CBC", "SHA", code_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);

    static final CipherSuite TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = new CipherSuite(
            "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5", true,
            KeyExchange_DH_anon_EXPORT, "RC4_40", "MD5",
            code_TLS_DH_anon_EXPORT_WITH_RC4_40_MD5);

    static final CipherSuite TLS_DH_anon_WITH_RC4_128_MD5 = new CipherSuite(
            "SSL_DH_anon_WITH_RC4_128_MD5", false, KeyExchange_DH_anon,
            "RC4_128", "MD5", code_TLS_DH_anon_WITH_RC4_128_MD5);

    static final CipherSuite TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite(
            "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA", true,
            KeyExchange_DH_anon_EXPORT, "DES40_CBC", "SHA",
            code_TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA);

    static final CipherSuite TLS_DH_anon_WITH_DES_CBC_SHA = new CipherSuite(
            "SSL_DH_anon_WITH_DES_CBC_SHA", false, KeyExchange_DH_anon,
            "DES_CBC", "SHA", code_TLS_DH_anon_WITH_DES_CBC_SHA);

    static final CipherSuite TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = new CipherSuite(
            "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA", false, KeyExchange_DH_anon,
            "3DES_EDE_CBC", "SHA", code_TLS_DH_anon_WITH_3DES_EDE_CBC_SHA);

    // array for quick access to cipher suite by code
    private static final CipherSuite[] suitesByCode = {
            TLS_NULL_WITH_NULL_NULL,
            TLS_RSA_WITH_NULL_MD5,
            TLS_RSA_WITH_NULL_SHA,
            TLS_RSA_EXPORT_WITH_RC4_40_MD5,
            TLS_RSA_WITH_RC4_128_MD5,
            TLS_RSA_WITH_RC4_128_SHA,
            TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
            TLS_RSA_WITH_IDEA_CBC_SHA,
            TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
            TLS_RSA_WITH_DES_CBC_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
            TLS_DH_DSS_WITH_DES_CBC_SHA,
            TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
            TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
            TLS_DH_RSA_WITH_DES_CBC_SHA,
            TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
            TLS_DHE_DSS_WITH_DES_CBC_SHA,
            TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
            TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
            TLS_DHE_RSA_WITH_DES_CBC_SHA,
            TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
            TLS_DH_anon_WITH_RC4_128_MD5,
            TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
            TLS_DH_anon_WITH_DES_CBC_SHA,
            TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
            };

    // hash for quick access to cipher suite by name
    private static final Hashtable<String, CipherSuite> suitesByName;

    /**
     * array of supported cipher suites.
     * Set of supported suites is defined at the moment provider's start
     */
//  TODO Dynamically supported suites: new providers may be dynamically
//  added/removed and the set of supported suites may be changed
    static final CipherSuite[] supportedCipherSuites;

    /**
     * array of supported cipher suites names
     */
    static final String[] supportedCipherSuiteNames;

    /**
     * default cipher suites
     */
    static final CipherSuite[] defaultCipherSuites;

    static {
        int count = 0;
        suitesByName = new Hashtable<String, CipherSuite>();
        for (int i = 0; i < suitesByCode.length; i++) {
            suitesByName.put(suitesByCode[i].getName(), suitesByCode[i]);
            if (suitesByCode[i].supported) {
                count++;
            }
        }
        supportedCipherSuites = new CipherSuite[count];
        supportedCipherSuiteNames = new String[count];
        count = 0;
        for (int i = 0; i < suitesByCode.length; i++) {
            if (suitesByCode[i].supported) {
                supportedCipherSuites[count] = suitesByCode[i];
                supportedCipherSuiteNames[count] = supportedCipherSuites[count].getName();
                count++;
            }
        }

        CipherSuite[] defaultPretendent = {
                TLS_RSA_WITH_RC4_128_MD5,
                TLS_RSA_WITH_RC4_128_SHA,
                // TLS_RSA_WITH_AES_128_CBC_SHA,
                // TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                // LS_DHE_DSS_WITH_AES_128_CBC_SHA,
                TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_DES_CBC_SHA,
                TLS_DHE_RSA_WITH_DES_CBC_SHA, TLS_DHE_DSS_WITH_DES_CBC_SHA,
                TLS_RSA_EXPORT_WITH_RC4_40_MD5,
                TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
                TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
                TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
                };
        count = 0;
        for (int i = 0; i < defaultPretendent.length; i++) {
            if (defaultPretendent[i].supported) {
                count++;
            }
        }
        defaultCipherSuites = new CipherSuite[count];
        count = 0;
        for (int i = 0; i < defaultPretendent.length; i++) {
            if (defaultPretendent[i].supported) {
                defaultCipherSuites[count++] = defaultPretendent[i];
            }
        }
    }

    /**
     * Returns CipherSuite by name
     * @param name
     * @return
     */
    public static CipherSuite getByName(String name) {
        return suitesByName.get(name);
    }

    /**
     * Returns CipherSuite based on TLS CipherSuite code
     * @see <a href="http://www.ietf.org/rfc/rfc2246.txt">TLS 1.0 spec., A.5. The CipherSuite</a>
     * @param b1
     * @param b2
     * @return
     */
    public static CipherSuite getByCode(byte b1, byte b2) {
        if (b1 != 0 || (b2 & 0xFF) > suitesByCode.length) {
            // Unknown
            return new CipherSuite("UNKNOWN_" + b1 + "_" + b2, false, 0, "",
                    "", new byte[] { b1, b2 });
        }
        return suitesByCode[b2];
    }

    /**
     * Returns CipherSuite based on V2CipherSpec code
     * as described in TLS 1.0 spec., E. Backward Compatibility With SSL
     *
     * @param b1
     * @param b2
     * @param b3
     * @return CipherSuite
     */
    public static CipherSuite getByCode(byte b1, byte b2, byte b3) {
        if (b1 == 0 && b2 == 0) {
            if ((b3 & 0xFF) <= suitesByCode.length) {
                return suitesByCode[b3];
            }
        }
        // as TLSv1 equivalent of V2CipherSpec should be included in
        // V2ClientHello, ignore V2CipherSpec
        return new CipherSuite("UNKNOWN_" + b1 + "_" + b2 + "_" + b3, false, 0,
                "", "", new byte[] { b1, b2, b3 });
    }

    /**
     * Creates CipherSuite
     * @param name
     * @param isExportable
     * @param keyExchange
     * @param cipherName
     * @param hash
     * @param code
     */
    public CipherSuite(String name, boolean isExportable, int keyExchange,
            String cipherName, String hash, byte[] code) {
        this.name = name;
        this.keyExchange = keyExchange;
        this.isExportable = isExportable;
        if (cipherName == null) {
            this.cipherName = null;
            keyMaterial = 0;
            expandedKeyMaterial = 0;
            effectiveKeyBytes = 0;
            IVSize = 0;
            blockSize = 0;
        } else if ("IDEA_CBC".equals(cipherName)) {
            this.cipherName = "IDEA/CBC/NoPadding";
            keyMaterial = 16;
            expandedKeyMaterial = 16;
            effectiveKeyBytes = 16;
            IVSize = 8;
            blockSize = 8;
        } else if ("RC2_CBC_40".equals(cipherName)) {
            this.cipherName = "RC2/CBC/NoPadding";
            keyMaterial = 5;
            expandedKeyMaterial = 16;
            effectiveKeyBytes = 5;
            IVSize = 8;
            blockSize = 8;
        } else if ("RC4_40".equals(cipherName)) {
            this.cipherName = "RC4";
            keyMaterial = 5;
            expandedKeyMaterial = 16;
            effectiveKeyBytes = 5;
            IVSize = 0;
            blockSize = 0;
        } else if ("RC4_128".equals(cipherName)) {
            this.cipherName = "RC4";
            keyMaterial = 16;
            expandedKeyMaterial = 16;
            effectiveKeyBytes = 16;
            IVSize = 0;
            blockSize = 0;
        } else if ("DES40_CBC".equals(cipherName)) {
            this.cipherName = "DES/CBC/NoPadding";
            keyMaterial = 5;
            expandedKeyMaterial = 8;
            effectiveKeyBytes = 5;
            IVSize = 8;
            blockSize = 8;
        } else if ("DES_CBC".equals(cipherName)) {
            this.cipherName = "DES/CBC/NoPadding";
            keyMaterial = 8;
            expandedKeyMaterial = 8;
            effectiveKeyBytes = 7;
            IVSize = 8;
            blockSize = 8;
        } else if ("3DES_EDE_CBC".equals(cipherName)) {
            this.cipherName = "DESede/CBC/NoPadding";
            keyMaterial = 24;
            expandedKeyMaterial = 24;
            effectiveKeyBytes = 24;
            IVSize = 8;
            blockSize = 8;
        } else {
            this.cipherName = cipherName;
            keyMaterial = 0;
            expandedKeyMaterial = 0;
            effectiveKeyBytes = 0;
            IVSize = 0;
            blockSize = 0;
        }

        if ("MD5".equals(hash)) {
            this.hmacName = "HmacMD5";
            this.hashName = "MD5";
            hashSize = 16;
        } else if ("SHA".equals(hash)) {
            this.hmacName = "HmacSHA1";
            this.hashName = "SHA-1";
            hashSize = 20;
        } else {
            this.hmacName = null;
            this.hashName = null;
            hashSize = 0;
        }

        cipherSuiteCode = code;

        if (this.cipherName != null) {
            try {
                Cipher.getInstance(this.cipherName);
            } catch (GeneralSecurityException e) {
                supported = false;
            }
        }

    }

    /**
     * Returns true if cipher suite is anonymous
     * @return
     */
    public boolean isAnonymous() {
        if (keyExchange == KeyExchange_DH_anon
                || keyExchange == KeyExchange_DH_anon_EXPORT) {
            return true;
        }
        return false;
    }

    /**
     * Returns array of supported CipherSuites
     * @return
     */
    public static CipherSuite[] getSupported() {
        return supportedCipherSuites;
    }

    /**
     * Returns array of supported cipher suites names
     * @return
     */
    public static String[] getSupportedCipherSuiteNames() {
        return supportedCipherSuiteNames.clone();
    }

    /**
     * Returns cipher suite name
     * @return
     */
    public String getName() {
        return name;
    }

    /**
     * Returns cipher suite code as byte array
     * @return
     */
    public byte[] toBytes() {
        return cipherSuiteCode;
    }

    /**
     * Returns cipher suite description
     */
    @Override
    public String toString() {
        return name + ": " + cipherSuiteCode[0] + " " + cipherSuiteCode[1];
    }

    /**
     * Compares this cipher suite to the specified object.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof CipherSuite
                && this.cipherSuiteCode[0] == ((CipherSuite) obj).cipherSuiteCode[0]
                && this.cipherSuiteCode[1] == ((CipherSuite) obj).cipherSuiteCode[1]) {
            return true;
        }
        return false;
    }

    /**
     * Returns cipher algorithm name
     * @return
     */
    public String getBulkEncryptionAlgorithm() {
        return cipherName;
    }

    /**
     * Returns cipher block size
     * @return
     */
    public int getBlockSize() {
        return blockSize;
    }

    /**
     * Returns MAC algorithm name
     * @return
     */
    public String getHmacName() {
        return hmacName;
    }

    /**
     * Returns hash algorithm name
     * @return
     */
    public String getHashName() {
        return hashName;
    }

    /**
     * Returns hash size
     * @return
     */
    public int getMACLength() {
        return hashSize;
    }

    /**
     * Indicates whether this cipher suite is exportable
     * @return
     */
    public boolean isExportable() {
        return isExportable;
    }

}

