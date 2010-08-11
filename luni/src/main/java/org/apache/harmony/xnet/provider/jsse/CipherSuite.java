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
     * algorithm used for authentication ("RSA", "DSA", "DH", null for anonymous)
     */
    final String authType;

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
    final int ivSize;
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
    static final int KEY_EXCHANGE_RSA = 1;
    static final int KEY_EXCHANGE_RSA_EXPORT = 2;
    static final int KEY_EXCHANGE_DHE_DSS = 3;
    static final int KEY_EXCHANGE_DHE_DSS_EXPORT = 4;
    static final int KEY_EXCHANGE_DHE_RSA = 5;
    static final int KEY_EXCHANGE_DHE_RSA_EXPORT = 6;
    static final int KEY_EXCHANGE_DH_DSS = 7;
    static final int KEY_EXCHANGE_DH_RSA = 8;
    static final int KEY_EXCHANGE_DH_anon = 9;
    static final int KEY_EXCHANGE_DH_anon_EXPORT = 10;
    static final int KEY_EXCHANGE_DH_DSS_EXPORT = 11;
    static final int KEY_EXCHANGE_DH_RSA_EXPORT = 12;

    /**
     * TLS cipher suite codes
     */
    static final byte[] CODE_SSL_NULL_WITH_NULL_NULL = { 0x00, 0x00 };
    static final byte[] CODE_SSL_RSA_WITH_NULL_MD5 = { 0x00, 0x01 };
    static final byte[] CODE_SSL_RSA_WITH_NULL_SHA = { 0x00, 0x02 };
    static final byte[] CODE_SSL_RSA_EXPORT_WITH_RC4_40_MD5 = { 0x00, 0x03 };
    static final byte[] CODE_SSL_RSA_WITH_RC4_128_MD5 = { 0x00, 0x04 };
    static final byte[] CODE_SSL_RSA_WITH_RC4_128_SHA = { 0x00, 0x05 };
    static final byte[] CODE_SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = { 0x00, 0x06 };
    // BEGIN android-removed
    // static final byte[] CODE_TLS_RSA_WITH_IDEA_CBC_SHA = { 0x00, 0x07 };
    // END android-removed
    static final byte[] CODE_SSL_RSA_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x08 };
    static final byte[] CODE_SSL_RSA_WITH_DES_CBC_SHA = { 0x00, 0x09 };
    static final byte[] CODE_SSL_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x0A };
    // BEGIN android-removed
    // static final byte[] CODE_SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x0B };
    // static final byte[] CODE_SSL_DH_DSS_WITH_DES_CBC_SHA = { 0x00, 0x0C };
    // static final byte[] CODE_SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x0D };
    // static final byte[] CODE_SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x0E };
    // static final byte[] CODE_SSL_DH_RSA_WITH_DES_CBC_SHA = { 0x00, 0x0F };
    // static final byte[] CODE_SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x10 };
    // END android-removed
    static final byte[] CODE_SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x11 };
    static final byte[] CODE_SSL_DHE_DSS_WITH_DES_CBC_SHA = { 0x00, 0x12 };
    static final byte[] CODE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x13 };
    static final byte[] CODE_SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x14 };
    static final byte[] CODE_SSL_DHE_RSA_WITH_DES_CBC_SHA = { 0x00, 0x15 };
    static final byte[] CODE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x16 };
    static final byte[] CODE_SSL_DH_anon_EXPORT_WITH_RC4_40_MD5 = { 0x00, 0x17 };
    static final byte[] CODE_SSL_DH_anon_WITH_RC4_128_MD5 = { 0x00, 0x18 };
    static final byte[] CODE_SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x19 };
    static final byte[] CODE_SSL_DH_anon_WITH_DES_CBC_SHA = { 0x00, 0x1A };
    static final byte[] CODE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x1B };

    // AES Cipher Suites from RFC 3268 - http://www.ietf.org/rfc/rfc3268.txt
    static final byte[] CODE_TLS_RSA_WITH_AES_128_CBC_SHA = { 0x00, 0x2F };
    //static final byte[] CODE_TLS_DH_DSS_WITH_AES_128_CBC_SHA = { 0x00, 0x30 };
    //static final byte[] CODE_TLS_DH_RSA_WITH_AES_128_CBC_SHA = { 0x00, 0x31 };
    static final byte[] CODE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA = { 0x00, 0x32 };
    static final byte[] CODE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA = { 0x00, 0x33 };
    static final byte[] CODE_TLS_DH_anon_WITH_AES_128_CBC_SHA = { 0x00, 0x34 };
    static final byte[] CODE_TLS_RSA_WITH_AES_256_CBC_SHA = { 0x00, 0x35 };
    //static final byte[] CODE_TLS_DH_DSS_WITH_AES_256_CBC_SHA = { 0x00, 0x36 };
    //static final byte[] CODE_TLS_DH_RSA_WITH_AES_256_CBC_SHA = { 0x00, 0x37 };
    static final byte[] CODE_TLS_DHE_DSS_WITH_AES_256_CBC_SHA = { 0x00, 0x38 };
    static final byte[] CODE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA = { 0x00, 0x39 };
    static final byte[] CODE_TLS_DH_anon_WITH_AES_256_CBC_SHA = { 0x00, 0x3A };

    static final CipherSuite SSL_NULL_WITH_NULL_NULL = new CipherSuite(
            "SSL_NULL_WITH_NULL_NULL", true, 0, null, null, null,
            CODE_SSL_NULL_WITH_NULL_NULL);

    static final CipherSuite SSL_RSA_WITH_NULL_MD5 = new CipherSuite(
            "SSL_RSA_WITH_NULL_MD5", true, KEY_EXCHANGE_RSA, "RSA", null, "MD5",
            CODE_SSL_RSA_WITH_NULL_MD5);

    static final CipherSuite SSL_RSA_WITH_NULL_SHA = new CipherSuite(
            "SSL_RSA_WITH_NULL_SHA", true, KEY_EXCHANGE_RSA, "RSA", null, "SHA",
            CODE_SSL_RSA_WITH_NULL_SHA);

    static final CipherSuite SSL_RSA_EXPORT_WITH_RC4_40_MD5 = new CipherSuite(
            "SSL_RSA_EXPORT_WITH_RC4_40_MD5", true, KEY_EXCHANGE_RSA_EXPORT,
            "RSA", "RC4_40", "MD5", CODE_SSL_RSA_EXPORT_WITH_RC4_40_MD5);

    static final CipherSuite SSL_RSA_WITH_RC4_128_MD5 = new CipherSuite(
            "SSL_RSA_WITH_RC4_128_MD5", false, KEY_EXCHANGE_RSA, "RSA", "RC4_128",
            "MD5", CODE_SSL_RSA_WITH_RC4_128_MD5);

    static final CipherSuite SSL_RSA_WITH_RC4_128_SHA = new CipherSuite(
            "SSL_RSA_WITH_RC4_128_SHA", false, KEY_EXCHANGE_RSA, "RSA", "RC4_128",
            "SHA", CODE_SSL_RSA_WITH_RC4_128_SHA);

    static final CipherSuite SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = new CipherSuite(
            "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5", true, KEY_EXCHANGE_RSA_EXPORT,
            "RSA", "RC2_CBC_40", "MD5", CODE_SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5);

    // BEGIN android-removed
    // static final CipherSuite TLS_RSA_WITH_IDEA_CBC_SHA = new CipherSuite(
    //         "TLS_RSA_WITH_IDEA_CBC_SHA", false, KEY_EXCHANGE_RSA, "RSA", "IDEA_CBC",
    //         "SHA", CODE_TLS_RSA_WITH_IDEA_CBC_SHA);
    // END android-removed

    static final CipherSuite SSL_RSA_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite(
            "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA", true, KEY_EXCHANGE_RSA_EXPORT,
            "RSA", "DES40_CBC", "SHA", CODE_SSL_RSA_EXPORT_WITH_DES40_CBC_SHA);

    static final CipherSuite SSL_RSA_WITH_DES_CBC_SHA = new CipherSuite(
            "SSL_RSA_WITH_DES_CBC_SHA", false, KEY_EXCHANGE_RSA, "RSA", "DES_CBC",
            "SHA", CODE_SSL_RSA_WITH_DES_CBC_SHA);

    static final CipherSuite SSL_RSA_WITH_3DES_EDE_CBC_SHA = new CipherSuite(
            "SSL_RSA_WITH_3DES_EDE_CBC_SHA", false, KEY_EXCHANGE_RSA,
            "RSA", "3DES_EDE_CBC", "SHA", CODE_SSL_RSA_WITH_3DES_EDE_CBC_SHA);

    // BEGIN android-removed
    // static final CipherSuite SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite(
    //         "SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", true,
    //         KEY_EXCHANGE_DH_DSS_EXPORT, "DH", "DES40_CBC", "SHA",
    //         CODE_SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
    //
    // static final CipherSuite SSL_DH_DSS_WITH_DES_CBC_SHA = new CipherSuite(
    //         "SSL_DH_DSS_WITH_DES_CBC_SHA", false, KEY_EXCHANGE_DH_DSS,
    //         "DH", "DES_CBC", "SHA", CODE_SSL_DH_DSS_WITH_DES_CBC_SHA);
    //
    // static final CipherSuite SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA = new CipherSuite(
    //         "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA", false, KEY_EXCHANGE_DH_DSS,
    //         "DH", "3DES_EDE_CBC", "SHA", CODE_SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA);
    //
    // static final CipherSuite SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite(
    //         "SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", true,
    //         KEY_EXCHANGE_DH_RSA_EXPORT, "DH", "DES40_CBC", "SHA",
    //         CODE_SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);
    //
    // static final CipherSuite SSL_DH_RSA_WITH_DES_CBC_SHA = new CipherSuite(
    //         "SSL_DH_RSA_WITH_DES_CBC_SHA", false, KEY_EXCHANGE_DH_RSA,
    //         "DH", "DES_CBC", "SHA", CODE_SSL_DH_RSA_WITH_DES_CBC_SHA);
    //
    // static final CipherSuite SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA = new CipherSuite(
    //         "SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA", false, KEY_EXCHANGE_DH_RSA,
    //         "DH", "3DES_EDE_CBC", "SHA", CODE_SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA);
    // END android-removed

    static final CipherSuite SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite(
            "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", true,
            KEY_EXCHANGE_DHE_DSS_EXPORT, "DSA", "DES40_CBC", "SHA",
            CODE_SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);

    static final CipherSuite SSL_DHE_DSS_WITH_DES_CBC_SHA = new CipherSuite(
            "SSL_DHE_DSS_WITH_DES_CBC_SHA", false, KEY_EXCHANGE_DHE_DSS,
            "DSA", "DES_CBC", "SHA", CODE_SSL_DHE_DSS_WITH_DES_CBC_SHA);

    static final CipherSuite SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA = new CipherSuite(
            "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA", false, KEY_EXCHANGE_DHE_DSS,
            "DSA", "3DES_EDE_CBC", "SHA", CODE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA);

    static final CipherSuite SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite(
            "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", true,
            KEY_EXCHANGE_DHE_RSA_EXPORT, "RSA", "DES40_CBC", "SHA",
            CODE_SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);

    static final CipherSuite SSL_DHE_RSA_WITH_DES_CBC_SHA = new CipherSuite(
            "SSL_DHE_RSA_WITH_DES_CBC_SHA", false, KEY_EXCHANGE_DHE_RSA,
            "RSA", "DES_CBC", "SHA", CODE_SSL_DHE_RSA_WITH_DES_CBC_SHA);

    static final CipherSuite SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA = new CipherSuite(
            "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA", false, KEY_EXCHANGE_DHE_RSA,
            "RSA", "3DES_EDE_CBC", "SHA", CODE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA);

    static final CipherSuite SSL_DH_anon_EXPORT_WITH_RC4_40_MD5 = new CipherSuite(
            "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5", true,
            KEY_EXCHANGE_DH_anon_EXPORT, "DH", "RC4_40", "MD5",
            CODE_SSL_DH_anon_EXPORT_WITH_RC4_40_MD5);

    static final CipherSuite SSL_DH_anon_WITH_RC4_128_MD5 = new CipherSuite(
            "SSL_DH_anon_WITH_RC4_128_MD5", false, KEY_EXCHANGE_DH_anon,
            "DH", "RC4_128", "MD5", CODE_SSL_DH_anon_WITH_RC4_128_MD5);

    static final CipherSuite SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite(
            "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA", true,
            KEY_EXCHANGE_DH_anon_EXPORT, "DH", "DES40_CBC", "SHA",
            CODE_SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA);

    static final CipherSuite SSL_DH_anon_WITH_DES_CBC_SHA = new CipherSuite(
            "SSL_DH_anon_WITH_DES_CBC_SHA", false, KEY_EXCHANGE_DH_anon,
            "DH", "DES_CBC", "SHA", CODE_SSL_DH_anon_WITH_DES_CBC_SHA);

    static final CipherSuite SSL_DH_anon_WITH_3DES_EDE_CBC_SHA = new CipherSuite(
            "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA", false, KEY_EXCHANGE_DH_anon,
            "DH", "3DES_EDE_CBC", "SHA", CODE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA);

    static final CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA
            = new CipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA",
                              false,
                              KEY_EXCHANGE_RSA,
                              "RSA",
                              "AES_128",
                              "SHA",
                              CODE_TLS_RSA_WITH_AES_128_CBC_SHA);
    static final CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA
            = new CipherSuite("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                              false,
                              KEY_EXCHANGE_DHE_DSS,
                              "DSA",
                              "AES_128",
                              "SHA",
                              CODE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
    static final CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA
            = new CipherSuite("TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                              false,
                              KEY_EXCHANGE_DHE_RSA,
                              "RSA",
                              "AES_128",
                              "SHA",
                              CODE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
    static final CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA
            = new CipherSuite("TLS_DH_anon_WITH_AES_128_CBC_SHA",
                              false,
                              KEY_EXCHANGE_DH_anon,
                              "DH",
                              "AES_128",
                              "SHA",
                              CODE_TLS_DH_anon_WITH_AES_128_CBC_SHA);
    static final CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA
            = new CipherSuite("TLS_RSA_WITH_AES_256_CBC_SHA",
                              false,
                              KEY_EXCHANGE_RSA,
                              "RSA",
                              "AES_256",
                              "SHA",
                              CODE_TLS_RSA_WITH_AES_256_CBC_SHA);
    static final CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA
            = new CipherSuite("TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                              false,
                              KEY_EXCHANGE_DHE_DSS,
                              "DSA",
                              "AES_256",
                              "SHA",
                              CODE_TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
    static final CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA
            = new CipherSuite("TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                              false,
                              KEY_EXCHANGE_DHE_RSA,
                              "RSA",
                              "AES_256",
                              "SHA",
                              CODE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
    static final CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA
            = new CipherSuite("TLS_DH_anon_WITH_AES_256_CBC_SHA",
                              false,
                              KEY_EXCHANGE_DH_anon,
                              "DH",
                              "AES_256",
                              "SHA",
                              CODE_TLS_DH_anon_WITH_AES_256_CBC_SHA);

    // array for quick access to cipher suite by code
    private static final CipherSuite[] SUITES_BY_CODE = {
        // http://www.iana.org/assignments/tls-parameters/tls-parameters.xml
        SSL_NULL_WITH_NULL_NULL,                        // { 0x00, 0x00 };
        SSL_RSA_WITH_NULL_MD5,                          // { 0x00, 0x01 };
        SSL_RSA_WITH_NULL_SHA,                          // { 0x00, 0x02 };
        SSL_RSA_EXPORT_WITH_RC4_40_MD5,                 // { 0x00, 0x03 };
        SSL_RSA_WITH_RC4_128_MD5,                       // { 0x00, 0x04 };
        SSL_RSA_WITH_RC4_128_SHA,                       // { 0x00, 0x05 };
        // BEGIN android-changed
        null, // SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,    // { 0x00, 0x06 };
        null, // TLS_RSA_WITH_IDEA_CBC_SHA,             // { 0x00, 0x07 };
        // END android-changed
        SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,              // { 0x00, 0x08 };
        SSL_RSA_WITH_DES_CBC_SHA,                       // { 0x00, 0x09 };
        SSL_RSA_WITH_3DES_EDE_CBC_SHA,                  // { 0x00, 0x0a };
        // BEGIN android-changed
        null, // SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA   // { 0x00, 0x0b };
        null, // SSL_DH_DSS_WITH_DES_CBC_SHA,           // { 0x00, 0x0c };
        null, // SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA,      // { 0x00, 0x0d };
        null, // SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,  // { 0x00, 0x0e };
        null, // SSL_DH_RSA_WITH_DES_CBC_SHA,           // { 0x00, 0x0f };
        null, // SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA,      // { 0x00, 0x10 };
        // END android-changed
        SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,          // { 0x00, 0x11 };
        SSL_DHE_DSS_WITH_DES_CBC_SHA,                   // { 0x00, 0x12 };
        SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA,              // { 0x00, 0x13 };
        SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,          // { 0x00, 0x14 };
        SSL_DHE_RSA_WITH_DES_CBC_SHA,                   // { 0x00, 0x15 };
        SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,              // { 0x00, 0x16 };
        SSL_DH_anon_EXPORT_WITH_RC4_40_MD5,             // { 0x00, 0x17 };
        SSL_DH_anon_WITH_RC4_128_MD5,                   // { 0x00, 0x18 };
        SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA,          // { 0x00, 0x19 };
        SSL_DH_anon_WITH_DES_CBC_SHA,                   // { 0x00, 0x1A };
        SSL_DH_anon_WITH_3DES_EDE_CBC_SHA,              // { 0x00, 0x1B };
        // BEGIN android-added
        null, // SSL_FORTEZZA_KEA_WITH_NULL_SHA         // { 0x00, 0x1C };
        null, // SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA // { 0x00, 0x1D };
        null, // TLS_KRB5_WITH_DES_CBC_SHA              // { 0x00, 0x1E };
        null, // TLS_KRB5_WITH_3DES_EDE_CBC_SHA         // { 0x00, 0x1F };
        null, // TLS_KRB5_WITH_RC4_128_SHA              // { 0x00, 0x20 };
        null, // TLS_KRB5_WITH_IDEA_CBC_SHA             // { 0x00, 0x21 };
        null, // TLS_KRB5_WITH_DES_CBC_MD5              // { 0x00, 0x22 };
        null, // TLS_KRB5_WITH_3DES_EDE_CBC_MD5         // { 0x00, 0x23 };
        null, // TLS_KRB5_WITH_RC4_128_MD5              // { 0x00, 0x24 };
        null, // TLS_KRB5_WITH_IDEA_CBC_MD5             // { 0x00, 0x25 };
        null, // TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA    // { 0x00, 0x26 };
        null, // TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA    // { 0x00, 0x27 };
        null, // TLS_KRB5_EXPORT_WITH_RC4_40_SHA        // { 0x00, 0x28 };
        null, // TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5    // { 0x00, 0x29 };
        null, // TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5    // { 0x00, 0x2A };
        null, // TLS_KRB5_EXPORT_WITH_RC4_40_MD5        // { 0x00, 0x2B };
        null, // TLS_PSK_WITH_NULL_SHA                  // { 0x00, 0x2C };
        null, // TLS_DHE_PSK_WITH_NULL_SHA              // { 0x00, 0x2D };
        null, // TLS_RSA_PSK_WITH_NULL_SHA              // { 0x00, 0x2E };
        TLS_RSA_WITH_AES_128_CBC_SHA,                   // { 0x00, 0x2F };
        null, // TLS_DH_DSS_WITH_AES_128_CBC_SHA        // { 0x00, 0x30 };
        null, // TLS_DH_RSA_WITH_AES_128_CBC_SHA        // { 0x00, 0x31 };
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA,               // { 0x00, 0x32 };
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA,               // { 0x00, 0x33 };
        TLS_DH_anon_WITH_AES_128_CBC_SHA,               // { 0x00, 0x34 };
        TLS_RSA_WITH_AES_256_CBC_SHA,                   // { 0x00, 0x35 };
        null, // TLS_DH_DSS_WITH_AES_256_CBC_SHA,       // { 0x00, 0x36 };
        null, // TLS_DH_RSA_WITH_AES_256_CBC_SHA,       // { 0x00, 0x37 };
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA,               // { 0x00, 0x38 };
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA,               // { 0x00, 0x39 };
        TLS_DH_anon_WITH_AES_256_CBC_SHA,               // { 0x00, 0x3A };
        // END android-added
    };

    // hash for quick access to cipher suite by name
    private static final Hashtable<String, CipherSuite> SUITES_BY_NAME;

    /**
     * array of supported cipher suites.
     * Set of supported suites is defined at the moment provider's start
     */
    //  TODO Dynamically supported suites: new providers may be dynamically
    //  added/removed and the set of supported suites may be changed
    static final CipherSuite[] SUPPORTED_CIPHER_SUITES;

    /**
     * array of supported cipher suites names
     */
    static final String[] SUPPORTED_CIPHER_SUITE_NAMES;

    /**
     * default cipher suites
     */
    static final CipherSuite[] DEFAULT_CIPHER_SUITES;

    static {
        int count = 0;
        SUITES_BY_NAME = new Hashtable<String, CipherSuite>();
        for (int i = 0; i < SUITES_BY_CODE.length; i++) {
            if (SUITES_BY_CODE[i] == SSL_NULL_WITH_NULL_NULL) {
                continue;
            }
            if (SUITES_BY_CODE[i] == null) {
                continue;
            }
            SUITES_BY_NAME.put(SUITES_BY_CODE[i].getName(), SUITES_BY_CODE[i]);
            if (SUITES_BY_CODE[i].supported) {
                count++;
            }
        }
        SUPPORTED_CIPHER_SUITES = new CipherSuite[count];
        SUPPORTED_CIPHER_SUITE_NAMES = new String[count];
        count = 0;
        for (int i = 0; i < SUITES_BY_CODE.length; i++) {
            if (SUITES_BY_CODE[i] == SSL_NULL_WITH_NULL_NULL) {
                continue;
            }
            if (SUITES_BY_CODE[i] == null) {
                continue;
            }
            if (SUITES_BY_CODE[i].supported) {
                SUPPORTED_CIPHER_SUITES[count] = SUITES_BY_CODE[i];
                SUPPORTED_CIPHER_SUITE_NAMES[count] = SUPPORTED_CIPHER_SUITES[count].getName();
                count++;
            }
        }

        CipherSuite[] defaultCipherSuites = {
                SSL_RSA_WITH_RC4_128_MD5,
                SSL_RSA_WITH_RC4_128_SHA,
                TLS_RSA_WITH_AES_128_CBC_SHA,
                TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                SSL_RSA_WITH_3DES_EDE_CBC_SHA,
                SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                SSL_RSA_WITH_DES_CBC_SHA,
                SSL_DHE_RSA_WITH_DES_CBC_SHA,
                SSL_DHE_DSS_WITH_DES_CBC_SHA,
                SSL_RSA_EXPORT_WITH_RC4_40_MD5,
                SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,
                SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
                SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
                };
        count = 0;
        for (int i = 0; i < defaultCipherSuites.length; i++) {
            if (defaultCipherSuites[i].supported) {
                count++;
            }
        }
        DEFAULT_CIPHER_SUITES = new CipherSuite[count];
        count = 0;
        for (int i = 0; i < defaultCipherSuites.length; i++) {
            if (defaultCipherSuites[i].supported) {
                DEFAULT_CIPHER_SUITES[count++] = defaultCipherSuites[i];
            }
        }
    }

    /**
     * Returns CipherSuite by name
     */
    public static CipherSuite getByName(String name) {
        return SUITES_BY_NAME.get(name);
    }

    /**
     * Returns CipherSuite based on TLS CipherSuite code
     * @see <a href="http://www.ietf.org/rfc/rfc2246.txt">TLS 1.0 spec., A.5. The CipherSuite</a>
     */
    public static CipherSuite getByCode(byte b1, byte b2) {
        if (b1 != 0 || (b2 & 0xFF) > SUITES_BY_CODE.length) {
            // Unknown
            return new CipherSuite("UNKNOWN_" + b1 + "_" + b2, false, 0, null,
                    null, null, new byte[] { b1, b2 });
        }
        return SUITES_BY_CODE[b2];
    }

    /**
     * Returns CipherSuite based on V2CipherSpec code
     * as described in TLS 1.0 spec., E. Backward Compatibility With SSL
     */
    public static CipherSuite getByCode(byte b1, byte b2, byte b3) {
        if (b1 == 0 && b2 == 0) {
            if ((b3 & 0xFF) <= SUITES_BY_CODE.length) {
                return SUITES_BY_CODE[b3];
            }
        }
        // as TLSv1 equivalent of V2CipherSpec should be included in
        // V2ClientHello, ignore V2CipherSpec
        return new CipherSuite("UNKNOWN_" + b1 + "_" + b2 + "_" + b3, false, 0,
                null, null, null, new byte[] { b1, b2, b3 });
    }

    /**
     * Creates CipherSuite
     */
    public CipherSuite(String name, boolean isExportable, int keyExchange,
            String authType, String cipherName, String hash, byte[] code) {
        this.name = name;
        this.keyExchange = keyExchange;
        this.authType = authType;
        this.isExportable = isExportable;
        if (cipherName == null) {
            this.cipherName = null;
            keyMaterial = 0;
            expandedKeyMaterial = 0;
            effectiveKeyBytes = 0;
            ivSize = 0;
            blockSize = 0;
        // BEGIN android-removed
        // } else if ("IDEA_CBC".equals(cipherName)) {
        //     this.cipherName = "IDEA/CBC/NoPadding";
        //     keyMaterial = 16;
        //     expandedKeyMaterial = 16;
        //     effectiveKeyBytes = 16;
        //     ivSize = 8;
        //     blockSize = 8;
        // } else if ("RC2_CBC_40".equals(cipherName)) {
        //     this.cipherName = "RC2/CBC/NoPadding";
        //     keyMaterial = 5;
        //     expandedKeyMaterial = 16;
        //     effectiveKeyBytes = 5;
        //     ivSize = 8;
        //     blockSize = 8;
        // END android-removed
        } else if ("RC4_40".equals(cipherName)) {
            this.cipherName = "RC4";
            keyMaterial = 5;
            expandedKeyMaterial = 16;
            effectiveKeyBytes = 5;
            ivSize = 0;
            blockSize = 0;
        } else if ("RC4_128".equals(cipherName)) {
            this.cipherName = "RC4";
            keyMaterial = 16;
            expandedKeyMaterial = 16;
            effectiveKeyBytes = 16;
            ivSize = 0;
            blockSize = 0;
        } else if ("DES40_CBC".equals(cipherName)) {
            this.cipherName = "DES/CBC/NoPadding";
            keyMaterial = 5;
            expandedKeyMaterial = 8;
            effectiveKeyBytes = 5;
            ivSize = 8;
            blockSize = 8;
        } else if ("DES_CBC".equals(cipherName)) {
            this.cipherName = "DES/CBC/NoPadding";
            keyMaterial = 8;
            expandedKeyMaterial = 8;
            effectiveKeyBytes = 7;
            ivSize = 8;
            blockSize = 8;
        } else if ("3DES_EDE_CBC".equals(cipherName)) {
            this.cipherName = "DESede/CBC/NoPadding";
            keyMaterial = 24;
            expandedKeyMaterial = 24;
            effectiveKeyBytes = 24;
            ivSize = 8;
            blockSize = 8;
        } else if ("AES_128".equals(cipherName)) {
            this.cipherName = "AES/CBC/NoPadding";
            keyMaterial = 16;
            expandedKeyMaterial = 16;
            effectiveKeyBytes = 16;
            ivSize = 16;
            blockSize = 16;
        } else if ("AES_256".equals(cipherName)) {
            this.cipherName = "AES/CBC/NoPadding";
            keyMaterial = 32;
            expandedKeyMaterial = 32;
            effectiveKeyBytes = 32;
            ivSize = 16;
            blockSize = 16;
        } else {
            this.cipherName = cipherName;
            keyMaterial = 0;
            expandedKeyMaterial = 0;
            effectiveKeyBytes = 0;
            ivSize = 0;
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
        if (keyExchange == KEY_EXCHANGE_DH_anon
                || keyExchange == KEY_EXCHANGE_DH_anon_EXPORT) {
            return true;
        }
        return false;
    }

    /**
     * Returns array of supported CipherSuites
     * @return
     */
    public static CipherSuite[] getSupported() {
        return SUPPORTED_CIPHER_SUITES;
    }

    /**
     * Returns array of supported cipher suites names
     * @return
     */
    public static String[] getSupportedCipherSuiteNames() {
        return SUPPORTED_CIPHER_SUITE_NAMES.clone();
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

