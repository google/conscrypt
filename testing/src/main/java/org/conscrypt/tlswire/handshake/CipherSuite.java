/*
 * Copyright (C) 2014 The Android Open Source Project
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
package org.conscrypt.tlswire.handshake;
import java.util.HashMap;
import java.util.Map;
/**
 * {@code CipherSuite} enum from TLS 1.2 RFC 5246.
 */
public class CipherSuite {
    // The list of cipher suites below is based on IANA registry
    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    private static final CipherSuite[] CIPHER_SUITES = new CipherSuite[] {
            new CipherSuite(0x0000, "TLS_NULL_WITH_NULL_NULL"),
            new CipherSuite(0x0001, "TLS_RSA_WITH_NULL_MD5", "SSL_RSA_WITH_NULL_MD5"),
            new CipherSuite(0x0002, "TLS_RSA_WITH_NULL_SHA", "SSL_RSA_WITH_NULL_SHA"),
            new CipherSuite(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "SSL_RSA_EXPORT_WITH_RC4_40_MD5"),
            new CipherSuite(0x0004, "TLS_RSA_WITH_RC4_128_MD5", "SSL_RSA_WITH_RC4_128_MD5"),
            new CipherSuite(0x0005, "TLS_RSA_WITH_RC4_128_SHA", "SSL_RSA_WITH_RC4_128_SHA"),
            new CipherSuite(0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
            new CipherSuite(0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA"),
            new CipherSuite(0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
                    "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA"),
            new CipherSuite(0x0009, "TLS_RSA_WITH_DES_CBC_SHA", "SSL_RSA_WITH_DES_CBC_SHA"),
            new CipherSuite(0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "SSL_RSA_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0x000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"),
            new CipherSuite(0x000c, "TLS_DH_DSS_WITH_DES_CBC_SHA"),
            new CipherSuite(0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0x000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"),
            new CipherSuite(0x000f, "TLS_DH_RSA_WITH_DES_CBC_SHA"),
            new CipherSuite(0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
                    "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"),
            new CipherSuite(0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA", "SSL_DHE_DSS_WITH_DES_CBC_SHA"),
            new CipherSuite(0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
                    "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
            new CipherSuite(0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA", "SSL_DHE_RSA_WITH_DES_CBC_SHA"),
            new CipherSuite(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
                    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
                    "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5"),
            new CipherSuite(0x0018, "TLS_DH_anon_WITH_RC4_128_MD5", "SSL_DH_anon_WITH_RC4_128_MD5"),
            new CipherSuite(0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
                    "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"),
            new CipherSuite(0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA", "SSL_DH_anon_WITH_DES_CBC_SHA"),
            new CipherSuite(0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
                    "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0x001e, "TLS_KRB5_WITH_DES_CBC_SHA"),
            new CipherSuite(0x001f, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0x0020, "TLS_KRB5_WITH_RC4_128_SHA"),
            new CipherSuite(0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA"),
            new CipherSuite(0x0022, "TLS_KRB5_WITH_DES_CBC_MD5"),
            new CipherSuite(0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"),
            new CipherSuite(0x0024, "TLS_KRB5_WITH_RC4_128_MD5"),
            new CipherSuite(0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5"),
            new CipherSuite(0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"),
            new CipherSuite(0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"),
            new CipherSuite(0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"),
            new CipherSuite(0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"),
            new CipherSuite(0x002a, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"),
            new CipherSuite(0x002b, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"),
            new CipherSuite(0x002c, "TLS_PSK_WITH_NULL_SHA"),
            new CipherSuite(0x002d, "TLS_DHE_PSK_WITH_NULL_SHA"),
            new CipherSuite(0x002e, "TLS_RSA_PSK_WITH_NULL_SHA"),
            new CipherSuite(0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0x003a, "TLS_DH_anon_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0x003b, "TLS_RSA_WITH_NULL_SHA256"),
            new CipherSuite(0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
            new CipherSuite(0x003e, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0x003f, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"),
            new CipherSuite(0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"),
            new CipherSuite(0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"),
            new CipherSuite(0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"),
            new CipherSuite(0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"),
            new CipherSuite(0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"),
            new CipherSuite(0x0060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"),
            new CipherSuite(0x0061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"),
            new CipherSuite(0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"),
            new CipherSuite(0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"),
            new CipherSuite(0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"),
            new CipherSuite(0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"),
            new CipherSuite(0x0066, "TLS_DHE_DSS_WITH_RC4_128_SHA"),
            new CipherSuite(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"),
            new CipherSuite(0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"),
            new CipherSuite(0x006a, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"),
            new CipherSuite(0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
            new CipherSuite(0x006c, "TLS_DH_anon_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0x006d, "TLS_DH_anon_WITH_AES_256_CBC_SHA256"),
            new CipherSuite(0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"),
            new CipherSuite(0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"),
            new CipherSuite(0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"),
            new CipherSuite(0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"),
            new CipherSuite(0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"),
            new CipherSuite(0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"),
            new CipherSuite(0x008a, "TLS_PSK_WITH_RC4_128_SHA"),
            new CipherSuite(0x008b, "TLS_PSK_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0x008c, "TLS_PSK_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0x008d, "TLS_PSK_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0x008e, "TLS_DHE_PSK_WITH_RC4_128_SHA"),
            new CipherSuite(0x008f, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA"),
            new CipherSuite(0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0x0096, "TLS_RSA_WITH_SEED_CBC_SHA"),
            new CipherSuite(0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA"),
            new CipherSuite(0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA"),
            new CipherSuite(0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA"),
            new CipherSuite(0x009a, "TLS_DHE_RSA_WITH_SEED_CBC_SHA"),
            new CipherSuite(0x009b, "TLS_DH_anon_WITH_SEED_CBC_SHA"),
            new CipherSuite(0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0x00a0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0x00a1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0x00a2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0x00a3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0x00a4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0x00a5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0x00a6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0x00a7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0x00a8, "TLS_PSK_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0x00a9, "TLS_PSK_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0x00aa, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0x00ab, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0x00ac, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0x00ad, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0x00ae, "TLS_PSK_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0x00af, "TLS_PSK_WITH_AES_256_CBC_SHA384"),
            new CipherSuite(0x00b0, "TLS_PSK_WITH_NULL_SHA256"),
            new CipherSuite(0x00b1, "TLS_PSK_WITH_NULL_SHA384"),
            new CipherSuite(0x00b2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0x00b3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"),
            new CipherSuite(0x00b4, "TLS_DHE_PSK_WITH_NULL_SHA256"),
            new CipherSuite(0x00b5, "TLS_DHE_PSK_WITH_NULL_SHA384"),
            new CipherSuite(0x00b6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0x00b7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"),
            new CipherSuite(0x00b8, "TLS_RSA_PSK_WITH_NULL_SHA256"),
            new CipherSuite(0x00b9, "TLS_RSA_PSK_WITH_NULL_SHA384"),
            new CipherSuite(0x00ba, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0x00bb, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0x00bc, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0x00bd, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0x00be, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0x00bf, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0x00c0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"),
            new CipherSuite(0x00c1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"),
            new CipherSuite(0x00c2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"),
            new CipherSuite(0x00c3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"),
            new CipherSuite(0x00c4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"),
            new CipherSuite(0x00c5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"),
            new CipherSuite(0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"),
            new CipherSuite(0x1301, "TLS_AES_128_GCM_SHA256"),
            new CipherSuite(0x1302, "TLS_AES_256_GCM_SHA384"),
            new CipherSuite(0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
            new CipherSuite(0x1304, "TLS_AES_128_CCM_SHA256"),
            new CipherSuite(0x1305, "TLS_AES_128_CCM_8_SHA256"),
            new CipherSuite(0x5600, "TLS_FALLBACK_SCSV"),
            new CipherSuite(0xc001, "TLS_ECDH_ECDSA_WITH_NULL_SHA"),
            new CipherSuite(0xc002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"),
            new CipherSuite(0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0xc004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0xc005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"),
            new CipherSuite(0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
            new CipherSuite(0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0xc00b, "TLS_ECDH_RSA_WITH_NULL_SHA"),
            new CipherSuite(0xc00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA"),
            new CipherSuite(0xc00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0xc00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0xc00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA"),
            new CipherSuite(0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
            new CipherSuite(0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0xc015, "TLS_ECDH_anon_WITH_NULL_SHA"),
            new CipherSuite(0xc016, "TLS_ECDH_anon_WITH_RC4_128_SHA"),
            new CipherSuite(0xc017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0xc019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0xc01a, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0xc01b, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0xc01c, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0xc01d, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0xc01e, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0xc01f, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0xc020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0xc021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0xc022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
            new CipherSuite(0xc025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0xc026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"),
            new CipherSuite(0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
            new CipherSuite(0xc029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0xc02a, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"),
            new CipherSuite(0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0xc02d, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0xc02e, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0xc031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"),
            new CipherSuite(0xc032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"),
            new CipherSuite(0xc033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA"),
            new CipherSuite(0xc034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"),
            new CipherSuite(0xc035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"),
            new CipherSuite(0xc036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"),
            new CipherSuite(0xc037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"),
            new CipherSuite(0xc038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"),
            new CipherSuite(0xc039, "TLS_ECDHE_PSK_WITH_NULL_SHA"),
            new CipherSuite(0xc03a, "TLS_ECDHE_PSK_WITH_NULL_SHA256"),
            new CipherSuite(0xc03b, "TLS_ECDHE_PSK_WITH_NULL_SHA384"),
            new CipherSuite(0xc03c, "TLS_RSA_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc03d, "TLS_RSA_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc03e, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc03f, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc04a, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc04b, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc04c, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc04d, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc04e, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc04f, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc05a, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc05b, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc05c, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc05d, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc05e, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc05f, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc06a, "TLS_PSK_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc06b, "TLS_PSK_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc06c, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc06d, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc06e, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"),
            new CipherSuite(0xc06f, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"),
            new CipherSuite(0xc070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"),
            new CipherSuite(0xc071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"),
            new CipherSuite(0xc072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0xc073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"),
            new CipherSuite(0xc074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0xc075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"),
            new CipherSuite(0xc076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0xc077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"),
            new CipherSuite(0xc078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0xc079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"),
            new CipherSuite(0xc07a, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc07b, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc07c, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc07d, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc07e, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc07f, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc08a, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc08b, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc08c, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc08d, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc08e, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc08f, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"),
            new CipherSuite(0xc093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"),
            new CipherSuite(0xc094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0xc095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"),
            new CipherSuite(0xc096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0xc097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"),
            new CipherSuite(0xc098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0xc099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"),
            new CipherSuite(0xc09a, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"),
            new CipherSuite(0xc09b, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"),
            new CipherSuite(0xc09c, "TLS_RSA_WITH_AES_128_CCM"),
            new CipherSuite(0xc09d, "TLS_RSA_WITH_AES_256_CCM"),
            new CipherSuite(0xc09e, "TLS_DHE_RSA_WITH_AES_128_CCM"),
            new CipherSuite(0xc09f, "TLS_DHE_RSA_WITH_AES_256_CCM"),
            new CipherSuite(0xc0a0, "TLS_RSA_WITH_AES_128_CCM_8"),
            new CipherSuite(0xc0a1, "TLS_RSA_WITH_AES_256_CCM_8"),
            new CipherSuite(0xc0a2, "TLS_DHE_RSA_WITH_AES_128_CCM_8"),
            new CipherSuite(0xc0a3, "TLS_DHE_RSA_WITH_AES_256_CCM_8"),
            new CipherSuite(0xc0a4, "TLS_PSK_WITH_AES_128_CCM"),
            new CipherSuite(0xc0a5, "TLS_PSK_WITH_AES_256_CCM"),
            new CipherSuite(0xc0a6, "TLS_DHE_PSK_WITH_AES_128_CCM"),
            new CipherSuite(0xc0a7, "TLS_DHE_PSK_WITH_AES_256_CCM"),
            new CipherSuite(0xc0a8, "TLS_PSK_WITH_AES_128_CCM_8"),
            new CipherSuite(0xc0a9, "TLS_PSK_WITH_AES_256_CCM_8"),
            new CipherSuite(0xc0aa, "TLS_PSK_DHE_WITH_AES_128_CCM_8"),
            new CipherSuite(0xc0ab, "TLS_PSK_DHE_WITH_AES_256_CCM_8"),
            new CipherSuite(0xc0ac, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"),
            new CipherSuite(0xc0ad, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"),
            new CipherSuite(0xc0ae, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"),
            new CipherSuite(0xc0af, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"),
            new CipherSuite(0xcc13, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_OLD"),
            new CipherSuite(0xcc14, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_OLD"),
            new CipherSuite(0xcc15, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_OLD"),
            new CipherSuite(0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
            new CipherSuite(0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
            new CipherSuite(0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
            new CipherSuite(0xccab, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"),
            new CipherSuite(0xccac, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
            new CipherSuite(0xccad, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
            new CipherSuite(0xccae, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"),
    };
    private static final Map<Integer, CipherSuite> CODE_TO_CIPHER_SUITE;
    private static final Map<String, CipherSuite> NAME_TO_CIPHER_SUITE;
    static {
        Map<Integer, CipherSuite> byCode = new HashMap<Integer, CipherSuite>();
        Map<String, CipherSuite> byName = new HashMap<String, CipherSuite>();
        for (CipherSuite cipherSuite : CIPHER_SUITES) {
            if (byCode.put(cipherSuite.code, cipherSuite) != null) {
                throw new RuntimeException(
                        "Cipher suite multiply defined: " + Integer.toHexString(cipherSuite.code));
            }
            String name = cipherSuite.name;
            if (byName.put(name, cipherSuite) != null) {
                throw new RuntimeException(
                        "Cipher suite multiply defined: " + cipherSuite.name);
            }
            String androidName = cipherSuite.getAndroidName();
            if (!name.equals(androidName)) {
                if (byName.put(androidName, cipherSuite) != null) {
                    throw new RuntimeException(
                            "Cipher suite multiply defined: " + cipherSuite.androidName);
                }
            }
        }
        CODE_TO_CIPHER_SUITE = byCode;
        NAME_TO_CIPHER_SUITE = byName;
    }
    public final int code;
    public final String name;
    private final String androidName;
    private CipherSuite(int code, String name) {
        this.code = code;
        this.name = name;
        this.androidName = null;
    }
    private CipherSuite(int code, String name, String androidName) {
        this.code = code;
        this.name = name;
        this.androidName = androidName;
    }
    public static CipherSuite valueOf(String name) {
        CipherSuite result = NAME_TO_CIPHER_SUITE.get(name);
        if (result != null) {
            return result;
        }
        throw new IllegalArgumentException("Unknown cipher suite: " + name);
    }
    public static CipherSuite valueOf(int code) {
        CipherSuite result = CODE_TO_CIPHER_SUITE.get(code);
        if (result != null) {
            return result;
        }
        return new CipherSuite(code, Integer.toHexString(code));
    }
    public String getAndroidName() {
        return (androidName != null) ? androidName : name;
    }
    @Override
    public String toString() {
        return name;
    }
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + code;
        return result;
    }
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof CipherSuite)) {
            return false;
        }
        CipherSuite other = (CipherSuite) obj;
        if (code != other.code) {
            return false;
        }
        return true;
    }
}
