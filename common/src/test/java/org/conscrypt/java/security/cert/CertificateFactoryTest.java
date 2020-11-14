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

package org.conscrypt.java.security.cert;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;
import java.util.TimeZone;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.conscrypt.Conscrypt;
import org.conscrypt.TestUtils;
import org.conscrypt.java.security.StandardNames;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class CertificateFactoryTest {

    private static final String VALID_CERTIFICATE_PEM =
            "-----BEGIN CERTIFICATE-----\n"
            + "MIIDITCCAoqgAwIBAgIQL9+89q6RUm0PmqPfQDQ+mjANBgkqhkiG9w0BAQUFADBM\n"
            + "MQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkg\n"
            + "THRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0wOTEyMTgwMDAwMDBaFw0x\n"
            + "MTEyMTgyMzU5NTlaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh\n"
            + "MRYwFAYDVQQHFA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKFApHb29nbGUgSW5jMRcw\n"
            + "FQYDVQQDFA53d3cuZ29vZ2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC\n"
            + "gYEA6PmGD5D6htffvXImttdEAoN4c9kCKO+IRTn7EOh8rqk41XXGOOsKFQebg+jN\n"
            + "gtXj9xVoRaELGYW84u+E593y17iYwqG7tcFR39SDAqc9BkJb4SLD3muFXxzW2k6L\n"
            + "05vuuWciKh0R73mkszeK9P4Y/bz5RiNQl/Os/CRGK1w7t0UCAwEAAaOB5zCB5DAM\n"
            + "BgNVHRMBAf8EAjAAMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwudGhhd3Rl\n"
            + "LmNvbS9UaGF3dGVTR0NDQS5jcmwwKAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUF\n"
            + "BwMCBglghkgBhvhCBAEwcgYIKwYBBQUHAQEEZjBkMCIGCCsGAQUFBzABhhZodHRw\n"
            + "Oi8vb2NzcC50aGF3dGUuY29tMD4GCCsGAQUFBzAChjJodHRwOi8vd3d3LnRoYXd0\n"
            + "ZS5jb20vcmVwb3NpdG9yeS9UaGF3dGVfU0dDX0NBLmNydDANBgkqhkiG9w0BAQUF\n"
            + "AAOBgQCfQ89bxFApsb/isJr/aiEdLRLDLE5a+RLizrmCUi3nHX4adpaQedEkUjh5\n"
            + "u2ONgJd8IyAPkU0Wueru9G2Jysa9zCRo1kNbzipYvzwY4OA8Ys+WAi0oR1A04Se6\n"
            + "z5nRUP8pJcA2NhUzUnC+MY+f6H/nEQyNv4SgQhqAibAxWEEHXw==\n"
            + "-----END CERTIFICATE-----\n";

    private static final String VALID_CERTIFICATE_PEM_CRLF =
            "-----BEGIN CERTIFICATE-----\r\n"
            + "MIIDITCCAoqgAwIBAgIQL9+89q6RUm0PmqPfQDQ+mjANBgkqhkiG9w0BAQUFADBM\r\n"
            + "MQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkg\r\n"
            + "THRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0wOTEyMTgwMDAwMDBaFw0x\r\n"
            + "MTEyMTgyMzU5NTlaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh\r\n"
            + "MRYwFAYDVQQHFA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKFApHb29nbGUgSW5jMRcw\r\n"
            + "FQYDVQQDFA53d3cuZ29vZ2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC\r\n"
            + "gYEA6PmGD5D6htffvXImttdEAoN4c9kCKO+IRTn7EOh8rqk41XXGOOsKFQebg+jN\r\n"
            + "gtXj9xVoRaELGYW84u+E593y17iYwqG7tcFR39SDAqc9BkJb4SLD3muFXxzW2k6L\r\n"
            + "05vuuWciKh0R73mkszeK9P4Y/bz5RiNQl/Os/CRGK1w7t0UCAwEAAaOB5zCB5DAM\r\n"
            + "BgNVHRMBAf8EAjAAMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwudGhhd3Rl\r\n"
            + "LmNvbS9UaGF3dGVTR0NDQS5jcmwwKAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUF\r\n"
            + "BwMCBglghkgBhvhCBAEwcgYIKwYBBQUHAQEEZjBkMCIGCCsGAQUFBzABhhZodHRw\r\n"
            + "Oi8vb2NzcC50aGF3dGUuY29tMD4GCCsGAQUFBzAChjJodHRwOi8vd3d3LnRoYXd0\r\n"
            + "ZS5jb20vcmVwb3NpdG9yeS9UaGF3dGVfU0dDX0NBLmNydDANBgkqhkiG9w0BAQUF\r\n"
            + "AAOBgQCfQ89bxFApsb/isJr/aiEdLRLDLE5a+RLizrmCUi3nHX4adpaQedEkUjh5\r\n"
            + "u2ONgJd8IyAPkU0Wueru9G2Jysa9zCRo1kNbzipYvzwY4OA8Ys+WAi0oR1A04Se6\r\n"
            + "z5nRUP8pJcA2NhUzUnC+MY+f6H/nEQyNv4SgQhqAibAxWEEHXw==\r\n"
            + "-----END CERTIFICATE-----\r\n";

    private static final byte[] VALID_CERTIFICATE_PEM_HEADER = "-----BEGIN CERTIFICATE-----\n"
            .getBytes(Charset.defaultCharset());

    private static final byte[] VALID_CERTIFICATE_PEM_DATA =
             ("MIIDITCCAoqgAwIBAgIQL9+89q6RUm0PmqPfQDQ+mjANBgkqhkiG9w0BAQUFADBM"
            + "MQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkg"
            + "THRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0wOTEyMTgwMDAwMDBaFw0x"
            + "MTEyMTgyMzU5NTlaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh"
            + "MRYwFAYDVQQHFA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKFApHb29nbGUgSW5jMRcw"
            + "FQYDVQQDFA53d3cuZ29vZ2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC"
            + "gYEA6PmGD5D6htffvXImttdEAoN4c9kCKO+IRTn7EOh8rqk41XXGOOsKFQebg+jN"
            + "gtXj9xVoRaELGYW84u+E593y17iYwqG7tcFR39SDAqc9BkJb4SLD3muFXxzW2k6L"
            + "05vuuWciKh0R73mkszeK9P4Y/bz5RiNQl/Os/CRGK1w7t0UCAwEAAaOB5zCB5DAM"
            + "BgNVHRMBAf8EAjAAMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwudGhhd3Rl"
            + "LmNvbS9UaGF3dGVTR0NDQS5jcmwwKAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUF"
            + "BwMCBglghkgBhvhCBAEwcgYIKwYBBQUHAQEEZjBkMCIGCCsGAQUFBzABhhZodHRw"
            + "Oi8vb2NzcC50aGF3dGUuY29tMD4GCCsGAQUFBzAChjJodHRwOi8vd3d3LnRoYXd0"
            + "ZS5jb20vcmVwb3NpdG9yeS9UaGF3dGVfU0dDX0NBLmNydDANBgkqhkiG9w0BAQUF"
            + "AAOBgQCfQ89bxFApsb/isJr/aiEdLRLDLE5a+RLizrmCUi3nHX4adpaQedEkUjh5"
            + "u2ONgJd8IyAPkU0Wueru9G2Jysa9zCRo1kNbzipYvzwY4OA8Ys+WAi0oR1A04Se6"
            + "z5nRUP8pJcA2NhUzUnC+MY+f6H/nEQyNv4SgQhqAibAxWEEHXw==")
                     .getBytes(Charset.defaultCharset());

    private static final byte[] VALID_CERTIFICATE_PEM_FOOTER = "\n-----END CERTIFICATE-----\n"
            .getBytes(Charset.defaultCharset());

    private static final String INVALID_CERTIFICATE_PEM =
            "-----BEGIN CERTIFICATE-----\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAA\n"
            + "-----END CERTIFICATE-----";

    private static final String VALID_CERTIFICATE_DER_BASE64 =
        "MIIDITCCAoqgAwIBAgIQL9+89q6RUm0PmqPfQDQ+mjANBgkqhkiG9w0BAQUFADBMMQswCQYDVQQG"
        + "EwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkgTHRkLjEWMBQGA1UEAxMNVGhh"
        + "d3RlIFNHQyBDQTAeFw0wOTEyMTgwMDAwMDBaFw0xMTEyMTgyMzU5NTlaMGgxCzAJBgNVBAYTAlVT"
        + "MRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHFA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKFApH"
        + "b29nbGUgSW5jMRcwFQYDVQQDFA53d3cuZ29vZ2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw"
        + "gYkCgYEA6PmGD5D6htffvXImttdEAoN4c9kCKO+IRTn7EOh8rqk41XXGOOsKFQebg+jNgtXj9xVo"
        + "RaELGYW84u+E593y17iYwqG7tcFR39SDAqc9BkJb4SLD3muFXxzW2k6L05vuuWciKh0R73mkszeK"
        + "9P4Y/bz5RiNQl/Os/CRGK1w7t0UCAwEAAaOB5zCB5DAMBgNVHRMBAf8EAjAAMDYGA1UdHwQvMC0w"
        + "K6ApoCeGJWh0dHA6Ly9jcmwudGhhd3RlLmNvbS9UaGF3dGVTR0NDQS5jcmwwKAYDVR0lBCEwHwYI"
        + "KwYBBQUHAwEGCCsGAQUFBwMCBglghkgBhvhCBAEwcgYIKwYBBQUHAQEEZjBkMCIGCCsGAQUFBzAB"
        + "hhZodHRwOi8vb2NzcC50aGF3dGUuY29tMD4GCCsGAQUFBzAChjJodHRwOi8vd3d3LnRoYXd0ZS5j"
        + "b20vcmVwb3NpdG9yeS9UaGF3dGVfU0dDX0NBLmNydDANBgkqhkiG9w0BAQUFAAOBgQCfQ89bxFAp"
        + "sb/isJr/aiEdLRLDLE5a+RLizrmCUi3nHX4adpaQedEkUjh5u2ONgJd8IyAPkU0Wueru9G2Jysa9"
        + "zCRo1kNbzipYvzwY4OA8Ys+WAi0oR1A04Se6z5nRUP8pJcA2NhUzUnC+MY+f6H/nEQyNv4SgQhqA"
        + "ibAxWEEHXw==";

    // Generated with openssl crl2pkcs7 -nocrl -certfile cert.pem
    private static final String VALID_CERTIFICATE_PKCS7_PEM = "-----BEGIN PKCS7-----\n"
            + "MIIDUgYJKoZIhvcNAQcCoIIDQzCCAz8CAQExADALBgkqhkiG9w0BBwGgggMlMIID\n"
            + "ITCCAoqgAwIBAgIQL9+89q6RUm0PmqPfQDQ+mjANBgkqhkiG9w0BAQUFADBMMQsw\n"
            + "CQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkgTHRk\n"
            + "LjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0wOTEyMTgwMDAwMDBaFw0xMTEy\n"
            + "MTgyMzU5NTlaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw\n"
            + "FAYDVQQHFA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKFApHb29nbGUgSW5jMRcwFQYD\n"
            + "VQQDFA53d3cuZ29vZ2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA\n"
            + "6PmGD5D6htffvXImttdEAoN4c9kCKO+IRTn7EOh8rqk41XXGOOsKFQebg+jNgtXj\n"
            + "9xVoRaELGYW84u+E593y17iYwqG7tcFR39SDAqc9BkJb4SLD3muFXxzW2k6L05vu\n"
            + "uWciKh0R73mkszeK9P4Y/bz5RiNQl/Os/CRGK1w7t0UCAwEAAaOB5zCB5DAMBgNV\n"
            + "HRMBAf8EAjAAMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwudGhhd3RlLmNv\n"
            + "bS9UaGF3dGVTR0NDQS5jcmwwKAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUFBwMC\n"
            + "BglghkgBhvhCBAEwcgYIKwYBBQUHAQEEZjBkMCIGCCsGAQUFBzABhhZodHRwOi8v\n"
            + "b2NzcC50aGF3dGUuY29tMD4GCCsGAQUFBzAChjJodHRwOi8vd3d3LnRoYXd0ZS5j\n"
            + "b20vcmVwb3NpdG9yeS9UaGF3dGVfU0dDX0NBLmNydDANBgkqhkiG9w0BAQUFAAOB\n"
            + "gQCfQ89bxFApsb/isJr/aiEdLRLDLE5a+RLizrmCUi3nHX4adpaQedEkUjh5u2ON\n"
            + "gJd8IyAPkU0Wueru9G2Jysa9zCRo1kNbzipYvzwY4OA8Ys+WAi0oR1A04Se6z5nR\n"
            + "UP8pJcA2NhUzUnC+MY+f6H/nEQyNv4SgQhqAibAxWEEHX6EAMQA=\n"
            + "-----END PKCS7-----\n";

    private static final String VALID_CERTIFICATE_PKCS7_DER_BASE64 =
            "MIIDUgYJKoZIhvcNAQcCoIIDQzCCAz8CAQExADALBgkqhkiG9w0BBwGgggMlMIID"
            + "ITCCAoqgAwIBAgIQL9+89q6RUm0PmqPfQDQ+mjANBgkqhkiG9w0BAQUFADBMMQsw"
            + "CQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkgTHRk"
            + "LjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0wOTEyMTgwMDAwMDBaFw0xMTEy"
            + "MTgyMzU5NTlaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw"
            + "FAYDVQQHFA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKFApHb29nbGUgSW5jMRcwFQYD"
            + "VQQDFA53d3cuZ29vZ2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA"
            + "6PmGD5D6htffvXImttdEAoN4c9kCKO+IRTn7EOh8rqk41XXGOOsKFQebg+jNgtXj"
            + "9xVoRaELGYW84u+E593y17iYwqG7tcFR39SDAqc9BkJb4SLD3muFXxzW2k6L05vu"
            + "uWciKh0R73mkszeK9P4Y/bz5RiNQl/Os/CRGK1w7t0UCAwEAAaOB5zCB5DAMBgNV"
            + "HRMBAf8EAjAAMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwudGhhd3RlLmNv"
            + "bS9UaGF3dGVTR0NDQS5jcmwwKAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUFBwMC"
            + "BglghkgBhvhCBAEwcgYIKwYBBQUHAQEEZjBkMCIGCCsGAQUFBzABhhZodHRwOi8v"
            + "b2NzcC50aGF3dGUuY29tMD4GCCsGAQUFBzAChjJodHRwOi8vd3d3LnRoYXd0ZS5j"
            + "b20vcmVwb3NpdG9yeS9UaGF3dGVfU0dDX0NBLmNydDANBgkqhkiG9w0BAQUFAAOB"
            + "gQCfQ89bxFApsb/isJr/aiEdLRLDLE5a+RLizrmCUi3nHX4adpaQedEkUjh5u2ON"
            + "gJd8IyAPkU0Wueru9G2Jysa9zCRo1kNbzipYvzwY4OA8Ys+WAi0oR1A04Se6z5nR"
            + "UP8pJcA2NhUzUnC+MY+f6H/nEQyNv4SgQhqAibAxWEEHX6EAMQA=";

    private static final String VALID_CRL_PEM =
        "-----BEGIN X509 CRL-----\n"
            + "MIIBUTCBuwIBATANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJHQjEkMCIGA1UE\n"
            + "ChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVXYWxlczEQ\n"
            + "MA4GA1UEBxMHRXJ3IFdlbhcNMTkwODA3MTAyNzEwWhcNMTkwOTA2MTAyNzEwWjAi\n"
            + "MCACAQcXDTE5MDgwNzEwMjY1NFowDDAKBgNVHRUEAwoBAaAOMAwwCgYDVR0UBAMC\n"
            + "AQIwDQYJKoZIhvcNAQELBQADgYEAzF/DLiIvZDX4FpSjNCnwKRblnhJLZ1NNBAHx\n"
            + "cRbfFY3psobvbGGOjxzCQW/03gkngG5VrSfdVOLMmQDrAxpKqeYqFDj0HAenWugb\n"
            + "CCHWAw8WN9XSJ4nGxdRiacG/5vEIx00ICUGCeGcnqWsSnFtagDtvry2c4MMexbSP\n"
            + "nDN0LLg=\n"
            + "-----END X509 CRL-----\n";

    private static final String VALID_CRL_PEM_CRLF =
        "-----BEGIN X509 CRL-----\r\n"
            + "MIIBUTCBuwIBATANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJHQjEkMCIGA1UE\r\n"
            + "ChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVXYWxlczEQ\r\n"
            + "MA4GA1UEBxMHRXJ3IFdlbhcNMTkwODA3MTAyNzEwWhcNMTkwOTA2MTAyNzEwWjAi\r\n"
            + "MCACAQcXDTE5MDgwNzEwMjY1NFowDDAKBgNVHRUEAwoBAaAOMAwwCgYDVR0UBAMC\r\n"
            + "AQIwDQYJKoZIhvcNAQELBQADgYEAzF/DLiIvZDX4FpSjNCnwKRblnhJLZ1NNBAHx\r\n"
            + "cRbfFY3psobvbGGOjxzCQW/03gkngG5VrSfdVOLMmQDrAxpKqeYqFDj0HAenWugb\r\n"
            + "CCHWAw8WN9XSJ4nGxdRiacG/5vEIx00ICUGCeGcnqWsSnFtagDtvry2c4MMexbSP\r\n"
            + "nDN0LLg=\r\n"
            + "-----END X509 CRL-----\r\n";

    private static final String VALID_CRL_DER_BASE64 =
        "MIIBUTCBuwIBATANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJHQjEkMCIGA1UE"
            + "ChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVXYWxlczEQ"
            + "MA4GA1UEBxMHRXJ3IFdlbhcNMTkwODA3MTAyNzEwWhcNMTkwOTA2MTAyNzEwWjAi"
            + "MCACAQcXDTE5MDgwNzEwMjY1NFowDDAKBgNVHRUEAwoBAaAOMAwwCgYDVR0UBAMC"
            + "AQIwDQYJKoZIhvcNAQELBQADgYEAzF/DLiIvZDX4FpSjNCnwKRblnhJLZ1NNBAHx"
            + "cRbfFY3psobvbGGOjxzCQW/03gkngG5VrSfdVOLMmQDrAxpKqeYqFDj0HAenWugb"
            + "CCHWAw8WN9XSJ4nGxdRiacG/5vEIx00ICUGCeGcnqWsSnFtagDtvry2c4MMexbSP"
            + "nDN0LLg=";

    // Generated with openssl crl2pkcs7 -in crl.pem
    private static final String VALID_CRL_PKCS7_PEM = "-----BEGIN PKCS7-----\n"
            + "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgAKGCAVUw\n"
            + "ggFRMIG7AgEBMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQK\n"
            + "ExtDZXJ0aWZpY2F0ZSBUcmFuc3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAw\n"
            + "DgYDVQQHEwdFcncgV2VuFw0xOTA4MDcxMDI3MTBaFw0xOTA5MDYxMDI3MTBaMCIw\n"
            + "IAIBBxcNMTkwODA3MTAyNjU0WjAMMAoGA1UdFQQDCgEBoA4wDDAKBgNVHRQEAwIB\n"
            + "AjANBgkqhkiG9w0BAQsFAAOBgQDMX8MuIi9kNfgWlKM0KfApFuWeEktnU00EAfFx\n"
            + "Ft8Vjemyhu9sYY6PHMJBb/TeCSeAblWtJ91U4syZAOsDGkqp5ioUOPQcB6da6BsI\n"
            + "IdYDDxY31dInicbF1GJpwb/m8QjHTQgJQYJ4ZyepaxKcW1qAO2+vLZzgwx7FtI+c\n"
            + "M3QsuDEA\n"
            + "-----END PKCS7-----\n";

    private static final String VALID_CRL_PKCS7_DER_BASE64 =
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgAKGCAVUw"
            + "ggFRMIG7AgEBMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQK"
            + "ExtDZXJ0aWZpY2F0ZSBUcmFuc3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAw"
            + "DgYDVQQHEwdFcncgV2VuFw0xOTA4MDcxMDI3MTBaFw0xOTA5MDYxMDI3MTBaMCIw"
            + "IAIBBxcNMTkwODA3MTAyNjU0WjAMMAoGA1UdFQQDCgEBoA4wDDAKBgNVHRQEAwIB"
            + "AjANBgkqhkiG9w0BAQsFAAOBgQDMX8MuIi9kNfgWlKM0KfApFuWeEktnU00EAfFx"
            + "Ft8Vjemyhu9sYY6PHMJBb/TeCSeAblWtJ91U4syZAOsDGkqp5ioUOPQcB6da6BsI"
            + "IdYDDxY31dInicbF1GJpwb/m8QjHTQgJQYJ4ZyepaxKcW1qAO2+vLZzgwx7FtI+c"
            + "M3QsuDEA";

    private static final String INVALID_CRL_PEM =
        "-----BEGIN X509 CRL-----\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAAAA\n"
            + "-----END X509 CRL-----\n";

    @Test
    public void test_generateCertificate() throws Exception {
        ServiceTester.test("CertificateFactory")
            .withAlgorithm("X509")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    CertificateFactory cf = CertificateFactory.getInstance("X509", p);
                    test_generateCertificate(cf);
                    test_generateCertificate_InputStream_Offset_Correct(cf);
                    test_generateCertificate_InputStream_Empty(cf);
                    test_generateCertificate_InputStream_InvalidStart_Failure(cf);
                    test_generateCertificate_AnyLineLength_Success(cf);
                    test_generateCertificate_PartialInput(cf);

                    test_generateCrl(cf);
                }
            });
    }

    private void test_generateCertificate(CertificateFactory cf) throws Exception {
        Certificate cert;
        {
            byte[] valid = VALID_CERTIFICATE_PEM.getBytes(Charset.defaultCharset());
            Certificate c = cf.generateCertificate(new ByteArrayInputStream(valid));
            assertNotNull(c);
            cert = c;
        }

        {
            byte[] valid = VALID_CERTIFICATE_PEM_CRLF.getBytes(Charset.defaultCharset());
            Certificate c = cf.generateCertificate(new ByteArrayInputStream(valid));
            assertNotNull(c);
            assertEquals(c, cert);
        }

        {
            byte[] valid = TestUtils.decodeBase64(VALID_CERTIFICATE_DER_BASE64);
            Certificate c = cf.generateCertificate(new ByteArrayInputStream(valid));
            assertNotNull(c);
            assertEquals(c, cert);
        }

        // The RI only supports PKCS#7 blobs with generateCertificates, not
        // generateCertificate.
        //
        // TODO(davidben): Also, PEM support for generateCertificate is broken. Remove it?
        if (!StandardNames.IS_RI) {
            byte[] valid = TestUtils.decodeBase64(VALID_CERTIFICATE_PKCS7_DER_BASE64);
            Certificate c = cf.generateCertificate(new ByteArrayInputStream(valid));
            assertNotNull(c);
            assertEquals(c, cert);
        }

        {
            byte[] valid = VALID_CERTIFICATE_PKCS7_PEM.getBytes(Charset.defaultCharset());
            Collection<? extends Certificate> cs = cf.generateCertificates(new ByteArrayInputStream(valid));
            assertEquals(1, cs.size());
            assertEquals(cs.iterator().next(), cert);
        }

        {
            byte[] valid = TestUtils.decodeBase64(VALID_CERTIFICATE_PKCS7_DER_BASE64);
            Collection<? extends Certificate> cs = cf.generateCertificates(new ByteArrayInputStream(valid));
            assertEquals(1, cs.size());
            assertEquals(cs.iterator().next(), cert);
        }

        try {
            byte[] invalid = INVALID_CERTIFICATE_PEM.getBytes(Charset.defaultCharset());
            cf.generateCertificate(new ByteArrayInputStream(invalid));
            fail();
        } catch (CertificateException expected) {
        }

        try {
            Certificate c = cf.generateCertificate(new ByteArrayInputStream(new byte[0]));
            // Bouncy Castle returns null on empty inputs rather than throwing an exception,
            // which technically doesn't satisfy the method contract, but we'll accept it
            assertTrue((c == null) && cf.getProvider().getName().equals("BC"));
        } catch (CertificateException maybeExpected) {
            assertFalse(cf.getProvider().getName().equals("BC"));
        }

        try {
            Certificate c = cf.generateCertificate(new ByteArrayInputStream(new byte[] { 0x00 }));
            // Bouncy Castle returns null on short inputs rather than throwing an exception,
            // which technically doesn't satisfy the method contract, but we'll accept it
            assertTrue((c == null) && cf.getProvider().getName().equals("BC"));
        } catch (CertificateException maybeExpected) {
            assertFalse(cf.getProvider().getName().equals("BC"));
        }

    }

    /*
     * Checks all possible line lengths for PEM input data.
     */
    private void test_generateCertificate_AnyLineLength_Success(CertificateFactory cf)
            throws Exception {
        // RI barfs on this
        if (StandardNames.IS_RI) {
            return;
        }

        int lineLength = 1;
        int maxLineLength = VALID_CERTIFICATE_PEM_DATA.length;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(VALID_CERTIFICATE_PEM_HEADER);
        int offset = 0;
        while (lineLength < (maxLineLength - 4)) {
            int end = offset + lineLength;
            if (end > VALID_CERTIFICATE_PEM_DATA.length) {
                end = VALID_CERTIFICATE_PEM_DATA.length;
            }
            baos.write(Arrays.copyOfRange(VALID_CERTIFICATE_PEM_DATA, offset, end));
            baos.write('\n');
            offset += lineLength;
            if (offset >= maxLineLength) {
                baos.write(VALID_CERTIFICATE_PEM_FOOTER);
                try {
                    Certificate c =
                            cf.generateCertificate(new ByteArrayInputStream(baos.toByteArray()));
                    assertNotNull(c);
                } catch (Exception e) {
                    throw new Exception("Fail at line length " + lineLength, e);
                }
                baos.reset();
                baos.write(VALID_CERTIFICATE_PEM_HEADER);
                offset = 0;
            } else {
                lineLength++;
            }
        }

    }

    private void test_generateCertificate_InputStream_Empty(CertificateFactory cf) throws Exception {
        try {
            Certificate c = cf.generateCertificate(new ByteArrayInputStream(new byte[0]));
            if (!"BC".equals(cf.getProvider().getName())) {
                fail("should throw CertificateException: " + cf.getProvider().getName());
            }
            assertNull(c);
        } catch (CertificateException e) {
            if ("BC".equals(cf.getProvider().getName())) {
                fail("should return null: " + cf.getProvider().getName());
            }
        }
    }

    private void test_generateCertificate_InputStream_InvalidStart_Failure(CertificateFactory cf)
            throws Exception {
        try {
            Certificate c = cf.generateCertificate(new ByteArrayInputStream(
                    "-----BEGIN CERTIFICATE-----".getBytes(Charset.defaultCharset())));
            if (!"BC".equals(cf.getProvider().getName())) {
                fail("should throw CertificateException: " + cf.getProvider().getName());
            }
            assertNull(c);
        } catch (CertificateException expected) {
            if ("BC".equals(cf.getProvider().getName())) {
                fail("should return null: " + cf.getProvider().getName());
            }
        }
    }

    private void test_generateCertificate_InputStream_Offset_Correct(CertificateFactory cf)
            throws Exception {
        byte[] valid = VALID_CERTIFICATE_PEM.getBytes(Charset.defaultCharset());

        byte[] doubleCertificateData = new byte[valid.length * 2];
        System.arraycopy(valid, 0, doubleCertificateData, 0, valid.length);
        System.arraycopy(valid, 0, doubleCertificateData, valid.length, valid.length);
        MeasuredInputStream certStream = new MeasuredInputStream(new ByteArrayInputStream(
                doubleCertificateData));
        Certificate certificate = cf.generateCertificate(certStream);
        assertNotNull(certificate);
        assertEquals(valid.length, certStream.getCount());
    }

    /**
     * Proxy that counts the number of bytes read from an InputStream.
     */
    private static class MeasuredInputStream extends InputStream {
        private long mCount = 0;

        private long mMarked = 0;

        private InputStream mStream;

        public MeasuredInputStream(InputStream is) {
            mStream = is;
        }

        public long getCount() {
            return mCount;
        }

        @Override
        public int read() throws IOException {
            int nextByte = mStream.read();
            mCount++;
            return nextByte;
        }

        @Override
        public int read(byte[] buffer) throws IOException {
            int count = mStream.read(buffer);
            mCount += count;
            return count;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            int count = mStream.read(buffer, offset, length);
            mCount += count;
            return count;
        }

        @Override
        public long skip(long byteCount) throws IOException {
            long count = mStream.skip(byteCount);
            mCount += count;
            return count;
        }

        @Override
        public int available() throws IOException {
            return mStream.available();
        }

        @Override
        public void close() throws IOException {
            mStream.close();
        }

        @Override
        public void mark(int readlimit) {
            mMarked = mCount;
            mStream.mark(readlimit);
        }

        @Override
        public boolean markSupported() {
            return mStream.markSupported();
        }

        @Override
        public synchronized void reset() throws IOException {
            mCount = mMarked;
            mStream.reset();
        }
    }

    /**
     * An InputStream that only returns two bytes at a time, no matter how many were requested.
     */
    private static class SlowInputStream extends FilterInputStream {
        protected SlowInputStream(InputStream inputStream) {
            super(inputStream);
        }

        @Override
        public int read(byte[] buffer) throws IOException {
            if (buffer.length < 2) {
                return super.read(buffer);
            }
            return super.read(buffer, 0, 2);
        }

        @Override
        public int read(byte[] buffer, int offset, int len) throws IOException {
            if (len < 2) {
                return super.read(buffer, offset, len);
            }
            return super.read(buffer, offset, 2);
        }
    }

    // Test that certificates are decoded properly even if the InputStream is unhelpful and only
    // returns partial inputs on basically every request.
    private void test_generateCertificate_PartialInput(CertificateFactory cf) throws Exception {
        byte[] valid = VALID_CERTIFICATE_PEM.getBytes(Charset.defaultCharset());
        Certificate c = cf.generateCertificate(new SlowInputStream(new ByteArrayInputStream(valid)));
        assertNotNull(c);

        valid = TestUtils.decodeBase64(VALID_CERTIFICATE_DER_BASE64);
        c = cf.generateCertificate(new SlowInputStream(new ByteArrayInputStream(valid)));
        assertNotNull(c);
    }

    /* CertPath tests */
    @Test
    public void testGenerateCertPath() throws Exception {
        KeyHolder ca = generateCertificate(true, null);
        KeyHolder cert1 = generateCertificate(true, ca);
        KeyHolder cert2 = generateCertificate(false, cert1);
        KeyHolder cert3 = generateCertificate(false, cert2);

        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(cert3.certificate);
        certs.add(cert2.certificate);
        certs.add(cert1.certificate);

        List<X509Certificate> duplicatedCerts = new ArrayList<X509Certificate>(certs);
        duplicatedCerts.add(cert2.certificate);

        Provider[] providers = Security.getProviders("CertificateFactory.X509");
        for (Provider p : providers) {
            final CertificateFactory cf = CertificateFactory.getInstance("X.509", p);

            if (Conscrypt.isConscrypt(p)) {
                // It's not specified whether duplicated certs should work, but we want Conscrypt
                // to accept them
                {
                    final CertPath duplicatedPath = cf.generateCertPath(duplicatedCerts);
                    // This shouldn't cause an exception
                    duplicatedPath.getEncoded();
                }
            }

            testCertPathEncoding(cf, certs, null);

            /* Make sure all encoding entries are the same. */
            final Iterator<String> it1 = cf.getCertPathEncodings();
            final Iterator<String> it2 = cf.generateCertPath(certs).getEncodings();
            for (;;) {
                assertEquals(p.getName(), it1.hasNext(), it2.hasNext());
                if (!it1.hasNext()) {
                    break;
                }

                String encoding = it1.next();
                assertEquals(p.getName(), encoding, it2.next());

                try {
                    it1.remove();
                    fail("Should not be able to remove from iterator");
                } catch (UnsupportedOperationException expected) {
                }

                try {
                    it2.remove();
                    fail("Should not be able to remove from iterator");
                } catch (UnsupportedOperationException expected) {
                }

                /* Now test using this encoding. */
                testCertPathEncoding(cf, certs, encoding);
            }
        }
    }

    private void testCertPathEncoding(CertificateFactory cf, List<X509Certificate> expectedCerts,
            String encoding) throws Exception {
        final String providerName = cf.getProvider().getName() + "[" + encoding + "]";

        final CertPath pathFromList = cf.generateCertPath(expectedCerts);

        // Create a copy we can modify and discard.
        final byte[] encodedCopy;
        if (encoding == null) {
            encodedCopy = pathFromList.getEncoded();
            assertNotNull(providerName, encodedCopy);

            // check idempotence
            assertEquals(providerName, Arrays.toString(pathFromList.getEncoded()),
                    Arrays.toString(encodedCopy));
        } else {
            encodedCopy = pathFromList.getEncoded(encoding);
            assertNotNull(providerName, encodedCopy);

            // check idempotence
            assertEquals(providerName, Arrays.toString(pathFromList.getEncoded(encoding)),
                    Arrays.toString(encodedCopy));
        }

        // Try to modify byte array.
        encodedCopy[0] ^= (byte) 0xFF;

        // Get a real copy we will use if the test proceeds.
        final byte[] encoded;
        if (encoding == null) {
            encoded = pathFromList.getEncoded();
            assertNotNull(providerName, encodedCopy);

            // check idempotence
            assertEquals(providerName, Arrays.toString(pathFromList.getEncoded()),
                    Arrays.toString(encoded));
        } else {
            encoded = pathFromList.getEncoded(encoding);
            assertNotNull(providerName, encodedCopy);

            // check idempotence
            assertEquals(providerName, Arrays.toString(pathFromList.getEncoded(encoding)),
                    Arrays.toString(encoded));
        }
        assertFalse(providerName, Arrays.toString(encoded).equals(Arrays.toString(encodedCopy)));

        encodedCopy[0] ^= (byte) 0xFF;
        assertEquals(providerName, Arrays.toString(encoded), Arrays.toString(encodedCopy));

        final CertPath actualPath;
        if (encoding == null) {
            actualPath = cf.generateCertPath(new ByteArrayInputStream(encoded));
        } else {
            actualPath = cf.generateCertPath(new ByteArrayInputStream(encoded), encoding);
        }

        // PKCS7 certificate bags are not guaranteed to be in order.
        final List<? extends Certificate> actualCerts;
        if (!"PKCS7".equals(encoding)) {
            actualCerts = actualPath.getCertificates();
            assertEquals(providerName, expectedCerts, actualCerts);
        } else {
            actualCerts = pathFromList.getCertificates();
        }

        try {
            actualCerts.remove(0);
            fail("List of certificate should be immutable");
        } catch (UnsupportedOperationException expected) {
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(actualPath);
        oos.close();

        byte[] serialized = baos.toByteArray();
        ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
        ObjectInputStream ois = new ObjectInputStream(bais);
        Object output = ois.readObject();
        assertTrue(providerName, output instanceof CertPath);

        assertEquals(providerName, actualPath, (CertPath) output);
    }

    public static class KeyHolder {
        public X509Certificate certificate;

        public PrivateKey privateKey;
    }

    @SuppressWarnings("deprecation")
    private static KeyHolder generateCertificate(boolean isCa, KeyHolder issuer) throws Exception {
        Date startDate = new Date();

        GregorianCalendar cal = new GregorianCalendar();
        cal.setTimeZone(TimeZone.getTimeZone("UTC"));
        cal.set(2100, 0, 1, 0, 0, 0); // Jan 1, 2100 UTC
        Date expiryDate = cal.getTime();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = kpg.generateKeyPair();

        BigInteger serial;
        X500Principal issuerPrincipal;
        X500Principal subjectPrincipal;
        PrivateKey caKey;
        if (issuer != null) {
            serial = issuer.certificate.getSerialNumber().add(BigInteger.ONE);
            subjectPrincipal = new X500Principal("CN=Test Certificate Serial #" + serial.toString());
            issuerPrincipal = issuer.certificate.getSubjectX500Principal();
            caKey = issuer.privateKey;
        } else {
            serial = BigInteger.ONE;
            subjectPrincipal = new X500Principal("CN=Test CA, O=Tests, C=US");
            issuerPrincipal = subjectPrincipal;
            caKey = keyPair.getPrivate();
        }

        BasicConstraints basicConstraints;
        if (isCa) {
            basicConstraints = new BasicConstraints(10 - serial.intValue());
        } else {
            basicConstraints = new BasicConstraints(false);
        }

        org.bouncycastle.x509.X509V3CertificateGenerator certGen =
                new org.bouncycastle.x509.X509V3CertificateGenerator();

        PublicKey pubKey = keyPair.getPublic();
        certGen.setSerialNumber(serial);
        certGen.setIssuerDN(issuerPrincipal);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setSubjectDN(subjectPrincipal);
        certGen.setPublicKey(pubKey);
        certGen.setSignatureAlgorithm("SHA1withRSA");

        if (issuer != null) {
            certGen.addExtension(Extension.authorityKeyIdentifier, false,
                    new org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure(
                            issuer.certificate));
        } else {
            certGen.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(generatePublicKeyDigest(pubKey)));
        }

        certGen.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(generatePublicKeyDigest(pubKey)));
        certGen.addExtension(Extension.basicConstraints, true, basicConstraints);

        X509Certificate cert = certGen.generate(caKey);

        KeyHolder holder = new KeyHolder();
        holder.certificate = cert;
        holder.privateKey = keyPair.getPrivate();

        return holder;
    }

    /**
     * Generates a type 1 key identifier according to RFC 3280 4.2.1.2.
     */
    private static byte[] generatePublicKeyDigest(PublicKey pubKey) {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());
        MessageDigest sha1digest;
        try {
            sha1digest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 not available");
        }
        return sha1digest.digest(spki.getPublicKeyData().getBytes());
    }

    private void test_generateCrl(CertificateFactory cf) throws Exception {
        byte[] valid = VALID_CRL_PEM.getBytes(Charset.defaultCharset());
        CRL c = cf.generateCRL(new ByteArrayInputStream(valid));
        assertNotNull(c);

        valid = VALID_CRL_PEM_CRLF.getBytes(Charset.defaultCharset());
        CRL c2 = cf.generateCRL(new ByteArrayInputStream(valid));
        assertNotNull(c2);
        assertEquals(c, c2);

        valid = TestUtils.decodeBase64(VALID_CRL_DER_BASE64);
        c2 = cf.generateCRL(new ByteArrayInputStream(valid));
        assertNotNull(c);
        assertEquals(c, c2);

        // The RI only supports PKCS#7 with generateCRLs, not generateCRL.
        //
        // TODO(davidben): Also, PEM support for generateCRL is broken. Remove it?
        if (!StandardNames.IS_RI) {
            valid = TestUtils.decodeBase64(VALID_CRL_PKCS7_DER_BASE64);
            c2 = cf.generateCRL(new ByteArrayInputStream(valid));
            assertNotNull(c);
            assertEquals(c, c2);
        }

        valid = TestUtils.decodeBase64(VALID_CRL_PKCS7_DER_BASE64);
        Collection<? extends CRL> crls = cf.generateCRLs(new ByteArrayInputStream(valid));
        assertEquals(1, crls.size());
        assertEquals(c, crls.iterator().next());

        valid = VALID_CRL_PKCS7_PEM.getBytes(Charset.defaultCharset());
        crls = cf.generateCRLs(new ByteArrayInputStream(valid));
        assertEquals(1, crls.size());
        assertEquals(c, crls.iterator().next());

        try {
            byte[] invalid = INVALID_CRL_PEM.getBytes(Charset.defaultCharset());
            cf.generateCRL(new ByteArrayInputStream(invalid));
            fail();
        } catch (CRLException expected) {
        }

        try {
            c = cf.generateCRL(new ByteArrayInputStream(new byte[0]));
            // Bouncy Castle returns null on empty inputs rather than throwing an exception,
            // which technically doesn't satisfy the method contract, but we'll accept it
            assertTrue((c == null) && cf.getProvider().getName().equals("BC"));
        } catch (CRLException maybeExpected) {
            assertFalse(cf.getProvider().getName().equals("BC"));
        }

        try {
            c = cf.generateCRL(new ByteArrayInputStream(new byte[] { 0x00 }));
            // Bouncy Castle returns null on short inputs rather than throwing an exception,
            // which technically doesn't satisfy the method contract, but we'll accept it
            assertTrue((c == null) && cf.getProvider().getName().equals("BC"));
        } catch (CRLException maybeExpected) {
            assertFalse(cf.getProvider().getName().equals("BC"));
        }

    }
}
