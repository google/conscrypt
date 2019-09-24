/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.conscrypt.java.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.PSource.PSpecified;
import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class AlgorithmParametersTestOAEP extends AbstractAlgorithmParametersTest {

    // The ASN.1 encoding for OAEP params (specified in RFC 4055 section 4.1) specifies
    // default values for all parameters, so we need to consider encodings with those
    // values both explicitly specified and unspecified.  When encoding values, it is required
    // that default values are left empty, but implementations must be able to parse explicitly-
    // specified defaults as well.
    //
    // See README.ASN1 for how to understand and reproduce this data.

    // asn1=SEQUENCE
    private static final String ENCODED_DATA_ALL_DEFAULTS = "MAA=";

    // asn1=SEQUENCE:oaep
    // [oaep]
    // hashFunc=EXP:0,SEQUENCE:sha1
    // maskGenFunc=EXP:1,SEQUENCE:mgf1
    // pSourceFunc=EXP:2,SEQUENCE:pSpecified
    // [mgf1]
    // oid=OID:1.2.840.113549.1.1.8
    // params=SEQUENCE:sha1
    // [pSpecified]
    // oid=OID:1.2.840.113549.1.1.9
    // val=OCTETSTRING:
    // [sha1]
    // oid=OID:sha1
    // params=NULL
    private static final String ENCODED_DATA_EXPLICIT_DEFAULTS =
            "MDigCzAJBgUrDgMCGgUAoRgwFgYJKoZIhvcNAQEIMAkGBSsOAwIaBQCiDzANBgkqhkiG9w0BAQkEAA==";

    // Base64 version of ASN.1-encoded data with none of the default values.  Specifically:
    // SHA-256 hashFunc, MGF1-SHA-384 maskGenFunc, and [1, 2, 3, 4] pSourceFunc

    // asn1=SEQUENCE:oaep
    // [oaep]
    // hashFunc=EXP:0,SEQUENCE:sha256
    // maskGenFunc=EXP:1,SEQUENCE:mgf1
    // pSourceFunc=EXP:2,SEQUENCE:pSpecified
    // [sha256]
    // oid=OID:sha256
    // params=NULL
    // [mgf1]
    // oid=OID:1.2.840.113549.1.1.8
    // params=SEQUENCE:sha384
    // [sha384]
    // oid=OID:sha384
    // params=NULL
    // [pSpecified]
    // oid=OID:1.2.840.113549.1.1.9
    // val=FORMAT:HEX,OCTETSTRING:01020304
    private static final String ENCODED_DATA_NON_DEFAULTS = "MESgDzANBglghkgBZQMEAgEFAKEc"
            + "MBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgIFAKITMBEGCSqGSIb3DQEBCQQEAQIDBA==";

    // Base64 version of ASN.1-encoded data with some default and some non-default values.
    // Specifically, SHA-1 hashFunc (default), MGF1-SHA-512 maskGenFunc (non-default),
    // empty pSourceFunc (default)

    // asn1=SEQUENCE:oaep
    // [oaep]
    // maskGenFunc=EXP:1,SEQUENCE:mgf1
    // [mgf1]
    // oid=OID:1.2.840.113549.1.1.8
    // params=SEQUENCE:sha512
    // [sha512]
    // oid=OID:sha512
    // params=NULL
    private static final String ENCODED_DATA_MIXED = "MB6hHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAIDBQA=";

    // Base64 version of the same ASN.1-encoded data as ENCODED_DATA_MIXED, but with the
    // default values explicitly specified.

    // asn1=SEQUENCE:oaep
    // [oaep]
    // hashFunc=EXP:0,SEQUENCE:sha1
    // maskGenFunc=EXP:1,SEQUENCE:mgf1
    // pSourceFunc=EXP:2,SEQUENCE:pSpecified
    // [sha1]
    // oid=OID:sha1
    // params=NULL
    // [mgf1]
    // oid=OID:1.2.840.113549.1.1.8
    // params=SEQUENCE:sha512
    // [pSpecified]
    // oid=OID:1.2.840.113549.1.1.9
    // val=OCTETSTRING:
    // [sha512]
    // oid=OID:sha512
    // params=NULL
    private static final String ENCODED_DATA_MIXED_EXPLICIT_DEFAULTS = "MDygCzAJBgUrDgMCGgUAoRww"
            + "GgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAwUAog8wDQYJKoZIhvcNAQEJBAA=";

    public AlgorithmParametersTestOAEP() {
        super("OAEP", new AlgorithmParameterAsymmetricHelper("RSA/ECB/OAEPPadding"), new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
    }

    @Test
    public void testEncoding() throws Exception {
        ServiceTester.test("AlgorithmParameters")
            .withAlgorithm("OAEP")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    AlgorithmParameters params = AlgorithmParameters.getInstance("OAEP", p);

                    OAEPParameterSpec spec = new OAEPParameterSpec(
                        "SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
                    params.init(spec);
                    if (!p.getName().equals("SunJCE")) {
                        assertEquals(
                            ENCODED_DATA_ALL_DEFAULTS,
                            TestUtils.encodeBase64(params.getEncoded()));
                    } else {
                        // SunJCE encodes the defaults explicitly, which is not allowed by RFC 4055.
                        assertEquals(
                            ENCODED_DATA_EXPLICIT_DEFAULTS,
                            TestUtils.encodeBase64(params.getEncoded()));
                    }

                    params = AlgorithmParameters.getInstance("OAEP", p);
                    spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA384,
                        new PSource.PSpecified(new byte[]{1, 2, 3, 4}));
                    params.init(spec);
                    assertEquals(
                        ENCODED_DATA_NON_DEFAULTS,
                        TestUtils.encodeBase64(params.getEncoded()));

                    params = AlgorithmParameters.getInstance("OAEP", p);
                    spec = new OAEPParameterSpec(
                        "SHA-1", "MGF1", MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT);
                    params.init(spec);
                    if (!p.getName().equals("SunJCE")) {
                        assertEquals(
                            ENCODED_DATA_MIXED,
                            TestUtils.encodeBase64(params.getEncoded()));
                    } else {
                        // SunJCE encodes the defaults explicitly, which is not allowed by RFC 4055.
                        assertEquals(
                            ENCODED_DATA_MIXED_EXPLICIT_DEFAULTS,
                            TestUtils.encodeBase64(params.getEncoded()));
                    }

                    params = AlgorithmParameters.getInstance("OAEP", p);
                    params.init(TestUtils.decodeBase64(ENCODED_DATA_ALL_DEFAULTS));
                    OAEPParameterSpec producedSpec = params
                        .getParameterSpec(OAEPParameterSpec.class);

                    assertEquals( "SHA-1",
                        producedSpec.getDigestAlgorithm());
                    assertEquals( "MGF1",
                        producedSpec.getMGFAlgorithm());
                    assertEquals(
                        MGF1ParameterSpec.SHA1.getDigestAlgorithm(),
                        ((MGF1ParameterSpec) producedSpec.getMGFParameters()).getDigestAlgorithm());
                    assertArrayEquals(PSpecified.DEFAULT.getValue(),
                        ((PSpecified) producedSpec.getPSource()).getValue());

                    params = AlgorithmParameters.getInstance("OAEP", p);
                    params.init(TestUtils.decodeBase64(ENCODED_DATA_EXPLICIT_DEFAULTS));
                    producedSpec = params.getParameterSpec(OAEPParameterSpec.class);

                    assertEquals( "SHA-1",
                        producedSpec.getDigestAlgorithm());
                    assertEquals( "MGF1",
                        producedSpec.getMGFAlgorithm());
                    assertEquals(
                        MGF1ParameterSpec.SHA1.getDigestAlgorithm(),
                        ((MGF1ParameterSpec) producedSpec.getMGFParameters()).getDigestAlgorithm());
                    assertArrayEquals(PSpecified.DEFAULT.getValue(),
                        ((PSpecified) producedSpec.getPSource()).getValue());

                    params = AlgorithmParameters.getInstance("OAEP", p);
                    params.init(TestUtils.decodeBase64(ENCODED_DATA_NON_DEFAULTS));
                    producedSpec = params.getParameterSpec(OAEPParameterSpec.class);

                    assertEquals( "SHA-256",
                        producedSpec.getDigestAlgorithm());
                    assertEquals( "MGF1",
                        producedSpec.getMGFAlgorithm());
                    assertEquals(
                        MGF1ParameterSpec.SHA384.getDigestAlgorithm(),
                        ((MGF1ParameterSpec) producedSpec.getMGFParameters()).getDigestAlgorithm());
                    assertArrayEquals(new byte[]{1, 2, 3, 4},
                        ((PSpecified) producedSpec.getPSource()).getValue());

                    params = AlgorithmParameters.getInstance("OAEP", p);
                    params.init(TestUtils.decodeBase64(ENCODED_DATA_MIXED));
                    producedSpec = params.getParameterSpec(OAEPParameterSpec.class);

                    assertEquals( "SHA-1",
                        producedSpec.getDigestAlgorithm());
                    assertEquals( "MGF1",
                        producedSpec.getMGFAlgorithm());
                    assertEquals(
                        MGF1ParameterSpec.SHA512.getDigestAlgorithm(),
                        ((MGF1ParameterSpec) producedSpec.getMGFParameters()).getDigestAlgorithm());
                    assertArrayEquals(PSpecified.DEFAULT.getValue(),
                        ((PSpecified) producedSpec.getPSource()).getValue());

                    params = AlgorithmParameters.getInstance("OAEP", p);
                    params.init(TestUtils.decodeBase64(ENCODED_DATA_MIXED_EXPLICIT_DEFAULTS));
                    producedSpec = params.getParameterSpec(OAEPParameterSpec.class);

                    assertEquals( "SHA-1",
                        producedSpec.getDigestAlgorithm());
                    assertEquals( "MGF1",
                        producedSpec.getMGFAlgorithm());
                    assertEquals(
                        MGF1ParameterSpec.SHA512.getDigestAlgorithm(),
                        ((MGF1ParameterSpec) producedSpec.getMGFParameters()).getDigestAlgorithm());
                    assertArrayEquals(PSpecified.DEFAULT.getValue(),
                        ((PSpecified) producedSpec.getPSource()).getValue());
                }
            });
    }

}
