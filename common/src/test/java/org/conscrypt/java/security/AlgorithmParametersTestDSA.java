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

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.spec.DSAParameterSpec;
import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class AlgorithmParametersTestDSA extends AbstractAlgorithmParametersTest {

    /*
     * Parameters generated with OpenSSL:
     * openssl dsaparam -genkey 1024 -C
     */
    private static final byte[] P = new byte[] {
            (byte) 0xE6, (byte) 0x41, (byte) 0x58, (byte) 0x77, (byte) 0x76,
            (byte) 0x5A, (byte) 0x4A, (byte) 0x53, (byte) 0xF1, (byte) 0xD6,
            (byte) 0xC8, (byte) 0x7D, (byte) 0x67, (byte) 0x1F, (byte) 0x2F,
            (byte) 0xFA, (byte) 0xDE, (byte) 0xB7, (byte) 0xAA, (byte) 0xCD,
            (byte) 0xD7, (byte) 0x5D, (byte) 0xD0, (byte) 0xE9, (byte) 0xB1,
            (byte) 0xDA, (byte) 0xFE, (byte) 0x42, (byte) 0xBE, (byte) 0xCC,
            (byte) 0x42, (byte) 0x52, (byte) 0x2E, (byte) 0x01, (byte) 0xD2,
            (byte) 0x16, (byte) 0xB1, (byte) 0x5B, (byte) 0xC4, (byte) 0x42,
            (byte) 0xF9, (byte) 0x55, (byte) 0x0F, (byte) 0xE2, (byte) 0xD5,
            (byte) 0x01, (byte) 0xD2, (byte) 0x7E, (byte) 0x22, (byte) 0xF6,
            (byte) 0xC1, (byte) 0xFE, (byte) 0x5C, (byte) 0x6A, (byte) 0xCF,
            (byte) 0x82, (byte) 0x1B, (byte) 0x5C, (byte) 0x46, (byte) 0x66,
            (byte) 0x8B, (byte) 0xAF, (byte) 0xDF, (byte) 0x44, (byte) 0xE2,
            (byte) 0x0E, (byte) 0xA3, (byte) 0x58, (byte) 0xF7, (byte) 0xA3,
            (byte) 0x24, (byte) 0xE3, (byte) 0x84, (byte) 0xA6, (byte) 0x16,
            (byte) 0xE0, (byte) 0xCA, (byte) 0x72, (byte) 0x55, (byte) 0x07,
            (byte) 0xA0, (byte) 0x99, (byte) 0x7B, (byte) 0xF8, (byte) 0xB1,
            (byte) 0x5A, (byte) 0x84, (byte) 0x36, (byte) 0x5A, (byte) 0xC8,
            (byte) 0x6A, (byte) 0xFE, (byte) 0xA6, (byte) 0xB4, (byte) 0x1B,
            (byte) 0x3A, (byte) 0x0A, (byte) 0x00, (byte) 0x6B, (byte) 0x72,
            (byte) 0xDC, (byte) 0x0C, (byte) 0xD1, (byte) 0x09, (byte) 0x25,
            (byte) 0x11, (byte) 0x68, (byte) 0x6B, (byte) 0x75, (byte) 0xDE,
            (byte) 0x2C, (byte) 0x1A, (byte) 0xC2, (byte) 0x3A, (byte) 0xCB,
            (byte) 0xA0, (byte) 0x17, (byte) 0xCA, (byte) 0x2D, (byte) 0xEE,
            (byte) 0xA2, (byte) 0x5A, (byte) 0x9D, (byte) 0x1F, (byte) 0x33,
            (byte) 0x1B, (byte) 0x07, (byte) 0x6D,
    };
    private static final byte[] Q = new byte[] {
            (byte) 0x9B, (byte) 0x39, (byte) 0xD0, (byte) 0x02, (byte) 0x0F,
            (byte) 0xE9, (byte) 0x96, (byte) 0x16, (byte) 0xC5, (byte) 0x25,
            (byte) 0xF7, (byte) 0x94, (byte) 0xA9, (byte) 0x2C, (byte) 0xD0,
            (byte) 0x25, (byte) 0x5B, (byte) 0x6E, (byte) 0xE0, (byte) 0x8F,
    };
    private static final byte[] G = new byte[] {
            (byte) 0x5E, (byte) 0x9C, (byte) 0x95, (byte) 0x5F, (byte) 0x7E,
            (byte) 0x91, (byte) 0x47, (byte) 0x4D, (byte) 0x68, (byte) 0xA4,
            (byte) 0x1C, (byte) 0x44, (byte) 0x3B, (byte) 0xEC, (byte) 0x0A,
            (byte) 0x7E, (byte) 0x59, (byte) 0x54, (byte) 0xF7, (byte) 0xEF,
            (byte) 0x42, (byte) 0xFB, (byte) 0x63, (byte) 0x95, (byte) 0x08,
            (byte) 0x2F, (byte) 0x4A, (byte) 0xD3, (byte) 0xBC, (byte) 0x79,
            (byte) 0x9D, (byte) 0xBA, (byte) 0xD8, (byte) 0x8A, (byte) 0x83,
            (byte) 0x84, (byte) 0xAE, (byte) 0x5B, (byte) 0x26, (byte) 0x80,
            (byte) 0xB3, (byte) 0xFB, (byte) 0x9C, (byte) 0xA3, (byte) 0xCF,
            (byte) 0xF4, (byte) 0x0A, (byte) 0xD5, (byte) 0xB6, (byte) 0x65,
            (byte) 0x65, (byte) 0x1A, (byte) 0x4F, (byte) 0xC0, (byte) 0x86,
            (byte) 0x3B, (byte) 0xE6, (byte) 0xFB, (byte) 0x4E, (byte) 0x9E,
            (byte) 0x49, (byte) 0x0A, (byte) 0x8C, (byte) 0x77, (byte) 0x2D,
            (byte) 0x93, (byte) 0x0B, (byte) 0xCA, (byte) 0x81, (byte) 0x07,
            (byte) 0x09, (byte) 0xC4, (byte) 0x71, (byte) 0xFD, (byte) 0xC8,
            (byte) 0xC7, (byte) 0xD1, (byte) 0xA3, (byte) 0xD0, (byte) 0xBB,
            (byte) 0x7D, (byte) 0x92, (byte) 0x74, (byte) 0x8B, (byte) 0x3B,
            (byte) 0x2A, (byte) 0x45, (byte) 0x1F, (byte) 0x5D, (byte) 0x85,
            (byte) 0x90, (byte) 0xE3, (byte) 0xFB, (byte) 0x0E, (byte) 0x16,
            (byte) 0xBA, (byte) 0x8A, (byte) 0xDE, (byte) 0x10, (byte) 0x0F,
            (byte) 0xE0, (byte) 0x0F, (byte) 0x37, (byte) 0xA7, (byte) 0xC1,
            (byte) 0xDC, (byte) 0xBC, (byte) 0x00, (byte) 0xB8, (byte) 0x24,
            (byte) 0x0F, (byte) 0xF6, (byte) 0x5F, (byte) 0xB1, (byte) 0xA8,
            (byte) 0x9A, (byte) 0xDB, (byte) 0x9F, (byte) 0x36, (byte) 0x54,
            (byte) 0x45, (byte) 0xBD, (byte) 0xC0, (byte) 0xE8, (byte) 0x27,
            (byte) 0x82, (byte) 0xC9, (byte) 0x75,
    };

    // The ASN.1 module for DSA is defined in RFC 3279 section 3. See README.ASN1 for how
    // to understand and reproduce this data.

    // asn1=SEQUENCE:dsa
    // [dsa]
    // p=INT:0xE6415877765A4A53F1D6C87D671F2FFADEB7AACDD75DD0E9B1DAFE42BECC42522E01D216B15BC442F9550FE2D501D27E22F6C1FE5C6ACF821B5C46668BAFDF44E20EA358F7A324E384A616E0CA725507A0997BF8B15A84365AC86AFEA6B41B3A0A006B72DC0CD1092511686B75DE2C1AC23ACBA017CA2DEEA25A9D1F331B076D
    // q=INT:0x9B39D0020FE99616C525F794A92CD0255B6EE08F
    // g=INT:0x5E9C955F7E91474D68A41C443BEC0A7E5954F7EF42FB6395082F4AD3BC799DBAD88A8384AE5B2680B3FB9CA3CFF40AD5B665651A4FC0863BE6FB4E9E490A8C772D930BCA810709C471FDC8C7D1A3D0BB7D92748B3B2A451F5D8590E3FB0E16BA8ADE100FE00F37A7C1DCBC00B8240FF65FB1A89ADB9F365445BDC0E82782C975
    private static final String ENCODED_DATA = "MIIBHgKBgQDmQVh3dlpKU/HWyH1nHy/63reqzddd0Omx2v5"
            + "CvsxCUi4B0haxW8RC+VUP4tUB0n4i9sH+XGrPghtcRmaLr99E4g6jWPejJOOEphbgynJVB6CZe/ixWoQ"
            + "2Wshq/qa0GzoKAGty3AzRCSURaGt13iwawjrLoBfKLe6iWp0fMxsHbQIVAJs50AIP6ZYWxSX3lKks0CV"
            + "bbuCPAoGAXpyVX36RR01opBxEO+wKfllU9+9C+2OVCC9K07x5nbrYioOErlsmgLP7nKPP9ArVtmVlGk/"
            + "Ahjvm+06eSQqMdy2TC8qBBwnEcf3Ix9Gj0Lt9knSLOypFH12FkOP7Dha6it4QD+APN6fB3LwAuCQP9l+"
            + "xqJrbnzZURb3A6CeCyXU=";

    public AlgorithmParametersTestDSA() {
        super("DSA", new AlgorithmParameterSignatureHelper<DSAParameterSpec>(
                "DSA", DSAParameterSpec.class), new DSAParameterSpec(
                new BigInteger(1, P), new BigInteger(1, Q), new BigInteger(1, G)));
    }

    @Test
    public void testEncoding() throws Exception {
        ServiceTester.test("AlgorithmParameters")
            .withAlgorithm("DSA")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    AlgorithmParameters params = AlgorithmParameters.getInstance("DSA", p);

                    DSAParameterSpec spec = new DSAParameterSpec(
                            new BigInteger(1, P), new BigInteger(1, Q), new BigInteger(1, G));

                    params.init(spec);
                    assertEquals(ENCODED_DATA, TestUtils.encodeBase64(params.getEncoded()));

                    params = AlgorithmParameters.getInstance("DSA", p);
                    params.init(TestUtils.decodeBase64(ENCODED_DATA));
                    DSAParameterSpec derivedSpec = params.getParameterSpec(DSAParameterSpec.class);

                    assertEquals(new BigInteger(1, P), derivedSpec.getP());
                    assertEquals(new BigInteger(1, Q), derivedSpec.getQ());
                    assertEquals(new BigInteger(1, G), derivedSpec.getG());
                }
            });
    }

}
