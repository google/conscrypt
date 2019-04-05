/*
 * Copyright (C) 2017 The Android Open Source Project
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
import static org.junit.Assert.assertTrue;

import java.security.AlgorithmParameters;
import java.security.Provider;
import javax.crypto.spec.GCMParameterSpec;
import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class AlgorithmParametersTestGCM extends AbstractAlgorithmParametersTest {

    private static final byte[] IV = new byte[] {
        (byte) 0x04, (byte) 0x08, (byte) 0x68, (byte) 0xC8,
        (byte) 0xFF, (byte) 0x64, (byte) 0x72, (byte) 0xF5,
        (byte) 0x04, (byte) 0x08, (byte) 0x68, (byte) 0xC8 };

    private static final int TLEN = 96;
    private static final int SUN_ALT_TLEN = 128;

    // The ASN.1 encoding for GCM params (specified in RFC 5084 section 3.2) specifies
    // a default value of 12 for TLEN, so both values with and without TLEN should work.
    // See README.ASN1 for how to understand and reproduce this data.

    // asn1=SEQUENCE:gcm
    // [gcm]
    // iv=FORMAT:HEX,OCTETSTRING:040868C8FF6472F5040868C8
    private static final String ENCODED_DATA_NO_TLEN = "MA4EDAQIaMj/ZHL1BAhoyA==";

    // asn1=SEQUENCE:gcm
    // [gcm]
    // iv=FORMAT:HEX,OCTETSTRING:040868C8FF6472F5040868C8
    // tlen=INT:12
    private static final String ENCODED_DATA_TLEN = "MBEEDAQIaMj/ZHL1BAhoyAIBDA==";

    public AlgorithmParametersTestGCM() {
        super("GCM", new AlgorithmParameterSymmetricHelper("AES", "GCM/NOPADDING", 128), new GCMParameterSpec(TLEN, IV));
    }

    @Test
    public void testEncoding() throws Exception {
        ServiceTester.test("AlgorithmParameters")
            .withAlgorithm("GCM")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    AlgorithmParameters params = AlgorithmParameters.getInstance("GCM", p);

                    params.init(new GCMParameterSpec(TLEN, IV));
                    String encoded = TestUtils.encodeBase64(params.getEncoded());
                    assertTrue("Encoded: " + encoded,
                        encoded.equals(ENCODED_DATA_TLEN) || encoded.equals(ENCODED_DATA_NO_TLEN));

                    params = AlgorithmParameters.getInstance("GCM", p);
                    params.init(TestUtils.decodeBase64(ENCODED_DATA_NO_TLEN));
                    GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);
                    if (!p.getName().equals("SunJCE")) {
                        assertEquals(TLEN, spec.getTLen());
                    } else {
                        // In some cases the SunJCE provider uses 128 as the default instead of 96
                        assertTrue(spec.getTLen() == TLEN || spec.getTLen() == SUN_ALT_TLEN);
                    }
                    assertArrayEquals(IV, spec.getIV());

                    params = AlgorithmParameters.getInstance("GCM", p);
                    params.init(TestUtils.decodeBase64(ENCODED_DATA_TLEN));
                    spec = params.getParameterSpec(GCMParameterSpec.class);
                    assertEquals(TLEN, spec.getTLen());
                    assertArrayEquals(IV, spec.getIV());
                }
            });
    }

}
