/*
 * Copyright (C) 2019 The Android Open Source Project
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
import static org.junit.Assert.assertTrue;

// android-add: import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
import org.conscrypt.TestUtils;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.List;

import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class AlgorithmParametersTestEC extends AbstractAlgorithmParametersTest {
    // android-add: Allow access to deprecated BC algorithms.

    private static final String CURVE_NAME = "secp384r1";
    private static final String CURVE_OID = "1.3.132.0.34";

    // See README.ASN1 for how to understand and reproduce this data

    // asn1=OID:1.3.132.0.34
    private static final String ENCODED_DATA = "BgUrgQQAIg==";

    public AlgorithmParametersTestEC() {
        super("EC",
              new AlgorithmParameterSignatureHelper<>("SHA256withECDSA", "EC",
                                                      ECGenParameterSpec.class),
              new ECGenParameterSpec(CURVE_NAME));
    }

    @Test
    public void testEncoding() throws Exception {
        ServiceTester.test("AlgorithmParameters").withAlgorithm("EC").run(new ServiceTester.Test() {
            @Override
            public void test(Provider p, String algorithm) throws Exception {
                AlgorithmParameters params = AlgorithmParameters.getInstance("EC", p);
                params.init(new ECGenParameterSpec(CURVE_NAME));
                assertEquals(ENCODED_DATA, TestUtils.encodeBase64(params.getEncoded()));

                params = AlgorithmParameters.getInstance("EC", p);
                params.init(new ECGenParameterSpec(CURVE_OID));
                assertEquals(ENCODED_DATA, TestUtils.encodeBase64(params.getEncoded()));

                params = AlgorithmParameters.getInstance("EC", p);
                params.init(TestUtils.decodeBase64(ENCODED_DATA));
                String name = params.getParameterSpec(ECGenParameterSpec.class).getName();
                assertTrue(CURVE_NAME.equals(name) || CURVE_OID.equals(name));
            }
        });
    }

    // This should be an exhaustive list of all curves that are supported in Conscrypt
    private static final List<String> SUPPORTED_CURVES =
            Arrays.asList("secp224r1", "secp256r1", "secp384r1", "secp521r1", "prime256v1",
                          "1.3.132.0.33", "1.3.132.0.34", "1.3.132.0.35", "1.2.840.10045.3.1.7");

    // A selection of curves that aren't supported
    private static final List<String> UNSUPPORTED_CURVES =
            Arrays.asList("secp192r1", "secp256k1", "prime192v1", "curve25519", "x25519",
                          "1.2.840.10045.3.1.1", "1.3.132.0.10");

    @Test
    public void testCurveSupport() throws Exception {
        AlgorithmParameterSignatureHelper<ECGenParameterSpec> helper =
                new AlgorithmParameterSignatureHelper<>("SHA256withECDSA", "EC",
                                                        ECGenParameterSpec.class);
        for (String curve : SUPPORTED_CURVES) {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curve));
            helper.test(params);
        }
        for (String curve : UNSUPPORTED_CURVES) {
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
                params.init(new ECGenParameterSpec(curve));
            } catch (InvalidParameterSpecException expected) {
            }
        }
    }
}
