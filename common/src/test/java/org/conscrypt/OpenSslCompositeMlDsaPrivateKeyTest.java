/*
 * Copyright (C) 2026 The Android Open Source Project
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

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.spec.InvalidKeySpecException;
import java.util.List;

@RunWith(JUnit4.class)
@SuppressWarnings("InsecureCryptoUsage")
public class OpenSslCompositeMlDsaPrivateKeyTest {
    @Test
    public void constructor_works() throws Exception {
        List<TestVector> vectors = TestUtils.readTestVectors("crypto/composite_mldsa.txt");
        for (TestVector tv : vectors) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            CompositeMlDsaAlgorithm compositeMlDsaAlgorithm =
                    CompositeMlDsaAlgorithm.fromName(algName);
            byte[] rawKey = TestUtils.decodeBase64(tv.getString("sk"));

            OpenSslCompositeMlDsaPrivateKey privateKey =
                    new OpenSslCompositeMlDsaPrivateKey(rawKey, compositeMlDsaAlgorithm);

            assertEquals(algName, privateKey.getAlgorithm());
            assertArrayEquals("getRaw() must match original sk bytes for: " + tv.getString("tcid"),
                              rawKey, privateKey.getRaw());
            assertEquals(compositeMlDsaAlgorithm, privateKey.getCompositeMlDsaAlgorithm());
        }
    }

    @Test
    public void getEncoded_works() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName).startsWith("id-");
            algName = algName.substring(3);
            // Temporarily skip EC keys until we add support for them.
            if (algName.contains("EC")) {
                continue;
            }
            byte[] pkcs8Bytes = TestUtils.decodeBase64(tv.getString("skpkcs8"));
            byte[] rawBytes = TestUtils.decodeBase64(tv.getString("sk"));
            OpenSslCompositeMlDsaPrivateKey privateKey = new OpenSslCompositeMlDsaPrivateKey(
                    rawBytes, CompositeMlDsaAlgorithm.fromName(algName));

            assertEquals("PKCS#8", privateKey.getFormat());
            assertArrayEquals(pkcs8Bytes, privateKey.getEncoded());
        }
    }

    @Test
    public void keyTooShort_throws() throws Exception {
        assertThrows(
                InvalidKeySpecException.class,
                ()
                        -> new OpenSslCompositeMlDsaPrivateKey(
                                TestUtils.decodeHex("dfdfcfcbb4b2312f520007399e6172a434a1a2d86204cf"
                                                    + "1e0586d7925aaac457"
                                                    + "9c939e538ab579ee8e644b903bf92f19516709"),
                                CompositeMlDsaAlgorithm.MLDSA44_ED25519_SHA512));
    }

    @Test
    public void testKeyProperties_ed25519() throws Exception {
        byte[] rawKey = TestUtils.decodeHex(
                "dfdfcfcbb4b2312f520007399e6172a434a1a2d86204cf1e0586d7925aaac457"
                + "9c939e538ab579ee8e644b903bf92f195167099d94fc9705addea8c73cb4454c");

        OpenSslCompositeMlDsaPrivateKey privateKey = new OpenSslCompositeMlDsaPrivateKey(
                rawKey, CompositeMlDsaAlgorithm.MLDSA44_ED25519_SHA512);

        assertArrayEquals(rawKey, privateKey.getRaw());
        assertEquals("MLDSA44-Ed25519-SHA512", privateKey.getAlgorithm());
        assertEquals(CompositeMlDsaAlgorithm.MLDSA44_ED25519_SHA512,
                     privateKey.getCompositeMlDsaAlgorithm());
        // Verify ML-DSA private key.
        assertArrayEquals(
                TestUtils.decodeHex(
                        "dfdfcfcbb4b2312f520007399e6172a434a1a2d86204cf1e0586d7925aaac457"),
                privateKey.getMlDsaPrivateKey().getSeed());
        // Verify Classic private key.
        assertThat(privateKey.getClassicPrivateKey()).isInstanceOf(OpenSslEdDsaPrivateKey.class);
        OpenSslEdDsaPrivateKey classicKey =
                (OpenSslEdDsaPrivateKey) privateKey.getClassicPrivateKey();
        assertArrayEquals(
                TestUtils.decodeHex(
                        "9c939e538ab579ee8e644b903bf92f195167099d94fc9705addea8c73cb4454c"),
                classicKey.getRaw());
    }
}
