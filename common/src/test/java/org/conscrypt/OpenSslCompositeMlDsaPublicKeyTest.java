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

import java.util.Arrays;
import java.util.List;

@RunWith(JUnit4.class)
@SuppressWarnings("InsecureCryptoUsage")
public class OpenSslCompositeMlDsaPublicKeyTest {
    private static final String MLDSA44_ED25519_PK_BASE64 =
            "FlplaQIgVuYEA04nN9VXyMWK4XDhRhnaGaWO6FqoCtiDr5rL89omEFSIf811XxbbHpKBJzROqBqK"
            + "fbPgsrMRZjBdHeRn5Oi4pK7bshdjBkXm7yCqPfMC50PkzKI5CFTsw13ikA4UmJuBupSxXDzhEchH"
            + "LCybpQPBdr++Tr4NKh0cEaDi9GFlDdzLsDP/1d9Dh1N57rHOCPLi/7tjmqPYrCzFspEADbBkKBfw"
            + "NgPRajzMl8FnQB8qQfMzK5tiO6jKEb+fd0C5UhwOYe4NXLazpqGtsV82Z0IC1DrQvHXNvePyHT/h"
            + "OASYQQKM7D8MUSs954UFZPYFqvQrh1JyRl+87cFioQGOjfn3tt2uhYpMqzyRyeaywjwq8tyJC4ZA"
            + "GuTTfDqXr76QdvTB4lKX42llgyIIdBwc4DBjugWYEiVR/PxGmzwyIBSM9PgXPAW+ijfEkyqayX0c"
            + "PQRFaqi6JKxhg0iWADGTssEK8ofZwz4N711co7LRNSqfcRFb+QT9v3aAQS/VZsxyTybLHLpACDsq"
            + "9qDCctewHEKZpVazOFRkTZlTIsp/YBd9avMTFWIgaxRjnuKiaLpMek0Hlx9BdvSQM9b7zFlIMGw1"
            + "1HBBtg/R22UfK+x2zNqSZeS3ZN6fylfum2YAm7IrNzn4car8g64DfQ6AMZHePK4eql5d5n8iShRA"
            + "FTRg8jGv6pkaQBM1OaPcWMba1eDicN5pyCaYgwrhYy2yVN3uTOF4/Z1pxZ8XQ3Dx6zkA79f4P7dN"
            + "hjGdYnlBH1wAnwTdGeP4epk3aF3jR/JJjRx0MxevLEYKN3DrSE580KWTmGEMM9UQcPz9sJ/+VgNk"
            + "gRKGRXhw001q8vAzEhriL8mFnZhBaCNvGTbckPTH4ri3qWHbiDpztzjqKg7/bmZflQ7N7y3eX8wW"
            + "SZ0g0Yh9KDJqwsIc7maoD20LxQRCr2dQZJ8mNOjsr+NonCDPBA4usp9i16WU1bBwRb81p+K6MWra"
            + "x+wG+m2eBn/n/tkXBYYy1r0fBfiTizFQY6bna0HSzXqHkwwmDYc20ZGo77JE4bBlagKFQ12W74bS"
            + "e7HwP28DxtvWKW56Is6lMuqZVkg8GQMW4Iz3hX9SKBe6/tw06PegPDbp/RfFAxzq9vcb5FU9kshM"
            + "dnvTAY6I7OjgVGR8FXN4iZARzU5+BBQa4QblkxDUyiPLSjSSAX3oKkWmu9S9LxmrhsHgd2KOqbZL"
            + "19EoZrx+eQyseaLjDuF569Da6V133Nqej46CPTZNp6ojwNSAjPY2ai1D0hZ8GQpTaeTRRiVcFUps"
            + "4UHRCsUbBSTC5RJLVoGqj0eORAhib4xp7DGlKf7s1j88ZH1OgOw/rIbFMsyKSQsKKmI22Bo3FW2i"
            + "VL/SoPGOKDupMQJvolkieVqK0DjUxsfDLf/VpkrM6fH3FIiw6Dz7vSz3CfUIQ0gDfQi/w08WWCP7"
            + "06VHeDwX1rscAvn2Cc6/q3TbP9bMYoEvS04p5LPGeHtvX/PVyfv9JNqAbrRVmtuTAd1rQhiPNHK5"
            + "JH5feweblxNOsluNH5iJ2tH70R/3LcbL6jiHS9DfoxzHPnX3arWpVF1ZZ4aZivePAOX8B9J7zbxd"
            + "hhdU1eUNFt+sEuGyA6VsTsHf8fZeXpbPwy1OBRMmNiJ3wG+VQC7guTMjnhs7kljuWlhZ1MlsnGro"
            + "X7y51x2l78r3ntwiXkpyfpOBiDezTHPu8kYMNkLaZWeo4bygR04SD75GmjwkYGAXKSvL2XMqT8iC"
            + "O8wQRrKneIeBgmQKojolj5EQlQIYptCzHjq0kVVout5a";

    private static final String MLDSA44_PK_BASE64 =
            "FlplaQIgVuYEA04nN9VXyMWK4XDhRhnaGaWO6FqoCtiDr5rL89omEFSIf811XxbbHpKBJzROqBqK"
            + "fbPgsrMRZjBdHeRn5Oi4pK7bshdjBkXm7yCqPfMC50PkzKI5CFTsw13ikA4UmJuBupSxXDzhEchH"
            + "LCybpQPBdr++Tr4NKh0cEaDi9GFlDdzLsDP/1d9Dh1N57rHOCPLi/7tjmqPYrCzFspEADbBkKBfw"
            + "NgPRajzMl8FnQB8qQfMzK5tiO6jKEb+fd0C5UhwOYe4NXLazpqGtsV82Z0IC1DrQvHXNvePyHT/h"
            + "OASYQQKM7D8MUSs954UFZPYFqvQrh1JyRl+87cFioQGOjfn3tt2uhYpMqzyRyeaywjwq8tyJC4ZA"
            + "GuTTfDqXr76QdvTB4lKX42llgyIIdBwc4DBjugWYEiVR/PxGmzwyIBSM9PgXPAW+ijfEkyqayX0c"
            + "PQRFaqi6JKxhg0iWADGTssEK8ofZwz4N711co7LRNSqfcRFb+QT9v3aAQS/VZsxyTybLHLpACDsq"
            + "9qDCctewHEKZpVazOFRkTZlTIsp/YBd9avMTFWIgaxRjnuKiaLpMek0Hlx9BdvSQM9b7zFlIMGw1"
            + "1HBBtg/R22UfK+x2zNqSZeS3ZN6fylfum2YAm7IrNzn4car8g64DfQ6AMZHePK4eql5d5n8iShRA"
            + "FTRg8jGv6pkaQBM1OaPcWMba1eDicN5pyCaYgwrhYy2yVN3uTOF4/Z1pxZ8XQ3Dx6zkA79f4P7dN"
            + "hjGdYnlBH1wAnwTdGeP4epk3aF3jR/JJjRx0MxevLEYKN3DrSE580KWTmGEMM9UQcPz9sJ/+VgNk"
            + "gRKGRXhw001q8vAzEhriL8mFnZhBaCNvGTbckPTH4ri3qWHbiDpztzjqKg7/bmZflQ7N7y3eX8wW"
            + "SZ0g0Yh9KDJqwsIc7maoD20LxQRCr2dQZJ8mNOjsr+NonCDPBA4usp9i16WU1bBwRb81p+K6MWra"
            + "x+wG+m2eBn/n/tkXBYYy1r0fBfiTizFQY6bna0HSzXqHkwwmDYc20ZGo77JE4bBlagKFQ12W74bS"
            + "e7HwP28DxtvWKW56Is6lMuqZVkg8GQMW4Iz3hX9SKBe6/tw06PegPDbp/RfFAxzq9vcb5FU9kshM"
            + "dnvTAY6I7OjgVGR8FXN4iZARzU5+BBQa4QblkxDUyiPLSjSSAX3oKkWmu9S9LxmrhsHgd2KOqbZL"
            + "19EoZrx+eQyseaLjDuF569Da6V133Nqej46CPTZNp6ojwNSAjPY2ai1D0hZ8GQpTaeTRRiVcFUps"
            + "4UHRCsUbBSTC5RJLVoGqj0eORAhib4xp7DGlKf7s1j88ZH1OgOw/rIbFMsyKSQsKKmI22Bo3FW2i"
            + "VL/SoPGOKDupMQJvolkieVqK0DjUxsfDLf/VpkrM6fH3FIiw6Dz7vSz3CfUIQ0gDfQi/w08WWCP7"
            + "06VHeDwX1rscAvn2Cc6/q3TbP9bMYoEvS04p5LPGeHtvX/PVyfv9JNqAbrRVmtuTAd1rQhiPNHK5"
            + "JH5feweblxNOsluNH5iJ2tH70R/3LcbL6jiHS9DfoxzHPnX3arWpVF1ZZ4aZivePAOX8B9J7zbxd"
            + "hhdU1eUNFt+sEuGyA6VsTsHf8fZeXpbPwy1OBRMmNiJ3wG+VQC7guTMjnhs7kljuWlhZ1MlsnGro"
            + "X7y51x2l78r3ntwiXkpyfpOBiDezTHPu8kYMNkLaZWeo4bygR04SD75GmjwkYGAXKSvL2XMqT8iC"
            + "Ow==";

    private static final String ED25519_PK_BASE64 = "zBBGsqd4h4GCZAqiOiWPkRCVAhim0LMeOrSRVWi63lo=";

    @Test
    public void constructor_works() throws Exception {
        List<TestVector> vectors = TestUtils.readTestVectors("crypto/composite_mldsa.txt");
        for (TestVector tv : vectors) {
            String algName = tv.getString("tcid");
            assertThat(algName.startsWith("id-")).isTrue();
            algName = algName.substring(3);
            CompositeMlDsaAlgorithm compositeMlDsaAlgorithm =
                    CompositeMlDsaAlgorithm.fromName(algName);
            byte[] rawKey = TestUtils.decodeBase64(tv.getString("pk"));

            OpenSslCompositeMlDsaPublicKey publicKey =
                    new OpenSslCompositeMlDsaPublicKey(rawKey, compositeMlDsaAlgorithm);

            assertEquals(algName, publicKey.getAlgorithm());
            assertArrayEquals("getRaw() must match original pk bytes for: " + tv.getString("tcid"),
                              rawKey, publicKey.getRaw());
            assertEquals(compositeMlDsaAlgorithm, publicKey.getCompositeMlDsaAlgorithm());
        }
    }

    @Test
    public void getEncoded_works() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            String algName = tv.getString("tcid");
            assertThat(algName.startsWith("id-")).isTrue();
            algName = algName.substring(3);
            byte[] spkiBytes = TestUtils.decodeBase64(tv.getString("pkx509"));
            byte[] rawBytes = TestUtils.decodeBase64(tv.getString("pk"));
            OpenSslCompositeMlDsaPublicKey publicKey = new OpenSslCompositeMlDsaPublicKey(
                    rawBytes, CompositeMlDsaAlgorithm.fromName(algName));

            assertEquals("X.509", publicKey.getFormat());
            assertArrayEquals(spkiBytes, publicKey.getEncoded());
        }
    }

    @Test
    public void keyShorterThanFullKey_throws() throws Exception {
        assertThrows(
                IllegalArgumentException.class,
                ()
                        -> new OpenSslCompositeMlDsaPublicKey(
                                Arrays.copyOf(TestUtils.decodeBase64(MLDSA44_ED25519_PK_BASE64),
                                              1330),
                                CompositeMlDsaAlgorithm.MLDSA44_ED25519_SHA512));
    }

    @Test
    public void keyShorterThanMlDsaKey_throws() throws Exception {
        assertThrows(IllegalArgumentException.class,
                     ()
                             -> new OpenSslCompositeMlDsaPublicKey(
                                     Arrays.copyOf(
                                             TestUtils.decodeBase64(MLDSA44_ED25519_PK_BASE64), 30),
                                     CompositeMlDsaAlgorithm.MLDSA44_ED25519_SHA512));
    }

    @Test
    public void emptyKey_throws() throws Exception {
        assertThrows(IllegalArgumentException.class,
                     ()
                             -> new OpenSslCompositeMlDsaPublicKey(
                                     new byte[0], CompositeMlDsaAlgorithm.MLDSA44_ED25519_SHA512));
    }

    @Test
    public void testKeyProperties_ed25519() throws Exception {
        byte[] rawKey = TestUtils.decodeBase64(MLDSA44_ED25519_PK_BASE64);
        OpenSslCompositeMlDsaPublicKey publicKey = new OpenSslCompositeMlDsaPublicKey(
                rawKey, CompositeMlDsaAlgorithm.MLDSA44_ED25519_SHA512);

        assertArrayEquals(rawKey, publicKey.getRaw());
        assertEquals("MLDSA44-Ed25519-SHA512", publicKey.getAlgorithm());
        assertEquals(CompositeMlDsaAlgorithm.MLDSA44_ED25519_SHA512,
                     publicKey.getCompositeMlDsaAlgorithm());
        // Verify ML-DSA public key.
        assertArrayEquals(TestUtils.decodeBase64(MLDSA44_PK_BASE64),
                          publicKey.getMlDsaPublicKey().getRaw());
        // Verify Classic public key.
        assertThat(publicKey.getClassicPublicKey()).isInstanceOf(OpenSslEdDsaPublicKey.class);
        OpenSslEdDsaPublicKey classicKey = (OpenSslEdDsaPublicKey) publicKey.getClassicPublicKey();
        assertArrayEquals(TestUtils.decodeBase64(ED25519_PK_BASE64), classicKey.getRaw());
    }
}
