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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import static java.nio.charset.StandardCharsets.UTF_8;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@RunWith(JUnit4.class)
public class CompositeMlDsaTest {
    private static final Provider PROVIDER = TestUtils.getConscryptProvider();

    private static Signature getInstance(CompositeMlDsaAlgorithm alg) throws Exception {
        return Signature.getInstance(alg.getName(), PROVIDER);
    }

    @Test
    public void verifyTestVectors() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            byte[] message = TestUtils.decodeBase64(tv.getString("m"));
            String algName = tv.getString("tcid");
            assertTrue(algName.startsWith("id-"));
            algName = algName.substring(3);

            CompositeMlDsaAlgorithm alg = CompositeMlDsaAlgorithm.fromName(algName);
            Signature signature = getInstance(alg);

            OpenSslCompositeMlDsaPublicKey publicKey = new OpenSslCompositeMlDsaPublicKey(
                    TestUtils.decodeBase64(tv.getString("pk")), alg);
            byte[] sigBytes = TestUtils.decodeBase64(tv.getString("s"));

            signature.initVerify(publicKey);
            signature.update(message, 0, message.length);

            assertTrue("Signature verification failed for algorithm: " + algName
                               + " (tcId: " + tv.getString("tcid") + ")",
                       signature.verify(sigBytes));
        }
    }

    @Test
    public void signVerify_works() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            byte[] message = TestUtils.decodeBase64(tv.getString("m"));
            String algName = tv.getString("tcid");
            assertTrue(algName.startsWith("id-"));
            algName = algName.substring(3);

            CompositeMlDsaAlgorithm alg = CompositeMlDsaAlgorithm.fromName(algName);
            Signature signature = getInstance(alg);
            OpenSslCompositeMlDsaPrivateKey privateKey = new OpenSslCompositeMlDsaPrivateKey(
                    TestUtils.decodeBase64(tv.getString("sk")), alg);
            OpenSslCompositeMlDsaPublicKey publicKey = new OpenSslCompositeMlDsaPublicKey(
                    TestUtils.decodeBase64(tv.getString("pk")), alg);

            signature.initSign(privateKey);
            signature.update(message, 0, message.length);
            byte[] signatureBytes = signature.sign();
            signature.initVerify(publicKey);
            signature.update(message, 0, message.length);

            assertTrue("Signature verification failed for algorithm: " + algName
                               + " (tcId: " + tv.getString("tcid") + ")",
                       signature.verify(signatureBytes));
        }
    }

    private static final String TEST_M =
            "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=";
    private static final String TEST_PK =
            "FlplaQIgVuYEA04nN9VXyMWK4XDhRhnaGaWO6FqoCtiDr5rL89omEFSIf811XxbbHpKBJzROqBqKfbPgsrMRZj"
            + "BdHeRn5Oi4pK7bshdjBkXm7yCqPfMC50PkzKI5CFTsw13ikA4UmJuBupSxXDzhEchHLCybpQPBdr++"
            + "Tr4NKh0cEaDi9GFlDdzLsDP/1d9Dh1N57rHOCPLi/"
            + "7tjmqPYrCzFspEADbBkKBfwNgPRajzMl8FnQB8qQfMzK5tiO6jKEb+"
            + "fd0C5UhwOYe4NXLazpqGtsV82Z0IC1DrQvHXNvePyHT/"
            + "hOASYQQKM7D8MUSs954UFZPYFqvQrh1JyRl+"
            + "87cFioQGOjfn3tt2uhYpMqzyRyeaywjwq8tyJC4ZAGuTTfDqXr76QdvTB4lKX42llgyIIdBwc4DBjugWYEiV"
            + "R/"
            + "PxGmzwyIBSM9PgXPAW+ijfEkyqayX0cPQRFaqi6JKxhg0iWADGTssEK8ofZwz4N711co7LRNSqfcRFb+"
            + "QT9v3aAQS/VZsxyTybLHLpACDsq9qDCctewHEKZpVazOFRkTZlTIsp/"
            + "YBd9avMTFWIgaxRjnuKiaLpMek0Hlx9BdvSQM9b7zFlIMGw11HBBtg/"
            + "R22UfK+"
            + "x2zNqSZeS3ZN6fylfum2YAm7IrNzn4car8g64DfQ6AMZHePK4eql5d5n8iShRAFTRg8jGv6pkaQBM1OaPcWM"
            + "ba1eDicN5pyCaYgwrhYy2yVN3uTOF4/Z1pxZ8XQ3Dx6zkA79f4P7dNhjGdYnlBH1wAnwTdGeP4epk3aF3jR/"
            + "JJjRx0MxevLEYKN3DrSE580KWTmGEMM9UQcPz9sJ/"
            + "+VgNkgRKGRXhw001q8vAzEhriL8mFnZhBaCNvGTbckPTH4ri3qWHbiDpztzjqKg7/"
            + "bmZflQ7N7y3eX8wWSZ0g0Yh9KDJqwsIc7maoD20LxQRCr2dQZJ8mNOjsr+"
            + "NonCDPBA4usp9i16WU1bBwRb81p+K6MWrax+wG+m2eBn/n/"
            + "tkXBYYy1r0fBfiTizFQY6bna0HSzXqHkwwmDYc20ZGo77JE4bBlagKFQ12W74bSe7HwP28DxtvWKW56Is6lM"
            + "uqZVkg8GQMW4Iz3hX9SKBe6/tw06PegPDbp/"
            + "RfFAxzq9vcb5FU9kshMdnvTAY6I7OjgVGR8FXN4iZARzU5+"
            + "BBQa4QblkxDUyiPLSjSSAX3oKkWmu9S9LxmrhsHgd2KOqbZL19EoZrx+"
            + "eQyseaLjDuF569Da6V133Nqej46CPTZNp6ojwNSAjPY2ai1D0hZ8GQpTaeTRRiVcFUps4UHRCsUbBSTC5RJL"
            + "VoGqj0eORAhib4xp7DGlKf7s1j88ZH1OgOw/rIbFMsyKSQsKKmI22Bo3FW2iVL/"
            + "SoPGOKDupMQJvolkieVqK0DjUxsfDLf/VpkrM6fH3FIiw6Dz7vSz3CfUIQ0gDfQi/"
            + "w08WWCP706VHeDwX1rscAvn2Cc6/q3TbP9bMYoEvS04p5LPGeHtvX/"
            + "PVyfv9JNqAbrRVmtuTAd1rQhiPNHK5JH5feweblxNOsluNH5iJ2tH70R/"
            + "3LcbL6jiHS9DfoxzHPnX3arWpVF1ZZ4aZivePAOX8B9J7zbxdhhdU1eUNFt+"
            + "sEuGyA6VsTsHf8fZeXpbPwy1OBRMmNiJ3wG+"
            + "VQC7guTMjnhs7kljuWlhZ1MlsnGroX7y51x2l78r3ntwiXkpyfpOBiDezTHPu8kYMNkLaZWeo4bygR04SD75"
            + "GmjwkYGAXKSvL2XMqT8iCO8wQRrKneIeBgmQKojolj5EQlQIYptCzHjq0kVVout5a";
    private static final String TEST_S =
            "jf3ldp/wzf7aHNAWXPULSa7WoqVbFXac+zkQpMtFRz/dQd8bbXrttS+XKo7F/"
            + "zb0ZuRfHteGNNoSVnkUvPU0i2Y1rVtgY5j7DlHKGSgk+WncxH+nusXYb4kjltDPZe4A/yvGSD6Boaq/09Yr/"
            + "edE79gSs1bkNyLL7Qa33BhiZEUAT4d3SDhi2WiPtv5gkiwRGrGs4PiRkkn9gTTPVHDlct1jpfip0lDt5BWXY"
            + "214k013ZKL0a+55lmMEXmyrdSTi6PdBUEQ61OCiiWEYDateWKRqZgj04qCQFJ4EdyAxVnQkN7bO1+"
            + "OZdE539uNDNs9nqToegkw1AE+"
            + "Iew6WGpmD4at8EyKC46OsHbCYgLzXgNBUqQEWuGUdb9JjXJx6Ycir4S1dZVcSSMopyNPfNoNrkVcQrjXuCEh"
            + "2wcUNq8YcYF8EapDBTZVdcGrkGeg7/kBexN/7jBXbTBfR0dXfX/"
            + "EsLPXRoWr4jW9IfTPWzaWjZijzndJXb8Mbf+PxhVQAH4fKPzMUYXsnSVLjgYv4/"
            + "EIqzC4CNXU2y3zEF+"
            + "0EBVG0sF0KKfzuAWvRA2Sfoy6TLotPvj574MoWoUSym9Fvk60MHmtUvUow4AAQEgjAPdR1zpJsnKdmZUWKrf"
            + "2MAB5powP7G94qywlLDlH93r9RarI90hGVdhaIoGdEU+e7A+i5Uj65AIQJGcHFxeHC1gQ+"
            + "gjTlVTyJt6TFmlCAcj8aLlOpQXO4TTq5Y3izgAZs92t2Nrpx8GByKgC7OHYG+aYo3Z+KvIANyfh377cogp8+"
            + "tW/YQchb/22l96/q3scWIViA+AKVRJnrOOYaaL9PHrCeG81b/"
            + "QUClZrmFozUiU7yyv++"
            + "J6orbIDXw5rGYEPaA618km10q0Podyy2WZvldOyR5MH238zql1lu1QIGL19ivHCnwJFtE9mJQJbZ+hUk/"
            + "OLfdRN025junC6h1XP52zVDu4Eb/"
            + "syrGu59ox5+JyF8czYVNQhfFjWD7+"
            + "Dbw5BUemv3388zjgY3q9mOfZexZglIBGvRccBuNaPnPDkxVF8o64gHgV/"
            + "ydyAUcq7kIKmUfi6geORAXtCjEtLQEDnkxGX/"
            + "iS7mokZ9mrb7TfygiuG93+"
            + "PPlxNu9PNG7ISXrGFFAwdZCPOyyiHIU1EquBehWnmvdcM0vt0BVz35hZq2LhcWW74xCMVpScU8CypJZCkgj8"
            + "ZtDUgl5z7ZfpX9OZ21glJK9s/"
            + "UQOmfoFZLYhszBB21S4X2nhKEOgFv8JW48SQzVoWLlATXen0UomBn3rh4PY+dmRGwj0gxEVGMDTeSRsF/"
            + "jF0l0GV437hvP4UlYaAVfc50RTOFargFEBS91YLFNfpcq5PMECgwJc5EC/"
            + "iK5FR2EXYJQM7xj0a5OH+qtVO+xNVlMJT7AXQ960ie+"
            + "IxvqAyHuRCXUKyi14KOdLFH5iGL0VsB8VZ1RtfU1wkwHyKkqioFE5LaoZ6MPoYMtPvRf+/"
            + "nOak9m6bwtF5IxrAS1fRGTTJmMlNK3xzMwwQsurt5KBaFBdE0FYOV01A0xMpN5Wo3YFpoOebnRYxXHdwDLZZ"
            + "1UAfokYkf+mS53h8xLI2mSW4J9LQaDg/y/sDuZPGIqKTyjlvc/"
            + "X8zN3UvQpXb8lAHAAfbo3Xj5mkGWUglUDBnIP378angbNEIzLZcuPsfrfcSGU0ki4zM4adptxGY5LX7DinlQ"
            + "6Pe4FO39BURjnYBrVH+zFQu20WfLrwBthjInasLUUUvdBew+n1/"
            + "gHaxDKqAIvfBubWXJdZpPqwT9wsHBwcKQhrXxnVDXeQD2n0Vxw4tMXc3KFVUEoLRxTWQlVveaJK3zSo8XZOL"
            + "S4WqEJoMweOGOAMjny6UUAjTl7wlMHOukwVK5jPCrATL40V0QvMNP08uy76fMkIFOgXvn1UmeKE1+"
            + "PP6k8iX4UiVxAbkAkHVc2bA7pPHot0Eii6QvEtZGrXATpIEcbN1FdS2FmxZ/"
            + "Jw+Ln+8uTviKuvlcUBXTte1MSWu2pw/"
            + "V2HskCGoxsvoyGIP3qRwooxEzPrN7IBLJVOpBj67dzxfoRwFIpGBrldINyQVxT9ENgwWnTCzrI+"
            + "1yZfhTlNnpw7gugImTMm9TVhFOA9kJKT/hPxq3Hyp/WJDYP/"
            + "qa+O7hL8zob6UBDuCgJToU3B5TXJNl2YGnmUF6TwyWt90l6kgBTqEX7PoaoFsXUdnAHtVc4BCqMGK+"
            + "fDYlrZs7PgaQbeCVcUKComEMUvg37D2OByl+"
            + "kaLUbWTCyv3ajWC7teAPSRTziIArC2YKJkHktKVssnUQWLKCqWmNkX9OzsaGzDFtP+2QOEVTnydi/"
            + "Zv25WuYPN9QifZmBz59vm/"
            + "7vl89loTK9LegfGjSk0U0scZGDnc7hMYKbo63mwifYY2hS26qb0ZFOioUfjrQgqoHzdvBcJpvJDaR3IeL9qy"
            + "5LHgXfWu/"
            + "Og4f7PAjX6e3mpyUA1XfxIXBT9VsuptCNnJxFBzG6V5eNPi4ZgDa3jEW3ZYs9JRUZbGQtSuTRg2JlS+xe7/"
            + "HNZPzP8ALwsaJ4zkRdEe55lqNW9nF9XiKaYXoX4FvZIE1a1e7nID2rnPIBO/"
            + "hdapEtaJFaed3dua6EmJjWBEMQfpjw5EczeHnE/zbyqSelUXKN7EH+eDnIoWAA4vBjurEOWcFCraT/"
            + "GNiJ81n7pT7hfsxUSDLhOdfDxy9pmttccsA8bjk4avPUOPA/"
            + "Z6+R5VhL9WS1Vzqr+"
            + "B9uw7PbZrFsgoYCUmKfcGi9hm0NEKvENnqS8LzTYgwENtk7JCvTnBSx2KwjPLx5HqvvUqCabb1R5OojT9wn0"
            + "IOGfD1Y4Q1x3PD4ZiqDAWG6iiG2wXL5fSEckqm8VJV/jgeXAZ/"
            + "C4cjIqiqF6BC7AL1ZBUCgHovQehyxT44K2xCe1KtdCvmpX59y0ZTLBA7IvO8gkbMA07BSrAhiNITMUWJulYM"
            + "H1D2lPZ2DKMqtTWe4HyPubEqBQAP6J9MPrCgsDuK+GVaFaCAzSj402on8ezdr12mHE3DiuGbdQLXJ/"
            + "2PNuwL22dnLe+r2BvPaFFbW/scPuxc58V2kU1SQWO8vjfWvMdbxIkZr8gJTHeDBfSo1HDjSoth/"
            + "kHJw+rbwe1iwyPuwz3fZX/ggsKF6tqZB1gejx/uzkMFx0kTVaOlq/c3/"
            + "0KRUpgeJWnrsvN7fEtLzx4j6uu4fL4/"
            + "QQmN1CiyNbe8gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwYIyw4p6ZpVOH9qAghOpGxm"
            + "CwS6dSUaGbwxWhCXBSwStykpNKHmRTmcmD0as/7cBaKsCuyU6hziLYmqqRsg8TYKZQN";

    @Test
    public void verify_invalidMlDsaKey_throws() throws Exception {
        byte[] message = TestUtils.decodeBase64(TEST_M);
        String algName = "MLDSA44-Ed25519-SHA512";

        CompositeMlDsaAlgorithm alg = CompositeMlDsaAlgorithm.fromName(algName);
        Signature signature = getInstance(alg);

        byte[] invalidPublicKeyBytes = TestUtils.decodeBase64(TEST_PK);
        invalidPublicKeyBytes[0] = (byte) (invalidPublicKeyBytes[0] ^ 0x01);
        OpenSslCompositeMlDsaPublicKey invalidMldsaPublicKey =
                new OpenSslCompositeMlDsaPublicKey(invalidPublicKeyBytes, alg);
        byte[] sigBytes = TestUtils.decodeBase64(TEST_S);

        signature.initVerify(invalidMldsaPublicKey);
        signature.update(message, 0, message.length);

        assertFalse("Signature verification failed for algorithm: " + algName
                            + " (tcId: id-MLDSA44-Ed25519-SHA512)",
                    signature.verify(sigBytes));
    }

    @Test
    public void verify_invalidTradPublicKey_throws() throws Exception {
        byte[] message = TestUtils.decodeBase64(TEST_M);
        String algName = "MLDSA44-Ed25519-SHA512";

        CompositeMlDsaAlgorithm alg = CompositeMlDsaAlgorithm.fromName(algName);
        Signature signature = getInstance(alg);

        byte[] invalidPublicKeyBytes = TestUtils.decodeBase64(TEST_PK);
        invalidPublicKeyBytes[invalidPublicKeyBytes.length - 1] =
                (byte) (invalidPublicKeyBytes[invalidPublicKeyBytes.length - 1] ^ 0x01);
        OpenSslCompositeMlDsaPublicKey invalidTradPublicKey =
                new OpenSslCompositeMlDsaPublicKey(invalidPublicKeyBytes, alg);
        byte[] sigBytes = TestUtils.decodeBase64(TEST_S);

        signature.initVerify(invalidTradPublicKey);
        signature.update(message, 0, message.length);

        assertFalse("Signature verification failed for algorithm: " + algName
                            + " (tcId: id-MLDSA44-Ed25519-SHA512)",
                    signature.verify(sigBytes));
    }

    @Test
    public void verify_invalidMessage_throws() throws Exception {
        byte[] invalidMessage = TestUtils.decodeBase64(TEST_M);
        invalidMessage[0] = (byte) (invalidMessage[0] ^ 0x01);
        String algName = "MLDSA44-Ed25519-SHA512";

        CompositeMlDsaAlgorithm alg = CompositeMlDsaAlgorithm.fromName(algName);
        Signature signature = getInstance(alg);

        OpenSslCompositeMlDsaPublicKey publicKey =
                new OpenSslCompositeMlDsaPublicKey(TestUtils.decodeBase64(TEST_PK), alg);
        byte[] sigBytes = TestUtils.decodeBase64(TEST_S);

        signature.initVerify(publicKey);
        signature.update(invalidMessage, 0, invalidMessage.length);

        assertFalse("Signature verification succeeded for algorithm: " + algName
                            + " (tcId: id-MLDSA44-Ed25519-SHA512)",
                    signature.verify(sigBytes));
    }

    @Test
    public void verify_invalidMlDsaSignature_throws() throws Exception {
        byte[] message = TestUtils.decodeBase64(TEST_M);
        String algName = "MLDSA44-Ed25519-SHA512";

        CompositeMlDsaAlgorithm alg = CompositeMlDsaAlgorithm.fromName(algName);
        Signature signature = getInstance(alg);

        OpenSslCompositeMlDsaPublicKey publicKey =
                new OpenSslCompositeMlDsaPublicKey(TestUtils.decodeBase64(TEST_PK), alg);
        byte[] invalidSigBytes = TestUtils.decodeBase64(TEST_S);
        invalidSigBytes[0] = (byte) (invalidSigBytes[0] ^ 0x01);

        signature.initVerify(publicKey);
        signature.update(message, 0, message.length);

        assertFalse("Signature verification succeeded for algorithm: " + algName
                            + " (tcId: id-MLDSA44-Ed25519-SHA512)",
                    signature.verify(invalidSigBytes));
    }

    @Test
    public void verify_invalidTradSignature_throws() throws Exception {
        byte[] message = TestUtils.decodeBase64(TEST_M);
        String algName = "MLDSA44-Ed25519-SHA512";

        CompositeMlDsaAlgorithm alg = CompositeMlDsaAlgorithm.fromName(algName);
        Signature signature = getInstance(alg);

        OpenSslCompositeMlDsaPublicKey publicKey =
                new OpenSslCompositeMlDsaPublicKey(TestUtils.decodeBase64(TEST_PK), alg);
        byte[] invalidSigBytes = TestUtils.decodeBase64(TEST_S);
        invalidSigBytes[invalidSigBytes.length - 1] =
                (byte) (invalidSigBytes[invalidSigBytes.length - 1] ^ 0x01);

        signature.initVerify(publicKey);
        signature.update(message, 0, message.length);

        assertFalse("Signature verification succeeded for algorithm: " + algName
                            + " (tcId: id-MLDSA44-Ed25519-SHA512)",
                    signature.verify(invalidSigBytes));
    }

    // The fuller set of tests with the provider API is performed in the `SignatureTest.java`.
    // Here we verify that the provider implementation indeed verifies the known test vectors.
    @Test
    public void verifyTestVectorsViaProvider_works() throws Exception {
        for (TestVector tv : TestUtils.readTestVectors("crypto/composite_mldsa.txt")) {
            byte[] message = TestUtils.decodeBase64(tv.getString("m"));
            String algName = tv.getString("tcid");
            assertTrue(algName.startsWith("id-"));
            algName = algName.substring(3);

            CompositeMlDsaAlgorithm alg = CompositeMlDsaAlgorithm.fromName(algName);
            Signature verifier = Signature.getInstance(algName, PROVIDER);

            OpenSslCompositeMlDsaPublicKey publicKey = new OpenSslCompositeMlDsaPublicKey(
                    TestUtils.decodeBase64(tv.getString("pk")), alg);
            byte[] sigBytes = TestUtils.decodeBase64(tv.getString("s"));

            verifier.initVerify(publicKey);
            verifier.update(message, 0, message.length);

            assertTrue("Signature verification failed for algorithm: " + algName
                               + " (tcId: " + tv.getString("tcid") + ")",
                       verifier.verify(sigBytes));
        }
    }

    @Test
    public void signWithoutInit_throws() throws Exception {
        Signature signature = Signature.getInstance("MLDSA44-Ed25519-SHA512", PROVIDER);
        assertThrows(SignatureException.class, () -> signature.sign());
    }

    @Test
    public void verifyWithoutInit_throws() throws Exception {
        Signature signature = Signature.getInstance("MLDSA44-Ed25519-SHA512", PROVIDER);
        assertThrows(SignatureException.class, () -> signature.verify(new byte[0]));
    }

    private void testSignVerifyRoundTripWithJce(String algName) throws Exception {
        CompositeMlDsaAlgorithm alg = CompositeMlDsaAlgorithm.fromName(algName);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg.getName(), PROVIDER);
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance(alg.getName(), PROVIDER);
        PublicKey publicKey =
                kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey privateKey =
                kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        Signature signer = getInstance(alg);
        signer.initSign(privateKey);
        byte[] message = "test message".getBytes(UTF_8);
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = getInstance(alg);
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertTrue(verifier.verify(sig));
    }

    @Test
    public void testSignVerifyRoundTripEd25519() throws Exception {
        testSignVerifyRoundTripWithJce("MLDSA44-Ed25519-SHA512");
    }

    @Test
    public void testSignVerifyRoundTripRsa() throws Exception {
        testSignVerifyRoundTripWithJce("MLDSA65-RSA3072-PSS-SHA512");
    }

    @Test
    public void testSignVerifyRoundTripEcdsa() throws Exception {
        testSignVerifyRoundTripWithJce("MLDSA87-ECDSA-P521-SHA512");
    }
}
