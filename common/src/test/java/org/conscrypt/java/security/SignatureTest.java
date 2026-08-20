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

package org.conscrypt.java.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

// android-add: import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
// android-add: import libcore.test.annotation.NonCts;
// android-add: import libcore.test.annotation.NonMts;
// android-add: import libcore.test.reasons.NonCtsReasons;
// android-add: import libcore.test.reasons.NonMtsReasons;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.conscrypt.TestUtils;
import org.conscrypt.testing.BrokenProvider;
import org.conscrypt.testing.OpaqueProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class SignatureTest {
    // android-add: Allow access to deprecated BC algorithms.

    // 20 bytes for DSA
    private static final byte[] emptyData = new byte[20];

    @Test
    // android-add: @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
    // android-add: @NonMts(reason = NonMtsReasons.API_LEVEL_GATING)
    public void test_getInstance() throws Exception {
        ServiceTester
                .test("Signature")
                // Do not test AndroidKeyStore's Signature. It needs an AndroidKeyStore-specific
                // key. It's OKish not to test AndroidKeyStore's Signature here because it's tested
                // by cts/tests/test/keystore.
                .skipProvider("AndroidKeyStore")
                .skipProvider("AndroidKeyStoreBCWorkaround")
                // The SunMSCAPI is very strange, including only supporting its own keys,
                // so don't test it.
                .skipProvider("SunMSCAPI")
                // SunPKCS11-NSS has a problem where failed verifications can leave the
                // operation open, which results in future init() calls to throw an exception.
                // This appears to be a problem in the underlying library (see
                // https://bugs.openjdk.java.net/browse/JDK-8044554), but skip verifying it all
                // the same.
                .skipProvider("SunPKCS11-NSS")
                // We don't have code to generate key pairs for these yet.
                .skipAlgorithm("Ed448")
                .skipAlgorithm("EdDSA")
                // ML-DSA is skipped because it doesn't yet support getFormat() and getEncoded().
                .skipAlgorithm("ML-DSA")
                .skipAlgorithm("ML-DSA-44")
                .skipAlgorithm("ML-DSA-65")
                .skipAlgorithm("ML-DSA-87")
                // SLH-DSA-SHA2-128S is skipped because it doesn't yet support getFormat() and
                // getEncoded().
                .skipAlgorithm("SLH-DSA-SHA2-128S")
                .skipAlgorithm("HSS/LMS")
                .run((provider, algorithm) -> {
                    KeyPair kp = keyPair(algorithm);
                    // Signature.getInstance(String)
                    Signature sig1 = Signature.getInstance(algorithm);
                    assertEquals(algorithm, sig1.getAlgorithm());
                    test_Signature(sig1, kp);

                    // Signature.getInstance(String, Provider)
                    Signature sig2 = Signature.getInstance(algorithm, provider);
                    assertEquals(algorithm, sig2.getAlgorithm());
                    assertEquals(provider, sig2.getProvider());
                    test_Signature(sig2, kp);

                    // Signature.getInstance(String, String)
                    Signature sig3 = Signature.getInstance(algorithm, provider.getName());
                    assertEquals(algorithm, sig3.getAlgorithm());
                    assertEquals(provider, sig3.getProvider());
                    test_Signature(sig3, kp);
                });
    }

    private final Map<String, KeyPair> keypairAlgorithmToInstance = new HashMap<>();

    private KeyPair keyPair(String sigAlgorithm) throws Exception {
        String sigAlgorithmUpperCase = sigAlgorithm.toUpperCase(Locale.ROOT);
        if (sigAlgorithmUpperCase.endsWith("ENCRYPTION")) {
            sigAlgorithm = sigAlgorithm.substring(0, sigAlgorithm.length() - "ENCRYPTION".length());
            sigAlgorithmUpperCase = sigAlgorithm.toUpperCase(Locale.ROOT);
        }

        String kpAlgorithm;
        // note ECDSA must be before DSA
        if (sigAlgorithmUpperCase.endsWith("ECDSA")
            || sigAlgorithmUpperCase.endsWith("ECDSAINP1363FORMAT")) {
            kpAlgorithm = "EC";
        } else if (sigAlgorithmUpperCase.endsWith("DSA")
                   || sigAlgorithmUpperCase.endsWith("DSAINP1363FORMAT")) {
            kpAlgorithm = "DSA";
        } else if (sigAlgorithmUpperCase.endsWith("RSA")
                   || sigAlgorithmUpperCase.endsWith("RSA/PSS")
                   || sigAlgorithmUpperCase.endsWith("RSASSA-PSS")) {
            kpAlgorithm = "RSA";
        } else if (sigAlgorithmUpperCase.equals("ED25519")) {
            kpAlgorithm = "ED25519";
        } else if (sigAlgorithmUpperCase.startsWith("ML-DSA")) {
            kpAlgorithm = "ML-DSA";
        } else if (sigAlgorithmUpperCase.startsWith("MLDSA")) {
            kpAlgorithm = sigAlgorithm;
        } else {
            throw new Exception("Unknown KeyPair algorithm for Signature algorithm "
                                + sigAlgorithm);
        }

        KeyPair kp = keypairAlgorithmToInstance.get(kpAlgorithm);
        if (kp == null) {
            KeyPairGenerator kpg;
            if (kpAlgorithm.equals("ED25519")) {
                // We use SunEC to generate Ed25519 keys because Conscrypt's Ed25519 keys
                // are not yet implement the EdECPublicKey and EdECPrivateKey interfaces.
                kpg = KeyPairGenerator.getInstance(kpAlgorithm, "SunEC");
            } else {
                kpg = KeyPairGenerator.getInstance(kpAlgorithm);
            }
            if (kpAlgorithm.equals("DSA")) {
                kpg.initialize(1024);
            }
            kp = kpg.generateKeyPair();
            keypairAlgorithmToInstance.put(kpAlgorithm, kp);
        }
        return kp;
    }

    private AlgorithmParameterSpec getAlgParamSpec(String algorithm) {
        if (algorithm.equalsIgnoreCase("RSASSA-PSS")) {
            return PSSParameterSpec.DEFAULT;
        }
        return null;
    }

    private void test_Signature(Signature sig, KeyPair keyPair) throws Exception {
        AlgorithmParameterSpec params = getAlgParamSpec(sig.getAlgorithm());
        sig.initSign(keyPair.getPrivate());
        if (params != null) {
            sig.setParameter(params);
        }
        sig.update(emptyData);
        byte[] signature = sig.sign();
        assertNotNull(sig.getAlgorithm(), signature);
        assertTrue(sig.getAlgorithm(), signature.length > 0);

        sig.initVerify(keyPair.getPublic());
        if (params != null) {
            sig.setParameter(params);
        }
        sig.update(emptyData);
        assertTrue(sig.getAlgorithm(), sig.verify(signature));

        // After verify, should be reusable as if we are after initVerify
        sig.update(emptyData);
        assertTrue(sig.getAlgorithm(), sig.verify(signature));

        /*
         * The RI appears to clear out the input data in RawDSA while calling
         * verify a second time.
         */
        if (StandardNames.IS_RI
            && ("NONEwithDSA".equalsIgnoreCase(sig.getAlgorithm())
                || "NONEwithDSAinP1363Format".equalsIgnoreCase(sig.getAlgorithm())
                || "RawDSA".equalsIgnoreCase(sig.getAlgorithm()))) {
            try {
                sig.verify(signature);
                fail("Expected RI to have a NONEwithDSA bug");
            } catch (SignatureException bug) {
                // Expected
            }
        } else if (StandardNames.IS_RI && "NONEwithECDSA".equalsIgnoreCase(sig.getAlgorithm())
                   && "SunPKCS11-NSS".equalsIgnoreCase(sig.getProvider().getName())) {
            // This provider doesn't work properly
            try {
                sig.verify(signature);
                fail("Expected RI to have a NONEwithECDSA bug");
            } catch (ProviderException bug) {
                // Expected
            }
        } else {
            // Calling Signature.verify a second time should not throw
            // http://code.google.com/p/android/issues/detail?id=34933
            sig.verify(signature);
        }
    }

    private static final byte[] pkBytes = TestUtils.decodeHex(
            "30819f300d06092a864886f70d010101050003818d0030818902818100cd769d178f61475fce3001"
            + "2604218320c77a427121d3b41dd76756c8fc0c428cd15cb754adc85466f47547b1c85623d9c17fc6"
            + "4f202fca21099caf99460c824ad657caa8c2db34996838d32623c4f23c8b6a4e6698603901262619"
            + "4840e0896b1a6ec4f6652484aad04569bb6a885b822a10d700224359c632dc7324520cbb3d020301"
            + "0001");
    private static final byte[] content = TestUtils.decodeHex(
            "f2fa9d73656e00fa01edc12e73656e2e7670632e6432004867268c46dd95030b93ce7260423e5c00"
            + "fabd4d656d6265727300fa018dc12e73656e2e7670632e643100d7c258dc00fabd44657669636573"
            + "00faa54b65797300fa02b5c12e4d2e4b009471968cc68835f8a68dde10f53d19693d480de767e5fb"
            + "976f3562324006372300fabdfd04e1f51ef3aa00fa8d00000001a203e202859471968cc68835f8a6"
            + "8dde10f53d19693d480de767e5fb976f356232400637230002bab504e1f51ef5810002c29d28463f"
            + "0003da8d000001e201eaf2fa9d73656e00fa01edc12e73656e2e7670632e6432004867268c46dd95"
            + "030b93ce7260423e5c00fabd4d656d6265727300fa018dc12e73656e2e7670632e643100d7c258dc"
            + "00fabd4465766963657300faa54b65797300fa02b5c12e4d2e4b009471968cc68835f8a68dde10f5"
            + "3d19693d480de767e5fb976f3562324006372300fabdfd04e1f51ef3aa000003e202859471968cc6"
            + "8835f8a68dde10f53d19693d480de767e5fb976f3562324006372300000000019a0a9530819f300d"
            + "06092a864886f70d010101050003818d0030818902818100cd769d178f61475fce30012604218320"
            + "c77a427121d3b41dd76756c8fc0c428cd15cb754adc85466f47547b1c85623d9c17fc64f202fca21"
            + "099caf99460c824ad657caa8c2db34996838d32623c4f23c8b6a4e66986039012626194840e0896b"
            + "1a6ec4f6652484aad04569bb6a885b822a10d700224359c632dc7324520cbb3d020301000100");
    private static final byte[] signature = TestUtils.decodeHex(
            "b4016456148cd2e9f580470aad63d19c1fee52b38c9dcb5b4d61a7ca369a7277497775d106d86394"
            + "a69229184333b5a3e6261d5bcebdb02530ca9909f4d790199eae7c140f7db39dee2232191bdf0bfb"
            + "34fdadc44326b9b3f3fa828652bab07f0362ac141c8c3784ebdec44e0b156a5e7bccdc81a56fe954"
            + "56ac8c0e4ae12d97");

    /*
     * This should actually fail because the ASN.1 encoding is incorrect. It is
     * missing the NULL in the AlgorithmIdentifier field.
     *
     * http://code.google.com/p/android/issues/detail?id=18566 <br/>
     * http://b/5038554
     */
    @Test
    public void test18566_AlgorithmOid_MissingNull_Failure() throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pkBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pk = keyFactory.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pk);
        sig.update(content);
        assertFalse(sig.verify(signature));
    }

    /*
     * Test vectors generated with this private key:
     *
     * -----BEGIN RSA PRIVATE KEY-----
     * MIIEpAIBAAKCAQEA4Ec+irjyKE/rnnQv+XSPoRjtmGM8kvUq63ouvg075gMpvnZq
     * 0Q62pRXQ0s/ZvqeTDwwwZTeJn3lYzT6FsB+IGFJNMSWEqUslHjYltUFB7b/uGYgI
     * 4buX/Hy0m56qr2jpyY19DtxTu8D6ADQ1bWMF+7zDxwAUBThqu8hzyw8+90JfPTPf
     * ezFa4DbSoLZq/UdQOxab8247UWJRW3Ff2oPeryxYrrmr+zCXw8yd2dvl7ylsF2E5
     * Ao6KZx5jBW1F9AGI0sQTNJCEXeUsJTTpxrJHjAe9rpKII7YtBmx3cPn2Pz26JH9T
     * CER0e+eqqF2FO4vSRKzsPePImrRkU6tNJMOsaQIDAQABAoIBADd4R3al8XaY9ayW
     * DfuDobZ1ZOZIvQWXz4q4CHGG8macJ6nsvdSA8Bl6gNBzCebGqW+SUzHlf4tKxvTU
     * XtpFojJpwJ/EKMB6Tm7fc4oV3sl/q9Lyu0ehTyDqcvz+TDbgGtp3vRN82NTaELsW
     * LpSkZilx8XX5hfoYjwVsuX7igW9Dq503R2Ekhs2owWGWwwgYqZXshdOEZ3kSZ7O/
     * IfJzcQppJYYldoQcW2cSwS1L0govMpmtt8E12l6VFavadufK8qO+gFUdBzt4vxFi
     * xIrSt/R0OgI47k0lL31efmUzzK5kzLOTYAdaL9HgNOw65c6cQIzL8OJeQRQCFoez
     * 3UdUroECgYEA9UGIS8Nzeyki1BGe9F4t7izUy7dfRVBaFXqlAJ+Zxzot8HJKxGAk
     * MGMy6omBd2NFRl3G3x4KbxQK/ztzluaomUrF2qloc0cv43dJ0U6z4HXmKdvrNYMz
     * im82SdCiZUp6Qv2atr+krE1IHTkLsimwZL3DEcwb4bYxidp8QM3s8rECgYEA6hp0
     * LduIHO23KIyH442GjdekCdFaQ/RF1Td6C1cx3b/KLa8oqOE81cCvzsM0fXSjniNa
     * PNljPydN4rlPkt9DgzkR2enxz1jyfeLgj/RZZMcg0+whOdx8r8kSlTzeyy81Wi4s
     * NaUPrXVMs7IxZkJLo7bjESoriYw4xcFe2yOGkzkCgYBRgo8exv2ZYCmQG68dfjN7
     * pfCvJ+mE6tiVrOYr199O5FoiQInyzBUa880XP84EdLywTzhqLNzA4ANrokGfVFeS
     * YtRxAL6TGYSj76Bb7PFBV03AebOpXEqD5sQ/MhTW3zLVEt4ZgIXlMeYWuD/X3Z0f
     * TiYHwzM9B8VdEH0dOJNYcQKBgQDbT7UPUN6O21P/NMgJMYigUShn2izKBIl3WeWH
     * wkQBDa+GZNWegIPRbBZHiTAfZ6nweAYNg0oq29NnV1toqKhCwrAqibPzH8zsiiL+
     * OVeVxcbHQitOXXSh6ajzDndZufwtY5wfFWc+hOk6XvFQb0MVODw41Fy9GxQEj0ch
     * 3IIyYQKBgQDYEUWTr0FfthLb8ZI3ENVNB0hiBadqO0MZSWjA3/HxHvD2GkozfV/T
     * dBu8lkDkR7i2tsR8OsEgQ1fTsMVbqShr2nP2KSlvX6kUbYl2NX08dR51FIaWpAt0
     * aFyCzjCQLWOdck/yTV4ulAfuNO3tLjtN9lqpvP623yjQe6aQPxZXaA==
     * -----END RSA PRIVATE KEY-----
     *
     */

    private static final BigInteger RSA_2048_MODULUS = new BigInteger(TestUtils.decodeHex(
            "00e0473e8ab8f2284feb9e742ff9748fa118ed98633c92f52aeb7a2ebe0d3be60329be766ad10eb6a515"
            + "d0d2cfd9bea7930f0c306537899f7958cd3e85b01f8818524d312584a94b251e3625b54141edbfee1988"
            + "08e1bb97fc7cb49b9eaaaf68e9c98d7d0edc53bbc0fa0034356d6305fbbcc3c7001405386abbc873cb0f"
            + "3ef7425f3d33df7b315ae036d2a0b66afd47503b169bf36e3b5162515b715fda83deaf2c58aeb9abfb30"
            + "97c3cc9dd9dbe5ef296c176139028e8a671e63056d45f40188d2c4133490845de52c2534e9c6b2478c07"
            + "bdae928823b62d066c7770f9f63f3dba247f530844747be7aaa85d853b8bd244acec3de3c89ab46453ab"
            + "4d24c3ac69"));

    private static final BigInteger RSA_2048_PRIVATE_EXPONENT = new BigInteger(TestUtils.decodeHex(
            "37784776a5f17698f5ac960dfb83a1b67564e648bd0597cf8ab8087186f2669c27a9ecbdd480f0197a80"
            + "d07309e6c6a96f925331e57f8b4ac6f4d45eda45a23269c09fc428c07a4e6edf738a15dec97fabd2f2bb"
            + "47a14f20ea72fcfe4c36e01ada77bd137cd8d4da10bb162e94a4662971f175f985fa188f056cb97ee281"
            + "6f43ab9d3747612486cda8c16196c30818a995ec85d38467791267b3bf21f273710a6925862576841c5b"
            + "6712c12d4bd20a2f3299adb7c135da5e9515abda76e7caf2a3be80551d073b78bf1162c48ad2b7f4743a"
            + "0238ee4d252f7d5e7e6533ccae64ccb39360075a2fd1e034ec3ae5ce9c408ccbf0e25e4114021687b3dd"
            + "4754ae81"));

    private static final BigInteger RSA_2048_PUBLIC_EXPONENT =
            new BigInteger(TestUtils.decodeHex("010001"));

    private static final BigInteger RSA_2048_PRIME_P = new BigInteger(TestUtils.decodeHex(
            "00f541884bc3737b2922d4119ef45e2dee2cd4cbb75f45505a157aa5009f99c73a2df0724ac460243063"
            + "32ea8981776345465dc6df1e0a6f140aff3b7396e6a8994ac5daa96873472fe37749d14eb3e075e629db"
            + "eb3583338a6f3649d0a2654a7a42fd9ab6bfa4ac4d481d390bb229b064bdc311cc1be1b63189da7c40cd"
            + "ecf2b1"));

    private static final BigInteger RSA_2048_PRIME_Q = new BigInteger(TestUtils.decodeHex(
            "00ea1a742ddb881cedb7288c87e38d868dd7a409d15a43f445d5377a0b5731ddbfca2daf28a8e13cd5c0"
            + "afcec3347d74a39e235a3cd9633f274de2b94f92df43833911d9e9f1cf58f27de2e08ff45964c720d3ec"
            + "2139dc7cafc912953cdecb2f355a2e2c35a50fad754cb3b23166424ba3b6e3112a2b898c38c5c15edb23"
            + "869339"));

    /* Test data is: "Android.\n" */
    private static final byte[] vector1Data = TestUtils.decodeHex("416e64726f69642e0a");

    private static final byte[] sha1WithRsaVector1Signature = TestUtils.decodeHex(
            "6d5bff68da1898725c1f4651771511cbe0b93b7df5969824859d3eed9bb28a91fbf685647418b51cb38d"
            + "990ddfaaa6a1c3b625b306e0ef28b04d50c77539b92c47b5e296f8f6cba058c93ed5fc26d955733975b3"
            + "b00a5f5e3b4a2eb10e7de5cc042cd10a32aad98d1fcbe37f6312b198464607d949d2bfb5bcbbfd1cd711"
            + "94aa5f7bb20c5d94535e815cbb1d4f30cdf8d7a5fa5ee0193fa4aa564eecebeea26cc94fc2cc2abc5b09"
            + "1073610c04b6b72c37d2ca2d54f2f777e1ba9f2907a274c6e91eded79c4bb76652e8acf676ab16829687"
            + "400fad2d46a6280413c2ce50566dbe0c91d08e809e918f62b357d6ae539183e938778f20dd137d15447e"
            + "b500d645");

    private static final byte[] vector2Data = TestUtils.decodeHex(
            "546869732069732061207369676e6564206d6573736167652066726f6d204b656e6e7920526f6f742e0a");

    private static final byte[] sha1WithRsaVector2Signature = TestUtils.decodeHex(
            "2ea633d19dfc4e27b3a89af2486215a2ce5f2b0ec526bad90f60ebf0d55c6b231195a4bd1168e73a373d"
            + "79b84fe9a188fba98b34a1e0ca11ddd0837fc10b1661ac09a2dd405b8c7ab2b4027cd49ae6a51a277770"
            + "e3e371c759c79fb8efe715020d70dc2ce9f7632ab5ee9f29568699b30fe51f76223b7fa99ed4c4835d57"
            + "cc37cb9a9e734493b4f16b98a057bb5e8f895b9726e4d0510a5ab7121a6db0793051832ee27a6766d395"
            + "cafccb9279322686e10dd819fa6537c94c2ae142c7d4b7eb1fc353646f2b781803da8d622470abe61613"
            + "246b5fd3ecc15864bd30985e33ce8764140785433e9f279f63669d2619c0020815cbb4aa4ac8c009157d"
            + "8a21bca3");

    /*
     * echo 'Android.' | openssl dgst -sha224 -binary -sign privkey.pem  | recode ../x1 | sed
     * 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha224WithRsaVector2Signature = TestUtils.decodeHex(
            "bd3fd4205bc0894f996cf4a470e35b33b3cafe1fb93ad69b1eda6506bdc32bf80ea0b5337f15dcbbdc98"
            + "96f5f8e5557d4851c5ae12a261c7a2000f35543c7e97192d8ffd510472236516411246d620b64ed6e860"
            + "9105ca576f53a4052a37dd2ea4c7bf9ef6d5d434b8b38b662cb65fa4b777f89a9c449ff0ca53562f992e"
            + "4ba2265030972b4b0c3e280b88879ececb57726bf6d6aa4d5f197aad44093362c8568284bf52c6a22be3"
            + "c27fe306c330b8d401e63ddbcae4fba87b2d8f397a639f02e891d1ee60eecaf2337df241520b9b1b2d89"
            + "38ec246040406fb66f86b50a3d98773f59413e4de44e91cd8e3360168dab0414e876f106cd4a88c7696b"
            + "c6da9e09");

    private static final byte[] sha256WithRsaVector2Signature = TestUtils.decodeHex(
            "186e311f1d44093ea0c43db41bf2d8a459abb53728b8946b6f1354ffac1584d0c9155b6905f144fddee8"
            + "b412599e4c0bd5493328e0cb8785d8186ffea22382f0e5391b8c931149722a5b25ff4e88709d9dffe2c0"
            + "7ec80340be4409eb9e8e88e4988206a49d638865a38e0d22f333f240e8916772291c08ff54a0ccad8488"
            + "4b3beff95eb3416abd94167d9d5377f16a9557ad659d7595f66ad288ea5ba2948f5e84181946830b6d5b"
            + "b9dba4e517029e11edd97b838789f3e4bf0ee8dc559cf7c9c3e22cf78caa171fd1c774c78e1c5bd23174"
            + "439a52bf89c5b4806a9e05dbbb078c0861baa4bc803add3b1a8c21d8a3c0c7d108e13499c0cf80fffa07"
            + "ef5c45e5");

    private static final byte[] sha384WithRsaVector2Signature = TestUtils.decodeHex(
            "aff77ac2bbb8bde342aa168a526c996608be15d97c602cac4d4cf4dfbc16580a4ede8db3bd034e2340a5"
            + "80ae83b40f9944c35edb591dea7b4df3d2adbd219f8e878f121333f1c09de7ec6eadea5d69bbab5bd855"
            + "56c8da8141fbd3116c97a7c3f131bfbe3fdb3585b7b0757faffb6561c70e63b57d95e9169d6a009f5ecd"
            + "ffa6bc71f22cd368b93faa06f19c7eca4afeb173198005a68514da7a167ac24657a7c0bfcddc2f64f66d"
            + "dccb5a29951cfef2da7ecb2612c6b0ba849b4fba1b7825b88f2e515f9efc40bc85cd867f88c5aa2b78b1"
            + "9c519ae1e1c04047cba4b76c31f2c89aad0bd3f6859a8f4fc9d8337c4530ea17d3e3902cdade41173f08"
            + "b934c0d1");

    private static final byte[] sha512WithRsaVector2Signature = TestUtils.decodeHex(
            "19e2e5f31883ecf0ab50054b5f22fc826dcae7be2394faf9a48a954d14088b5e031b74dec1459cce1dac"
            + "abd3a8c3ca6780f60346657759bbb883eec23e78dd89cd9b7835a909c877ddd3a064b07448514fa0ae33"
            + "b328b0a8788fa232a60aaa09b58d4c4446b4d2066b8c516e9cfa1f943e199c63fea99ae36c82645fcac2"
            + "8d66be126eb6356daaed4b50081cbf077078c0bbc58d6c8d35ff0481d8f4d24ac30523cbeb20b1d42dd8"
            + "7ad47ef6a9e87269feab544dd1f46b833117ed26e9d25bad4242a58f987c1b5c8e8856208e48f94d8291"
            + "cbc81c7ca5691b40c24c25164ffa09ebf56c553c6ef7c0c134d153a36964eef4f9c796608487b4c73c26"
            + "a73abf95");

    private static final byte[] md5WithRsaVector2Signature = TestUtils.decodeHex(
            "04178310e26edfa9aed2dc5f701daf54c05f0b2ce6d000184cf68f1810749099a9903c5a38d33d48cf31"
            + "af1298fb66e858eccae142f984176f4c3ec440c670b038f347eb6fcbea2141f3a03e42ada5ad5d2c1a8e"
            + "3eb3a5783d560993c993d3d29ac5a52eb2d837c7131a0bda50286d476552cde7ec5700413428b98b0341"
            + "b6d5a8efd3dd80d569e4f04da47d602fef790775ebf74b4341db33ad9c7b78833477e480bee66fddaca5"
            + "37cfb54411779645f9ae48a6be3032eb436f663957f8e66031d0fccf9fe53dcfbd7b1320ce11fde5ff90"
            + "85dfca3dd94416c23228c7016deacb0d85086fcb416a3c0f3d38b561c56464814ccdd16a872802af8f59"
            + "e5672500");

    /*
     * openssl rsautl -raw -sign -inkey rsa.key | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] noneWithRsaVector1Signature = TestUtils.decodeHex(
            "35433844ad3f9702fb591f4a2bb906ec66e6d2c58b7be318bf07d601f9d989c4db0068ff9b4390f2db83"
            + "f47ec681013a0be5ed08733ee13fdf1f076d228dcc4ee39abccc8f9e9b024800ac9fa48f87a1a8e69dcd"
            + "8b05e9d2058dc99516d0cd43258a1146d7744ccf58f9a1308452c9015f244cb19f7d1238270f5effe055"
            + "8ba3ad60358358af99de3f5d8080ff9bde5cab974364d99ffb6765a599e7e6eb0595fc46284bd88cf50a"
            + "eb1f30eae7671125f0447574940678d021f43fc8c44a57be023c93f695fbd1778b43f0b97de032e172b5"
            + "623f86c3d45f5e541b5be674a10be518d24f93f30958cef0a361e46e46458950bd033f38da5dd01b1fb1"
            + "ee8959c5");

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha1 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha1 -pkeyopt rsa_pss_saltlen:20 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha1WithRsaPssVector2Signature = TestUtils.decodeHex(
            "66e3a520e95ddf99a60477f8397874f5c24e9eeb24deb436691fac01ff5ae3898ae99232a7a4c0250014"
            + "ff381937841a3dcaeef3c691ed02e61d73dad45593549ae62e7d5c41afedad8e7f473b23c3b8bbcd87c4"
            + "a3321657ccb8b696841abcf80953b09de16fb2eb83dc6131d702b4d1babdf078c6be1fb0e1ca32579f8c"
            + "d3bb041b30745dead36b74316f335a70968bcb22f3aa7482b282714d42133feae339c50327ff78b2a671"
            + "071cb397fbe8856d14dff97d0d0c9fc3e2dbe0a505bc4736eb1eba601219a57e550c9bd49ae9725c5bf4"
            + "aa4a128bc28ec29a3e0c40a40afff8c18559dac68c832a6884531728783f5aa404e6238d2a71c1bc1cfd"
            + "75166e85");
    private static final PSSParameterSpec sha1WithRsaPssVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha1 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha1 -pkeyopt rsa_pss_saltlen:0 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha1WithRsaPssNoSaltVector2Signature = TestUtils.decodeHex(
            "3161a5472844485ada78a785e96469cf14073fa8dbfcb7898774b9813762d1070f3ddfa8843831eb173f"
            + "e028751fe94dd362facfcc2ec781e1eaec78fe1959541d27ed0c54dfe344312131a723c4e2698ab31a72"
            + "4f4e82862d2b85fe4a2890f7dfd6b13ec6fb767b3d12816efd007dd0dc25d0866ce80f09827489796973"
            + "3764ee535720fa0b4a5a4d33ac8b04a54a1a9b66aa0b3d15d93e2fd2a128135998c3457cee60d0bd4216"
            + "8419f6d9f77d77ad60e2e322b9fad5fa6e1f693fb1a71a22f7319768620f39b0e763ae6569d0d356c9a6"
            + "a4a5a461a9c445cd4976c85346d06335890422d7b663afc29710dfdee639252fead8565ac1b8cac18ab8"
            + "872fcd21");
    private static final PSSParameterSpec sha1WithRsaPssNoSaltVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 0, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha1 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha1 -pkeyopt rsa_pss_saltlen:234 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha1WithRsaPssMaxSaltVector2Signature = TestUtils.decodeHex(
            "49dbad487c06037c58e13820462860649451a3d1c952c62ab3ccd61950996058a286a874508c0e325856"
            + "6d3038fb26c3fd8e3673829ab4e52296553c18d746f17ce68e0a18a729968dfc0ebe91a0f8e2705ae376"
            + "ac1810b4b1ff58bc10f5882f0b109d522d42dbfda7233c4bb3d2961bceb3a3c342a40e355cc232c78cfc"
            + "7fe0f71d38213cdf821abd83e956f0f15476e3ce8669c2616d8ef5a361ca16cb7af5bf36cb7db1e97041"
            + "cf895113cc9550c8b63035e31308f6be20f1484d4695fe9ed2d529812e0f6fa70215ca7577297c3ae32b"
            + "d73d5c943b2a91dbfa69471c2c4649e6375d787176c1b62e4e3c836f82c3d850d71baff9e3f147c81286"
            + "829d3fce");
    private static final PSSParameterSpec sha1WithRsaPssMaxSaltVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 234, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha224 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha224 -pkeyopt rsa_pss_saltlen:28 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha224WithRsaPssVector2Signature = TestUtils.decodeHex(
            "8641cc4b827404438cabf63bfb94bc4c0afe0f4f0f9f8435578b8dc358a670ac406dbcc16afa313b7a23"
            + "ca1fcda7e3d67c2cf36ff5829e187090e6a34461b6469b0de53cae22f487b703d842334ecc7adfd757eb"
            + "516cb1994d9482a769858d8218e453f59f821ce1251c8ee7c1ecbe3fc3ed4189941311753f385258ab88"
            + "0130b4cd453e1a5f36f851906e6f319d40901aa810ef9df8b00301fbd83d837901a782c2463568d20881"
            + "3114e8138cd4c4cbb985259340883411daffef4ddc31747b5ea7511513b19e0651ba11da641b78765796"
            + "f31b86b2f366642b04818cdce0ea66624431a219f1776758185bcbba2891475b4f17232ae4b0ae824eca"
            + "a612ca70");
    private static final PSSParameterSpec sha224WithRsaPssVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), 28, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha224 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha224 -pkeyopt rsa_pss_saltlen:0 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha224WithRsaPssNoSaltVector2Signature = TestUtils.decodeHex(
            "d83848cda40936354755db6c2d8317103ece950258cea80244b7e4323d50e18cf3246fa42dd7fb7097be"
            + "ed272d22dc62976639e0365f0778af5edcfd21a8d5a7d1ba1cdaca80728add5c166a47fc11427e4e3f49"
            + "cf2f54d713765de92a29cc73dbe5de48a2e9d1d035fea11c13047577f45503c46dac251d57ff0de091ea"
            + "f61f3f69d600bd89ead331805e044c59ded062933bc99fe769c0b8edbf0d602855200c9fa2423495aef8"
            + "677cf1a0c074f2df755b6e2ffb1fddc3d3900a33f60316c4f8edb745395d7cf882ce7dfb022de0963560"
            + "5dbc35804c397ce7d4b419d1e58e6d250cb90c8d45e46773cf877c78aab942ae7fb8ec4fd285018000bd"
            + "f5ea446d");
    private static final PSSParameterSpec sha224WithRsaPssNoSaltVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), 0, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha224 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha224 -pkeyopt rsa_pss_saltlen:226 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha224WithRsaPssMaxSaltVector2Signature = TestUtils.decodeHex(
            "2c195e63c532c3c752e9694c04e54af27278bfc58d5a71efa95877944971bf453ea42e339b4ea495079c"
            + "aac4a860bccdc345e6bcadb6f30ef6d5cf33a382625295a80ed4ac1f9adc00d678ea530019e3817c7a8e"
            + "3057b781d74d1dcb998de4fa6e4ea6da1392317c2b3aa0f1038312d123edc4015763af4015ecb85ace3d"
            + "3ecdd8f376ca232068175b7fbc22672a9105b38560d876d52b9c80b6ea1e05c7952c4f145fee0832f712"
            + "2bcdf3837cce048a363db29715dbd6fa5329d14355ddaea7b42cd9a774a808d6c205bf673bba8d99c114"
            + "1a32cad5ccf964075bb8a969ed01cdd28867ff92a3c69797a1c515c8b6fe4a072e463f27b8ee69cbdc30"
            + "1977c5ef");
    private static final PSSParameterSpec sha224WithRsaPssMaxSaltVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), 226, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha256 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha256 -pkeyopt rsa_pss_saltlen:32 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha256WithRsaPssVector2Signature = TestUtils.decodeHex(
            "9433cb9e2c1746b38fb79398a345ead451603e00a393050fcb6effa59718f6ed6b6cad9c73639c5ba5a1"
            + "42a30e32f5f055ee58c1bd990a2bfdbd1e23ef997dc1e2d5716c9670c3754883855ec63affe5f16b857b"
            + "61a6b1cf600932afef95a41bd6fad0d717cab019217f5e9bbbb8e0b195b3da0bb8fa15757388c84533d1"
            + "5cb7fb3805a085992cb1c2feac5d2c1bd34281c81cb7537ec59f84976f00c35e8b673d9ad0e29b2dc6d8"
            + "ef1914498852f793ebdbb65505b6e770e45a9e807848a8e5598d1c5d953825fc38c3ffe26fe4fc648bca"
            + "915f0b4e9ab5225dc55a77ed23e0138fac13e581eed1ad8a0f2b4cb21354448e53e233147f9ba9d3bbfc"
            + "acc931b6");
    private static final PSSParameterSpec sha256WithRsaPssVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha256 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha256 -pkeyopt rsa_pss_saltlen:0 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha256WithRsaPssNoSaltVector2Signature = TestUtils.decodeHex(
            "4cb733780aa7eb355e998fe92a3d8c9b19c7c8b810c56da4443eab908270fa7be6063606935450cd5faa"
            + "0142adb9026eae600060551bbb9e03b7863dccfa6e2007618f53c62bef8f0f8b8022dc9e204a57a115e0"
            + "0195db46856d279f443bb135049df8c6d7d7ef9a535a73b3d03239e1283a9d694e57c1dffe5fa8ffe875"
            + "853390833d8f154716f232f94696cc2e8f273fcf91a69ebf422fd652d73bcdfe0b4a3b1957476533d9f7"
            + "e4c305493cc0dfc154188ddae459e93bd6890799b0f4090a2cba0be479b1dbadab5da21e767f74624907"
            + "7a5bd70fa42c361342bacf0afcc3315e06848a8a840d48bd67cf04b4fbbb0491b10aa470581a9b0286bd"
            + "ae77971c");
    private static final PSSParameterSpec sha256WithRsaPssNoSaltVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 0, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha256 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha256 -pkeyopt rsa_pss_saltlen:222 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha256WithRsaPssMaxSaltVector2Signature = TestUtils.decodeHex(
            "3b43a8b534d8f9addd1f7a73bffaed10f316cce5090f6802e7550dcf1b83cda2d602dd72a65f058a1ea1"
            + "4f92d909196e80a047985cf734527d85cf9febafb453f05d2887aca7b4cfdd8ba4c9caaaf4a825263411"
            + "14241c1c50c8ff7eff6f4f14b357480a5a955deb714e86fc381b93450915d3066b9d055c4ab393d10154"
            + "ccedbf0e7e3332a6a5f73d2ecb76a72264b81953fe8cc81e6cee08077e93431bcf37e4abe7d7838e19ae"
            + "055191107b70fc731296fad0caa359a7ddc31d9c7b50bb57b886f2cac4867a969002dfa0880e89452752"
            + "da86424b90c3c141605c2915e55c439b40e5041b4a93dd55c4fcfe0c659698dec505c53eb0254e65248d"
            + "4e9d9401");
    private static final PSSParameterSpec sha256WithRsaPssMaxSaltVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 222, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha384 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha384 -pkeyopt rsa_pss_saltlen:48 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha384WithRsaPssVector2Signature = TestUtils.decodeHex(
            "20cb979c2e5159569f04477c5c5759bc43d94becacb988a2308bee2fc173f113b25e1ac8d2aa2716a114"
            + "ab458a7e22222a2eda6a7e3f669955af2b94d86bc260b555a92629fc175605b7482fab68cf3762794f32"
            + "04f6eabe798473ee1cee9f727ac664b44fde0b384762a9fd1b75ecfe2d042d0ace13fada3f4c11ea0200"
            + "0a9312dc60e752908aa3aec59ad7d50dbc7adbf410e0dbc097f184cf66b2045881b59b4af9d7ca510967"
            + "487be5e9074e6ac1a6689017ab0efb3e39748504420a9e02a950ff232d30dd17c082f7bb3b03bdb196cd"
            + "713f67595e45e01c8052d7f0c1e6cf5913256f9fbbb97f7e7d93d93f95b79adbe22c53839a066d2281b5"
            + "63ae4aee");
    private static final PSSParameterSpec sha384WithRsaPssVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha384 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha384 -pkeyopt rsa_pss_saltlen:0 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha384WithRsaPssNoSaltVector2Signature = TestUtils.decodeHex(
            "410c3aecf6d98fa361bb03edd9697de1e14e5e714e889c79d3712807281996553081295c4a18693674ac"
            + "99b1bca0fc17a4d1ae84a6096bb302b28104598ccfadfb766fe25e09e5bc54bd08a81860af09671503a8"
            + "8b3f31b776fdf682c789c24780064f8c9cd74f631ef034d791d29662fd68e3e0fb7d0ad752fed1959ed2"
            + "84be3d1f8cc4d6e3cfe8b3822efa39a3203cbe6afa04d27441dce80ee7f236d42e6acfdf8b4b77e80a64"
            + "862cca9201b28ab8b26c0b1890319329bab18894440b3864c1de0bd8e4ba0a412435aae3598e575143e1"
            + "9cf6f8166883088c2d40d2efd6ae9877e8f2c71961d643cd762e7acb1a5d7345f27cd0888351f3190fd5"
            + "403fd9bf");
    private static final PSSParameterSpec sha384WithRsaPssNoSaltVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 0, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha384 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha384 -pkeyopt rsa_pss_saltlen:206 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha384WithRsaPssMaxSaltVector2Signature = TestUtils.decodeHex(
            "def7c321790f55d1569ab008a127c95e64f4c78394cabd50d6c55694bd0b55e604adafaf4f2d917ff160"
            + "0ceee844fc698043bcab8335b0c6cbe6922909cfdbad1693c7be81680f7bc1c28cba5980aefb60222836"
            + "be377286024bf9145a6b324472332e7fa1fd07f2d99d037717fb0efff73768f68f9b2cebaf6c509f34b2"
            + "523b946f6016520abf954144839185a1f7f9174af7f1e89c75861244195c6531892afcbee8ecc9d741da"
            + "d9c98b9060ccb27abaa0eebe9ce7f227929c3c0f5cee3848cfff333580995da75a7aea967428367be133"
            + "7c78ec05720e5d165c7758a7313fba91a716fc31ca30e0f45d074a9c1d2b4eb87c67cb3469854e99418a"
            + "3585f21a");
    private static final PSSParameterSpec sha384WithRsaPssMaxSaltVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 206, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha512 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha512 -pkeyopt rsa_pss_saltlen:64 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha512WithRsaPssVector2Signature = TestUtils.decodeHex(
            "9fedf8ee305f30631d86d3ad1dd8d267e2436471988200842c881a28cda234170f348a10796ccbda2fdf"
            + "4d9801e8b3f5cd60eadea50c09a14ac46b09b3371f8a64812e2275243bc00e1f37c91e6faf3e9b3fa3c3"
            + "0bb9836002c629830916d93d84028120e9015b85c881256bcb7848653ad6959b622d84541294b7f01cb6"
            + "59cdc386e663d7999ac4bf8edd4610beab78c6304723b62c025e1f079654ee28c7ec57db9eefe411f804"
            + "a926c261f184eb94bd48cad184ce822ef64e176f78b90ba97dbce5f87da8767a8bb5054237da15e2c470"
            + "6e956047f90ff4a273f173bd0b9b44b6a9af502d5ca3726f85e80cf9e1e8f7c085145395f99e6505f022"
            + "7f4f4045");
    private static final PSSParameterSpec sha512WithRsaPssVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha512 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha512 -pkeyopt rsa_pss_saltlen:64 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha512WithRsaPssNoSaltVector2Signature = TestUtils.decodeHex(
            "49a3bc2e6796a53e3946d6a1a04f3a038f62f2d890ade23b4f988851410923ebf45d6a221212dc27e9f7"
            + "64a3de3ab0d6f2c6bc0ba2a1aab051da4f28a8eb346037f7507db8e7248eac0331b8e0db97e91b7e2799"
            + "934d46b3fed623b3ab3e33a1104e34275825b7baeebee06e54f7737b5a9c74eac77ec6f7d5320e2899d8"
            + "ef97628ae316ade2f4119117f33290cb3c89f420f12d74225064c2f4c40d186a0252148567a408e5bf65"
            + "15b35a88ebd475f95273a05eba376a612b168aa800bb4dfa04b8ab4da4fc9dcf638334aeaea67773a2b5"
            + "77ac000306d4df8161ce8ec1d599d52fe827fa847e57f1c9eb4ff992c6d0258a16d0ece533a6f9d50c7b"
            + "ecc65845");
    private static final PSSParameterSpec sha512WithRsaPssNoSaltVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 0, 1);

    /*
     * echo "This is a signed message from Kenny Root." | openssl sha512 -binary -out digest.bin \
     *     && openssl pkeyutl -sign -in digest.bin -inkey privkey.pem \
     *         -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha512 -pkeyopt rsa_pss_saltlen:190 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] sha512WithRsaPssMaxSaltVector2Signature = TestUtils.decodeHex(
            "909245a11e0f5ff68fa0be342962be4180f0b89f29638926c2221f60b6fc5a3e99b8c63b67339719c6ff"
            + "0ca9045af0029a190fea770d56380aed4eb757bdc9a3e8c07df6a34b6145065e56f5ef766bb7d4bba43c"
            + "52f80667f7c38c5edffe302ef8593c3beaa05d8f18731a2db15507c833ed8a5ec3ae5131c4fae8e9be2e"
            + "28aaeda84ba313b98257d1720da7f867b855f306aea769660b805665c7e960dc2d4b26a9ed54799e551d"
            + "ee7849a11f9b37c0bae64b3baf129932148c4deb08a4e3c6378b6e7ceca378ed4e36bca27d110ed05314"
            + "93165445797a1aa1ecf3123ffe68ff5a3fe71337eb600a8e4f54461982bfb7d2197178384ce3c4ea8f9b"
            + "e5ba06fc");
    private static final PSSParameterSpec sha512WithRsaPssMaxSaltVector2SignatureParameterSpec =
            new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 190, 1);

    @Test
    public void testGetCommonInstances_Success() throws Exception {
        assertNotNull(Signature.getInstance("SHA1withRSA"));
        assertNotNull(Signature.getInstance("SHA256withRSA"));
        assertNotNull(Signature.getInstance("SHA384withRSA"));
        assertNotNull(Signature.getInstance("SHA512withRSA"));
        assertNotNull(Signature.getInstance("NONEwithRSA"));
        assertNotNull(Signature.getInstance("MD5withRSA"));
        assertNotNull(Signature.getInstance("SHA1withDSA"));
    }

    private void verify(Signature sig, PublicKey key, byte[] data, byte[] signature)
            throws Exception {
        sig.initVerify(key);
        sig.update(data);

        assertTrue("Signature must match expected signature", sig.verify(signature));

        ByteBuffer heap = ByteBuffer.wrap(data);
        sig.initVerify(key);
        sig.update(heap);

        assertTrue("Signature must match expected signature", sig.verify(signature));

        ByteBuffer direct = ByteBuffer.allocateDirect(data.length);
        direct.put(data);
        direct.flip();
        sig.initVerify(key);
        sig.update(direct);

        assertTrue("Signature must match expected signature", sig.verify(signature));
    }

    @Test
    public void testVerify_SHA1withRSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA1withRSA");
        verify(sig, pubKey, vector1Data, sha1WithRsaVector1Signature);
    }

    @Test
    public void testVerify_SHA256withRSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA256withRSA");
        verify(sig, pubKey, vector2Data, sha256WithRsaVector2Signature);
    }

    @Test
    public void testVerify_SHA384withRSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA384withRSA");
        verify(sig, pubKey, vector2Data, sha384WithRsaVector2Signature);
    }

    @Test
    public void testVerify_SHA512withRSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA512withRSA");
        verify(sig, pubKey, vector2Data, sha512WithRsaVector2Signature);
    }

    @Test
    public void testVerify_MD5withRSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("MD5withRSA");
        verify(sig, pubKey, vector2Data, md5WithRsaVector2Signature);
    }

    @Test
    public void testVerify_SHA1withRSAPSS_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA1withRSA/PSS");
        sig.initVerify(pubKey);
        assertPSSAlgorithmParametersEquals(sha1WithRsaPssVector2SignatureParameterSpec,
                                           sig.getParameters());
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha1WithRsaPssVector2Signature));
    }

    @Test
    public void testVerify_SHA1withRSAPSS_NoSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA1withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha1WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha1WithRsaPssNoSaltVector2Signature));
    }

    @Test
    public void testVerify_SHA1withRSAPSS_MaxSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA1withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha1WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha1WithRsaPssMaxSaltVector2Signature));
    }

    @Test
    public void testVerify_SHA224withRSAPSS_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA224withRSA/PSS");
        sig.initVerify(pubKey);
        assertPSSAlgorithmParametersEquals(sha224WithRsaPssVector2SignatureParameterSpec,
                                           sig.getParameters());
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha224WithRsaPssVector2Signature));
    }

    @Test
    public void testVerify_SHA224withRSAPSS_NoSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA224withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha224WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha224WithRsaPssNoSaltVector2Signature));
    }

    @Test
    public void testVerify_SHA224withRSAPSS_MaxSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA224withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha224WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha224WithRsaPssMaxSaltVector2Signature));
    }

    @Test
    public void testVerify_SHA256withRSAPSS_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA256withRSA/PSS");
        sig.initVerify(pubKey);
        assertPSSAlgorithmParametersEquals(sha256WithRsaPssVector2SignatureParameterSpec,
                                           sig.getParameters());
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha256WithRsaPssVector2Signature));
    }

    @Test
    public void testVerify_SHA256withRSAPSS_NoSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA256withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha256WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha256WithRsaPssNoSaltVector2Signature));
    }

    @Test
    public void testVerify_SHA256withRSAPSS_MaxSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA256withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha256WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha256WithRsaPssMaxSaltVector2Signature));
    }

    @Test
    public void testVerify_SHA384withRSAPSS_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA384withRSA/PSS");
        sig.initVerify(pubKey);
        assertPSSAlgorithmParametersEquals(sha384WithRsaPssVector2SignatureParameterSpec,
                                           sig.getParameters());
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha384WithRsaPssVector2Signature));
    }

    @Test
    public void testVerify_SHA384withRSAPSS_NoSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA384withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha384WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha384WithRsaPssNoSaltVector2Signature));
    }

    @Test
    public void testVerify_SHA384withRSAPSS_MaxSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA384withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha384WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha384WithRsaPssMaxSaltVector2Signature));
    }

    @Test
    public void testVerify_SHA512withRSAPSS_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA512withRSA/PSS");
        sig.initVerify(pubKey);
        assertPSSAlgorithmParametersEquals(sha512WithRsaPssVector2SignatureParameterSpec,
                                           sig.getParameters());
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha512WithRsaPssVector2Signature));
    }

    @Test
    public void testVerify_SHA512withRSAPSS_NoSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA512withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha512WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha512WithRsaPssNoSaltVector2Signature));
    }

    @Test
    public void testVerify_SHA512withRSAPSS_MaxSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA512withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha512WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        assertTrue("Signature must verify", sig.verify(sha512WithRsaPssMaxSaltVector2Signature));
    }

    @Test
    public void testVerify_SHA1withRSA_Key_InitSignThenInitVerify_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        RSAPrivateKeySpec privKeySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(privKeySpec);

        Signature sig = Signature.getInstance("SHA1withRSA");

        // Start a signing operation
        sig.initSign(privKey);
        sig.update(vector2Data);

        // Switch to verify
        sig.initVerify(pubKey);
        sig.update(vector1Data);

        assertTrue("Signature must match expected signature",
                   sig.verify(sha1WithRsaVector1Signature));
    }

    @Test
    public void testVerify_SHA1withRSA_Key_TwoMessages_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(pubKey);

        sig.update(vector1Data);
        assertTrue("First signature must match expected signature",
                   sig.verify(sha1WithRsaVector1Signature));

        sig.update(vector2Data);
        assertTrue("Second signature must match expected signature",
                   sig.verify(sha1WithRsaVector2Signature));
    }

    @Test
    public void testVerify_SHA1withRSA_Key_WrongExpectedSignature_Failure() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(pubKey);
        sig.update(vector1Data);

        assertFalse("Signature should fail to verify", sig.verify(sha1WithRsaVector2Signature));
    }

    @Test
    public void testSign_SHA1withRSA_CrtKeyWithPublicExponent_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec keySpec =
                new RSAPrivateCrtKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT,
                                         RSA_2048_PRIVATE_EXPONENT, null, null, null, null, null);

        // The RI fails on this key which is totally unreasonable.
        final PrivateKey privKey;
        try {
            privKey = kf.generatePrivate(keySpec);
        } catch (NullPointerException e) {
            if (StandardNames.IS_RI) {
                return;
            } else {
                fail("Private key should be created");
                return;
            }
        }

        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(privKey);
        sig.update(vector1Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertArrayEquals("Signature should match expected", signature,
                          sha1WithRsaVector1Signature);

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.update(vector1Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA1withRSA_CrtKey_NoPrivateExponent_Failure() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec keySpec =
                new RSAPrivateCrtKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT, null,
                                         RSA_2048_PRIME_P, RSA_2048_PRIME_Q, null, null, null);

        // Failing on this key early is okay.
        final PrivateKey privKey;
        try {
            privKey = kf.generatePrivate(keySpec);
        } catch (NullPointerException | InvalidKeySpecException e) {
            return;
        }

        Signature sig = Signature.getInstance("SHA1withRSA");

        try {
            sig.initSign(privKey);
            fail("Should throw error when private exponent is not available");
        } catch (InvalidKeyException expected) {
        }
    }

    @Test
    public void testSign_SHA1withRSA_CrtKey_NoModulus_Failure() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec keySpec =
                new RSAPrivateCrtKeySpec(null, RSA_2048_PUBLIC_EXPONENT, RSA_2048_PRIVATE_EXPONENT,
                                         RSA_2048_PRIME_P, RSA_2048_PRIME_Q, null, null, null);

        // Failing on this key early is okay.
        final PrivateKey privKey;
        try {
            privKey = kf.generatePrivate(keySpec);
        } catch (NullPointerException | InvalidKeySpecException e) {
            return;
        }

        Signature sig = Signature.getInstance("SHA1withRSA");

        try {
            sig.initSign(privKey);
            fail("Should throw error when modulus is not available");
        } catch (InvalidKeyException expected) {
        }
    }

    @Test
    public void testSign_SHA1withRSA_Key_EmptyKey_Failure() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(null, null);

        // Failing on this key early is okay.
        final PrivateKey privKey;
        try {
            privKey = kf.generatePrivate(keySpec);
        } catch (NullPointerException | InvalidKeySpecException e) {
            return;
        }

        Signature sig = Signature.getInstance("SHA1withRSA");

        try {
            sig.initSign(privKey);
            fail("Should throw error when key is empty");
        } catch (InvalidKeyException expected) {
        }
    }

    private void sign(Signature sig, PrivateKey privKey, PublicKey pubKey, byte[] data,
                      byte[] signature) throws Exception {
        sig.initSign(privKey);
        sig.update(data);

        byte[] generatedSignature = sig.sign();
        assertNotNull("Signature must not be null", generatedSignature);
        assertArrayEquals("Signature should match expected", signature, generatedSignature);

        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue("Signature must verify correctly", sig.verify(generatedSignature));

        ByteBuffer heap = ByteBuffer.wrap(data);
        sig.initSign(privKey);
        sig.update(heap);

        generatedSignature = sig.sign();
        assertNotNull("Signature must not be null", generatedSignature);
        assertArrayEquals("Signature should match expected", signature, generatedSignature);

        heap.rewind();
        sig.initVerify(pubKey);
        sig.update(heap);
        assertTrue("Signature must verify correctly", sig.verify(generatedSignature));

        ByteBuffer direct = ByteBuffer.allocateDirect(data.length);
        direct.put(data);
        direct.flip();
        sig.initSign(privKey);
        sig.update(direct);

        generatedSignature = sig.sign();
        assertNotNull("Signature must not be null", generatedSignature);
        assertArrayEquals("Signature should match expected", signature, generatedSignature);

        direct.rewind();
        sig.initVerify(pubKey);
        sig.update(direct);
        assertTrue("Signature must verify correctly", sig.verify(generatedSignature));
    }

    @Test
    public void testSign_SHA1withRSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);
        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("SHA1withRSA");
        sign(sig, privKey, pubKey, vector1Data, sha1WithRsaVector1Signature);
    }

    @Test
    public void testSign_SHA224withRSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);
        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("SHA224withRSA");
        sign(sig, privKey, pubKey, vector2Data, sha224WithRsaVector2Signature);
    }

    @Test
    public void testSign_SHA256withRSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);
        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sign(sig, privKey, pubKey, vector2Data, sha256WithRsaVector2Signature);
    }

    @Test
    public void testSign_SHA384withRSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);
        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("SHA384withRSA");
        sign(sig, privKey, pubKey, vector2Data, sha384WithRsaVector2Signature);
    }

    @Test
    public void testSign_SHA512withRSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);
        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("SHA512withRSA");
        sign(sig, privKey, pubKey, vector2Data, sha512WithRsaVector2Signature);
    }

    @Test
    public void testSign_MD5withRSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);
        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("MD5withRSA");
        sign(sig, privKey, pubKey, vector2Data, md5WithRsaVector2Signature);
    }

    @Test
    public void testSign_SHA1withRSAPSS_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA1withRSA/PSS");
        sig.initSign(privKey);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha1WithRsaPssVector2SignatureParameterSpec,
                                           sig.getParameters());

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA1withRSAPSS_NoSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA1withRSA/PSS");
        sig.initSign(privKey);
        sig.setParameter(sha1WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha1WithRsaPssNoSaltVector2SignatureParameterSpec,
                                           sig.getParameters());
        assertArrayEquals("Signature should match expected", signature,
                          sha1WithRsaPssNoSaltVector2Signature);

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.setParameter(sha1WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA1withRSAPSS_MaxSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA1withRSA/PSS");
        sig.initSign(privKey);
        sig.setParameter(sha1WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha1WithRsaPssMaxSaltVector2SignatureParameterSpec,
                                           sig.getParameters());

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig = Signature.getInstance("SHA1withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha1WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA224withRSAPSS_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA224withRSA/PSS");
        sig.initSign(privKey);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha224WithRsaPssVector2SignatureParameterSpec,
                                           sig.getParameters());

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA224withRSAPSS_NoSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA224withRSA/PSS");
        sig.initSign(privKey);
        sig.setParameter(sha224WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha224WithRsaPssNoSaltVector2SignatureParameterSpec,
                                           sig.getParameters());
        assertArrayEquals("Signature should match expected", signature,
                          sha224WithRsaPssNoSaltVector2Signature);

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.setParameter(sha224WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA224withRSAPSS_MaxSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA224withRSA/PSS");
        sig.initSign(privKey);
        sig.setParameter(sha224WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha224WithRsaPssMaxSaltVector2SignatureParameterSpec,
                                           sig.getParameters());

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig = Signature.getInstance("SHA224withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha224WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA256withRSAPSS_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA256withRSA/PSS");
        sig.initSign(privKey);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha256WithRsaPssVector2SignatureParameterSpec,
                                           sig.getParameters());

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA256withRSAPSS_NoSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA256withRSA/PSS");
        sig.initSign(privKey);
        sig.setParameter(sha256WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha256WithRsaPssNoSaltVector2SignatureParameterSpec,
                                           sig.getParameters());
        assertArrayEquals("Signature should match expected", signature,
                          sha256WithRsaPssNoSaltVector2Signature);

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.setParameter(sha256WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA256withRSAPSS_MaxSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA256withRSA/PSS");
        sig.initSign(privKey);
        sig.setParameter(sha256WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha256WithRsaPssMaxSaltVector2SignatureParameterSpec,
                                           sig.getParameters());

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig = Signature.getInstance("SHA256withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha256WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA384withRSAPSS_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA384withRSA/PSS");
        sig.initSign(privKey);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha384WithRsaPssVector2SignatureParameterSpec,
                                           sig.getParameters());

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA384withRSAPSS_NoSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA384withRSA/PSS");
        sig.initSign(privKey);
        sig.setParameter(sha384WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha384WithRsaPssNoSaltVector2SignatureParameterSpec,
                                           sig.getParameters());
        assertArrayEquals("Signature should match expected", signature,
                          sha384WithRsaPssNoSaltVector2Signature);

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.setParameter(sha384WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA384withRSAPSS_MaxSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA384withRSA/PSS");
        sig.initSign(privKey);
        sig.setParameter(sha384WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha384WithRsaPssMaxSaltVector2SignatureParameterSpec,
                                           sig.getParameters());

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig = Signature.getInstance("SHA384withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha384WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA512withRSAPSS_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA512withRSA/PSS");
        sig.initSign(privKey);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha512WithRsaPssVector2SignatureParameterSpec,
                                           sig.getParameters());

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA512withRSAPSS_NoSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA512withRSA/PSS");
        sig.initSign(privKey);
        sig.setParameter(sha512WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha512WithRsaPssNoSaltVector2SignatureParameterSpec,
                                           sig.getParameters());
        assertArrayEquals("Signature should match expected", signature,
                          sha512WithRsaPssNoSaltVector2Signature);

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.setParameter(sha512WithRsaPssNoSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_SHA512withRSAPSS_MaxSalt_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA512withRSA/PSS");
        sig.initSign(privKey);
        sig.setParameter(sha512WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertPSSAlgorithmParametersEquals(sha512WithRsaPssMaxSaltVector2SignatureParameterSpec,
                                           sig.getParameters());

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig = Signature.getInstance("SHA512withRSA/PSS");
        sig.initVerify(pubKey);
        sig.setParameter(sha512WithRsaPssMaxSaltVector2SignatureParameterSpec);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testSign_NONEwithRSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("NONEwithRSA");
        sig.initSign(privKey);
        sig.update(vector1Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertArrayEquals("Signature should match expected", signature,
                          noneWithRsaVector1Signature);

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.update(vector1Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testVerify_NONEwithRSA_Key_WrongSignature_Failure() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("NONEwithRSA");
        sig.initVerify(pubKey);
        sig.update(vector1Data);
        assertFalse("Invalid signature must not verify",
                    sig.verify("Invalid".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testSign_NONEwithRSA_Key_DataTooLarge_Failure() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("NONEwithRSA");
        sig.initSign(privKey);

        final int oneTooBig = RSA_2048_MODULUS.bitLength() - 10;
        for (int i = 0; i < oneTooBig; i++) {
            sig.update((byte) i);
        }

        try {
            sig.sign();
            fail("Should throw exception when data is too large");
        } catch (SignatureException expected) {
        }
    }

    @Test
    public void testSign_NONEwithRSA_Key_DataTooLarge_SingleByte_Failure() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec keySpec =
                new RSAPrivateKeySpec(RSA_2048_MODULUS, RSA_2048_PRIVATE_EXPONENT);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("NONEwithRSA");
        sig.initSign(privKey);

        // This should make it two bytes too big.
        final int oneTooBig = RSA_2048_MODULUS.bitLength() - 10;
        for (int i = 0; i < oneTooBig; i++) {
            sig.update((byte) i);
        }

        try {
            sig.sign();
            fail("Should throw exception when data is too large");
        } catch (SignatureException expected) {
        }
    }

    @Test
    public void testVerify_NONEwithRSA_Key_DataTooLarge_Failure() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("NONEwithRSA");
        sig.initVerify(pubKey);

        // This should make it one bytes too big.
        final int oneTooBig = RSA_2048_MODULUS.bitLength() + 1;
        final byte[] vector = new byte[oneTooBig];
        for (int i = 0; i < oneTooBig; i++) {
            vector[i] = vector1Data[i % vector1Data.length];
        }
        sig.update(vector);

        assertFalse("Should not verify when signature is too large",
                    sig.verify(noneWithRsaVector1Signature));
    }

    @Test
    public void testVerify_NONEwithRSA_Key_DataTooLarge_SingleByte_Failure() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("NONEwithRSA");
        sig.initVerify(pubKey);

        // This should make it twice as big as it should be.
        final int tooBig = RSA_2048_MODULUS.bitLength() * 2;
        for (int i = 0; i < tooBig; i++) {
            sig.update(vector1Data[i % vector1Data.length]);
        }

        assertFalse("Should not verify when signature is too large",
                    sig.verify(noneWithRsaVector1Signature));
    }

    @Test
    public void testVerify_NONEwithRSA_Key_SignatureTooSmall_Failure() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("NONEwithRSA");
        sig.initVerify(pubKey);
        sig.update(vector1Data);

        assertFalse("Invalid signature should not verify",
                    sig.verify("Invalid sig".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testVerify_NONEwithRSA_Key_SignatureTooLarge_Failure() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");

        RSAPublicKeySpec pubKeySpec =
                new RSAPublicKeySpec(RSA_2048_MODULUS, RSA_2048_PUBLIC_EXPONENT);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("NONEwithRSA");
        sig.initVerify(pubKey);
        sig.update(vector1Data);

        byte[] invalidSignature = new byte[noneWithRsaVector1Signature.length * 2];
        System.arraycopy(noneWithRsaVector1Signature, 0, invalidSignature, 0,
                         noneWithRsaVector1Signature.length);
        System.arraycopy(noneWithRsaVector1Signature, 0, invalidSignature,
                         noneWithRsaVector1Signature.length, noneWithRsaVector1Signature.length);

        try {
            sig.verify(invalidSignature);
            fail("Should throw exception when signature is too large");
        } catch (SignatureException expected) {
        }
    }

    @Test
    public void testSign_NONEwithECDSA_Key_Success() throws Exception {
        KeyPair keys = keyPair("NONEwithECDSA");
        Signature sig = Signature.getInstance("NONEwithECDSA");

        sig.initSign(keys.getPrivate());
        sig.update(vector1Data);
        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);
        assertTrue("Signature must not be empty", signature.length > 0);

        sig.initVerify(keys.getPublic());
        sig.update(vector1Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testVerify_NONEwithECDSA_Key_Success() throws Exception {
        PublicKey pub = getNamedCurveEcPublicKey();
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        Signature sig = Signature.getInstance("NONEwithECDSA");

        // namedCurveSignature was signed using SHA1withECDSA, so NONEwithECDSA should
        // verify the digest
        sig.initVerify(pub);
        sig.update(sha1.digest(namedCurveVector));
        assertTrue(sig.verify(namedCurveSignature));
    }

    @Test
    public void testVerify_NONEwithECDSA_Key_WrongData_Failure() throws Exception {
        PublicKey pub = getNamedCurveEcPublicKey();
        Signature sig = Signature.getInstance("NONEwithECDSA");

        sig.initVerify(pub);
        sig.update(namedCurveVector);
        assertFalse(sig.verify(namedCurveSignature));
    }

    // Suppress ErrorProne's warning about the try block that doesn't call fail() but
    // expects an exception, it's intentional
    @SuppressWarnings("MissingFail")
    @Test
    public void testVerify_NONEwithECDSA_Key_SingleByte_Failure() throws Exception {
        PublicKey pub = getNamedCurveEcPublicKey();
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        Signature sig = Signature.getInstance("NONEwithECDSA");

        byte[] corrupted = new byte[namedCurveSignature.length];
        corrupted[0] = (byte) (corrupted[0] ^ 1);

        sig.initVerify(pub);
        sig.update(sha1.digest(namedCurveVector));
        try {
            assertFalse(sig.verify(corrupted));
        } catch (SignatureException expected) {
            // It's valid to either return false or throw an exception, accept either
        }
    }

    // Tests that an opaque key will be accepted by the ECDSA signature and will delegate to a
    // functioning alternative provider
    @Test
    public void test_NONEwithECDSA_OpaqueKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair kp = keyGen.generateKeyPair();

        // Insert this at #2 so that Conscrypt is still the first provider and CryptoUpcalls
        // has to drop to manual provider selection rather than relying on Signature's internals
        Security.insertProviderAt(new OpaqueProvider(), 2);
        try {
            Signature sig =
                    Signature.getInstance("NONEwithECDSA", TestUtils.getConscryptProvider());
            sig.initSign(OpaqueProvider.wrapKeyMarked(kp.getPrivate()));
            sig.update(new byte[] {1, 2, 3, 4, 5, 6, 7, 8});
            byte[] data = sig.sign();

            sig.initVerify(kp.getPublic());
            sig.update(new byte[] {1, 2, 3, 4, 5, 6, 7, 8});
            assertTrue(sig.verify(data));
        } finally {
            Security.removeProvider(OpaqueProvider.NAME);
        }
    }

    // Tests that an opaque key will be accepted by the ECDSA signature and that a broken
    // alternative provider that throws UnsupportedOperationException will be skipped and
    // a functioning provider that follows will work.
    @Test
    public void test_NONEwithECDSA_OpaqueKey_BrokenProvider() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair kp = keyGen.generateKeyPair();

        // Insert these at #2 so that Conscrypt is still the first provider and CryptoUpcalls
        // has to drop to manual provider selection rather than relying on Signature's internals
        Security.insertProviderAt(new OpaqueProvider(), 2);
        Security.insertProviderAt(new BrokenProvider(), 2);
        try {
            Signature sig =
                    Signature.getInstance("NONEwithECDSA", TestUtils.getConscryptProvider());
            sig.initSign(OpaqueProvider.wrapKeyMarked(kp.getPrivate()));
            sig.update(new byte[] {1, 2, 3, 4, 5, 6, 7, 8});
            byte[] data = sig.sign();

            sig.initVerify(kp.getPublic());
            sig.update(new byte[] {1, 2, 3, 4, 5, 6, 7, 8});
            assertTrue(sig.verify(data));
        } finally {
            Security.removeProvider(OpaqueProvider.NAME);
            Security.removeProvider(BrokenProvider.NAME);
        }
    }

    /*
     * These tests were generated with this DSA private key:
     *
     * -----BEGIN DSA PRIVATE KEY-----
     * MIIBugIBAAKBgQCeYcKJ73epThNnZB8JAf4kE1Pgt5CoTnb+iYJ/esU8TgwgVTCV
     * QoXhQH0njwcN6NyZ77MHlDTWfP+cvmnT60Q3UO9J+OJb2NEQhJfq46UcwE5pynA9
     * eLkW5f5hXYpasyxhtgE70AF8Mo3h82kOi1jGzwCU+EkqS+raAP9L0L5AIwIVAL/u
     * qg8SNFBy+GAT2PFBARClL1dfAoGAd9R6EsyBfn7rOvvmhm1aEB2tqU+5A10hGuQw
     * lXWOzV7RvQpF7uf3a2UCYNAurz28B90rjjPAk4DZK6dxV3a8jrng1/QjjUEal08s
     * G9VLZuj60lANF6s0MT2kiNiOqKduFwO3D2h8ZHuSuGPkmmcYgSfUCxNI031O9qiP
     * VhctCFECgYAz7i1DhjRGUkCdYQd5tVaI42lhXOV71MTYPbuFOIxTL/hny7Z0PZWR
     * A1blmYE6vrArDEhzpmRvDJZSIMzMfJjUIGu1KO73zpo9siK0xY0/sw5r3QC9txP2
     * 2Mv3BUIl5TLrs9outQJ0VMwldY2fElgCLWcSVkH44qZwWir1cq+cIwIUEGPDardb
     * pNvWlWgTDD6a6ZTby+M=
     * -----END DSA PRIVATE KEY-----
     *
     */

    private static final BigInteger DSA_PRIV =
            new BigInteger(TestUtils.decodeHex("1063c36ab75ba4dbd69568130c3e9ae994dbcbe3"));

    private static final BigInteger DSA_PUB = new BigInteger(TestUtils.decodeHex(
            "33ee2d4386344652409d610779b55688e369615ce57bd4c4d83dbb85388c532ff867cbb6743d95910356"
            + "e599813abeb02b0c4873a6646f0c965220cccc7c98d4206bb528eef7ce9a3db222b4c58d3fb30e6bdd00"
            + "bdb713f6d8cbf7054225e532ebb3da2eb5027454cc25758d9f1258022d67125641f8e2a6705a2af572af"
            + "9c23"));

    private static final BigInteger DSA_P = new BigInteger(TestUtils.decodeHex(
            "009e61c289ef77a94e1367641f0901fe241353e0b790a84e76fe89827f7ac53c4e0c205530954285e140"
            + "7d278f070de8dc99efb3079434d67cff9cbe69d3eb443750ef49f8e25bd8d1108497eae3a51cc04e69ca"
            + "703d78b916e5fe615d8a5ab32c61b6013bd0017c328de1f3690e8b58c6cf0094f8492a4beada00ff4bd0"
            + "be4023"));

    private static final BigInteger DSA_Q =
            new BigInteger(TestUtils.decodeHex("00bfeeaa0f12345072f86013d8f1410110a52f575f"));

    private static final BigInteger DSA_G = new BigInteger(TestUtils.decodeHex(
            "77d47a12cc817e7eeb3afbe6866d5a101dada94fb9035d211ae43095758ecd5ed1bd0a45eee7f76b6502"
            + "60d02eaf3dbc07dd2b8e33c09380d92ba7715776bc8eb9e0d7f4238d411a974f2c1bd54b66e8fad2500d"
            + "17ab34313da488d88ea8a76e1703b70f687c647b92b863e49a67188127d40b1348d37d4ef6a88f56172d"
            + "0851"));

    /**
     * A possible signature using SHA1withDSA of vector2Data. Note that DSS is
     * randomized, so this won't be the exact signature you'll get out of
     * another signing operation unless you use a fixed RNG.
     */
    private static final byte[] sha1WithDsaVector2Signature = TestUtils.decodeHex(
            "302d02150088efac2b8be261c62bead596bcb0a1300c1fed11021415c4fc826f17dc87827523d458dc73"
            + "3df351c057");

    /**
     * A possible signature using SHA224withDSA of vector2Data. Note that DSS is
     * randomized, so this won't be the exact signature you'll get out of
     * another signing operation unless you use a fixed RNG.
     */
    private static final byte[] sha224WithDsaVector2Signature = TestUtils.decodeHex(
            "302d021500ade56df5118d2e625d988ac4887ee6a34499ef490214153e32d6f9792c606ef9a978e74b87"
            + "089660deb5");

    /**
     * A possible signature using SHA256withDSA of vector2Data. Note that DSS is
     * randomized, so this won't be the exact signature you'll get out of
     * another signing operation unless you use a fixed RNG.
     */
    private static final byte[] sha256WithDsaVector2Signature = TestUtils.decodeHex(
            "302d02140ab17445e163436865bcca4527114d52fb2293dd02150098321a167749a778fde0f771d48050"
            + "a7dd94d16c");

    @Test
    public void testSign_SHA1withDSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("DSA");
        DSAPrivateKeySpec keySpec = new DSAPrivateKeySpec(DSA_PRIV, DSA_P, DSA_Q, DSA_G);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA1withDSA");
        sig.initSign(privKey);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);

        DSAPublicKeySpec pubKeySpec = new DSAPublicKeySpec(DSA_PUB, DSA_P, DSA_Q, DSA_G);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testVerify_SHA1withDSA_Key_Success() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("DSA");
        DSAPublicKeySpec pubKeySpec = new DSAPublicKeySpec(DSA_PUB, DSA_P, DSA_Q, DSA_G);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("SHA1withDSA");
        sig.initVerify(pubKey);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(sha1WithDsaVector2Signature));
    }

    @Test
    public void testSign_SHA224withDSA_Key_Success() throws Exception {
        TestUtils.assumeSHA2WithDSAAvailable();
        KeyFactory kf = KeyFactory.getInstance("DSA");
        DSAPrivateKeySpec keySpec = new DSAPrivateKeySpec(DSA_PRIV, DSA_P, DSA_Q, DSA_G);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA224withDSA");
        sig.initSign(privKey);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);

        DSAPublicKeySpec pubKeySpec = new DSAPublicKeySpec(DSA_PUB, DSA_P, DSA_Q, DSA_G);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testVerify_SHA224withDSA_Key_Success() throws Exception {
        TestUtils.assumeSHA2WithDSAAvailable();
        KeyFactory kf = KeyFactory.getInstance("DSA");
        DSAPublicKeySpec pubKeySpec = new DSAPublicKeySpec(DSA_PUB, DSA_P, DSA_Q, DSA_G);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("SHA224withDSA");
        sig.initVerify(pubKey);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(sha224WithDsaVector2Signature));
    }

    @Test
    public void testSign_SHA256withDSA_Key_Success() throws Exception {
        TestUtils.assumeSHA2WithDSAAvailable();
        KeyFactory kf = KeyFactory.getInstance("DSA");
        DSAPrivateKeySpec keySpec = new DSAPrivateKeySpec(DSA_PRIV, DSA_P, DSA_Q, DSA_G);
        PrivateKey privKey = kf.generatePrivate(keySpec);

        Signature sig = Signature.getInstance("SHA256withDSA");
        sig.initSign(privKey);
        sig.update(vector2Data);

        byte[] signature = sig.sign();
        assertNotNull("Signature must not be null", signature);

        DSAPublicKeySpec pubKeySpec = new DSAPublicKeySpec(DSA_PUB, DSA_P, DSA_Q, DSA_G);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);
        sig.initVerify(pubKey);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(signature));
    }

    @Test
    public void testVerify_SHA256withDSA_Key_Success() throws Exception {
        TestUtils.assumeSHA2WithDSAAvailable();
        KeyFactory kf = KeyFactory.getInstance("DSA");
        DSAPublicKeySpec pubKeySpec = new DSAPublicKeySpec(DSA_PUB, DSA_P, DSA_Q, DSA_G);
        PublicKey pubKey = kf.generatePublic(pubKeySpec);

        Signature sig = Signature.getInstance("SHA256withDSA");
        sig.initVerify(pubKey);
        sig.update(vector2Data);
        assertTrue("Signature must verify correctly", sig.verify(sha256WithDsaVector2Signature));
    }

    private static final byte[] namedCurveVector =
            "Satoshi Nakamoto".getBytes(Charset.defaultCharset());
    // $ echo -n "Satoshi Nakamoto" > signed
    // $ openssl dgst -ecdsa-with-SHA1 -sign key.pem -out sig signed
    private static final byte[] namedCurveSignature = TestUtils.decodeHex(
            "304402205b41ece6dcc1c5bfcfdae74658d99c08c5e783f3926c11ecc1a8bea5d95cdf27022061a7d5fc68"
            + "7287e2e02dd7c6723e2e27fe0555f789590a37e96b1bb0355b4df0");

    private static PublicKey getNamedCurveEcPublicKey() throws Exception {
        // These are the parameters for the BitCoin curve (secp256k1). See
        // https://en.bitcoin.it/wiki/Secp256k1.
        final BigInteger p = new BigInteger(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
        final BigInteger a = BigInteger.valueOf(0);
        final BigInteger b = BigInteger.valueOf(7);
        final BigInteger x = new BigInteger(
                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
        final BigInteger y = new BigInteger(
                "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
        final BigInteger order = new BigInteger(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        final int cofactor = 1;

        final ECParameterSpec spec = new ECParameterSpec(new EllipticCurve(new ECFieldFp(p), a, b),
                                                         new ECPoint(x, y), order, cofactor);

        // $ openssl ecparam -name secp256k1 -genkey > key.pem
        // $ openssl ec -text -noout < key.pem
        final BigInteger px = new BigInteger(
                "2d45572747a625db5fd23b30f97044a682f2d42d31959295043c1fa0034c8ed3", 16);
        final BigInteger py = new BigInteger(
                "4d330f52e4bba00145a331041c8bbcf300c4fbfdf3d63d8de7608155b2793808", 16);

        final KeyFactory factory = KeyFactory.getInstance("EC");
        ECPublicKeySpec keySpec = new ECPublicKeySpec(new ECPoint(px, py), spec);
        return factory.generatePublic(keySpec);
    }

    @Test
    public void testArbitraryCurve() throws Exception {
        final PublicKey pub = getNamedCurveEcPublicKey();

        Signature ecdsaVerify = Signature.getInstance("SHA1withECDSA");
        ecdsaVerify.initVerify(pub);
        ecdsaVerify.update(namedCurveVector);
        boolean result = ecdsaVerify.verify(namedCurveSignature);
        assertTrue(result);

        ecdsaVerify = Signature.getInstance("SHA1withECDSA");
        ecdsaVerify.initVerify(pub);
        ecdsaVerify.update("Not Satoshi Nakamoto".getBytes(StandardCharsets.UTF_8));
        result = ecdsaVerify.verify(namedCurveSignature);
        assertFalse(result);
    }

    private static void assertPSSAlgorithmParametersEquals(PSSParameterSpec expectedSpec,
                                                           AlgorithmParameters actual)
            throws InvalidParameterSpecException {
        assertNotNull(actual);
        assertEqualsIgnoreCase("PSS", actual.getAlgorithm());
        PSSParameterSpec actualSpec = actual.getParameterSpec(PSSParameterSpec.class);
        assertPSSParameterSpecEquals(expectedSpec, actualSpec);
    }

    private static void assertPSSParameterSpecEquals(PSSParameterSpec expected,
                                                     PSSParameterSpec actual) {
        assertEqualsIgnoreCase(expected.getDigestAlgorithm(), actual.getDigestAlgorithm());
        assertEqualsIgnoreCase(expected.getMGFAlgorithm(), actual.getMGFAlgorithm());
        if (!"MGF1".equalsIgnoreCase(expected.getMGFAlgorithm())) {
            fail("Unsupported MGF algorithm: " + expected.getMGFAlgorithm());
        }
        MGF1ParameterSpec expectedMgfParams = (MGF1ParameterSpec) expected.getMGFParameters();
        MGF1ParameterSpec actualMgfParams = (MGF1ParameterSpec) actual.getMGFParameters();
        assertEqualsIgnoreCase(expectedMgfParams.getDigestAlgorithm(),
                               actualMgfParams.getDigestAlgorithm());
        assertEquals(expected.getSaltLength(), actual.getSaltLength());
        assertEquals(expected.getTrailerField(), actual.getTrailerField());
    }

    private static void assertEqualsIgnoreCase(String expected, String actual) {
        if (expected == null) {
            if (actual == null) {
                return;
            }
            fail("Expected null, actual: <" + actual + ">");
        } else if (actual == null) {
            fail("Expected: <" + expected + ">, actual: null");
        } else {
            if (!expected.equalsIgnoreCase(actual)) {
                fail("Expected: <" + expected + ">, actual: <" + actual + ">");
            }
        }
    }
}
