/*
 * Copyright (C) 2025 The Android Open Source Project
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

import static org.conscrypt.TestUtils.decodeBase64;
import static org.conscrypt.TestUtils.decodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

@RunWith(JUnit4.class)
public class MlDsaTest {
    private final Provider conscryptProvider = TestUtils.getConscryptProvider();

    private static final String ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18";
    private static final String ML_DSA_87_OID = "2.16.840.1.101.3.4.3.19";

    @BeforeClass
    public static void setUp() {
        TestUtils.assumeAllowsUnsignedCrypto();
    }

    public static final class RawKeySpec extends EncodedKeySpec {
        public RawKeySpec(byte[] encoded) {
            super(encoded);
        }

        @Override
        public String getFormat() {
            return "raw";
        }
    }

    // Example from https://openjdk.org/jeps/497.
    @Test
    public void example_works() throws Exception {
        // KeyPairGenerator with generic "ML-DSA" will use ML-DSA-65 by default.
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] msg = new byte[123];
        Signature ss = Signature.getInstance("ML-DSA", conscryptProvider);
        ss.initSign(privateKey);
        ss.update(msg);
        byte[] sig = ss.sign();

        Signature sv = Signature.getInstance("ML-DSA", conscryptProvider);
        sv.initVerify(publicKey);
        sv.update(msg);
        boolean verified = sv.verify(sig);
        assertTrue(verified);
    }

    @Test
    public void emptyMessage_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-65", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] emptyMessage = new byte[0];

        Signature signature = Signature.getInstance("ML-DSA-65", conscryptProvider);

        signature.initSign(keyPair.getPrivate());
        signature.update(emptyMessage);
        byte[] sig = signature.sign();

        signature.initVerify(keyPair.getPublic());
        signature.update(emptyMessage);
        assertTrue(signature.verify(sig));

        // Create a signature without calling update.
        signature.initSign(keyPair.getPrivate());
        byte[] sig2 = signature.sign();

        signature.initVerify(keyPair.getPublic());
        assertTrue(signature.verify(sig2));

        signature.initVerify(keyPair.getPublic());
        signature.update(emptyMessage);
        assertTrue(signature.verify(sig2));
    }

    @Test
    public void mldsa65KeyPair_signVerify_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-65", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        assertEquals("ML-DSA", privateKey.getAlgorithm());
        assertEquals("ML-DSA", publicKey.getAlgorithm());

        for (String signAlgorithm : new String[] {"ML-DSA-65", "ML-DSA", ML_DSA_65_OID}) {
            byte[] msg = new byte[123];
            Signature ss = Signature.getInstance(signAlgorithm, conscryptProvider);
            ss.initSign(privateKey);
            ss.update(msg);
            byte[] sig = ss.sign();
            assertEquals(3309, sig.length);

            for (String verifyAlgorithm : new String[] {"ML-DSA-65", "ML-DSA", ML_DSA_65_OID}) {
                Signature sv = Signature.getInstance(verifyAlgorithm, conscryptProvider);
                sv.initVerify(publicKey);
                sv.update(msg);
                boolean verified = sv.verify(sig);
                assertTrue(verified);
            }
        }

        // ML-DSA-87 does not support ML-DSA-65 keys.
        Signature s87 = Signature.getInstance("ML-DSA-87", conscryptProvider);
        assertThrows(InvalidKeyException.class, () -> s87.initSign(privateKey));
        assertThrows(InvalidKeyException.class, () -> s87.initVerify(publicKey));
    }

    @Test
    public void mldsa87KeyPair_signVerify_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-87", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        assertEquals("ML-DSA", privateKey.getAlgorithm());
        assertEquals("ML-DSA", publicKey.getAlgorithm());

        for (String signAlgorithm : new String[] {"ML-DSA-87", "ML-DSA", ML_DSA_87_OID}) {
            byte[] msg = new byte[123];
            Signature ss = Signature.getInstance(signAlgorithm, conscryptProvider);
            ss.initSign(privateKey);
            ss.update(msg);
            byte[] sig = ss.sign();
            assertEquals(4627, sig.length);

            for (String verifyAlgorithm : new String[] {"ML-DSA-87", "ML-DSA", ML_DSA_87_OID}) {
                Signature sv = Signature.getInstance(verifyAlgorithm, conscryptProvider);
                sv.initVerify(publicKey);
                sv.update(msg);
                boolean verified = sv.verify(sig);
                assertTrue(verified);
            }
        }

        // ML-DSA-65 does not support ML-DSA-87 signatures.
        Signature s65 = Signature.getInstance("ML-DSA-65", conscryptProvider);
        assertThrows(InvalidKeyException.class, () -> s65.initSign(privateKey));
        assertThrows(InvalidKeyException.class, () -> s65.initVerify(publicKey));
    }

    @Test
    public void mldsa65KeyPair_toAndFromRaw_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-65", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        for (String keyFactoryAlgorithm : new String[] {"ML-DSA-65", "ML-DSA", ML_DSA_65_OID}) {
            KeyFactory keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm, conscryptProvider);

            EncodedKeySpec privateKeySpec =
                    keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
            assertEquals("raw", privateKeySpec.getFormat());
            assertEquals(32, privateKeySpec.getEncoded().length);

            EncodedKeySpec publicKeySpec =
                    keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
            assertEquals("raw", publicKeySpec.getFormat());
            assertEquals(1952, publicKeySpec.getEncoded().length);

            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            assertEquals(privateKey, keyPair.getPrivate());
            assertEquals(publicKey, keyPair.getPublic());
        }

        // ML-DSA-87 key factory must not support ML-DSA-65 keys.
        KeyFactory keyFactory87 = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory87.getKeySpec(keyPair.getPrivate(), RawKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory87.getKeySpec(keyPair.getPublic(), RawKeySpec.class));
    }

    @Test
    public void mldsa87KeyPair_toAndFromRaw_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-87", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        for (String keyFactoryAlgorithm : new String[] {"ML-DSA-87", ML_DSA_87_OID}) {
            KeyFactory keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm, conscryptProvider);

            EncodedKeySpec privateKeySpec =
                    keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
            assertEquals("raw", privateKeySpec.getFormat());
            assertEquals(32, privateKeySpec.getEncoded().length);

            EncodedKeySpec publicKeySpec =
                    keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
            assertEquals("raw", publicKeySpec.getFormat());
            assertEquals(2592, publicKeySpec.getEncoded().length);

            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            assertEquals(privateKey, keyPair.getPrivate());
            assertEquals(publicKey, keyPair.getPublic());
        }

        {
            // The generic ML-DSA algorithm supports exporting ML-DSA-87 keys.
            KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", conscryptProvider);

            EncodedKeySpec privateKeySpec =
                    keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
            assertEquals("raw", privateKeySpec.getFormat());
            assertEquals(32, privateKeySpec.getEncoded().length);

            EncodedKeySpec publicKeySpec =
                    keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
            assertEquals("raw", publicKeySpec.getFormat());
            assertEquals(2592, publicKeySpec.getEncoded().length);

            // Importing the private key works, but the generated key will be a ML-DSA-65 key.
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            assertNotEquals(privateKey, keyPair.getPrivate());

            // This fails because the key factory expects a ML-DSA-65 key, which has a different
            // length.
            assertThrows(
                    InvalidKeySpecException.class, () -> keyFactory.generatePublic(publicKeySpec));
        }

        // ML-DSA-65 key factory must not support ML-DSA-87 keys.
        KeyFactory keyFactory65 = KeyFactory.getInstance("ML-DSA-65", conscryptProvider);
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory65.getKeySpec(keyPair.getPrivate(), RawKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory65.getKeySpec(keyPair.getPublic(), RawKeySpec.class));
    }

    @Test
    public void generateFromInvalidRawKey_throws() throws Exception {
        for (String keyFactoryAlgorithm : new String[] {"ML-DSA-65", "ML-DSA-87", "ML-DSA"}) {
            KeyFactory keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm, conscryptProvider);

            assertThrows(InvalidKeySpecException.class, () -> keyFactory.generatePrivate(null));
            assertThrows(InvalidKeySpecException.class, () -> keyFactory.generatePublic(null));

            byte[] invalidRawKey = new byte[42];
            assertThrows(InvalidKeySpecException.class,
                    () -> keyFactory.generatePrivate(new RawKeySpec(invalidRawKey)));
            assertThrows(InvalidKeySpecException.class,
                    () -> keyFactory.generatePublic(new RawKeySpec(invalidRawKey)));
        }
    }

    /** Helper class to test KeyFactory.translateKey. */
    static class TestPublicKey implements PublicKey {
        public TestPublicKey(byte[] x509encoded) {
            this.x509encoded = x509encoded;
        }

        private final byte[] x509encoded;

        @Override
        public String getAlgorithm() {
            return "ML-DSA";
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            return x509encoded;
        }
    }

    /** Helper class to test KeyFactory.translateKey. */
    static class TestPrivateKey implements PrivateKey {
        public TestPrivateKey(byte[] pkcs8encoded) {
            this.pkcs8encoded = pkcs8encoded;
        }

        private final byte[] pkcs8encoded;

        @Override
        public String getAlgorithm() {
            return "ML-DSA";
        }

        @Override
        public String getFormat() {
            return "PKCS#8";
        }

        @Override
        public byte[] getEncoded() {
            return pkcs8encoded;
        }
    }

    @Test
    public void mldsa65KeyPair_x509AndPkcs8() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-65", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        assertEquals("PKCS#8", keyPair.getPrivate().getFormat());
        assertEquals(54, keyPair.getPrivate().getEncoded().length);

        assertEquals("X.509", keyPair.getPublic().getFormat());
        assertEquals(1974, keyPair.getPublic().getEncoded().length);

        for (String algorithm : new String[] {"ML-DSA-65", "ML-DSA"}) {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm, conscryptProvider);

            PKCS8EncodedKeySpec privateKeySpec =
                    keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class);
            assertEquals("PKCS#8", privateKeySpec.getFormat());
            assertArrayEquals(privateKeySpec.getEncoded(), keyPair.getPrivate().getEncoded());

            X509EncodedKeySpec publicKeySpec =
                    keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class);
            assertEquals("X.509", publicKeySpec.getFormat());
            assertArrayEquals(publicKeySpec.getEncoded(), keyPair.getPublic().getEncoded());

            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            assertEquals(privateKey, keyPair.getPrivate());
            assertEquals(publicKey, keyPair.getPublic());

            assertEquals(keyPair.getPrivate(), keyFactory.translateKey(keyPair.getPrivate()));
            assertEquals(keyPair.getPrivate(),
                    keyFactory.translateKey(new TestPrivateKey(keyPair.getPrivate().getEncoded())));
            assertEquals(keyPair.getPublic(), keyFactory.translateKey(keyPair.getPublic()));
            assertEquals(keyPair.getPublic(),
                    keyFactory.translateKey(new TestPublicKey(keyPair.getPublic().getEncoded())));
        }

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                ()
                        -> keyFactory.generatePrivate(
                                new RawKeySpec(keyPair.getPrivate().getEncoded())));
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.generatePublic(new RawKeySpec(keyPair.getPublic().getEncoded())));

        assertThrows(
                InvalidKeyException.class, () -> keyFactory.translateKey(keyPair.getPrivate()));
        assertThrows(InvalidKeyException.class,
                ()
                        -> keyFactory.translateKey(
                                new TestPrivateKey(keyPair.getPrivate().getEncoded())));
        assertThrows(InvalidKeyException.class, () -> keyFactory.translateKey(keyPair.getPublic()));
        assertThrows(InvalidKeyException.class,
                () -> keyFactory.translateKey(new TestPublicKey(keyPair.getPublic().getEncoded())));
    }

    @Test
    public void mldsa87KeyPair_x509AndPkcs8() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-87", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();
        assertEquals("PKCS#8", keyPair.getPrivate().getFormat());
        assertEquals(54, keyPair.getPrivate().getEncoded().length);

        assertEquals("X.509", keyPair.getPublic().getFormat());
        assertEquals(2614, keyPair.getPublic().getEncoded().length);

        for (String algorithm : new String[] {"ML-DSA-87", "ML-DSA"}) {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm, conscryptProvider);

            PKCS8EncodedKeySpec privateKeySpec =
                    keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class);
            assertEquals("PKCS#8", privateKeySpec.getFormat());
            assertArrayEquals(privateKeySpec.getEncoded(), keyPair.getPrivate().getEncoded());

            X509EncodedKeySpec publicKeySpec =
                    keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class);
            assertEquals("X.509", publicKeySpec.getFormat());
            assertArrayEquals(publicKeySpec.getEncoded(), keyPair.getPublic().getEncoded());

            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            assertEquals(privateKey, keyPair.getPrivate());
            assertEquals(publicKey, keyPair.getPublic());

            assertEquals(keyPair.getPrivate(), keyFactory.translateKey(keyPair.getPrivate()));
            assertEquals(keyPair.getPrivate(),
                    keyFactory.translateKey(new TestPrivateKey(keyPair.getPrivate().getEncoded())));
            assertEquals(keyPair.getPublic(), keyFactory.translateKey(keyPair.getPublic()));
            assertEquals(keyPair.getPublic(),
                    keyFactory.translateKey(new TestPublicKey(keyPair.getPublic().getEncoded())));
        }

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-65", conscryptProvider);
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class,
                ()
                        -> keyFactory.generatePrivate(
                                new RawKeySpec(keyPair.getPrivate().getEncoded())));
        assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.generatePublic(new RawKeySpec(keyPair.getPublic().getEncoded())));

        assertThrows(
                InvalidKeyException.class, () -> keyFactory.translateKey(keyPair.getPrivate()));
        assertThrows(InvalidKeyException.class,
                ()
                        -> keyFactory.translateKey(
                                new TestPrivateKey(keyPair.getPrivate().getEncoded())));
        assertThrows(InvalidKeyException.class, () -> keyFactory.translateKey(keyPair.getPublic()));
        assertThrows(InvalidKeyException.class,
                () -> keyFactory.translateKey(new TestPublicKey(keyPair.getPublic().getEncoded())));
    }

    @Test
    public void mldsa65_privateKeyFromSeedOnlyPkcs8_works() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", conscryptProvider);

        // From:
        // https://datatracker.ietf.org/doc/html/rfc9881#appendix-C.1.2.1
        String privateKeyBase64 =
                "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
        byte[] pkcs8EncodedPrivateKey = decodeBase64(privateKeyBase64);
        assertEquals(54, pkcs8EncodedPrivateKey.length);

        PrivateKey privateKey =
                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedPrivateKey));
        assertEquals("ML-DSA", privateKey.getAlgorithm());
        assertArrayEquals(
                decodeHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                keyFactory.getKeySpec(privateKey, RawKeySpec.class).getEncoded());

        // From:
        // https://datatracker.ietf.org/doc/html/rfc9881#name-example-public-keys
        String publicKeyBase64 = "MIIHsjALBglghkgBZQMEAxIDggehAEhoPZGXjjHrPd24sEc0gtK4il9iWUn9j1il"
                + "YeaWvUwn0Fs427Lt8B5mTv2Bvh6ok2iM5oqi1RxZWPi7xutOie5n0sAyCVTVchLK"
                + "xyKf8dbq8DkovVFRH42I2EdzbH3icw1ZeOVBBxMWCXiGdxG/VTmgv8TDUMK+Vyuv"
                + "DuLi+xbM/qCAKNmaxJrrt1k33c4RHNq2L/886ouiIz0eVvvFxaHnJt5j+t0q8Bax"
                + "GRd/o9lxotkncXP85VtndFrwt8IdWX2+uT5qMvNBxJpai+noJQiNHyqkUVXWyK4V"
                + "Nn5OsAO4/feFEHGUlzn5//CQI+r0UQTSqEpFkG7tRnGkTcKNJ5h7tV32np6FYfYa"
                + "gKcmmVA4Zf7Zt+5yqOF6GcQIFE9LKa/vcDHDpthXFhC0LJ9CEkWojxl+FoErAxFZ"
                + "tluWh+Wz6TTFIlrpinm6c9Kzmdc1EO/60Z5TuEUPC6j84QEv2Y0mCnSqqhP64kmg"
                + "BrHDT1uguILyY3giL7NvIoPCQ/D/618btBSgpw1V49QKVrbLyIrh8Dt7KILZje6i"
                + "jhRcne39jq8c7y7ZSosFD4lk9G0eoNDCpD4N2mGCrb9PbtF1tnQiV4Wb8i86QX7P"
                + "H52JMXteU51YevFrnhMT4EUU/6ZLqLP/K4Mh+IEcs/sCLI9kTnCkuAovv+5gSrtz"
                + "eQkeqObFx038AoNma0DAeThwAoIEoTa/XalWjreY00kDi9sMEeA0ReeEfLUGnHXP"
                + "KKxgHHeZ2VghDdvLIm5Rr++fHeR7Bzhz1tP5dFa+3ghQgudKKYss1I9LMJMVXzZs"
                + "j6YBxq+FjfoywISRsqKYh/kDNZSaXW7apnmIKjqV1r9tlwoiH0udPYy/OEr4GqyV"
                + "4rMpTgR4msg3J6XcBFWflq9B2KBTUW/u7rxSdG62qygZ4JEIcQ2DXwEfpjBlhyrT"
                + "NNXN/7KyMQUH6S/Jk64xfal/TzCc2vD2ftmdkCFVdgg4SflTskbX/ts/22dnmFCl"
                + "rUBOZBR/t89Pau3dBa+0uDSWjR/ogBSWDc5dlCI2Um4SpHjWnl++aXAxCzCMBoRQ"
                + "GM/HsqtDChOmsax7sCzMuz2RGsLxEGhhP74Cm/3OAs9c04lQ7XLIOUTt+8dWFa+H"
                + "+GTAUfPFVFbFQShjpAwG0dq1Yr3/BXG408ORe70wCIC7pemYI5uV+pG31kFtTzmL"
                + "OtvNMJg+01krTZ731CNv0A9Q2YqlOiNaxBcnIPd9lhcmcpgM/o/3pacCeD7cK6Mb"
                + "IlkBWhEvx/RoqcL5RkA5AC0w72eLTLeYvBFiFr96mnwYugO3tY/QdRXTEVBJ02FL"
                + "56B+dEMAdQ3x0sWHUziQWer8PXhczdMcB2SL7cA6XDuK1G0GTVnBPVc3Ryn8TilT"
                + "YuKlGRIEUwQovBUir6KP9f4WVeMEylvIwnrQ4MajndTfKJVsFLOMyTaCzv5AK71e"
                + "gtKcRk5E6103tI/FaN/gzG6OFrrqBeUTVZDxkpTnPoNnsCFtu4FQMLneVZE/CAOc"
                + "QjUcWeVRXdWvjgiaFeYl6Pbe5jk4bEZJfXomMoh3TeWBp96WKbQbRCQUH5ePuDMS"
                + "CO/ew8bg3jm8VwY/Pc1sRwNzwIiR6inLx8xtZIO4iJCDrOhqp7UbHCz+birRjZfO"
                + "NvvFbqQvrpfmp6wRSGRHjDZt8eux57EakJhQT9WXW98fSdxwACtjwXOanSY/utQH"
                + "P2qfbCuK9LTDMqEDoM/6Xe6y0GLKPCFf02ACa+fFFk9KRCTvdJSIBNZvRkh3Msgg"
                + "LHlUeGR7TqcdYnwIYCTMo1SkHwh3s48Zs3dK0glcjaU7Bp4hx2ri0gB+FnGe1ACA"
                + "0zT32lLp9aWZBDnK8IOpW4M/Aq0QoIwabQ8mDAByhb1KL0dwOlrvRlKH0lOxisIl"
                + "FDFiEP9WaBSxD4eik9bxmdPDlZmQ0MEmi09Q1fn877vyN70MKLgBgtZll0HxTxC/"
                + "uyG7oSq2IKojlvVsBoa06pAXmQIkIWsv6K12xKkUju+ahqNjWmqne8Hc+2+6Wad9"
                + "/am3Uw3AyoZIyNlzc44Burjwi0kF6EqkZBvWAkEM2XUgJl8vIx8rNeFesvoE0r2U"
                + "1ad6uvHg4WEBCpkAh/W0bqmIsrwFEv2g+pI9rdbEXFMB0JSDZzJltasuEPS6Ug9r"
                + "utVkpcPV4nvbCA99IOEylqMYGVTDnGSclD6+F99cH3quCo/hJsR3WFpdTWSKDQCL"
                + "avXozTG+aakpbU8/0l7YbyIeS5P2X1kplnUzYkuSNXUMMHB1ULWFNtEJpxMcWlu+"
                + "SlcVVnwSU0rsdmB2Huu5+uKJHHdFibgOVmrVV93vc2cZa3In6phw7wnd/seda5MZ"
                + "poebUgXXa/erpazzOvtZ0X/FTmg4PWvloI6bZtpT3N4Ai7KUuFgr0TLNzEmVn9vC"
                + "HlJyGIDIrQNSx58DpDu9hMTN/cbFKQBeHnzZo0mnFoo1Vpul3qgYlo1akUZr1uZO"
                + "IL9iQXGYr8ToHCjdd+1AKCMjmLUvvehryE9HW5AWcQziqrwRoGtNuskB7BbPNlyj"
                + "8tU4E5SKaToPk+ecRspdWm3KPSjKUK0YvRP8pVBZ3ZsYX3n5xHGWpOgbIQS8RgoF"
                + "HgLy6ERP";
        byte[] x509EncodedPublicKey = decodeBase64(publicKeyBase64);

        PublicKey publicKey =
                keyFactory.generatePublic(new X509EncodedKeySpec(x509EncodedPublicKey));
        assertEquals("ML-DSA", publicKey.getAlgorithm());

        // Test that privateKey and publicKey are a ML-DSA-65 key pair.
        byte[] message = new byte[42];

        Signature signer = Signature.getInstance("ML-DSA-65", conscryptProvider);
        signer.initSign(privateKey);
        signer.update(message);
        byte[] sig = signer.sign();
        assertEquals(3309, sig.length);

        Signature verifier = Signature.getInstance("ML-DSA-65", conscryptProvider);
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertTrue(verifier.verify(sig));
    }

    @Test
    public void mldsa87_privateKeyFromSeedOnlyPkcs8_works() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", conscryptProvider);

        // From:
        // https://datatracker.ietf.org/doc/html/rfc9881#appendix-C.1.3.1
        String privateKeyBase64 =
                "MDQCAQAwCwYJYIZIAWUDBAMTBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
        byte[] pkcs8EncodedPrivateKey = decodeBase64(privateKeyBase64);
        assertEquals(54, pkcs8EncodedPrivateKey.length);

        PrivateKey privateKey =
                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedPrivateKey));
        assertEquals("ML-DSA", privateKey.getAlgorithm());
        assertArrayEquals(
                decodeHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                keyFactory.getKeySpec(privateKey, RawKeySpec.class).getEncoded());

        // From:
        // https://datatracker.ietf.org/doc/html/rfc9881#name-example-public-keys
        String publicKeyBase64 = "MIIKMjALBglghkgBZQMEAxMDggohAJeSvOwvJDBoaoL8zzwvX/Zl53HXq0G5AljP"
                + "p+kOyXEkpzsyO5uiGrZNdnxDP1pSHv/hj4bkahiJUsRGfgSLcp5/xNEV5+SNoYlt"
                + "X+EZsQ3N3vYssweVQHS0IzblKDbeYdqUH4036misgQb6vhkHBnmvYAhTcSD3B5O4"
                + "6pzA5ue3tMmlx0IcYPJEUboekz2xou4Wx5VZ8hs9G4MFhQqkKvuxPx9NW59INfnY"
                + "ffzrFi0O9Kf9xMuhdDzRyHu0ln2hbMh2S2Vp347lvcv/6aTgV0jm/fIlr55O63dz"
                + "ti6Phfm1a1SJRVUYRPvYmAakrDab7S0lYQD2iKatXgpwmCbcREnpHiPFUG5kI2Hv"
                + "WjE3EvebxLMYaGHKhaS6sX5/lD0bijM6o6584WtEDWAY+eBNr1clx/GpP60aWie2"
                + "eJW9JJqpFoXeIK8yyLfiaMf5aHfQyFABE1pPCo8bgmT6br5aNJ2K7K0aFimczy/Z"
                + "x7hbrOLO06oSdrph7njtflyltnzdRYqTVAMOaru6v1agojFv7J26g7UdQv0xZ/Hg"
                + "+QhV1cZlCbIQJl3B5U7ES0O6fPmu8Ri0TYCRLOdRZqZlHhFs6+SSKacGLAmTH3Gr"
                + "0ik/dvfvwyFbqXgAA35Y5HC9u7Q8GwQ56vecVNk7RKrJ7+n74VGHTPsqZMvuKMxM"
                + "D+d3Xl2HDxwC5bLjxQBMmV8kybd5y3U6J30Ocf1CXra8LKVs4SnbUfcHQPMeY5dr"
                + "UMcxLpeX14xbGsJKX6NHzJFuCoP1w7Z1zTC4Hj+hC5NETgc5dXHM6Yso2lHbkFa8"
                + "coxbCxGB4vvTh7THmrGl/v7ONxZ693LdrRTrTDmC2lpZ0OnrFz7GMVCRFwAno6te"
                + "9qoSnLhYVye5NYooUB1xOnLz8dsxcUKG+bZAgBOvBgRddVkvwLfdR8c+2cdbEenX"
                + "xp98rfwygKkGLFJzxDvhw0+HRIhkzqe1yX1tMvWb1fJThGU7tcT6pFvqi4lAKEPm"
                + "Rba5Jp4r2YjdrLAzMo/7BgRQ998IAFPmlpslHodezsMs/FkoQNaatpp14Gs3nFNd"
                + "lSZrCC9PCckxYrM7DZ9zB6TqqlIQRDf+1m+O4+q71F1nslqBM/SWRotSuv/b+tk+"
                + "7xqYGLXkLscieIo9jTUp/Hd9K6VwgB364B7IgwKDfB+54DVXJ2Re4QRsP5Ffaugt"
                + "rU+2sDVqRlGP/INBVcO0/m2vpsyKXM9TxzoISdjUT33PcnVOcOG337RHu070nRpx"
                + "j2Fxu84gCVDgzpJhBrFRo+hx1c5JcxvWZQqbDKly2hxfE21Egg6mODwI87OEzyM4"
                + "54nFE/YYzFaUpvDO4QRRHh7XxfI6Hr/YoNuEJFUyQBVtv2IoMbDGQ9HFUbbz96mN"
                + "KbhcLeBaZfphXu4WSVvZBzdnIRW1PpHF2QAozz8ak5U6FT3lO0QITpzP9rc2aTkm"
                + "2u/rstd6pa1om5LzFoZmnfFtFxXMWPeiz7ct0aUekvglmTp0Aivn6etgVGVEVwlN"
                + "FJKPICFeeyIqxWtRrb7I2L22mDl5p+OiG0S10VGMqX0LUZX1HtaiQ1DIl0fh7epR"
                + "tEjj6RRwVM6SeHPJDbOU2GiI4H3/F3WT1veeFSMCIErrA74jhq8+JAeL0CixaJ9e"
                + "FHyfRSyM6wLsWcydtjoDV2zur+mCOQI4l9oCNmMKU8Def0NaGYaXkvqzbnueY1dg"
                + "8JBp5kMucAA1rCoCh5//Ch4b7FIgRxk9lOtd8e/VPuoRRMp4lAhS9eyXJ5BLNm7e"
                + "T14tMx+tX8KC6ixH6SMUJ3HD3XWoc1dIfe+Z5fGOnZ7WI8F10CiIxR+CwHqA1UcW"
                + "s8PCvb4unwqbuq6+tNUpNodkBvXADo5LvQpewFeX5iB8WrbIjxpohCG9BaEU9Nfe"
                + "KsJB+g6L7f9H92Ldy+qpEAT40x6FCVyBBUmUrTgm40S6lgQIEPwLKtHeSM+t4ALG"
                + "LlpJoHMas4NEvBY23xa/YH1WhV5W1oQAPHGOS62eWgmZefzd7rHEp3ds03o0F8sO"
                + "GE4p75vA6HR1umY74J4Aq1Yut8D3Fl+WmptCQUGYzPG/8qLI1omkFOznZiknZlaJ"
                + "6U25YeuuxWFcvBp4lcaFGslhQy/xEY1GB9Mu+dxzLVEzO+S00OMN3qeE7Ki+R+dB"
                + "vpwZYx3EcKUu9NwTpPNjP9Q014fBcJd7QX31mOHQ3eUGu3HW8LwX7HDjsDzcGWXL"
                + "Npk/YzsEcuUNCSOsbGb98dPmRZzBIfD1+U0J6dvPXWkOIyM4OKC6y3xjjRsmUKQw"
                + "jNFxtoVRJtHaZypu2FqNeMKG+1b0qz0hSXUoBFxjJiyKQq8vmALFO3u4vijnj+C1"
                + "zkX7t6GvGjsoqNlLeJDjyILjm8mOnwrXYCW/DdLwApjnFBoiaz187kFPYE0eC6VN"
                + "EdX+WLzOpq13rS6MHKrPMkWQFLe5EAGx76itFypSP7jjZbV3Ehv5/Yiixgwh6CHX"
                + "tqy0elqZXkDKztXCI7j+beXhjp0uWJOu/rt6rn/xoUYmDi8RDpOVKCE6ACWjjsea"
                + "q8hhsl68UJpGdMEyqqy34BRvFO/RHPyvTKpPd1pxbOMl4KQ1pNNJ1yC88TdFCvxF"
                + "BG/Bofg6nTKXd6cITkqtrnEizpcAWTBSjrPH9/ESmzcoh6NxFVo7ogGiXL8dy2Tn"
                + "ze4JLDFB+1VQ/j0N2C6HDleLK0ZQCBgRO49laXc8Z3OFtppCt33Lp6z/2V/URS4j"
                + "qqHTfh2iFR6mWNQKNZayesn4Ep3GzwZDdyYktZ9PRhIw30ccomCHw5QtXGaH32CC"
                + "g1k1o/h8t2Kww7HQ3aSmUzllvvG3uCkuJUwBTQkP7YV8RMGDnGlMCmTj+tkKEfU0"
                + "citu4VdPLhSdVddE3kiHAk4IURQxwGJ1DhbHSrnzJC8ts/+xKo1hB/qiKdb2NzsH"
                + "8205MrO9sEwZ3WTq3X+Tw8Vkw1ihyB3PHJwx5bBlaPl1RMF9wVaYxcs4mDqa/EJ4"
                + "P6p3OlLJ2CYGkL6eMVaqW8FQneo/aVh2lc1v8XK6g+am2KfWu+u7zaNnJzGYP4m8"
                + "WDHcN8PzxcVvrMaX88sgvV2629cC5UhErC9iaQH+FZ25Pf1Hc9j+c1YrhGwfyFbR"
                + "gCdihA68cteYi951y8pw0xnTLODMAlO7KtRVcj7gx/RzbObmZlxayjKkgcU4Obwl"
                + "kWewE9BCM5Xuuaqu4yBhSafVUNZ/xf3+SopcNdJRC2ZDeauPcoVaKvR6vOKmMgSO"
                + "r4nly0qI3rxTpZUQOszk8c/xis/wev4etXFqoeQLYxNMOjrpV5+of1Fb4JPC0p22"
                + "1rZck2YeAGNrWScE0JPMZxbCNC6xhT1IyFxjrIooVEYse3fn470erFvKKP+qALXT"
                + "SfilR62HW5aowrKRDJMBMJo/kTilaTER9Vs8AJypR8Od/ILZjrHKpKnL6IX3hvqG"
                + "5VvgYiIvi6kKl0BzMmsxISrs4KNKYA==";
        byte[] x509EncodedPublicKey = decodeBase64(publicKeyBase64);

        PublicKey publicKey =
                keyFactory.generatePublic(new X509EncodedKeySpec(x509EncodedPublicKey));
        assertEquals("ML-DSA", publicKey.getAlgorithm());

        // Test that privateKey and publicKey are a ML-DSA-87 key pair.
        byte[] message = new byte[42];

        Signature signer = Signature.getInstance("ML-DSA", conscryptProvider);
        signer.initSign(privateKey);
        signer.update(message);
        byte[] sig = signer.sign();
        assertEquals(4627, sig.length);

        Signature verifier = Signature.getInstance("ML-DSA", conscryptProvider);
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertTrue(verifier.verify(sig));
    }

    @Test
    public void testVectors() throws Exception {
        List<TestVector> vectors = TestUtils.readTestVectors("crypto/mldsa.txt");

        for (TestVector vector : vectors) {
            String errMsg = vector.getString("name");
            String algorithm = vector.getString("algorithm");
            byte[] seed = vector.getBytes("seed");
            byte[] publicKey = vector.getBytes("public_key");
            byte[] message = vector.getBytes("message");
            byte[] signature = vector.getBytes("signature");

            if (!algorithm.startsWith("ML-DSA")) {
                assertTrue(errMsg + ", algorithm must start with ML-DSA", false);
            }

            KeyFactory keyFactory = KeyFactory.getInstance(algorithm, conscryptProvider);

            Signature signer = Signature.getInstance(algorithm, conscryptProvider);
            signer.initSign(keyFactory.generatePrivate(new RawKeySpec(seed)));
            signer.update(message);
            byte[] sig = signer.sign();

            assertEquals(errMsg + ", signature length mismatch", signature.length, sig.length);

            Signature verifier = Signature.getInstance(algorithm, conscryptProvider);
            verifier.initVerify(keyFactory.generatePublic(new RawKeySpec(publicKey)));
            verifier.update(message);
            assertTrue(errMsg + ", new signature verification failed", verifier.verify(sig));

            verifier.initVerify(keyFactory.generatePublic(new RawKeySpec(publicKey)));
            verifier.update(message);
            assertTrue(errMsg + ", testvector signature verification failed. how about: ["
                            + TestUtils.encodeHex(sig) + "]",
                    verifier.verify(signature));
        }
    }

    @Test
    public void serializeAndDeserialize_65_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-65", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(keyPair.getPrivate());
            oos.writeObject(keyPair.getPublic());
        }

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        PrivateKey inflatedPrivateKey = (PrivateKey) ois.readObject();
        PublicKey inflatedPublicKey = (PublicKey) ois.readObject();

        assertEquals(inflatedPrivateKey, keyPair.getPrivate());
        assertEquals(inflatedPublicKey, keyPair.getPublic());
    }

    @Test
    public void serializeAndDeserialize_87_works() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-87", conscryptProvider);
        KeyPair keyPair = keyGen.generateKeyPair();

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(keyPair.getPrivate());
            oos.writeObject(keyPair.getPublic());
        }

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        PrivateKey inflatedPrivateKey = (PrivateKey) ois.readObject();
        PublicKey inflatedPublicKey = (PublicKey) ois.readObject();

        assertEquals(inflatedPrivateKey, keyPair.getPrivate());
        assertEquals(inflatedPublicKey, keyPair.getPublic());
    }

    @Test
    public void serializeAndDeserializePrivateKey_65_withTestVectors_works() throws Exception {
        byte[] rawPrivateKey = TestUtils.decodeHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-65", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(privateKey);
        }

        String hexClassName = TestUtils.encodeHex(
                privateKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String serializationWithoutWriteMethod = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + hexClassName
                + "3bacc385e8e106a3" // serialVersionUID
                + "0200015b0004"
                + "73656564" // hex("seed")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "20" // hex(32), size of the raw private key
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"; // rawPrivateKey

        // Expected serialization when the key class implements a writeObject method.
        String serializationWithWriteMethod = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + hexClassName
                + "3bacc385e8e106a3" // serialVersionUID
                + "03" // classDescFlags = SC_WRITE_METHOD | SC_SERIALIZABLE
                + "00015b0004"
                + "73656564" // hex("seed")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "20" // hex(32), size of the raw private key
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" // rawPrivateKey
                + "78"; // TC_ENDBLOCKDATA

        assertEquals(serializationWithWriteMethod, TestUtils.encodeHex(baos.toByteArray()));

        // Verify that deserialization of both formats work.
        {
            ByteArrayInputStream bais =
                    new ByteArrayInputStream(TestUtils.decodeHex(serializationWithoutWriteMethod));
            ObjectInputStream ois = new ObjectInputStream(bais);
            PrivateKey inflatedPrivateKey = (PrivateKey) ois.readObject();
            assertEquals(inflatedPrivateKey, privateKey);
        }
        {
            ByteArrayInputStream bais =
                    new ByteArrayInputStream(TestUtils.decodeHex(serializationWithWriteMethod));
            ObjectInputStream ois = new ObjectInputStream(bais);
            PrivateKey inflatedPrivateKey = (PrivateKey) ois.readObject();
            assertEquals(inflatedPrivateKey, privateKey);
        }
    }

    @Test
    public void serializeAndDeserializePrivateKey_87_withTestVectors_works() throws Exception {
        byte[] rawPrivateKey = TestUtils.decodeHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(privateKey);
        }

        String hexClassName = TestUtils.encodeHex(
                privateKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String serializationWithoutWriteMethod = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + hexClassName
                + "3bacc385e8e106a3" // serialVersionUID
                + "0200015b0004"
                + "73656564" // hex("seed")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "21" // hex(33), size of "seed", which is 32 + 1
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" // rawPrivateKey
                + "57"; // hex(87)

        // Expected serialization when the key class implements a writeObject method.
        String serializationWithWriteMethod = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + hexClassName
                + "3bacc385e8e106a3" // serialVersionUID
                + "03" // classDescFlags = SC_WRITE_METHOD | SC_SERIALIZABLE
                + "00015b0004"
                + "73656564" // hex("seed")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "21" // hex(33), size of "seed", which is 32 + 1
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" // rawPrivateKey
                + "57" // hex(87)
                + "78"; // TC_ENDBLOCKDATA

        assertEquals(serializationWithWriteMethod, TestUtils.encodeHex(baos.toByteArray()));

        // Verify that deserialization of both formats work.
        {
            ByteArrayInputStream bais =
                    new ByteArrayInputStream(TestUtils.decodeHex(serializationWithoutWriteMethod));
            ObjectInputStream ois = new ObjectInputStream(bais);
            PrivateKey inflatedPrivateKey = (PrivateKey) ois.readObject();
            assertEquals(inflatedPrivateKey, privateKey);
        }
        {
            ByteArrayInputStream bais =
                    new ByteArrayInputStream(TestUtils.decodeHex(serializationWithWriteMethod));
            ObjectInputStream ois = new ObjectInputStream(bais);
            PrivateKey inflatedPrivateKey = (PrivateKey) ois.readObject();
            assertEquals(inflatedPrivateKey, privateKey);
        }
    }

    @Test
    public void serializeAndDeserializePublicKey_65_withTestVectors_works() throws Exception {
        byte[] rawPublicKey = new byte[1952];

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-65", conscryptProvider);
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(publicKey);
        }

        String hexClassName = TestUtils.encodeHex(
                publicKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String serializationWithoutWriteMethod = "aced0005737200"
                + Integer.toHexString(publicKey.getClass().getName().length()) + hexClassName
                + "064c7113d078e42d" // serialVersionUID
                + "0200015b0003"
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e002000078700000"
                + "07a0" + TestUtils.encodeHex(rawPublicKey);

        // Expected serialization when the key class implements a writeObject method.
        String serializationWithWriteMethod = "aced0005737200"
                + Integer.toHexString(publicKey.getClass().getName().length()) + hexClassName
                + "064c7113d078e42d" // serialVersionUID
                + "03" // classDescFlags = SC_WRITE_METHOD | SC_SERIALIZABLE
                + "00015b0003"
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e002000078700000"
                + "07a0" + TestUtils.encodeHex(rawPublicKey) + "78"; // TC_ENDBLOCKDATA

        assertEquals(serializationWithWriteMethod, TestUtils.encodeHex(baos.toByteArray()));

        // Verify that deserialization of both formats work.
        {
            ByteArrayInputStream bais =
                    new ByteArrayInputStream(TestUtils.decodeHex(serializationWithoutWriteMethod));
            ObjectInputStream ois = new ObjectInputStream(bais);
            PublicKey inflatedPublicKey = (PublicKey) ois.readObject();
            assertEquals(inflatedPublicKey, publicKey);
        }
        {
            ByteArrayInputStream bais =
                    new ByteArrayInputStream(TestUtils.decodeHex(serializationWithWriteMethod));
            ObjectInputStream ois = new ObjectInputStream(bais);
            PublicKey inflatedPublicKey = (PublicKey) ois.readObject();
            assertEquals(inflatedPublicKey, publicKey);
        }
    }

    @Test
    public void serializeAndDeserializePublicKey_87_withTestVectors_works() throws Exception {
        byte[] rawPublicKey = new byte[2592];

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(16384);
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(publicKey);
        }

        String hexClassName = TestUtils.encodeHex(
                publicKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String serializationWithoutWriteMethod = "aced0005737200"
                + Integer.toHexString(publicKey.getClass().getName().length()) + hexClassName
                + "064c7113d078e42d" // serialVersionUID
                + "0200015b0003"
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e002000078700000"
                + "0a20" // hex(2592), size of the raw public key
                + TestUtils.encodeHex(rawPublicKey);

        // Expected serialization when the key class implements a writeObject method.
        String serializationWithWriteMethod = "aced0005737200"
                + Integer.toHexString(publicKey.getClass().getName().length()) + hexClassName
                + "064c7113d078e42d" // serialVersionUID
                + "03" // classDescFlags = SC_WRITE_METHOD | SC_SERIALIZABLE
                + "00015b0003"
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e002000078700000"
                + "0a20" // hex(2592), size of the raw public key
                + TestUtils.encodeHex(rawPublicKey) + "78"; // TC_ENDBLOCKDATA

        assertEquals(serializationWithWriteMethod, TestUtils.encodeHex(baos.toByteArray()));

        // Verify that deserialization of both formats work.
        {
            ByteArrayInputStream bais =
                    new ByteArrayInputStream(TestUtils.decodeHex(serializationWithoutWriteMethod));
            ObjectInputStream ois = new ObjectInputStream(bais);
            PublicKey inflatedPublicKey = (PublicKey) ois.readObject();
            assertEquals(inflatedPublicKey, publicKey);
        }
        {
            ByteArrayInputStream bais =
                    new ByteArrayInputStream(TestUtils.decodeHex(serializationWithWriteMethod));
            ObjectInputStream ois = new ObjectInputStream(bais);
            PublicKey inflatedPublicKey = (PublicKey) ois.readObject();
            assertEquals(inflatedPublicKey, publicKey);
        }
    }

    @Test
    public void deserializePrivateKeyWithWrongSuffix_fails() throws Exception {
        byte[] rawPrivateKey = TestUtils.decodeHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));
        String hexClassName = TestUtils.encodeHex(
                privateKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String invalidPrivateKey = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + hexClassName
                + "3bacc385e8e106a3" // serialVersionUID
                + "0200015b0004"
                + "73656564" // hex("seed")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "21" // hex(33), size of encoded seed, which is 1 + 32
                // encoded seed.
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "41"; // wrong suffix.

        ByteArrayInputStream bais =
                new ByteArrayInputStream(TestUtils.decodeHex(invalidPrivateKey));
        ObjectInputStream ois = new ObjectInputStream(bais);

        try {
            ois.readObject();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException | EOFException e) {
            // Expected
        }
    }

    @Test
    public void deserializePrivateKeyWithWrongSize_fails() throws Exception {
        byte[] rawPrivateKey = TestUtils.decodeHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        PrivateKey privateKey = keyFactory.generatePrivate(new RawKeySpec(rawPrivateKey));
        String hexClassName = TestUtils.encodeHex(
                privateKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String invalidPrivateKey = "aced0005737200"
                + Integer.toHexString(privateKey.getClass().getName().length()) + hexClassName
                + "3bacc385e8e106a3" // serialVersionUID
                + "0200015b0004"
                + "73656564" // hex("seed")
                + "7400025b427870757200025b42acf317f8060854e00200007870000000"
                + "22" // hex(34), illegal size of encoded seed, only 32 or 33 are allowed.
                // encoded seed.
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "5757";

        ByteArrayInputStream bais =
                new ByteArrayInputStream(TestUtils.decodeHex(invalidPrivateKey));
        ObjectInputStream ois = new ObjectInputStream(bais);

        try {
            ois.readObject();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException | EOFException e) {
            // Expected
        }
    }

    @Test
    public void deserializeInvalidPublicKey_fails() throws Exception {
        byte[] rawPublicKey = new byte[2592];
        byte[] invalidRawPublicKey = new byte[2593]; // one byte too long.

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-87", conscryptProvider);
        PublicKey publicKey = keyFactory.generatePublic(new RawKeySpec(rawPublicKey));
        String hexClassName = TestUtils.encodeHex(
                publicKey.getClass().getName().getBytes(StandardCharsets.UTF_8));

        String hexPublicKey = "aced0005737200"
                + Integer.toHexString(publicKey.getClass().getName().length()) + hexClassName
                + "064c7113d078e42d" // serialVersionUID
                + "0200015b0003"
                + "726177" // hex("raw")
                + "7400025b427870757200025b42acf317f8060854e002000078700000"
                + "0a21" // hex(2593), size of the invalid raw public key
                + TestUtils.encodeHex(invalidRawPublicKey);

        ByteArrayInputStream bais = new ByteArrayInputStream(TestUtils.decodeHex(hexPublicKey));
        ObjectInputStream ois = new ObjectInputStream(bais);

        try {
            ois.readObject();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException | EOFException e) {
            // Expected
        }
    }
}
