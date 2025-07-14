/*
 * Copyright (C) 2011 The Android Open Source Project
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

package org.conscrypt.javax.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.conscrypt.Conscrypt;
import org.conscrypt.TestUtils;
import org.conscrypt.java.security.StandardNames;
import org.conscrypt.java.security.TestKeyStore;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class CipherTest {

    @BeforeClass
    public static void setUp() {
        TestUtils.assumeAllowsUnsignedCrypto();
    }

    /** GCM tag size used for tests. */
    private static final int GCM_TAG_SIZE_BITS = 96;
    private static final int GCM_SIV_TAG_SIZE_BITS = 128;

    private static final String[] RSA_PROVIDERS = StandardNames.IS_RI
        ? new String[] { "SunJCE", StandardNames.JSSE_PROVIDER_NAME }
        : new String[] { "BC" , StandardNames.JSSE_PROVIDER_NAME };

    private static final String[] AES_PROVIDERS = StandardNames.IS_RI
        ? new String[] { "SunJCE", StandardNames.JSSE_PROVIDER_NAME }
        : new String[] { "BC", StandardNames.JSSE_PROVIDER_NAME };

    private static boolean isSupported(String algorithm, String provider) {
        if (algorithm.equals("RC2")) {
            return false;
        }
        if (algorithm.equals("PBEWITHMD5ANDRC2")) {
            return false;
        }
        if (algorithm.startsWith("PBEWITHSHA1ANDRC2")) {
            return false;
        }
        if (algorithm.equals("PBEWITHSHAAND40BITRC2-CBC")) {
            return false;
        }
        if (algorithm.equals("PBEWITHSHAAND128BITRC2-CBC")) {
            return false;
        }
        if (algorithm.equals("PBEWITHSHAANDTWOFISH-CBC")) {
            return false;
        }
        if (!IS_UNLIMITED) {
            if (algorithm.equals("PBEWITHMD5ANDTRIPLEDES")) {
                return false;
            }
        }
        // stream modes CFB, CTR, CTS, OFB with PKCS5Padding or PKCS7Padding don't really make sense
        if (!provider.equals("AndroidOpenSSL") &&
            (algorithm.equals("AES/CFB/PKCS5PADDING")
             || algorithm.equals("AES/CFB/PKCS7PADDING")
             || algorithm.equals("AES/CTR/PKCS5PADDING")
             || algorithm.equals("AES/CTR/PKCS7PADDING")
             || algorithm.equals("AES/CTS/PKCS5PADDING")
             || algorithm.equals("AES/CTS/PKCS7PADDING")
             || algorithm.equals("AES/OFB/PKCS5PADDING")
             || algorithm.equals("AES/OFB/PKCS7PADDING"))) {
            return false;
        }

        if (provider.equals("BC")) {
            return isSupportedByBC(algorithm);
        }

        return true;
    }

    /*
     * Checks for algorithms removed from BC in Android 12 and so not usable for these
     * tests.
     *
     * TODO(prb): make this version aware, as this test runs against BC on older Android
     * versions via MTS and should continue to test these algorithms there.
     *
     */
    private static boolean isSupportedByBC(String algorithm) {
        String[] removedBcPrefices = new String[]{
            "AES/ECB",
            "AES/CBC",
            "AES/GCM"
        };
        for (String prefix : removedBcPrefices) {
            if (algorithm.startsWith(prefix)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSupportedForWrapping(String algorithm) {
        if (isOnlyWrappingAlgorithm(algorithm)) {
            return true;
        }
        // http://b/9097343 RSA with NoPadding won't work since
        // leading zeroes in the underlying key material are lost.
        if (algorithm.equals("RSA/ECB/NOPADDING")) {
            return false;
        }
        // AESWRAP should be used instead, fails with BC and SunJCE otherwise.
        return !algorithm.startsWith("AES") && !algorithm.startsWith("DESEDE");
    }

    private synchronized static int getEncryptMode(String algorithm) {
        if (isOnlyWrappingAlgorithm(algorithm)) {
            return Cipher.WRAP_MODE;
        }
        return Cipher.ENCRYPT_MODE;
    }

    private synchronized static int getDecryptMode(String algorithm) {
        if (isOnlyWrappingAlgorithm(algorithm)) {
            return Cipher.UNWRAP_MODE;
        }
        return Cipher.DECRYPT_MODE;
    }

    private static String getBaseAlgorithm(String algorithm) {
        if (algorithm.equals("AESWRAP")) {
            return "AES";
        }
        if (algorithm.startsWith("AES/")) {
            return "AES";
        }
        if (algorithm.startsWith("AES_128/") || algorithm.startsWith("AES_256/")) {
            return "AES";
        }
        if (algorithm.equals("GCM")) {
            return "AES";
        }
        if (algorithm.startsWith("CHACHA20/")) {
            return "CHACHA20";
        }
        if (algorithm.startsWith("DESEDE/")) {
            return "DESEDE";
        }
        if (algorithm.equals("PBEWITHMD5AND128BITAES-CBC-OPENSSL")) {
            return "AES";
        }
        if (algorithm.equals("PBEWITHMD5AND192BITAES-CBC-OPENSSL")) {
            return "AES";
        }
        if (algorithm.equals("PBEWITHMD5AND256BITAES-CBC-OPENSSL")) {
            return "AES";
        }
        if (algorithm.equals("PBEWITHSHA256AND128BITAES-CBC-BC")) {
            return "AES";
        }
        if (algorithm.equals("PBEWITHSHA256AND192BITAES-CBC-BC")) {
            return "AES";
        }
        if (algorithm.equals("PBEWITHSHA256AND256BITAES-CBC-BC")) {
            return "AES";
        }
        if (algorithm.equals("PBEWITHSHAAND128BITAES-CBC-BC")) {
            return "AES";
        }
        if (algorithm.equals("PBEWITHSHAAND192BITAES-CBC-BC")) {
            return "AES";
        }
        if (algorithm.equals("PBEWITHSHAAND256BITAES-CBC-BC")) {
            return "AES";
        }
        if (algorithm.equals("PBEWITHMD5ANDDES")) {
            return "DES";
        }
        if (algorithm.equals("PBEWITHSHA1ANDDES")) {
            return "DES";
        }
        if (algorithm.equals("DESEDEWRAP")) {
            return "DESEDE";
        }
        if (algorithm.equals("PBEWITHSHAAND2-KEYTRIPLEDES-CBC")) {
            return "DESEDE";
        }
        if (algorithm.equals("PBEWITHSHAAND3-KEYTRIPLEDES-CBC")) {
            return "DESEDE";
        }
        if (algorithm.equals("PBEWITHMD5ANDTRIPLEDES")) {
            return "DESEDE";
        }
        if (algorithm.equals("PBEWITHSHA1ANDDESEDE")) {
            return "DESEDE";
        }
        if (algorithm.equals("RSA/ECB/NOPADDING")) {
            return "RSA";
        }
        if (algorithm.equals("RSA/ECB/PKCS1PADDING")) {
            return "RSA";
        }
        if (algorithm.equals("PBEWITHSHAAND40BITRC4")) {
            return "ARC4";
        }
        if (algorithm.equals("PBEWITHSHAAND128BITRC4")) {
            return "ARC4";
        }
        return algorithm;
    }

    private static boolean isAsymmetric(String algorithm) {
        return getBaseAlgorithm(algorithm).equals("RSA");
    }

    private static boolean isOnlyWrappingAlgorithm(String algorithm) {
        return algorithm.endsWith("WRAP");
    }

    private static boolean isPBE(String algorithm) {
        return algorithm.startsWith("PBE");
    }

    private static boolean isAEAD(String algorithm) {
        return "GCM".equals(algorithm) || algorithm.contains("/GCM/")
                || algorithm.contains("/GCM-SIV/")
                || algorithm.equals("CHACHA20/POLY1305/NOPADDING");
    }

    private static boolean isStreamMode(String algorithm) {
        return algorithm.contains("/CTR/") || algorithm.contains("/OFB")
                || algorithm.contains("/CFB");
    }

    private static boolean isRandomizedEncryption(String algorithm) {
        return algorithm.endsWith("/PKCS1PADDING") || algorithm.endsWith("/OAEPPADDING")
                || algorithm.contains("/OAEPWITH");
    }

    private static final Map<String, Key> ENCRYPT_KEYS = new HashMap<>();

    /**
     * Returns the key meant for enciphering for {@code algorithm}.
     */
    private synchronized static Key getEncryptKey(String algorithm) {
        Key key = ENCRYPT_KEYS.get(algorithm);
        if (key != null) {
            return key;
        }
        try {
            if (algorithm.startsWith("RSA")) {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                        RSA_2048_publicExponent);
                key = kf.generatePublic(keySpec);
            } else if (isPBE(algorithm)) {
                SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
                key = skf.generateSecret(new PBEKeySpec("secret".toCharArray()));
            } else {
                KeyGenerator kg = KeyGenerator.getInstance(getBaseAlgorithm(algorithm));
                if (algorithm.startsWith("AES_256/")) {
                    // This is the 256-bit constrained version, so we have to switch from the
                    // default of 128-bit keys.
                    kg.init(256);
                }
                key = kg.generateKey();
            }
        } catch (Exception e) {
            throw new AssertionError("Error generating keys for test setup", e);
        }
        ENCRYPT_KEYS.put(algorithm, key);
        return key;
    }

    private static final Map<String, Key> DECRYPT_KEYS = new HashMap<>();

    /**
     * Returns the key meant for deciphering for {@code algorithm}.
     */
    private synchronized static Key getDecryptKey(String algorithm) {
        Key key = DECRYPT_KEYS.get(algorithm);
        if (key != null) {
            return key;
        }
        try {
            if (algorithm.startsWith("RSA")) {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(RSA_2048_modulus,
                        RSA_2048_publicExponent, RSA_2048_privateExponent, RSA_2048_primeP,
                        RSA_2048_primeQ, RSA_2048_primeExponentP, RSA_2048_primeExponentQ,
                        RSA_2048_crtCoefficient);
                key = kf.generatePrivate(keySpec);
            } else {
                assertFalse(algorithm, isAsymmetric(algorithm));
                key = getEncryptKey(algorithm);
            }
        } catch (Exception e) {
            throw new AssertionError("Error generating keys for test setup", e);
        }
        DECRYPT_KEYS.put(algorithm, key);
        return key;
    }

    private static final Map<String, Integer> EXPECTED_BLOCK_SIZE = new HashMap<>();
    static {
        setExpectedBlockSize("AES", 16);
        setExpectedBlockSize("AES/CBC/PKCS5PADDING", 16);
        setExpectedBlockSize("AES/CBC/PKCS7PADDING", 16);
        setExpectedBlockSize("AES/CBC/NOPADDING", 16);
        setExpectedBlockSize("AES/CFB/PKCS5PADDING", 16);
        setExpectedBlockSize("AES/CFB/PKCS7PADDING", 16);
        setExpectedBlockSize("AES/CFB/NOPADDING", 16);
        setExpectedBlockSize("AES/CTR/PKCS5PADDING", 16);
        setExpectedBlockSize("AES/CTR/PKCS7PADDING", 16);
        setExpectedBlockSize("AES/CTR/NOPADDING", 16);
        setExpectedBlockSize("AES/CTS/PKCS5PADDING", 16);
        setExpectedBlockSize("AES/CTS/PKCS7PADDING", 16);
        setExpectedBlockSize("AES/CTS/NOPADDING", 16);
        setExpectedBlockSize("AES/ECB/PKCS5PADDING", 16);
        setExpectedBlockSize("AES/ECB/PKCS7PADDING", 16);
        setExpectedBlockSize("AES/ECB/NOPADDING", 16);
        setExpectedBlockSize("AES/GCM/NOPADDING", 16);
        setExpectedBlockSize("AES/GCM-SIV/NOPADDING", 16);
        setExpectedBlockSize("AES/OFB/PKCS5PADDING", 16);
        setExpectedBlockSize("AES/OFB/PKCS7PADDING", 16);
        setExpectedBlockSize("AES/OFB/NOPADDING", 16);
        setExpectedBlockSize("AES_128/CBC/PKCS5PADDING", 16);
        setExpectedBlockSize("AES_128/CBC/NOPADDING", 16);
        setExpectedBlockSize("AES_128/ECB/PKCS5PADDING", 16);
        setExpectedBlockSize("AES_128/ECB/NOPADDING", 16);
        setExpectedBlockSize("AES_128/GCM/NOPADDING", 16);
        setExpectedBlockSize("AES_128/GCM-SIV/NOPADDING", 16);
        setExpectedBlockSize("AES_256/CBC/PKCS5PADDING", 16);
        setExpectedBlockSize("AES_256/CBC/NOPADDING", 16);
        setExpectedBlockSize("AES_256/ECB/PKCS5PADDING", 16);
        setExpectedBlockSize("AES_256/ECB/NOPADDING", 16);
        setExpectedBlockSize("AES_256/GCM/NOPADDING", 16);
        setExpectedBlockSize("AES_256/GCM-SIV/NOPADDING", 16);
        setExpectedBlockSize("PBEWITHMD5AND128BITAES-CBC-OPENSSL", 16);
        setExpectedBlockSize("PBEWITHMD5AND192BITAES-CBC-OPENSSL", 16);
        setExpectedBlockSize("PBEWITHMD5AND256BITAES-CBC-OPENSSL", 16);
        setExpectedBlockSize("PBEWITHSHA256AND128BITAES-CBC-BC", 16);
        setExpectedBlockSize("PBEWITHSHA256AND192BITAES-CBC-BC", 16);
        setExpectedBlockSize("PBEWITHSHA256AND256BITAES-CBC-BC", 16);
        setExpectedBlockSize("PBEWITHSHAAND128BITAES-CBC-BC", 16);
        setExpectedBlockSize("PBEWITHSHAAND192BITAES-CBC-BC", 16);
        setExpectedBlockSize("PBEWITHSHAAND256BITAES-CBC-BC", 16);

        if (StandardNames.IS_RI) {
            setExpectedBlockSize("AESWRAP", 16);
        } else {
            setExpectedBlockSize("AESWRAP", 0);
        }

        setExpectedBlockSize("ARC4", 0);
        setExpectedBlockSize("CHACHA20", 0);
        setExpectedBlockSize("CHACHA20/POLY1305/NOPADDING", 0);
        setExpectedBlockSize("PBEWITHSHAAND40BITRC4", 0);
        setExpectedBlockSize("PBEWITHSHAAND128BITRC4", 0);

        setExpectedBlockSize("BLOWFISH", 8);

        setExpectedBlockSize("DES", 8);
        setExpectedBlockSize("PBEWITHMD5ANDDES", 8);
        setExpectedBlockSize("PBEWITHSHA1ANDDES", 8);

        setExpectedBlockSize("DESEDE", 8);
        setExpectedBlockSize("DESEDE/CBC/PKCS5PADDING", 8);
        setExpectedBlockSize("DESEDE/CBC/NOPADDING", 8);
        setExpectedBlockSize("PBEWITHSHAAND2-KEYTRIPLEDES-CBC", 8);
        setExpectedBlockSize("PBEWITHSHAAND3-KEYTRIPLEDES-CBC", 8);


        if (StandardNames.IS_RI) {
            setExpectedBlockSize("DESEDEWRAP", 8);
        } else {
            setExpectedBlockSize("DESEDEWRAP", 0);
        }

        setExpectedBlockSize("RSA", "SunJCE",0);
        setExpectedBlockSize("RSA/ECB/NoPadding", "SunJCE", 0);
        setExpectedBlockSize("RSA/ECB/PKCS1Padding", "SunJCE", 0);
        setExpectedBlockSize("RSA/ECB/OAEPPadding", "SunJCE", 0);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "SunJCE", 0);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-224AndMGF1Padding", "SunJCE", 0);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "SunJCE", 0);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-384AndMGF1Padding", "SunJCE", 0);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-512AndMGF1Padding", "SunJCE", 0);

        setExpectedBlockSize("RSA", Cipher.ENCRYPT_MODE, 256);
        setExpectedBlockSize("RSA/ECB/NoPadding", Cipher.ENCRYPT_MODE, 256);
        setExpectedBlockSize("RSA/ECB/PKCS1Padding", Cipher.ENCRYPT_MODE, 245);

        // BC strips the leading 0 for us even when NoPadding is specified
        setExpectedBlockSize("RSA", Cipher.ENCRYPT_MODE, "BC", 255);
        setExpectedBlockSize("RSA/ECB/NoPadding", Cipher.ENCRYPT_MODE, "BC", 255);

        setExpectedBlockSize("RSA", Cipher.DECRYPT_MODE, 256);
        setExpectedBlockSize("RSA/ECB/NoPadding", Cipher.DECRYPT_MODE, 256);
        setExpectedBlockSize("RSA/ECB/PKCS1Padding", Cipher.DECRYPT_MODE, 256);

        // OAEP padding modes change the output and block size. SHA-1 is the default.
        setExpectedBlockSize("RSA/ECB/OAEPPadding", Cipher.ENCRYPT_MODE, 214);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", Cipher.ENCRYPT_MODE, 214);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-224AndMGF1Padding", Cipher.ENCRYPT_MODE, 198);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", Cipher.ENCRYPT_MODE, 190);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-384AndMGF1Padding", Cipher.ENCRYPT_MODE, 158);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-512AndMGF1Padding", Cipher.ENCRYPT_MODE, 126);

        setExpectedBlockSize("RSA/ECB/OAEPPadding", Cipher.DECRYPT_MODE, 256);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", Cipher.DECRYPT_MODE, 256);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-224AndMGF1Padding", Cipher.DECRYPT_MODE, 256);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", Cipher.DECRYPT_MODE, 256);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-384AndMGF1Padding", Cipher.DECRYPT_MODE, 256);
        setExpectedBlockSize("RSA/ECB/OAEPWithSHA-512AndMGF1Padding", Cipher.DECRYPT_MODE, 256);
    }

    private static String modeKey(String algorithm, int mode) {
        return algorithm + ":" + mode;
    }

    private static String modeProviderKey(String algorithm, int mode, String provider) {
        return algorithm + ":" + mode + ":" + provider;
    }

    private static String providerKey(String algorithm, String provider) {
        return algorithm + ":" + provider;
    }

    private static void setExpectedSize(Map<String, Integer> map,
                                        String algorithm, int value) {
        algorithm = algorithm.toUpperCase(Locale.US);
        map.put(algorithm, value);
    }

    private static void setExpectedSize(Map<String, Integer> map,
                                        String algorithm, int mode, int value) {
        setExpectedSize(map, modeKey(algorithm, mode), value);
    }

    private static void setExpectedSize(Map<String, Integer> map,
                                        String algorithm, int mode, String provider, int value) {
        setExpectedSize(map, modeProviderKey(algorithm, mode, provider), value);
    }

    private static void setExpectedSize(Map<String, Integer> map,
            String algorithm, String provider, int value) {
        setExpectedSize(map, providerKey(algorithm, provider), value);
    }

    private static int getExpectedSize(Map<String, Integer> map, String algorithm, int mode, String provider) {
        algorithm = algorithm.toUpperCase(Locale.US);
        provider = provider.toUpperCase(Locale.US);
        Integer expected = map.get(modeProviderKey(algorithm, mode, provider));
        if (expected != null) {
            return expected;
        }
        expected = map.get(providerKey(algorithm, provider));
        if (expected != null) {
            return expected;
        }
        expected = map.get(modeKey(algorithm, mode));
        if (expected != null) {
            return expected;
        }
        expected = map.get(algorithm);
        assertNotNull("Algorithm " + algorithm + " with mode " + mode + " and provider " + provider
                      + " not found in " + map, expected);
        return expected;
    }

    private static void setExpectedBlockSize(String algorithm, int value) {
        setExpectedSize(EXPECTED_BLOCK_SIZE, algorithm, value);
    }

    private static void setExpectedBlockSize(String algorithm, int mode, int value) {
        setExpectedSize(EXPECTED_BLOCK_SIZE, algorithm, mode, value);
    }

    private static void setExpectedBlockSize(String algorithm, String provider, int value) {
        setExpectedSize(EXPECTED_BLOCK_SIZE, algorithm, provider, value);
    }

    private static void setExpectedBlockSize(String algorithm, int mode, String provider, int value) {
        setExpectedSize(EXPECTED_BLOCK_SIZE, algorithm, mode, provider, value);
    }

    private static int getExpectedBlockSize(String algorithm, int mode, String provider) {
        return getExpectedSize(EXPECTED_BLOCK_SIZE, algorithm, mode, provider);
    }

    private static final Map<String, Integer> EXPECTED_OUTPUT_SIZE = new HashMap<>();
    static {
        setExpectedOutputSize("AES/CBC/NOPADDING", 0);
        setExpectedOutputSize("AES/CFB/NOPADDING", 0);
        setExpectedOutputSize("AES/CTR/NOPADDING", 0);
        setExpectedOutputSize("AES/CTS/NOPADDING", 0);
        setExpectedOutputSize("AES/ECB/NOPADDING", 0);
        setExpectedOutputSize("AES/OFB/NOPADDING", 0);
        setExpectedOutputSize("AES_128/CBC/NOPADDING", 0);
        setExpectedOutputSize("AES_128/ECB/NOPADDING", 0);
        setExpectedOutputSize("AES_256/CBC/NOPADDING", 0);
        setExpectedOutputSize("AES_256/ECB/NOPADDING", 0);

        setExpectedOutputSize("AES", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES/CBC/PKCS5PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES/CBC/PKCS7PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES/CFB/PKCS5PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES/CFB/PKCS7PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES/CTR/PKCS5PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES/CTR/PKCS7PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES/CTS/PKCS5PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES/CTS/PKCS7PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES/ECB/PKCS5PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES/ECB/PKCS7PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES/GCM/NOPADDING", Cipher.ENCRYPT_MODE, GCM_TAG_SIZE_BITS / 8);
        setExpectedOutputSize("AES/GCM-SIV/NOPADDING", Cipher.ENCRYPT_MODE, GCM_SIV_TAG_SIZE_BITS / 8);
        setExpectedOutputSize("AES/OFB/PKCS5PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES/OFB/PKCS7PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES_128/CBC/PKCS5PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES_128/CBC/PKCS7PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES_128/ECB/PKCS5PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES_128/ECB/PKCS7PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES_128/GCM/NOPADDING", Cipher.ENCRYPT_MODE, GCM_TAG_SIZE_BITS / 8);
        setExpectedOutputSize("AES_128/GCM-SIV/NOPADDING", Cipher.ENCRYPT_MODE, GCM_SIV_TAG_SIZE_BITS / 8);
        setExpectedOutputSize("AES_256/CBC/PKCS5PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES_256/CBC/PKCS7PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES_256/ECB/PKCS5PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES_256/ECB/PKCS7PADDING", Cipher.ENCRYPT_MODE, 16);
        setExpectedOutputSize("AES_256/GCM/NOPADDING", Cipher.ENCRYPT_MODE, GCM_TAG_SIZE_BITS / 8);
        setExpectedOutputSize("AES_256/GCM-SIV/NOPADDING", Cipher.ENCRYPT_MODE, GCM_SIV_TAG_SIZE_BITS / 8);
        setExpectedOutputSize("PBEWITHMD5AND128BITAES-CBC-OPENSSL", 16);
        setExpectedOutputSize("PBEWITHMD5AND192BITAES-CBC-OPENSSL", 16);
        setExpectedOutputSize("PBEWITHMD5AND256BITAES-CBC-OPENSSL", 16);
        setExpectedOutputSize("PBEWITHSHA256AND128BITAES-CBC-BC", 16);
        setExpectedOutputSize("PBEWITHSHA256AND192BITAES-CBC-BC", 16);
        setExpectedOutputSize("PBEWITHSHA256AND256BITAES-CBC-BC", 16);
        setExpectedOutputSize("PBEWITHSHAAND128BITAES-CBC-BC", 16);
        setExpectedOutputSize("PBEWITHSHAAND192BITAES-CBC-BC", 16);
        setExpectedOutputSize("PBEWITHSHAAND256BITAES-CBC-BC", 16);
        // AndroidOpenSSL returns zero for the non-block ciphers
        setExpectedOutputSize("AES/CFB/PKCS5PADDING", Cipher.ENCRYPT_MODE, "AndroidOpenSSL", 0);
        setExpectedOutputSize("AES/CFB/PKCS7PADDING", Cipher.ENCRYPT_MODE, "AndroidOpenSSL", 0);
        setExpectedOutputSize("AES/CTR/PKCS5PADDING", Cipher.ENCRYPT_MODE, "AndroidOpenSSL", 0);
        setExpectedOutputSize("AES/CTR/PKCS7PADDING", Cipher.ENCRYPT_MODE, "AndroidOpenSSL", 0);
        setExpectedOutputSize("AES/CTS/PKCS5PADDING", Cipher.ENCRYPT_MODE, "AndroidOpenSSL", 0);
        setExpectedOutputSize("AES/CTS/PKCS7PADDING", Cipher.ENCRYPT_MODE, "AndroidOpenSSL", 0);
        setExpectedOutputSize("AES/OFB/PKCS5PADDING", Cipher.ENCRYPT_MODE, "AndroidOpenSSL", 0);
        setExpectedOutputSize("AES/OFB/PKCS7PADDING", Cipher.ENCRYPT_MODE, "AndroidOpenSSL", 0);

        setExpectedOutputSize("AES", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/CBC/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/CBC/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/CFB/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/CFB/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/CTR/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/CTR/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/CTS/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/CTS/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/ECB/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/ECB/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/GCM/NOPADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/GCM-SIV/NOPADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/OFB/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES/OFB/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES_128/CBC/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES_128/CBC/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES_128/ECB/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES_128/ECB/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES_128/GCM/NOPADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES_128/GCM-SIV/NOPADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES_256/CBC/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES_256/CBC/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES_256/ECB/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES_256/ECB/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES_256/GCM/NOPADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("AES_256/GCM-SIV/NOPADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHMD5AND128BITAES-CBC-OPENSSL", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHMD5AND192BITAES-CBC-OPENSSL", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHMD5AND256BITAES-CBC-OPENSSL", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHSHA256AND128BITAES-CBC-BC", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHSHA256AND192BITAES-CBC-BC", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHSHA256AND256BITAES-CBC-BC", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHSHAAND128BITAES-CBC-BC", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHSHAAND192BITAES-CBC-BC", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHSHAAND256BITAES-CBC-BC", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/CBC/PKCS5PADDING", Cipher.DECRYPT_MODE, "AndroidOpenSSL", 0);
        setExpectedOutputSize("DESEDE/CBC/PKCS7PADDING", Cipher.DECRYPT_MODE, "AndroidOpenSSL", 0);

        if (StandardNames.IS_RI) {
            setExpectedOutputSize("AESWRAP", Cipher.WRAP_MODE, 8);
            setExpectedOutputSize("AESWRAP", Cipher.UNWRAP_MODE, 0);
        } else {
            setExpectedOutputSize("AESWRAP", -1);
        }

        setExpectedOutputSize("ARC4", 0);
        setExpectedOutputSize("ARCFOUR", 0);
        setExpectedOutputSize("CHACHA20", 0);
        setExpectedOutputSize("CHACHA20/POLY1305/NOPADDING", 0);
        setExpectedOutputSize("PBEWITHSHAAND40BITRC4", 0);
        setExpectedOutputSize("PBEWITHSHAAND128BITRC4", 0);

        setExpectedOutputSize("BLOWFISH", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("BLOWFISH", Cipher.DECRYPT_MODE, 0);

        setExpectedOutputSize("DES", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("PBEWITHMD5ANDDES", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("PBEWITHSHA1ANDDES", Cipher.ENCRYPT_MODE, 8);

        setExpectedOutputSize("DES", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHMD5ANDDES", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHSHA1ANDDES", Cipher.DECRYPT_MODE, 0);

        setExpectedOutputSize("DESEDE/CBC/NOPADDING", 0);
        setExpectedOutputSize("DESEDE/CFB/NOPADDING", 0);
        setExpectedOutputSize("DESEDE/CTR/NOPADDING", 0);
        setExpectedOutputSize("DESEDE/CTS/NOPADDING", 0);
        setExpectedOutputSize("DESEDE/ECB/NOPADDING", 0);
        setExpectedOutputSize("DESEDE/OFB/NOPADDING", 0);

        setExpectedOutputSize("DESEDE", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("DESEDE/CBC/PKCS5PADDING", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("DESEDE/CBC/PKCS7PADDING", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("DESEDE/CFB/PKCS5PADDING", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("DESEDE/CFB/PKCS7PADDING", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("DESEDE/CTR/PKCS5PADDING", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("DESEDE/CTR/PKCS7PADDING", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("DESEDE/CTS/PKCS5PADDING", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("DESEDE/CTS/PKCS7PADDING", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("DESEDE/ECB/PKCS5PADDING", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("DESEDE/ECB/PKCS7PADDING", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("DESEDE/OFB/PKCS5PADDING", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("DESEDE/OFB/PKCS7PADDING", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("PBEWITHSHAAND2-KEYTRIPLEDES-CBC", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("PBEWITHSHAAND3-KEYTRIPLEDES-CBC", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("PBEWITHMD5ANDTRIPLEDES", Cipher.ENCRYPT_MODE, 8);
        setExpectedOutputSize("PBEWITHSHA1ANDDESEDE", Cipher.ENCRYPT_MODE, 8);

        setExpectedOutputSize("DESEDE", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/CBC/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/CBC/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/CFB/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/CFB/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/CTR/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/CTR/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/CTS/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/CTS/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/ECB/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/ECB/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/OFB/PKCS5PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("DESEDE/OFB/PKCS7PADDING", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHSHAAND2-KEYTRIPLEDES-CBC", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHSHAAND3-KEYTRIPLEDES-CBC", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHMD5ANDTRIPLEDES", Cipher.DECRYPT_MODE, 0);
        setExpectedOutputSize("PBEWITHSHA1ANDDESEDE", Cipher.DECRYPT_MODE, 0);

        if (StandardNames.IS_RI) {
            setExpectedOutputSize("DESEDEWRAP", Cipher.WRAP_MODE, 16);
            setExpectedOutputSize("DESEDEWRAP", Cipher.UNWRAP_MODE, 0);
        } else {
            setExpectedOutputSize("DESEDEWRAP", -1);
        }

        setExpectedOutputSize("RSA", Cipher.ENCRYPT_MODE, 256);
        setExpectedOutputSize("RSA/ECB/NoPadding", Cipher.ENCRYPT_MODE, 256);
        setExpectedOutputSize("RSA/ECB/PKCS1Padding", Cipher.ENCRYPT_MODE, 256);

        setExpectedOutputSize("RSA", Cipher.DECRYPT_MODE, 256);
        setExpectedOutputSize("RSA/ECB/NoPadding", Cipher.DECRYPT_MODE, 256);
        setExpectedOutputSize("RSA/ECB/PKCS1Padding", Cipher.DECRYPT_MODE, 245);
        setExpectedOutputSize("RSA/ECB/OAEPPadding", Cipher.DECRYPT_MODE, 256);

        // SunJCE returns the full for size even when PKCS1Padding is specified
        setExpectedOutputSize("RSA/ECB/PKCS1Padding", Cipher.DECRYPT_MODE, "SunJCE", 256);

        // BC strips the leading 0 for us even when NoPadding is specified
        setExpectedOutputSize("RSA", Cipher.DECRYPT_MODE, "BC", 255);
        setExpectedOutputSize("RSA/ECB/NoPadding", Cipher.DECRYPT_MODE, "BC", 255);

        // OAEP padding modes change the output and block size. SHA-1 is the default.
        setExpectedOutputSize("RSA/ECB/OAEPPadding", Cipher.DECRYPT_MODE, 214);
        setExpectedOutputSize("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", Cipher.DECRYPT_MODE, 214);
        setExpectedOutputSize("RSA/ECB/OAEPWithSHA-224AndMGF1Padding", Cipher.DECRYPT_MODE, 198);
        setExpectedOutputSize("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", Cipher.DECRYPT_MODE, 190);
        setExpectedOutputSize("RSA/ECB/OAEPWithSHA-384AndMGF1Padding", Cipher.DECRYPT_MODE, 158);
        setExpectedOutputSize("RSA/ECB/OAEPWithSHA-512AndMGF1Padding", Cipher.DECRYPT_MODE, 126);

        setExpectedOutputSize("RSA/ECB/OAEPPadding", Cipher.ENCRYPT_MODE, 256);
        setExpectedOutputSize("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", Cipher.ENCRYPT_MODE, 256);
        setExpectedOutputSize("RSA/ECB/OAEPWithSHA-224AndMGF1Padding", Cipher.ENCRYPT_MODE, 256);
        setExpectedOutputSize("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", Cipher.ENCRYPT_MODE, 256);
        setExpectedOutputSize("RSA/ECB/OAEPWithSHA-384AndMGF1Padding", Cipher.ENCRYPT_MODE, 256);
        setExpectedOutputSize("RSA/ECB/OAEPWithSHA-512AndMGF1Padding", Cipher.ENCRYPT_MODE, 256);
    }

    private static void setExpectedOutputSize(String algorithm, int value) {
        setExpectedSize(EXPECTED_OUTPUT_SIZE, algorithm, value);
    }

    private static void setExpectedOutputSize(String algorithm, int mode, int value) {
        setExpectedSize(EXPECTED_OUTPUT_SIZE, algorithm, mode, value);
    }

    private static void setExpectedOutputSize(String algorithm, int mode, String provider, int value) {
        setExpectedSize(EXPECTED_OUTPUT_SIZE, algorithm, mode, provider, value);
    }

    private static int getExpectedOutputSize(String algorithm, int mode, String provider) {
        return getExpectedSize(EXPECTED_OUTPUT_SIZE, algorithm, mode, provider);
    }

    private static final byte[] ORIGINAL_PLAIN_TEXT = new byte[] { 0x0a, 0x0b, 0x0c };
    private static final byte[] SIXTEEN_BYTE_BLOCK_PLAIN_TEXT = new byte[] { 0x0a, 0x0b, 0x0c, 0x00,
                                                                             0x00, 0x00, 0x00, 0x00,
                                                                             0x00, 0x00, 0x00, 0x00,
                                                                             0x00, 0x00, 0x00, 0x00 };
    private static final byte[] EIGHT_BYTE_BLOCK_PLAIN_TEXT = new byte[] { 0x0a, 0x0b, 0x0c, 0x00,
            0x00, 0x00, 0x00, 0x00 };
    private static final byte[] PKCS1_BLOCK_TYPE_00_PADDED_PLAIN_TEXT = new byte[] {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x0b, 0x0c
    };
    private static final byte[] PKCS1_BLOCK_TYPE_01_PADDED_PLAIN_TEXT = new byte[] {
        (byte) 0x00, (byte) 0x01, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c
    };
    private static final byte[] PKCS1_BLOCK_TYPE_02_PADDED_PLAIN_TEXT = new byte[] {
        (byte) 0x00, (byte) 0x02, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c
    };


    private static byte[] getActualPlainText(String algorithm) {
        // Block mode AES with NoPadding needs to match underlying block size
        if (algorithm.equals("AES")
            || algorithm.equals("AES/CBC/NOPADDING")
            || algorithm.equals("AES/CTS/NOPADDING")
            || algorithm.equals("AES/ECB/NOPADDING")
            || algorithm.equals("AES_128/CBC/NOPADDING")
            || algorithm.equals("AES_128/ECB/NOPADDING")
            || algorithm.equals("AES_256/CBC/NOPADDING")
            || algorithm.equals("AES_256/ECB/NOPADDING")) {
            return SIXTEEN_BYTE_BLOCK_PLAIN_TEXT;
        }
        if (algorithm.equals("DESEDE")
            || algorithm.equals("DESEDE/CBC/NOPADDING")
            || algorithm.equals("DESEDE/ECB/NOPADDING")) {
            return EIGHT_BYTE_BLOCK_PLAIN_TEXT;
        }
        return ORIGINAL_PLAIN_TEXT;
    }

    private static byte[] getExpectedPlainText(String algorithm, String provider) {
        // Block mode AES with NoPadding needs to match underlying block size
        if (algorithm.equals("AES")
            || algorithm.equals("AES/CBC/NOPADDING")
            || algorithm.equals("AES/CTS/NOPADDING")
            || algorithm.equals("AES/ECB/NOPADDING")
            || algorithm.equals("AES_128/CBC/NOPADDING")
            || algorithm.equals("AES_128/ECB/NOPADDING")
            || algorithm.equals("AES_256/CBC/NOPADDING")
            || algorithm.equals("AES_256/ECB/NOPADDING")) {
            return SIXTEEN_BYTE_BLOCK_PLAIN_TEXT;
        }
        if (algorithm.equals("DESEDE")
            || algorithm.equals("DESEDE/CBC/NOPADDING")
            || algorithm.equals("DESEDE/ECB/NOPADDING")) {
            return EIGHT_BYTE_BLOCK_PLAIN_TEXT;
        }
        // BC strips the leading 0 for us even when NoPadding is specified
        if (!provider.equals("BC") && algorithm.equals("RSA/ECB/NOPADDING")) {
            return PKCS1_BLOCK_TYPE_00_PADDED_PLAIN_TEXT;
        }
        return ORIGINAL_PLAIN_TEXT;
    }

    private static AlgorithmParameterSpec getEncryptAlgorithmParameterSpec(String algorithm) {
        if (isPBE(algorithm)) {
            final byte[] salt = new byte[8];
            new SecureRandom().nextBytes(salt);
            return new PBEParameterSpec(salt, 1024);
        }
        if (algorithm.equals("AES/GCM/NOPADDING")
            || algorithm.equals("AES_128/GCM/NOPADDING")
            || algorithm.equals("AES_256/GCM/NOPADDING")) {
            final byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            return new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv);
        }
        if (algorithm.equals("AES/GCM-SIV/NOPADDING")
            || algorithm.equals("AES_128/GCM-SIV/NOPADDING")
            || algorithm.equals("AES_256/GCM-SIV/NOPADDING")) {
            final byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            return new GCMParameterSpec(GCM_SIV_TAG_SIZE_BITS, iv);
        }
        if (algorithm.equals("AES/CBC/NOPADDING")
            || algorithm.equals("AES/CBC/PKCS5PADDING")
            || algorithm.equals("AES/CBC/PKCS7PADDING")
            || algorithm.equals("AES/CFB/NOPADDING")
            || algorithm.equals("AES/CTR/NOPADDING")
            || algorithm.equals("AES/CTS/NOPADDING")
            || algorithm.equals("AES/OFB/NOPADDING")
            || algorithm.equals("AES_128/CBC/NOPADDING")
            || algorithm.equals("AES_128/CBC/PKCS5PADDING")
            || algorithm.equals("AES_128/CBC/PKCS7PADDING")
            || algorithm.equals("AES_256/CBC/NOPADDING")
            || algorithm.equals("AES_256/CBC/PKCS5PADDING")
            || algorithm.equals("AES_256/CBC/PKCS7PADDING")) {
            final byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            return new IvParameterSpec(iv);
        }
        if (algorithm.equals("DESEDE/CBC/NOPADDING")
            || algorithm.equals("DESEDE/CBC/PKCS5PADDING")
            || algorithm.equals("DESEDE/CBC/PKCS7PADDING")
            || algorithm.equals("DESEDE/CFB/NOPADDING")
            || algorithm.equals("DESEDE/CTR/NOPADDING")
            || algorithm.equals("DESEDE/CTS/NOPADDING")
            || algorithm.equals("DESEDE/OFB/NOPADDING")) {
            final byte[] iv = new byte[8];
            new SecureRandom().nextBytes(iv);
            return new IvParameterSpec(iv);
        }
        if (algorithm.equals("CHACHA20")
            || algorithm.equals("CHACHA20/POLY1305/NOPADDING")) {
            final byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            return new IvParameterSpec(iv);
        }
        return null;
    }

    private static AlgorithmParameterSpec getDecryptAlgorithmParameterSpec(AlgorithmParameterSpec encryptSpec,
                                                                           Cipher encryptCipher) {
        String algorithm = encryptCipher.getAlgorithm().toUpperCase(Locale.US);
        if (isPBE(algorithm)) {
            return encryptSpec;
        }
        if (isOnlyWrappingAlgorithm(algorithm)) {
            return null;
        }
        byte[] iv = encryptCipher.getIV();
        if (iv != null) {
            if ("AES/GCM/NOPADDING".equals(algorithm)
                    || "AES_128/GCM/NOPADDING".equals(algorithm)
                    || "AES_256/GCM/NOPADDING".equals(algorithm)) {
                return new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv);
            }
            if ("AES/GCM-SIV/NOPADDING".equals(algorithm)
                || "AES_128/GCM-SIV/NOPADDING".equals(algorithm)
                || "AES_256/GCM-SIV/NOPADDING".equals(algorithm)) {
                return new GCMParameterSpec(GCM_SIV_TAG_SIZE_BITS, iv);
            }
            return new IvParameterSpec(iv);
        }
        return null;
    }

    /*
     * This must be below everything else to make sure the other static blocks
     * have run first.
     */
    private static final boolean IS_UNLIMITED;
    static {
        boolean is_unlimited;
        if (StandardNames.IS_RI) {
            try {
                String algorithm = "PBEWITHMD5ANDTRIPLEDES";
                Cipher.getInstance(algorithm).init(getEncryptMode(algorithm),
                                                   getEncryptKey(algorithm),
                                                   getEncryptAlgorithmParameterSpec(algorithm));
                is_unlimited = true;
            } catch (Exception e) {
                is_unlimited = false;
                System.out.println("WARNING: Some tests disabled due to lack of "
                                   + "'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files'");
            }
        } else {
            is_unlimited = true;
        }
        IS_UNLIMITED = is_unlimited;
    }

    @Test
    public void test_getInstance() throws Exception {
        final ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(errBuffer);

        Set<String> seenBaseCipherNames = new HashSet<>();
        Set<String> seenCiphersWithModeAndPadding = new HashSet<>();

        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                String type = service.getType();
                if (!type.equals("Cipher")) {
                    continue;
                }

                String algorithm = service.getAlgorithm().toUpperCase(Locale.US);

                /*
                 * Any specific modes and paddings aren't tested directly here,
                 * but we need to make sure we see the bare algorithm from some
                 * provider. We will test each mode specifically when we get the
                 * base cipher.
                 */
                final int firstSlash = algorithm.indexOf('/');
                if (firstSlash == -1) {
                    seenBaseCipherNames.add(algorithm);
                } else {
                    final int secondSlash = algorithm.indexOf('/', firstSlash + 1);
                    if (secondSlash > 0) {
                        // Only look for a base Cipher if there are two slashes, to avoid SunJCE
                        // quirks like PBEWithHmacSHA512/224AndAES_128
                        final String baseCipherName = algorithm.substring(0, firstSlash);
                        if (!seenBaseCipherNames.contains(baseCipherName)
                            && !(baseCipherName.equals("AES_128")
                            || baseCipherName.equals("AES_192")
                            || baseCipherName.equals("AES_256"))) {
                            seenCiphersWithModeAndPadding.add(baseCipherName);
                        }
                        if (!Conscrypt.isConscrypt(provider)) {
                            continue;
                        }
                    }
                }

                if (provider.getName().equals("SunJCE")) {
                    // The SunJCE provider acts in numerous idiosyncratic ways that don't
                    // match any other provider.  Examples include returning non-null IVs
                    // when no IV was provided on init, NullPointerExceptions when null
                    // SecureRandoms are supplied (but only to PBE ciphers), and not
                    // supplying KeyGenerators for some algorithms.  We aren't sufficiently
                    // interested in verifying this provider's behavior to adapt the
                    // tests and Oracle presumably tests them well anyway, so just skip
                    // verifying them.
                    continue;
                }

                try {
                    test_Cipher_Algorithm(provider, algorithm);
                } catch (Throwable e) {
                    out.append("Error encountered checking " + algorithm
                               + " with provider " + provider.getName() + "\n");
                    e.printStackTrace(out);
                }

                Set<String> modes = StandardNames.getModesForCipher(algorithm);
                if (modes != null) {
                    for (String mode : modes) {
                        Set<String> paddings = StandardNames.getPaddingsForCipher(algorithm);
                        if (paddings != null) {
                            for (String padding : paddings) {
                                final String algorithmName = algorithm + "/" + mode + "/" + padding;
                                try {
                                    if (isSupported(algorithmName, provider.getName())) {
                                        test_Cipher_Algorithm(provider, algorithmName);
                                    }
                                } catch (Throwable e) {
                                    out.append("Error encountered checking " + algorithmName
                                               + " with provider " + provider.getName() + "\n");
                                    e.printStackTrace(out);
                                }
                            }
                        }
                    }
                }
            }
        }

        seenCiphersWithModeAndPadding.removeAll(seenBaseCipherNames);
        assertEquals("Ciphers seen with mode and padding but not base cipher",
                Collections.EMPTY_SET, seenCiphersWithModeAndPadding);

        out.flush();
        if (errBuffer.size() > 0) {
            throw new Exception("Errors encountered:\n\n" + errBuffer + "\n\n");
        }
    }

    private void test_Cipher_Algorithm(Provider provider, String algorithm) throws Exception {
        if (algorithm.equals("RSA") && provider.getName().equals("BC")) {
            // http://b/9097343 BC's Cipher.RSA defaults to NoPadding
            // which makes it fail the key wrapping test if the
            // generated AES key to wrap starts with a leading
            // zero. For the purposes of the test, use the same
            // default behavior as the RI. Real code really should
            // specify the exact mode and padding they need and not
            // rely on defaults. http://b/9097343
            algorithm = "RSA/ECB/PKCS1Padding";
        }

        // SunMSCAPI seems to have different opinion on what RSA should do compared to other
        // providers. As such it fails many tests, so we will skip it for now.
        if (algorithm.startsWith("RSA") && provider.getName().equals("SunMSCAPI")) {
            return;
        }

        // Cipher.getInstance(String)
        Cipher c1 = Cipher.getInstance(algorithm);
        if (provider.equals(c1.getProvider())) {
            assertEquals(algorithm, c1.getAlgorithm());
            test_Cipher(c1);
        }

        // Cipher.getInstance(String, Provider)
        Cipher c2 = Cipher.getInstance(algorithm, provider);
        assertEquals(algorithm, c2.getAlgorithm());
        assertEquals(provider, c2.getProvider());
        test_Cipher(c2);

        // Cipher.getInstance(String, String)
        Cipher c3 = Cipher.getInstance(algorithm, provider.getName());
        assertEquals(algorithm, c3.getAlgorithm());
        assertEquals(provider, c3.getProvider());
        test_Cipher(c3);
    }

    private void test_Cipher(Cipher c) throws Exception {
        String algorithm = c.getAlgorithm().toUpperCase(Locale.US);
        String providerName = c.getProvider().getName();
        if (!isSupported(algorithm, providerName)) {
            return;
        }
        String cipherID = algorithm + ":" + providerName;

        try {
            c.getOutputSize(0);
            fail("getOutputSize() should throw if called before Cipher initialization");
        } catch (IllegalStateException expected) {
        }

        // TODO: test keys from different factories (e.g. OpenSSLRSAPrivateKey vs BCRSAPrivateKey)
        Key encryptKey = getEncryptKey(algorithm);

        AlgorithmParameterSpec encryptSpec = getEncryptAlgorithmParameterSpec(algorithm);
        int encryptMode = getEncryptMode(algorithm);

        // Bouncycastle doesn't return a default PBEParameterSpec
        if (isPBE(algorithm) && !"BC".equals(providerName)) {
            assertNotNull(cipherID + " getParameters()", c.getParameters());
            assertNotNull(c.getParameters().getParameterSpec(PBEParameterSpec.class));
        } else {
            assertNull(cipherID + " getParameters()", c.getParameters());
        }
        try {
            assertNull(cipherID + " getIV()", c.getIV());
        } catch (NullPointerException e) {
            // Bouncycastle apparently has a bug here with AESWRAP, et al.
            if (!("BC".equals(providerName) && isOnlyWrappingAlgorithm(algorithm))) {
                throw e;
            }
        }

        test_Cipher_init_NullParameters(c, encryptMode, encryptKey);

        c.init(encryptMode, encryptKey, encryptSpec);
        assertEquals(cipherID + " getBlockSize() encryptMode",
                getExpectedBlockSize(algorithm, encryptMode, providerName), c.getBlockSize());
        assertTrue(cipherID + " getOutputSize(0) encryptMode",
                getExpectedOutputSize(algorithm, encryptMode, providerName) <= c.getOutputSize(0));
        if ((algorithm.endsWith("/PKCS5PADDING") || algorithm.endsWith("/PKCS7PADDING"))
                && isStreamMode(algorithm)) {
            assertEquals(getExpectedOutputSize(algorithm, encryptMode, providerName),
                    c.doFinal(new byte[1]).length);
        }

        if (isPBE(algorithm)) {
            if (algorithm.endsWith("RC4")) {
                assertNull(cipherID + " getIV()", c.getIV());
            } else {
                assertNotNull(cipherID + " getIV()", c.getIV());
            }
        } else if (encryptSpec instanceof IvParameterSpec) {
            assertEquals(cipherID + " getIV()",
                    Arrays.toString(((IvParameterSpec) encryptSpec).getIV()),
                    Arrays.toString(c.getIV()));
        } else if (encryptSpec instanceof GCMParameterSpec) {
            assertNotNull(c.getIV());
            assertEquals(cipherID + " getIV()",
                    Arrays.toString(((GCMParameterSpec) encryptSpec).getIV()),
                    Arrays.toString(c.getIV()));
        } else {
            try {
                assertNull(cipherID + " getIV()", c.getIV());
            } catch (NullPointerException e) {
                // Bouncycastle apparently has a bug here with AESWRAP, et al.
                if (!("BC".equals(providerName) && isOnlyWrappingAlgorithm(algorithm))) {
                    throw e;
                }
            }
        }

        AlgorithmParameters encParams = c.getParameters();
        assertCorrectAlgorithmParameters(providerName, cipherID, encryptSpec, encParams);

        AlgorithmParameterSpec decryptSpec = getDecryptAlgorithmParameterSpec(encryptSpec, c);
        int decryptMode = getDecryptMode(algorithm);

        Key decryptKey = getDecryptKey(algorithm);

        test_Cipher_init_Decrypt_NullParameters(c, decryptMode, decryptKey, decryptSpec != null);

        c.init(decryptMode, decryptKey, decryptSpec);
        assertEquals(cipherID + " getBlockSize() decryptMode",
                     getExpectedBlockSize(algorithm, decryptMode, providerName), c.getBlockSize());
        assertEquals(cipherID + " getOutputSize(0) decryptMode",
                     getExpectedOutputSize(algorithm, decryptMode, providerName), c.getOutputSize(0));

        if (isPBE(algorithm)) {
            if (algorithm.endsWith("RC4")) {
                assertNull(cipherID + " getIV()", c.getIV());
            } else {
                assertNotNull(cipherID + " getIV()", c.getIV());
            }
        } else if (decryptSpec instanceof IvParameterSpec) {
            assertEquals(cipherID + " getIV()",
                    Arrays.toString(((IvParameterSpec) decryptSpec).getIV()),
                    Arrays.toString(c.getIV()));
        } else if (decryptSpec instanceof GCMParameterSpec) {
            assertNotNull(c.getIV());
            assertEquals(cipherID + " getIV()",
                    Arrays.toString(((GCMParameterSpec) decryptSpec).getIV()),
                    Arrays.toString(c.getIV()));
        } else {
            try {
                assertNull(cipherID + " getIV()", c.getIV());
            } catch (NullPointerException e) {
                // Bouncycastle apparently has a bug here with AESWRAP, et al.
                if (!("BC".equals(providerName) && isOnlyWrappingAlgorithm(algorithm))) {
                    throw e;
                }
            }
        }

        AlgorithmParameters decParams = c.getParameters();
        assertCorrectAlgorithmParameters(providerName, cipherID, decryptSpec, decParams);

        assertNull(cipherID, c.getExemptionMechanism());

        // Test wrapping a key.  Every cipher should be able to wrap. Except those that can't.
        /* Bouncycastle is broken for wrapping because getIV() fails. */
        if (isSupportedForWrapping(algorithm) && !providerName.equals("BC")) {
            // Generate a small SecretKey for AES.
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey sk = kg.generateKey();

            // Wrap it.  Use a new encrypt spec so that AEAD algorithms that prohibit IV reuse
            // don't complain.
            encryptSpec = getEncryptAlgorithmParameterSpec(algorithm);
            c.init(Cipher.WRAP_MODE, encryptKey, encryptSpec);
            byte[] cipherText = c.wrap(sk);

            // Unwrap it
            c.init(Cipher.UNWRAP_MODE, decryptKey, getDecryptAlgorithmParameterSpec(encryptSpec, c));
            Key decryptedKey = c.unwrap(cipherText, sk.getAlgorithm(), Cipher.SECRET_KEY);

            assertEquals(cipherID
                    + " sk.getAlgorithm()=" + sk.getAlgorithm()
                    + " decryptedKey.getAlgorithm()=" + decryptedKey.getAlgorithm()
                    + " encryptKey.getEncoded()=" + Arrays.toString(sk.getEncoded())
                    + " decryptedKey.getEncoded()=" + Arrays.toString(decryptedKey.getEncoded()),
                    sk, decryptedKey);
        }

        if (!isOnlyWrappingAlgorithm(algorithm)) {
            // Use a new encrypt spec so that AEAD algorithms that prohibit IV reuse don't complain
            encryptSpec = getEncryptAlgorithmParameterSpec(algorithm);
            c.init(Cipher.ENCRYPT_MODE, encryptKey, encryptSpec);
            if (isAEAD(algorithm)) {
                c.updateAAD(new byte[24]);
            }
            byte[] cipherText = c.doFinal(getActualPlainText(algorithm));
            if (!isRandomizedEncryption(algorithm) && !isAEAD(algorithm)) {
                byte[] cipherText2 = c.doFinal(getActualPlainText(algorithm));
                assertEquals(cipherID, Arrays.toString(cipherText), Arrays.toString(cipherText2));
            }
            decryptSpec = getDecryptAlgorithmParameterSpec(encryptSpec, c);
            c.init(Cipher.DECRYPT_MODE, decryptKey, decryptSpec);
            if (isAEAD(algorithm)) {
                c.updateAAD(new byte[24]);
            }
            byte[] decryptedPlainText = c.doFinal(cipherText);
            assertEquals(cipherID,
                         Arrays.toString(getExpectedPlainText(algorithm, providerName)),
                         Arrays.toString(decryptedPlainText));
            if (isAEAD(algorithm)) {
                c.updateAAD(new byte[24]);
            }
            byte[] decryptedPlainText2 = c.doFinal(cipherText);
            assertEquals(cipherID,
                         Arrays.toString(decryptedPlainText),
                         Arrays.toString(decryptedPlainText2));

            // Use a new encrypt spec so that AEAD algorithms that prohibit IV reuse don't complain
            encryptSpec = getEncryptAlgorithmParameterSpec(algorithm);
            test_Cipher_ShortBufferException(c, algorithm, Cipher.ENCRYPT_MODE, encryptSpec,
                    encryptKey, getActualPlainText(algorithm));
            decryptSpec = getDecryptAlgorithmParameterSpec(encryptSpec, c);
            test_Cipher_ShortBufferException(c, algorithm, Cipher.DECRYPT_MODE, decryptSpec,
                    decryptKey, cipherText);

            test_Cipher_aborted_doFinal(c, algorithm, providerName, encryptKey, decryptKey);
        }
    }

    private void assertCorrectAlgorithmParameters(String providerName, String cipherID,
            final AlgorithmParameterSpec spec, AlgorithmParameters params)
            throws Exception {
        if (spec == null) {
            return;
        }

        // Bouncycastle has a bug where PBE algorithms sometimes return null parameters.
        if ("BC".equals(providerName) && isPBE(cipherID) && params == null) {
            return;
        }

        assertNotNull(cipherID + " getParameters() should not be null", params);

        if (spec instanceof GCMParameterSpec) {
            GCMParameterSpec gcmDecryptSpec = params.getParameterSpec(GCMParameterSpec.class);
            assertEquals(cipherID + " getIV()", Arrays.toString(((GCMParameterSpec) spec).getIV()),
                    Arrays.toString(gcmDecryptSpec.getIV()));
            assertEquals(cipherID + " getTLen()", ((GCMParameterSpec) spec).getTLen(),
                    gcmDecryptSpec.getTLen());
        } else if (spec instanceof IvParameterSpec) {
            IvParameterSpec ivDecryptSpec = params.getParameterSpec(IvParameterSpec.class);
            assertEquals(cipherID + " getIV()", Arrays.toString(((IvParameterSpec) spec).getIV()),
                    Arrays.toString(ivDecryptSpec.getIV()));
        } else if (spec instanceof PBEParameterSpec) {
            // Bouncycastle seems to be undecided about whether it returns this
            // or not
            if (!"BC".equals(providerName)) {
                assertNotNull(cipherID + " getParameters()", params);
            }
        } else if (spec instanceof OAEPParameterSpec) {
            assertOAEPParametersEqual((OAEPParameterSpec) spec,
                    params.getParameterSpec(OAEPParameterSpec.class));
        } else {
            fail("Unhandled algorithm specification class: " + spec.getClass().getName());
        }
    }

    private static void assertOAEPParametersEqual(OAEPParameterSpec expectedOaepSpec,
            OAEPParameterSpec actualOaepSpec) {
        assertEquals(expectedOaepSpec.getDigestAlgorithm(), actualOaepSpec.getDigestAlgorithm());

        assertEquals(expectedOaepSpec.getMGFAlgorithm(), actualOaepSpec.getMGFAlgorithm());
        if ("MGF1".equals(expectedOaepSpec.getMGFAlgorithm())) {
            MGF1ParameterSpec expectedMgf1Spec = (MGF1ParameterSpec) expectedOaepSpec
                    .getMGFParameters();
            MGF1ParameterSpec actualMgf1Spec = (MGF1ParameterSpec) actualOaepSpec
                    .getMGFParameters();
            assertEquals(expectedMgf1Spec.getDigestAlgorithm(),
                    actualMgf1Spec.getDigestAlgorithm());
        } else {
            fail("Unknown MGF algorithm: " + expectedOaepSpec.getMGFAlgorithm());
        }

        if (expectedOaepSpec.getPSource() instanceof PSource.PSpecified
                && actualOaepSpec.getPSource() instanceof PSource.PSpecified) {
            assertEquals(
                    Arrays.toString(
                            ((PSource.PSpecified) expectedOaepSpec.getPSource()).getValue()),
                    Arrays.toString(
                            ((PSource.PSpecified) actualOaepSpec.getPSource()).getValue()));
        } else {
            fail("Unknown PSource type");
        }
    }

    /**
     * Try various .init(...) calls with null parameters to make sure it is
     * handled.
     */
    private void test_Cipher_init_NullParameters(Cipher c, int encryptMode, Key encryptKey)
            throws Exception {
        try {
            c.init(encryptMode, encryptKey, (AlgorithmParameterSpec) null);
        } catch (InvalidAlgorithmParameterException e) {
            if (!isPBE(c.getAlgorithm())) {
                throw e;
            }
        }

        try {
            c.init(encryptMode, encryptKey, (AlgorithmParameterSpec) null, null);
        } catch (InvalidAlgorithmParameterException e) {
            if (!isPBE(c.getAlgorithm())) {
                throw e;
            }
        }

        try {
            c.init(encryptMode, encryptKey, (AlgorithmParameters) null);
        } catch (InvalidAlgorithmParameterException e) {
            if (!isPBE(c.getAlgorithm())) {
                throw e;
            }
        }

        try {
            c.init(encryptMode, encryptKey, (AlgorithmParameters) null, null);
        } catch (InvalidAlgorithmParameterException e) {
            if (!isPBE(c.getAlgorithm())) {
                throw e;
            }
        }
    }

    private void test_Cipher_init_Decrypt_NullParameters(Cipher c, int decryptMode, Key encryptKey,
            boolean needsParameters) throws Exception {
        try {
            c.init(decryptMode, encryptKey, (AlgorithmParameterSpec) null);
            if (needsParameters) {
                fail("Should throw InvalidAlgorithmParameterException with null parameters");
            }
        } catch (InvalidAlgorithmParameterException e) {
            if (!needsParameters) {
                throw e;
            }
        }

        try {
            c.init(decryptMode, encryptKey, (AlgorithmParameterSpec) null, null);
            if (needsParameters) {
                fail("Should throw InvalidAlgorithmParameterException with null parameters");
            }
        } catch (InvalidAlgorithmParameterException e) {
            if (!needsParameters) {
                throw e;
            }
        }

        try {
            c.init(decryptMode, encryptKey, (AlgorithmParameters) null);
            if (needsParameters) {
                fail("Should throw InvalidAlgorithmParameterException with null parameters");
            }
        } catch (InvalidAlgorithmParameterException e) {
            if (!needsParameters) {
                throw e;
            }
        }

        try {
            c.init(decryptMode, encryptKey, (AlgorithmParameters) null, null);
            if (needsParameters) {
                fail("Should throw InvalidAlgorithmParameterException with null parameters");
            }
        } catch (InvalidAlgorithmParameterException e) {
            if (!needsParameters) {
                throw e;
            }
        }
    }

    // Checks that the Cipher throws ShortBufferException when given a too-short buffer
    private void test_Cipher_ShortBufferException(Cipher c, String algorithm, int encryptMode,
            AlgorithmParameterSpec spec, Key key, byte[] text) throws Exception {
        c.init(encryptMode, key, spec);
        if (isAEAD(algorithm)) {
            c.updateAAD(new byte[24]);
        }
        if (c.getOutputSize(text.length) > 0) {
            byte[] output;
            if (algorithm.startsWith("RSA/")) {
                // RSA encryption pads the input data to a full block before encrypting,
                // so unlike most algorithms, getOutputSize can't determine how much space
                // is necessary until the data is actually decrypted.
                output = new byte[1];
            } else {
                // Other algorithms can much more easily forsee how much output data there
                // will be, so don't let them get away with being overly conservative.
                output = new byte[c.getOutputSize(text.length) - 1];
            }
            try {
                c.doFinal(text, 0, text.length, output);
                fail("Short buffer should have thrown ShortBufferException");
            } catch (ShortBufferException expected) {
                // Ignored
            }
        }
    }

    // Checks that if the cipher operation is aborted by a ShortBufferException the output
    // is still correct.
    private void test_Cipher_aborted_doFinal(Cipher c, String algorithm, String provider,
            Key encryptKey, Key decryptKey) throws Exception {
        byte[] text = getActualPlainText(algorithm);
        AlgorithmParameterSpec encryptSpec = getEncryptAlgorithmParameterSpec(algorithm);
        c.init(Cipher.ENCRYPT_MODE, encryptKey, encryptSpec);
        if (isAEAD(algorithm)) {
            c.updateAAD(new byte[24]);
        }
        try {
            c.doFinal(text, 0, text.length, new byte[0]);
            fail("Short buffer should have thrown ShortBufferException");
        } catch (ShortBufferException expected) {
            // Ignored
        }
        byte[] cipherText = c.doFinal(text);
        c.init(Cipher.DECRYPT_MODE, decryptKey, getDecryptAlgorithmParameterSpec(encryptSpec, c));
        if (isAEAD(algorithm)) {
            c.updateAAD(new byte[24]);
        }
        byte[] plainText = c.doFinal(cipherText);
        byte[] expectedPlainText = getExpectedPlainText(algorithm, provider);
        assertArrayEquals("Expected " + Arrays.toString(expectedPlainText) + " but was "
                + Arrays.toString(plainText)
                , expectedPlainText, plainText);
    }

    @Test
    public void testInputPKCS1Padding() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testInputPKCS1Padding(provider);
        }
    }

    private void testInputPKCS1Padding(String provider) throws Exception {
        // Type 1 is for signatures (PrivateKey to "encrypt")
        testInputPKCS1Padding(provider, PKCS1_BLOCK_TYPE_01_PADDED_PLAIN_TEXT, getDecryptKey("RSA"), getEncryptKey("RSA"));
        try {
            testInputPKCS1Padding(provider, PKCS1_BLOCK_TYPE_02_PADDED_PLAIN_TEXT, getDecryptKey("RSA"), getEncryptKey("RSA"));
            fail();
        } catch (BadPaddingException expected) {
        }

        // Type 2 is for enciphering (PublicKey to "encrypt")
        testInputPKCS1Padding(provider, PKCS1_BLOCK_TYPE_02_PADDED_PLAIN_TEXT, getEncryptKey("RSA"), getDecryptKey("RSA"));
        try {
            testInputPKCS1Padding(provider, PKCS1_BLOCK_TYPE_01_PADDED_PLAIN_TEXT, getEncryptKey("RSA"), getDecryptKey("RSA"));
            fail();
        } catch (BadPaddingException expected) {
        }
    }

    private void testInputPKCS1Padding(String provider, byte[] prePaddedPlainText, Key encryptKey, Key decryptKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/NoPadding", provider);
        encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey);
        byte[] cipherText = encryptCipher.doFinal(prePaddedPlainText);
        encryptCipher.update(prePaddedPlainText);
        encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey);
        byte[] cipherText2 = encryptCipher.doFinal(prePaddedPlainText);
        assertEquals(Arrays.toString(cipherText),
                     Arrays.toString(cipherText2));

        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
        decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey);
        byte[] plainText = decryptCipher.doFinal(cipherText);
        assertEquals(Arrays.toString(ORIGINAL_PLAIN_TEXT),
                     Arrays.toString(plainText));
        decryptCipher.update(prePaddedPlainText);
        decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey);
        byte[] plainText2 = decryptCipher.doFinal(cipherText);
        assertEquals(Arrays.toString(plainText),
                     Arrays.toString(plainText2));
    }

    @Test
    public void testOutputPKCS1Padding() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testOutputPKCS1Padding(provider);
        }
    }

    private void testOutputPKCS1Padding(String provider) throws Exception {
        // Type 1 is for signatures (PrivateKey to "encrypt")
        testOutputPKCS1Padding(provider, (byte) 1, getDecryptKey("RSA"), getEncryptKey("RSA"));
        // Type 2 is for enciphering (PublicKey to "encrypt")
        testOutputPKCS1Padding(provider, (byte) 2, getEncryptKey("RSA"), getDecryptKey("RSA"));
    }

    private void testOutputPKCS1Padding(String provider, byte expectedBlockType, Key encryptKey, Key decryptKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
        encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey);
        byte[] cipherText = encryptCipher.doFinal(ORIGINAL_PLAIN_TEXT);
        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/NoPadding", provider);
        decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey);
        byte[] plainText = decryptCipher.doFinal(cipherText);
        assertPadding(provider, expectedBlockType, ORIGINAL_PLAIN_TEXT, plainText);
    }

    private void assertPadding(String provider, byte expectedBlockType, byte[] expectedData, byte[] actualDataWithPadding) {
        assertNotNull(provider, actualDataWithPadding);
        int expectedOutputSize = getExpectedOutputSize("RSA", Cipher.DECRYPT_MODE, provider);
        assertEquals(provider, expectedOutputSize, actualDataWithPadding.length);
        int expectedBlockTypeOffset;
        if (provider.equals("BC")) {
            // BC strips the leading 0 for us on decrypt even when NoPadding is specified...
            expectedBlockTypeOffset = 0;
        } else {
            expectedBlockTypeOffset = 1;
            assertEquals(provider, 0, actualDataWithPadding[0]);
        }
        byte actualBlockType = actualDataWithPadding[expectedBlockTypeOffset];
        assertEquals(provider, expectedBlockType, actualBlockType);
        int actualDataOffset = actualDataWithPadding.length - expectedData.length;
        if (actualBlockType == 1) {
            int expectedDataOffset = expectedBlockTypeOffset + 1;
            for (int i = expectedDataOffset; i < actualDataOffset - 1; i++) {
                assertEquals(provider, (byte) 0xFF, actualDataWithPadding[i]);
            }
        }
        assertEquals(provider, 0x00, actualDataWithPadding[actualDataOffset-1]);
        byte[] actualData = new byte[expectedData.length];
        System.arraycopy(actualDataWithPadding, actualDataOffset, actualData, 0, actualData.length);
        assertEquals(provider, Arrays.toString(expectedData), Arrays.toString(actualData));
    }

    @Test
    public void testCipherInitWithCertificate () throws Exception {
        // no key usage specified, everything is fine
        assertCipherInitWithKeyUsage(0,                         true,  true, true,  true);

        // common case is that encrypt/wrap is prohibited when special usage is specified
        assertCipherInitWithKeyUsage(KeyUsage.digitalSignature, false, true, false, true);
        assertCipherInitWithKeyUsage(KeyUsage.nonRepudiation,   false, true, false, true);
        assertCipherInitWithKeyUsage(KeyUsage.keyAgreement,     false, true, false, true);
        assertCipherInitWithKeyUsage(KeyUsage.keyCertSign,      false, true, false, true);
        assertCipherInitWithKeyUsage(KeyUsage.cRLSign,          false, true, false, true);

        // Note they encipherOnly/decipherOnly don't have to do with
        // ENCRYPT_MODE or DECRYPT_MODE, but restrict usage relative
        // to keyAgreement. There is not a *_MODE option that
        // corresponds to this in Cipher, the RI does not enforce
        // anything in Cipher.
        // http://code.google.com/p/android/issues/detail?id=12955
        assertCipherInitWithKeyUsage(KeyUsage.encipherOnly,     false, true, false, true);
        assertCipherInitWithKeyUsage(KeyUsage.decipherOnly,     false, true, false, true);
        assertCipherInitWithKeyUsage(KeyUsage.keyAgreement | KeyUsage.encipherOnly,
                                                                false, true, false, true);
        assertCipherInitWithKeyUsage(KeyUsage.keyAgreement | KeyUsage.decipherOnly,
                                                                false, true, false, true);

        // except when wrapping a key is specifically allowed or
        assertCipherInitWithKeyUsage(KeyUsage.keyEncipherment,  false, true, true,  true);
        // except when wrapping data encryption is specifically allowed
        assertCipherInitWithKeyUsage(KeyUsage.dataEncipherment, true,  true, false, true);
    }

    private void assertCipherInitWithKeyUsage (int keyUsage,
                                               boolean allowEncrypt,
                                               boolean allowDecrypt,
                                               boolean allowWrap,
                                               boolean allowUnwrap) throws Exception {
        Certificate certificate = certificateWithKeyUsage(keyUsage);
        assertCipherInitWithKeyUsage(certificate, allowEncrypt, Cipher.ENCRYPT_MODE);
        assertCipherInitWithKeyUsage(certificate, allowDecrypt, Cipher.DECRYPT_MODE);
        assertCipherInitWithKeyUsage(certificate, allowWrap,    Cipher.WRAP_MODE);
        assertCipherInitWithKeyUsage(certificate, allowUnwrap,  Cipher.UNWRAP_MODE);
    }

    private void assertCipherInitWithKeyUsage(Certificate certificate,
                                              boolean allowMode,
                                              int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        if (allowMode) {
            cipher.init(mode, certificate);
        } else {
            try {
                cipher.init(mode, certificate);
                String modeString;
                switch (mode) {
                    case Cipher.ENCRYPT_MODE:
                        modeString = "ENCRYPT_MODE";
                        break;
                    case Cipher.DECRYPT_MODE:
                        modeString = "DECRYPT_MODE";
                        break;
                    case Cipher.WRAP_MODE:
                        modeString = "WRAP_MODE";
                        break;
                    case Cipher.UNWRAP_MODE:
                        modeString = "UNWRAP_MODE";
                        break;
                    default:
                        throw new AssertionError("Unknown Cipher.*_MODE " + mode);
                }
                fail("Should have had InvalidKeyException for " + modeString
                     + " for " + certificate);
            } catch (InvalidKeyException expected) {
            }
        }
    }

    private Certificate certificateWithKeyUsage(int keyUsage) {
        // note the rare usage of non-zero keyUsage
        return new TestKeyStore.Builder()
                .aliasPrefix("rsa-dsa-ec")
                .keyUsage(keyUsage)
                .build()
                .getPrivateKey("RSA", "RSA").getCertificate();
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

    private static final BigInteger RSA_2048_modulus = new BigInteger(new byte[] {
        (byte) 0x00, (byte) 0xe0, (byte) 0x47, (byte) 0x3e, (byte) 0x8a, (byte) 0xb8, (byte) 0xf2, (byte) 0x28,
        (byte) 0x4f, (byte) 0xeb, (byte) 0x9e, (byte) 0x74, (byte) 0x2f, (byte) 0xf9, (byte) 0x74, (byte) 0x8f,
        (byte) 0xa1, (byte) 0x18, (byte) 0xed, (byte) 0x98, (byte) 0x63, (byte) 0x3c, (byte) 0x92, (byte) 0xf5,
        (byte) 0x2a, (byte) 0xeb, (byte) 0x7a, (byte) 0x2e, (byte) 0xbe, (byte) 0x0d, (byte) 0x3b, (byte) 0xe6,
        (byte) 0x03, (byte) 0x29, (byte) 0xbe, (byte) 0x76, (byte) 0x6a, (byte) 0xd1, (byte) 0x0e, (byte) 0xb6,
        (byte) 0xa5, (byte) 0x15, (byte) 0xd0, (byte) 0xd2, (byte) 0xcf, (byte) 0xd9, (byte) 0xbe, (byte) 0xa7,
        (byte) 0x93, (byte) 0x0f, (byte) 0x0c, (byte) 0x30, (byte) 0x65, (byte) 0x37, (byte) 0x89, (byte) 0x9f,
        (byte) 0x79, (byte) 0x58, (byte) 0xcd, (byte) 0x3e, (byte) 0x85, (byte) 0xb0, (byte) 0x1f, (byte) 0x88,
        (byte) 0x18, (byte) 0x52, (byte) 0x4d, (byte) 0x31, (byte) 0x25, (byte) 0x84, (byte) 0xa9, (byte) 0x4b,
        (byte) 0x25, (byte) 0x1e, (byte) 0x36, (byte) 0x25, (byte) 0xb5, (byte) 0x41, (byte) 0x41, (byte) 0xed,
        (byte) 0xbf, (byte) 0xee, (byte) 0x19, (byte) 0x88, (byte) 0x08, (byte) 0xe1, (byte) 0xbb, (byte) 0x97,
        (byte) 0xfc, (byte) 0x7c, (byte) 0xb4, (byte) 0x9b, (byte) 0x9e, (byte) 0xaa, (byte) 0xaf, (byte) 0x68,
        (byte) 0xe9, (byte) 0xc9, (byte) 0x8d, (byte) 0x7d, (byte) 0x0e, (byte) 0xdc, (byte) 0x53, (byte) 0xbb,
        (byte) 0xc0, (byte) 0xfa, (byte) 0x00, (byte) 0x34, (byte) 0x35, (byte) 0x6d, (byte) 0x63, (byte) 0x05,
        (byte) 0xfb, (byte) 0xbc, (byte) 0xc3, (byte) 0xc7, (byte) 0x00, (byte) 0x14, (byte) 0x05, (byte) 0x38,
        (byte) 0x6a, (byte) 0xbb, (byte) 0xc8, (byte) 0x73, (byte) 0xcb, (byte) 0x0f, (byte) 0x3e, (byte) 0xf7,
        (byte) 0x42, (byte) 0x5f, (byte) 0x3d, (byte) 0x33, (byte) 0xdf, (byte) 0x7b, (byte) 0x31, (byte) 0x5a,
        (byte) 0xe0, (byte) 0x36, (byte) 0xd2, (byte) 0xa0, (byte) 0xb6, (byte) 0x6a, (byte) 0xfd, (byte) 0x47,
        (byte) 0x50, (byte) 0x3b, (byte) 0x16, (byte) 0x9b, (byte) 0xf3, (byte) 0x6e, (byte) 0x3b, (byte) 0x51,
        (byte) 0x62, (byte) 0x51, (byte) 0x5b, (byte) 0x71, (byte) 0x5f, (byte) 0xda, (byte) 0x83, (byte) 0xde,
        (byte) 0xaf, (byte) 0x2c, (byte) 0x58, (byte) 0xae, (byte) 0xb9, (byte) 0xab, (byte) 0xfb, (byte) 0x30,
        (byte) 0x97, (byte) 0xc3, (byte) 0xcc, (byte) 0x9d, (byte) 0xd9, (byte) 0xdb, (byte) 0xe5, (byte) 0xef,
        (byte) 0x29, (byte) 0x6c, (byte) 0x17, (byte) 0x61, (byte) 0x39, (byte) 0x02, (byte) 0x8e, (byte) 0x8a,
        (byte) 0x67, (byte) 0x1e, (byte) 0x63, (byte) 0x05, (byte) 0x6d, (byte) 0x45, (byte) 0xf4, (byte) 0x01,
        (byte) 0x88, (byte) 0xd2, (byte) 0xc4, (byte) 0x13, (byte) 0x34, (byte) 0x90, (byte) 0x84, (byte) 0x5d,
        (byte) 0xe5, (byte) 0x2c, (byte) 0x25, (byte) 0x34, (byte) 0xe9, (byte) 0xc6, (byte) 0xb2, (byte) 0x47,
        (byte) 0x8c, (byte) 0x07, (byte) 0xbd, (byte) 0xae, (byte) 0x92, (byte) 0x88, (byte) 0x23, (byte) 0xb6,
        (byte) 0x2d, (byte) 0x06, (byte) 0x6c, (byte) 0x77, (byte) 0x70, (byte) 0xf9, (byte) 0xf6, (byte) 0x3f,
        (byte) 0x3d, (byte) 0xba, (byte) 0x24, (byte) 0x7f, (byte) 0x53, (byte) 0x08, (byte) 0x44, (byte) 0x74,
        (byte) 0x7b, (byte) 0xe7, (byte) 0xaa, (byte) 0xa8, (byte) 0x5d, (byte) 0x85, (byte) 0x3b, (byte) 0x8b,
        (byte) 0xd2, (byte) 0x44, (byte) 0xac, (byte) 0xec, (byte) 0x3d, (byte) 0xe3, (byte) 0xc8, (byte) 0x9a,
        (byte) 0xb4, (byte) 0x64, (byte) 0x53, (byte) 0xab, (byte) 0x4d, (byte) 0x24, (byte) 0xc3, (byte) 0xac,
        (byte) 0x69,
    });

    private static final BigInteger RSA_2048_privateExponent = new BigInteger(new byte[] {
        (byte) 0x37, (byte) 0x78, (byte) 0x47, (byte) 0x76, (byte) 0xa5, (byte) 0xf1, (byte) 0x76, (byte) 0x98,
        (byte) 0xf5, (byte) 0xac, (byte) 0x96, (byte) 0x0d, (byte) 0xfb, (byte) 0x83, (byte) 0xa1, (byte) 0xb6,
        (byte) 0x75, (byte) 0x64, (byte) 0xe6, (byte) 0x48, (byte) 0xbd, (byte) 0x05, (byte) 0x97, (byte) 0xcf,
        (byte) 0x8a, (byte) 0xb8, (byte) 0x08, (byte) 0x71, (byte) 0x86, (byte) 0xf2, (byte) 0x66, (byte) 0x9c,
        (byte) 0x27, (byte) 0xa9, (byte) 0xec, (byte) 0xbd, (byte) 0xd4, (byte) 0x80, (byte) 0xf0, (byte) 0x19,
        (byte) 0x7a, (byte) 0x80, (byte) 0xd0, (byte) 0x73, (byte) 0x09, (byte) 0xe6, (byte) 0xc6, (byte) 0xa9,
        (byte) 0x6f, (byte) 0x92, (byte) 0x53, (byte) 0x31, (byte) 0xe5, (byte) 0x7f, (byte) 0x8b, (byte) 0x4a,
        (byte) 0xc6, (byte) 0xf4, (byte) 0xd4, (byte) 0x5e, (byte) 0xda, (byte) 0x45, (byte) 0xa2, (byte) 0x32,
        (byte) 0x69, (byte) 0xc0, (byte) 0x9f, (byte) 0xc4, (byte) 0x28, (byte) 0xc0, (byte) 0x7a, (byte) 0x4e,
        (byte) 0x6e, (byte) 0xdf, (byte) 0x73, (byte) 0x8a, (byte) 0x15, (byte) 0xde, (byte) 0xc9, (byte) 0x7f,
        (byte) 0xab, (byte) 0xd2, (byte) 0xf2, (byte) 0xbb, (byte) 0x47, (byte) 0xa1, (byte) 0x4f, (byte) 0x20,
        (byte) 0xea, (byte) 0x72, (byte) 0xfc, (byte) 0xfe, (byte) 0x4c, (byte) 0x36, (byte) 0xe0, (byte) 0x1a,
        (byte) 0xda, (byte) 0x77, (byte) 0xbd, (byte) 0x13, (byte) 0x7c, (byte) 0xd8, (byte) 0xd4, (byte) 0xda,
        (byte) 0x10, (byte) 0xbb, (byte) 0x16, (byte) 0x2e, (byte) 0x94, (byte) 0xa4, (byte) 0x66, (byte) 0x29,
        (byte) 0x71, (byte) 0xf1, (byte) 0x75, (byte) 0xf9, (byte) 0x85, (byte) 0xfa, (byte) 0x18, (byte) 0x8f,
        (byte) 0x05, (byte) 0x6c, (byte) 0xb9, (byte) 0x7e, (byte) 0xe2, (byte) 0x81, (byte) 0x6f, (byte) 0x43,
        (byte) 0xab, (byte) 0x9d, (byte) 0x37, (byte) 0x47, (byte) 0x61, (byte) 0x24, (byte) 0x86, (byte) 0xcd,
        (byte) 0xa8, (byte) 0xc1, (byte) 0x61, (byte) 0x96, (byte) 0xc3, (byte) 0x08, (byte) 0x18, (byte) 0xa9,
        (byte) 0x95, (byte) 0xec, (byte) 0x85, (byte) 0xd3, (byte) 0x84, (byte) 0x67, (byte) 0x79, (byte) 0x12,
        (byte) 0x67, (byte) 0xb3, (byte) 0xbf, (byte) 0x21, (byte) 0xf2, (byte) 0x73, (byte) 0x71, (byte) 0x0a,
        (byte) 0x69, (byte) 0x25, (byte) 0x86, (byte) 0x25, (byte) 0x76, (byte) 0x84, (byte) 0x1c, (byte) 0x5b,
        (byte) 0x67, (byte) 0x12, (byte) 0xc1, (byte) 0x2d, (byte) 0x4b, (byte) 0xd2, (byte) 0x0a, (byte) 0x2f,
        (byte) 0x32, (byte) 0x99, (byte) 0xad, (byte) 0xb7, (byte) 0xc1, (byte) 0x35, (byte) 0xda, (byte) 0x5e,
        (byte) 0x95, (byte) 0x15, (byte) 0xab, (byte) 0xda, (byte) 0x76, (byte) 0xe7, (byte) 0xca, (byte) 0xf2,
        (byte) 0xa3, (byte) 0xbe, (byte) 0x80, (byte) 0x55, (byte) 0x1d, (byte) 0x07, (byte) 0x3b, (byte) 0x78,
        (byte) 0xbf, (byte) 0x11, (byte) 0x62, (byte) 0xc4, (byte) 0x8a, (byte) 0xd2, (byte) 0xb7, (byte) 0xf4,
        (byte) 0x74, (byte) 0x3a, (byte) 0x02, (byte) 0x38, (byte) 0xee, (byte) 0x4d, (byte) 0x25, (byte) 0x2f,
        (byte) 0x7d, (byte) 0x5e, (byte) 0x7e, (byte) 0x65, (byte) 0x33, (byte) 0xcc, (byte) 0xae, (byte) 0x64,
        (byte) 0xcc, (byte) 0xb3, (byte) 0x93, (byte) 0x60, (byte) 0x07, (byte) 0x5a, (byte) 0x2f, (byte) 0xd1,
        (byte) 0xe0, (byte) 0x34, (byte) 0xec, (byte) 0x3a, (byte) 0xe5, (byte) 0xce, (byte) 0x9c, (byte) 0x40,
        (byte) 0x8c, (byte) 0xcb, (byte) 0xf0, (byte) 0xe2, (byte) 0x5e, (byte) 0x41, (byte) 0x14, (byte) 0x02,
        (byte) 0x16, (byte) 0x87, (byte) 0xb3, (byte) 0xdd, (byte) 0x47, (byte) 0x54, (byte) 0xae, (byte) 0x81,
    });

    private static final BigInteger RSA_2048_publicExponent = new BigInteger(new byte[] {
        (byte) 0x01, (byte) 0x00, (byte) 0x01,
    });

    private static final BigInteger RSA_2048_primeP = new BigInteger(new byte[] {
        (byte) 0x00, (byte) 0xf5, (byte) 0x41, (byte) 0x88, (byte) 0x4b, (byte) 0xc3, (byte) 0x73, (byte) 0x7b,
        (byte) 0x29, (byte) 0x22, (byte) 0xd4, (byte) 0x11, (byte) 0x9e, (byte) 0xf4, (byte) 0x5e, (byte) 0x2d,
        (byte) 0xee, (byte) 0x2c, (byte) 0xd4, (byte) 0xcb, (byte) 0xb7, (byte) 0x5f, (byte) 0x45, (byte) 0x50,
        (byte) 0x5a, (byte) 0x15, (byte) 0x7a, (byte) 0xa5, (byte) 0x00, (byte) 0x9f, (byte) 0x99, (byte) 0xc7,
        (byte) 0x3a, (byte) 0x2d, (byte) 0xf0, (byte) 0x72, (byte) 0x4a, (byte) 0xc4, (byte) 0x60, (byte) 0x24,
        (byte) 0x30, (byte) 0x63, (byte) 0x32, (byte) 0xea, (byte) 0x89, (byte) 0x81, (byte) 0x77, (byte) 0x63,
        (byte) 0x45, (byte) 0x46, (byte) 0x5d, (byte) 0xc6, (byte) 0xdf, (byte) 0x1e, (byte) 0x0a, (byte) 0x6f,
        (byte) 0x14, (byte) 0x0a, (byte) 0xff, (byte) 0x3b, (byte) 0x73, (byte) 0x96, (byte) 0xe6, (byte) 0xa8,
        (byte) 0x99, (byte) 0x4a, (byte) 0xc5, (byte) 0xda, (byte) 0xa9, (byte) 0x68, (byte) 0x73, (byte) 0x47,
        (byte) 0x2f, (byte) 0xe3, (byte) 0x77, (byte) 0x49, (byte) 0xd1, (byte) 0x4e, (byte) 0xb3, (byte) 0xe0,
        (byte) 0x75, (byte) 0xe6, (byte) 0x29, (byte) 0xdb, (byte) 0xeb, (byte) 0x35, (byte) 0x83, (byte) 0x33,
        (byte) 0x8a, (byte) 0x6f, (byte) 0x36, (byte) 0x49, (byte) 0xd0, (byte) 0xa2, (byte) 0x65, (byte) 0x4a,
        (byte) 0x7a, (byte) 0x42, (byte) 0xfd, (byte) 0x9a, (byte) 0xb6, (byte) 0xbf, (byte) 0xa4, (byte) 0xac,
        (byte) 0x4d, (byte) 0x48, (byte) 0x1d, (byte) 0x39, (byte) 0x0b, (byte) 0xb2, (byte) 0x29, (byte) 0xb0,
        (byte) 0x64, (byte) 0xbd, (byte) 0xc3, (byte) 0x11, (byte) 0xcc, (byte) 0x1b, (byte) 0xe1, (byte) 0xb6,
        (byte) 0x31, (byte) 0x89, (byte) 0xda, (byte) 0x7c, (byte) 0x40, (byte) 0xcd, (byte) 0xec, (byte) 0xf2,
        (byte) 0xb1,
    });

    private static final BigInteger RSA_2048_primeQ = new BigInteger(new byte[] {
        (byte) 0x00, (byte) 0xea, (byte) 0x1a, (byte) 0x74, (byte) 0x2d, (byte) 0xdb, (byte) 0x88, (byte) 0x1c,
        (byte) 0xed, (byte) 0xb7, (byte) 0x28, (byte) 0x8c, (byte) 0x87, (byte) 0xe3, (byte) 0x8d, (byte) 0x86,
        (byte) 0x8d, (byte) 0xd7, (byte) 0xa4, (byte) 0x09, (byte) 0xd1, (byte) 0x5a, (byte) 0x43, (byte) 0xf4,
        (byte) 0x45, (byte) 0xd5, (byte) 0x37, (byte) 0x7a, (byte) 0x0b, (byte) 0x57, (byte) 0x31, (byte) 0xdd,
        (byte) 0xbf, (byte) 0xca, (byte) 0x2d, (byte) 0xaf, (byte) 0x28, (byte) 0xa8, (byte) 0xe1, (byte) 0x3c,
        (byte) 0xd5, (byte) 0xc0, (byte) 0xaf, (byte) 0xce, (byte) 0xc3, (byte) 0x34, (byte) 0x7d, (byte) 0x74,
        (byte) 0xa3, (byte) 0x9e, (byte) 0x23, (byte) 0x5a, (byte) 0x3c, (byte) 0xd9, (byte) 0x63, (byte) 0x3f,
        (byte) 0x27, (byte) 0x4d, (byte) 0xe2, (byte) 0xb9, (byte) 0x4f, (byte) 0x92, (byte) 0xdf, (byte) 0x43,
        (byte) 0x83, (byte) 0x39, (byte) 0x11, (byte) 0xd9, (byte) 0xe9, (byte) 0xf1, (byte) 0xcf, (byte) 0x58,
        (byte) 0xf2, (byte) 0x7d, (byte) 0xe2, (byte) 0xe0, (byte) 0x8f, (byte) 0xf4, (byte) 0x59, (byte) 0x64,
        (byte) 0xc7, (byte) 0x20, (byte) 0xd3, (byte) 0xec, (byte) 0x21, (byte) 0x39, (byte) 0xdc, (byte) 0x7c,
        (byte) 0xaf, (byte) 0xc9, (byte) 0x12, (byte) 0x95, (byte) 0x3c, (byte) 0xde, (byte) 0xcb, (byte) 0x2f,
        (byte) 0x35, (byte) 0x5a, (byte) 0x2e, (byte) 0x2c, (byte) 0x35, (byte) 0xa5, (byte) 0x0f, (byte) 0xad,
        (byte) 0x75, (byte) 0x4c, (byte) 0xb3, (byte) 0xb2, (byte) 0x31, (byte) 0x66, (byte) 0x42, (byte) 0x4b,
        (byte) 0xa3, (byte) 0xb6, (byte) 0xe3, (byte) 0x11, (byte) 0x2a, (byte) 0x2b, (byte) 0x89, (byte) 0x8c,
        (byte) 0x38, (byte) 0xc5, (byte) 0xc1, (byte) 0x5e, (byte) 0xdb, (byte) 0x23, (byte) 0x86, (byte) 0x93,
        (byte) 0x39,
    });

    private static final BigInteger RSA_2048_primeExponentP = new BigInteger(1, new byte[] {
        (byte) 0x51, (byte) 0x82, (byte) 0x8F, (byte) 0x1E, (byte) 0xC6, (byte) 0xFD, (byte) 0x99, (byte) 0x60,
        (byte) 0x29, (byte) 0x90, (byte) 0x1B, (byte) 0xAF, (byte) 0x1D, (byte) 0x7E, (byte) 0x33, (byte) 0x7B,
        (byte) 0xA5, (byte) 0xF0, (byte) 0xAF, (byte) 0x27, (byte) 0xE9, (byte) 0x84, (byte) 0xEA, (byte) 0xD8,
        (byte) 0x95, (byte) 0xAC, (byte) 0xE6, (byte) 0x2B, (byte) 0xD7, (byte) 0xDF, (byte) 0x4E, (byte) 0xE4,
        (byte) 0x5A, (byte) 0x22, (byte) 0x40, (byte) 0x89, (byte) 0xF2, (byte) 0xCC, (byte) 0x15, (byte) 0x1A,
        (byte) 0xF3, (byte) 0xCD, (byte) 0x17, (byte) 0x3F, (byte) 0xCE, (byte) 0x04, (byte) 0x74, (byte) 0xBC,
        (byte) 0xB0, (byte) 0x4F, (byte) 0x38, (byte) 0x6A, (byte) 0x2C, (byte) 0xDC, (byte) 0xC0, (byte) 0xE0,
        (byte) 0x03, (byte) 0x6B, (byte) 0xA2, (byte) 0x41, (byte) 0x9F, (byte) 0x54, (byte) 0x57, (byte) 0x92,
        (byte) 0x62, (byte) 0xD4, (byte) 0x71, (byte) 0x00, (byte) 0xBE, (byte) 0x93, (byte) 0x19, (byte) 0x84,
        (byte) 0xA3, (byte) 0xEF, (byte) 0xA0, (byte) 0x5B, (byte) 0xEC, (byte) 0xF1, (byte) 0x41, (byte) 0x57,
        (byte) 0x4D, (byte) 0xC0, (byte) 0x79, (byte) 0xB3, (byte) 0xA9, (byte) 0x5C, (byte) 0x4A, (byte) 0x83,
        (byte) 0xE6, (byte) 0xC4, (byte) 0x3F, (byte) 0x32, (byte) 0x14, (byte) 0xD6, (byte) 0xDF, (byte) 0x32,
        (byte) 0xD5, (byte) 0x12, (byte) 0xDE, (byte) 0x19, (byte) 0x80, (byte) 0x85, (byte) 0xE5, (byte) 0x31,
        (byte) 0xE6, (byte) 0x16, (byte) 0xB8, (byte) 0x3F, (byte) 0xD7, (byte) 0xDD, (byte) 0x9D, (byte) 0x1F,
        (byte) 0x4E, (byte) 0x26, (byte) 0x07, (byte) 0xC3, (byte) 0x33, (byte) 0x3D, (byte) 0x07, (byte) 0xC5,
        (byte) 0x5D, (byte) 0x10, (byte) 0x7D, (byte) 0x1D, (byte) 0x38, (byte) 0x93, (byte) 0x58, (byte) 0x71,
    });

    private static final BigInteger RSA_2048_primeExponentQ = new BigInteger(1, new byte[] {
        (byte) 0xDB, (byte) 0x4F, (byte) 0xB5, (byte) 0x0F, (byte) 0x50, (byte) 0xDE, (byte) 0x8E, (byte) 0xDB,
        (byte) 0x53, (byte) 0xFF, (byte) 0x34, (byte) 0xC8, (byte) 0x09, (byte) 0x31, (byte) 0x88, (byte) 0xA0,
        (byte) 0x51, (byte) 0x28, (byte) 0x67, (byte) 0xDA, (byte) 0x2C, (byte) 0xCA, (byte) 0x04, (byte) 0x89,
        (byte) 0x77, (byte) 0x59, (byte) 0xE5, (byte) 0x87, (byte) 0xC2, (byte) 0x44, (byte) 0x01, (byte) 0x0D,
        (byte) 0xAF, (byte) 0x86, (byte) 0x64, (byte) 0xD5, (byte) 0x9E, (byte) 0x80, (byte) 0x83, (byte) 0xD1,
        (byte) 0x6C, (byte) 0x16, (byte) 0x47, (byte) 0x89, (byte) 0x30, (byte) 0x1F, (byte) 0x67, (byte) 0xA9,
        (byte) 0xF0, (byte) 0x78, (byte) 0x06, (byte) 0x0D, (byte) 0x83, (byte) 0x4A, (byte) 0x2A, (byte) 0xDB,
        (byte) 0xD3, (byte) 0x67, (byte) 0x57, (byte) 0x5B, (byte) 0x68, (byte) 0xA8, (byte) 0xA8, (byte) 0x42,
        (byte) 0xC2, (byte) 0xB0, (byte) 0x2A, (byte) 0x89, (byte) 0xB3, (byte) 0xF3, (byte) 0x1F, (byte) 0xCC,
        (byte) 0xEC, (byte) 0x8A, (byte) 0x22, (byte) 0xFE, (byte) 0x39, (byte) 0x57, (byte) 0x95, (byte) 0xC5,
        (byte) 0xC6, (byte) 0xC7, (byte) 0x42, (byte) 0x2B, (byte) 0x4E, (byte) 0x5D, (byte) 0x74, (byte) 0xA1,
        (byte) 0xE9, (byte) 0xA8, (byte) 0xF3, (byte) 0x0E, (byte) 0x77, (byte) 0x59, (byte) 0xB9, (byte) 0xFC,
        (byte) 0x2D, (byte) 0x63, (byte) 0x9C, (byte) 0x1F, (byte) 0x15, (byte) 0x67, (byte) 0x3E, (byte) 0x84,
        (byte) 0xE9, (byte) 0x3A, (byte) 0x5E, (byte) 0xF1, (byte) 0x50, (byte) 0x6F, (byte) 0x43, (byte) 0x15,
        (byte) 0x38, (byte) 0x3C, (byte) 0x38, (byte) 0xD4, (byte) 0x5C, (byte) 0xBD, (byte) 0x1B, (byte) 0x14,
        (byte) 0x04, (byte) 0x8F, (byte) 0x47, (byte) 0x21, (byte) 0xDC, (byte) 0x82, (byte) 0x32, (byte) 0x61,
    });

    private static final BigInteger RSA_2048_crtCoefficient = new BigInteger(1, new byte[] {
        (byte) 0xD8, (byte) 0x11, (byte) 0x45, (byte) 0x93, (byte) 0xAF, (byte) 0x41, (byte) 0x5F, (byte) 0xB6,
        (byte) 0x12, (byte) 0xDB, (byte) 0xF1, (byte) 0x92, (byte) 0x37, (byte) 0x10, (byte) 0xD5, (byte) 0x4D,
        (byte) 0x07, (byte) 0x48, (byte) 0x62, (byte) 0x05, (byte) 0xA7, (byte) 0x6A, (byte) 0x3B, (byte) 0x43,
        (byte) 0x19, (byte) 0x49, (byte) 0x68, (byte) 0xC0, (byte) 0xDF, (byte) 0xF1, (byte) 0xF1, (byte) 0x1E,
        (byte) 0xF0, (byte) 0xF6, (byte) 0x1A, (byte) 0x4A, (byte) 0x33, (byte) 0x7D, (byte) 0x5F, (byte) 0xD3,
        (byte) 0x74, (byte) 0x1B, (byte) 0xBC, (byte) 0x96, (byte) 0x40, (byte) 0xE4, (byte) 0x47, (byte) 0xB8,
        (byte) 0xB6, (byte) 0xB6, (byte) 0xC4, (byte) 0x7C, (byte) 0x3A, (byte) 0xC1, (byte) 0x20, (byte) 0x43,
        (byte) 0x57, (byte) 0xD3, (byte) 0xB0, (byte) 0xC5, (byte) 0x5B, (byte) 0xA9, (byte) 0x28, (byte) 0x6B,
        (byte) 0xDA, (byte) 0x73, (byte) 0xF6, (byte) 0x29, (byte) 0x29, (byte) 0x6F, (byte) 0x5F, (byte) 0xA9,
        (byte) 0x14, (byte) 0x6D, (byte) 0x89, (byte) 0x76, (byte) 0x35, (byte) 0x7D, (byte) 0x3C, (byte) 0x75,
        (byte) 0x1E, (byte) 0x75, (byte) 0x14, (byte) 0x86, (byte) 0x96, (byte) 0xA4, (byte) 0x0B, (byte) 0x74,
        (byte) 0x68, (byte) 0x5C, (byte) 0x82, (byte) 0xCE, (byte) 0x30, (byte) 0x90, (byte) 0x2D, (byte) 0x63,
        (byte) 0x9D, (byte) 0x72, (byte) 0x4F, (byte) 0xF2, (byte) 0x4D, (byte) 0x5E, (byte) 0x2E, (byte) 0x94,
        (byte) 0x07, (byte) 0xEE, (byte) 0x34, (byte) 0xED, (byte) 0xED, (byte) 0x2E, (byte) 0x3B, (byte) 0x4D,
        (byte) 0xF6, (byte) 0x5A, (byte) 0xA9, (byte) 0xBC, (byte) 0xFE, (byte) 0xB6, (byte) 0xDF, (byte) 0x28,
        (byte) 0xD0, (byte) 0x7B, (byte) 0xA6, (byte) 0x90, (byte) 0x3F, (byte) 0x16, (byte) 0x57, (byte) 0x68,
    });

    /**
     * Test data is PKCS#1 padded "Android.\n" which can be generated by:
     * echo "Android." | openssl rsautl -inkey rsa.key -sign | openssl rsautl -inkey rsa.key -raw -verify | recode ../x1
     */
    private static final byte[] RSA_2048_Vector1 = new byte[] {
        (byte) 0x00, (byte) 0x01, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0x00, (byte) 0x41, (byte) 0x6E, (byte) 0x64, (byte) 0x72, (byte) 0x6F,
        (byte) 0x69, (byte) 0x64, (byte) 0x2E, (byte) 0x0A,
    };

    /**
     * This vector is simply "Android.\n" which is too short.
     */
    private static final byte[] TooShort_Vector = new byte[] {
        (byte) 0x41, (byte) 0x6E, (byte) 0x64, (byte) 0x72, (byte) 0x6F, (byte) 0x69,
        (byte) 0x64, (byte) 0x2E, (byte) 0x0A,
    };

    /**
     * This vector is simply "Android.\n" padded with zeros.
     */
    private static final byte[] TooShort_Vector_Zero_Padded = new byte[] {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x41, (byte) 0x6e, (byte) 0x64, (byte) 0x72, (byte) 0x6f,
        (byte) 0x69, (byte) 0x64, (byte) 0x2e, (byte) 0x0a,
    };

    /**
     * openssl rsautl -raw -sign -inkey rsa.key | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] RSA_Vector1_Encrypt_Private = new byte[] {
        (byte) 0x35, (byte) 0x43, (byte) 0x38, (byte) 0x44, (byte) 0xAD, (byte) 0x3F,
        (byte) 0x97, (byte) 0x02, (byte) 0xFB, (byte) 0x59, (byte) 0x1F, (byte) 0x4A,
        (byte) 0x2B, (byte) 0xB9, (byte) 0x06, (byte) 0xEC, (byte) 0x66, (byte) 0xE6,
        (byte) 0xD2, (byte) 0xC5, (byte) 0x8B, (byte) 0x7B, (byte) 0xE3, (byte) 0x18,
        (byte) 0xBF, (byte) 0x07, (byte) 0xD6, (byte) 0x01, (byte) 0xF9, (byte) 0xD9,
        (byte) 0x89, (byte) 0xC4, (byte) 0xDB, (byte) 0x00, (byte) 0x68, (byte) 0xFF,
        (byte) 0x9B, (byte) 0x43, (byte) 0x90, (byte) 0xF2, (byte) 0xDB, (byte) 0x83,
        (byte) 0xF4, (byte) 0x7E, (byte) 0xC6, (byte) 0x81, (byte) 0x01, (byte) 0x3A,
        (byte) 0x0B, (byte) 0xE5, (byte) 0xED, (byte) 0x08, (byte) 0x73, (byte) 0x3E,
        (byte) 0xE1, (byte) 0x3F, (byte) 0xDF, (byte) 0x1F, (byte) 0x07, (byte) 0x6D,
        (byte) 0x22, (byte) 0x8D, (byte) 0xCC, (byte) 0x4E, (byte) 0xE3, (byte) 0x9A,
        (byte) 0xBC, (byte) 0xCC, (byte) 0x8F, (byte) 0x9E, (byte) 0x9B, (byte) 0x02,
        (byte) 0x48, (byte) 0x00, (byte) 0xAC, (byte) 0x9F, (byte) 0xA4, (byte) 0x8F,
        (byte) 0x87, (byte) 0xA1, (byte) 0xA8, (byte) 0xE6, (byte) 0x9D, (byte) 0xCD,
        (byte) 0x8B, (byte) 0x05, (byte) 0xE9, (byte) 0xD2, (byte) 0x05, (byte) 0x8D,
        (byte) 0xC9, (byte) 0x95, (byte) 0x16, (byte) 0xD0, (byte) 0xCD, (byte) 0x43,
        (byte) 0x25, (byte) 0x8A, (byte) 0x11, (byte) 0x46, (byte) 0xD7, (byte) 0x74,
        (byte) 0x4C, (byte) 0xCF, (byte) 0x58, (byte) 0xF9, (byte) 0xA1, (byte) 0x30,
        (byte) 0x84, (byte) 0x52, (byte) 0xC9, (byte) 0x01, (byte) 0x5F, (byte) 0x24,
        (byte) 0x4C, (byte) 0xB1, (byte) 0x9F, (byte) 0x7D, (byte) 0x12, (byte) 0x38,
        (byte) 0x27, (byte) 0x0F, (byte) 0x5E, (byte) 0xFF, (byte) 0xE0, (byte) 0x55,
        (byte) 0x8B, (byte) 0xA3, (byte) 0xAD, (byte) 0x60, (byte) 0x35, (byte) 0x83,
        (byte) 0x58, (byte) 0xAF, (byte) 0x99, (byte) 0xDE, (byte) 0x3F, (byte) 0x5D,
        (byte) 0x80, (byte) 0x80, (byte) 0xFF, (byte) 0x9B, (byte) 0xDE, (byte) 0x5C,
        (byte) 0xAB, (byte) 0x97, (byte) 0x43, (byte) 0x64, (byte) 0xD9, (byte) 0x9F,
        (byte) 0xFB, (byte) 0x67, (byte) 0x65, (byte) 0xA5, (byte) 0x99, (byte) 0xE7,
        (byte) 0xE6, (byte) 0xEB, (byte) 0x05, (byte) 0x95, (byte) 0xFC, (byte) 0x46,
        (byte) 0x28, (byte) 0x4B, (byte) 0xD8, (byte) 0x8C, (byte) 0xF5, (byte) 0x0A,
        (byte) 0xEB, (byte) 0x1F, (byte) 0x30, (byte) 0xEA, (byte) 0xE7, (byte) 0x67,
        (byte) 0x11, (byte) 0x25, (byte) 0xF0, (byte) 0x44, (byte) 0x75, (byte) 0x74,
        (byte) 0x94, (byte) 0x06, (byte) 0x78, (byte) 0xD0, (byte) 0x21, (byte) 0xF4,
        (byte) 0x3F, (byte) 0xC8, (byte) 0xC4, (byte) 0x4A, (byte) 0x57, (byte) 0xBE,
        (byte) 0x02, (byte) 0x3C, (byte) 0x93, (byte) 0xF6, (byte) 0x95, (byte) 0xFB,
        (byte) 0xD1, (byte) 0x77, (byte) 0x8B, (byte) 0x43, (byte) 0xF0, (byte) 0xB9,
        (byte) 0x7D, (byte) 0xE0, (byte) 0x32, (byte) 0xE1, (byte) 0x72, (byte) 0xB5,
        (byte) 0x62, (byte) 0x3F, (byte) 0x86, (byte) 0xC3, (byte) 0xD4, (byte) 0x5F,
        (byte) 0x5E, (byte) 0x54, (byte) 0x1B, (byte) 0x5B, (byte) 0xE6, (byte) 0x74,
        (byte) 0xA1, (byte) 0x0B, (byte) 0xE5, (byte) 0x18, (byte) 0xD2, (byte) 0x4F,
        (byte) 0x93, (byte) 0xF3, (byte) 0x09, (byte) 0x58, (byte) 0xCE, (byte) 0xF0,
        (byte) 0xA3, (byte) 0x61, (byte) 0xE4, (byte) 0x6E, (byte) 0x46, (byte) 0x45,
        (byte) 0x89, (byte) 0x50, (byte) 0xBD, (byte) 0x03, (byte) 0x3F, (byte) 0x38,
        (byte) 0xDA, (byte) 0x5D, (byte) 0xD0, (byte) 0x1B, (byte) 0x1F, (byte) 0xB1,
        (byte) 0xEE, (byte) 0x89, (byte) 0x59, (byte) 0xC5,
    };

    private static final byte[] RSA_Vector1_ZeroPadded_Encrypted = new byte[] {
        (byte) 0x60, (byte) 0x4a, (byte) 0x12, (byte) 0xa3, (byte) 0xa7, (byte) 0x4a,
        (byte) 0xa4, (byte) 0xbf, (byte) 0x6c, (byte) 0x36, (byte) 0xad, (byte) 0x66,
        (byte) 0xdf, (byte) 0xce, (byte) 0xf1, (byte) 0xe4, (byte) 0x0f, (byte) 0xd4,
        (byte) 0x54, (byte) 0x5f, (byte) 0x03, (byte) 0x15, (byte) 0x4b, (byte) 0x9e,
        (byte) 0xeb, (byte) 0xfe, (byte) 0x9e, (byte) 0x24, (byte) 0xce, (byte) 0x8e,
        (byte) 0xc3, (byte) 0x36, (byte) 0xa5, (byte) 0x76, (byte) 0xf6, (byte) 0x54,
        (byte) 0xb7, (byte) 0x84, (byte) 0x48, (byte) 0x2f, (byte) 0xd4, (byte) 0x45,
        (byte) 0x74, (byte) 0x48, (byte) 0x5f, (byte) 0x08, (byte) 0x4e, (byte) 0x9c,
        (byte) 0x89, (byte) 0xcc, (byte) 0x34, (byte) 0x40, (byte) 0xb1, (byte) 0x5f,
        (byte) 0xa7, (byte) 0x0e, (byte) 0x11, (byte) 0x4b, (byte) 0xb5, (byte) 0x94,
        (byte) 0xbe, (byte) 0x14, (byte) 0xaa, (byte) 0xaa, (byte) 0xe0, (byte) 0x38,
        (byte) 0x1c, (byte) 0xce, (byte) 0x40, (byte) 0x61, (byte) 0xfc, (byte) 0x08,
        (byte) 0xcb, (byte) 0x14, (byte) 0x2b, (byte) 0xa6, (byte) 0x54, (byte) 0xdf,
        (byte) 0x05, (byte) 0x5c, (byte) 0x9b, (byte) 0x4f, (byte) 0x14, (byte) 0x93,
        (byte) 0xb0, (byte) 0x70, (byte) 0xd9, (byte) 0x32, (byte) 0xdc, (byte) 0x24,
        (byte) 0xe0, (byte) 0xae, (byte) 0x48, (byte) 0xfc, (byte) 0x53, (byte) 0xee,
        (byte) 0x7c, (byte) 0x9f, (byte) 0x69, (byte) 0x34, (byte) 0xf4, (byte) 0x76,
        (byte) 0xee, (byte) 0x67, (byte) 0xb2, (byte) 0xa7, (byte) 0x33, (byte) 0x1c,
        (byte) 0x47, (byte) 0xff, (byte) 0x5c, (byte) 0xf0, (byte) 0xb8, (byte) 0x04,
        (byte) 0x2c, (byte) 0xfd, (byte) 0xe2, (byte) 0xb1, (byte) 0x4a, (byte) 0x0a,
        (byte) 0x69, (byte) 0x1c, (byte) 0x80, (byte) 0x2b, (byte) 0xb4, (byte) 0x50,
        (byte) 0x65, (byte) 0x5c, (byte) 0x76, (byte) 0x78, (byte) 0x9a, (byte) 0x0c,
        (byte) 0x05, (byte) 0x62, (byte) 0xf0, (byte) 0xc4, (byte) 0x1c, (byte) 0x38,
        (byte) 0x15, (byte) 0xd0, (byte) 0xe2, (byte) 0x5a, (byte) 0x3d, (byte) 0xb6,
        (byte) 0xe0, (byte) 0x88, (byte) 0x85, (byte) 0xd1, (byte) 0x4f, (byte) 0x7e,
        (byte) 0xfc, (byte) 0x77, (byte) 0x0d, (byte) 0x2a, (byte) 0x45, (byte) 0xd5,
        (byte) 0xf8, (byte) 0x3c, (byte) 0x7b, (byte) 0x2d, (byte) 0x1b, (byte) 0x82,
        (byte) 0xfe, (byte) 0x58, (byte) 0x22, (byte) 0x47, (byte) 0x06, (byte) 0x58,
        (byte) 0x8b, (byte) 0x4f, (byte) 0xfb, (byte) 0x9b, (byte) 0x1c, (byte) 0x70,
        (byte) 0x36, (byte) 0x12, (byte) 0x04, (byte) 0x17, (byte) 0x47, (byte) 0x8a,
        (byte) 0x0a, (byte) 0xec, (byte) 0x12, (byte) 0x3b, (byte) 0xf8, (byte) 0xd2,
        (byte) 0xdc, (byte) 0x3c, (byte) 0xc8, (byte) 0x46, (byte) 0xc6, (byte) 0x51,
        (byte) 0x06, (byte) 0x06, (byte) 0xcb, (byte) 0x84, (byte) 0x67, (byte) 0xb5,
        (byte) 0x68, (byte) 0xd9, (byte) 0x9c, (byte) 0xd4, (byte) 0x16, (byte) 0x5c,
        (byte) 0xb4, (byte) 0xe2, (byte) 0x55, (byte) 0xe6, (byte) 0x3a, (byte) 0x73,
        (byte) 0x01, (byte) 0x1d, (byte) 0x6f, (byte) 0x30, (byte) 0x31, (byte) 0x59,
        (byte) 0x8b, (byte) 0x2f, (byte) 0x4c, (byte) 0xe7, (byte) 0x86, (byte) 0x4c,
        (byte) 0x39, (byte) 0x4e, (byte) 0x67, (byte) 0x3b, (byte) 0x22, (byte) 0x9b,
        (byte) 0x85, (byte) 0x5a, (byte) 0xc3, (byte) 0x29, (byte) 0xaf, (byte) 0x8c,
        (byte) 0x7c, (byte) 0x59, (byte) 0x4a, (byte) 0x24, (byte) 0xfa, (byte) 0xba,
        (byte) 0x55, (byte) 0x40, (byte) 0x13, (byte) 0x64, (byte) 0xd8, (byte) 0xcb,
        (byte) 0x4b, (byte) 0x98, (byte) 0x3f, (byte) 0xae, (byte) 0x20, (byte) 0xfd,
        (byte) 0x8a, (byte) 0x50, (byte) 0x73, (byte) 0xe4,
    };
    /*
     * echo -n 'This is a test of OAEP' | xxd -p -i | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] RSA_Vector2_Plaintext = new byte[] {
            (byte) 0x54, (byte) 0x68, (byte) 0x69, (byte) 0x73, (byte) 0x20, (byte) 0x69,
            (byte) 0x73, (byte) 0x20, (byte) 0x61, (byte) 0x20, (byte) 0x74, (byte) 0x65,
            (byte) 0x73, (byte) 0x74, (byte) 0x20, (byte) 0x6f, (byte) 0x66, (byte) 0x20,
            (byte) 0x4f, (byte) 0x41, (byte) 0x45, (byte) 0x50
    };

    /*
     * echo -n 'This is a test of OAEP' | openssl pkeyutl -encrypt -inkey rsakey.pem \
     * -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 \
     * | xxd -p -i | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] RSA_Vector2_OAEP_SHA1_MGF1_SHA1 = new byte[] {
            (byte) 0x53, (byte) 0x71, (byte) 0x84, (byte) 0x2e, (byte) 0x01, (byte) 0x74,
            (byte) 0x82, (byte) 0xb3, (byte) 0x01, (byte) 0xac, (byte) 0x2b, (byte) 0xbd,
            (byte) 0x40, (byte) 0xa7, (byte) 0x5b, (byte) 0x60, (byte) 0xf1, (byte) 0xde,
            (byte) 0x54, (byte) 0x1d, (byte) 0x94, (byte) 0xc1, (byte) 0x10, (byte) 0x31,
            (byte) 0x6f, (byte) 0xa3, (byte) 0xd8, (byte) 0x41, (byte) 0x2e, (byte) 0x82,
            (byte) 0xad, (byte) 0x07, (byte) 0x6f, (byte) 0x25, (byte) 0x6c, (byte) 0xb5,
            (byte) 0xef, (byte) 0xc6, (byte) 0xa6, (byte) 0xfb, (byte) 0xb1, (byte) 0x9d,
            (byte) 0x75, (byte) 0x67, (byte) 0xb0, (byte) 0x97, (byte) 0x21, (byte) 0x3c,
            (byte) 0x17, (byte) 0x04, (byte) 0xdc, (byte) 0x4e, (byte) 0x7e, (byte) 0x3f,
            (byte) 0x5c, (byte) 0x13, (byte) 0x5e, (byte) 0x15, (byte) 0x0f, (byte) 0xe2,
            (byte) 0xa7, (byte) 0x62, (byte) 0x6a, (byte) 0x08, (byte) 0xb1, (byte) 0xbc,
            (byte) 0x2f, (byte) 0xcb, (byte) 0xb5, (byte) 0x96, (byte) 0x2d, (byte) 0xec,
            (byte) 0x71, (byte) 0x4d, (byte) 0x59, (byte) 0x6e, (byte) 0x27, (byte) 0x85,
            (byte) 0x87, (byte) 0x9b, (byte) 0xcc, (byte) 0x40, (byte) 0x32, (byte) 0x09,
            (byte) 0x06, (byte) 0xe6, (byte) 0x7d, (byte) 0xdf, (byte) 0xeb, (byte) 0x2f,
            (byte) 0xa8, (byte) 0x1c, (byte) 0x53, (byte) 0xdb, (byte) 0xa7, (byte) 0x48,
            (byte) 0xf5, (byte) 0xbf, (byte) 0x2f, (byte) 0xbb, (byte) 0xee, (byte) 0xc7,
            (byte) 0x55, (byte) 0x5e, (byte) 0xc4, (byte) 0x1c, (byte) 0x84, (byte) 0xed,
            (byte) 0x97, (byte) 0x7e, (byte) 0xce, (byte) 0xa5, (byte) 0x69, (byte) 0x73,
            (byte) 0xb3, (byte) 0xe0, (byte) 0x8c, (byte) 0x2a, (byte) 0xf2, (byte) 0xc7,
            (byte) 0x65, (byte) 0xff, (byte) 0x10, (byte) 0xed, (byte) 0x25, (byte) 0xf0,
            (byte) 0xf8, (byte) 0xda, (byte) 0x2f, (byte) 0x7f, (byte) 0xe0, (byte) 0x69,
            (byte) 0xed, (byte) 0xb1, (byte) 0x0e, (byte) 0xcb, (byte) 0x43, (byte) 0xe4,
            (byte) 0x31, (byte) 0xe6, (byte) 0x52, (byte) 0xfd, (byte) 0xa7, (byte) 0xe5,
            (byte) 0x21, (byte) 0xd0, (byte) 0x67, (byte) 0x0a, (byte) 0xc1, (byte) 0xa1,
            (byte) 0xb9, (byte) 0x04, (byte) 0xdb, (byte) 0x98, (byte) 0x4f, (byte) 0xf9,
            (byte) 0x5c, (byte) 0x60, (byte) 0x4d, (byte) 0xac, (byte) 0x7a, (byte) 0x69,
            (byte) 0xbd, (byte) 0x63, (byte) 0x0d, (byte) 0xb2, (byte) 0x01, (byte) 0x83,
            (byte) 0xd7, (byte) 0x22, (byte) 0x5d, (byte) 0xed, (byte) 0xbd, (byte) 0x32,
            (byte) 0x98, (byte) 0xd1, (byte) 0x4a, (byte) 0x2e, (byte) 0xb7, (byte) 0xb1,
            (byte) 0x6d, (byte) 0x8a, (byte) 0x8f, (byte) 0xef, (byte) 0xc3, (byte) 0x89,
            (byte) 0xdf, (byte) 0xa5, (byte) 0xac, (byte) 0xfb, (byte) 0x38, (byte) 0x61,
            (byte) 0x32, (byte) 0xc5, (byte) 0x19, (byte) 0x83, (byte) 0x1f, (byte) 0x9c,
            (byte) 0x45, (byte) 0x58, (byte) 0xdd, (byte) 0xa3, (byte) 0x57, (byte) 0xe4,
            (byte) 0x91, (byte) 0xd2, (byte) 0x11, (byte) 0xf8, (byte) 0x96, (byte) 0x36,
            (byte) 0x67, (byte) 0x99, (byte) 0x2b, (byte) 0x62, (byte) 0x21, (byte) 0xe3,
            (byte) 0xa8, (byte) 0x5e, (byte) 0xa4, (byte) 0x2e, (byte) 0x0c, (byte) 0x29,
            (byte) 0xf9, (byte) 0xcd, (byte) 0xfa, (byte) 0xbe, (byte) 0x3f, (byte) 0xd8,
            (byte) 0xec, (byte) 0x6b, (byte) 0x32, (byte) 0xb3, (byte) 0x40, (byte) 0x4f,
            (byte) 0x48, (byte) 0xe3, (byte) 0x14, (byte) 0x87, (byte) 0xa7, (byte) 0x5c,
            (byte) 0xba, (byte) 0xdf, (byte) 0x0e, (byte) 0x64, (byte) 0xdc, (byte) 0xe2,
            (byte) 0x51, (byte) 0xf4, (byte) 0x41, (byte) 0x25, (byte) 0x23, (byte) 0xc8,
            (byte) 0x50, (byte) 0x1e, (byte) 0x9e, (byte) 0xb0
    };

    /*
     * echo -n 'This is a test of OAEP' | openssl pkeyutl -encrypt -inkey rsakey.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha1 | xxd -p -i | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] RSA_Vector2_OAEP_SHA256_MGF1_SHA1 = new byte[] {
            (byte) 0x25, (byte) 0x9f, (byte) 0xc3, (byte) 0x69, (byte) 0xbc, (byte) 0x3f,
            (byte) 0xe7, (byte) 0x9e, (byte) 0x76, (byte) 0xef, (byte) 0x6c, (byte) 0xd2,
            (byte) 0x2b, (byte) 0x7b, (byte) 0xf0, (byte) 0xeb, (byte) 0xc2, (byte) 0x28,
            (byte) 0x40, (byte) 0x4e, (byte) 0x9b, (byte) 0x2a, (byte) 0x4e, (byte) 0xa4,
            (byte) 0x79, (byte) 0x66, (byte) 0xf1, (byte) 0x10, (byte) 0x96, (byte) 0x8c,
            (byte) 0x58, (byte) 0x92, (byte) 0xb7, (byte) 0x70, (byte) 0xed, (byte) 0x3a,
            (byte) 0xe0, (byte) 0x99, (byte) 0xd1, (byte) 0x80, (byte) 0x4b, (byte) 0x53,
            (byte) 0x70, (byte) 0x9b, (byte) 0x51, (byte) 0xbf, (byte) 0xc1, (byte) 0x3a,
            (byte) 0x70, (byte) 0xc5, (byte) 0x79, (byte) 0x21, (byte) 0x6e, (byte) 0xb3,
            (byte) 0xf7, (byte) 0xa9, (byte) 0xe6, (byte) 0xcb, (byte) 0x70, (byte) 0xe4,
            (byte) 0xf3, (byte) 0x4f, (byte) 0x45, (byte) 0xcf, (byte) 0xb7, (byte) 0x2b,
            (byte) 0x38, (byte) 0xfd, (byte) 0x5d, (byte) 0x9a, (byte) 0x53, (byte) 0xc5,
            (byte) 0x05, (byte) 0x74, (byte) 0x8d, (byte) 0x1d, (byte) 0x6e, (byte) 0x83,
            (byte) 0xaa, (byte) 0x71, (byte) 0xc5, (byte) 0xe1, (byte) 0xa1, (byte) 0xa6,
            (byte) 0xf3, (byte) 0xee, (byte) 0x5f, (byte) 0x9e, (byte) 0x4f, (byte) 0xe8,
            (byte) 0x15, (byte) 0xd5, (byte) 0xa9, (byte) 0x1b, (byte) 0xa6, (byte) 0x41,
            (byte) 0x2b, (byte) 0x18, (byte) 0x13, (byte) 0x20, (byte) 0x9f, (byte) 0x6b,
            (byte) 0xf1, (byte) 0xd8, (byte) 0xf4, (byte) 0x87, (byte) 0xfa, (byte) 0x80,
            (byte) 0xec, (byte) 0x0e, (byte) 0xa4, (byte) 0x4b, (byte) 0x24, (byte) 0x03,
            (byte) 0x14, (byte) 0x25, (byte) 0xf2, (byte) 0x20, (byte) 0xfc, (byte) 0x52,
            (byte) 0xf9, (byte) 0xd6, (byte) 0x7a, (byte) 0x4a, (byte) 0x45, (byte) 0x33,
            (byte) 0xec, (byte) 0xde, (byte) 0x3c, (byte) 0x5b, (byte) 0xf2, (byte) 0xdc,
            (byte) 0x8e, (byte) 0xc6, (byte) 0xb3, (byte) 0x26, (byte) 0xd3, (byte) 0x68,
            (byte) 0xa7, (byte) 0xd8, (byte) 0x3a, (byte) 0xde, (byte) 0xa9, (byte) 0x25,
            (byte) 0x1d, (byte) 0x42, (byte) 0x75, (byte) 0x66, (byte) 0x16, (byte) 0x29,
            (byte) 0xad, (byte) 0x09, (byte) 0x74, (byte) 0x41, (byte) 0xbb, (byte) 0x45,
            (byte) 0x39, (byte) 0x04, (byte) 0x7a, (byte) 0x93, (byte) 0xad, (byte) 0x1c,
            (byte) 0xa6, (byte) 0x38, (byte) 0xf4, (byte) 0xac, (byte) 0xca, (byte) 0x5a,
            (byte) 0xab, (byte) 0x92, (byte) 0x76, (byte) 0x26, (byte) 0x3c, (byte) 0xeb,
            (byte) 0xda, (byte) 0xfc, (byte) 0x25, (byte) 0x93, (byte) 0x23, (byte) 0x01,
            (byte) 0xe2, (byte) 0xac, (byte) 0x5e, (byte) 0x4c, (byte) 0xb7, (byte) 0xbc,
            (byte) 0x5b, (byte) 0xaa, (byte) 0x14, (byte) 0xe9, (byte) 0xbf, (byte) 0x2d,
            (byte) 0x3a, (byte) 0xdc, (byte) 0x2f, (byte) 0x6b, (byte) 0x4d, (byte) 0x0e,
            (byte) 0x0a, (byte) 0x82, (byte) 0x3c, (byte) 0xd9, (byte) 0x32, (byte) 0xc1,
            (byte) 0xc4, (byte) 0xa2, (byte) 0x46, (byte) 0x71, (byte) 0x10, (byte) 0x54,
            (byte) 0x1a, (byte) 0xa6, (byte) 0xaa, (byte) 0x64, (byte) 0xe7, (byte) 0xc2,
            (byte) 0xae, (byte) 0xbc, (byte) 0x3d, (byte) 0xa4, (byte) 0xa8, (byte) 0xd1,
            (byte) 0xb7, (byte) 0x27, (byte) 0xef, (byte) 0x5f, (byte) 0xe7, (byte) 0xa7,
            (byte) 0x5d, (byte) 0xa0, (byte) 0xcd, (byte) 0x57, (byte) 0xf1, (byte) 0xe0,
            (byte) 0xd8, (byte) 0x42, (byte) 0x10, (byte) 0x77, (byte) 0xc3, (byte) 0xa7,
            (byte) 0x1e, (byte) 0x0c, (byte) 0x37, (byte) 0x16, (byte) 0x11, (byte) 0x94,
            (byte) 0x21, (byte) 0xf2, (byte) 0xca, (byte) 0x60, (byte) 0xce, (byte) 0xca,
            (byte) 0x59, (byte) 0xf9, (byte) 0xe5, (byte) 0xe4
    };

    /*
     * echo -n 'This is a test of OAEP' | openssl pkeyutl -encrypt -inkey /tmp/rsakey.txt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha1 -pkeyopt rsa_oaep_label:010203FFA00A | xxd -p -i | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] RSA_Vector2_OAEP_SHA256_MGF1_SHA1_LABEL = new byte[] {
            (byte) 0x80, (byte) 0xb1, (byte) 0xf2, (byte) 0xc2, (byte) 0x03, (byte) 0xc5,
            (byte) 0xdf, (byte) 0xbd, (byte) 0xed, (byte) 0xfe, (byte) 0xe6, (byte) 0xff,
            (byte) 0xd3, (byte) 0x38, (byte) 0x1e, (byte) 0x6d, (byte) 0xae, (byte) 0x47,
            (byte) 0xfe, (byte) 0x19, (byte) 0xf9, (byte) 0x8c, (byte) 0xf1, (byte) 0x4d,
            (byte) 0x18, (byte) 0x2b, (byte) 0x7e, (byte) 0x8e, (byte) 0x47, (byte) 0x39,
            (byte) 0xa8, (byte) 0x04, (byte) 0xc4, (byte) 0x7d, (byte) 0x56, (byte) 0x03,
            (byte) 0x15, (byte) 0x92, (byte) 0x18, (byte) 0xde, (byte) 0x56, (byte) 0xb3,
            (byte) 0x01, (byte) 0x93, (byte) 0x16, (byte) 0xe3, (byte) 0xfa, (byte) 0xaa,
            (byte) 0xf3, (byte) 0x73, (byte) 0x39, (byte) 0x26, (byte) 0xfb, (byte) 0xb0,
            (byte) 0x18, (byte) 0x20, (byte) 0xdb, (byte) 0xa1, (byte) 0xbf, (byte) 0x31,
            (byte) 0x22, (byte) 0xc8, (byte) 0x1d, (byte) 0xdb, (byte) 0xa0, (byte) 0x5a,
            (byte) 0x22, (byte) 0xcd, (byte) 0x09, (byte) 0xb3, (byte) 0xcb, (byte) 0xa2,
            (byte) 0x46, (byte) 0x14, (byte) 0x35, (byte) 0x66, (byte) 0xe8, (byte) 0xb8,
            (byte) 0x07, (byte) 0x23, (byte) 0xc5, (byte) 0xae, (byte) 0xe6, (byte) 0xf1,
            (byte) 0x7a, (byte) 0x8f, (byte) 0x5c, (byte) 0x44, (byte) 0x34, (byte) 0xbf,
            (byte) 0xd6, (byte) 0xf8, (byte) 0x0c, (byte) 0xc7, (byte) 0x8d, (byte) 0xcd,
            (byte) 0x23, (byte) 0x84, (byte) 0xbe, (byte) 0x9b, (byte) 0xbf, (byte) 0x9a,
            (byte) 0x70, (byte) 0x0f, (byte) 0x18, (byte) 0xc0, (byte) 0x6f, (byte) 0x23,
            (byte) 0x67, (byte) 0xf8, (byte) 0xbb, (byte) 0xce, (byte) 0xc2, (byte) 0x47,
            (byte) 0x82, (byte) 0xa0, (byte) 0xa5, (byte) 0x60, (byte) 0xcd, (byte) 0x25,
            (byte) 0xa5, (byte) 0x4b, (byte) 0xe4, (byte) 0x06, (byte) 0x7f, (byte) 0x46,
            (byte) 0x62, (byte) 0x86, (byte) 0x94, (byte) 0xbc, (byte) 0x7f, (byte) 0xb0,
            (byte) 0x2e, (byte) 0xc1, (byte) 0x8c, (byte) 0x6c, (byte) 0x58, (byte) 0x05,
            (byte) 0x6f, (byte) 0x35, (byte) 0x76, (byte) 0xd3, (byte) 0xdf, (byte) 0xc0,
            (byte) 0xdd, (byte) 0x66, (byte) 0xbe, (byte) 0xa1, (byte) 0x7e, (byte) 0x52,
            (byte) 0xed, (byte) 0x81, (byte) 0x0e, (byte) 0x2d, (byte) 0x5b, (byte) 0x2b,
            (byte) 0xe3, (byte) 0x52, (byte) 0x0e, (byte) 0x56, (byte) 0x9b, (byte) 0x05,
            (byte) 0x72, (byte) 0xa8, (byte) 0xc8, (byte) 0x57, (byte) 0x22, (byte) 0x67,
            (byte) 0x0e, (byte) 0x5f, (byte) 0x01, (byte) 0xf2, (byte) 0x69, (byte) 0x66,
            (byte) 0x6a, (byte) 0x47, (byte) 0x4f, (byte) 0x78, (byte) 0xb3, (byte) 0x1e,
            (byte) 0x7d, (byte) 0xce, (byte) 0xb3, (byte) 0x35, (byte) 0xdf, (byte) 0x23,
            (byte) 0xac, (byte) 0xf8, (byte) 0x88, (byte) 0xa1, (byte) 0xde, (byte) 0x38,
            (byte) 0x96, (byte) 0xfd, (byte) 0xa2, (byte) 0x5d, (byte) 0x09, (byte) 0x52,
            (byte) 0x11, (byte) 0x2b, (byte) 0x21, (byte) 0xf0, (byte) 0x0d, (byte) 0x4c,
            (byte) 0x15, (byte) 0xc3, (byte) 0x88, (byte) 0x2b, (byte) 0xf6, (byte) 0x2b,
            (byte) 0xe3, (byte) 0xfd, (byte) 0x52, (byte) 0xf0, (byte) 0x09, (byte) 0x5c,
            (byte) 0x4f, (byte) 0x5b, (byte) 0x8b, (byte) 0x84, (byte) 0x71, (byte) 0x72,
            (byte) 0x8d, (byte) 0xaa, (byte) 0x6c, (byte) 0x55, (byte) 0xba, (byte) 0xe7,
            (byte) 0x9c, (byte) 0xba, (byte) 0xbf, (byte) 0xf4, (byte) 0x09, (byte) 0x0a,
            (byte) 0x60, (byte) 0xec, (byte) 0x53, (byte) 0xa4, (byte) 0x01, (byte) 0xa5,
            (byte) 0xf2, (byte) 0x58, (byte) 0xab, (byte) 0x95, (byte) 0x68, (byte) 0x79,
            (byte) 0x0b, (byte) 0xc3, (byte) 0xc4, (byte) 0x00, (byte) 0x68, (byte) 0x19,
            (byte) 0xca, (byte) 0x07, (byte) 0x0d, (byte) 0x32
    };

    /*
     * echo -n 'This is a test of OAEP' | openssl pkeyutl -encrypt -inkey rsakey.pem \
     * -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha224 -pkeyopt rsa_mgf1_md:sha224 \
     * | xxd -p -i | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] RSA_Vector2_OAEP_SHA224_MGF1_SHA224 = new byte[] {
            (byte) 0xae, (byte) 0xdd, (byte) 0xe6, (byte) 0xab, (byte) 0x00, (byte) 0xd6,
            (byte) 0x1e, (byte) 0x7e, (byte) 0x85, (byte) 0x63, (byte) 0xab, (byte) 0x51,
            (byte) 0x79, (byte) 0x92, (byte) 0xf1, (byte) 0xb9, (byte) 0x4f, (byte) 0x23,
            (byte) 0xae, (byte) 0xf7, (byte) 0x1b, (byte) 0x5f, (byte) 0x10, (byte) 0x5b,
            (byte) 0xa5, (byte) 0x15, (byte) 0x87, (byte) 0xa3, (byte) 0xbb, (byte) 0x26,
            (byte) 0xfe, (byte) 0x7f, (byte) 0xc0, (byte) 0xa3, (byte) 0x67, (byte) 0x95,
            (byte) 0xda, (byte) 0xc4, (byte) 0x6f, (byte) 0x6e, (byte) 0x08, (byte) 0x23,
            (byte) 0x28, (byte) 0x0b, (byte) 0xdd, (byte) 0x29, (byte) 0x29, (byte) 0xdc,
            (byte) 0xb0, (byte) 0x35, (byte) 0x16, (byte) 0x2e, (byte) 0x0f, (byte) 0xb9,
            (byte) 0x1d, (byte) 0x90, (byte) 0x27, (byte) 0x68, (byte) 0xc7, (byte) 0x92,
            (byte) 0x52, (byte) 0x8a, (byte) 0x1d, (byte) 0x48, (byte) 0x6a, (byte) 0x7d,
            (byte) 0x0b, (byte) 0xf6, (byte) 0x35, (byte) 0xca, (byte) 0xe1, (byte) 0x57,
            (byte) 0xdd, (byte) 0x36, (byte) 0x3b, (byte) 0x51, (byte) 0x45, (byte) 0x77,
            (byte) 0x28, (byte) 0x4f, (byte) 0x98, (byte) 0xc0, (byte) 0xe0, (byte) 0xa7,
            (byte) 0x51, (byte) 0x98, (byte) 0x84, (byte) 0x7a, (byte) 0x29, (byte) 0x05,
            (byte) 0x9f, (byte) 0x60, (byte) 0x66, (byte) 0xf6, (byte) 0x83, (byte) 0xcd,
            (byte) 0x03, (byte) 0x3e, (byte) 0x82, (byte) 0x0f, (byte) 0x57, (byte) 0x4b,
            (byte) 0x27, (byte) 0x14, (byte) 0xf6, (byte) 0xc8, (byte) 0x5b, (byte) 0xed,
            (byte) 0xc3, (byte) 0x77, (byte) 0x6f, (byte) 0xec, (byte) 0x0e, (byte) 0xae,
            (byte) 0x59, (byte) 0xbe, (byte) 0x68, (byte) 0x76, (byte) 0x16, (byte) 0x17,
            (byte) 0x77, (byte) 0xe2, (byte) 0xbd, (byte) 0xe0, (byte) 0x5a, (byte) 0x14,
            (byte) 0xd9, (byte) 0xf4, (byte) 0x3f, (byte) 0x50, (byte) 0x31, (byte) 0xf0,
            (byte) 0x0c, (byte) 0x82, (byte) 0x6c, (byte) 0xcc, (byte) 0x81, (byte) 0x84,
            (byte) 0x3e, (byte) 0x63, (byte) 0x93, (byte) 0xe7, (byte) 0x12, (byte) 0x2d,
            (byte) 0xc9, (byte) 0xa3, (byte) 0xe3, (byte) 0xce, (byte) 0xfd, (byte) 0xc7,
            (byte) 0xe1, (byte) 0xef, (byte) 0xa4, (byte) 0x16, (byte) 0x5c, (byte) 0x60,
            (byte) 0xb1, (byte) 0x80, (byte) 0x31, (byte) 0x15, (byte) 0x5c, (byte) 0x35,
            (byte) 0x25, (byte) 0x0b, (byte) 0x89, (byte) 0xe4, (byte) 0x56, (byte) 0x74,
            (byte) 0x8b, (byte) 0xaf, (byte) 0x8e, (byte) 0xe9, (byte) 0xe2, (byte) 0x37,
            (byte) 0x17, (byte) 0xe6, (byte) 0x7b, (byte) 0x78, (byte) 0xd8, (byte) 0x2c,
            (byte) 0x27, (byte) 0x52, (byte) 0x21, (byte) 0x96, (byte) 0xa0, (byte) 0x92,
            (byte) 0x95, (byte) 0x64, (byte) 0xc3, (byte) 0x7f, (byte) 0x45, (byte) 0xfc,
            (byte) 0x3d, (byte) 0x48, (byte) 0x4a, (byte) 0xd5, (byte) 0xa4, (byte) 0x0a,
            (byte) 0x57, (byte) 0x07, (byte) 0x57, (byte) 0x95, (byte) 0x9f, (byte) 0x2f,
            (byte) 0x75, (byte) 0x32, (byte) 0x2a, (byte) 0x4d, (byte) 0x64, (byte) 0xbd,
            (byte) 0xb1, (byte) 0xe0, (byte) 0x46, (byte) 0x4f, (byte) 0xe8, (byte) 0x6c,
            (byte) 0x4b, (byte) 0x77, (byte) 0xcc, (byte) 0x36, (byte) 0x87, (byte) 0x05,
            (byte) 0x56, (byte) 0x9a, (byte) 0xe4, (byte) 0x2c, (byte) 0x43, (byte) 0xfd,
            (byte) 0x34, (byte) 0x97, (byte) 0xf8, (byte) 0xd7, (byte) 0x91, (byte) 0xff,
            (byte) 0x56, (byte) 0x86, (byte) 0x17, (byte) 0x49, (byte) 0x0a, (byte) 0x52,
            (byte) 0xfb, (byte) 0xe5, (byte) 0x49, (byte) 0xdf, (byte) 0xc1, (byte) 0x28,
            (byte) 0x9d, (byte) 0x85, (byte) 0x66, (byte) 0x9d, (byte) 0x1d, (byte) 0xa4,
            (byte) 0x7e, (byte) 0x9a, (byte) 0x5b, (byte) 0x30
    };

    /*
     * echo -n 'This is a test of OAEP' | openssl pkeyutl -encrypt -inkey /tmp/rsakey.txt \
     * -pkeyopt rsa_padding_mode:oaep -pkey rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 \
     * | xxd -p -i | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] RSA_Vector2_OAEP_SHA256_MGF1_SHA256 = new byte[] {
            (byte) 0x6a, (byte) 0x2b, (byte) 0xb2, (byte) 0xa3, (byte) 0x26, (byte) 0xa6,
            (byte) 0x7a, (byte) 0x4a, (byte) 0x1f, (byte) 0xe5, (byte) 0xc8, (byte) 0x94,
            (byte) 0x11, (byte) 0x1a, (byte) 0x92, (byte) 0x07, (byte) 0x0a, (byte) 0xf4,
            (byte) 0x07, (byte) 0x0b, (byte) 0xd6, (byte) 0x37, (byte) 0xa5, (byte) 0x5d,
            (byte) 0x16, (byte) 0x0a, (byte) 0x7d, (byte) 0x13, (byte) 0x27, (byte) 0x32,
            (byte) 0x5a, (byte) 0xc3, (byte) 0x0d, (byte) 0x7a, (byte) 0x54, (byte) 0xfe,
            (byte) 0x02, (byte) 0x28, (byte) 0xc6, (byte) 0x8e, (byte) 0x32, (byte) 0x7b,
            (byte) 0x0a, (byte) 0x52, (byte) 0xf8, (byte) 0xe6, (byte) 0xab, (byte) 0x16,
            (byte) 0x77, (byte) 0x7c, (byte) 0x53, (byte) 0xcd, (byte) 0xb0, (byte) 0xb6,
            (byte) 0x90, (byte) 0xce, (byte) 0x7b, (byte) 0xa5, (byte) 0xdb, (byte) 0xab,
            (byte) 0xfd, (byte) 0xf5, (byte) 0xbb, (byte) 0x49, (byte) 0x63, (byte) 0xb7,
            (byte) 0xa8, (byte) 0x3e, (byte) 0x53, (byte) 0xf1, (byte) 0x00, (byte) 0x4d,
            (byte) 0x72, (byte) 0x15, (byte) 0x34, (byte) 0xa8, (byte) 0x5b, (byte) 0x00,
            (byte) 0x01, (byte) 0x75, (byte) 0xdc, (byte) 0xb6, (byte) 0xd1, (byte) 0xdf,
            (byte) 0xcb, (byte) 0x93, (byte) 0xf3, (byte) 0x31, (byte) 0x04, (byte) 0x7e,
            (byte) 0x48, (byte) 0x3e, (byte) 0xc9, (byte) 0xaf, (byte) 0xd7, (byte) 0xbd,
            (byte) 0x9e, (byte) 0x73, (byte) 0x01, (byte) 0x79, (byte) 0xf8, (byte) 0xdc,
            (byte) 0x46, (byte) 0x31, (byte) 0x55, (byte) 0x83, (byte) 0x21, (byte) 0xd1,
            (byte) 0x19, (byte) 0x0b, (byte) 0x57, (byte) 0xf1, (byte) 0x06, (byte) 0xb9,
            (byte) 0x32, (byte) 0x0e, (byte) 0x9d, (byte) 0x38, (byte) 0x53, (byte) 0x94,
            (byte) 0x96, (byte) 0xd4, (byte) 0x6d, (byte) 0x18, (byte) 0xe2, (byte) 0xe3,
            (byte) 0xcd, (byte) 0xfa, (byte) 0xfe, (byte) 0xb3, (byte) 0xe3, (byte) 0x27,
            (byte) 0xd7, (byte) 0x45, (byte) 0xe8, (byte) 0x46, (byte) 0x6b, (byte) 0x06,
            (byte) 0x0f, (byte) 0x5e, (byte) 0x24, (byte) 0x02, (byte) 0xef, (byte) 0xa2,
            (byte) 0x69, (byte) 0xe6, (byte) 0x15, (byte) 0xb3, (byte) 0x8f, (byte) 0x71,
            (byte) 0x97, (byte) 0x39, (byte) 0xfb, (byte) 0x32, (byte) 0xe0, (byte) 0xe5,
            (byte) 0xac, (byte) 0x46, (byte) 0xb4, (byte) 0xe7, (byte) 0x3d, (byte) 0x89,
            (byte) 0xba, (byte) 0xd9, (byte) 0x4c, (byte) 0x25, (byte) 0x97, (byte) 0xef,
            (byte) 0xe6, (byte) 0x17, (byte) 0x23, (byte) 0x4e, (byte) 0xc8, (byte) 0xdb,
            (byte) 0x18, (byte) 0x9b, (byte) 0xba, (byte) 0xb5, (byte) 0x7e, (byte) 0x19,
            (byte) 0x4d, (byte) 0x95, (byte) 0x7d, (byte) 0x60, (byte) 0x1b, (byte) 0xa7,
            (byte) 0x06, (byte) 0x1e, (byte) 0x99, (byte) 0x4a, (byte) 0xf2, (byte) 0x82,
            (byte) 0x71, (byte) 0x62, (byte) 0x41, (byte) 0xa4, (byte) 0xa7, (byte) 0xdb,
            (byte) 0x88, (byte) 0xb0, (byte) 0x4a, (byte) 0xc7, (byte) 0x3b, (byte) 0xce,
            (byte) 0x91, (byte) 0x4f, (byte) 0xc7, (byte) 0xca, (byte) 0x6f, (byte) 0x89,
            (byte) 0xac, (byte) 0x1a, (byte) 0x36, (byte) 0x84, (byte) 0x0c, (byte) 0x97,
            (byte) 0xa0, (byte) 0x1a, (byte) 0x08, (byte) 0x6f, (byte) 0x70, (byte) 0xf3,
            (byte) 0x94, (byte) 0xa0, (byte) 0x0f, (byte) 0x44, (byte) 0xdd, (byte) 0x86,
            (byte) 0x9d, (byte) 0x2c, (byte) 0xac, (byte) 0x43, (byte) 0xed, (byte) 0xb8,
            (byte) 0xa1, (byte) 0x66, (byte) 0xf3, (byte) 0xd3, (byte) 0x5c, (byte) 0xe5,
            (byte) 0xe2, (byte) 0x4c, (byte) 0x7e, (byte) 0xda, (byte) 0x20, (byte) 0xbd,
            (byte) 0x5a, (byte) 0x75, (byte) 0x12, (byte) 0x31, (byte) 0x23, (byte) 0x02,
            (byte) 0xb5, (byte) 0x1f, (byte) 0x38, (byte) 0x98
    };

    /*
     * echo -n 'This is a test of OAEP' | openssl pkeyutl -encrypt -inkey /tmp/rsakey.txt \
     * -pkeyopt rsa_padding_mode:oaep -pkey rsa_oaep_md:sha384 -pkeyopt rsa_mgf1_md:sha384 \
     * | xxd -p -i | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] RSA_Vector2_OAEP_SHA384_MGF1_SHA384 = new byte[] {
            (byte) 0xa1, (byte) 0xb3, (byte) 0x3b, (byte) 0x34, (byte) 0x69, (byte) 0x9e,
            (byte) 0xd8, (byte) 0xa0, (byte) 0x37, (byte) 0x2c, (byte) 0xeb, (byte) 0xef,
            (byte) 0xf2, (byte) 0xaf, (byte) 0xfa, (byte) 0x63, (byte) 0x5d, (byte) 0x88,
            (byte) 0xac, (byte) 0x51, (byte) 0xd4, (byte) 0x7f, (byte) 0x85, (byte) 0xf0,
            (byte) 0x5e, (byte) 0xb4, (byte) 0x81, (byte) 0x7c, (byte) 0x82, (byte) 0x4f,
            (byte) 0x92, (byte) 0xf7, (byte) 0x77, (byte) 0x48, (byte) 0x4c, (byte) 0xb1,
            (byte) 0x42, (byte) 0xb3, (byte) 0x0e, (byte) 0x94, (byte) 0xc8, (byte) 0x5a,
            (byte) 0xae, (byte) 0xed, (byte) 0x8d, (byte) 0x51, (byte) 0x72, (byte) 0x6b,
            (byte) 0xa9, (byte) 0xd4, (byte) 0x1e, (byte) 0xbe, (byte) 0x38, (byte) 0x2c,
            (byte) 0xd0, (byte) 0x43, (byte) 0xae, (byte) 0xb4, (byte) 0x30, (byte) 0xa9,
            (byte) 0x93, (byte) 0x47, (byte) 0xb5, (byte) 0x9d, (byte) 0x03, (byte) 0x92,
            (byte) 0x25, (byte) 0x74, (byte) 0xed, (byte) 0xfa, (byte) 0xfe, (byte) 0xf1,
            (byte) 0xba, (byte) 0x04, (byte) 0x3a, (byte) 0x4d, (byte) 0x6d, (byte) 0x9a,
            (byte) 0x0d, (byte) 0x95, (byte) 0x02, (byte) 0xb0, (byte) 0xac, (byte) 0x77,
            (byte) 0x11, (byte) 0x44, (byte) 0xeb, (byte) 0xd2, (byte) 0x02, (byte) 0x90,
            (byte) 0xea, (byte) 0x2f, (byte) 0x68, (byte) 0x2a, (byte) 0x69, (byte) 0xcf,
            (byte) 0x45, (byte) 0x34, (byte) 0xff, (byte) 0x00, (byte) 0xc6, (byte) 0x3c,
            (byte) 0x0b, (byte) 0x2c, (byte) 0x5f, (byte) 0x8c, (byte) 0x2c, (byte) 0xbf,
            (byte) 0xc2, (byte) 0x4b, (byte) 0x16, (byte) 0x07, (byte) 0x84, (byte) 0x74,
            (byte) 0xf0, (byte) 0x7a, (byte) 0x01, (byte) 0x7e, (byte) 0x74, (byte) 0x01,
            (byte) 0x88, (byte) 0xce, (byte) 0xda, (byte) 0xe4, (byte) 0x21, (byte) 0x89,
            (byte) 0xfc, (byte) 0xac, (byte) 0x68, (byte) 0xdb, (byte) 0xfc, (byte) 0x5f,
            (byte) 0x3f, (byte) 0x00, (byte) 0xd9, (byte) 0x32, (byte) 0x1d, (byte) 0xa5,
            (byte) 0xec, (byte) 0x72, (byte) 0x46, (byte) 0x23, (byte) 0xe5, (byte) 0x7f,
            (byte) 0x49, (byte) 0x0e, (byte) 0x3e, (byte) 0xf2, (byte) 0x2b, (byte) 0x16,
            (byte) 0x52, (byte) 0x9f, (byte) 0x9d, (byte) 0x0c, (byte) 0xfe, (byte) 0xab,
            (byte) 0xdd, (byte) 0x77, (byte) 0x77, (byte) 0x94, (byte) 0xa4, (byte) 0x92,
            (byte) 0xa2, (byte) 0x41, (byte) 0x0d, (byte) 0x4b, (byte) 0x57, (byte) 0x80,
            (byte) 0xd6, (byte) 0x74, (byte) 0x63, (byte) 0xd5, (byte) 0xbf, (byte) 0x5c,
            (byte) 0xa0, (byte) 0xda, (byte) 0x3c, (byte) 0xe6, (byte) 0xbf, (byte) 0xa4,
            (byte) 0xc3, (byte) 0xfb, (byte) 0x46, (byte) 0x3b, (byte) 0x73, (byte) 0x30,
            (byte) 0x4b, (byte) 0x57, (byte) 0x27, (byte) 0x0c, (byte) 0x81, (byte) 0xde,
            (byte) 0x8a, (byte) 0x01, (byte) 0xe5, (byte) 0x7e, (byte) 0xe0, (byte) 0x16,
            (byte) 0x11, (byte) 0x24, (byte) 0x34, (byte) 0x22, (byte) 0x01, (byte) 0x9f,
            (byte) 0xe6, (byte) 0xa9, (byte) 0xfb, (byte) 0xad, (byte) 0x55, (byte) 0x17,
            (byte) 0x2a, (byte) 0x92, (byte) 0x87, (byte) 0xf3, (byte) 0x72, (byte) 0xc9,
            (byte) 0x3d, (byte) 0xc9, (byte) 0x2e, (byte) 0x32, (byte) 0x8e, (byte) 0xbb,
            (byte) 0xdc, (byte) 0x1b, (byte) 0xa7, (byte) 0x7b, (byte) 0x73, (byte) 0xd7,
            (byte) 0xf4, (byte) 0xad, (byte) 0xa9, (byte) 0x3a, (byte) 0xf7, (byte) 0xa8,
            (byte) 0x82, (byte) 0x92, (byte) 0x40, (byte) 0xd4, (byte) 0x51, (byte) 0x87,
            (byte) 0xe1, (byte) 0xb7, (byte) 0x4f, (byte) 0x91, (byte) 0x75, (byte) 0x5b,
            (byte) 0x03, (byte) 0x9d, (byte) 0xa1, (byte) 0xd4, (byte) 0x00, (byte) 0x05,
            (byte) 0x79, (byte) 0x42, (byte) 0x93, (byte) 0x76
    };

    /*
     * echo -n 'This is a test of OAEP' | openssl pkeyutl -encrypt -inkey /tmp/rsakey.txt \
     * -pkeyopt rsa_padding_mode:oaep -pkey rsa_oaep_md:sha512 -pkeyopt rsa_mgf1_md:sha512 \
     * | xxd -p -i | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] RSA_Vector2_OAEP_SHA512_MGF1_SHA512 = new byte[] {
            (byte) 0x75, (byte) 0x0f, (byte) 0xf9, (byte) 0x21, (byte) 0xca, (byte) 0xcc,
            (byte) 0x0e, (byte) 0x13, (byte) 0x9e, (byte) 0x38, (byte) 0xa4, (byte) 0xa7,
            (byte) 0xee, (byte) 0x61, (byte) 0x6d, (byte) 0x56, (byte) 0xea, (byte) 0x36,
            (byte) 0xeb, (byte) 0xec, (byte) 0xfa, (byte) 0x1a, (byte) 0xeb, (byte) 0x0c,
            (byte) 0xb2, (byte) 0x58, (byte) 0x9d, (byte) 0xde, (byte) 0x47, (byte) 0x27,
            (byte) 0x2d, (byte) 0xbd, (byte) 0x8b, (byte) 0xa7, (byte) 0xf1, (byte) 0x8b,
            (byte) 0xba, (byte) 0x4c, (byte) 0xab, (byte) 0x39, (byte) 0x6a, (byte) 0x82,
            (byte) 0x0d, (byte) 0xaf, (byte) 0x4c, (byte) 0xde, (byte) 0xdb, (byte) 0x5e,
            (byte) 0xdb, (byte) 0x08, (byte) 0x98, (byte) 0x06, (byte) 0xc5, (byte) 0x99,
            (byte) 0xb6, (byte) 0x6d, (byte) 0xbc, (byte) 0x5b, (byte) 0xf9, (byte) 0xe4,
            (byte) 0x97, (byte) 0x0b, (byte) 0xba, (byte) 0xe3, (byte) 0x17, (byte) 0xa9,
            (byte) 0x3c, (byte) 0x4b, (byte) 0x21, (byte) 0xd8, (byte) 0x29, (byte) 0xf8,
            (byte) 0xa7, (byte) 0x1c, (byte) 0x15, (byte) 0xd7, (byte) 0xf6, (byte) 0xfc,
            (byte) 0x53, (byte) 0x64, (byte) 0x97, (byte) 0x9e, (byte) 0x22, (byte) 0xb1,
            (byte) 0x93, (byte) 0x26, (byte) 0x80, (byte) 0xdc, (byte) 0xaa, (byte) 0x1b,
            (byte) 0xae, (byte) 0x69, (byte) 0x0f, (byte) 0x74, (byte) 0x3d, (byte) 0x61,
            (byte) 0x80, (byte) 0x68, (byte) 0xb8, (byte) 0xaf, (byte) 0x63, (byte) 0x72,
            (byte) 0x37, (byte) 0x4f, (byte) 0xf3, (byte) 0x29, (byte) 0x4a, (byte) 0x75,
            (byte) 0x4f, (byte) 0x29, (byte) 0x40, (byte) 0x01, (byte) 0xd3, (byte) 0xc6,
            (byte) 0x56, (byte) 0x1a, (byte) 0xaf, (byte) 0xc3, (byte) 0xb3, (byte) 0xd2,
            (byte) 0xb9, (byte) 0x91, (byte) 0x35, (byte) 0x1b, (byte) 0x89, (byte) 0x4c,
            (byte) 0x61, (byte) 0xa2, (byte) 0x8e, (byte) 0x6f, (byte) 0x12, (byte) 0x4a,
            (byte) 0x10, (byte) 0xc2, (byte) 0xcc, (byte) 0xab, (byte) 0x51, (byte) 0xec,
            (byte) 0x1b, (byte) 0xb5, (byte) 0xfe, (byte) 0x20, (byte) 0x16, (byte) 0xb2,
            (byte) 0xc5, (byte) 0x0f, (byte) 0xe1, (byte) 0x6a, (byte) 0xb4, (byte) 0x6c,
            (byte) 0x27, (byte) 0xd9, (byte) 0x42, (byte) 0xb9, (byte) 0xb6, (byte) 0x55,
            (byte) 0xa8, (byte) 0xbc, (byte) 0x1c, (byte) 0x32, (byte) 0x54, (byte) 0x84,
            (byte) 0xec, (byte) 0x1e, (byte) 0x95, (byte) 0xd8, (byte) 0xae, (byte) 0xca,
            (byte) 0xc1, (byte) 0xad, (byte) 0x4c, (byte) 0x65, (byte) 0xd6, (byte) 0xc2,
            (byte) 0x19, (byte) 0x66, (byte) 0xad, (byte) 0x9f, (byte) 0x55, (byte) 0x15,
            (byte) 0xe1, (byte) 0x5d, (byte) 0x8f, (byte) 0xab, (byte) 0x18, (byte) 0x68,
            (byte) 0x42, (byte) 0x7c, (byte) 0x48, (byte) 0xb7, (byte) 0x2c, (byte) 0xfd,
            (byte) 0x1a, (byte) 0x07, (byte) 0xa1, (byte) 0x6a, (byte) 0xfb, (byte) 0x81,
            (byte) 0xc6, (byte) 0x93, (byte) 0xbf, (byte) 0xa3, (byte) 0x5d, (byte) 0xfd,
            (byte) 0xce, (byte) 0xf3, (byte) 0x17, (byte) 0x26, (byte) 0xf0, (byte) 0xda,
            (byte) 0x0e, (byte) 0xd1, (byte) 0x86, (byte) 0x9d, (byte) 0x61, (byte) 0xd1,
            (byte) 0x8a, (byte) 0xdb, (byte) 0x36, (byte) 0x39, (byte) 0x1c, (byte) 0xd4,
            (byte) 0x99, (byte) 0x53, (byte) 0x30, (byte) 0x5a, (byte) 0x01, (byte) 0xf4,
            (byte) 0xa0, (byte) 0xca, (byte) 0x94, (byte) 0x72, (byte) 0x3d, (byte) 0xe3,
            (byte) 0x50, (byte) 0x95, (byte) 0xcb, (byte) 0xa9, (byte) 0x37, (byte) 0xeb,
            (byte) 0x66, (byte) 0x21, (byte) 0x20, (byte) 0x2e, (byte) 0xf2, (byte) 0xfd,
            (byte) 0xfa, (byte) 0x54, (byte) 0xbf, (byte) 0x17, (byte) 0x23, (byte) 0xbb,
            (byte) 0x9e, (byte) 0x77, (byte) 0xe0, (byte) 0xaa
    };

    /*
     * echo -n 'This is a test of OAEP' | openssl pkeyutl -encrypt -inkey /tmp/rsakey.txt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha512 -pkeyopt rsa_mgf1_md:sha512 -pkeyopt rsa_oaep_label:010203FFA00A | xxd -p -i | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] RSA_Vector2_OAEP_SHA512_MGF1_SHA512_LABEL = new byte[] {
            (byte) 0x31, (byte) 0x3b, (byte) 0x23, (byte) 0xcf, (byte) 0x40, (byte) 0xfe,
            (byte) 0x15, (byte) 0x94, (byte) 0xd6, (byte) 0x81, (byte) 0x21, (byte) 0x69,
            (byte) 0x8e, (byte) 0x58, (byte) 0xd5, (byte) 0x0f, (byte) 0xa8, (byte) 0x72,
            (byte) 0x94, (byte) 0x13, (byte) 0xfe, (byte) 0xf9, (byte) 0xa1, (byte) 0x47,
            (byte) 0x49, (byte) 0x91, (byte) 0xcb, (byte) 0x66, (byte) 0xe6, (byte) 0x5d,
            (byte) 0x02, (byte) 0xad, (byte) 0xd4, (byte) 0x2f, (byte) 0x4f, (byte) 0xab,
            (byte) 0xb7, (byte) 0x9e, (byte) 0xc0, (byte) 0xf0, (byte) 0x3d, (byte) 0x66,
            (byte) 0x0e, (byte) 0x20, (byte) 0x82, (byte) 0x7f, (byte) 0x22, (byte) 0x8f,
            (byte) 0x81, (byte) 0xba, (byte) 0x47, (byte) 0xc7, (byte) 0xaf, (byte) 0xb6,
            (byte) 0x0e, (byte) 0x78, (byte) 0xe3, (byte) 0x30, (byte) 0xd7, (byte) 0x6c,
            (byte) 0x81, (byte) 0xc2, (byte) 0x05, (byte) 0x7e, (byte) 0xe9, (byte) 0xac,
            (byte) 0x8d, (byte) 0x45, (byte) 0x25, (byte) 0xe8, (byte) 0x26, (byte) 0x39,
            (byte) 0x88, (byte) 0x64, (byte) 0x2e, (byte) 0xc6, (byte) 0xed, (byte) 0xd4,
            (byte) 0xad, (byte) 0x94, (byte) 0xc8, (byte) 0x4e, (byte) 0x4a, (byte) 0x71,
            (byte) 0x1e, (byte) 0x11, (byte) 0x14, (byte) 0x03, (byte) 0x56, (byte) 0x02,
            (byte) 0x28, (byte) 0x32, (byte) 0x8f, (byte) 0xe2, (byte) 0x16, (byte) 0x4a,
            (byte) 0x62, (byte) 0xa6, (byte) 0x9a, (byte) 0x8d, (byte) 0xf8, (byte) 0x33,
            (byte) 0x35, (byte) 0xa2, (byte) 0xc7, (byte) 0x70, (byte) 0xcc, (byte) 0x26,
            (byte) 0x1e, (byte) 0x4d, (byte) 0x9c, (byte) 0x4e, (byte) 0x2b, (byte) 0xe8,
            (byte) 0xfd, (byte) 0x07, (byte) 0x33, (byte) 0x15, (byte) 0x53, (byte) 0x11,
            (byte) 0x5c, (byte) 0x6f, (byte) 0x5d, (byte) 0x23, (byte) 0x7b, (byte) 0x3f,
            (byte) 0x73, (byte) 0xff, (byte) 0xf4, (byte) 0xbe, (byte) 0x1f, (byte) 0xe6,
            (byte) 0x5a, (byte) 0xb8, (byte) 0x2b, (byte) 0xd2, (byte) 0xbe, (byte) 0xa0,
            (byte) 0x91, (byte) 0x5d, (byte) 0xca, (byte) 0x89, (byte) 0xb3, (byte) 0xce,
            (byte) 0x0a, (byte) 0x2b, (byte) 0xce, (byte) 0xb9, (byte) 0xbe, (byte) 0x5d,
            (byte) 0xb2, (byte) 0xc2, (byte) 0xd6, (byte) 0xa9, (byte) 0xbc, (byte) 0x37,
            (byte) 0xed, (byte) 0x9a, (byte) 0xba, (byte) 0x35, (byte) 0xf8, (byte) 0x6e,
            (byte) 0x63, (byte) 0x76, (byte) 0xd1, (byte) 0x12, (byte) 0xf5, (byte) 0x89,
            (byte) 0xf0, (byte) 0x13, (byte) 0x86, (byte) 0xe7, (byte) 0x1b, (byte) 0x94,
            (byte) 0xcb, (byte) 0xc8, (byte) 0x5c, (byte) 0x4c, (byte) 0x1b, (byte) 0x8a,
            (byte) 0x2d, (byte) 0x6b, (byte) 0x24, (byte) 0x1a, (byte) 0x38, (byte) 0x14,
            (byte) 0x77, (byte) 0x49, (byte) 0xe5, (byte) 0x08, (byte) 0x25, (byte) 0xe4,
            (byte) 0xa6, (byte) 0xcf, (byte) 0x62, (byte) 0xfd, (byte) 0x66, (byte) 0x28,
            (byte) 0xf0, (byte) 0x3a, (byte) 0x9c, (byte) 0x31, (byte) 0xef, (byte) 0x48,
            (byte) 0x2a, (byte) 0xd3, (byte) 0x3e, (byte) 0x29, (byte) 0xfa, (byte) 0x18,
            (byte) 0x8f, (byte) 0xd6, (byte) 0xaa, (byte) 0x1d, (byte) 0x10, (byte) 0xcd,
            (byte) 0x35, (byte) 0x25, (byte) 0x92, (byte) 0x48, (byte) 0xa0, (byte) 0x2c,
            (byte) 0xc1, (byte) 0x31, (byte) 0xeb, (byte) 0x47, (byte) 0x5b, (byte) 0x22,
            (byte) 0x52, (byte) 0x7c, (byte) 0xf5, (byte) 0xec, (byte) 0x76, (byte) 0x90,
            (byte) 0x94, (byte) 0x58, (byte) 0xd9, (byte) 0xd6, (byte) 0xe0, (byte) 0x0a,
            (byte) 0x3f, (byte) 0x09, (byte) 0x98, (byte) 0x03, (byte) 0xc5, (byte) 0x07,
            (byte) 0x8f, (byte) 0x89, (byte) 0x1e, (byte) 0x62, (byte) 0x2c, (byte) 0xea,
            (byte) 0x17, (byte) 0x0a, (byte) 0x2e, (byte) 0x68
    };

    @Test
    public void testRSA_ECB_NoPadding_Private_OnlyDoFinal_Success() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Private_OnlyDoFinal_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Private_OnlyDoFinal_Success(String provider) throws Exception {
        final PrivateKey privKey = (PrivateKey) getDecryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually decrypting with private keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, privKey);
        byte[] encrypted = c.doFinal(RSA_2048_Vector1);
        assertArrayEquals("Encrypted should match expected",
                RSA_Vector1_Encrypt_Private, encrypted);

        c.init(Cipher.DECRYPT_MODE, privKey);
        encrypted = c.doFinal(RSA_2048_Vector1);
        assertArrayEquals("Encrypted should match expected",
                RSA_Vector1_Encrypt_Private, encrypted);
    }

    @Test
    public void testRSA_ECB_NoPadding_Private_UpdateThenEmptyDoFinal_Success() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Private_UpdateThenEmptyDoFinal_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Private_UpdateThenEmptyDoFinal_Success(String provider) throws Exception {
        final PrivateKey privKey = (PrivateKey) getDecryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually decrypting with private keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, privKey);
        c.update(RSA_2048_Vector1);
        byte[] encrypted = c.doFinal();
        assertArrayEquals("Encrypted should match expected",
                RSA_Vector1_Encrypt_Private, encrypted);

        c.init(Cipher.DECRYPT_MODE, privKey);
        c.update(RSA_2048_Vector1);
        encrypted = c.doFinal();
        assertArrayEquals("Encrypted should match expected",
                RSA_Vector1_Encrypt_Private, encrypted);
    }

    @Test
    public void testRSA_ECB_NoPadding_Private_SingleByteUpdateThenEmptyDoFinal_Success()
            throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Private_SingleByteUpdateThenEmptyDoFinal_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Private_SingleByteUpdateThenEmptyDoFinal_Success(String provider)
            throws Exception {
        final PrivateKey privKey = (PrivateKey) getDecryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually decrypting with private keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, privKey);
        int i;
        for (i = 0; i < RSA_2048_Vector1.length / 2; i++) {
            c.update(RSA_2048_Vector1, i, 1);
        }
        byte[] encrypted = c.doFinal(RSA_2048_Vector1, i, RSA_2048_Vector1.length - i);
        assertArrayEquals("Encrypted should match expected",
                RSA_Vector1_Encrypt_Private, encrypted);

        c.init(Cipher.DECRYPT_MODE, privKey);
        for (i = 0; i < RSA_2048_Vector1.length / 2; i++) {
            c.update(RSA_2048_Vector1, i, 1);
        }
        encrypted = c.doFinal(RSA_2048_Vector1, i, RSA_2048_Vector1.length - i);
        assertArrayEquals("Encrypted should match expected",
                RSA_Vector1_Encrypt_Private, encrypted);
    }

    @Test
    public void testRSA_ECB_NoPadding_Private_OnlyDoFinalWithOffset_Success() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Private_OnlyDoFinalWithOffset_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Private_OnlyDoFinalWithOffset_Success(String provider) throws Exception {
        final PrivateKey privKey = (PrivateKey) getDecryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually decrypting with private keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, privKey);
        byte[] encrypted = new byte[RSA_Vector1_Encrypt_Private.length];
        final int encryptLen = c
                .doFinal(RSA_2048_Vector1, 0, RSA_2048_Vector1.length, encrypted, 0);
        assertEquals("Encrypted size should match expected", RSA_Vector1_Encrypt_Private.length,
                encryptLen);
        assertArrayEquals("Encrypted should match expected",
                RSA_Vector1_Encrypt_Private, encrypted);

        c.init(Cipher.DECRYPT_MODE, privKey);
        final int decryptLen = c
                .doFinal(RSA_2048_Vector1, 0, RSA_2048_Vector1.length, encrypted, 0);
        assertEquals("Encrypted size should match expected", RSA_Vector1_Encrypt_Private.length,
                decryptLen);
        assertArrayEquals("Encrypted should match expected",
                RSA_Vector1_Encrypt_Private, encrypted);
    }

    @Test
    public void testRSA_ECB_NoPadding_Public_OnlyDoFinal_Success() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Public_OnlyDoFinal_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Public_OnlyDoFinal_Success(String provider) throws Exception {
        final PublicKey pubKey = (PublicKey) getEncryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually encrypting with public keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encrypted = c.doFinal(RSA_Vector1_Encrypt_Private);
        assertEncryptedEqualsNoPadding(provider, Cipher.ENCRYPT_MODE, RSA_2048_Vector1, encrypted);

        c.init(Cipher.DECRYPT_MODE, pubKey);
        encrypted = c.doFinal(RSA_Vector1_Encrypt_Private);
        assertEncryptedEqualsNoPadding(provider, Cipher.DECRYPT_MODE, RSA_2048_Vector1, encrypted);
    }

    @Test
    public void testRSA_ECB_NoPadding_Public_OnlyDoFinalWithOffset_Success() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Public_OnlyDoFinalWithOffset_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Public_OnlyDoFinalWithOffset_Success(String provider) throws Exception {
        final PublicKey pubKey = (PublicKey) getEncryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually encrypting with public keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encrypted = new byte[RSA_2048_Vector1.length];
        final int encryptLen = c.doFinal(RSA_Vector1_Encrypt_Private, 0,
                RSA_Vector1_Encrypt_Private.length, encrypted, 0);
        assertEquals("Encrypted size should match expected", RSA_2048_Vector1.length, encryptLen);
        assertEncryptedEqualsNoPadding(provider, Cipher.ENCRYPT_MODE, RSA_2048_Vector1, encrypted);

        c.init(Cipher.DECRYPT_MODE, pubKey);
        int decryptLen = c.doFinal(RSA_Vector1_Encrypt_Private, 0,
                RSA_Vector1_Encrypt_Private.length, encrypted, 0);
        if (provider.equals("BC")) {
            // BC strips the leading 0 for us on decrypt even when NoPadding is specified...
            decryptLen++;
            encrypted = Arrays.copyOf(encrypted, encrypted.length - 1);
        }
        assertEquals("Encrypted size should match expected", RSA_2048_Vector1.length, decryptLen);
        assertEncryptedEqualsNoPadding(provider, Cipher.DECRYPT_MODE, RSA_2048_Vector1, encrypted);
    }

    @Test
    public void testRSA_ECB_NoPadding_Public_UpdateThenEmptyDoFinal_Success() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Public_UpdateThenEmptyDoFinal_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Public_UpdateThenEmptyDoFinal_Success(String provider) throws Exception {
        final PublicKey pubKey = (PublicKey) getEncryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually encrypting with public keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, pubKey);
        c.update(RSA_Vector1_Encrypt_Private);
        byte[] encrypted = c.doFinal();
        assertEncryptedEqualsNoPadding(provider, Cipher.ENCRYPT_MODE, RSA_2048_Vector1, encrypted);

        c.init(Cipher.DECRYPT_MODE, pubKey);
        c.update(RSA_Vector1_Encrypt_Private);
        encrypted = c.doFinal();
        assertEncryptedEqualsNoPadding(provider, Cipher.DECRYPT_MODE, RSA_2048_Vector1, encrypted);
    }

    @Test
    public void testRSA_ECB_NoPadding_Public_SingleByteUpdateThenEmptyDoFinal_Success()
            throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Public_SingleByteUpdateThenEmptyDoFinal_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Public_SingleByteUpdateThenEmptyDoFinal_Success(String provider)
            throws Exception {
        final PublicKey pubKey = (PublicKey) getEncryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually encrypting with public keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, pubKey);
        int i;
        for (i = 0; i < RSA_Vector1_Encrypt_Private.length / 2; i++) {
            c.update(RSA_Vector1_Encrypt_Private, i, 1);
        }
        byte[] encrypted = c.doFinal(RSA_Vector1_Encrypt_Private, i, RSA_2048_Vector1.length - i);
        assertEncryptedEqualsNoPadding(provider, Cipher.ENCRYPT_MODE, RSA_2048_Vector1, encrypted);

        c.init(Cipher.DECRYPT_MODE, pubKey);
        for (i = 0; i < RSA_Vector1_Encrypt_Private.length / 2; i++) {
            c.update(RSA_Vector1_Encrypt_Private, i, 1);
        }
        encrypted = c.doFinal(RSA_Vector1_Encrypt_Private, i, RSA_2048_Vector1.length - i);
        assertEncryptedEqualsNoPadding(provider, Cipher.DECRYPT_MODE, RSA_2048_Vector1, encrypted);
    }

    @Test
    public void testRSA_ECB_NoPadding_Public_TooSmall_Success() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Public_TooSmall_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Public_TooSmall_Success(String provider) throws Exception {
        final PublicKey pubKey = (PublicKey) getEncryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually encrypting with public keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encrypted = c.doFinal(TooShort_Vector);
        assertArrayEquals("Encrypted should match expected",
                RSA_Vector1_ZeroPadded_Encrypted, encrypted);

        c.init(Cipher.DECRYPT_MODE, pubKey);
        encrypted = c.doFinal(TooShort_Vector);
        assertArrayEquals("Encrypted should match expected",
                RSA_Vector1_ZeroPadded_Encrypted, encrypted);
    }

    @Test
    public void testRSA_ECB_NoPadding_Private_TooSmall_Success() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Private_TooSmall_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Private_TooSmall_Success(String provider) throws Exception {
        final PrivateKey privKey = (PrivateKey) getDecryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually encrypting with public keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, privKey);
        byte[] encrypted = c.doFinal(RSA_Vector1_ZeroPadded_Encrypted);
        assertEncryptedEqualsNoPadding(provider, Cipher.ENCRYPT_MODE,
                                       TooShort_Vector_Zero_Padded, encrypted);

        c.init(Cipher.DECRYPT_MODE, privKey);
        encrypted = c.doFinal(RSA_Vector1_ZeroPadded_Encrypted);
        assertEncryptedEqualsNoPadding(provider, Cipher.DECRYPT_MODE,
                                       TooShort_Vector_Zero_Padded, encrypted);
    }

    private static void assertEncryptedEqualsNoPadding(String provider, int mode,
                                                       byte[] expected, byte[] actual) {
        if (provider.equals("BC") && mode == Cipher.DECRYPT_MODE) {
            // BouncyCastle does us the favor of stripping leading zeroes in DECRYPT_MODE
            int nonZeroOffset = 0;
            for (byte b : expected) {
                if (b != 0) {
                    break;
                }
                nonZeroOffset++;
            }
            expected = Arrays.copyOfRange(expected, nonZeroOffset, expected.length);
        }
        assertEquals("Encrypted should match expected",
                     Arrays.toString(expected), Arrays.toString(actual));
    }

    @Test
    public void testRSA_ECB_NoPadding_Private_CombinedUpdateAndDoFinal_TooBig_Failure()
            throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Private_CombinedUpdateAndDoFinal_TooBig_Failure(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Private_CombinedUpdateAndDoFinal_TooBig_Failure(String provider)
            throws Exception {
        final PrivateKey privKey = (PrivateKey) getDecryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually encrypting with public keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, privKey);
        c.update(RSA_Vector1_ZeroPadded_Encrypted);

        try {
            c.doFinal(RSA_Vector1_ZeroPadded_Encrypted);
            fail("Should have error when block size is too big.");
        } catch (IllegalBlockSizeException success) {
            assertNotEquals("BC", provider);
        } catch (ArrayIndexOutOfBoundsException success) {
            assertEquals("BC", provider);
        }
    }

    @Test
    public void testRSA_ECB_NoPadding_Private_UpdateInAndOutPlusDoFinal_TooBig_Failure()
            throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Private_UpdateInAndOutPlusDoFinal_TooBig_Failure(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Private_UpdateInAndOutPlusDoFinal_TooBig_Failure(String provider)
            throws Exception {
        final PrivateKey privKey = (PrivateKey) getDecryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually encrypting with public keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, privKey);

        byte[] output = new byte[RSA_2048_Vector1.length];
        c.update(RSA_Vector1_ZeroPadded_Encrypted, 0, RSA_Vector1_ZeroPadded_Encrypted.length,
                output);

        try {
            c.doFinal(RSA_Vector1_ZeroPadded_Encrypted);
            fail("Should have error when block size is too big.");
        } catch (IllegalBlockSizeException success) {
            assertNotEquals("BC", provider);
        } catch (ArrayIndexOutOfBoundsException success) {
            assertEquals("BC", provider);
        }
    }

    @Test
    public void testRSA_ECB_NoPadding_Private_OnlyDoFinal_TooBig_Failure() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_Private_OnlyDoFinal_TooBig_Failure(provider);
        }
    }

    private void testRSA_ECB_NoPadding_Private_OnlyDoFinal_TooBig_Failure(String provider) throws Exception {
        final PrivateKey privKey = (PrivateKey) getDecryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);

        /*
         * You're actually encrypting with public keys, but there is no
         * distinction made here. It's all keyed off of what kind of key you're
         * using. ENCRYPT_MODE and DECRYPT_MODE are the same.
         */
        c.init(Cipher.ENCRYPT_MODE, privKey);

        byte[] tooBig_Vector = new byte[RSA_Vector1_ZeroPadded_Encrypted.length * 2];
        System.arraycopy(RSA_Vector1_ZeroPadded_Encrypted, 0, tooBig_Vector, 0,
                RSA_Vector1_ZeroPadded_Encrypted.length);
        System.arraycopy(RSA_Vector1_ZeroPadded_Encrypted, 0, tooBig_Vector,
                RSA_Vector1_ZeroPadded_Encrypted.length, RSA_Vector1_ZeroPadded_Encrypted.length);

        try {
            c.doFinal(tooBig_Vector);
            fail("Should have error when block size is too big.");
        } catch (IllegalBlockSizeException success) {
            assertNotEquals("BC", provider);
        } catch (ArrayIndexOutOfBoundsException success) {
            assertEquals("BC", provider);
        }
    }

    @Test
    public void testRSA_ECB_NoPadding_GetBlockSize_Success() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_GetBlockSize_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_GetBlockSize_Success(String provider) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);
        if (provider.equals("SunJCE")) {
            assertEquals(0, c.getBlockSize());
        } else {
            try {
                c.getBlockSize();
                fail();
            } catch (IllegalStateException expected) {
            }
        }

        final PublicKey pubKey = (PublicKey) getEncryptKey("RSA");
        c.init(Cipher.ENCRYPT_MODE, pubKey);
        assertEquals(getExpectedBlockSize("RSA", Cipher.ENCRYPT_MODE, provider), c.getBlockSize());
    }

    @Test
    public void testRSA_ECB_NoPadding_GetOutputSize_NoInit_Failure() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_GetOutputSize_NoInit_Failure(provider);
        }
    }

    private void testRSA_ECB_NoPadding_GetOutputSize_NoInit_Failure(String provider) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);
        try {
            c.getOutputSize(RSA_2048_Vector1.length);
            fail("Should throw IllegalStateException if getOutputSize is called before init");
        } catch (IllegalStateException success) {
            // Expected.
        }
    }

    @Test
    public void testRSA_ECB_NoPadding_GetOutputSize_Success() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_GetOutputSize_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_GetOutputSize_Success(String provider) throws Exception {
        final PublicKey pubKey = (PublicKey) getEncryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);
        c.init(Cipher.ENCRYPT_MODE, pubKey);

        final int modulusInBytes = RSA_2048_modulus.bitLength() / 8;
        assertEquals(modulusInBytes, c.getOutputSize(RSA_2048_Vector1.length));
        assertEquals(modulusInBytes, c.getOutputSize(RSA_2048_Vector1.length * 2));
        assertEquals(modulusInBytes, c.getOutputSize(0));
    }

    @Test
    public void testRSA_ECB_NoPadding_GetIV_Success() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_GetIV_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_GetIV_Success(String provider) throws Exception {
        final PublicKey pubKey = (PublicKey) getEncryptKey("RSA");

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);
        assertNull("ECB mode has no IV and should be null", c.getIV());

        c.init(Cipher.ENCRYPT_MODE, pubKey);

        assertNull("ECB mode has no IV and should be null", c.getIV());
    }

    @Test
    public void testRSA_ECB_NoPadding_GetParameters_NoneProvided_Success() throws Exception {
        for (String provider : RSA_PROVIDERS) {
            testRSA_ECB_NoPadding_GetParameters_NoneProvided_Success(provider);
        }
    }

    private void testRSA_ECB_NoPadding_GetParameters_NoneProvided_Success(String provider) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", provider);
        assertNull("Parameters should be null", c.getParameters());
    }

    /*
     * Test vector generation:
     * openssl rand -hex 16 | sed 's/\(..\)/(byte) 0x\1, /g'
     */
    private static final SecretKeySpec DES_112_KEY = new SecretKeySpec(new byte[] {
            (byte) 0x6b, (byte) 0xb3, (byte) 0x85, (byte) 0x1c, (byte) 0x3d, (byte) 0x50,
            (byte) 0xd4, (byte) 0x95, (byte) 0x39, (byte) 0x48, (byte) 0x77, (byte) 0x30,
            (byte) 0x1a, (byte) 0xd7, (byte) 0x86, (byte) 0x57,
    }, "DESede");

    /*
     * Test vector generation:
     * openssl rand -hex 24 | sed 's/\(..\)/(byte) 0x\1, /g'
     */
    private static final SecretKeySpec DES_168_KEY = new SecretKeySpec(new byte[] {
            (byte) 0xfe, (byte) 0xd4, (byte) 0xd7, (byte) 0xc9, (byte) 0x8a, (byte) 0x13,
            (byte) 0x6a, (byte) 0xa8, (byte) 0x5a, (byte) 0xb8, (byte) 0x19, (byte) 0xb8,
            (byte) 0xcf, (byte) 0x3c, (byte) 0x5f, (byte) 0xe0, (byte) 0xa2, (byte) 0xf7,
            (byte) 0x7b, (byte) 0x65, (byte) 0x43, (byte) 0xc0, (byte) 0xc4, (byte) 0xe1,
    }, "DESede");

    /*
     * Test vector generation:
     * openssl rand -hex 5 | sed 's/\(..\)/(byte) 0x\1, /g'
     */
    private static final SecretKeySpec ARC4_40BIT_KEY = new SecretKeySpec(new byte[] {
            (byte) 0x9c, (byte) 0xc8, (byte) 0xb9, (byte) 0x94, (byte) 0x98,
    }, "ARC4");

    /*
     * Test vector generation:
     * openssl rand -hex 24 | sed 's/\(..\)/(byte) 0x\1, /g'
     */
    private static final SecretKeySpec ARC4_128BIT_KEY = new SecretKeySpec(new byte[] {
            (byte) 0xbc, (byte) 0x0a, (byte) 0x3c, (byte) 0xca, (byte) 0xb5, (byte) 0x42,
            (byte) 0xfa, (byte) 0x5d, (byte) 0x86, (byte) 0x5b, (byte) 0x44, (byte) 0x87,
            (byte) 0x83, (byte) 0xd8, (byte) 0xcb, (byte) 0xd4,
    }, "ARC4");

    /*
     * Test vector generation:
     * openssl rand -hex 16
     * echo '3d4f8970b1f27537f40a39298a41555f' | sed 's/\(..\)/(byte) 0x\1, /g'
     */
    private static final SecretKeySpec AES_128_KEY = new SecretKeySpec(new byte[] {
            (byte) 0x3d, (byte) 0x4f, (byte) 0x89, (byte) 0x70, (byte) 0xb1, (byte) 0xf2,
            (byte) 0x75, (byte) 0x37, (byte) 0xf4, (byte) 0x0a, (byte) 0x39, (byte) 0x29,
            (byte) 0x8a, (byte) 0x41, (byte) 0x55, (byte) 0x5f,
    }, "AES");

    /*
     * Test key generation:
     * openssl rand -hex 24
     * echo '5a7a3d7e40b64ed996f7afa15f97fd595e27db6af428e342' | sed 's/\(..\)/(byte) 0x\1, /g'
     */
    private static final SecretKeySpec AES_192_KEY = new SecretKeySpec(new byte[] {
            (byte) 0x5a, (byte) 0x7a, (byte) 0x3d, (byte) 0x7e, (byte) 0x40, (byte) 0xb6,
            (byte) 0x4e, (byte) 0xd9, (byte) 0x96, (byte) 0xf7, (byte) 0xaf, (byte) 0xa1,
            (byte) 0x5f, (byte) 0x97, (byte) 0xfd, (byte) 0x59, (byte) 0x5e, (byte) 0x27,
            (byte) 0xdb, (byte) 0x6a, (byte) 0xf4, (byte) 0x28, (byte) 0xe3, (byte) 0x42,
    }, "AES");

    /*
     * Test key generation:
     * openssl rand -hex 32
     * echo 'ec53c6d51d2c4973585fb0b8e51cd2e39915ff07a1837872715d6121bf861935' | sed 's/\(..\)/(byte) 0x\1, /g'
     */
    private static final SecretKeySpec AES_256_KEY = new SecretKeySpec(new byte[] {
            (byte) 0xec, (byte) 0x53, (byte) 0xc6, (byte) 0xd5, (byte) 0x1d, (byte) 0x2c,
            (byte) 0x49, (byte) 0x73, (byte) 0x58, (byte) 0x5f, (byte) 0xb0, (byte) 0xb8,
            (byte) 0xe5, (byte) 0x1c, (byte) 0xd2, (byte) 0xe3, (byte) 0x99, (byte) 0x15,
            (byte) 0xff, (byte) 0x07, (byte) 0xa1, (byte) 0x83, (byte) 0x78, (byte) 0x72,
            (byte) 0x71, (byte) 0x5d, (byte) 0x61, (byte) 0x21, (byte) 0xbf, (byte) 0x86,
            (byte) 0x19, (byte) 0x35,
    }, "AES");

    /*
     * Test vector generation:
     * echo -n 'Testing rocks!' | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] DES_Plaintext1 = new byte[] {
            (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x69, (byte) 0x6E,
            (byte) 0x67, (byte) 0x20, (byte) 0x72, (byte) 0x6F, (byte) 0x63, (byte) 0x6B,
            (byte) 0x73, (byte) 0x21
    };


    /*
     * Test vector generation: take DES_Plaintext1 and PKCS #5 pad it manually (it's not hard).
     */
    private static final byte[] DES_Plaintext1_PKCS5_Padded = new byte[] {
            (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x69, (byte) 0x6E,
            (byte) 0x67, (byte) 0x20, (byte) 0x72, (byte) 0x6F, (byte) 0x63, (byte) 0x6B,
            (byte) 0x73, (byte) 0x21, (byte) 0x02, (byte) 0x02,
    };

    /*
     * Test vector generation:
     * openssl rand -hex 8 | sed 's/\(..\)/(byte) 0x\1, /g'
     */
    private static final byte[] DES_IV1 = new byte[] {
            (byte) 0x5c, (byte) 0x47, (byte) 0x5e, (byte) 0x57, (byte) 0x0c, (byte) 0x46,
            (byte) 0xcb, (byte) 0x47,
    };

    /*
     * Test vector generation:
     * openssl enc -des-ede-cbc -K 6bb3851c3d50d495394877301ad78657 -iv 5c475e570c46cb47 -in blah
     * | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[]
            DES_Plaintext1_Encrypted_With_DES_112_KEY_And_DESEDE_CBC_PKCS5PADDING_With_DES_IV1 =
                    new byte[] {
            (byte) 0x09, (byte) 0xA5, (byte) 0x5D, (byte) 0x94, (byte) 0x94, (byte) 0xAA,
            (byte) 0x3F, (byte) 0xC8, (byte) 0xB7, (byte) 0x73, (byte) 0x94, (byte) 0x0E,
            (byte) 0xFC, (byte) 0xF4, (byte) 0xA5, (byte) 0x28,
    };


    /*
     * Test vector generation:
     * openssl enc -des-ede3-cbc -K fed4d7c98a136aa85ab819b8cf3c5fe0a2f77b6543c0c4e1
     *     -iv 5c475e570c46cb47 -in blah | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[]
            DES_Plaintext1_Encrypted_With_DES_168_KEY_And_DESEDE_CBC_PKCS5PADDING_With_DES_IV1 =
                    new byte[] {
            (byte) 0xC9, (byte) 0xF1, (byte) 0x83, (byte) 0x1F, (byte) 0x24, (byte) 0x83,
            (byte) 0x2C, (byte) 0x7B, (byte) 0x66, (byte) 0x66, (byte) 0x99, (byte) 0x98,
            (byte) 0x27, (byte) 0xB0, (byte) 0xED, (byte) 0x47
    };


    /*
     * Test vector generation:
     * echo -n 'Plaintext for arc4' | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] ARC4_Plaintext1 = new byte[] {
            (byte) 0x50, (byte) 0x6C, (byte) 0x61, (byte) 0x69, (byte) 0x6E, (byte) 0x74,
            (byte) 0x65, (byte) 0x78, (byte) 0x74, (byte) 0x20, (byte) 0x66, (byte) 0x6F,
            (byte) 0x72, (byte) 0x20, (byte) 0x61, (byte) 0x72, (byte) 0x63, (byte) 0x34
    };

    /*
     * Test vector generation:
     *  echo -n 'Plaintext for arc4' | openssl enc -rc4-40 -K 9cc8b99498 | recode ../x1 \
     *     | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] ARC4_Plaintext1_Encrypted_With_ARC4_40Bit_Key = new byte[] {
            (byte) 0x63, (byte) 0xF7, (byte) 0x11, (byte) 0x90, (byte) 0x63, (byte) 0xEF,
            (byte) 0x5E, (byte) 0xB3, (byte) 0x93, (byte) 0xB3, (byte) 0x46, (byte) 0x3F,
            (byte) 0x1B, (byte) 0x02, (byte) 0x53, (byte) 0x9B, (byte) 0xD9, (byte) 0xE0
    };

    /*
     * Test vector generation:
     *  echo -n 'Plaintext for arc4' | openssl enc -rc4 -K bc0a3ccab542fa5d865b448783d8cbd4 \
     *     | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] ARC4_Plaintext1_Encrypted_With_ARC4_128Bit_Key = new byte[] {
            (byte) 0x25, (byte) 0x14, (byte) 0xA9, (byte) 0x72, (byte) 0x4D, (byte) 0xA9,
            (byte) 0xF6, (byte) 0xA7, (byte) 0x2F, (byte) 0xB7, (byte) 0x0D, (byte) 0x60,
            (byte) 0x09, (byte) 0xBE, (byte) 0x41, (byte) 0x9B, (byte) 0x32, (byte) 0x2B
    };

    /*
     * Test vector creation:
     * echo -n 'Hello, world!' | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext = new byte[] {
            (byte) 0x48, (byte) 0x65, (byte) 0x6C, (byte) 0x6C, (byte) 0x6F, (byte) 0x2C,
            (byte) 0x20, (byte) 0x77, (byte) 0x6F, (byte) 0x72, (byte) 0x6C, (byte) 0x64,
            (byte) 0x21,
    };

    /*
     * Test vector creation:
     * openssl enc -aes-128-ecb -K 3d4f8970b1f27537f40a39298a41555f -in blah|openssl enc -aes-128-ecb -K 3d4f8970b1f27537f40a39298a41555f -nopad -d|recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext_Padded = new byte[] {
            (byte) 0x48, (byte) 0x65, (byte) 0x6C, (byte) 0x6C, (byte) 0x6F, (byte) 0x2C,
            (byte) 0x20, (byte) 0x77, (byte) 0x6F, (byte) 0x72, (byte) 0x6C, (byte) 0x64,
            (byte) 0x21, (byte) 0x03, (byte) 0x03, (byte) 0x03
    };

    /*
     * Test vector generation:
     * openssl enc -aes-128-ecb -K 3d4f8970b1f27537f40a39298a41555f -in blah|recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted = new byte[] {
            (byte) 0x65, (byte) 0x3E, (byte) 0x86, (byte) 0xFB, (byte) 0x05, (byte) 0x5A,
            (byte) 0x52, (byte) 0xEA, (byte) 0xDD, (byte) 0x08, (byte) 0xE7, (byte) 0x48,
            (byte) 0x33, (byte) 0x01, (byte) 0xFC, (byte) 0x5A,
    };

    /*
     * Taken from BoringSSL test vectors.
     */
    private static final SecretKeySpec AES_128_GCM_TestVector_1_Key = new SecretKeySpec(new byte[] {
            (byte) 0xca, (byte) 0xbd, (byte) 0xcf, (byte) 0x54, (byte) 0x1a, (byte) 0xeb,
            (byte) 0xf9, (byte) 0x17, (byte) 0xba, (byte) 0xc0, (byte) 0x19, (byte) 0xf1,
            (byte) 0x39, (byte) 0x25, (byte) 0xd2, (byte) 0x67,
    }, "AES");

    /*
     * Taken from BoringSSL test vectors.
     */
    private static final byte[] AES_128_GCM_TestVector_1_IV = new byte[] {
            (byte) 0x2c, (byte) 0x34, (byte) 0xc0, (byte) 0x0c, (byte) 0x42, (byte) 0xda,
            (byte) 0xe3, (byte) 0x82, (byte) 0x27, (byte) 0x9d, (byte) 0x79, (byte) 0x74,
    };

    /*
     * Taken from BoringSSL test vectors.
     */
    private static final byte[] AES_128_GCM_TestVector_1_AAD = new byte[] {
            (byte) 0xdd, (byte) 0x10, (byte) 0xe3, (byte) 0x71, (byte) 0xb2, (byte) 0x2e,
            (byte) 0x15, (byte) 0x67, (byte) 0x1c, (byte) 0x31, (byte) 0xaf, (byte) 0xee,
            (byte) 0x55, (byte) 0x2b, (byte) 0xf1, (byte) 0xde, (byte) 0xa0, (byte) 0x7c,
            (byte) 0xbb, (byte) 0xf6, (byte) 0x85, (byte) 0xe2, (byte) 0xca, (byte) 0xa0,
            (byte) 0xe0, (byte) 0x36, (byte) 0x37, (byte) 0x16, (byte) 0xa2, (byte) 0x76,
            (byte) 0xe1, (byte) 0x20, (byte) 0xc6, (byte) 0xc0, (byte) 0xeb, (byte) 0x4a,
            (byte) 0xcb, (byte) 0x1a, (byte) 0x4d, (byte) 0x1b, (byte) 0xa7, (byte) 0x3f,
            (byte) 0xde, (byte) 0x66, (byte) 0x15, (byte) 0xf7, (byte) 0x08, (byte) 0xaa,
            (byte) 0xa4, (byte) 0x6b, (byte) 0xc7, (byte) 0x6c, (byte) 0x7f, (byte) 0xf3,
            (byte) 0x45, (byte) 0xa4, (byte) 0xf7, (byte) 0x6b, (byte) 0xda, (byte) 0x11,
            (byte) 0x7f, (byte) 0xe5, (byte) 0x6f, (byte) 0x0d, (byte) 0xc9, (byte) 0xb9,
            (byte) 0x39, (byte) 0x04, (byte) 0x0d, (byte) 0xdd,
    };

    /*
     * Taken from BoringSSL test vectors.
     */
    private static final byte[] AES_128_GCM_TestVector_1_Plaintext = new byte[] {
            (byte) 0x88, (byte) 0xcc, (byte) 0x1e, (byte) 0x07, (byte) 0xdf, (byte) 0xde,
            (byte) 0x8e, (byte) 0x08, (byte) 0x08, (byte) 0x2e, (byte) 0x67, (byte) 0x66,
            (byte) 0xe0, (byte) 0xa8, (byte) 0x81, (byte) 0x03, (byte) 0x38, (byte) 0x47,
            (byte) 0x42, (byte) 0xaf, (byte) 0x37, (byte) 0x8d, (byte) 0x7b, (byte) 0x6b,
            (byte) 0x8a, (byte) 0x87, (byte) 0xfc, (byte) 0xe0, (byte) 0x36, (byte) 0xaf,
            (byte) 0x74, (byte) 0x41, (byte) 0xc1, (byte) 0x39, (byte) 0x61, (byte) 0xc2,
            (byte) 0x5a, (byte) 0xfe, (byte) 0xa7, (byte) 0xf6, (byte) 0xe5, (byte) 0x61,
            (byte) 0x93, (byte) 0xf5, (byte) 0x4b, (byte) 0xee, (byte) 0x00, (byte) 0x11,
            (byte) 0xcb, (byte) 0x78, (byte) 0x64, (byte) 0x2c, (byte) 0x3a, (byte) 0xb9,
            (byte) 0xe6, (byte) 0xd5, (byte) 0xb2, (byte) 0xe3, (byte) 0x58, (byte) 0x33,
            (byte) 0xec, (byte) 0x16, (byte) 0xcd, (byte) 0x35, (byte) 0x55, (byte) 0x15,
            (byte) 0xaf, (byte) 0x1a, (byte) 0x19, (byte) 0x0f,
    };

    /*
     * Taken from BoringSSL test vectors.
     */
    private static final byte[] AES_128_GCM_TestVector_1_Encrypted = new byte[] {
            (byte) 0x04, (byte) 0x94, (byte) 0x53, (byte) 0xba, (byte) 0xf1, (byte) 0x57,
            (byte) 0x87, (byte) 0x87, (byte) 0xd6, (byte) 0x8e, (byte) 0xd5, (byte) 0x47,
            (byte) 0x87, (byte) 0x26, (byte) 0xc0, (byte) 0xb8, (byte) 0xa6, (byte) 0x36,
            (byte) 0x33, (byte) 0x7a, (byte) 0x0b, (byte) 0x8a, (byte) 0x82, (byte) 0xb8,
            (byte) 0x68, (byte) 0x36, (byte) 0xf9, (byte) 0x1c, (byte) 0xde, (byte) 0x25,
            (byte) 0xe6, (byte) 0xe4, (byte) 0x4c, (byte) 0x34, (byte) 0x59, (byte) 0x40,
            (byte) 0xe8, (byte) 0x19, (byte) 0xa0, (byte) 0xc5, (byte) 0x05, (byte) 0x75,
            (byte) 0x1e, (byte) 0x60, (byte) 0x3c, (byte) 0xb8, (byte) 0xf8, (byte) 0xc4,
            (byte) 0xfe, (byte) 0x98, (byte) 0x71, (byte) 0x91, (byte) 0x85, (byte) 0x56,
            (byte) 0x27, (byte) 0x94, (byte) 0xa1, (byte) 0x85, (byte) 0xe5, (byte) 0xde,
            (byte) 0xc4, (byte) 0x15, (byte) 0xc8, (byte) 0x1f, (byte) 0x2f, (byte) 0x16,
            (byte) 0x2c, (byte) 0xdc, (byte) 0xd6, (byte) 0x50, (byte) 0xdc, (byte) 0xe7,
            (byte) 0x19, (byte) 0x87, (byte) 0x28, (byte) 0xbf, (byte) 0xc1, (byte) 0xb5,
            (byte) 0xf9, (byte) 0x49, (byte) 0xb9, (byte) 0xb5, (byte) 0x37, (byte) 0x41,
            (byte) 0x99, (byte) 0xc6,
    };

    /*
     * Test key generation:
     * openssl rand -hex 16
     * echo '787bdeecf05556eac5d3d865e435f6d9' | sed 's/\(..\)/(byte) 0x\1, /g'
     */
    private static final byte[] AES_192_CTR_NoPadding_TestVector_1_IV = new byte[] {
            (byte) 0x78, (byte) 0x7b, (byte) 0xde, (byte) 0xec, (byte) 0xf0, (byte) 0x55,
            (byte) 0x56, (byte) 0xea, (byte) 0xc5, (byte) 0xd3, (byte) 0xd8, (byte) 0x65,
            (byte) 0xe4, (byte) 0x35, (byte) 0xf6, (byte) 0xd9,

    };

    /*
     * Test vector generation:
     * echo -n 'AES-192 is a silly option' | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] AES_192_CTR_NoPadding_TestVector_1_Plaintext = new byte[] {
            (byte) 0x41, (byte) 0x45, (byte) 0x53, (byte) 0x2D, (byte) 0x31, (byte) 0x39,
            (byte) 0x32, (byte) 0x20, (byte) 0x69, (byte) 0x73, (byte) 0x20, (byte) 0x61,
            (byte) 0x20, (byte) 0x73, (byte) 0x69, (byte) 0x6C, (byte) 0x6C, (byte) 0x79,
            (byte) 0x20, (byte) 0x6F, (byte) 0x70, (byte) 0x74, (byte) 0x69, (byte) 0x6F,
            (byte) 0x6E
    };

    /*
     * Test vector generation:
     * echo -n 'AES-192 is a silly option' | openssl enc -aes-192-ctr -K 5a7a3d7e40b64ed996f7afa15f97fd595e27db6af428e342 -iv 787bdeecf05556eac5d3d865e435f6d9 | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] AES_192_CTR_NoPadding_TestVector_1_Ciphertext = new byte[] {
            (byte) 0xE9, (byte) 0xC6, (byte) 0xA0, (byte) 0x40, (byte) 0xC2, (byte) 0x6A,
            (byte) 0xB5, (byte) 0x20, (byte) 0xFE, (byte) 0x9E, (byte) 0x65, (byte) 0xB7,
            (byte) 0x7C, (byte) 0x5E, (byte) 0xFE, (byte) 0x1F, (byte) 0xF1, (byte) 0x6F,
            (byte) 0x20, (byte) 0xAC, (byte) 0x37, (byte) 0xE9, (byte) 0x75, (byte) 0xE3,
            (byte) 0x52
    };

    /*
     * Test key generation: openssl rand -hex 16 echo
     * 'ceaa31952dfd3d0f5af4b2042ba06094' | sed 's/\(..\)/(byte) 0x\1, /g'
     */
    private static final byte[] AES_256_CBC_PKCS5Padding_TestVector_1_IV = new byte[] {
            (byte) 0xce, (byte) 0xaa, (byte) 0x31, (byte) 0x95, (byte) 0x2d, (byte) 0xfd,
            (byte) 0x3d, (byte) 0x0f, (byte) 0x5a, (byte) 0xf4, (byte) 0xb2, (byte) 0x04,
            (byte) 0x2b, (byte) 0xa0, (byte) 0x60, (byte) 0x94,
    };

    /*
     * Test vector generation:
     * echo -n 'I only regret that I have but one test to write.' | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] AES_256_CBC_PKCS5Padding_TestVector_1_Plaintext = new byte[] {
            (byte) 0x49, (byte) 0x20, (byte) 0x6F, (byte) 0x6E, (byte) 0x6C, (byte) 0x79,
            (byte) 0x20, (byte) 0x72, (byte) 0x65, (byte) 0x67, (byte) 0x72, (byte) 0x65,
            (byte) 0x74, (byte) 0x20, (byte) 0x74, (byte) 0x68, (byte) 0x61, (byte) 0x74,
            (byte) 0x20, (byte) 0x49, (byte) 0x20, (byte) 0x68, (byte) 0x61, (byte) 0x76,
            (byte) 0x65, (byte) 0x20, (byte) 0x62, (byte) 0x75, (byte) 0x74, (byte) 0x20,
            (byte) 0x6F, (byte) 0x6E, (byte) 0x65, (byte) 0x20, (byte) 0x74, (byte) 0x65,
            (byte) 0x73, (byte) 0x74, (byte) 0x20, (byte) 0x74, (byte) 0x6F, (byte) 0x20,
            (byte) 0x77, (byte) 0x72, (byte) 0x69, (byte) 0x74, (byte) 0x65, (byte) 0x2E
    };

    /*
     * Test vector generation:
     * echo -n 'I only regret that I have but one test to write.' | openssl enc -aes-256-cbc -K ec53c6d51d2c4973585fb0b8e51cd2e39915ff07a1837872715d6121bf861935 -iv ceaa31952dfd3d0f5af4b2042ba06094 | openssl enc -aes-256-cbc -K ec53c6d51d2c4973585fb0b8e51cd2e39915ff07a1837872715d6121bf861935 -iv ceaa31952dfd3d0f5af4b2042ba06094 -d -nopad | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] AES_256_CBC_PKCS5Padding_TestVector_1_Plaintext_Padded = new byte[] {
            (byte) 0x49, (byte) 0x20, (byte) 0x6F, (byte) 0x6E, (byte) 0x6C, (byte) 0x79,
            (byte) 0x20, (byte) 0x72, (byte) 0x65, (byte) 0x67, (byte) 0x72, (byte) 0x65,
            (byte) 0x74, (byte) 0x20, (byte) 0x74, (byte) 0x68, (byte) 0x61, (byte) 0x74,
            (byte) 0x20, (byte) 0x49, (byte) 0x20, (byte) 0x68, (byte) 0x61, (byte) 0x76,
            (byte) 0x65, (byte) 0x20, (byte) 0x62, (byte) 0x75, (byte) 0x74, (byte) 0x20,
            (byte) 0x6F, (byte) 0x6E, (byte) 0x65, (byte) 0x20, (byte) 0x74, (byte) 0x65,
            (byte) 0x73, (byte) 0x74, (byte) 0x20, (byte) 0x74, (byte) 0x6F, (byte) 0x20,
            (byte) 0x77, (byte) 0x72, (byte) 0x69, (byte) 0x74, (byte) 0x65, (byte) 0x2E,
            (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10,
            (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10,
            (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10
    };

    /*
     * Test vector generation:
     * echo -n 'I only regret that I have but one test to write.' | openssl enc -aes-256-cbc -K ec53c6d51d2c4973585fb0b8e51cd2e39915ff07a1837872715d6121bf861935 -iv ceaa31952dfd3d0f5af4b2042ba06094 | recode ../x1 | sed 's/0x/(byte) 0x/g'
     */
    private static final byte[] AES_256_CBC_PKCS5Padding_TestVector_1_Ciphertext = new byte[] {
            (byte) 0x90, (byte) 0x65, (byte) 0xDD, (byte) 0xAF, (byte) 0x7A, (byte) 0xCE,
            (byte) 0xAE, (byte) 0xBF, (byte) 0xE8, (byte) 0xF6, (byte) 0x9E, (byte) 0xDB,
            (byte) 0xEA, (byte) 0x65, (byte) 0x28, (byte) 0xC4, (byte) 0x9A, (byte) 0x28,
            (byte) 0xEA, (byte) 0xA3, (byte) 0x95, (byte) 0x2E, (byte) 0xFF, (byte) 0xF1,
            (byte) 0xA0, (byte) 0xCA, (byte) 0xC2, (byte) 0xA4, (byte) 0x65, (byte) 0xCD,
            (byte) 0xBF, (byte) 0xCE, (byte) 0x9E, (byte) 0xF1, (byte) 0x57, (byte) 0xF6,
            (byte) 0x32, (byte) 0x2E, (byte) 0x8F, (byte) 0x93, (byte) 0x2E, (byte) 0xAE,
            (byte) 0x41, (byte) 0x33, (byte) 0x54, (byte) 0xD0, (byte) 0xEF, (byte) 0x8C,
            (byte) 0x52, (byte) 0x14, (byte) 0xAC, (byte) 0x2D, (byte) 0xD5, (byte) 0xA4,
            (byte) 0xF9, (byte) 0x20, (byte) 0x77, (byte) 0x25, (byte) 0x91, (byte) 0x3F,
            (byte) 0xD1, (byte) 0xB9, (byte) 0x00, (byte) 0x3E
    };

    private static class CipherTestParam {
        public final String transformation;

        public final AlgorithmParameterSpec spec;

        public final Key encryptKey;

        public final Key decryptKey;

        public final byte[] aad;

        public final byte[] plaintext;

        public final byte[] ciphertext;

        public final byte[] plaintextPadded;

        public final boolean isStreamCipher;

        public CipherTestParam(String transformation, AlgorithmParameterSpec spec, Key encryptKey,
                Key decryptKey, byte[] aad, byte[] plaintext, byte[] plaintextPadded,
                byte[] ciphertext, boolean isStreamCipher) {
            this.transformation = transformation.toUpperCase(Locale.ROOT);
            this.spec = spec;
            this.encryptKey = encryptKey;
            this.decryptKey = decryptKey;
            this.aad = aad;
            this.plaintext = plaintext;
            this.plaintextPadded = plaintextPadded;
            this.ciphertext = ciphertext;
            this.isStreamCipher = isStreamCipher;
        }

        public CipherTestParam(String transformation, AlgorithmParameterSpec spec, Key key,
                byte[] aad, byte[] plaintext, byte[] plaintextPadded, byte[] ciphertext,
                boolean isStreamCipher) {
            this(transformation, spec, key, key, aad, plaintext, plaintextPadded, ciphertext,
                    isStreamCipher);
        }

        public CipherTestParam(String transformation, AlgorithmParameterSpec spec, Key key,
                byte[] aad, byte[] plaintext, byte[] plaintextPadded, byte[] ciphertext) {
            this(transformation, spec, key, aad, plaintext, plaintextPadded, ciphertext,
                    false /* isStreamCipher */);
        }

        public boolean compatibleWith(String provider) {
            // SunJCE doesn't support PKCS7Padding
            if (provider.equals("SunJCE") && transformation.endsWith("/PKCS7PADDING")) {
                return false;
            }
            if (provider.equals("BC")) {
                return isSupportedByBC(transformation);
            }
            return true;
        }
    }

    private static class OAEPCipherTestParam extends CipherTestParam {
        public OAEPCipherTestParam(String transformation, OAEPParameterSpec spec,
                PublicKey encryptKey, PrivateKey decryptKey, byte[] plaintext, byte[] ciphertext) {
            super(transformation, spec, encryptKey, decryptKey, null, plaintext, plaintext, ciphertext,
                    false);
        }

        @Override
        public boolean compatibleWith(String provider) {
            // OAEP transformations have two digests, the "main" digest and the MGF-1 digest.
            // BC and Conscrypt set the MGF-1 digest to the same as the main digest when it's
            // not specified, whereas Sun's provider sets it to SHA-1.  Thus, the results from
            // the different providers won't match when there isn't an explicit MGF-1 digest set
            // and the main digest isn't SHA-1.  See b/22405492.
            if (provider.equals("SunJCE")
                    && (spec == null)
                    && !transformation.toUpperCase(Locale.US).equals("RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING")) {
                return false;
            }
            return true;
        }
    }

    private static final List<CipherTestParam> DES_CIPHER_TEST_PARAMS = new ArrayList<>();
    static {
        DES_CIPHER_TEST_PARAMS.add(new CipherTestParam(
                "DESede/CBC/PKCS5Padding",
                new IvParameterSpec(DES_IV1),
                DES_112_KEY,
                null,
                DES_Plaintext1,
                DES_Plaintext1_PKCS5_Padded,
                DES_Plaintext1_Encrypted_With_DES_112_KEY_And_DESEDE_CBC_PKCS5PADDING_With_DES_IV1
                ) {
                    @Override
                    public boolean compatibleWith(String provider) {
                        // SunJCE doesn't support extending 112-bit keys to 168-bit keys
                        return !provider.equals("SunJCE");
                    }
                });
        DES_CIPHER_TEST_PARAMS.add(new CipherTestParam(
                "DESede/CBC/PKCS5Padding",
                new IvParameterSpec(DES_IV1),
                DES_168_KEY,
                null,
                DES_Plaintext1,
                DES_Plaintext1_PKCS5_Padded,
                DES_Plaintext1_Encrypted_With_DES_168_KEY_And_DESEDE_CBC_PKCS5PADDING_With_DES_IV1
                ));
    }

    private static final List<CipherTestParam> ARC4_CIPHER_TEST_PARAMS = new ArrayList<>();
    static {
        ARC4_CIPHER_TEST_PARAMS.add(new CipherTestParam(
                "ARC4",
                null,
                ARC4_40BIT_KEY,
                null, // aad
                ARC4_Plaintext1,
                null, // padded
                ARC4_Plaintext1_Encrypted_With_ARC4_40Bit_Key,
                true /*isStreamCipher */
        ));
        ARC4_CIPHER_TEST_PARAMS.add(new CipherTestParam(
                "ARC4",
                null,
                ARC4_128BIT_KEY,
                null, // aad
                ARC4_Plaintext1,
                null, // padded
                ARC4_Plaintext1_Encrypted_With_ARC4_128Bit_Key,
                true /*isStreamCipher */
        ));
    }

    private static final List<CipherTestParam> CIPHER_TEST_PARAMS = new ArrayList<>();
    static {
        CIPHER_TEST_PARAMS.add(new CipherTestParam(
                "AES/ECB/PKCS5Padding",
                null,
                AES_128_KEY,
                null,
                AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext,
                AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext_Padded,
                AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted));
        // PKCS#5 is assumed to be equivalent to PKCS#7 -- same test vectors are thus used for both.
        CIPHER_TEST_PARAMS.add(new CipherTestParam(
                "AES/ECB/PKCS7Padding",
                null,
                AES_128_KEY,
                null,
                AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext,
                AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext_Padded,
                AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted));
        CIPHER_TEST_PARAMS.add(new CipherTestParam(
                "AES/GCM/NOPADDING",
                new GCMParameterSpec(
                        (AES_128_GCM_TestVector_1_Encrypted.length -
                                AES_128_GCM_TestVector_1_Plaintext.length) * 8,
                        AES_128_GCM_TestVector_1_IV),
                AES_128_GCM_TestVector_1_Key,
                AES_128_GCM_TestVector_1_AAD,
                AES_128_GCM_TestVector_1_Plaintext,
                AES_128_GCM_TestVector_1_Plaintext,
                AES_128_GCM_TestVector_1_Encrypted));
        if (IS_UNLIMITED) {
            CIPHER_TEST_PARAMS.add(new CipherTestParam(
                    "AES/CTR/NoPadding",
                    new IvParameterSpec(AES_192_CTR_NoPadding_TestVector_1_IV),
                    AES_192_KEY,
                    null,
                    AES_192_CTR_NoPadding_TestVector_1_Plaintext,
                    AES_192_CTR_NoPadding_TestVector_1_Plaintext,
                    AES_192_CTR_NoPadding_TestVector_1_Ciphertext));
            CIPHER_TEST_PARAMS.add(new CipherTestParam(
                    "AES/CBC/PKCS5Padding",
                    new IvParameterSpec(AES_256_CBC_PKCS5Padding_TestVector_1_IV),
                    AES_256_KEY,
                    null,
                    AES_256_CBC_PKCS5Padding_TestVector_1_Plaintext,
                    AES_256_CBC_PKCS5Padding_TestVector_1_Plaintext_Padded,
                    AES_256_CBC_PKCS5Padding_TestVector_1_Ciphertext));
            CIPHER_TEST_PARAMS.add(new CipherTestParam(
                    "AES/CBC/PKCS7Padding",
                    new IvParameterSpec(AES_256_CBC_PKCS5Padding_TestVector_1_IV),
                    AES_256_KEY,
                    null,
                    AES_256_CBC_PKCS5Padding_TestVector_1_Plaintext,
                    AES_256_CBC_PKCS5Padding_TestVector_1_Plaintext_Padded,
                    AES_256_CBC_PKCS5Padding_TestVector_1_Ciphertext));
        }
    }

    private static final List<CipherTestParam> RSA_OAEP_CIPHER_TEST_PARAMS = new ArrayList<>();
    static {
        addRsaOaepTest("SHA-1", MGF1ParameterSpec.SHA1, RSA_Vector2_OAEP_SHA1_MGF1_SHA1);
        addRsaOaepTest("SHA-256", MGF1ParameterSpec.SHA1, RSA_Vector2_OAEP_SHA256_MGF1_SHA1);
        addRsaOaepTest("SHA-224", MGF1ParameterSpec.SHA224, RSA_Vector2_OAEP_SHA224_MGF1_SHA224);
        addRsaOaepTest("SHA-256", MGF1ParameterSpec.SHA256, RSA_Vector2_OAEP_SHA256_MGF1_SHA256);
        addRsaOaepTest("SHA-384", MGF1ParameterSpec.SHA384, RSA_Vector2_OAEP_SHA384_MGF1_SHA384);
        addRsaOaepTest("SHA-512", MGF1ParameterSpec.SHA512, RSA_Vector2_OAEP_SHA512_MGF1_SHA512);
        addRsaOaepTest("SHA-256", MGF1ParameterSpec.SHA1, RSA_Vector2_OAEP_SHA256_MGF1_SHA1_LABEL,
                new byte[] { 0x01, 0x02, 0x03, (byte) 0xFF, (byte) 0xA0, 0x0A });
        addRsaOaepTest("SHA-512", MGF1ParameterSpec.SHA512, RSA_Vector2_OAEP_SHA512_MGF1_SHA512_LABEL,
                new byte[] { 0x01, 0x02, 0x03, (byte) 0xFF, (byte) 0xA0, 0x0A });
    }

    private static void addRsaOaepTest(String digest, MGF1ParameterSpec mgf1Spec, byte[] vector) {
        addRsaOaepTest(digest, mgf1Spec, vector, null);
    }

    private static void addRsaOaepTest(String digest, MGF1ParameterSpec mgf1Spec, byte[] vector, byte[] label) {
        final PSource pSource;
        if (label == null) {
            pSource = PSource.PSpecified.DEFAULT;
        } else {
            pSource = new PSource.PSpecified(label);
        }

        if (mgf1Spec.getDigestAlgorithm().equals(digest) && label == null) {
            RSA_OAEP_CIPHER_TEST_PARAMS.add(new OAEPCipherTestParam(
                    "RSA/ECB/OAEPWith" + digest + "AndMGF1Padding",
                    null,
                    (PublicKey) getEncryptKey("RSA"),
                    (PrivateKey) getDecryptKey("RSA"),
                    RSA_Vector2_Plaintext,
                    vector));
        }

        RSA_OAEP_CIPHER_TEST_PARAMS.add(new OAEPCipherTestParam(
                "RSA/ECB/OAEPWith" + digest + "AndMGF1Padding",
                new OAEPParameterSpec(digest, "MGF1", mgf1Spec, pSource),
                (PublicKey) getEncryptKey("RSA"),
                (PrivateKey) getDecryptKey("RSA"),
                RSA_Vector2_Plaintext,
                vector));

        RSA_OAEP_CIPHER_TEST_PARAMS.add(new OAEPCipherTestParam(
                "RSA/ECB/OAEPPadding",
                new OAEPParameterSpec(digest, "MGF1", mgf1Spec, pSource),
                (PublicKey) getEncryptKey("RSA"),
                (PrivateKey) getDecryptKey("RSA"),
                RSA_Vector2_Plaintext,
                vector));
    }

    @Test
    public void testCipher_Success() throws Exception {
        for (String provider : AES_PROVIDERS) {
            testCipher_Success(provider);
        }

        testCipher_Success_ForAllSupportingProviders_AtLeastOneProviderRequired(
                DES_CIPHER_TEST_PARAMS);
        testCipher_Success_ForAllSupportingProviders_AtLeastOneProviderRequired(
                ARC4_CIPHER_TEST_PARAMS);
        testCipher_Success_ForAllSupportingProviders_AtLeastOneProviderRequired(
                RSA_OAEP_CIPHER_TEST_PARAMS);
    }

    /**
     * For each test vector in the list, tests that the transformation is supported by at least one
     * provider and that all implementations of the transformation pass the Known Answer Test (KAT)
     * as well as other functional tests.
     */
    private void testCipher_Success_ForAllSupportingProviders_AtLeastOneProviderRequired(
            List<CipherTestParam> testVectors) throws Exception {
        ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(errBuffer);
        for (CipherTestParam testVector : testVectors) {
            ArrayList<Provider> providers = new ArrayList<>();

            Provider[] providerArray = Security.getProviders("Cipher." + testVector.transformation);
            if (providerArray != null) {
                Collections.addAll(providers, providerArray);
            }

            if (testVector.transformation.indexOf('/') > 0) {
                Provider[] baseTransformProviderArray = Security.getProviders("Cipher."
                        + testVector.transformation.substring(
                                  0, testVector.transformation.indexOf('/')));
                if (baseTransformProviderArray != null) {
                    Collections.addAll(providers, baseTransformProviderArray);
                }
            }

            if (providers.isEmpty()) {
                out.append("No providers offer " + testVector.transformation + "\n");
                continue;
            }

            for (Provider provider : providers) {
                // Do not test AndroidKeyStore's Signature. It needs an AndroidKeyStore-specific key.
                // It's OKish not to test AndroidKeyStore's Signature here because it's tested
                // by cts/tests/test/keystore.
                if (provider.getName().startsWith("AndroidKeyStore")) {
                    continue;
                }

                // SunMSCAPI seems to have different opinion on what RSA should do compared to other
                // providers. As such it fails many tests, so we will skip it for now.
                if (provider.getName().equals("SunMSCAPI") && testVector.transformation.startsWith("RSA")) {
                    continue;
                }

                try {
                    checkCipher(testVector, provider.getName());
                } catch (Throwable e) {
                    logTestFailure(out, provider.getName(), testVector, e);
                }
            }
        }
        out.flush();
        if (errBuffer.size() > 0) {
            throw new Exception("Errors encountered:\n\n" + errBuffer + "\n\n");
        }
    }

    private void testCipher_Success(String provider) throws Exception {
        final ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(errBuffer);
        for (CipherTestParam p : CIPHER_TEST_PARAMS) {
            try {
                checkCipher(p, provider);
            } catch (Throwable e) {
                logTestFailure(out, provider, p, e);
            }
        }
        out.flush();
        if (errBuffer.size() > 0) {
            throw new Exception("Errors encountered:\n\n" + errBuffer + "\n\n");
        }
    }

    private void logTestFailure(PrintStream logStream, String provider, CipherTestParam params,
            Throwable e) {
        logStream.append("Error encountered checking " + params.transformation);

        if (params.encryptKey instanceof SecretKey) {
            logStream.append(", keySize=" + (params.encryptKey.getEncoded().length * 8));
        }

        if (params.spec instanceof OAEPParameterSpec) {
            OAEPParameterSpec oaepSpec = (OAEPParameterSpec) params.spec;
            logStream.append(", OAEPSpec{digest=" + oaepSpec.getDigestAlgorithm() + ", mgfAlg="
                    + oaepSpec.getMGFAlgorithm());
            if (oaepSpec.getMGFParameters() instanceof MGF1ParameterSpec) {
                MGF1ParameterSpec mgf1Spec = (MGF1ParameterSpec) oaepSpec.getMGFParameters();
                logStream.append(", mgf1Hash=" + mgf1Spec.getDigestAlgorithm());
            }
            logStream.append(", pSource=");
            PSource pSource = oaepSpec.getPSource();
            logStream.append(pSource.getAlgorithm());
            if (pSource.getAlgorithm().equals("PSpecified")) {
                logStream.append(":{");
                logStream.append(Arrays.toString(((PSource.PSpecified) pSource).getValue()));
                logStream.append('}');
            }
            logStream.append('}');
        }

        logStream.append(" with provider " + provider + "\n");
        e.printStackTrace(logStream);
    }

    private void checkCipher(CipherTestParam p, String provider) throws Exception {
        if (!p.compatibleWith(provider)) {
            return;
        }
        Cipher c = Cipher.getInstance(p.transformation, provider);

        c.init(Cipher.ENCRYPT_MODE, p.encryptKey, p.spec);

        // This doesn't quite work on OAEPPadding unless it's the default case,
        // because its size depends on the message digest algorithms used.
        if (!p.transformation.endsWith("OAEPPADDING")) {
            assertEquals(p.transformation + " getBlockSize() ENCRYPT_MODE",
                    getExpectedBlockSize(p.transformation, Cipher.ENCRYPT_MODE, provider),
                    c.getBlockSize());
        }
        assertTrue(p.transformation + " getOutputSize(0) ENCRYPT_MODE",
                getExpectedOutputSize(p.transformation, Cipher.ENCRYPT_MODE, provider) <= c
                        .getOutputSize(0));

        if (p.aad != null) {
            c.updateAAD(p.aad);
        }
        final byte[] actualCiphertext = c.doFinal(p.plaintext);
        if (!isRandomizedEncryption(p.transformation)) {
            assertEquals(p.transformation + " " + provider, Arrays.toString(p.ciphertext),
                    Arrays.toString(actualCiphertext));
        }

        c = Cipher.getInstance(p.transformation, provider);
        c.init(Cipher.ENCRYPT_MODE, p.encryptKey, p.spec);
        if (!(p instanceof OAEPCipherTestParam) || p.spec != null) {
            assertCorrectAlgorithmParameters(provider, p.transformation, p.spec, c.getParameters());
        }

        byte[] emptyCipherText = c.doFinal();
        assertNotNull(emptyCipherText);

        c.init(Cipher.DECRYPT_MODE, p.decryptKey, p.spec);

        assertEquals(p.transformation + " getBlockSize() DECRYPT_MODE",
                getExpectedBlockSize(p.transformation, Cipher.DECRYPT_MODE, provider),
                c.getBlockSize());

        // This doesn't quite work on OAEPPadding unless it's the default case,
        // because its size depends on the message digest algorithms used.
        if (!p.transformation.endsWith("OAEPPADDING")) {
            assertTrue(p.transformation + " getOutputSize(0) DECRYPT_MODE",
                    getExpectedOutputSize(p.transformation, Cipher.DECRYPT_MODE, provider) <= c
                            .getOutputSize(0));
        }

        if (!isAEAD(p.transformation)) {
            try {
                c.updateAAD(new byte[8]);
                fail("Cipher should not support AAD");
            } catch (UnsupportedOperationException | IllegalStateException expected) {
            }
        }

        try {
            byte[] emptyPlainText = c.doFinal(emptyCipherText);
            assertEquals(Arrays.toString(new byte[0]), Arrays.toString(emptyPlainText));
        } catch (AEADBadTagException maybe) {
            if (!"AndroidOpenSSL".equals(provider) || !isAEAD(p.transformation)) {
                throw maybe;
            }
        } catch (BadPaddingException maybe) {
            // BC's OAEP has a bug where it doesn't support decrypt of a zero-length plaintext
            if (!("BC".equals(provider) && p.transformation.contains("OAEP"))) {
                throw maybe;
            }
        }

        // decrypt an empty ciphertext; not valid for RSA
        if (!p.transformation.contains("OAEP")) {
            if ((!isAEAD(p.transformation)
                    && (StandardNames.IS_RI || provider.equals("AndroidOpenSSL") ||
                            (provider.equals("BC") && p.transformation.contains("/CTR/"))))
                    || p.transformation.equals("ARC4")) {
                assertEquals(Arrays.toString(new byte[0]),
                             Arrays.toString(c.doFinal()));

                c.update(new byte[0]);
                assertEquals(Arrays.toString(new byte[0]),
                             Arrays.toString(c.doFinal()));
            } else if (provider.equals("BC") || isAEAD(p.transformation)) {
                try {
                    c.doFinal();
                    fail(p.transformation + " " + provider);
                } catch (IllegalBlockSizeException maybe) {
                    if (isAEAD(p.transformation)) {
                        throw maybe;
                    }
                } catch (AEADBadTagException maybe) {
                    if (!isAEAD(p.transformation)) {
                        throw maybe;
                    }
                } catch (ProviderException maybe) {
                    boolean isShortBufferException
                            = maybe.getCause() instanceof ShortBufferException;
                    if (!isAEAD(p.transformation)
                            || !isBuggyProvider(provider)
                            || !isShortBufferException) {
                        throw maybe;
                    }
                }
                try {
                    c.update(new byte[0]);
                    c.doFinal();
                    fail(p.transformation + " " + provider);
                } catch (IllegalBlockSizeException maybe) {
                    if (isAEAD(p.transformation)) {
                        throw maybe;
                    }
                } catch (AEADBadTagException maybe) {
                    if (!isAEAD(p.transformation)) {
                        throw maybe;
                    }
                } catch (ProviderException maybe) {
                    boolean isShortBufferException
                            = maybe.getCause() instanceof ShortBufferException;
                    if (!isAEAD(p.transformation)
                            || !isBuggyProvider(provider)
                            || !isShortBufferException) {
                        throw maybe;
                    }
                }
            } else {
                throw new AssertionError("Define your behavior here for " + provider);
            }
        }

        // Cipher might be in unspecified state from failures above.
        c.init(Cipher.DECRYPT_MODE, p.decryptKey, p.spec);

        // .doFinal(input)
        {
            if (p.aad != null) {
                c.updateAAD(p.aad);
            }
            final byte[] actualPlaintext = c.doFinal(p.ciphertext);
            assertEquals(Arrays.toString(p.plaintext), Arrays.toString(actualPlaintext));
        }

        // .doFinal(input, offset, len, output)
        {
            final byte[] largerThanCiphertext = new byte[p.ciphertext.length + 5];
            System.arraycopy(p.ciphertext, 0, largerThanCiphertext, 5, p.ciphertext.length);

            if (p.aad != null) {
                final byte[] largerThanAad = new byte[p.aad.length + 100];
                System.arraycopy(p.aad, 0, largerThanAad, 50, p.aad.length);
                assertTrue(p.aad.length > 1);
                c.updateAAD(largerThanAad, 50, 1);
                c.updateAAD(largerThanAad, 51, p.aad.length - 1);
            }

            final byte[] actualPlaintext = new byte[c.getOutputSize(p.ciphertext.length)];
            assertEquals(p.plaintext.length,
                    c.doFinal(largerThanCiphertext, 5, p.ciphertext.length, actualPlaintext));
            assertEquals(Arrays.toString(p.plaintext),
                    Arrays.toString(Arrays.copyOfRange(actualPlaintext, 0, p.plaintext.length)));
        }

        // .doFinal(input, offset, len, output, offset)
        {
            final byte[] largerThanCiphertext = new byte[p.ciphertext.length + 10];
            System.arraycopy(p.ciphertext, 0, largerThanCiphertext, 5, p.ciphertext.length);

            if (p.aad != null) {
                final byte[] largerThanAad = new byte[p.aad.length + 2];
                System.arraycopy(p.aad, 0, largerThanAad, 2, p.aad.length);
                c.updateAAD(largerThanAad, 2, p.aad.length);
            }

            final byte[] actualPlaintext = new byte[c.getOutputSize(p.ciphertext.length) + 2];
            assertEquals(p.plaintext.length,
                    c.doFinal(largerThanCiphertext, 5, p.ciphertext.length, actualPlaintext, 1));
            assertEquals(Arrays.toString(p.plaintext),
                    Arrays.toString(Arrays.copyOfRange(actualPlaintext, 1, p.plaintext.length + 1)));
        }

        if (!p.isStreamCipher && !p.transformation.endsWith("NOPADDING")
                && !isRandomizedEncryption(p.transformation)) {
            Cipher cNoPad = Cipher.getInstance(
                    getCipherTransformationWithNoPadding(p.transformation), provider);
            cNoPad.init(Cipher.DECRYPT_MODE, p.decryptKey, p.spec);

            if (p.aad != null) {
                c.updateAAD(p.aad);
            }
            final byte[] actualPlaintextPadded = cNoPad.doFinal(p.ciphertext);
            assertEquals(provider + ":" + cNoPad.getAlgorithm(),
                    Arrays.toString(p.plaintextPadded), Arrays.toString(actualPlaintextPadded));
        }

        // Test wrapping a key. Every cipher should be able to wrap.
        {
            // Generate a small SecretKey for AES.
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey sk = kg.generateKey();

            // Wrap it
            c = Cipher.getInstance(p.transformation, provider);
            c.init(Cipher.WRAP_MODE, p.encryptKey, p.spec);
            byte[] cipherText = c.wrap(sk);

            // Unwrap it
            c.init(Cipher.UNWRAP_MODE, p.decryptKey, p.spec);
            Key decryptedKey = c.unwrap(cipherText, sk.getAlgorithm(), Cipher.SECRET_KEY);

            assertEquals(
                    "sk.getAlgorithm()=" + sk.getAlgorithm() + " decryptedKey.getAlgorithm()="
                            + decryptedKey.getAlgorithm() + " encryptKey.getEncoded()="
                            + Arrays.toString(sk.getEncoded()) + " decryptedKey.getEncoded()="
                            + Arrays.toString(decryptedKey.getEncoded()), sk, decryptedKey);
        }
    }

    // SunJCE has known issues between 17 and 21
    private boolean isBuggyProvider(String providerName) {
        return providerName.equals("SunJCE")
                && TestUtils.isJavaVersion(17)
                && !TestUtils.isJavaVersion(21);
    }

    /**
     * Gets the Cipher transformation with the same algorithm and mode as the provided one but
     * which uses no padding.
     */
    private static String getCipherTransformationWithNoPadding(String transformation) {
        // The transformation is assumed to be in the Algorithm/Mode/Padding format.
        int paddingModeDelimiterIndex = transformation.lastIndexOf('/');
        if (paddingModeDelimiterIndex == -1) {
            fail("No padding mode delimiter: " + transformation);
        }
        String paddingMode = transformation.substring(paddingModeDelimiterIndex + 1);
        if (!paddingMode.toLowerCase(Locale.ROOT).endsWith("padding")) {
            fail("No padding mode specified:" + transformation);
        }
        return transformation.substring(0, paddingModeDelimiterIndex) + "/NoPadding";
    }

    @Test
    public void testCipher_updateAAD_BeforeInit_Failure() throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");

        try {
            c.updateAAD((byte[]) null);
            fail("should not be able to call updateAAD before Cipher is initialized");
        } catch (IllegalArgumentException expected) {
        }

        try {
            c.updateAAD((ByteBuffer) null);
            fail("should not be able to call updateAAD before Cipher is initialized");
        } catch (IllegalStateException expected) {
        }

        try {
            c.updateAAD(new byte[8]);
            fail("should not be able to call updateAAD before Cipher is initialized");
        } catch (IllegalStateException expected) {
        }

        try {
            c.updateAAD(null, 0, 8);
            fail("should not be able to call updateAAD before Cipher is initialized");
        } catch (IllegalStateException expected) {
        }

        ByteBuffer bb = ByteBuffer.allocate(8);
        try {
            c.updateAAD(bb);
            fail("should not be able to call updateAAD before Cipher is initialized");
        } catch (IllegalStateException expected) {
        }
    }

    @Test
    public void testCipher_updateAAD_AfterInit_Failure() throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[128 / 8], "AES"));

        try {
            c.updateAAD((byte[]) null);
            fail("should not be able to call updateAAD with null input");
        } catch (IllegalArgumentException expected) {
        }

        try {
            c.updateAAD((ByteBuffer) null);
            fail("should not be able to call updateAAD with null input");
        } catch (IllegalArgumentException expected) {
        }

        try {
            c.updateAAD(null, 0, 8);
            fail("should not be able to call updateAAD with null input");
        } catch (IllegalArgumentException expected) {
        }

        try {
            c.updateAAD(new byte[8], -1, 7);
            fail("should not be able to call updateAAD with invalid offset");
        } catch (IllegalArgumentException expected) {
        }

        try {
            c.updateAAD(new byte[8], 0, -1);
            fail("should not be able to call updateAAD with negative length");
        } catch (IllegalArgumentException expected) {
        }

        try {
            c.updateAAD(new byte[8], 0, 8 + 1);
            fail("should not be able to call updateAAD with too large length");
        } catch (IllegalArgumentException expected) {
        }

        try {
            c.updateAAD(new byte[8]);
            fail("should not be able to call updateAAD on non-AEAD cipher");
        } catch (UnsupportedOperationException | IllegalStateException expected) {
        }
    }

    @Test
    public void testCipher_ShortBlock_Failure() throws Exception {
        for (String provider : AES_PROVIDERS) {
            testCipher_ShortBlock_Failure(provider);
        }
    }

    private void testCipher_ShortBlock_Failure(String provider) throws Exception {
        final ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(errBuffer);
        for (CipherTestParam p : CIPHER_TEST_PARAMS) {
            if (!p.compatibleWith(provider)) {
                continue;
            }
            try {
                checkCipher_ShortBlock_Failure(p, provider);
            } catch (Exception e) {
                logTestFailure(out, provider, p, e);
            }
        }
        out.flush();
        if (errBuffer.size() > 0) {
            throw new Exception("Errors encountered:\n\n" + errBuffer + "\n\n");
        }
    }

    @Test
    public void testCipher_DoFinal_wrapMode_Failure() throws Exception {
        checkCipher_DoFinal_invalidMode_Failure(Cipher.WRAP_MODE);
    }

    @Test
    public void testCipher_DoFinal_unwrapMode_Failure() throws Exception {
        checkCipher_DoFinal_invalidMode_Failure(Cipher.UNWRAP_MODE);
    }

    /**
     * Helper for testing that Cipher.doFinal() throws IllegalStateException when
     * initialized in modes other than DECRYPT or ENCRYPT.
     */
    private static void checkCipher_DoFinal_invalidMode_Failure(int opmode) throws Exception {
        String msg = String.format(Locale.US,
                "doFinal() should throw IllegalStateException [mode=%d]", opmode);
        int bs = createAesCipher(opmode).getBlockSize();
        assertEquals(16, bs); // check test is set up correctly
        try {
            createAesCipher(opmode).doFinal();
            fail(msg);
        } catch (IllegalStateException expected) {
        }

        try {
            createAesCipher(opmode).doFinal(new byte[0]);
            fail(msg);
        } catch (IllegalStateException expected) {
        }

        try {
            createAesCipher(opmode).doFinal(new byte[2 * bs], 0, bs);
            fail(msg);
        } catch (IllegalStateException expected) {
        }

        try {
            createAesCipher(opmode).doFinal(new byte[2 * bs], 0, bs, new byte[2 * bs], 0);
            fail(msg);
        } catch (IllegalStateException expected) {
        }
    }

    @Test
    public void testCipher_Update_wrapMode_Failure() throws Exception {
        checkCipher_Update_invalidMode_Failure(Cipher.WRAP_MODE);
    }

    @Test
    public void testCipher_Update_unwrapMode_Failure() throws Exception {
        checkCipher_Update_invalidMode_Failure(Cipher.UNWRAP_MODE);
    }

    /**
     * Helper for testing that Cipher.update() throws IllegalStateException when
     * initialized in modes other than DECRYPT or ENCRYPT.
     */
    private static void checkCipher_Update_invalidMode_Failure(final int opmode) throws Exception {
        String msg = "update() should throw IllegalStateException [mode=" + opmode + "]";
        final int bs = createAesCipher(opmode).getBlockSize();
        assertEquals(16, bs); // check test is set up correctly
        assertIllegalStateException(msg, () -> createAesCipher(opmode).update(new byte[0]));
        assertIllegalStateException(msg, () -> createAesCipher(opmode).update(new byte[2 * bs]));
        assertIllegalStateException(msg, () -> createAesCipher(opmode).update(
                new byte[2 * bs] /* input */, bs /* inputOffset */, 0 /* inputLen */));
        try {
            createAesCipher(opmode).update(new byte[2*bs] /* input */, 0 /* inputOffset */,
                    2 * bs /* inputLen */, new byte[2 * bs] /* output */, 0 /* outputOffset */);
            fail(msg);
        } catch (IllegalStateException expected) {
        }
    }

    @Test
    public void testCipher_Update_WithZeroLengthInput_ReturnsNull() throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, AES_128_KEY);
        assertNull(c.update(new byte[0]));
        assertNull(c.update(new byte[c.getBlockSize() * 2], 0, 0));

        // Try with non-zero offset just in case the implementation mixes up offset and inputLen
        assertNull(c.update(new byte[c.getBlockSize() * 2], 16, 0));
    }

    @Test
    public void testCipher_Wrap_decryptMode_Failure() throws Exception {
        checkCipher_Wrap_invalidMode_Failure(Cipher.DECRYPT_MODE);
    }

    @Test
    public void testCipher_Wrap_encryptMode_Failure() throws Exception {
        checkCipher_Wrap_invalidMode_Failure(Cipher.ENCRYPT_MODE);
    }

    @Test
    public void testCipher_Wrap_unwrapMode_Failure() throws Exception {
        checkCipher_Wrap_invalidMode_Failure(Cipher.UNWRAP_MODE);
    }

    /**
     * Helper for testing that Cipher.wrap() throws IllegalStateException when
     * initialized in modes other than WRAP.
     */
    private static void checkCipher_Wrap_invalidMode_Failure(int opmode) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey key = kg.generateKey();
        Cipher cipher = createAesCipher(opmode);
        try {
            cipher.wrap(key);
            fail("wrap() should throw IllegalStateException [mode=" + opmode + "]");
        } catch (IllegalStateException expected) {
        }
    }

    @Test
    public void testCipher_Unwrap_decryptMode_Failure() throws Exception {
        checkCipher_Unwrap_invalidMode_Failure(Cipher.DECRYPT_MODE);
    }

    @Test
    public void testCipher_Unwrap_encryptMode_Failure() throws Exception {
        checkCipher_Unwrap_invalidMode_Failure(Cipher.ENCRYPT_MODE);
    }

    @Test
    public void testCipher_Unwrap_wrapMode_Failure() throws Exception {
        checkCipher_Unwrap_invalidMode_Failure(Cipher.WRAP_MODE);
    }

    /**
     * Helper for testing that Cipher.unwrap() throws IllegalStateException when
     * initialized in modes other than UNWRAP.
     */
    private static void checkCipher_Unwrap_invalidMode_Failure(int opmode) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey key = kg.generateKey();
        Cipher cipher = createAesCipher(opmode);
        byte[] wrappedKey = createAesCipher(Cipher.WRAP_MODE).wrap(key);
        try {
            cipher.unwrap(wrappedKey, key.getAlgorithm(), Cipher.PRIVATE_KEY);
            fail("unwrap() should throw IllegalStateException [mode=" + opmode + "]");
        } catch (IllegalStateException expected) {
        }
    }

    private void checkCipher_ShortBlock_Failure(CipherTestParam p, String provider) throws Exception {
        // Do not try to test ciphers with no padding already.
        String noPaddingTransform = getCipherTransformationWithNoPadding(p.transformation);
        if (p.transformation.equals(noPaddingTransform)) {
            return;
        }

        Cipher c = Cipher.getInstance(
                getCipherTransformationWithNoPadding(p.transformation), provider);
        if (c.getBlockSize() == 0) {
            return;
        }

        if (!p.transformation.endsWith("NOPADDING")) {
            c.init(Cipher.ENCRYPT_MODE, p.encryptKey);
            try {
                c.doFinal(new byte[] { 0x01, 0x02, 0x03 });
                fail("Should throw IllegalBlockSizeException on wrong-sized block; transform="
                        + p.transformation + " provider=" + provider);
            } catch (IllegalBlockSizeException expected) {
            }
        }
    }

    @Test
    public void testAES_ECB_PKCS5Padding_ShortBuffer_Failure() throws Exception {
        for (String provider : AES_PROVIDERS) {
            testAES_ECB_PKCS5Padding_ShortBuffer_Failure(provider);
        }
    }

    private void testAES_ECB_PKCS5Padding_ShortBuffer_Failure(String provider) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
        c.init(Cipher.ENCRYPT_MODE, AES_128_KEY);

        final byte[] fragmentOutput = c.update(AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext);
        if (fragmentOutput != null) {
            assertEquals(0, fragmentOutput.length);
        }

        // Provide null buffer.
        {
            try {
                c.doFinal(null, 0);
                fail("Should throw NullPointerException on null output buffer");
            } catch (NullPointerException | IllegalArgumentException expected) {
            }
        }

        // Provide short buffer.
        {
            final byte[] output = new byte[c.getBlockSize() - 1];
            try {
                c.doFinal(output, 0);
                fail("Should throw ShortBufferException on short output buffer");
            } catch (ShortBufferException expected) {
            }
        }

        // Start 1 byte into output buffer.
        {
            final byte[] output = new byte[c.getBlockSize()];
            try {
                c.doFinal(output, 1);
                fail("Should throw ShortBufferException on short output buffer");
            } catch (ShortBufferException expected) {
            }
        }

        // Should keep data for real output buffer
        {
            final byte[] output = new byte[c.getBlockSize()];
            assertEquals(AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted.length, c.doFinal(output, 0));
            assertArrayEquals(AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted, output);
        }
    }

    @Test
    public void testAES_ECB_NoPadding_IncrementalUpdate_Success() throws Exception {
        for (String provider : AES_PROVIDERS) {
            testAES_ECB_NoPadding_IncrementalUpdate_Success(provider);
        }
    }

    private void testAES_ECB_NoPadding_IncrementalUpdate_Success(String provider) throws Exception {
        String algorithm = "AES/ECB/NoPadding";
        if (!isSupported(algorithm, provider)) {
            return;
        }
        Cipher c = Cipher.getInstance(algorithm, provider);
        assertEquals(provider, c.getProvider().getName());
        c.init(Cipher.ENCRYPT_MODE, AES_128_KEY);

        for (int i = 0; i < AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext_Padded.length - 1; i++) {
            final byte[] outputFragment = c.update(AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext_Padded, i, 1);
            if (outputFragment != null) {
                assertEquals(0, outputFragment.length);
            }
        }

        final byte[] output = c.doFinal(AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext_Padded,
                AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext_Padded.length - 1, 1);
        assertNotNull(provider, output);
        assertEquals(provider, AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext_Padded.length,
                output.length);

        assertArrayEquals(provider, AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted, output);
    }

    private static final byte[] AES_IV_ZEROES = new byte[] {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    };

    @Test
    public void testAES_ECB_NoPadding_IvParameters_Failure() throws Exception {
        for (String provider : AES_PROVIDERS) {
            testAES_ECB_NoPadding_IvParameters_Failure(provider);
        }
    }

    private void testAES_ECB_NoPadding_IvParameters_Failure(String provider) throws Exception {
        String algorithm = "AES/ECB/NoPadding";
        if (!isSupported(algorithm, provider)) {
            return;
        }
        Cipher c = Cipher.getInstance(algorithm, provider);

        AlgorithmParameterSpec spec = new IvParameterSpec(AES_IV_ZEROES);
        try {
            c.init(Cipher.ENCRYPT_MODE, AES_128_KEY, spec);
            fail("Should not accept an IV in ECB mode; provider=" + provider);
        } catch (InvalidAlgorithmParameterException expected) {
        }
    }

    @Test
    public void testRC4_MultipleKeySizes() throws Exception {
        final int SMALLEST_KEY_SIZE = 40;
        final int LARGEST_KEY_SIZE = 1024;

        /* Make an array of keys for our tests */
        SecretKey[] keys = new SecretKey[LARGEST_KEY_SIZE - SMALLEST_KEY_SIZE];
        {
            KeyGenerator kg = KeyGenerator.getInstance("ARC4");
            for (int keysize = SMALLEST_KEY_SIZE; keysize < LARGEST_KEY_SIZE; keysize++) {
                final int index = keysize - SMALLEST_KEY_SIZE;
                kg.init(keysize);
                keys[index] = kg.generateKey();
            }
        }

        /*
         * Use this to compare the output of the first provider against
         * subsequent providers.
         */
        String[] expected = new String[LARGEST_KEY_SIZE - SMALLEST_KEY_SIZE];

        /* Find all providers that provide ARC4. We must have at least one! */
        Map<String, String> filter = new HashMap<>();
        filter.put("Cipher.ARC4", "");
        Provider[] providers = Security.getProviders(filter);
        assertTrue("There must be security providers of Cipher.ARC4", providers.length > 0);

        /* Keep track of this for later error messages */
        String firstProvider = providers[0].getName();

        for (Provider p : providers) {
            Cipher c = Cipher.getInstance("ARC4", p);

            for (int keysize = SMALLEST_KEY_SIZE; keysize < LARGEST_KEY_SIZE; keysize++) {
                final int index = keysize - SMALLEST_KEY_SIZE;
                final SecretKey sk = keys[index];

                /*
                 * Test that encryption works. Donig this in a loop also has the
                 * benefit of testing that re-initialization works for this
                 * cipher.
                 */
                c.init(Cipher.ENCRYPT_MODE, sk);
                byte[] cipherText = c.doFinal(ORIGINAL_PLAIN_TEXT);
                assertNotNull(cipherText);

                /*
                 * Compare providers against eachother to make sure they're all
                 * in agreement. This helps when you add a brand new provider.
                 */
                if (expected[index] == null) {
                    expected[index] = Arrays.toString(cipherText);
                } else {
                    assertEquals(firstProvider + " should output the same as " + p.getName()
                            + " for key size " + keysize, expected[index],
                            Arrays.toString(cipherText));
                }

                c.init(Cipher.DECRYPT_MODE, sk);
                byte[] actualPlaintext = c.doFinal(cipherText);
                assertEquals("Key size: " + keysize, Arrays.toString(ORIGINAL_PLAIN_TEXT),
                        Arrays.toString(actualPlaintext));
            }
        }
    }

    @Test
    public void testAES_keyConstrained() throws Exception {
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            if (isBuggyProvider(p.getName())) {
                continue;
            }
            for (Provider.Service s : p.getServices()) {
                if (s.getType().equals("Cipher")) {
                    if (s.getAlgorithm().startsWith("AES_128/")) {
                        Cipher c = Cipher.getInstance(s.getAlgorithm(), p);
                        assertTrue(s.getAlgorithm(), checkAES_keyConstraint(c, 128));
                        assertFalse(s.getAlgorithm(), checkAES_keyConstraint(c, 192));
                        assertFalse(s.getAlgorithm(), checkAES_keyConstraint(c, 256));
                    } else if (s.getAlgorithm().startsWith("AES_256/")) {
                        Cipher c = Cipher.getInstance(s.getAlgorithm(), p);
                        assertFalse(s.getAlgorithm(), checkAES_keyConstraint(c, 128));
                        assertFalse(s.getAlgorithm(), checkAES_keyConstraint(c, 192));
                        assertTrue(s.getAlgorithm(), checkAES_keyConstraint(c, 256));
                    }
                }
            }
        }
    }

    private boolean checkAES_keyConstraint(Cipher c, int keySize) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(getBaseAlgorithm(c.getAlgorithm()));
        kg.init(keySize);
        SecretKey key = kg.generateKey();
        try {
            c.init(Cipher.ENCRYPT_MODE, key);
            return true;
        } catch (InvalidKeyException e) {
            return false;
        }
    }

    /*
     * When in decrypt mode and using padding, the buffer shouldn't necessarily have room for an
     * extra block when using padding.
     * http://b/19186852
     */
    @Test
    public void testDecryptBufferMultipleBlockSize_mustNotThrowException() throws Exception {
        String testString = "Hello, World!";
        byte[] testKey = "0123456789012345".getBytes(StandardCharsets.US_ASCII);
        String testedCipher = "AES/ECB/PKCS7Padding";

        Cipher encCipher = Cipher.getInstance(testedCipher);
        encCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(testKey, "AES"));
        byte[] plainBuffer = testString.getBytes(StandardCharsets.US_ASCII);
        byte[] encryptedBuffer = new byte[16];
        int encryptedLength = encCipher.doFinal(
                plainBuffer, 0, plainBuffer.length, encryptedBuffer);
        assertEquals(16, encryptedLength);

        Cipher cipher = Cipher.getInstance(testedCipher);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(testKey, "AES"));
        // Must not throw exception.
        int unencryptedBytes = cipher.doFinal(
                encryptedBuffer, 0, encryptedBuffer.length, encryptedBuffer);
        assertEquals(testString,
                new String(encryptedBuffer, 0, unencryptedBytes, StandardCharsets.US_ASCII));
    }

    /*
     * When using padding in decrypt mode, ensure that empty buffers decode to empty strings
     * (no padding needed for the empty buffer).
     * http://b/19186852
     */
    @Test
    public void testDecryptBufferZeroSize_mustDecodeToEmptyString() throws Exception {
        String[] androidOpenSSLCiphers = { "AES/CBC/PKCS5PADDING", "AES/CBC/PKCS7PADDING",
                "AES/ECB/PKCS5PADDING", "AES/ECB/PKCS7PADDING", "DESEDE/CBC/PKCS5PADDING",
                "DESEDE/CBC/PKCS7PADDING" };
        for (String c : androidOpenSSLCiphers) {
            Cipher cipher = Cipher.getInstance(c);
            assertTrue(Conscrypt.isConscrypt(cipher.getProvider()));
            if (c.contains("/CBC/")) {
                cipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec("0123456789012345".getBytes(StandardCharsets.US_ASCII),
                                c.startsWith("AES/") ? "AES" : "DESEDE"),
                        new IvParameterSpec(
                                ("01234567" + (c.startsWith("AES/") ? "89012345" : ""))
                                        .getBytes(StandardCharsets.US_ASCII)));
            } else {
                cipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec("0123456789012345".getBytes(StandardCharsets.US_ASCII),
                                c.startsWith("AES/") ? "AES" : "DESEDE"));
            }

            byte[] buffer = new byte[0];
            int bytesProduced = cipher.doFinal(buffer, 0, buffer.length, buffer);
            assertEquals("", new String(buffer, 0, bytesProduced, StandardCharsets.US_ASCII));
        }
    }

    /*
     * Check that RSA with OAEPPadding is supported.
     * http://b/22208820
     */
    @Test
    public void test_RSA_OAEPPadding() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024, SecureRandom.getInstance("SHA1PRNG"));
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keyGen.generateKeyPair().getPublic());
        cipher.doFinal(new byte[] {1,2,3,4});
    }

    /*
     * Check that initializing with a GCM AlgorithmParameters produces the same result
     * as initializing with a GCMParameterSpec.
     */
    @Test
    public void test_AESGCMNoPadding_init_algParams() throws Exception {
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(96, new byte[12]);
        AlgorithmParameters params = AlgorithmParameters.getInstance("GCM");
        params.init(spec);
        Cipher c1 = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher c2 = Cipher.getInstance("AES/GCM/NoPadding");

        c1.init(Cipher.ENCRYPT_MODE, key, spec);
        c2.init(Cipher.ENCRYPT_MODE, key, params);
        // Cipher can adjust the provider based on the reponses to the init call, make sure
        // we got the same provider for both
        assertEquals(c1.getProvider(), c2.getProvider());
        c1.updateAAD(new byte[] {
                0x01, 0x02, 0x03, 0x04, 0x05,
        });
        c2.updateAAD(new byte[] {
                0x01, 0x02, 0x03, 0x04, 0x05,
        });

        assertEquals(Arrays.toString(c1.doFinal()), Arrays.toString(c2.doFinal()));
    }

    /*
     * http://b/27224566
     * http://b/27994930
     * Check that a PBKDF2WITHHMACSHA1 secret key factory works well with a
     * PBEWITHSHAAND128BITAES-CBC-BC cipher. The former is PKCS5 and the latter is PKCS12, and so
     * mixing them is not recommended. However, until 1.52 BouncyCastle was accepting this mixture,
     * assuming the IV was a 0 vector. Some apps still use this functionality. This
     * compatibility is likely to be removed in later versions of Android.
     * TODO(27995180): consider whether we keep this compatibility. Consider whether we only allow
     * if an IV is passed in the parameters.
     */
    @Test
    public void test_PBKDF2WITHHMACSHA1_SKFactory_and_PBEAESCBC_Cipher_noIV() throws Exception {
        Assume.assumeNotNull(Security.getProvider("BC"));
        byte[] plaintext = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19 };
        byte[] ciphertext = new byte[] {  92, -65, -128, 16, -102, -115, -44, 52, 16, 124, -34,
                -45, 58, -70, -17, 127, 119, -67, 87, 91, 63, -13, -40, 9, 97, -17, -71, 97, 10,
                -61, -19, -73 };
        SecretKeyFactory skf =
                SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA1");
        PBEKeySpec pbeks = new PBEKeySpec("password".toCharArray(),
                "salt".getBytes(TestUtils.UTF_8),
                100, 128);
        SecretKey secretKey = skf.generateSecret(pbeks);

        Cipher cipher =
                Cipher.getInstance("PBEWITHSHAAND128BITAES-CBC-BC");
        PBEParameterSpec paramSpec = new PBEParameterSpec("salt".getBytes(TestUtils.UTF_8), 100);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        assertEquals(Arrays.toString(ciphertext), Arrays.toString(cipher.doFinal(plaintext)));

        secretKey = skf.generateSecret(pbeks);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        assertEquals(Arrays.toString(plaintext), Arrays.toString(cipher.doFinal(ciphertext)));
    }

    /*
     * http://b/27224566
     * http://b/27994930
     * Check that a PBKDF2WITHHMACSHA1 secret key factory works well with a
     * PBEWITHSHAAND128BITAES-CBC-BC cipher. The former is PKCS5 and the latter is PKCS12, and so
     * mixing them is not recommended. However, until 1.52 BouncyCastle was accepting this mixture,
     * assuming the IV was a 0 vector. Some apps still use this functionality. This
     * compatibility is likely to be removed in later versions of Android.
     * TODO(27995180): consider whether we keep this compatibility. Consider whether we only allow
     * if an IV is passed in the parameters.
     */
    @Test
    public void test_PBKDF2WITHHMACSHA1_SKFactory_and_PBEAESCBC_Cipher_withIV() throws Exception {
        Assume.assumeNotNull(Security.getProvider("BC"));
        byte[] plaintext = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,  12, 13, 14, 15, 16,
                17, 18, 19 };
        byte[] ciphertext = { 68, -87, 71, -6, 32, -77, 124, 3, 35, -26, 96, -16, 100, -17, 52, -32,
                110, 26, -117, 112, -25, -113, -58, -30, 19, -46, -21, 59, -126, -8, -70, -89 };
        byte[] iv = new byte[] { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
        SecretKeyFactory skf =
                SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA1");
        PBEKeySpec pbeks = new PBEKeySpec("password".toCharArray(),
                "salt".getBytes(TestUtils.UTF_8),
                100, 128);
        SecretKey secretKey = skf.generateSecret(pbeks);
        Cipher cipher =
                Cipher.getInstance("PBEWITHSHAAND128BITAES-CBC-BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        assertEquals(Arrays.toString(ciphertext), Arrays.toString(cipher.doFinal(plaintext)));

        secretKey = skf.generateSecret(pbeks);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        assertEquals(Arrays.toString(plaintext), Arrays.toString(cipher.doFinal(ciphertext)));
    }

    private static Cipher createAesCipher(int opmode) {
        try {
            final Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(opmode, AES_128_KEY);
            return c;
        } catch (Exception e) {
            fail("Unexpected Exception: " + e.getMessage());
            return null; // unreachable
        }
    }

    /**
     * Asserts that running the given runnable results in an IllegalStateException
     */
    private static void assertIllegalStateException(String failureMessage, Runnable runnable) {
        try {
            runnable.run();
            fail(failureMessage);
        } catch (IllegalStateException expected) {
            // expected
        }
    }
}
