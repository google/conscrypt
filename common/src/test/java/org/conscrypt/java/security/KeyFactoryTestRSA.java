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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

// android-add: import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;

import org.conscrypt.TestUtils;
// android-add: import org.junit.ClassRule;
import org.junit.Test;
// android-add: import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;

@RunWith(JUnit4.class)
public class KeyFactoryTestRSA extends AbstractKeyFactoryTest<RSAPublicKeySpec, RSAPrivateKeySpec> {
    // android-add: Allow access to deprecated BC algorithms.

    public KeyFactoryTestRSA() {
        super("RSA", RSAPublicKeySpec.class, RSAPrivateKeySpec.class);
    }

    private static Provider getConscryptProvider() {
        Provider p = Security.getProvider(StandardNames.JSSE_PROVIDER_NAME);
        if (p == null) {
            p = Security.getProvider("Conscrypt");
        }
        return (p != null) ? p : TestUtils.getConscryptProvider();
    }

    @Override
    protected void check(KeyPair keyPair) throws Exception {
        new CipherAsymmetricCryptHelper("RSA").test(keyPair);
    }

    @Test
    public void getEncodedFailsWhenCrtValuesMissing() throws Exception {
        PrivateKey privateKey = getPrivateKey();
        try {
            // Key has only modulus and private exponent so can't be encoded as PKCS#8
            privateKey.getEncoded();
            fail();
        } catch (RuntimeException e) {
            // Expected
        }
    }

    @Test
    public void testExtraBufferSpace_Public() throws Exception {
        PublicKey publicKey = DefaultKeys.getPublicKey("RSA");
        byte[] encoded = publicKey.getEncoded();
        byte[] longBuffer = new byte[encoded.length + 147];
        System.arraycopy(encoded, 0, longBuffer, 0, encoded.length);
        KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(longBuffer));
    }

    @Test
    public void testInvalidKeySpec() throws Exception {
        Provider p = getConscryptProvider();
        final KeyFactory factory = KeyFactory.getInstance("RSA", p);

        try {
            factory.getKeySpec(new TestPrivateKey(DefaultKeys.getPrivateKey("RSA"), "Invalid"),
                               RSAPrivateKeySpec.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            factory.getKeySpec(new TestPrivateKey(DefaultKeys.getPrivateKey("RSA"), "Invalid"),
                               RSAPrivateCrtKeySpec.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            factory.getKeySpec(new TestPublicKey(DefaultKeys.getPublicKey("RSA"), "Invalid"),
                               RSAPublicKeySpec.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }
    }

    @Test
    public void javaSerialization() throws Exception {
        PrivateKey privatekey = getPrivateKey();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bos);
        out.writeObject(privatekey);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        ObjectInputStream in = new ObjectInputStream(bis);
        PrivateKey copy = (PrivateKey) in.readObject();

        assertEquals(privatekey, copy);
    }

    /**
     * ANDROID COMPATIBILITY GATE (b/473446952, b/493922460): BoringSSL enforces the minimum RSA
     * modulus size ({@code OPENSSL_RSA_MIN_MODULUS_BITS = 512}) at compile time in C++
     * ({@code rsa_check_public_key}), while {@code ChainStrengthAnalyzer} separately enforces a
     * 1024-bit minimum on X.509 certificate chains validated via {@code TrustManager}. Legacy
     * Android apps still rely on 512-bit RSA keys via {@code KeyFactory}, {@code Signature}, and
     * {@code Cipher}. Do NOT raise this minimum key-size bound or relax/remove this test without
     * an Android compatibility review and an associated AppCompat / aconfig flag.
     */
    @Test
    public void rsa512BitKeySupported() throws Exception {
        Provider p = getConscryptProvider();
        KeyFactory factory = KeyFactory.getInstance("RSA", p);

        RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                new X509EncodedKeySpec(decodeBase64(RSA_512_PUBLIC_KEY_B64)));
        assertEquals(512, publicKey.getModulus().bitLength());

        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) factory.generatePrivate(
                new PKCS8EncodedKeySpec(decodeBase64(RSA_512_PRIVATE_KEY_B64)));
        assertEquals(512, privateKey.getModulus().bitLength());

        RSAPublicKeySpec publicKeySpec = factory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        RSAPublicKey publicKeyFromSpec = (RSAPublicKey) factory.generatePublic(publicKeySpec);
        assertEquals(512, publicKeyFromSpec.getModulus().bitLength());

        RSAPrivateCrtKeySpec privateKeySpec =
                factory.getKeySpec(privateKey, RSAPrivateCrtKeySpec.class);
        RSAPrivateCrtKey privateKeyFromSpec =
                (RSAPrivateCrtKey) factory.generatePrivate(privateKeySpec);
        assertEquals(512, privateKeyFromSpec.getModulus().bitLength());

        Signature verifier = Signature.getInstance("SHA256withRSA", p);
        verifier.initVerify(publicKey);
        verifier.update(COMPAT_GATE_MESSAGE);
        assertTrue(verifier.verify(decodeBase64(RSA_512_SHA256_SIG_B64)));

        Signature signer = Signature.getInstance("SHA256withRSA", p);
        signer.initSign(privateKeyFromSpec);
        signer.update(COMPAT_GATE_MESSAGE);
        byte[] runtimeSig = signer.sign();

        verifier.initVerify(publicKeyFromSpec);
        verifier.update(COMPAT_GATE_MESSAGE);
        assertTrue(verifier.verify(runtimeSig));

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", p);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] ciphertext = cipher.doFinal(COMPAT_GATE_MESSAGE);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        assertArrayEquals(COMPAT_GATE_MESSAGE, cipher.doFinal(ciphertext));
    }

    /**
     * ANDROID COMPATIBILITY GATE (b/434718345, b/475843783, b/493922460): BoringSSL enforces the
     * maximum RSA modulus size ({@code OPENSSL_RSA_MAX_MODULUS_BITS = 16384}) at compile time in
     * C++ ({@code rsa_check_public_key}). Android platform components
     * ({@code recoverablekeystore}) and Play App Signing certificates rely on parsing and
     * verifying 16384-bit RSA public keys. Lowering this bound previously broke
     * {@code EVP_parse_public_key} in CTS and production apps. Do NOT lower this maximum
     * key-size bound or relax/remove this test without an Android compatibility review and an
     * associated AppCompat / aconfig flag.
     */
    @Test
    public void rsa16384BitPublicKeySupported() throws Exception {
        Provider p = getConscryptProvider();
        KeyFactory factory = KeyFactory.getInstance("RSA", p);

        RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                new X509EncodedKeySpec(decodeBase64(RSA_16384_PUBLIC_KEY_B64)));
        assertEquals(16384, publicKey.getModulus().bitLength());

        RSAPublicKeySpec publicKeySpec = factory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        RSAPublicKey publicKeyFromSpec = (RSAPublicKey) factory.generatePublic(publicKeySpec);
        assertEquals(16384, publicKeyFromSpec.getModulus().bitLength());

        byte[] precomputedSig = decodeBase64(RSA_16384_SHA256_SIG_B64);
        Signature verifier = Signature.getInstance("SHA256withRSA", p);
        verifier.initVerify(publicKey);
        verifier.update(COMPAT_GATE_MESSAGE);
        assertTrue(verifier.verify(precomputedSig));

        verifier.initVerify(publicKeyFromSpec);
        verifier.update(COMPAT_GATE_MESSAGE);
        assertTrue(verifier.verify(precomputedSig));
    }

    /**
     * ANDROID COMPATIBILITY GATE (b/434718345, b/475843783, b/493922460): Guards 16384-bit RSA
     * private-key parsing and signing separately from {@link #rsa16384BitPublicKeySupported()},
     * as BoringSSL notes that future changes may impose a tighter modulus limit specifically on
     * private-key operations ({@code OPENSSL_RSA_MAX_MODULUS_BITS} in {@code openssl/rsa.h}).
     * Uses a pre-computed 16384-bit CRT key to avoid slow runtime prime generation. Do NOT lower
     * this bound or relax/remove this test without an Android compatibility review and an
     * associated AppCompat / aconfig flag.
     */
    @Test
    public void rsa16384BitPrivateKeySupported() throws Exception {
        Provider p = getConscryptProvider();
        KeyFactory factory = KeyFactory.getInstance("RSA", p);

        RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                new X509EncodedKeySpec(decodeBase64(RSA_16384_PUBLIC_KEY_B64)));
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) factory.generatePrivate(
                new PKCS8EncodedKeySpec(decodeBase64(RSA_16384_PRIVATE_KEY_B64)));
        assertEquals(16384, privateKey.getModulus().bitLength());

        RSAPrivateCrtKeySpec privateKeySpec =
                factory.getKeySpec(privateKey, RSAPrivateCrtKeySpec.class);
        RSAPrivateCrtKey privateKeyFromSpec =
                (RSAPrivateCrtKey) factory.generatePrivate(privateKeySpec);
        assertEquals(16384, privateKeyFromSpec.getModulus().bitLength());

        Signature signer = Signature.getInstance("SHA256withRSA", p);
        signer.initSign(privateKeyFromSpec);
        signer.update(COMPAT_GATE_MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA", p);
        verifier.initVerify(publicKey);
        verifier.update(COMPAT_GATE_MESSAGE);
        assertTrue(verifier.verify(signature));
    }

    private static byte[] decodeBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    private static final byte[] COMPAT_GATE_MESSAGE =
            "conscrypt-rsa-compat-gate".getBytes(StandardCharsets.UTF_8);

    // Pre-computed 512-bit and 16384-bit RSA test vectors (X.509 SPKI public keys, PKCS#8 CRT
    // private keys, and SHA256withRSA signatures over COMPAT_GATE_MESSAGE).
    private static final String RSA_512_PUBLIC_KEY_B64 =
            "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOeH8w1QI3HhVdj4az6CjYjMFjx1FzCh"
            + "9hIXyPHaZf8NMVx17UAxRNKWyFbN0FtZADCNGJn50/MhYJUDQ7cVB0kCAwEAAQ==";

    private static final String RSA_512_PRIVATE_KEY_B64 =
            "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA54fzDVAjceFV2Phr"
            + "PoKNiMwWPHUXMKH2EhfI8dpl/w0xXHXtQDFE0pbIVs3QW1kAMI0YmfnT8yFglQND"
            + "txUHSQIDAQABAkAhJ9XFfUlmIHezt3dcH0P3aApzI+1rOHZNhvxurfDXQh2eETBO"
            + "1V2SiGgcAAiIoK2UCPIGA++D3R4Elv3pjN5RAiEA/ImRhRXHGxCHHZHYO1dg/S4y"
            + "Keja2UwdAeIypVJ3s/UCIQDqtKWMlKR4s721LaWP+nhtzwgks9mSDGP7JLLRYyXF"
            + "hQIgaiEOTNXIJTGe9uhR7S5djkkZv88iGewIzL/Y9O1hbPkCIQC7mtPtT+87r+iG"
            + "xsrdEEds9py6wau6iv7sA0SQDCFoBQIhALRwYAx9dnWzxuzrkF0S93mFbJqFpmq3"
            + "IPGfkEasNW1P";

    private static final String RSA_512_SHA256_SIG_B64 =
            "kwDE3vqKil10xTa4QVEJU1g/5eCJ0Ljqk5W3EPCqgrQ5mOpwXw/j4Ls8P9M0IJcS"
            + "tBaO16NQOyuiPyqyzpG2rA==";

    private static final String RSA_16384_PUBLIC_KEY_B64 =
            "MIIIIjANBgkqhkiG9w0BAQEFAAOCCA8AMIIICgKCCAEAs+na0/7RsGRa8i8oR7Fh"
            + "S79yWLgmif3fwh1e7n357AKv5s/y/c9hwdnIaWjvtMnpJ4wMyGM8w9loHJhA4+As"
            + "katyvjraKXBTAJ3l0z8hUDJAQ7tPkAmvf5HBNaUkEgQtZm589sa99Pd2ypTpVCZN"
            + "PGxcFlJyIupPQssdbTKlBYRaxIZWWNuks+KkOCMoZYIfkr12ZapXpo8EerobWoN7"
            + "hyjMBu2EwFNrB85PUUrQZOR2arYzwQJ5z9Wh4fkzEsGrWPWzZ43a2VhtG2pjseLT"
            + "lM3/74g+pa6PW4M607KuRbKlELcz2Y9IqypA0hKNJquR9joVHDQwRabBAPtu5xKv"
            + "JAMxJ95U/8gCH9ONMMczSwqMGVtA05FMw7aVNLErhYL7cEBXlIRidemg03ecY8jl"
            + "AdjRA4SuhywZhSEYoqidi3AXDNFG9G2hygL4w+uccQjpBRvgBdpsOZ8pcw4WMygd"
            + "CPQcVeCfEuwjoOhSzfAYESBXQfRxPPYY0CzG4PdF2IOVZr8p0eXPgOtZ9TvwnDow"
            + "6bbdl+Nb777O+jz5Uow4yp6ZBJQU8ZzR7ZeaPDuh1PpjDFQ+IlQa3WvJRl1W7sKv"
            + "kor0mX8d/uEbJgjrkMsgxly4yFQ8GigY4NVwxPVKyKSnlGzgMzJPMoxT9VySWYYE"
            + "gOTU4JsJMzY8ROxfLKc0HHmYpumg5cmTdpC42O9ETXfBKgRaL92NH1SILqcQzjYf"
            + "EBRE2X8xyhFnvdvGNiPeB96R8cNcLTeKRtbd4NI1wuE1yLfDzbub8lWQg9wrJekU"
            + "3tKgRUAS+0BWCHUholV6s/kkQwlEZkmoLgRBKkceHoj9uRGqXh6Wb5lN8DWN8L1D"
            + "qlwg845zE2IbUErYIxMciJPiUmFfxUH9xroiW3u+lTeRrEHa6lMk+J8CdlypWeWY"
            + "RTVEOC4Vj+vtTzv3kQekWxJVahvjdUyIYlm2opGG+gG1ppvIanjcX3eawXBMpFsy"
            + "b3Nyye3Dj+leKbfYqIqkFNOfliMhLTDBVPX4xZ1MsOdEeoGzFTyC2ABaOGr5sXW9"
            + "Uw9VSVIt03aXlBrPBrLcn+Rr9a6H8K1Pt0G8f9q22UW5yKn9rES4IzoUhBtbkbT0"
            + "iUqm8CqPYEeal/xOcuSRrTZ4biwgPkU+V1tWJw4wQXONYHz4ljQO8vVnzWiIcjxz"
            + "a+OKfWeo+9Win5k/pyUkHMGjYqtrtlvwtulx2OgbFB23vmlBt/b8ihgmGOdNJuwy"
            + "5p3VzEX1re365bKJmfcS4uUJW4RJ1bJGO+WOGS6TjoqUAonPc7qbKDL4sMpESNzW"
            + "r0CV18KvhQyFu5y1lsh1sNPWs/2LIslnYNLKfMqFK/nTpr8QHZBzxY6cjHgU5OY+"
            + "9xCL5TdVXQNGZxxz/I/zvVqlla4cpUQo2i2xInJ9iwMiVzW7sWFmpgLa8wBRdLQk"
            + "Cumawl3LOSTdtwutMcNzxHaXelAYv7oQOLi6wsD8m97IwuFXATUydgzP4XdJhiBT"
            + "SM0LVfA+3bt+ydnVXA9JkhJNo776SV3SPMtDBJtv73SQOivo5v7noqyV2wwTEnnZ"
            + "68GhsfLJYcNT7QOByzoZwr3wRxfO6H8HEwquRx+jpi16FkELhQYxcei0mgumVwGw"
            + "0fa45Llw+1K9sNVg62ktjuW2ZIOt3j6IuVvUvrHSXZhTKDQuua8LLW4pOo4q8RSd"
            + "dqwo8X+oWy2/aqbh+mVeZS+rObSN2vn4Z4SN0wSp97+1oln/bfFdNs2MwvSrqrsS"
            + "jb8irGn6Rjmudazjg1lPspSlRpqh3yQkgoQp1xNSI/1d1NpyvuVsZ+oQOMnTbIsv"
            + "sS/HfabRqAu6dI9VKHhdbSOcNehy550I/+RfP8sr5/5UTJzvBxik459GQEzRILJM"
            + "UclTUHZjUPD7gQ1EByIlPe+sW476kfUkh5ikq/iBB4gB4bO7Cl5j4SDfg1L+et+f"
            + "ye+nhbVow/nfKWDTD5s2NGkfGJzhcbu1zeA2qEIG708oCU+tnJcCFcAT2Lwv99ea"
            + "dMwXX6GzAD+pPbOwZQzuoStUarLnX+jzyUY71y8Zj2VnoDU/Fb8H+hr6mBuxo3wg"
            + "PAnSwJNi2RIVXLJNZKYr7kU08cz6ICzufLc1GzqWRNQqBowDapc5y4RYvfRlog6o"
            + "X5q6cq842Fy/p/vg9kHK8erEphxbw5khZzBdkhSsXBlIXgT8SLmg/AcjZDkXW7pX"
            + "1a4hZwRcr/vn43pa9yV10xwh9aGSyji474TUxmeogqHDVVFT0S3z+UP7k/DKdF7j"
            + "d9g6CbSvmRpXKnlxzg9Rm+vVgk2U8iuCpQSayT5ykgb1ywOr+GnsUrJRutxPqiWm"
            + "3VdQyMHJ0hhDt4B/fc09/EhIq9VFhzwuubFIUol1iwQwDjSVB6LB9HJQ0HcrFnWV"
            + "YD4dQXgWTL2C3md5OUBSSTzg+2YD+BP+7+B4zRyFmZgw1YPMIDRUpV25/elGu0+3"
            + "BEkHr1oM+C5boce9tHLHFT45oVT85U7g6GWJw9n0FYnMMZ69VSHzOLFwNV7K5AcP"
            + "w8RX/pBAkkp95PRrvBR9FlGJUE4bH7ZiKG1Orl5n+ZWdTcwN3ReGGyNB6Ms44O9p"
            + "GQfLDDzOkLzvFiOeQK8FAdcAidwXduxSFHE+8g8Tf8A9SvV5bRqxKsyvp2gHvd/6"
            + "ZKnIKbEgP78Mos6tAu7MdeL8pcjU1OaKKM7Zu8e6Vb0MB/C8bgabLN8dIeJwOOQE"
            + "5RBxd/RUo3GAqjyJ2diODKkCAwEAAQ==";

    private static final String RSA_16384_PRIVATE_KEY_B64 =
            "MIIkQwIBADANBgkqhkiG9w0BAQEFAASCJC0wgiQpAgEAAoIIAQCz6drT/tGwZFry"
            + "LyhHsWFLv3JYuCaJ/d/CHV7uffnsAq/mz/L9z2HB2chpaO+0yeknjAzIYzzD2Wgc"
            + "mEDj4CyRq3K+OtopcFMAneXTPyFQMkBDu0+QCa9/kcE1pSQSBC1mbnz2xr3093bK"
            + "lOlUJk08bFwWUnIi6k9Cyx1tMqUFhFrEhlZY26Sz4qQ4Iyhlgh+SvXZlqlemjwR6"
            + "uhtag3uHKMwG7YTAU2sHzk9RStBk5HZqtjPBAnnP1aHh+TMSwatY9bNnjdrZWG0b"
            + "amOx4tOUzf/viD6lro9bgzrTsq5FsqUQtzPZj0irKkDSEo0mq5H2OhUcNDBFpsEA"
            + "+27nEq8kAzEn3lT/yAIf040wxzNLCowZW0DTkUzDtpU0sSuFgvtwQFeUhGJ16aDT"
            + "d5xjyOUB2NEDhK6HLBmFIRiiqJ2LcBcM0Ub0baHKAvjD65xxCOkFG+AF2mw5nylz"
            + "DhYzKB0I9BxV4J8S7COg6FLN8BgRIFdB9HE89hjQLMbg90XYg5VmvynR5c+A61n1"
            + "O/CcOjDptt2X41vvvs76PPlSjDjKnpkElBTxnNHtl5o8O6HU+mMMVD4iVBrda8lG"
            + "XVbuwq+SivSZfx3+4RsmCOuQyyDGXLjIVDwaKBjg1XDE9UrIpKeUbOAzMk8yjFP1"
            + "XJJZhgSA5NTgmwkzNjxE7F8spzQceZim6aDlyZN2kLjY70RNd8EqBFov3Y0fVIgu"
            + "pxDONh8QFETZfzHKEWe928Y2I94H3pHxw1wtN4pG1t3g0jXC4TXIt8PNu5vyVZCD"
            + "3Csl6RTe0qBFQBL7QFYIdSGiVXqz+SRDCURmSaguBEEqRx4eiP25EapeHpZvmU3w"
            + "NY3wvUOqXCDzjnMTYhtQStgjExyIk+JSYV/FQf3GuiJbe76VN5GsQdrqUyT4nwJ2"
            + "XKlZ5ZhFNUQ4LhWP6+1PO/eRB6RbElVqG+N1TIhiWbaikYb6AbWmm8hqeNxfd5rB"
            + "cEykWzJvc3LJ7cOP6V4pt9ioiqQU05+WIyEtMMFU9fjFnUyw50R6gbMVPILYAFo4"
            + "avmxdb1TD1VJUi3TdpeUGs8Gstyf5Gv1rofwrU+3Qbx/2rbZRbnIqf2sRLgjOhSE"
            + "G1uRtPSJSqbwKo9gR5qX/E5y5JGtNnhuLCA+RT5XW1YnDjBBc41gfPiWNA7y9WfN"
            + "aIhyPHNr44p9Z6j71aKfmT+nJSQcwaNiq2u2W/C26XHY6BsUHbe+aUG39vyKGCYY"
            + "500m7DLmndXMRfWt7frlsomZ9xLi5QlbhEnVskY75Y4ZLpOOipQCic9zupsoMviw"
            + "ykRI3NavQJXXwq+FDIW7nLWWyHWw09az/YsiyWdg0sp8yoUr+dOmvxAdkHPFjpyM"
            + "eBTk5j73EIvlN1VdA0ZnHHP8j/O9WqWVrhylRCjaLbEicn2LAyJXNbuxYWamAtrz"
            + "AFF0tCQK6ZrCXcs5JN23C60xw3PEdpd6UBi/uhA4uLrCwPyb3sjC4VcBNTJ2DM/h"
            + "d0mGIFNIzQtV8D7du37J2dVcD0mSEk2jvvpJXdI8y0MEm2/vdJA6K+jm/ueirJXb"
            + "DBMSednrwaGx8slhw1PtA4HLOhnCvfBHF87ofwcTCq5HH6OmLXoWQQuFBjFx6LSa"
            + "C6ZXAbDR9rjkuXD7Ur2w1WDraS2O5bZkg63ePoi5W9S+sdJdmFMoNC65rwstbik6"
            + "jirxFJ12rCjxf6hbLb9qpuH6ZV5lL6s5tI3a+fhnhI3TBKn3v7WiWf9t8V02zYzC"
            + "9KuquxKNvyKsafpGOa51rOODWU+ylKVGmqHfJCSChCnXE1Ij/V3U2nK+5Wxn6hA4"
            + "ydNsiy+xL8d9ptGoC7p0j1UoeF1tI5w16HLnnQj/5F8/yyvn/lRMnO8HGKTjn0ZA"
            + "TNEgskxRyVNQdmNQ8PuBDUQHIiU976xbjvqR9SSHmKSr+IEHiAHhs7sKXmPhIN+D"
            + "Uv5635/J76eFtWjD+d8pYNMPmzY0aR8YnOFxu7XN4DaoQgbvTygJT62clwIVwBPY"
            + "vC/315p0zBdfobMAP6k9s7BlDO6hK1Rqsudf6PPJRjvXLxmPZWegNT8Vvwf6GvqY"
            + "G7GjfCA8CdLAk2LZEhVcsk1kpivuRTTxzPogLO58tzUbOpZE1CoGjANqlznLhFi9"
            + "9GWiDqhfmrpyrzjYXL+n++D2Qcrx6sSmHFvDmSFnMF2SFKxcGUheBPxIuaD8ByNk"
            + "ORdbulfVriFnBFyv++fjelr3JXXTHCH1oZLKOLjvhNTGZ6iCocNVUVPRLfP5Q/uT"
            + "8Mp0XuN32DoJtK+ZGlcqeXHOD1Gb69WCTZTyK4KlBJrJPnKSBvXLA6v4aexSslG6"
            + "3E+qJabdV1DIwcnSGEO3gH99zT38SEir1UWHPC65sUhSiXWLBDAONJUHosH0clDQ"
            + "dysWdZVgPh1BeBZMvYLeZ3k5QFJJPOD7ZgP4E/7v4HjNHIWZmDDVg8wgNFSlXbn9"
            + "6Ua7T7cESQevWgz4Lluhx720cscVPjmhVPzlTuDoZYnD2fQVicwxnr1VIfM4sXA1"
            + "XsrkBw/DxFf+kECSSn3k9Gu8FH0WUYlQThsftmIobU6uXmf5lZ1NzA3dF4YbI0Ho"
            + "yzjg72kZB8sMPM6QvO8WI55ArwUB1wCJ3Bd27FIUcT7yDxN/wD1K9XltGrEqzK+n"
            + "aAe93/pkqcgpsSA/vwyizq0C7sx14vylyNTU5oooztm7x7pVvQwH8LxuBpss3x0h"
            + "4nA45ATlEHF39FSjcYCqPInZ2I4MqQIDAQABAoIIAAO7kzeP6iplSqEvtCQ9N+T8"
            + "bm6fE3kMT6kDEmqTKfZEcAFFpF5oSRPMQKURg26D8w2Q/yZTeML9LuJdkJjOT0wg"
            + "sja/mURJHb10rcVwhrnXg1iti6FT+0IoT7dTyPE6LYgaPHTsjYc9AyNc2dlN9Y8g"
            + "zPu9AZeAbZP8VIzSlZlWRoGKdIwq1wOsbPapxlvt7ut6eR2Fuc2I2qhdw4wXxtUv"
            + "VhMv3Tjxb9Yvn5rOK2r6LMLIT9IAeJOpT+EUo17q0uCyepmM2C5nXdVJNcoFmnR4"
            + "wtCck1J0G0XkNtWqt6kx9afojksf0jJvf2qA7lDGyn+ccyw+6hcw/1wetsRVHzEe"
            + "FY0ANL9BzjTn+nCCo84VVstaK1QmGip7Dm4BJwNvi/mnYKnLT6MUWzz+zXJqQy85"
            + "xKfQCA3PnLSBidoqqWoeVheFISyYgbOssBwHWxtHjOdAO2A1/6Fl2WaXIRY2Df1N"
            + "2h5c3dSbh+drmEDIa05EOu/MzauBQwn1g948J7KJbzYX8dHkK5P2BPARTyc8WCAF"
            + "yvYID49kZBCpC8RYGrauDEPU6PkwCb5mMxsA0JVO6SoHdo8gWCihm5O53uS4HMK0"
            + "ujJvXilhB2N0DshDszKqYT5/7FUET2IdFLGYSKyiu59ZAcpga2g6gIkl0RuArAfR"
            + "t5fQOxIQFACbN/9umcsKBRdYTYu28YElq4b7jZHMv7DvMQocnurvNAwc4qpgB/D0"
            + "mrNeORFew6WtDMW6NxA34IIllqDardrniugUoiPFOh8DHHZOQ5ZQZnAINRT3/U1u"
            + "xCPrrLAAFyRK7B9vhgGgwfHX0xfB6S1bPBkrBtnOMKoATvhLOHRft+KHGeun4ZmE"
            + "GqwOYNVni/arW23FuSodZRGLV6WeEJofxVz/9/gBJtu3NX6tYThquwBZF9AcPDaH"
            + "8vWIk88XL2/T+mTxV+7Bf3p09tACx1dTCS2UkjpXXirgwR27QVmD/7/3rVrTmrLZ"
            + "QqC2dv/0g0Pomf+VMMrhQSIVu1vo81VWf2X37BTXhTkNdPlviNG2cnHkEbmTZ3+Z"
            + "YPvlTyjykvDNs01S2UBm2tVq7wMYvpHMxxCzcmcpVAknxJa6rkPqjW1F9S1CKCZi"
            + "M40K694IXkhz0+38mJpKiipBSdRA6c+iLKH8hRakQ2Lt9Nb0YGeYU9kBuewiizqA"
            + "9A3DKaxf6pwf79ZvE7GWL3jCmbik26+rQfW2+M1snP1SEk9FXpGtwpW7Zsxh702P"
            + "4DCLWwnT6VGOsUuXC0j7jc3cj+p1rdo3teUHSO2WvCrUvkaK+gWxfZtmiTOUFfOd"
            + "c7VHIsWwL/dDFfBCpHVQvY4zleTY3yvshfQbt43lKVEADTyvykTVCFi+T1eGJR1l"
            + "DhtsAsEB+X42ydjORR2x0OI0MoM0ea+h93DUgvP1CEl7btDVwbm+0LY9GtKoDu1c"
            + "C+87fMPcFq/6BRdDXtUOH+PDNN5cRpUhAhnpLA7EJOY3nxyyGSNChFm0gm4ogyAK"
            + "bWoXse6FFDV667BIH1ZFaBtts4SafoK0gUXPBhiF5VX26p4AjNOvAxrlcE3hthjy"
            + "S9xF5Tj9j2xc64xiZvgXBsQuYwVuaDCYtp2pH9yTmqML/oZjNVpcEVL20xW8EOlq"
            + "214ovuLU7KSB1bBkHUHxBPJm7eKerb9JnGOO+jYpDeyQICZMTJPhVuG/oUCqMCye"
            + "iSkHQTfufG5v7cORDb80DVrNxd2Lfqnxoj9OZg+igC2fb5QnZvupgwnf1+gPC7xl"
            + "gDlbh1rLM5ukir1UxG7dp6vFjDyiGDLas+tM+fK7KvwFY7yaYFtBb+fDrQSdzMsT"
            + "kzsxX9zEpuI6EQAYpUVoYD61giESWF6tjDukPiUAHdR1YrQVptNdnjiW4aEeP16M"
            + "ULq9d1iVxDwihc4z5WsdbiniXUqXNCrhZT/eYnUGnErOa35opkzB6XRq50fwdGDo"
            + "2R2wh7/8sgCAJWzoMXz5TYjgep2rgWtC3dzasxALhkjZRTwna6k4KxpEkn0da9km"
            + "WQ9cP/xjCOf6FxAD3HJ6cING4vQr5ODLi5dsLBhu9YEZ0z6JBHSCbaAJ/4vPwOYM"
            + "LbzI0Fre91B60PmkLKHe5BZA49i4GwJBoaam32qzXk3AzRcXbop2ttYJLxFfOa9Z"
            + "yapP3fv3HIxuWJhQCW+XKdOFkAFwIQoKK37tmQS04DVMn0+HIxD5OsQjfDKwve6i"
            + "LF5saByg2ddicZ9jZxyua+srlyjeJnxSPD9+Qq6Yq70HA8nsxKLH5o+hUfZG2E1j"
            + "5Lz3UcWKExPj43/yqC0H0bCwiinLiuwCuJVfA5/Bm17SEgEaX46Sd7dbilJ+cOSN"
            + "4l/LTbomRem5ddS4Bff0hvP/noxjWNz2LPHRiMVO1hrKUljg904+Szh+M3QjMNJd"
            + "7z0IqT2gbbmWoVxd1ZilH5VTVknMOrgC9VMb4+ozADSE598FUDz4WS0cKyfGF7PV"
            + "Ha3fUwK0IBOLJUbqbQWeKZvVgT4Hf+Ea8VRhkNCRn+6kmHk/t0gJWcWQSdWKA96+"
            + "E0jZwsN3cPDpj13AYLGBu2lTpQFQej6OUdJ01YQIUtBP+p4Ger/hwLJJqDOVsKZM"
            + "e6oo/KcYrqVEkC9GBuCkRotIFTF+3SZW4C1s6Y6VNnYMNttTUsjStVw7ex8He8RF"
            + "xcV4Kaa+3bEWYZgZvB5FLaBLGe8RPqW4Um3fqHG+yOev2BbkvbuOPQBJN6p/D9fl"
            + "0cpY1u1/9FPCalOv5fuJAoIEAQDrF72xzEyy4Hphun9NrEKyfcN5XBJqZMbZDITB"
            + "dLQnFD5Yb/GBMqsCQPnZcrWpoy3ZPAJp/yb6WMMvnBryWyY14knAY/0I9vKCgl6R"
            + "5nEfjrO1fd4Cm7J7eED55WwvRR7pQjL2/ZcnA/ceAOzw3oy5XTLu26kbvjr7GnFS"
            + "f186zpsfj0pB9Uj/pHXG5+gyzgDpwQiOOv3RPaqzfA5SZWIMZJoNhmm1Zakp+XYa"
            + "5eHJCL3kHO4521rxTzMFlmd+3XZvPbbILJNfS59HQjC9/N+ZkpvgSU3plABu4Pdd"
            + "s/Bb/UVxLyeXuv4Zh/toRjH3gFNuV/0L8I1+PQBljgikIjqMPrumHKTEgC7+THjX"
            + "yHkQfKLp9i7F/aUSGUc+tx4Pp+mYGzolU44gbxDEX/FkCir9vtQwy2KqOnZNIrfJ"
            + "zG0XfxN4WEfHvuKKss6qx/SuAJhgHWXDhGmQz8ZMr2amtnyYwcVl7uHD+qsDhZ1f"
            + "79fm2HSKq8zlAdms/ZntPwkF43vvBhqvr+MFyzqRehZ1W17nTXCKK+pnTyi9oFUj"
            + "4M2+lBIgZianAnYa2lHSmIpsY09l6CqksSatR13GyKeqN3mtoOImIQmTw8D17YLk"
            + "TXtLET2MOsQHjZ603FX24eJONcOYUWQ5qthZrC9Jlr5B2SbCV8lfdcEs7LTbIKs4"
            + "kFnHkyF4dgYMNhIWm2dPdacEaaNotCo7F+qbdCFZxPwmvQO0ef96fxedmmrC/v7C"
            + "GoXOSh7+UWWsVwClR70GPzLXz6cQe804j4RoGZD2rEMt+UXXbbmzzKyFPW8buL2A"
            + "uI4uf1iA0SPXsOO48SSYkRGjgDoWS9V+k4Rx9UM2pLuWyWhF/pfu8E+hiQSdwv7C"
            + "GQOY2yuDLLjpMXG82yidd5TYXit+eCMfLesYlsyRr21VSDFddtVnSOhrj1ghgnNE"
            + "H28i2rBl2snMRz+63X9Zh9fQyjQJL7Sk7WzeHRnGudNycHLNxtjYLtcZXQHQt26+"
            + "cl+Zj0ddpy18hqchi7iIro7c0iRRY/xmjzsNzbgY8BgOGvvnetldtV9ci8HclnEz"
            + "L+MCD9fhgwRt8U2OsBgZuaYoAYH5x2+Zq3YVZ4c115TIa+5orhlKlqq4MLmVC+w2"
            + "M+l7DmDCJuSsW3zHOvzXKA04dZbhKPN/o7NH2X1EOqtG714ZM3MGTBzoKgaLIQGA"
            + "Ot7y363KtPMru02pUC1yi4ohJmJBqtllEkDzmb98Auf7AlcZK4tlYOwlIpTPy4e+"
            + "BkIB98db5K4icrlVoQbQ1Q5yjT9PYH0Hcdlow8gPAeoB/sI76IklFhUt8Y3KLrPw"
            + "kbQ0D5aEAbTtKJXuX7gw5LLcG6+0DhYOj9Xs5vqvjhXZpOsLAoIEAQDD6d7u1CDM"
            + "gu/1L5ZN6cdZ8ISzyJf9elvoo9/P2EiiV9uX5p9UuGeP34tJorRiscNh/8elXiJA"
            + "M9IbIEk9yyFTu+GaLzh/bopWNee8kU9zELts5wKWIxGh4FOQyOQUNZjlElu7OjA6"
            + "Icxjf0TRyAIkJqr/w2PK7rfRdCYjJC6lozNqRTaUtwbPpvataIJjIV1LRcrl3IvE"
            + "LXVMHLsV33sNiA9Dj7KJT9YL44u6fVNroz/7zxooGhWfgSBrZg9onUkRa2NkIhyt"
            + "PMJjzUxSqNjvSZn4K4VORTPow3e6GXqNmbyc/ngGT6q/NhoKzwM2j6wCr4YnBEnl"
            + "IFabVtYqowYY2yT6d3j6hvVH+yMT0y3/P24AMJe+LM25wln6XgB3tN9qGXd6lDUd"
            + "sMq1tyCn2rZfZHvd3gl1ZoHMNgdlXfZ8b5xbbMUKWNATZ/JnTXiEUmGhj1I/JH79"
            + "DaRYT2OWOPohUsjwGGG+iKAK2injIBJbDXXiwowPsXqc1L26Hdimxu45+UGFHHoi"
            + "p+3aC4nTUl5O3hsQXdUhg22fjSpOIuRS/3vmtS8bWwVQstQMvyFlyDDTfhyEXqa8"
            + "l3ZreFJVrLDY0msf3TY2pB8mpROdwOXWrf22k42A6XOUU/Bapx3IsACQQev9e9oV"
            + "TEOW4BLL9xM63HYwiustApfBJ9iTKe+YTRZYILrDocwKNbxoQf42mQwwTXmEBuOe"
            + "FC8OdIa6ZHjUWxZlBTFzkZhC+0MoGp91yi0dYOt7mp9HLgSjYq9xA0UlaDWb1I4d"
            + "U7Yvq552oUZm4cuMa49VRDn24FVrx3nAVPUdTzX1TItCP96XXsW+SiSHnYL1yg0S"
            + "fjpTxITz7MqfKBGsYurFWwZBR8kA3iQxZ1UgyUO8ZakMHmjflabx48SYL8yJlkg0"
            + "vQnOe+LgNNUDV1FNCsc1rOp1rRwC2hCjgPX7NR+XHoWKal4UBxNUtV3ZVONGljDw"
            + "xAOsaFrgWT2y31Mfd4OB9VMkk+dA0Lb5qoebRh2FCJ3dbnJOCFPHz+emfaV77pDq"
            + "MeRX/GGhTiCoW7hfF/+UHk2ZOv82fwJel6P3opRso8mGHzGspLViVY6HIEV60mn/"
            + "5o56gYUDZRhbJpAddFtDOA6nJo5rooHGPfQocMKC8OpTn8YMIjL7hdxDJSHkMuIl"
            + "Qwb7ZTaBkXP8BazUXE42f8BOBABI2kLnKs/yYRbmiTcH5vc0fXHiR/zeLZRanzGu"
            + "G+WtaXUepzNtWZGvKO5kPyQSDKsKE06mkUk3E9Zjs4XJYSE2VM0rKkYJ0KjNWZzW"
            + "3+nZynm3j619yQJOOb3HHr6bouzEKe1CV18nzyIN3zH6DH9G78sgDcSstK+QNp5I"
            + "fhcR1eBNWVebAoIEAQCqMKGvGUtdI4z1OuH2BQKz3L+qF7FtPE+HybxBoI7ay5jm"
            + "xQN8mIWcOBWoCZbhm7QRU5Qb0A8TpTaIPOZ1FO9wisUBdmE0IDInsOFtlfnG8rO+"
            + "a8RQ9w4avE+tmRzci5l5G+dxTtwh7ojzO5BMP5B4kLPSn0qpPunL5rSrGHKETBWY"
            + "n08OuNeD2jc5K6G5RdD7aDcdYC9nTtFI5kIn/CUi+6FasTfNji8Mp/+MMWdm9eEi"
            + "Rp9fWyFXGBLDtMJv4TtgBLlR6JM3pbNFDvHiWDI3Jx+ZGvhAZFh77HinaSBUN+IR"
            + "siVjfod9TCgAsPBzUH8VnrUd86M7BEZJPq2axPzFkpSeCJZveqyKhCnnbMXX3aLC"
            + "5Omvg5QAqjQdfstQYiqFZxCM/RQi/sSQpTRHS+UblQ5f1J00xuXlqYCLomZHYENk"
            + "F+S/Ab1W02Mx11eWr++fhSiqhi02HHReB4y0m99PZtfUlz7xdYJgJlZroWIXSBP2"
            + "X7ERCGnhBiZszflmPez2eODQ1u/uvdVEg7HGe8MUh8c0/93NtEy2GmAIfTH1CZSl"
            + "x82rkeiWP/6ECtIK7UoJaC2W1Hg/cS6+PXzDiS2ZOKL/H2OjiU8jujHLvRvImE6K"
            + "OfC31xpRrEC/XX9LRzi2CBYaeUfuguwoxewuF1orzwmFBeY285VqHRhW9olIJYdR"
            + "gX+XT32AyDfeGjoyw5b8sZDw/rtklomeRzCTiron6Tm+IEukWKl5SMh9FF5RnO8b"
            + "BSopvUJGZMy+vPm9qiIzmKxUifE8u2VqbgKkQZUCA/kv5LfwLS1GUFM/4Ftt5drY"
            + "Ro9AElqJBGmN2Vd/mdBzW6rO21RCe1+RK2hyHJRUN58d5vJ+6oZg/00Wjq0/90pk"
            + "x/eFOboxEicw9+TVTjcGc0pZxBAx2Nl3jhwEZSL3mpObFfjMBRW0DJANfQQjo1WY"
            + "Ju935wyH5tnOorzl9bv9+n839nmdwktqxhQBAM7bkVxiBGbLgb1Sr7iIPpxeuo7b"
            + "ia8wOvq7Gj8ZE+VwjuCj21JZnM8PiyH/S7DeZUJ/rTu2zxqeEL7jRjXk7IHWeEm8"
            + "g/Cs9sdCyNBprzBOPekuPebYxHvTuwLzQ4H+JcSOG5tLmA83EG8JK3xxMNuRrjL1"
            + "2toovIJ0aIup5uDLQrVbgx3kBUpAdX5t6lscGyVv8QMQSAGVQPdDuT0w622DPdK+"
            + "sIhp3Eq4i8aa6dGxdewjxd9jf/dtYpxw1lnCKUuMeS2M0sGhkItScvFt63HVot67"
            + "86zsW0k4aD5a6CJxYze16xAYV58gbLtjwer6TsemPw0pv/bNL9WJzI2PVquyFKbO"
            + "Ib4tAfiofLsHCklBdvmXy6rEF/Syb/SDKsU+rllJAoIEAQC8HIBZU8eWdxcOlr28"
            + "W/91RXM16SK/WVCMpWUOff7oGnIYfXF5eIK/64Yjkx2fMk6Hd4BsMWGzwc45C5wn"
            + "wDZk3x702+hku3AK7UFwlxnxQxyjqYCbRlr00p+Kgso0+W2wbhs0P9/0wWUuGBKt"
            + "V11u9s30PNlCDkrjy6Ge1mwP0Q9aN9D7pG3eztNGl/WyV2PsFbyHT2fIW1moVmHw"
            + "05+k04LMfVqRa937lmYhD5sc3ChgkW/tF3axq9vEI8Ah0/xHxJQvnm1ojdGc4JAr"
            + "QkLiKAq19pvOFraMBbudLj+1XOt01wXKEY7CgKEqxbCxH+yqu3yVVBHb9lwSVaPY"
            + "VqZREYKFGFhKPXGgxuvcakZdMrtdZUseaIi0l3+r3byXNE3c400MnugNdSZ+qrKp"
            + "WWEJYUNqOntchauVuD8LvtggjU5Vnq/ninVoXMOtGv7gFvX1mdcAF/vy4LlvrfLS"
            + "WC0b+BBGMTMRLsB1CxtzIOVfFiKeM+0mWGSB1+fAoE3ZfWNauRGHTVuckR/Z4IBb"
            + "L1isY6ka4u31euu0amg3lFslsnh2gnwTySbmYH8pKhBYWYtAV3PsSbHRnaEv+d0c"
            + "tG8uEYSYmOAoQRhEE/cs3v4RTwkw2KbjI8U9pAdCE/qOKyivWwzMXLJ/BrZTVR3X"
            + "SIrnVq4JWCoOEtJBvg++5mJPG52byvlpRJ7VItmgRdVg+T1x18IY2kCOFZVFTO/c"
            + "YwJ97GQpZX4hGKhZkEbgaAe6owEEl34kNchAIViExQnt+pTXISNwV/yI/ksNpLzH"
            + "7Xza5m16jACZf6QkfyymC2fFHA4rMVZ/DRsd5pPFRlOarjg7GyuW84XvvtIkgqqi"
            + "SDgZ7/BgVK5WB1uPLO08bw/TfAOKMpZefEKAB2btYBVnZyrqceL0LR9xvB2BbQTg"
            + "APqTdbDzx6iVyk1p5mjh+B5H0Fjf9xc5FC5nRFDG7DBMgsT1HAQKT8X4OE3Kqnyv"
            + "tCCA8twud6QHEdbeZUGDw6QdP/drSTyo8ygZaKZKdMZ1MhSckUJnKB9vL66wKP5Z"
            + "Utoarc7vR+y4fQxHWBWbbwKIbxQaf7oCQpYKuUMKITCklb//0SXFk+oBs5AU4u4j"
            + "31sukm2ISqQie93d8zCG+weeoPgiKHssHUTyPJR+LAxF5DclJa9QHOd1ndFDa+CV"
            + "MmNqlsxnL6ZNwAaXIlJfoWrh6gK3GTBS9Weop8WvWdAS1MphTuSGyxp5sgGrq3mw"
            + "kBzaH0m6JRQZn2L0DcPhLb60QwZI4zxUiRipzyCDuZMyoimT3Q1n92aYD3HMFBUh"
            + "As0z3ODg2aJ2YfflGuA6ToOo0pnkcIejSC8FiCBhrXeddHrm1atJTphWxPNDxdfU"
            + "jTeHAoIEAANaBJbQNN8T0VneR5vQc8UXOVfiteIFSijyiAXB1302wVcZTqK36ixo"
            + "eXzs/XNbd4mXrN6qMATtycPT9WBXxcoBECcEIPm44XPRqaBMtQdn/TrZwk4dlOPn"
            + "0GpbPV9uldjnz+ZSDu8cQqCW72anrMiSRU7ybmsrcuP+ZJYtPy8kk95F8cawzP2d"
            + "u2seTBJBYQ/BcG+KTX9S/C5Rs6NQ7LkicrEI2DiCnAAK4Bkvid1KLrSSq6I90bHn"
            + "sn7DbYZs23GWe/1zwWtXq/XJNJ4XAiIGrni2rQkYIlmD9iFQh0EjR054Rt+tMHzh"
            + "xokKxpTr7VLoZotGfVwT1MXRKQTvn0JihBynLvqbraOXnAlNiUM54yxiP4f7bxbg"
            + "L5xKNw8TQEvJLJnsf6AeUAy4vJkSmWeNxAB1ZPJPa0mqfr7SKQwCkqUP2Bh4uNpJ"
            + "h2ZqWhX8K0i2lHd/+yLdI4pc07DAhmCX54eYO5RqC7XyWEL3RImF2z/Z66CX2DXg"
            + "e4wbspheYHg30/m5NLmNOyFT6SkCCuSwKO6yffshhutlV4o5qWhDoSonjwUJCxhC"
            + "tqwXRkXh3VQbUoxLXUk7ZjSghIFZGUO36CUTt4dXGo8kRJRimkJs94wHHyeKnXM9"
            + "eYT64aC3zdocwiOsRFzqq+aoKJzhcfunqFYOz/+HrRIZ5IbXKE8e3qXj/pHz9SGI"
            + "W2iMH6a2vSHZnXTXpWFOUvVkOk6Qi/MBXnIENbCLbwzJuyG6YrKKmT2RVX6HCrSy"
            + "ltGMiokRc3V0Zq5x+V0mJ+DJtsnwKPT5TTL2d098c9geChuZ1rzZNoAM1vQyhmNl"
            + "7GzFdhv23WOnfrWcxE0Y83Equ3N70WjyO9mIsY4TuaD415zsWew5OLWKs+Q5oh+U"
            + "/i3wg9vDulPNXyZxH1poHBA6fpTs78RH91P/NhUNL1LaHKkiPc8i3MXIoMFR25Yf"
            + "RdhHrbp+JgsXahfeoGr8zN8xLHSGAhq73ZEtDerWLLqUylH5JmX80ZgjtCQ2nJM/"
            + "CBYcbGJgYbdyUvg9wdu0fbuhDZm6zH36EkDYucZsiVndjIyPgtk0uNgBquT8FG3b"
            + "KLOOJVdn8h1fnbGwdoGJvrY2fgStIkEn++b++hsTAk8e9fist86E+Ac8g6WCF2vC"
            + "uxh45C5AH/RN1CcXiaGn27Y18uYdF3+ovlfVatu5muhYjTgwFta4yLPa9Kh/Crj1"
            + "puI9pBvlyH5MIFuueI+R9vgbYmMgC9wvBCFj1VCWyiRTJMREFZrC7qJ83yLkGhgY"
            + "G59g3gZ/apjLkMV34hmo0R3eVzROVC/GfspxByUmx0pTf3KeignjsBqSauvGboCc"
            + "zxwkKzfRtKPnvdf6dqkEGUpbtXiA9m0=";

    private static final String RSA_16384_SHA256_SIG_B64 =
            "CCEjevVe0dZZhYV8l5owbuq2XzvEZW/hEJy5UblZ3wDuzVNyqgFDxLbfwASLlKOF"
            + "X7Asi+t4jrTzlrFgJ6DuS7UkLswlnPMo27r0cmPdu4tE1dMVDlY6skG517H03SCX"
            + "uHdWB3Q20Lm1XNAN46dQlbJw6mtOiqrjozYTSNZfX0dcS6LTsN6aAtWrZ/j6IoTK"
            + "O4RkNcXqQNfVWR1W5mplZ1qZSoR5+0j3lNHSHBBEAC8J3hF552dYDdsE0u0bsDko"
            + "uaGHWyAvrupLjSx2rhLogmxfGs9SXyK+Zp0LmY4D2FhfY/JCKZVgJdQpRnIloco5"
            + "xmDJvzXMzW9r7wcRJkTSsD7c8ssQK67kFRHLkTHRsiA91QWj1T5LsPuFQ4qSVYeR"
            + "oG6sUeqGf7VG74uS+r9oVJBBalLU4B/VwMh1HvfjaMzr5pIqozgfOPzVBrUbBWdb"
            + "UhRf/+8NDUxlZRINby3J9bVQeVPqknhTVvI0xAxHJsDjUjXyJhexpDmcjuornolI"
            + "/M9+V+9DAZ/ubUJClIZRzwYZl4zxwDSWVzuvzSvQEqcHWgiXJfAuWrHDlLbbKSRZ"
            + "EVXcfANl0IP+pgUlUaHTIjTuaTcX/SODibm/TwpepXdm6wci/yGR0I5ugLKHhhkL"
            + "ktcuIRALkE0EmIZ5FOF+MQn/YntgZNThrMw4tjH0U3F7Z5OVx9eTT9YsegbLcAUu"
            + "+FSdlfvbzmjSAIhF2GYdJidetvqQXMTs2Xq6ZcJ8Sm3AM10vlLFckFAIvmmZs8nQ"
            + "JGv/dGhuZo6nyWINMecOjkVqnDL+vfDbtd8U8I0QaDoLOzw1Umvrg+Hfw8ETBA30"
            + "Cabymfqiac2N7sU5s3+H8RnJbeq6LDOtIdXEocgGEIDMvR4LiGBqi3/u/SKrybWi"
            + "d2/0Y+6OBn1AEBkExupZXjescel6HrhySP3rm8gQhWV3Dsj5UX3DSDlCijwX+c3b"
            + "OjoL+RivLSKxivfcdR73iLjfihvGqG0uhGtX+9ZHfkSNQA0/C1rKVvAw3tVXU4Xt"
            + "8gqJrPrvMdEjqnmftcEqrKzONC7CMyCq4Gj4SE2OLerdf1PQ61dV6C0cIlyV8+Lj"
            + "thWdo8qx0JctfVKiJNlttVnw2dmHP4fsSBTGIprZ6F6veqU3u01MOklArTziqR3V"
            + "hGcO04DSq389QYixFePJgC/zV1vzPS2+fZ/qTbni4EIcNu+UVrBLXwBhI0p83TOu"
            + "7iBboQBHXszOCpKOClEHnttQBdW8fY3zmrMWTeLuK2LVKrMCpVfukkkGZ/P+V0Ze"
            + "6S01DGtN5QZCXhr3U3Z5xm3SedBc1A/jEtPHWVAOibGoUxGYY14smtk8lGYU/biZ"
            + "X/F0lRFMNIgjA6fOgzqI/VeQVsDKYxpOL6rdqEtyq6vHaR3fizqaAapGOnG52nFH"
            + "T58erlafjGb1+0AfuAGKUsF6BYluiRobh2FB8Hvc921kian9eI+IGnqFzwIblsyp"
            + "5L6QsTpZjsm+6sU9hTjODs5Y0Vo1sS2GLS1vixZ2EHX9M9SyR68FDkyWRGTtJfBg"
            + "B4UH7exTJr3E0H2DnR67BUUpWtuuFoL/oQvADaLgfajL9lFNInjKj95TO8uhX5b8"
            + "8EMKjXND7JzHx8rOQH+XJWpzbxzyYpeXvZWcFY+hq6HjqkZb+yALtTspXJxxzVyQ"
            + "HGukUZZsgwSwgwm2tSO0uDTv+5kfQpvXSPfLbwRmFoLdnqssyEPpQXn6tVJreZs4"
            + "BemxPqArYeZD3BLbgjB302vPfVFoaIXLvzAOoitwHsoTPQ4qKNfsAerrWtrWf/Lr"
            + "fzRyycrpo74wpybWemrPhsLrU/x1haLA4K6KbrKHql/PdxAIV69XmyaSfljF9T80"
            + "XMYUU4Z6qlqrqu10jdkn54cTLZxcmD7Z6wTvWZcTXqv469t2OCHrwZaMz1oJTSNq"
            + "wTZEqPTI+M3M/facfjZ0L0o4hrcYmG9RpKAQqHrfD/GQ+cV/yBLGZbI8EdtrD7/Q"
            + "G1WzR7dvTb3tO8PTG9RYVvcPyQ8z6Kd7UOp79MEamICp2OqmqUvmBbqPrs+v8R53"
            + "3/wwC9j73YQoG1nt+ThUBCswtSXYKXNs2zt2xiyHUg0LLW2ZKGeXteI3d5pEGVxy"
            + "NFFBQTzZw3kYXv+sgJ4X0eoWT5CkCWz9mnLfxzOJGJvxhra69HmLwICw96R42qBO"
            + "kKlKkmrKmOfGlXrdrmLUNiB3f0odEP1SDPeqz25kXtccuuB6tfXvAtPXTfDlpL/m"
            + "8WZGtEvWJFBB/4MyG/U5F+meh9RfISYHAxtju/w59UU8wzxIm1xBR+fni9qjXcbt"
            + "WVysHr4ahbE9aO0+jeYEgKHLGYJIPQyBP752Ius1LJNfhEPe3U3FsrV3HrrBQydk"
            + "ghc1p9aALTPdwls8UPFkYx1ipXhWjvRD9wgfgwtC3MOHteHrMvWHJCFYIr8opJg/"
            + "i19qglGEDzAfQEqtMw8WIGwYLvAVFJC6D96qkaIVJ1RCwOog8HZhGXPADM/AphlI"
            + "lFeWnms8Mjjgc5JekTtF9Iarjn+euR2hp4i1LyoQDqD8+N6YSeYXdni+chL1nZF2"
            + "gLYFbp9+qTkRUxkNfJzCiyoz+Vjyz3beshf6MlY5nVrUVR8ixUxCJk9ama5QhoHT"
            + "4ONTULGXrA2ipLRsQlnwRq1DbkCFL+X0ATaAT2wwlwZ+4D8Ux073qZVtz2VvM5vS"
            + "Zd3FaPlPAxQAoelveypo4VkghoNCnTPHKawTwh0d3e8=";

    @Override
    protected List<KeyPair> getKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return Arrays.asList(new KeyPair(DefaultKeys.getPublicKey(algorithmName), getPrivateKey()));
    }

    // The private RSA key returned by DefaultKeys.getPrivateKey() is built from a PKCS#8
    // KeySpec and so will be an instance of RSAPrivateCrtKey, but we want to test RSAPrivateKey
    // in this unit test and so we extract the modulus and private exponent to build the
    // correct private key subtype.
    private PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) DefaultKeys.getPrivateKey(algorithmName);
        RSAPrivateKeySpec spec =
                new RSAPrivateKeySpec(crtKey.getModulus(), crtKey.getPrivateExponent());
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
        assertTrue(privateKey instanceof RSAPrivateKey);
        assertFalse(privateKey instanceof RSAPrivateCrtKey);
        return privateKey;
    }
}
