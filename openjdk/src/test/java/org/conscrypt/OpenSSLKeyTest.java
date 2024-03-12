/*
 * Copyright (C) 2015 The Android Open Source Project
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

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import junit.framework.TestCase;

public class OpenSSLKeyTest extends TestCase {
    static final String RSA_PUBLIC_KEY =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3G7PGpfZx68wTY9eLb4b\n" +
        "th3Y7MXgh1A2oqB202KTiClKy9Y+Z+HCx5KIXXcycVjAfhK7qG+F/XVeE0TpzR8c\n" +
        "0wj2e3kxwS/wiMjoYXIcbFW0iN6g1F6n71Zykf0uOE8DZKCffzjmld+Ia5M4qKsC\n" +
        "gW4TTUODGVChBUTKui4b7Q8qsBOUTXm7SeyuZcZRChZ2w9aICZ3OR1qHnG0EXvgs\n" +
        "0ZhCIgvtVQPaEwqMWaGYQKa8hW9X3KUvY6D8fQkQdhY2j5m/y2757tNsQWhH7l/C\n" +
        "gdH/2F7qa3+V1yTqj9ihceLq1/FxAZkd6q7G9YE8ZyvtoKU86o6+4arMELQi86QF\n" +
        "cQIDAQAB\n" +
        "-----END PUBLIC KEY-----";

    static final String RSA_PRIVATE_KEY =
        "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIIEpAIBAAKCAQEA3G7PGpfZx68wTY9eLb4bth3Y7MXgh1A2oqB202KTiClKy9Y+\n" +
        "Z+HCx5KIXXcycVjAfhK7qG+F/XVeE0TpzR8c0wj2e3kxwS/wiMjoYXIcbFW0iN6g\n" +
        "1F6n71Zykf0uOE8DZKCffzjmld+Ia5M4qKsCgW4TTUODGVChBUTKui4b7Q8qsBOU\n" +
        "TXm7SeyuZcZRChZ2w9aICZ3OR1qHnG0EXvgs0ZhCIgvtVQPaEwqMWaGYQKa8hW9X\n" +
        "3KUvY6D8fQkQdhY2j5m/y2757tNsQWhH7l/CgdH/2F7qa3+V1yTqj9ihceLq1/Fx\n" +
        "AZkd6q7G9YE8ZyvtoKU86o6+4arMELQi86QFcQIDAQABAoIBABkX4iqoU6nYJxsF\n" +
        "MZbqd9QdBLc7dWph9r4/nxdENwA+lx2qN3Ny703xv+VH7u2ZSVxwvH0ZqPqn9Dwk\n" +
        "UatAmfLqJ8j5jHDuCKdBm7aQG203unQER/G1Ds//ms5EsJDHad74K//7FcDE8A4y\n" +
        "9bW5tfDO+5KFl3R3ycTERoG4QwSSyb8qGbA5Xo+C+9EK9ldE5f7tnryXpG/iCHem\n" +
        "NanAF+Jxof1GanaCD6xQDug4ReEqZrWWwtco89qfNNSXEpH05hPmgl35UKO9RQn5\n" +
        "07EtowT+WwDEQ/8zMmuL+z/hEf1LiHKCLH8oMtr6D+ENmroiMQhJ6XjlHIqp2nvB\n" +
        "wHUR2IMCgYEA++hWbdHxZ3I+QvBIjUKF6OfWkN0ZHVWU9ZNTZoG4ggdxlm5XN+C7\n" +
        "tohumtChIU0oNkdG38akyN5HlTg+tbd7E0ZgBnYMwAsEEXt5aEoFtFAxEorI26zr\n" +
        "uvWqRwXNFVKTuC9+JFZvFiteYMSWzryn8dS2cNVG1hswGa1kf0Xg218CgYEA4AOS\n" +
        "F1snvadqxocM7U8LpY8mSeXV5PayZN87GLFaK41G/zD0l+mVZAWZld9ux+rR/2OP\n" +
        "uPWZWtn/+4v2DERukA0jerGdFocCv1s893Stoz/oVapCW0h6pa+Fa6EX2nuqNST0\n" +
        "bE/dbHhfYditfoGQhQlOLmqrJc+B6jaOt+m7oS8CgYBVvwxMbX4inDydRHUtwEsc\n" +
        "sG3U+a2m0o7V2MQ2zEkl2arMbdq6ZoD+7QnZINL4Ju9dKn3xhghpZ2AuZurRqBb4\n" +
        "xKfDC0Pjytwjp0f4O9odOn65tQwR2paTGTRQ4KSicW1e8KubauB9R13kyoYa8RSp\n" +
        "uKIxXieykaaZ1u+ycvLLOQKBgQC1PU5SRTbm82+pBZTI3t4eaa3htekTISD+CbnH\n" +
        "ZZ39hIT/bH1H9v0d+oXjQu1fI7YZOVULoPEdFylLPFaqYCdPtsGQv+jHVB498bRm\n" +
        "xOjDHq57uI+NSRupt1Nr297vroPsEWULyKXt34nUITllE7B4Yin11el4YuXKN6/K\n" +
        "Tnm2kwKBgQC6Qy/DiFeF5uf0xnAkh0HFjzL+F3isIUV5l31jzna2sJSKridm+Hst\n" +
        "mnaNDu/BKViEvSof3IpW8f7PSzskc4+Fos1KMdCkxG3bNrym8OLdWi+J4NjTbbCa\n" +
        "sudhqm8rNr8zWFAEZ48jpcv7whYfkjCIh4z0uVNOq9dspolJaW14yg==\n" +
        "-----END RSA PRIVATE KEY-----";

    static final BigInteger RSA_MODULUS = new BigInteger(
        "dc6ecf1a97d9c7af304d8f5e2dbe1bb61dd8ecc5e0875036a2a076d362938829" +
        "4acbd63e67e1c2c792885d77327158c07e12bba86f85fd755e1344e9cd1f1cd3" +
        "08f67b7931c12ff088c8e861721c6c55b488dea0d45ea7ef567291fd2e384f03" +
        "64a09f7f38e695df886b9338a8ab02816e134d43831950a10544caba2e1bed0f" +
        "2ab013944d79bb49ecae65c6510a1676c3d688099dce475a879c6d045ef82cd1" +
        "9842220bed5503da130a8c59a19840a6bc856f57dca52f63a0fc7d0910761636" +
        "8f99bfcb6ef9eed36c416847ee5fc281d1ffd85eea6b7f95d724ea8fd8a171e2" +
        "ead7f17101991deaaec6f5813c672beda0a53cea8ebee1aacc10b422f3a40571", 16);

    static final BigInteger RSA_PUBLIC_EXPONENT = new BigInteger("10001", 16);
    static final BigInteger RSA_PRIVATE_EXPONENT = new BigInteger(
        "1917e22aa853a9d8271b053196ea77d41d04b73b756a61f6be3f9f174437003e" +
        "971daa377372ef4df1bfe547eeed99495c70bc7d19a8faa7f43c2451ab4099f2" +
        "ea27c8f98c70ee08a7419bb6901b6d37ba740447f1b50ecfff9ace44b090c769" +
        "def82bfffb15c0c4f00e32f5b5b9b5f0cefb9285977477c9c4c44681b8430492" +
        "c9bf2a19b0395e8f82fbd10af65744e5feed9ebc97a46fe20877a635a9c017e2" +
        "71a1fd466a76820fac500ee83845e12a66b596c2d728f3da9f34d4971291f4e6" +
        "13e6825df950a3bd4509f9d3b12da304fe5b00c443ff33326b8bfb3fe111fd4b" +
        "8872822c7f2832dafa0fe10d9aba22310849e978e51c8aa9da7bc1c07511d883", 16);

    public void test_fromPublicKeyPemInputStream() throws Exception {
        ByteArrayInputStream is = new ByteArrayInputStream(RSA_PUBLIC_KEY.getBytes("UTF-8"));
        OpenSSLKey key = OpenSSLKey.fromPublicKeyPemInputStream(is);
        OpenSSLRSAPublicKey publicKey = (OpenSSLRSAPublicKey)key.getPublicKey();
        assertEquals(RSA_MODULUS, publicKey.getModulus());
        assertEquals(RSA_PUBLIC_EXPONENT, publicKey.getPublicExponent());
    }

    public void test_fromPrivateKeyPemInputStream() throws Exception {
        ByteArrayInputStream is = new ByteArrayInputStream(RSA_PRIVATE_KEY.getBytes("UTF-8"));
        OpenSSLKey key = OpenSSLKey.fromPrivateKeyPemInputStream(is);
        OpenSSLRSAPrivateKey privateKey = (OpenSSLRSAPrivateKey)key.getPrivateKey();
        assertEquals(RSA_MODULUS, privateKey.getModulus());
        assertEquals(RSA_PRIVATE_EXPONENT, privateKey.getPrivateExponent());
    }
}

