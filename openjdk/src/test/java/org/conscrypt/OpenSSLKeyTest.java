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
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOHsK2E2FLYfEMWEVH/rJMTqDZLLLysh\n" +
        "AH5odcfhYdF9xvFFU9rqJT7zXUDH4SjdhZGUUAO5IOC1e8ZIyRsbiY0CAwEAAQ==\n" +
        "-----END PUBLIC KEY-----";

    static final String RSA_PRIVATE_KEY =
        "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIIBOgIBAAJBAOHsK2E2FLYfEMWEVH/rJMTqDZLLLyshAH5odcfhYdF9xvFFU9rq\n" +
        "JT7zXUDH4SjdhZGUUAO5IOC1e8ZIyRsbiY0CAwEAAQJBALcu+oGJC0QcbknpIWbT\n" +
        "L+4mZTkYXLeYu8DDTHT0j47+6eEyYBOoRGcZDdlMWquvFIrV48RSot0GPh1MBE1p\n" +
        "lKECIQD4krM4UshCwUHH9ZVkoxcPsxzPTTW7ukky4RZVN6mgWQIhAOisOAXVVjon\n" +
        "fbGNQ6CezH7oOttEeZmiWCu48AVCyixVAiAaDZ41OA//Vywi3i2jV6iyH47Ud347\n" +
        "R+ImMAtcMTJZOQIgF0+Z1UvIdc8bErzad68xQc22h91WaYQQXWEL+xrz8nkCIDcA\n" +
        "MpCP/H5qTCj/l5rxQg+/NUGCg2pHHNLL+cy5N5RM\n" +
        "-----END RSA PRIVATE KEY-----";

    static final BigInteger RSA_MODULUS = new BigInteger(
        "e1ec2b613614b61f10c584547feb24c4ea0d92cb2f2b21007e6875c7e161d17d" +
        "c6f14553daea253ef35d40c7e128dd8591945003b920e0b57bc648c91b1b898d", 16);

    static final BigInteger RSA_PUBLIC_EXPONENT = new BigInteger("10001", 16);
    static final BigInteger RSA_PRIVATE_EXPONENT = new BigInteger(
        "b72efa81890b441c6e49e92166d32fee266539185cb798bbc0c34c74f48f8efe" +
        "e9e1326013a84467190dd94c5aabaf148ad5e3c452a2dd063e1d4c044d6994a1", 16);

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

