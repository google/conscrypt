/*
 * Copyright (C) 2023 The Android Open Source Project
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
 * limitations under the License
 */

package org.conscrypt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeNotNull;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.Mac;

@RunWith(JUnit4.class)
public class HkdfTest {
    private final String SHA256 = "HmacSHA256";
    private final String conscryptProviderName = Platform.getDefaultProviderName();
    // This test will always be run with the Conscrypt under test installed as default Provider
    // so conscryptProvider will never be null.
    private final Provider conscryptProvider = Security.getProvider(conscryptProviderName);

    @Test
    public void conscryptIsInstalled() {
        assertNotNull("This test should only be run with Conscrypt installed as a Provider",
            conscryptProvider);
    }

    @Test
    public void noArgConstructor() throws Exception {
        assertThrows(NullPointerException.class, () ->  new Hkdf(null));

        Hkdf hkdf = new Hkdf(SHA256);
        assertSame(conscryptProvider, hkdf.getProvider());

        // No need to test these for every constructor overload
        assertEquals(Mac.getInstance(SHA256).getMacLength(), hkdf.getMacLength());
        assertThrows(NoSuchAlgorithmException.class, () -> new Hkdf("No such MAC"));
    }

    @Test
    public void providerNameConstructor() throws Exception {
        assertThrows(NullPointerException.class,
            () ->  new Hkdf(null, conscryptProviderName));

        // Unknown provider name, should throw
        assertThrows(NoSuchProviderException.class,
            () ->  new Hkdf(SHA256, "No such name"));

        // Explicitly ask for our Conscrypt
        Hkdf hkdf = new Hkdf(SHA256, conscryptProviderName);
        assertSame(conscryptProvider, hkdf.getProvider());
    }

    @Test
    public void providerNameConstructor_NonConscrypt() throws Exception {
        Provider provider =  TestUtils.getNonConscryptProviderFor("Mac",  SHA256);
        assumeNotNull(provider);

        Hkdf hkdf = new Hkdf(SHA256, provider.getName());
        assertSame(provider, hkdf.getProvider());
    }

    @Test
    public void providerConstructor() throws Exception {
        assertThrows(NullPointerException.class,
            () ->  new Hkdf(null, conscryptProvider));

        assertThrows(NullPointerException.class,
            () ->  new Hkdf(SHA256, (Provider) null));

        assertThrows(NullPointerException.class,
            () ->  new Hkdf(null, (Provider) null));

        Hkdf hkdf = new Hkdf(SHA256, conscryptProvider);
        assertSame(conscryptProvider, hkdf.getProvider());

        Provider myProvider = Conscrypt.newProvider();
        hkdf = new Hkdf(SHA256, myProvider);
        assertSame(myProvider, hkdf.getProvider());
    }

    @Test
    public void extract() throws Exception {
        Hkdf hkdf = new Hkdf(SHA256);
        assertThrows(NullPointerException.class, () -> hkdf.extract(null, new byte[0]));
        assertThrows(NullPointerException.class, () -> hkdf.extract(new byte[0], null));
        assertThrows(NullPointerException.class, () -> hkdf.extract(null, null));
        assertThrows(IllegalArgumentException.class, () -> hkdf.extract(new byte[0], new byte[0]));
    }

    @Test
    public void expand() throws Exception {
        Hkdf hkdf = new Hkdf(SHA256);
        int macLen = hkdf.getMacLength();
        assertThrows(NullPointerException.class, () -> hkdf.expand(null, new byte[0], 1));
        assertThrows(NullPointerException.class, () -> hkdf.expand(new byte[macLen], null, 1));
        assertThrows(NullPointerException.class, () -> hkdf.expand(null, null, 1));
        assertThrows(NullPointerException.class, () -> hkdf.expand(null, null, 1));
        // Negative length
        assertThrows(IllegalArgumentException.class,
            () -> hkdf.expand(new byte[macLen], new byte[0], -1));
        // PRK too small
        assertThrows(IllegalArgumentException.class,
            () -> hkdf.expand(new byte[0], new byte[0], 1));
        // Length too large
        assertThrows(IllegalArgumentException.class,
            () -> hkdf.expand(new byte[macLen], new byte[0], 255 * macLen + 1));

    }

    @Test
    public void testVectors() throws Exception {
        // Test against all providers that have SHA-256 (assume they'll also have SHA-1)
        List<Provider> providers = Arrays.stream(Security.getProviders())
            .filter(p -> p.getService("Mac", SHA256) != null)
            .collect(Collectors.toList());

        List<TestVector> vectors = TestUtils.readTestVectors("crypto/hkdf.txt");

        for (Provider provider : providers) {
            for (TestVector vector : vectors) {
                String errMsg = provider.getName() + ": " + vector.getString("name");
                String macName = vector.getString("hash");
                byte[] ikm = vector.getBytes("ikm");
                byte[] salt = vector.getBytesOrEmpty("salt");
                byte[] prk_expected = vector.getBytes("prk");

                Hkdf hkdf = new Hkdf(macName, provider);
                byte[] prk = hkdf.extract(salt, ikm);
                assertArrayEquals(errMsg, prk_expected, prk);

                byte[] info = vector.getBytes("info");
                int length = vector.getInt("l");
                byte[] okm_expected = vector.getBytes("okm");

                byte[] okm = hkdf.expand(prk, info, length);
                assertArrayEquals(errMsg, okm_expected, okm);
            }
        }
    }
}
