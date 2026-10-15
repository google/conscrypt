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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;

import javax.crypto.KDF;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;

@android.annotation.Hide
@SuppressWarnings("NewApi")
@RunWith(JUnit4.class)
public class OpenSslProviderTest {
    @Test
    public void testProviderKdfAndKemRegistration() throws Exception {
        Provider provider = TestUtils.getConscryptProvider();
        assertNotNull(provider);

        if (Platform.isPqcKemKdfSupported()) {
            assertNotNull(provider.getService("KDF", "HKDF-SHA256"));
            assertNotNull(provider.getService("KDF", "HKDF-SHA384"));
            assertNotNull(provider.getService("KDF", "HKDF-SHA512"));
            assertNotNull(provider.getService("KDF", "HKDF-SHA1"));

            assertNotNull(provider.getService("KEM", "ML-KEM-768"));
            assertNotNull(provider.getService("KEM", "ML-KEM-1024"));
            assertNotNull(provider.getService("KEM", "ML-KEM"));

            // End-to-end JCE KDF API test
            for (String kdfAlg :
                 new String[] {"HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512", "HKDF-SHA1"}) {
                KDF kdf = KDF.getInstance(kdfAlg, provider);
                HKDFParameterSpec spec = HKDFParameterSpec.ofExtract()
                                                 .addIKM(new byte[] {1, 2, 3, 4})
                                                 .addSalt(new byte[] {5, 6, 7, 8})
                                                 .thenExpand(new byte[] {9, 10}, 32);
                SecretKey derivedKey = kdf.deriveKey("AES", spec);
                byte[] derivedData = kdf.deriveData(spec);
                assertEquals("AES", derivedKey.getAlgorithm());
                assertEquals(32, derivedData.length);
                assertArrayEquals(derivedData, derivedKey.getEncoded());
            }

            // End-to-end JCE KEM API test
            for (String kemAlg : new String[] {"ML-KEM", "ML-KEM-768", "ML-KEM-1024"}) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(kemAlg, provider);
                KeyPair kp = kpg.generateKeyPair();

                KEM kem = KEM.getInstance(kemAlg, provider);
                KEM.Encapsulator encapsulator = kem.newEncapsulator(kp.getPublic());
                KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");

                KEM.Decapsulator decapsulator = kem.newDecapsulator(kp.getPrivate());
                SecretKey decapsulated =
                        decapsulator.decapsulate(encapsulated.encapsulation(), 0, 32, "AES");
                assertEquals("AES", decapsulated.getAlgorithm());
                assertArrayEquals(encapsulated.key().getEncoded(), decapsulated.getEncoded());
            }
        }
    }
}
