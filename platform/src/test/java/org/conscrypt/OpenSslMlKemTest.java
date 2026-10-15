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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

import org.conscrypt.TestVector;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;

@SuppressWarnings("NewApi")
@RunWith(JUnit4.class)
public class OpenSslMlKemTest {
    @Test
    public void mlKem768_encapsulateAndDecapsulate_matchesSharedSecret() throws Exception {
        OpenSslMlKemKeyPairGenerator.MlKem768 kpg = new OpenSslMlKemKeyPairGenerator.MlKem768();
        KeyPair keyPair = kpg.generateKeyPair();

        OpenSslMlKem.MlKem768 kem = new OpenSslMlKem.MlKem768();
        KEMSpi.EncapsulatorSpi encapsulator =
                kem.engineNewEncapsulator(keyPair.getPublic(), null, null);
        assertEquals(32, encapsulator.engineSecretSize());
        assertEquals(1088, encapsulator.engineEncapsulationSize());

        KEM.Encapsulated encapsulated = encapsulator.engineEncapsulate(0, 32, "Generic");
        assertNotNull(encapsulated);
        assertNotNull(encapsulated.key());
        assertEquals("Generic", encapsulated.key().getAlgorithm());
        assertEquals(32, encapsulated.key().getEncoded().length);
        assertEquals(1088, encapsulated.encapsulation().length);
        assertNull(encapsulated.params());

        KEMSpi.DecapsulatorSpi decapsulator = kem.engineNewDecapsulator(keyPair.getPrivate(), null);
        assertEquals(32, decapsulator.engineSecretSize());
        assertEquals(1088, decapsulator.engineEncapsulationSize());

        SecretKey decapsulatedKey =
                decapsulator.engineDecapsulate(encapsulated.encapsulation(), 0, 32, "Generic");
        assertNotNull(decapsulatedKey);
        assertEquals("Generic", decapsulatedKey.getAlgorithm());
        assertArrayEquals(encapsulated.key().getEncoded(), decapsulatedKey.getEncoded());
    }

    @Test
    public void mlKem768_encapsulateAndDecapsulate_withSlicingAndAlgorithm() throws Exception {
        OpenSslMlKemKeyPairGenerator.MlKem768 kpg = new OpenSslMlKemKeyPairGenerator.MlKem768();
        KeyPair keyPair = kpg.generateKeyPair();

        OpenSslMlKem.MlKem768 kem = new OpenSslMlKem.MlKem768();
        KEMSpi.EncapsulatorSpi encapsulator =
                kem.engineNewEncapsulator(keyPair.getPublic(), null, null);
        KEM.Encapsulated encapsulated = encapsulator.engineEncapsulate(0, 16, "AES");
        assertEquals("AES", encapsulated.key().getAlgorithm());
        assertEquals(16, encapsulated.key().getEncoded().length);

        KEMSpi.DecapsulatorSpi decapsulator = kem.engineNewDecapsulator(keyPair.getPrivate(), null);
        SecretKey decapsulatedKey =
                decapsulator.engineDecapsulate(encapsulated.encapsulation(), 0, 16, "AES");
        assertEquals("AES", decapsulatedKey.getAlgorithm());
        assertEquals(16, decapsulatedKey.getEncoded().length);
        assertArrayEquals(encapsulated.key().getEncoded(), decapsulatedKey.getEncoded());
    }

    @Test
    public void mlKem1024_encapsulateAndDecapsulate_matchesSharedSecret() throws Exception {
        OpenSslMlKemKeyPairGenerator.MlKem1024 kpg = new OpenSslMlKemKeyPairGenerator.MlKem1024();
        KeyPair keyPair = kpg.generateKeyPair();

        OpenSslMlKem.MlKem1024 kem = new OpenSslMlKem.MlKem1024();
        KEMSpi.EncapsulatorSpi encapsulator =
                kem.engineNewEncapsulator(keyPair.getPublic(), null, null);
        assertEquals(32, encapsulator.engineSecretSize());
        assertEquals(1568, encapsulator.engineEncapsulationSize());

        KEM.Encapsulated encapsulated = encapsulator.engineEncapsulate(0, 32, "Generic");
        assertNotNull(encapsulated);
        assertNotNull(encapsulated.key());
        assertEquals("Generic", encapsulated.key().getAlgorithm());
        assertEquals(32, encapsulated.key().getEncoded().length);
        assertEquals(1568, encapsulated.encapsulation().length);

        KEMSpi.DecapsulatorSpi decapsulator = kem.engineNewDecapsulator(keyPair.getPrivate(), null);
        assertEquals(32, decapsulator.engineSecretSize());
        assertEquals(1568, decapsulator.engineEncapsulationSize());

        SecretKey decapsulatedKey =
                decapsulator.engineDecapsulate(encapsulated.encapsulation(), 0, 32, "Generic");
        assertNotNull(decapsulatedKey);
        assertEquals("Generic", decapsulatedKey.getAlgorithm());
        assertArrayEquals(encapsulated.key().getEncoded(), decapsulatedKey.getEncoded());
    }

    @Test
    public void mlKem1024_encapsulateAndDecapsulate_withSlicingAndAlgorithm() throws Exception {
        OpenSslMlKemKeyPairGenerator.MlKem1024 kpg = new OpenSslMlKemKeyPairGenerator.MlKem1024();
        KeyPair keyPair = kpg.generateKeyPair();

        OpenSslMlKem.MlKem1024 kem = new OpenSslMlKem.MlKem1024();
        KEMSpi.EncapsulatorSpi encapsulator =
                kem.engineNewEncapsulator(keyPair.getPublic(), null, null);
        KEM.Encapsulated encapsulated = encapsulator.engineEncapsulate(8, 24, "HmacSHA256");
        assertEquals("HmacSHA256", encapsulated.key().getAlgorithm());
        assertEquals(16, encapsulated.key().getEncoded().length);

        KEMSpi.DecapsulatorSpi decapsulator = kem.engineNewDecapsulator(keyPair.getPrivate(), null);
        SecretKey decapsulatedKey =
                decapsulator.engineDecapsulate(encapsulated.encapsulation(), 8, 24, "HmacSHA256");
        assertEquals("HmacSHA256", decapsulatedKey.getAlgorithm());
        assertEquals(16, decapsulatedKey.getEncoded().length);
        assertArrayEquals(encapsulated.key().getEncoded(), decapsulatedKey.getEncoded());
    }

    @Test
    public void mlKem_generic_handlesBoth768And1024() throws Exception {
        OpenSslMlKem.MlKem genericKem = new OpenSslMlKem.MlKem();

        // ML-KEM-768
        OpenSslMlKemKeyPairGenerator.MlKem768 kpg768 = new OpenSslMlKemKeyPairGenerator.MlKem768();
        KeyPair kp768 = kpg768.generateKeyPair();

        KEMSpi.EncapsulatorSpi enc768 =
                genericKem.engineNewEncapsulator(kp768.getPublic(), null, null);
        assertEquals(1088, enc768.engineEncapsulationSize());
        assertEquals(32, enc768.engineSecretSize());
        KEM.Encapsulated res768 = enc768.engineEncapsulate(0, 32, "AES");

        KEMSpi.DecapsulatorSpi dec768 = genericKem.engineNewDecapsulator(kp768.getPrivate(), null);
        assertEquals(1088, dec768.engineEncapsulationSize());
        SecretKey sec768 = dec768.engineDecapsulate(res768.encapsulation(), 0, 32, "AES");
        assertArrayEquals(res768.key().getEncoded(), sec768.getEncoded());

        // ML-KEM-1024
        OpenSslMlKemKeyPairGenerator.MlKem1024 kpg1024 =
                new OpenSslMlKemKeyPairGenerator.MlKem1024();
        KeyPair kp1024 = kpg1024.generateKeyPair();

        KEMSpi.EncapsulatorSpi enc1024 =
                genericKem.engineNewEncapsulator(kp1024.getPublic(), null, null);
        assertEquals(1568, enc1024.engineEncapsulationSize());
        assertEquals(32, enc1024.engineSecretSize());
        KEM.Encapsulated res1024 = enc1024.engineEncapsulate(0, 32, "AES");

        KEMSpi.DecapsulatorSpi dec1024 =
                genericKem.engineNewDecapsulator(kp1024.getPrivate(), null);
        assertEquals(1568, dec1024.engineEncapsulationSize());
        SecretKey sec1024 = dec1024.engineDecapsulate(res1024.encapsulation(), 0, 32, "AES");
        assertArrayEquals(res1024.key().getEncoded(), sec1024.getEncoded());
    }

    @Test
    public void mlKem_testVectors_cryptoMlKemTxt() throws Exception {
        List<TestVector> vectors = TestUtils.readTestVectors("crypto/mlkem.txt");

        for (TestVector vector : vectors) {
            String keyAlgorithm = vector.getString("key-algorithm");
            byte[] pk = vector.getBytes("pk");
            byte[] sk = vector.getBytes("sk");
            byte[] enc = vector.getBytes("enc");

            MlKemAlgorithm algo = "ML-KEM-768".equals(keyAlgorithm) ? MlKemAlgorithm.ML_KEM_768
                                                                      : MlKemAlgorithm.ML_KEM_1024;

            PublicKey publicKey = new OpenSslMlKemPublicKey(pk, algo);
            PrivateKey privateKey = new OpenSslMlKemPrivateKey(sk, algo);

            KEMSpi kem = algo.equals(MlKemAlgorithm.ML_KEM_768) ? new OpenSslMlKem.MlKem768()
                                                                : new OpenSslMlKem.MlKem1024();

            // Decapsulate known test vector encapsulation
            KEMSpi.DecapsulatorSpi decapsulator = kem.engineNewDecapsulator(privateKey, null);
            SecretKey secretKey = decapsulator.engineDecapsulate(enc, 0, 32, "Generic");
            assertNotNull(secretKey);
            assertEquals(32, secretKey.getEncoded().length);

            // Test roundtrip encapsulation & decapsulation
            KEMSpi.EncapsulatorSpi encapsulator = kem.engineNewEncapsulator(publicKey, null, null);
            KEM.Encapsulated newEncapsulated = encapsulator.engineEncapsulate(0, 32, "Generic");
            SecretKey roundtripKey = decapsulator.engineDecapsulate(newEncapsulated.encapsulation(),
                                                                    0, 32, "Generic");
            assertArrayEquals(newEncapsulated.key().getEncoded(), roundtripKey.getEncoded());

            // Also test with generic MlKem
            OpenSslMlKem.MlKem genericKem = new OpenSslMlKem.MlKem();
            KEMSpi.DecapsulatorSpi genericDecapsulator =
                    genericKem.engineNewDecapsulator(privateKey, null);
            SecretKey genericSecretKey =
                    genericDecapsulator.engineDecapsulate(enc, 0, 32, "Generic");
            assertArrayEquals(secretKey.getEncoded(), genericSecretKey.getEncoded());

            KEMSpi.EncapsulatorSpi genericEncapsulator =
                    genericKem.engineNewEncapsulator(publicKey, null, null);
            KEM.Encapsulated genericEncapsulated =
                    genericEncapsulator.engineEncapsulate(0, 32, "Generic");
            SecretKey genericRoundtripKey = genericDecapsulator.engineDecapsulate(
                    genericEncapsulated.encapsulation(), 0, 32, "Generic");
            assertArrayEquals(genericEncapsulated.key().getEncoded(),
                              genericRoundtripKey.getEncoded());
        }
    }

    @Test
    public void newEncapsulator_invalidParameters_throwsExceptions() throws Exception {
        OpenSslMlKemKeyPairGenerator.MlKem768 kpg768 = new OpenSslMlKemKeyPairGenerator.MlKem768();
        KeyPair keyPair768 = kpg768.generateKeyPair();
        OpenSslMlKemKeyPairGenerator.MlKem1024 kpg1024 =
                new OpenSslMlKemKeyPairGenerator.MlKem1024();
        KeyPair keyPair1024 = kpg1024.generateKeyPair();

        OpenSslMlKem.MlKem768 kem768 = new OpenSslMlKem.MlKem768();

        // Null key
        assertThrows(InvalidKeyException.class,
                     () -> kem768.engineNewEncapsulator(null, null, null));

        // Unsupported spec
        assertThrows(
                InvalidAlgorithmParameterException.class,
                ()
                        -> kem768.engineNewEncapsulator(keyPair768.getPublic(),
                                                        new AlgorithmParameterSpec() {}, null));

        // Mismatched algorithm key
        assertThrows(InvalidKeyException.class,
                     () -> kem768.engineNewEncapsulator(keyPair1024.getPublic(), null, null));
    }

    @Test
    public void newDecapsulator_invalidParameters_throwsExceptions() throws Exception {
        OpenSslMlKemKeyPairGenerator.MlKem768 kpg768 = new OpenSslMlKemKeyPairGenerator.MlKem768();
        KeyPair keyPair768 = kpg768.generateKeyPair();
        OpenSslMlKemKeyPairGenerator.MlKem1024 kpg1024 =
                new OpenSslMlKemKeyPairGenerator.MlKem1024();
        KeyPair keyPair1024 = kpg1024.generateKeyPair();

        OpenSslMlKem.MlKem768 kem768 = new OpenSslMlKem.MlKem768();

        // Null key
        assertThrows(InvalidKeyException.class, () -> kem768.engineNewDecapsulator(null, null));

        // Unsupported spec
        assertThrows(InvalidAlgorithmParameterException.class,
                     ()
                             -> kem768.engineNewDecapsulator(keyPair768.getPrivate(),
                                                             new AlgorithmParameterSpec() {}));

        // Mismatched algorithm key
        assertThrows(InvalidKeyException.class,
                     () -> kem768.engineNewDecapsulator(keyPair1024.getPrivate(), null));
    }

    @Test
    public void encapsulate_invalidRangeAndNullAlgorithm_throwsExceptions() throws Exception {
        OpenSslMlKemKeyPairGenerator.MlKem768 kpg = new OpenSslMlKemKeyPairGenerator.MlKem768();
        KeyPair keyPair = kpg.generateKeyPair();

        OpenSslMlKem.MlKem768 kem = new OpenSslMlKem.MlKem768();
        KEMSpi.EncapsulatorSpi encapsulator =
                kem.engineNewEncapsulator(keyPair.getPublic(), null, null);

        // Null algorithm
        assertThrows(NullPointerException.class, () -> encapsulator.engineEncapsulate(0, 32, null));

        // Invalid range: from < 0
        assertThrows(IndexOutOfBoundsException.class,
                     () -> encapsulator.engineEncapsulate(-1, 32, "Generic"));

        // Invalid range: from > to
        assertThrows(IndexOutOfBoundsException.class,
                     () -> encapsulator.engineEncapsulate(16, 8, "Generic"));

        // Invalid range: to > secretSize (32)
        assertThrows(IndexOutOfBoundsException.class,
                     () -> encapsulator.engineEncapsulate(0, 33, "Generic"));
    }

    @Test
    public void decapsulate_invalidParameters_throwsExceptions() throws Exception {
        OpenSslMlKemKeyPairGenerator.MlKem768 kpg = new OpenSslMlKemKeyPairGenerator.MlKem768();
        KeyPair keyPair = kpg.generateKeyPair();

        OpenSslMlKem.MlKem768 kem = new OpenSslMlKem.MlKem768();
        KEMSpi.DecapsulatorSpi decapsulator = kem.engineNewDecapsulator(keyPair.getPrivate(), null);

        // Null encapsulation
        assertThrows(NullPointerException.class,
                     () -> decapsulator.engineDecapsulate(null, 0, 32, "Generic"));

        // Null algorithm
        assertThrows(NullPointerException.class,
                     () -> decapsulator.engineDecapsulate(new byte[1088], 0, 32, null));

        // Invalid encapsulation length
        assertThrows(DecapsulateException.class,
                     () -> decapsulator.engineDecapsulate(new byte[1087], 0, 32, "Generic"));
        assertThrows(DecapsulateException.class,
                     () -> decapsulator.engineDecapsulate(new byte[1089], 0, 32, "Generic"));

        // Invalid range
        assertThrows(IndexOutOfBoundsException.class,
                     () -> decapsulator.engineDecapsulate(new byte[1088], -1, 32, "Generic"));
        assertThrows(IndexOutOfBoundsException.class,
                     () -> decapsulator.engineDecapsulate(new byte[1088], 16, 8, "Generic"));
        assertThrows(IndexOutOfBoundsException.class,
                     () -> decapsulator.engineDecapsulate(new byte[1088], 0, 33, "Generic"));
    }

    @Test
    public void jceApi_encapsulateAndDecapsulate() throws Exception {
        if (!Platform.isPqcKemKdfSupported()) {
            return;
        }
        Provider provider = TestUtils.getConscryptProvider();
        for (String algorithm : new String[] {"ML-KEM", "ML-KEM-768", "ML-KEM-1024"}) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance(algorithm, provider);
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey priv =
                    kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

            KEM kem = KEM.getInstance(algorithm, provider);
            KEM.Encapsulator encapsulator = kem.newEncapsulator(pub);
            KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");

            KEM.Decapsulator decapsulator = kem.newDecapsulator(priv);
            SecretKey decapsulated =
                    decapsulator.decapsulate(encapsulated.encapsulation(), 0, 32, "AES");
            assertEquals("AES", decapsulated.getAlgorithm());
            assertArrayEquals(encapsulated.key().getEncoded(), decapsulated.getEncoded());
        }
    }
}
