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

import static org.conscrypt.HpkeSuite.AEAD_AES_256_GCM;
import static org.conscrypt.HpkeSuite.KDF_HKDF_SHA256;
import static org.conscrypt.HpkeSuite.KEM_DHKEM_X25519_HKDF_SHA256;
import static org.conscrypt.TestUtils.decodeHex;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class HpkeFixture {
    static final byte[] DEFAULT_AAD = decodeHex("436f756e742d30");
    static final byte[] DEFAULT_ENC =
            decodeHex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    static final byte[] DEFAULT_INFO = decodeHex("4f6465206f6e2061204772656369616e2055726e");

    static final byte[] DEFAULT_PK_BYTES =
            decodeHex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    static final PublicKey DEFAULT_PK = createPublicKey(DEFAULT_PK_BYTES);
    static final byte[] DEFAULT_SK_BYTES =
            decodeHex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    static final PrivateKey DEFAULT_SK = createPrivateKey(DEFAULT_SK_BYTES);

    static final byte[] DEFAULT_PT =
            decodeHex("4265617574792069732074727574682c20747275746820626561757479");
    static final byte[] DEFAULT_CT = decodeHex(
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a");

    static final int DEFAULT_EXPORTER_LENGTH = 32;
    static final byte[] DEFAULT_EXPORTER_CONTEXT = decodeHex("00");

    static final HpkeSuite DEFAULT_SUITE = createDefaultHpkeSuite();

    static final String DEFAULT_SUITE_NAME = DEFAULT_SUITE.name();

    static HpkeContextRecipient createDefaultHpkeContextRecipient(byte[] enc)
        throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        return createDefaultHpkeContextRecipient(enc, DEFAULT_INFO);
    }

    static HpkeContextRecipient createDefaultHpkeContextRecipient(byte[] enc, byte[] info)
        throws NoSuchAlgorithmException, InvalidKeyException {
        HpkeContextRecipient contextRecipient =
                HpkeContextRecipient.getInstance(DEFAULT_SUITE_NAME);
        contextRecipient.init(enc, DEFAULT_SK, info);
        return contextRecipient;
    }

    static HpkeContextSender createDefaultHpkeContextSender()
        throws NoSuchAlgorithmException, InvalidKeyException {
        return createDefaultHpkeContextSender(DEFAULT_INFO);
    }

    static HpkeContextSender createDefaultHpkeContextSender(byte[] info)
        throws NoSuchAlgorithmException, InvalidKeyException {
        HpkeContextSender hpke = HpkeContextSender.getInstance(DEFAULT_SUITE_NAME);
        hpke.init(DEFAULT_PK, info);
        return hpke;
    }

    static HpkeSuite createDefaultHpkeSuite() {
        return new HpkeSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);
    }

    static PublicKey createPublicKey(byte[] publicKey) {
        try {
            final KeyFactory factory = KeyFactory.getInstance("XDH");
            final KeySpec spec = new XdhKeySpec(publicKey);
            return factory.generatePublic(spec);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    static PrivateKey createPrivateKey(byte[] privateKey) {
        try {
            final KeyFactory factory = KeyFactory.getInstance("XDH");
            final KeySpec spec = new XdhKeySpec(privateKey);
            return factory.generatePrivate(spec);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
