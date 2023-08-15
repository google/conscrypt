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

import java.security.PublicKey;
import org.conscrypt.NativeRef.EVP_HPKE_CTX;

/**
 * Hybrid Public Key Encryption (HPKE) Sender APIs.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#hpke-export">HPKE RFC 9180</a>
 */
public class HpkeContextSender {
    private final HpkeSuite hpkeSuite;
    private EVP_HPKE_CTX ctx;
    private byte[] enc;

    private HpkeContextSender(HpkeSuite hpkeSuite) {
        this.hpkeSuite = hpkeSuite;
    }

    /**
     * Initializes the internal HPKE context for the sender using BASE (0x00) mode. Once initialized
     * the encapsulated key is created which can be accessed through the {@link #getEnc()} method.
     *
     * @param publicKey public key matching the KEM public key size
     * @param info      optional application-supplied information
     * @return encapsulated key
     * @throws IllegalArgumentException if providing a public key that does not match the size
     *                                  expectation
     * @throws IllegalStateException    if an issue is encountered while setting up the sender
     *                                  (an issue could occur most likely if the keys configured are
     *                                  not valid)
     */
    public static HpkeContextSender setupBase(
            HpkeSuite hpkeSuite, PublicKey publicKey, byte[] info) {
        return setupBase(new HpkeContextSenderHelper(), hpkeSuite, publicKey, info);
    }

    @Internal
    static HpkeContextSender setupBaseForTesting(HpkeContextSenderHelper contextHelper,
            HpkeSuite hpkeSuite, PublicKey publicKey, byte[] info) {
        Preconditions.checkNotNull(contextHelper, "hpkeContextSenderHelper");
        return setupBase(contextHelper, hpkeSuite, publicKey, info);
    }

    private static HpkeContextSender setupBase(HpkeContextSenderHelper contextHelper,
            HpkeSuite hpkeSuite, PublicKey publicKey, byte[] info) {
        Preconditions.checkNotNull(hpkeSuite, "hpkeSuite");
        final byte[] pk = hpkeSuite.getKem().validatePublicKeyTypeAndGetRawKey(publicKey);
        try {
            final Object[] result = contextHelper.setupBase(hpkeSuite.getKem().getId(),
                    hpkeSuite.getKdf().getId(), hpkeSuite.getAead().getId(), pk, info);
            final HpkeContextSender ctxSender = new HpkeContextSender(hpkeSuite);
            ctxSender.ctx = (EVP_HPKE_CTX) result[0];
            ctxSender.enc = (byte[]) result[1];
            return ctxSender;
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Error while setting up base sender with the keys provided", e);
        }
    }

    /**
     * Returns the enc (encapsulated key) that was created during the initialization/setup phase.
     *
     * @return enc (encapsulated key)
     */
    public byte[] getEnc() {
        return enc;
    }

    /**
     * Hybrid Public Key Encryption (HPKE) encryption.
     * <p>
     * Note: This API keeps track of its state. It maintains an internal HPKE context. As a result,
     * to encrypt multiple messages that are expected to be decrypted using the same context, one
     * must call this method for each of the messages.
     *
     * @param plaintext message that will be encrypted
     * @param aad       optional associated data
     * @return ciphertext
     */
    public byte[] seal(byte[] plaintext, byte[] aad) {
        Preconditions.checkNotNull(plaintext, "plaintext");
        return NativeCrypto.EVP_HPKE_CTX_seal(ctx, plaintext, aad);
    }

    /**
     * Hybrid Public Key Encryption (HPKE) secret export.
     *
     * @param length          expected output length
     * @param exporterContext optional exporter context
     * @return exported value
     * @throws IllegalArgumentException if the length is not valid based on the KDF spec
     */
    public byte[] export(int length, byte[] exporterContext) {
        hpkeSuite.getKdf().validateExportLength(length);
        return NativeCrypto.EVP_HPKE_CTX_export(ctx, exporterContext, length);
    }
}
