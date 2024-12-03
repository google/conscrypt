/*
 * Copyright (C) 2024 The Android Open Source Project
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

package android.crypto.hpke;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import libcore.util.NonNull;
import libcore.util.Nullable;


/**
 * Service Provider Interface for HPKE client API classes to communicate with implementations
 * of HPKE as described in RFC 9180.
 * <p>
 * There are no standard Java Cryptography Architecture names or interface classes for HPKE,
 * but instances of this class can be obtained by calling
 * {@code Provider.getService("ConscryptHpke", String SuiteName)} where {@code suiteName}
 * is the name of the HPKE suite, e.g.
 * {@code "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM"}.
 */
public interface HpkeSpi {
    /**
     * Initialises an HPKE SPI in one of the sender modes described in RFC 9180.
     * <p>
     * If {@code senderKey} is supplied then Asymmetric Key Authentication will be used,
     * (MODE_AUTH)
     * <p>
     * If {@code psk} and {@code psk_id} are supplied then Pre-Shared Key Authentication
     * will be used (MODE_PSK).
     * <p>
     * If all of {@code senderKey}, {@code psk} and {@code psk_id} are supplied then both
     * Key and PSK authentication will be used (MODE_PSK_AUTH).
     * <p>
     * If neither is supplied then no sender authentication will be used (MODE_BASE).
     * <p>
     * Note that only base mode is currently supported on Android.
     * <p>
     * Public and private keys must be supplied in a format that can be used by the
     * implementation.  An instance of the {@code "XDH"} {@link java.security.KeyFactory} can
     * be used to translate {@code KeySpecs} or keys from another {@link java.security.Provider}
     *
     * @param recipientKey public key of the recipient
     * @param info application-supplied information, may be null or empty
     * @param senderKey private key of the sender, for symmetric auth modes only, else null
     * @param psk pre-shared key, for PSK auth modes only, else null
     * @param psk_id pre-shared key ID, for PSK auth modes only, else null
     * @throws InvalidKeyException if recipientKey is null or an unsupported key format
     * @throws UnsupportedOperationException if the mode is not supported by this implementation
     * @throws IllegalStateException if this SPI has already been initialised
     */
    void engineInitSender(
            @NonNull PublicKey recipientKey,
            @Nullable byte[] info,
            @Nullable PrivateKey senderKey,
            @Nullable byte[] psk,
            @Nullable byte[] psk_id)
            throws InvalidKeyException;

    /**
     * Initialises an HPKE SPI in one of the sender modes described in RFC 9180 with
     * a predefined random seed to allow testing against known test vectors.
     * <p>
     * This mode provides absolutely no security and should only be used for testing
     * purposes.
     * <p>
     * If {@code senderKey} is supplied then Asymmetric Key Authentication will be used,
     * (MODE_AUTH)
     * <p>
     * If {@code psk} and {@code psk_id} are supplied then Pre-Shared Key Authentication
     * will be used (MODE_PSK).
     * <p>
     * If all of {@code senderKey}, {@code psk} and {@code psk_id} are supplied then both
     * Key and PSK authentication will be used (MODE_AUTH_PSK).
     * <p>
     * If neither is supplied then no sender authentication will be used (MODE_BASE).
     * <p>
     * Note that only base mode is currently supported on Android.
     * <p>
     * Public and private keys must be supplied in a format that can be used by the
     * implementation.  An instance of the {@code "XDH"} {@link java.security.KeyFactory} can
     * be used to translate {@code KeySpecs} or keys from another {@link java.security.Provider}
     *
     *
     * @param recipientKey public key of the recipient
     * @param info application-supplied information, may be null or empty
     * @param senderKey private key of the sender, for symmetric auth modes only, else null
     * @param psk pre-shared key, for PSK auth modes only, else null
     * @param psk_id pre-shared key ID, for PSK auth modes only, else null
     * @param sKe Predetermined random seed, should only be used for validation against
     *            known test vectors
     * @throws InvalidKeyException if recipientKey is null or an unsupported key format or senderKey
     *            is an unsupported key format
     * @throws UnsupportedOperationException if the mode is not supported by this implementation
     * @throws IllegalStateException if this SPI has already been initialised
     */
    void engineInitSenderWithSeed(
            @NonNull PublicKey recipientKey,
            @Nullable byte[] info,
            @Nullable PrivateKey senderKey,
            @Nullable byte[] psk,
            @Nullable byte[] psk_id,
            @NonNull byte[] sKe)
            throws InvalidKeyException;

    /**
     * Initialises an HPKE SPI in one of the recipient modes described in RFC 9180.
     * <p>
     * If {@code senderKey} is supplied then Asymmetric Key Authentication will be used,
     * (MODE_AUTH)
     * <p>
     * If {@code psk} and {@code psk_id} are supplied then Pre-Shared Key Authentication
     * will be used (MODE_PSK).
     * <p>
     * If all of {@code senderKey}, {@code psk} and {@code psk_id} are supplied then both
     * Key and PSK authentication will be used (MODE_AUTH_PSK).
     * <p>
     * If neither is supplied then no sender authentication will be used (MODE_BASE).
     * <p>
     * Note that only base mode is currently supported on Android.
     * <p>
     * Public and private keys must be supplied in a format that can be used by the
     * implementation.  An instance of the {@code "XDH"} {@link java.security.KeyFactory} can
     * be used to translate {@code KeySpecs} or keys from another {@link java.security.Provider}
     *
     * @param encapsulated encapsulated ephemeral key from a sender
     * @param recipientKey private key of the recipient
     * @param info application-supplied information, may be null or empty
     * @param senderKey public key of sender, for asymmetric auth modes only, else null
     * @param psk pre-shared key, for PSK auth modes only, else null
     * @param psk_id pre-shared key ID, for PSK auth modes only, else null
     * @throws InvalidKeyException if recipientKey is null or an unsupported key format or senderKey
     *         is an unsupported key format
     * @throws UnsupportedOperationException if the mode is not supported by this implementation
     * @throws IllegalStateException if this SPI has already been initialised
     */
    void engineInitRecipient(
            @NonNull byte[] encapsulated,
            @NonNull PrivateKey recipientKey,
            @Nullable byte[] info,
            @Nullable PublicKey senderKey,
            @Nullable byte[] psk,
            @Nullable byte[] psk_id)
            throws InvalidKeyException;

    /**
     * Seals a message, using the internal key schedule maintained by an HPKE sender SPI.
     *
     * @param plaintext the plaintext
     * @param aad optional associated data, may be null or empty
     * @return the ciphertext
     * @throws NullPointerException if the plaintext is null
     * @throws IllegalStateException if this SPI has not been initialised or if it was initialised
     *         as a recipient
     */
    @NonNull byte[] engineSeal(@NonNull byte[] plaintext, @Nullable byte[] aad);

    /**
     * Opens a message, using the internal key schedule maintained by an HPKE recipient SPI.
     *
     * @param ciphertext the ciphertext
     * @param aad optional associated data, may be null or empty
     * @return the plaintext
     * @throws IllegalStateException if this SPI has not been initialised or if it was initialised
     *         as a sender
     * @throws GeneralSecurityException on decryption failures
     */
    @NonNull byte[] engineOpen(@NonNull byte[] ciphertext, @Nullable byte[] aad)
            throws GeneralSecurityException;

    /**
     * Exports secret key material from this SPI as described in RFC 9180.
     *
     * @param length  expected output length
     * @param context optional context string, may be null or empty
     * @return exported value
     * @throws IllegalArgumentException if the length is not valid for the KDF in use
     * @throws IllegalStateException if this SPI has not been initialised
     *
     */
    @NonNull byte[] engineExport(int length, @Nullable byte[] context);

    /**
     * Returns the encapsulated key material for an HPKE sender.
     *
     * @return the key material
     * @throws IllegalStateException if this SPI has not been initialised or if it was initialised
     *         as a recipient
     */
    @NonNull byte[] getEncapsulated();
}
