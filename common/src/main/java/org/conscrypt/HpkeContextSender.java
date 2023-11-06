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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

/**
 * Hybrid Public Key Encryption (HPKE) sender APIs.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#hpke-export">HPKE RFC 9180</a>
 *
 * Sender subclass of HpkeContext.  See base class for details.
 */
public class HpkeContextSender extends HpkeContext {
    private HpkeContextSender(HpkeSpi spi) {
        super(spi);
    }

    /**
     * Returns the encapsulated key created for this HpkeContextSender.
     *
     * @return the encapsulated key
     * @throws IllegalStateException if this HpkeContextSender has not been initialised.
     */
    public byte[] getEncapsulated() {
        return spi.getEncapsulated();
    }

    /**
     * Seals a message, using the internal key schedule maintained by this HpkeContextSender.
     *
     * @param plaintext the plaintext
     * @param aad optional associated data, may be null or empty
     * @return the ciphertext
     * @throws NullPointerException if the plaintext is null
     * @throws IllegalStateException if this HpkeContextSender has not been initialised
     */
    public byte[] seal(byte[] plaintext, byte[] aad) {
        return spi.engineSeal(plaintext, aad);
    }

    /**
     * Returns an uninitialised HpkeContextSender.
     *
     * @param suite the HPKE suite to use.  @see {@link HpkeSuite} for details.
     * @return an uninitialised HpkeContextSender for the requested suite
     * @throws NoSuchAlgorithmException if no implementation could be found
     */
    public static HpkeContextSender getInstance(String suite) throws NoSuchAlgorithmException {
        return new HpkeContextSender(findSpi(suite));
    }

    /**
     * Returns an uninitialised HpkeContextSender from a specific {@link Provider}
     *
     * @param suite the HPKE suite to use.  @see {@link HpkeSuite} for details.
     * @param providerName the name of the Provider to use
     * @return an uninitialised HpkeContextSender for the requested suite
     * @throws NoSuchAlgorithmException if no implementation could be found
     * @throws NoSuchProviderException if providerName is null or no such Provider exists
     */
    public static HpkeContextSender getInstance(String suite, String providerName)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        return new HpkeContextSender(findSpi(suite, providerName));
    }

    /**
     * Returns an uninitialised HpkeContextSender from a specific {@link Provider}
     *
     * @param suite the HPKE suite to use.  @see {@link HpkeSuite} for details.
     * @param provider the Provider to use
     * @return an uninitialised HpkeContextSender for the requested suite
     * @throws NoSuchAlgorithmException if no implementation could be found
     * @throws NoSuchProviderException if provider is null
     */
    public static HpkeContextSender getInstance(String suite, Provider provider)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        return new HpkeContextSender(findSpi(suite, provider));
    }

    /**
     * Initialises this HpkeContextSender in BASE mode, i.e. with no sender authentication.
     *
     * @param recipientKey public key of the recipient
     * @param info additional application-supplied information, may be null or empty
     * @throws InvalidKeyException if recipientKey is null or an unsupported key format
     * @throws UnsupportedOperationException if mode is not a supported HPKE mode
     * @throws IllegalStateException if this HpkeContextSender has already been initialised
     */
    public void init(PublicKey recipientKey, byte[] info) throws InvalidKeyException {
        spi.engineInitSender(
                recipientKey, info, null, HpkeSpi.DEFAULT_PSK, HpkeSpi.DEFAULT_PSK_ID);
    }

    /**
     * Initialises this HpkeContextSender in AUTH mode, i.e. messages are authenticated using
     * the sender's public key.
     *
     * @param recipientKey public key of the recipient
     * @param info additional application-supplied information, may be null or empty
     * @param senderKey private key of the sender
     * @throws InvalidKeyException if either recipientKey or senderKey are null
     *         or an unsupported key format
     * @throws UnsupportedOperationException if mode is not a supported HPKE mode
     * @throws IllegalStateException if this HpkeContextSender has already been initialised
     */
    public void init(PublicKey recipientKey, byte[] info, PrivateKey senderKey)
            throws InvalidKeyException {
        if (senderKey == null) {
            throw new InvalidKeyException("Sender private key is null");
        }
        // Remaining argument checks are performed by the SPI
        spi.engineInitSender(
                recipientKey, info, senderKey, HpkeSpi.DEFAULT_PSK, HpkeSpi.DEFAULT_PSK_ID);
    }

    /**
     * Initialises this HpkeContextSender in PSK mode, i.e. messages are authenticated using
     * a pre-shared secret key.
     *
     * @param recipientKey public key of the recipient
     * @param info additional application-supplied information, may be null or empty
     * @param psk the a pre-shared secret key
     * @param psk_id the id of the pre-shared secret key
     * @throws NullPointerException if psk or psk_id are null
     * @throws InvalidKeyException if recipientKey is null or an unsupported key format
     * @throws UnsupportedOperationException if mode is not a supported HPKE mode
     * @throws IllegalStateException if this HpkeContextSender has already been initialised
     */
    public void init(PublicKey recipientKey, byte[] info, byte[] psk, byte[] psk_id)
            throws InvalidKeyException {
        spi.engineInitSender(recipientKey, info, null, psk, psk_id);
    }

    /**
     * Initialises this HpkeContextSender in PSK_AUTH mode, i.e. messages are authenticated using
     * both the sender's public key and a pre-shared secret key.
     *
     * @param recipientKey public key of the recipient
     * @param info additional application-supplied information, may be null or empty
     * @param senderKey private key of the sender
     * @param psk the a pre-shared secret key
     * @param psk_id the id of the pre-shared secret key
     * @throws NullPointerException if psk or psk_id are null
     * @throws InvalidKeyException if either recipientKey or senderKey are null
     *         or an unsupported key format
     * @throws UnsupportedOperationException if mode is not a supported HPKE mode
     * @throws IllegalStateException if this HpkeContextSender has already been initialised
     */
    public void init(PublicKey recipientKey, byte[] info, PrivateKey senderKey,
            byte[] psk, byte[] psk_id) throws InvalidKeyException {
        if (senderKey == null) {
            throw new InvalidKeyException("Sender private key is null");
        }
        // Remaining argument checks are performed by the SPI
        spi.engineInitSender(recipientKey, info, senderKey, psk, psk_id);
    }

    /**
     * Initialises this HpkeContextSender for testing in BASE mode ONLY.
     *
     * @param recipientKey public key of the recipient
     * @param info additional application-supplied information, may be null or empty
     * @param sKe random seed to use during testing
     * @throws InvalidKeyException if recipientKey is null or an unsupported key format
     * @throws UnsupportedOperationException if mode is not a supported HPKE mode
     * @throws IllegalStateException if this HpkeContextSender has already been initialised
     * @throws IllegalArgumentException if sKe is null
     */
    @Internal
    public void initForTesting(PublicKey recipientKey, byte[] info, byte[] sKe)
        throws InvalidKeyException {
        if (sKe == null) {
            throw new IllegalArgumentException("null seed");
        }
        spi.engineInitSenderForTesting(
                recipientKey, info, null, HpkeSpi.DEFAULT_PSK, HpkeSpi.DEFAULT_PSK, sKe);
    }
}
