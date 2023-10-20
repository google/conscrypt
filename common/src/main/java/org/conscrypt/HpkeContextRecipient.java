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
import javax.crypto.BadPaddingException;

/**
 * Hybrid Public Key Encryption (HPKE) recipient APIs.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#hpke-export">HPKE RFC 9180</a>
 *
 * Recipient subclass of HpkeContext.  See base class for details.
 */
public class HpkeContextRecipient extends HpkeContext {
    private HpkeContextRecipient(HpkeSpi spi) {
        super(spi);
    }

    /**
     * Opens a message, using the internal key schedule maintained by this HpkeContextRecipient.
     *
     * @param ciphertext the ciphertext
     * @param aad optional associated data, may be null or empty
     * @return the plaintext
     * @throws IllegalStateException if this HpkeContextRecipient has not been initialised
     * @throws javax.crypto.BadPaddingException on decryption failures (XXX rework this but it's
     *         what Cipher does!)
     */
    public byte[] open(byte[] ciphertext, byte[] aad) throws BadPaddingException {
        return spi.engineOpen(ciphertext, aad);
    }

    /**
     * Returns an uninitialised HpkeContextRecipient.
     *
     * @param suite the HPKE suite to use.  @see {@link HpkeSuite} for details.
     * @return an uninitialised HpkeContextRecipient for the requested suite
     * @throws NoSuchAlgorithmException if no implementation could be found
     */
    public static HpkeContextRecipient getInstance(String suite) throws NoSuchAlgorithmException {
        return new HpkeContextRecipient(findSpi(suite));
    }

    /**
     * Returns an uninitialised HpkeContextRecipient from a specific {@link Provider}
     *
     * @param suite the HPKE suite to use.  @see {@link HpkeSuite} for details.
     * @param providerName the name of the Provider to use
     * @return an uninitialised HpkeContextRecipient for the requested suite
     * @throws NoSuchAlgorithmException if no implementation could be found
     * @throws NoSuchProviderException if providerName is null or no such Provider exists
     */
    public static HpkeContextRecipient getInstance(String suite, String providerName)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        return new HpkeContextRecipient(findSpi(suite, providerName));
    }

    /**
     * Returns an uninitialised HpkeContextRecipient from a specific {@link Provider}
     *
     * @param suite the HPKE suite to use.  @see {@link HpkeSuite} for details.
     * @param provider the Provider to use
     * @return an uninitialised HpkeContextRecipient for the requested suite
     * @throws NoSuchAlgorithmException if no implementation could be found
     * @throws NoSuchProviderException if providerName is null or no such Provider exists
     */
    public static HpkeContextRecipient getInstance(String suite, Provider provider)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        return new HpkeContextRecipient(findSpi(suite, provider));
    }

    /**
     * Initialises this HpkeContextRecipient.
     *
     * @param mode HPKE mode to use, currently only HpkeContext.MODE_BASE is supported.
     * @param enc encapsulated ephemeral key from a HpkeContextSender
     * @param privateKey private key of the recipient
     * @param info application-supplied information, may be null or empty
     * @throws InvalidKeyException if privateKey is null or an unsupported key format
     * @throws UnsupportedOperationException if mode is not a supported HPKE mode
     * @throws IllegalStateException if this HpkeContextRecipient has already been initialised
     */
    public void init(int mode, byte[] enc, PrivateKey privateKey, byte[] info)
        throws InvalidKeyException {
        spi.engineInitRecipient(mode, enc, privateKey, info);
    }
}
