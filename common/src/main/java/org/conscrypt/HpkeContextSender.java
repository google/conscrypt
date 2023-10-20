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
import java.security.Provider;
import java.security.PublicKey;

/**
 * Hybrid Public Key Encryption (HPKE) sender APIs.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#hpke-export">HPKE RFC 9180</a>
 *
 * Sender subclass of HpkeContext.  See base class for details.
 */
public class HpkeContextSender extends HpkeContext{
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
     * Initialises this HpkeContextSender.
     *
     * @param mode HPKE mode to use, currently only HpkeContext.MODE_BASE is supported.
     * @param publicKey public key of the recipient
     * @param info application-supplied information, may be null or empty
     * @throws InvalidKeyException if publicKey is null or an unsupported key format
     * @throws UnsupportedOperationException if mode is not a supported HPKE mode
     * @throws IllegalStateException if this HpkeContextSender has already been initialised
     */
    public void init(int mode, PublicKey publicKey, byte[] info)
            throws InvalidKeyException {
        spi.engineInitSender(mode, publicKey, info, null);
    }

    /**
     * Initialises this HpkeContextSender for testing ONLY.
     *
     * @param mode HPKE mode to use, currently only HpkeContext.MODE_BASE is supported.
     * @param publicKey public key of the recipient
     * @param info application-supplied information, may be null or empty
     * @param sKe random seed to use during testing
     * @throws InvalidKeyException if publicKey is null or an unsupported key format
     * @throws UnsupportedOperationException if mode is not a supported HPKE mode
     * @throws IllegalStateException if this HpkeContextSender has already been initialised
     * @throws IllegalArgumentException if sKe is null
     */
    @Internal
    public void initForTesting(int mode, PublicKey publicKey, byte[] info, byte[] sKe)
        throws InvalidKeyException {
        if (sKe == null) {
            throw new IllegalArgumentException("null seed");
        }
        spi.engineInitSender(mode, publicKey, info, sKe);
    }
}
