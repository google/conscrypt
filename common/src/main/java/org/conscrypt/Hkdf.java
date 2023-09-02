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
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hkdf - perform HKDF ket extraction operations as per RFC 5869.
 * <p>
 * Instances should be instantiated using the standard JCA name for the required HMAC and
 * optionally the name of an installed security Provider from which to retrieve Mac instances.
 * <p>
 * If no Provider is specified then this class will try and locate an installed Conscrypt
 * Provider and if that fails it will instantiate (but not install) one.
 * <p>
 * Each invocation of expand or extract uses a new Mac instance and so instances
 * of Hkdf are thread-safe.
 */
public final class Hkdf {
    // HMAC algorithm to use.
    private final String hmacName;
    // Provider to use for getting Mac instances
    private final Provider provider;

    // Output length for the Mac in use.
    private final int macLength;

    /**
     * Creates an Hkdf instance which will use hmacName as the name for the underlying
     * HMAC algorithm.
     * <p>
     * The Hkdf instace will try and obtain Mac instances from an installed Conscrypt Provider with
     * the same name as this Conscrypt instance would use. Failing that it will look for
     * different flavous of Conscrypt that have been installed as Providers, and failing that
     * it will instantiate a private instance of this Conscrypt.
     *
     * @param hmacName the name of the HMAC algorithm to use
     *
     * @throws NoSuchAlgorithmException if hmacName is not a valid HMAC name
     */
    public Hkdf(String hmacName) throws NoSuchProviderException, NoSuchAlgorithmException {
        this(hmacName, (String) null);
    }

    /**
     * Creates an Hkdf instance which will use hmacName as the name for the underlying
     * HMAC algorithm to obtain from the specified Provider.
     * <p>
     * The Hkdf instance will try and obtain Mac instances from an installed Provider with
     * the name providerName.
     *
     * @param hmacName the name of the HMAC algorithm to use
     * @param providerName the name of the Provider to use
     * @throws NoSuchProviderException if an invalid Provider name was supplied
     * @throws NoSuchAlgorithmException if hmacName is not a valid HMAC name
     */
    public Hkdf(String hmacName, String providerName)
        throws NoSuchProviderException, NoSuchAlgorithmException {
        this(hmacName, findProvider(providerName));
    }

    /**
     * Creates an Hkdf instance which will use hmacName as the name for the underlying
     * HMAC algorithm to obtain from the specified Provider.
     * <p>
     * The Hkdf instance will try and obtain Mac instances from the specified Provider which
     * does not need to be installed as a JVM-wide Provider.
     *
     * @param hmacName the name of the HMAC algorithm to use
     * @param provider the Provider to use
     * @throws NoSuchAlgorithmException if hmacName is not a valid HMAC name
     */
    public Hkdf(String hmacName, Provider provider) throws NoSuchAlgorithmException {
        Objects.requireNonNull(hmacName);
        Objects.requireNonNull(provider);
        this.hmacName = hmacName;
        this.provider = provider;

        // Stash the MAC length with the bonus that we'll fail fast here if no such algorithm.
        macLength = Mac.getInstance(hmacName, provider).getMacLength();
    }

    private static Provider findProvider(String requestedName) throws NoSuchProviderException {
        if (requestedName != null) {
            Provider provider = Security.getProvider(requestedName);
            if (provider != null) {
                return provider;
            }
            throw new NoSuchProviderException();
        }
        // If no Provider name was supplied, look for possible Conscrypt Providers
        // in order of preference.
        List<String> candidates = Arrays.asList(
            Platform.getDefaultProviderName(), // Our own platform's Provider name
            "Conscrypt",                       // Android unbundled or OpenJDK
            "GmsCore_OpenSSL",                 // Google Play Services
            "AndroidOpenSSL");                 // Android platform
        for (String candidate : candidates) {
            Provider provider = Security.getProvider(candidate);
            if (provider != null) {
                return provider;
            }
        }
        // No user requested Provider and no Conscrypt Provider installed so instantiate one
        // for our private use but don't install it.
        return Conscrypt.newProvider();
    }

    // Visible for testing.
    Provider getProvider() {
        return provider;
    }

    // Visible for testing.
    int getMacLength() {
        return macLength;
    }

    /**
     * Performs an HKDF extract operation as specified in RFC 5869.
     *
     * @param salt the salt to use
     * @param ikm initial keying material
     * @return a pseudorandom key suitable for use in expand operations
     * @throws InvalidKeyException if the salt is not suitable for use as an HMAC key
     */

    public byte[] extract(byte[] salt, byte[] ikm) throws InvalidKeyException {
        Objects.requireNonNull(salt);
        Objects.requireNonNull(ikm);
        if (salt.length == 0) {
            salt = new byte[getMacLength()];
        }
        Preconditions.checkArgument(ikm.length > 0, "Empty keying material");
        Mac mac = getMac(salt);
        return mac.doFinal(ikm);
    }

    /**
     * Performs an HKDF expand operation as specified in RFC 5869.
     *
     * @param prk a pseudorandom key of at least HashLen octets, usually the output from the
     *            extract step. Where HashLen is the key size of the underlying Mac
     * @param info optional context and application specific information, can be zero length
     * @param length length of output keying material in bytes (<= 255*HashLen)
     * @return output of keying material of length bytes
     * @throws InvalidKeyException if prk is not suitable for use as an HMAC key
     * @throws IllegalArgumentException if length is out of the allowed range
     */
    public byte[] expand(byte[] prk, byte[] info, int length) throws InvalidKeyException {
        Objects.requireNonNull(prk);
        Objects.requireNonNull(info);
        Preconditions.checkArgument(length >= 0, "Negative length");
        Preconditions.checkArgument(length < 255 * getMacLength(), "Length too long");
        Mac mac = getMac(prk);

        byte[] t = new byte[0];
        byte[] output = new byte[0];
        byte[] counter = new byte[] { 0x00 };
        while (output.length < length) {
            counter[0]++;
            byte[] data = concat(t, info, counter);
            t = mac.doFinal(data);
            output = concat(output,
                Arrays.copyOfRange(t, 0, Math.min(getMacLength(), length - output.length)));
        }
        return output;
    }

    private byte[] concat(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }

    private Mac getMac(byte[] key) throws InvalidKeyException {
        try {
            Mac mac = Mac.getInstance(hmacName, provider);
            mac.init(new SecretKeySpec(key, "RAW"));
            return mac; // https://www.youtube.com/watch?v=uB1D9wWxd2w
        } catch (NoSuchAlgorithmException e) {
            // In theory, can't happen
            throw new IllegalStateException("No longer able to locate " + hmacName);
        }
    }
}
