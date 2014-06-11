/*
 * Copyright 2014 The Android Open Source Project
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

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Provides a place where NativeCrypto can call back up to do Java language
 * calls to work on delegated key types from native code.
 */
public final class CryptoUpcalls {
    private static final String RSA_CRYPTO_ALGORITHM = "RSA/ECB/PKCS1Padding";

    private CryptoUpcalls() {
    }

    /**
     * Finds the first provider which provides {@code algorithm} but is not from
     * the same ClassLoader as ours.
     */
    public static Provider getExternalProvider(String algorithm) {
        Provider selectedProvider = null;
        for (Provider p : Security.getProviders(algorithm)) {
            if (!p.getClass().getClassLoader().equals(CryptoUpcalls.class.getClassLoader())) {
                selectedProvider = p;
                break;
            }
        }
        if (selectedProvider == null) {
            System.err.println("Could not find external provider for algorithm: " + algorithm);
        }
        return selectedProvider;
    }

    public static byte[] rawSignDigestWithPrivateKey(PrivateKey javaKey, byte[] message) {
        // Get the raw signature algorithm for this key type.
        String algorithm = null;
        // Hint: Algorithm names come from:
        // http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
        if (javaKey instanceof RSAPrivateKey) {
            // IMPORTANT: Due to a platform bug, this will throw
            // NoSuchAlgorithmException
            // on Android 4.0.x and 4.1.x. Fixed in 4.2 and higher.
            // See https://android-review.googlesource.com/#/c/40352/
            algorithm = "NONEwithRSA";
        } else if (javaKey instanceof DSAPrivateKey) {
            algorithm = "NONEwithDSA";
        } else if (javaKey instanceof ECPrivateKey) {
            algorithm = "NONEwithECDSA";
        } else {
            throw new RuntimeException("Unexpected key type: " + javaKey.toString());
        }

        Provider p = getExternalProvider("Signature." + algorithm);
        if (p == null) {
            return null;
        }

        // Get the Signature for this key.
        Signature signature = null;
        try {
            signature = Signature.getInstance(algorithm, p);
        } catch (NoSuchAlgorithmException e) {
            ;
        }

        if (signature == null) {
            System.err.println("Unsupported private key algorithm: " + javaKey.getAlgorithm());
            return null;
        }

        // Sign the message.
        try {
            signature.initSign(javaKey);
            signature.update(message);
            return signature.sign();
        } catch (Exception e) {
            System.err.println("Exception while signing message with " + javaKey.getAlgorithm()
                    + " private key:");
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] rawCipherWithPrivateKey(PrivateKey javaKey, boolean encrypt,
            byte[] input) {
        if (!(javaKey instanceof RSAPrivateKey)) {
            System.err.println("Unexpected key type: " + javaKey.toString());
            return null;
        }

        Provider p = getExternalProvider("Cipher." + RSA_CRYPTO_ALGORITHM);
        if (p == null) {
            return null;
        }

        Cipher c = null;
        try {
            c = Cipher.getInstance(RSA_CRYPTO_ALGORITHM, p);
        } catch (NoSuchAlgorithmException e) {
            ;
        } catch (NoSuchPaddingException e) {
            ;
        }

        if (c == null) {
            System.err.println("Unsupported private key algorithm: " + javaKey.getAlgorithm());
        }

        try {
            c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, javaKey);
            return c.doFinal(input);
        } catch (Exception e) {
            System.err.println("Exception while ciphering message with " + javaKey.getAlgorithm()
                    + " private key:");
            e.printStackTrace();
            return null;
        }
    }
}
