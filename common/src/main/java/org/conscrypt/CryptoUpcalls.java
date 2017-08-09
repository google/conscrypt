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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Provides a place where NativeCrypto can call back up to do Java language
 * calls to work on delegated key types from native code. Delegated keys are
 * usually backed by hardware so we don't have access directly to the private
 * key material. If it were a key where we can get to the private key, we
 * would not ever call into this class.
 */
final class CryptoUpcalls {
    private static final Logger logger = Logger.getLogger(CryptoUpcalls.class.getName());

    private CryptoUpcalls() {}

    private static boolean isOurProvider(Provider p) {
        return p.getClass().getPackage().equals(CryptoUpcalls.class.getPackage());
    }

    /**
     * Finds providers that are not us that provide the requested algorithms.
     */
    private static ArrayList<Provider> getExternalProviders(String algorithm) {
        ArrayList<Provider> providers = new ArrayList<>(1);
        for (Provider p : Security.getProviders(algorithm)) {
            if (!isOurProvider(p)) {
                providers.add(p);
            }
        }
        if (providers.isEmpty()) {
            logger.warning("Could not find external provider for algorithm: " + algorithm);
        }
        return providers;
    }

    static byte[] rawSignDigestWithPrivateKey(PrivateKey javaKey, byte[] message) {
        // Get the raw signature algorithm for this key type.
        String algorithm;
        // Hint: Algorithm names come from:
        // http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
        String keyAlgorithm = javaKey.getAlgorithm();
        if ("RSA".equals(keyAlgorithm)) {
            // IMPORTANT: Due to a platform bug, this will throw
            // NoSuchAlgorithmException
            // on Android 4.0.x and 4.1.x. Fixed in 4.2 and higher.
            // See https://android-review.googlesource.com/#/c/40352/
            algorithm = "NONEwithRSA";
        } else if ("EC".equals(keyAlgorithm)) {
            algorithm = "NONEwithECDSA";
        } else {
            throw new RuntimeException("Unexpected key type: " + javaKey.toString());
        }

        Signature signature;

        // Since this is a delegated key, we cannot handle providing a signature using this key.
        // Otherwise we wouldn't end up in this classs in the first place. The first step is to
        // try to get the most preferred provider as long as it isn't us.
        try {
            signature = Signature.getInstance(algorithm);
            signature.initSign(javaKey);

            // Ignore it if it points back to us.
            if (isOurProvider(signature.getProvider())) {
                signature = null;
            }
        } catch (NoSuchAlgorithmException e) {
            logger.warning("Unsupported signature algorithm: " + algorithm);
            return null;
        } catch (InvalidKeyException e) {
            logger.warning("Preferred provider doesn't support key:");
            e.printStackTrace();
            signature = null;
        }

        // If the preferred provider was us, fall back to trying to find the
        // first not-us provider that initializes correctly.
        if (signature == null) {
            ArrayList<Provider> providers = getExternalProviders("Signature." + algorithm);
            for (Provider p : providers) {
                try {
                    signature = Signature.getInstance(algorithm, p);
                    signature.initSign(javaKey);
                    break;
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    signature = null;
                }
            }
            if (signature == null) {
                logger.warning("Could not find provider for algorithm: " + algorithm);
                return null;
            }
        }

        // Sign the message.
        try {
            signature.update(message);
            return signature.sign();
        } catch (Exception e) {
            logger.log(Level.WARNING,
                    "Exception while signing message with " + javaKey.getAlgorithm()
                            + " private key:",
                    e);
            return null;
        }
    }

    static byte[] rsaDecryptWithPrivateKey(PrivateKey javaKey, int openSSLPadding, byte[] input) {
        String keyAlgorithm = javaKey.getAlgorithm();
        if (!"RSA".equals(keyAlgorithm)) {
            logger.warning("Unexpected key type: " + keyAlgorithm);
            return null;
        }

        String jcaPadding;
        switch (openSSLPadding) {
            case NativeConstants.RSA_PKCS1_PADDING:
                jcaPadding = "PKCS1Padding";
                break;
            case NativeConstants.RSA_NO_PADDING:
                jcaPadding = "NoPadding";
                break;
            case NativeConstants.RSA_PKCS1_OAEP_PADDING:
                jcaPadding = "OAEPPadding";
                break;
            default:
                logger.warning("Unsupported OpenSSL/BoringSSL padding: " + openSSLPadding);
                return null;
        }

        String transformation = "RSA/ECB/" + jcaPadding;
        Cipher c = null;

        // Since this is a delegated key, we cannot handle providing a cipher using this key.
        // Otherwise we wouldn't end up in this classs in the first place. The first step is to
        // try to get the most preferred provider as long as it isn't us.
        try {
            c = Cipher.getInstance(transformation);
            c.init(Cipher.DECRYPT_MODE, javaKey);

            // Ignore it if it points back to us.
            if (isOurProvider(c.getProvider())) {
                c = null;
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.warning("Unsupported cipher algorithm: " + transformation);
            return null;
        } catch (InvalidKeyException e) {
            logger.log(Level.WARNING, "Preferred provider doesn't support key:", e);
            c = null;
        }

        // If the preferred provider was us, fall back to trying to find the
        // first not-us provider that initializes correctly.
        if (c == null) {
            ArrayList<Provider> providers = getExternalProviders("Cipher." + transformation);
            for (Provider p : providers) {
                try {
                    c = Cipher.getInstance(transformation, p);
                    c.init(Cipher.DECRYPT_MODE, javaKey);
                    break;
                } catch (
                        NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
                    c = null;
                }
            }
            if (c == null) {
                logger.warning("Could not find provider for algorithm: " + transformation);
                return null;
            }
        }

        try {
            return c.doFinal(input);
        } catch (Exception e) {
            logger.log(Level.WARNING,
                    "Exception while decrypting message with " + javaKey.getAlgorithm()
                            + " private key using " + transformation + ":",
                    e);
            return null;
        }
    }
}
