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
import java.util.List;
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

    /**
     * Finds providers that are not us that provide the requested algorithms.
     */
    private static List<Provider> getExternalProviders(String algorithm) {
        List<Provider> providers = new ArrayList<>(1);
        for (Provider p : Security.getProviders(algorithm)) {
            if (!Conscrypt.isConscrypt(p)) {
                providers.add(p);
            }
        }
        if (providers.isEmpty()) {
            logger.warning("Could not find external provider for algorithm: " + algorithm);
        }
        return providers;
    }

    static byte[] ecSignDigestWithPrivateKey(PrivateKey javaKey, byte[] message) {
        // Hint: Algorithm names come from:
        // http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
        String keyAlgorithm = javaKey.getAlgorithm();
        if (!"EC".equals(keyAlgorithm)) {
            throw new RuntimeException("Unexpected key type: " + javaKey);
        }

        return signDigestWithPrivateKey(javaKey, message, "NONEwithECDSA");
    }

    private static byte[] signDigestWithPrivateKey(PrivateKey javaKey, byte[] message,
            String algorithm) {
        Signature signature;

        // Since this is a delegated key, we cannot handle providing a signature using this key.
        // Otherwise we wouldn't end up in this class in the first place. The first step is to
        // try to get the most preferred provider as long as it isn't us.
        try {
            signature = Signature.getInstance(algorithm);
            signature.initSign(javaKey);

            // Ignore it if it points back to us.
            if (Conscrypt.isConscrypt(signature.getProvider())) {
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
            List<Provider> providers = getExternalProviders("Signature." + algorithm);
            RuntimeException savedRuntimeException = null;
            for (Provider p : providers) {
                try {
                    signature = Signature.getInstance(algorithm, p);
                    signature.initSign(javaKey);
                    break;
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    signature = null;
                } catch (RuntimeException e) {
                    signature = null;
                    if (savedRuntimeException == null) {
                        savedRuntimeException = e;
                    }
                }
            }
            if (signature == null) {
                if (savedRuntimeException != null) {
                    throw savedRuntimeException;
                }
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

    static byte[] rsaSignDigestWithPrivateKey(PrivateKey javaKey, int openSSLPadding,
            byte[] message) {
        // An RSA cipher + ENCRYPT_MODE produces a standard RSA signature
        return rsaOpWithPrivateKey(javaKey, openSSLPadding, Cipher.ENCRYPT_MODE, message);
    }

    static byte[] rsaDecryptWithPrivateKey(PrivateKey javaKey, int openSSLPadding, byte[] input) {
        return rsaOpWithPrivateKey(javaKey, openSSLPadding, Cipher.DECRYPT_MODE, input);
    }

    private static byte[] rsaOpWithPrivateKey(PrivateKey javaKey, int openSSLPadding,
            int cipherMode, byte[] input) {
        String keyAlgorithm = javaKey.getAlgorithm();
        if (!"RSA".equals(keyAlgorithm)) {
            logger.warning("Unexpected key type: " + keyAlgorithm);
            return null;
        }

        String jcaPadding;
        switch (openSSLPadding) {
            case NativeConstants.RSA_PKCS1_PADDING:
                // Since we're using this with a private key, this will produce RSASSA-PKCS1-v1_5
                // (signature) padding rather than RSAES-PKCS1-v1_5 (encryption) padding
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
        Cipher c;

        // Since this is a delegated key, we cannot handle providing a cipher using this key.
        // Otherwise we wouldn't end up in this class in the first place. The first step is to
        // try to get the most preferred provider as long as it isn't us.
        try {
            c = Cipher.getInstance(transformation);
            c.init(cipherMode, javaKey);

            // Ignore it if it points back to us.
            if (Conscrypt.isConscrypt(c.getProvider())) {
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
            List<Provider> providers = getExternalProviders("Cipher." + transformation);
            for (Provider p : providers) {
                try {
                    c = Cipher.getInstance(transformation, p);
                    c.init(cipherMode, javaKey);
                    break;
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
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
