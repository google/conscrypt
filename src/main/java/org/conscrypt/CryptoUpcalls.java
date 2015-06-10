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
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Provides a place where NativeCrypto can call back up to do Java language
 * calls to work on delegated key types from native code.
 */
public final class CryptoUpcalls {

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

        Provider p = getExternalProvider("Signature." + algorithm);
        if (p == null) {
            return null;
        }

        // Get the Signature for this key.
        Signature signature;
        try {
            signature = Signature.getInstance(algorithm, p);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Unsupported signature algorithm: " + algorithm);
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

    public static byte[] rsaDecryptWithPrivateKey(PrivateKey javaKey, int openSSLPadding,
            byte[] input) {
        String keyAlgorithm = javaKey.getAlgorithm();
        if (!"RSA".equals(keyAlgorithm)) {
            System.err.println("Unexpected key type: " + keyAlgorithm);
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
                System.err.println("Unsupported OpenSSL/BoringSSL padding: " + openSSLPadding);
                return null;
        }

        String transformation = "RSA/ECB/" + jcaPadding;
        Provider p = getExternalProvider("Cipher." + transformation);
        if (p == null) {
            return null;
        }

        Cipher c = null;
        try {
            c = Cipher.getInstance(transformation, p);
        } catch (NoSuchAlgorithmException e) {
            ;
        } catch (NoSuchPaddingException e) {
            ;
        }

        if (c == null) {
            System.err.println("Unsupported transformation: " + transformation);
            return null;
        }

        try {
            c.init(Cipher.DECRYPT_MODE, javaKey);
            return c.doFinal(input);
        } catch (Exception e) {
            System.err.println("Exception while decrypting message with " + javaKey.getAlgorithm()
                    + " private key using " + transformation + ":");
            e.printStackTrace();
            return null;
        }
    }
}
