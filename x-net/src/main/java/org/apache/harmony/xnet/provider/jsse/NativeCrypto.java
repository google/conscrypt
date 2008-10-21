/*
 * Copyright (C) 2008 The Android Open Source Project
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

package org.apache.harmony.xnet.provider.jsse;

/**
 * Provides the Java side of our JNI glue for OpenSSL. Currently only hashing
 * and verifying are covered. Is expected to grow over time. Also needs to move
 * into libcore/openssl at some point.
 */
public class NativeCrypto {

    static {
        // Need to ensure that OpenSSL initialization is done exactly once.
        // This can be cleaned up later, when all OpenSSL glue moves into its
        // own libcore module. Make it run, make it nice.
        OpenSSLSocketImpl.class.getClass();
    }

    // --- DSA/RSA public/private key handling functions -----------------------
    
    public static native int EVP_PKEY_new_DSA(byte[] p, byte[] q, byte[] g, byte[] priv_key, byte[] pub_key);

    public static native int EVP_PKEY_new_RSA(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q);
    
    public static native void EVP_PKEY_free(int pkey);
  
  // --- RSA public/private key handling functions ---------------------------
  
//  public static native int rsaCreatePublicKey(byte[] n, byte[] e);
//  
//  public static native int rsaCreatePrivateKey(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q);
//
//  public static native void rsaDestroyKey(int rsa);
    
    // --- DSA public/private key handling functions ---------------------------
    
//    public static native int dsaCreatePublicKey(byte[] p, byte[] q, byte[] g, byte[] pub_key);
//    
//    public static native int dsaCreatePrivateKey(byte[] p, byte[] q, byte[] g, byte[] priv_key, byte[] pub_key);
//
//    public static native void dsaDestroyKey(int dsa);
    
    // --- RSA public/private key handling functions ---------------------------
    
//    public static native int rsaCreatePublicKey(byte[] n, byte[] e);
//    
//    public static native int rsaCreatePrivateKey(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q);
//
//    public static native void rsaDestroyKey(int rsa);
    
    // --- General context handling functions (despite the names) --------------
    
    public static native int EVP_new();
    
    public static native void EVP_free(int ctx);
    
    // --- Digest handling functions -------------------------------------------
    
    public static native void EVP_DigestInit(int ctx, String algorithm);
    
    public static native void EVP_DigestUpdate(int ctx, byte[] buffer, int offset, int length);

    public static native int EVP_DigestFinal(int ctx, byte[] hash, int offset);

    public static native int EVP_DigestSize(int ctx);

    public static native int EVP_DigestBlockSize(int ctx);
    
    // --- Signature handling functions ----------------------------------------
    
    public static native void EVP_VerifyInit(int ctx, String algorithm);
    
    public static native void EVP_VerifyUpdate(int ctx, byte[] buffer, int offset, int length);
    
    public static native int EVP_VerifyFinal(int ctx, byte[] signature, int offset, int length, int key);
    
}
