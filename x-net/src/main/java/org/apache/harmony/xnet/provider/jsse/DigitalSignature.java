/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/**
 * @author Boris Kuznetsov
 * @version $Revision$
 */
package org.apache.harmony.xnet.provider.jsse;

import org.apache.harmony.xnet.provider.jsse.AlertException;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.net.ssl.SSLException;

/**
 * This class represents Signature type, as descrybed in TLS v 1.0 Protocol
 * specification, 7.4.3. It allow to init, update and sign hash. Hash algorithm
 * depends on SignatureAlgorithm.
 * 
 * select (SignatureAlgorithm)
 *       {   case anonymous: struct { };
 *           case rsa:
 *               digitally-signed struct {
 *                   opaque md5_hash[16];
 *                   opaque sha_hash[20];
 *               };
 *           case dsa:
 *               digitally-signed struct {
 *                   opaque sha_hash[20];
 *               };
 *       } Signature;
 * 
 * Digital signing description see in TLS spec., 4.7.
 * (http://www.ietf.org/rfc/rfc2246.txt)
 *  
 */
public class DigitalSignature {

    private MessageDigest md5 = null;
    private MessageDigest sha = null;
    private Signature signature = null;
    private Cipher cipher = null;
    
    private byte[] md5_hash;
    private byte[] sha_hash;
     
    /**
     * Create Signature type
     * @param keyExchange
     */
    public DigitalSignature(int keyExchange) {
        try { 
            if (keyExchange == CipherSuite.KeyExchange_RSA_EXPORT ||
                    keyExchange == CipherSuite.KeyExchange_RSA ||
                    keyExchange == CipherSuite.KeyExchange_DHE_RSA ||
                    keyExchange == CipherSuite.KeyExchange_DHE_RSA_EXPORT) {
                // SignatureAlgorithm is rsa
                md5 = MessageDigest.getInstance("MD5");
                sha = MessageDigest.getInstance("SHA-1");
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            } else if (keyExchange == CipherSuite.KeyExchange_DHE_DSS ||
                    keyExchange == CipherSuite.KeyExchange_DHE_DSS_EXPORT ) {
                // SignatureAlgorithm is dsa
                sha = MessageDigest.getInstance("SHA-1");
                signature = Signature.getInstance("NONEwithDSA");
// The Signature should be empty in case of anonimous signature algorithm:
//            } else if (keyExchange == CipherSuite.KeyExchange_DH_anon ||
//                    keyExchange == CipherSuite.KeyExchange_DH_anon_EXPORT) {            
//
            }
        } catch (Exception e) {
            throw new AlertException(
                    AlertProtocol.INTERNAL_ERROR,
                    new SSLException(
                            "INTERNAL ERROR: Unexpected exception on digital signature",
                            e));
        }    
            
    }
    
    /**
     * Initiate Signature type by private key
     * @param key
     */
    public void init(PrivateKey key) {
        try {
            if (signature != null) {
                signature.initSign(key);
            } else if (cipher != null) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            }
        } catch (Exception e){
            e.printStackTrace();
        }
    }
    
    /**
     * Initiate Signature type by certificate
     * @param cert
     */
    public void init(Certificate cert) {
        try {
            if (signature != null) {
                signature.initVerify(cert);
            } else if (cipher != null) {
                cipher.init(Cipher.DECRYPT_MODE, cert);
            }
        } catch (Exception e){
            e.printStackTrace();
        }
    }
    
    /**
     * Update Signature hash
     * @param data
     */
    public void update(byte[] data) {
        try {
            if (sha != null) {
                sha.update(data);
            }
            if (md5 != null) {
                md5.update(data);
            }
        } catch (Exception e){
            e.printStackTrace();
        }        
    }
    
    /**
     * Sets MD5 hash
     * @param data
     */
    public void setMD5(byte[] data) {
        md5_hash = data;    
    }
    
    /**
     * Sets SHA hash
     * @param data
     */
    public void setSHA(byte[] data) {
        sha_hash = data;    
    }
    
    /**
     * Sign hash
     * @return Signature bytes
     */
    public byte[] sign() {
        try {
            if (md5 != null && md5_hash == null) {
                md5_hash = new byte[16];
                md5.digest(md5_hash, 0, md5_hash.length);
            }    
            if (md5_hash != null) {
                if (signature != null) {
                    signature.update(md5_hash);
                } else if (cipher != null) {
                    cipher.update(md5_hash);
                }
            }
            if (sha != null && sha_hash == null) {
                sha_hash = new byte[20];
                sha.digest(sha_hash, 0, sha_hash.length);
            }
            if (sha_hash != null) {
                if (signature != null) {
                    signature.update(sha_hash);
                } else if (cipher != null) {
                    cipher.update(sha_hash);
                }
            }
            if (signature != null) {
                return signature.sign();
            } else if (cipher != null) {
                return cipher.doFinal();
            } 
            return new byte[0];
        } catch (Exception e){
            e.printStackTrace();
            return new byte[0];
        }    
    }

    /**
     * Verifies the signature data. 
     * @param data - the signature bytes 
     * @return true if verified
     */
    public boolean verifySignature(byte[] data) {
        try {
            if (signature != null) {
                return signature.verify(data);
            } else if (cipher != null) {
                byte[] decrypt = cipher.doFinal(data);
                byte[] md5_sha;
                if (md5_hash != null && sha_hash != null) {
                    md5_sha = new byte[md5_hash.length + sha_hash.length];
                    System.arraycopy(md5_hash, 0, md5_sha, 0, md5_hash.length);
                    System.arraycopy(sha_hash, 0, md5_sha, md5_hash.length, sha_hash.length);
                } else if (md5_hash != null) {
                    md5_sha = md5_hash;
                } else {
                    md5_sha = sha_hash;
                }
                if (Arrays.equals(decrypt, md5_sha)) {
                    return true;
                } else {
                    return false;
                }
            } else if (data == null || data.length == 0) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e){
                e.printStackTrace();
                return false;
        }
    }

}
