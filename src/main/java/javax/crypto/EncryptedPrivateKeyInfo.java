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
* @author Vladimir N. Molotkov, Stepan M. Mishura
* @version $Revision$
*/

package javax.crypto;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.harmony.crypto.internal.nls.Messages;
import org.apache.harmony.security.asn1.ASN1Any;
import org.apache.harmony.security.asn1.ASN1Implicit;
import org.apache.harmony.security.asn1.ASN1Integer;
import org.apache.harmony.security.asn1.ASN1OctetString;
import org.apache.harmony.security.asn1.ASN1Sequence;
import org.apache.harmony.security.asn1.ASN1SetOf;
import org.apache.harmony.security.asn1.ASN1Type;
import org.apache.harmony.security.utils.AlgNameMapper;
import org.apache.harmony.security.x509.AlgorithmIdentifier;


/**
 * @com.intel.drl.spec_ref
 */
public class EncryptedPrivateKeyInfo {
    // Encryption algorithm name
    private String algName;
    // Encryption algorithm parameters
    private final AlgorithmParameters algParameters;
    // Encrypted private key data
    private final byte[] encryptedData;
    // Encryption algorithm OID
    private String oid;
    // This EncryptedPrivateKeyInfo ASN.1 DER encoding
    private volatile byte[] encoded;

    /**
     * @com.intel.drl.spec_ref
     */
    public EncryptedPrivateKeyInfo(byte[] encoded)
            throws IOException {
        if (encoded == null) {
            throw new NullPointerException(Messages.getString("crypto.22")); //$NON-NLS-1$
        }
        this.encoded = new byte[encoded.length];
        System.arraycopy(encoded, 0, this.encoded, 0, encoded.length);
        Object[] values;
            
        values = (Object[])asn1.decode(encoded);

        AlgorithmIdentifier aId = (AlgorithmIdentifier) values[0];

        algName = aId.getAlgorithm();
        // algName == oid now
        boolean mappingExists = mapAlgName();
        // algName == name from map oid->name if mapping exists, or
        // algName == oid if mapping does not exist

        AlgorithmParameters aParams = null;
        byte[] params = aId.getParameters();
        if (params != null && !isNullValue(params)) {
            try {
                aParams = AlgorithmParameters.getInstance(algName);
                aParams.init(aId.getParameters());
                if (!mappingExists) {
                    algName = aParams.getAlgorithm();
                }
            } catch (NoSuchAlgorithmException e) {
            }
        }
        algParameters = aParams;

        encryptedData = (byte[]) values[1];
    }

    private static boolean isNullValue(byte[] toCheck) {
        return toCheck[0] == 5 && toCheck[1] == 0;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public EncryptedPrivateKeyInfo(String encrAlgName, byte[] encryptedData)
        throws NoSuchAlgorithmException {
        if (encrAlgName == null) {
            throw new NullPointerException(Messages.getString("crypto.23")); //$NON-NLS-1$
        }
        this.algName = encrAlgName;
        if (!mapAlgName()) {
            throw new NoSuchAlgorithmException(Messages.getString("crypto.24", this.algName)); //$NON-NLS-1$
        }
        if (encryptedData == null) {
            throw new NullPointerException(
                    Messages.getString("crypto.25")); //$NON-NLS-1$
        }
        if (encryptedData.length == 0) {
            throw new IllegalArgumentException(Messages.getString("crypto.26")); //$NON-NLS-1$
        }
        this.encryptedData = new byte[encryptedData.length];
        System.arraycopy(encryptedData, 0,
                this.encryptedData, 0, encryptedData.length);
        this.algParameters = null;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public EncryptedPrivateKeyInfo(AlgorithmParameters algParams,
            byte[] encryptedData)
        throws NoSuchAlgorithmException {
        if (algParams == null) {
            throw new NullPointerException(Messages.getString("crypto.27")); //$NON-NLS-1$
        }
        this.algParameters = algParams;
        if (encryptedData == null) {
            throw new NullPointerException(
                    Messages.getString("crypto.25")); //$NON-NLS-1$
        }
        if (encryptedData.length == 0) {
            throw new IllegalArgumentException(Messages.getString("crypto.26")); //$NON-NLS-1$
        }
        this.encryptedData = new byte[encryptedData.length];
        System.arraycopy(encryptedData, 0,
                this.encryptedData, 0, encryptedData.length);
        this.algName = this.algParameters.getAlgorithm();
        if (!mapAlgName()) {
            throw new NoSuchAlgorithmException(Messages.getString("crypto.24", this.algName)); //$NON-NLS-1$
        }
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public String getAlgName() {
        return algName;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public AlgorithmParameters getAlgParameters() {
        return algParameters;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public byte[] getEncryptedData() {
        byte[] ret = new byte[encryptedData.length];
        System.arraycopy(encryptedData, 0, ret, 0, encryptedData.length);
        return ret;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public PKCS8EncodedKeySpec getKeySpec(Cipher cipher)
        throws InvalidKeySpecException {
        if (cipher == null) {
            throw new NullPointerException(Messages.getString("crypto.28")); //$NON-NLS-1$
        }
        try {
            byte[] decryptedData = cipher.doFinal(encryptedData);
            try {
                ASN1PrivateKeyInfo.verify(decryptedData);
            } catch (IOException e1) {
                throw new InvalidKeySpecException(
                        Messages.getString("crypto.29")); //$NON-NLS-1$
            }
            return new PKCS8EncodedKeySpec(decryptedData);
        } catch (IllegalStateException e) {
            throw new InvalidKeySpecException(e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new InvalidKeySpecException(e.getMessage());
        } catch (BadPaddingException e) {
            throw new InvalidKeySpecException(e.getMessage());
        }
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public PKCS8EncodedKeySpec getKeySpec(Key decryptKey)
        throws NoSuchAlgorithmException,
               InvalidKeyException {
        if (decryptKey == null) {
            throw new NullPointerException(Messages.getString("crypto.2A")); //$NON-NLS-1$
        }
        try {
            Cipher cipher = Cipher.getInstance(algName);
            if (algParameters == null) {
                cipher.init(Cipher.DECRYPT_MODE, decryptKey);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, decryptKey, algParameters);
            }
            byte[] decryptedData = cipher.doFinal(encryptedData);
            try {
                ASN1PrivateKeyInfo.verify(decryptedData);
            } catch (IOException e1) {
                throw new InvalidKeyException(
                        Messages.getString("crypto.29")); //$NON-NLS-1$
            }
            return new PKCS8EncodedKeySpec(decryptedData);
        } catch (NoSuchPaddingException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        } catch (IllegalStateException e) {
            throw new InvalidKeyException(e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new InvalidKeyException(e.getMessage());
        } catch (BadPaddingException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public PKCS8EncodedKeySpec getKeySpec(Key decryptKey, String providerName)
        throws NoSuchProviderException, 
               NoSuchAlgorithmException,
               InvalidKeyException {
        if (decryptKey == null) {
            throw new NullPointerException(Messages.getString("crypto.2A")); //$NON-NLS-1$
        }
        if (providerName == null) {
            throw new NullPointerException(
                    Messages.getString("crypto.2B")); //$NON-NLS-1$
        }
        try {
            Cipher cipher = Cipher.getInstance(algName, providerName);
            if (algParameters == null) {
                cipher.init(Cipher.DECRYPT_MODE, decryptKey);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, decryptKey, algParameters);
            }
            byte[] decryptedData = cipher.doFinal(encryptedData);
            try {
                ASN1PrivateKeyInfo.verify(decryptedData);
            } catch (IOException e1) {
                throw new InvalidKeyException(
                        Messages.getString("crypto.29")); //$NON-NLS-1$
            }
            return new PKCS8EncodedKeySpec(decryptedData);
        } catch (NoSuchPaddingException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        } catch (IllegalStateException e) {
            throw new InvalidKeyException(e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new InvalidKeyException(e.getMessage());
        } catch (BadPaddingException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public PKCS8EncodedKeySpec getKeySpec(Key decryptKey, Provider provider)
        throws NoSuchAlgorithmException,
               InvalidKeyException {
        if (decryptKey == null) {
            throw new NullPointerException(Messages.getString("crypto.2A")); //$NON-NLS-1$
        }
        if (provider == null) {
            throw new NullPointerException(Messages.getString("crypto.2C")); //$NON-NLS-1$
        }
        try {
            Cipher cipher = Cipher.getInstance(algName, provider);
            if (algParameters == null) {
                cipher.init(Cipher.DECRYPT_MODE, decryptKey);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, decryptKey, algParameters);
            }
            byte[] decryptedData = cipher.doFinal(encryptedData);
            try {
                ASN1PrivateKeyInfo.verify(decryptedData);
            } catch (IOException e1) {
                throw new InvalidKeyException(
                        Messages.getString("crypto.29")); //$NON-NLS-1$
            }
            return new PKCS8EncodedKeySpec(decryptedData);
        } catch (NoSuchPaddingException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        } catch (IllegalStateException e) {
            throw new InvalidKeyException(e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new InvalidKeyException(e.getMessage());
        } catch (BadPaddingException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public byte[] getEncoded() throws IOException {
        if (encoded == null) {
            // Generate ASN.1 encoding:
            encoded = asn1.encode(this);
        }
        byte[] ret = new byte[encoded.length];
        System.arraycopy(encoded, 0, ret, 0, encoded.length);
        return ret;
    }

    // Performs all needed alg name mappings.
    // Returns 'true' if mapping available 'false' otherwise
    private boolean mapAlgName() {
        if (AlgNameMapper.isOID(this.algName)) {
            // OID provided to the ctor
            // get rid of possible leading "OID."
            this.oid = AlgNameMapper.normalize(this.algName);
            // try to find mapping OID->algName
            this.algName = AlgNameMapper.map2AlgName(this.oid);
            // if there is no mapping OID->algName
            // set OID as algName
            if (this.algName == null) {
                this.algName = this.oid;
            }
        } else {
            String stdName = AlgNameMapper.getStandardName(this.algName);
            // Alg name provided to the ctor
            // try to find mapping algName->OID or
            // (algName->stdAlgName)->OID
            this.oid = AlgNameMapper.map2OID(this.algName);
            if (this.oid == null) {
                if (stdName == null) {
                    // no above mappings available
                    return false;
                }
                this.oid = AlgNameMapper.map2OID(stdName);
                if (this.oid == null) {
                    return false;
                }
                this.algName = stdName;
            } else if (stdName != null) {
                this.algName = stdName;
            }
        }
        return true;
    }

    //
    // EncryptedPrivateKeyInfo DER encoder/decoder.
    // EncryptedPrivateKeyInfo ASN.1 definition
    // (as defined in PKCS #8: Private-Key Information Syntax Standard
    //  http://www.ietf.org/rfc/rfc2313.txt)
    //
    // EncryptedPrivateKeyInfo ::=  SEQUENCE {
    //      encryptionAlgorithm   AlgorithmIdentifier,
    //      encryptedData   OCTET STRING }
    //

    private static final byte[] nullParam = new byte[] { 5, 0 };
    
    private static final ASN1Sequence asn1 = new ASN1Sequence(new ASN1Type[] {
            AlgorithmIdentifier.ASN1, ASN1OctetString.getInstance() }) {

                @Override
                protected void getValues(Object object, Object[] values) {
        
                    EncryptedPrivateKeyInfo epki = (EncryptedPrivateKeyInfo) object;
        
                    try {
                        byte[] algParmsEncoded = (epki.algParameters == null) ? nullParam
                                : epki.algParameters.getEncoded();
                        values[0] = new AlgorithmIdentifier(epki.oid, algParmsEncoded);
                        values[1] = epki.encryptedData;
                    } catch (IOException e) {
                        throw new RuntimeException(e.getMessage());
                    }
                }
    };

    // PrivateKeyInfo DER decoder.
    // PrivateKeyInfo ASN.1 definition
    // (as defined in PKCS #8: Private-Key Information Syntax Standard
    //  http://www.ietf.org/rfc/rfc2313.txt)
    //
    // 
    //    PrivateKeyInfo ::= SEQUENCE {
    //        version Version,
    //        privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
    //        privateKey PrivateKey,
    //        attributes [0] IMPLICIT Attributes OPTIONAL }
    //
    //      Version ::= INTEGER
    //
    //      PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
    //
    //      PrivateKey ::= OCTET STRING
    //
    //      Attributes ::= SET OF Attribute

    private static final ASN1SetOf ASN1Attributes = new ASN1SetOf(ASN1Any.getInstance());

    private static final ASN1Sequence ASN1PrivateKeyInfo = new ASN1Sequence(
            new ASN1Type[] { ASN1Integer.getInstance(), AlgorithmIdentifier.ASN1,
                    ASN1OctetString.getInstance(),
                    new ASN1Implicit(0, ASN1Attributes) }) {
        {
            setOptional(3); //attributes are optional
        }
    };
}
