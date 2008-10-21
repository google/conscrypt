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
* @author Alexander Y. Kleymenov
* @version $Revision$
*/

package javax.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.harmony.crypto.internal.nls.Messages;

/**
 * @com.intel.drl.spec_ref
 */
public class SealedObject implements Serializable {

    // the value of this field was derived by using serialver utility
    /**
     * @com.intel.drl.spec_ref
     */
    private static final long serialVersionUID = 4482838265551344752L;

    /**
     * @com.intel.drl.spec_ref
     */
    protected byte[] encodedParams;
    private byte[] encryptedContent;
    private String sealAlg;
    private String paramsAlg;

    private void readObject(ObjectInputStream s)
                throws IOException, ClassNotFoundException {
        encodedParams = (byte []) s.readUnshared();
        encryptedContent = (byte []) s.readUnshared();
        sealAlg = (String) s.readUnshared();
        paramsAlg = (String) s.readUnshared();
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public SealedObject(Serializable object, Cipher c)
                throws IOException, IllegalBlockSizeException {
        if (c == null) {
            throw new NullPointerException(Messages.getString("crypto.13")); //$NON-NLS-1$
        }
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(object);
            oos.flush();
            AlgorithmParameters ap = c.getParameters();
            this.encodedParams = (ap == null) ? null : ap.getEncoded();
            this.paramsAlg = (ap == null) ? null : ap.getAlgorithm();
            this.sealAlg = c.getAlgorithm();
            this.encryptedContent = c.doFinal(bos.toByteArray());
        } catch (BadPaddingException e) {
            // should be never thrown because the cipher
            // should be initialized for encryption
            throw new IOException(e.toString());
        }
    }

    /**
     * @com.intel.drl.spec_ref
     */
    protected SealedObject(SealedObject so) {
        if (so == null) {
            throw new NullPointerException(Messages.getString("crypto.14")); //$NON-NLS-1$
        }
        this.encryptedContent = so.encryptedContent;
        this.encodedParams = so.encodedParams;
        this.sealAlg = so.sealAlg;
        this.paramsAlg = so.paramsAlg;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public final String getAlgorithm() {
        return sealAlg;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public final Object getObject(Key key)
                throws IOException, ClassNotFoundException,
                       NoSuchAlgorithmException, InvalidKeyException {
        try {
            Cipher cipher = Cipher.getInstance(sealAlg);
            if ((paramsAlg != null) && (paramsAlg.length() != 0)) {
                AlgorithmParameters params =
                    AlgorithmParameters.getInstance(paramsAlg);
                params.init(encodedParams);
                cipher.init(Cipher.DECRYPT_MODE, key, params);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key);
            }
            byte[] serialized = cipher.doFinal(encryptedContent);
            ObjectInputStream ois =
                    new ObjectInputStream(
                            new ByteArrayInputStream(serialized));
            return ois.readObject();
        } catch (NoSuchPaddingException e)  {
            // should not be thrown because cipher text was made
            // with existing padding
            throw new NoSuchAlgorithmException(e.toString());
        } catch (InvalidAlgorithmParameterException e) {
            // should not be thrown because cipher text was made
            // with correct algorithm parameters
            throw new NoSuchAlgorithmException(e.toString());
        } catch (IllegalBlockSizeException e) {
            // should not be thrown because the cipher text
            // was correctly made
            throw new NoSuchAlgorithmException(e.toString());
        } catch (BadPaddingException e) {
            // should not be thrown because the cipher text
            // was correctly made
            throw new NoSuchAlgorithmException(e.toString());
        } catch (IllegalStateException  e) {
            // should never be thrown because cipher is initialized
            throw new NoSuchAlgorithmException(e.toString());
        }
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public final Object getObject(Cipher c)
                throws IOException, ClassNotFoundException,
                       IllegalBlockSizeException, BadPaddingException {
        if (c == null) {
            throw new NullPointerException(Messages.getString("crypto.13")); //$NON-NLS-1$
        }
        byte[] serialized = c.doFinal(encryptedContent);
        ObjectInputStream ois =
                new ObjectInputStream(
                        new ByteArrayInputStream(serialized));
        return ois.readObject();
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public final Object getObject(Key key, String provider)
                throws IOException, ClassNotFoundException,
                       NoSuchAlgorithmException, NoSuchProviderException,
                       InvalidKeyException {
        if ((provider == null) || (provider.length() == 0)) {
            throw new IllegalArgumentException(
                    Messages.getString("crypto.15")); //$NON-NLS-1$
        }
        try {
            Cipher cipher = Cipher.getInstance(sealAlg, provider);
            if ((paramsAlg != null) && (paramsAlg.length() != 0)) {
                AlgorithmParameters params =
                    AlgorithmParameters.getInstance(paramsAlg);
                params.init(encodedParams);
                cipher.init(Cipher.DECRYPT_MODE, key, params);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key);
            }
            byte[] serialized = cipher.doFinal(encryptedContent);
            ObjectInputStream ois =
                    new ObjectInputStream(
                            new ByteArrayInputStream(serialized));
            return ois.readObject();
        } catch (NoSuchPaddingException e)  {
            // should not be thrown because cipher text was made
            // with existing padding
            throw new NoSuchAlgorithmException(e.toString());
        } catch (InvalidAlgorithmParameterException e) {
            // should not be thrown because cipher text was made
            // with correct algorithm parameters
            throw new NoSuchAlgorithmException(e.toString());
        } catch (IllegalBlockSizeException e) {
            // should not be thrown because the cipher text
            // was correctly made
            throw new NoSuchAlgorithmException(e.toString());
        } catch (BadPaddingException e) {
            // should not be thrown because the cipher text
            // was correctly made
            throw new NoSuchAlgorithmException(e.toString());
        } catch (IllegalStateException  e) {
            // should never be thrown because cipher is initialized
            throw new NoSuchAlgorithmException(e.toString());
        }
    }
}

