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
* @author Boris V. Kuznetsov
* @version $Revision$
*/

package javax.crypto;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.harmony.crypto.internal.NullCipherSpi;
import org.apache.harmony.crypto.internal.nls.Messages;
import org.apache.harmony.security.fortress.Engine;

/**
 * @com.intel.drl.spec_ref
 * 
 */
public class Cipher {

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final int DECRYPT_MODE = 2;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final int ENCRYPT_MODE = 1;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final int PRIVATE_KEY = 2;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final int PUBLIC_KEY = 1;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final int SECRET_KEY = 3;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final int UNWRAP_MODE = 4;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final int WRAP_MODE = 3;

    private int mode;

    /**
     * The service name.
     */
    private static final String SERVICE = "Cipher"; //$NON-NLS-1$

    /**
     * Used to access common engine functionality
     */
    private static final Engine engine = new Engine(SERVICE);

    /**
     * The provider
     */
    private Provider provider;

    /**
     * The SPI implementation.
     */
    private CipherSpi spiImpl;

    /**
     * The transformation.
     */
    private String transformation;

    private static SecureRandom sec_rand;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected Cipher(CipherSpi cipherSpi, Provider provider,
            String transformation) {
        if (cipherSpi == null) {
            throw new NullPointerException();
        }
        if (!(cipherSpi instanceof NullCipherSpi) && provider == null) {
            throw new NullPointerException();
        }
        this.provider = provider;
        this.transformation = transformation;
        this.spiImpl = cipherSpi;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final Cipher getInstance(String transformation)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        return getCipher(transformation, null);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final Cipher getInstance(String transformation,
            String provider) throws NoSuchAlgorithmException,
            NoSuchProviderException, NoSuchPaddingException {

        if (provider == null) {
            throw new IllegalArgumentException(Messages.getString("crypto.04")); //$NON-NLS-1$
        }

        Provider p = Security.getProvider(provider);
        if (p == null) {
            throw new NoSuchProviderException(Messages.getString("crypto.16", provider)); //$NON-NLS-1$
        }
        return getInstance(transformation, p);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final Cipher getInstance(String transformation,
            Provider provider) throws NoSuchAlgorithmException,
            NoSuchPaddingException {
        if (provider == null) {
            throw new IllegalArgumentException(Messages.getString("crypto.04")); //$NON-NLS-1$
        }
        Cipher c = getCipher(transformation, provider);
        return c;
    }

    /**
     * Find appropriate Cipher according the specification rules
     * 
     * @param transformation
     * @param provider
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    private static synchronized Cipher getCipher(String transformation, Provider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {

        if (transformation == null || "".equals(transformation)) { //$NON-NLS-1$
            throw new NoSuchAlgorithmException(Messages.getString("crypto.17", //$NON-NLS-1$
                    transformation));
        }

        String[] transf = checkTransformation(transformation);

        boolean needSetPadding = false;
        boolean needSetMode = false;
        if (transf[1] == null && transf[2] == null) { // "algorithm"
            if (provider == null) {
                engine.getInstance(transf[0], null);
            } else {
                engine.getInstance(transf[0], provider, null);
            }
        } else {
            String[] searhOrder = {
                    transf[0] + "/" + transf[1] + "/" + transf[2], // "algorithm/mode/padding" //$NON-NLS-1$ //$NON-NLS-2$
                    transf[0] + "/" + transf[1], // "algorithm/mode" //$NON-NLS-1$
                    transf[0] + "//" + transf[2], // "algorithm//padding" //$NON-NLS-1$
                    transf[0] // "algorithm"
            };
            int i;
            for (i = 0; i < searhOrder.length; i++) {
                try {
                    if (provider == null) {
                        engine.getInstance(searhOrder[i], null);
                    } else {
                        engine.getInstance(searhOrder[i], provider, null);
                    }
                    break;
                } catch (NoSuchAlgorithmException e) {
                    if ( i == searhOrder.length-1) {
                        throw new NoSuchAlgorithmException(transformation);
                    }
                }
            }
            switch (i) {
            case 1: // "algorithm/mode"
                needSetPadding = true;
                break;
            case 2: // "algorithm//padding"
                needSetMode = true;
                break;
            case 3: // "algorithm"
                needSetPadding = true;
                needSetMode = true;
            }
        }
        CipherSpi cspi;
        try {
            cspi = (CipherSpi) engine.spi;
        } catch (ClassCastException e) {
            throw new NoSuchAlgorithmException(e);
        }
        Cipher c = new Cipher(cspi, engine.provider, transformation);
        if (needSetMode) {
            c.spiImpl.engineSetMode(transf[1]);
        }
        if (needSetPadding) {
            c.spiImpl.engineSetPadding(transf[2]);
        }
        return c;
    }

    private static String[] checkTransformation(String transformation)
            throws NoSuchAlgorithmException {
        String[] transf = { null, null, null };
        StringTokenizer st;
        int i = 0;
        for (st = new StringTokenizer(transformation, "/"); st //$NON-NLS-1$
                .hasMoreElements();) {
            if (i > 2) {
                throw new NoSuchAlgorithmException(Messages.getString("crypto.17", //$NON-NLS-1$
                        transformation));
            }
            transf[i] = st.nextToken();
            if (transf[i] != null) {
                transf[i] = transf[i].trim();
                if ("".equals(transf[i])) { //$NON-NLS-1$
                    transf[i] = null;
                }
                i++;
            }
        }
        if (transf[0] == null) {
            throw new NoSuchAlgorithmException(Messages.getString("crypto.17", //$NON-NLS-1$
                    transformation));
        }
        if (!(transf[1] == null && transf[2] == null)
                && (transf[1] == null || transf[2] == null)) {
            throw new NoSuchAlgorithmException(Messages.getString("crypto.17", //$NON-NLS-1$
                    transformation));
        }
        return transf;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final Provider getProvider() {
        return provider;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final String getAlgorithm() {
        return transformation;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final int getBlockSize() {
        return spiImpl.engineGetBlockSize();
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final int getOutputSize(int inputLen) {
        if (mode == 0) {
            throw new IllegalStateException(
                    Messages.getString("crypto.18")); //$NON-NLS-1$
        }
        return spiImpl.engineGetOutputSize(inputLen);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final byte[] getIV() {
        return spiImpl.engineGetIV();
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final AlgorithmParameters getParameters() {
        return spiImpl.engineGetParameters();
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final ExemptionMechanism getExemptionMechanism() {
        //FIXME implement getExemptionMechanism

        //        try {
        //            return ExemptionMechanism.getInstance(transformation, provider);
        //        } catch (NoSuchAlgorithmException e) {
        return null;
        //        }

    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(int opmode, Key key) throws InvalidKeyException {
        if (sec_rand == null) {
            // In theory it might be thread-unsafe but in the given case it's OK
            // since it does not matter which SecureRandom instance is passed
            // to the init()
            sec_rand = new SecureRandom();
        }
        init(opmode, key, sec_rand);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
        if (opmode != ENCRYPT_MODE && opmode != DECRYPT_MODE
                && opmode != UNWRAP_MODE && opmode != WRAP_MODE) {
            throw new InvalidParameterException(Messages.getString("crypto.19")); //$NON-NLS-1$
        }
        //        FIXME InvalidKeyException
        //        if keysize exceeds the maximum allowable keysize
        //        (jurisdiction policy files)
        spiImpl.engineInit(opmode, key, random);
        mode = opmode;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(int opmode, Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (sec_rand == null) {
            sec_rand = new SecureRandom();
        }
        init(opmode, key, params, sec_rand);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        if (opmode != ENCRYPT_MODE && opmode != DECRYPT_MODE
                && opmode != UNWRAP_MODE && opmode != WRAP_MODE) {
            throw new InvalidParameterException(Messages.getString("crypto.19")); //$NON-NLS-1$
        }
        //        FIXME InvalidKeyException
        //        if keysize exceeds the maximum allowable keysize
        //        (jurisdiction policy files)
        //        FIXME InvalidAlgorithmParameterException
        //        cryptographic strength exceed the legal limits
        //        (jurisdiction policy files)
        spiImpl.engineInit(opmode, key, params, random);
        mode = opmode;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(int opmode, Key key, AlgorithmParameters params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (sec_rand == null) {
            sec_rand = new SecureRandom();
        }
        init(opmode, key, params, sec_rand);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(int opmode, Key key, AlgorithmParameters params,
            SecureRandom random) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        if (opmode != ENCRYPT_MODE && opmode != DECRYPT_MODE
                && opmode != UNWRAP_MODE && opmode != WRAP_MODE) {
            throw new InvalidParameterException(Messages.getString("crypto.19")); //$NON-NLS-1$
        }
        //        FIXME InvalidKeyException
        //        if keysize exceeds the maximum allowable keysize
        //        (jurisdiction policy files)
        //        FIXME InvalidAlgorithmParameterException
        //        cryptographic strength exceed the legal limits
        //        (jurisdiction policy files)
        spiImpl.engineInit(opmode, key, params, random);
        mode = opmode;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(int opmode, Certificate certificate)
            throws InvalidKeyException {
        if (sec_rand == null) {
            sec_rand = new SecureRandom();
        }
        init(opmode, certificate, sec_rand);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(int opmode, Certificate certificate,
            SecureRandom random) throws InvalidKeyException {
        if (opmode != ENCRYPT_MODE && opmode != DECRYPT_MODE
                && opmode != UNWRAP_MODE && opmode != WRAP_MODE) {
            throw new InvalidParameterException(Messages.getString("crypto.19")); //$NON-NLS-1$
        }
        if (certificate instanceof X509Certificate) {
            Set<String> ce = ((X509Certificate) certificate).getCriticalExtensionOIDs();
            boolean critical = false;
            if (ce != null && !ce.isEmpty()) {
                for (String oid : ce) {
                    if (oid.equals("2.5.29.15")) { //KeyUsage OID = 2.5.29.15 //$NON-NLS-1$
                        critical = true;
                        break;
                    }
                }
                if (critical) {
                    boolean[] keyUsage = ((X509Certificate) certificate)
                            .getKeyUsage();
                    // As specified in RFC 3280 -
                    // Internet X.509 Public Key Infrastructure
                    // Certificate and Certificate Revocation List (CRL) Profile.
                    // (http://www.ietf.org/rfc/rfc3280.txt)
                    //
                    // KeyUsage ::= BIT STRING {digitalSignature (0),
                    //                          ...
                    //                          encipherOnly (7),
                    //                          decipherOnly (8) }
                    if (keyUsage != null) {
                        if (opmode == ENCRYPT_MODE && (!keyUsage[7])) {
                            throw new InvalidKeyException(
                                    Messages.getString("crypto.1A")); //$NON-NLS-1$
                        } else if (opmode == DECRYPT_MODE && (!keyUsage[8])) {
                            throw new InvalidKeyException(
                                    Messages.getString("crypto.1B")); //$NON-NLS-1$
                        }
                    }
                }
            }
        }
        //        FIXME InvalidKeyException
        //        if keysize exceeds the maximum allowable keysize
        //        (jurisdiction policy files)
        spiImpl.engineInit(opmode, certificate.getPublicKey(), random);
        mode = opmode;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final byte[] update(byte[] input) {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE) {
            throw new IllegalStateException(
                    Messages.getString("crypto.1C")); //$NON-NLS-1$
        }
        if (input == null) {
            throw new IllegalArgumentException(Messages.getString("crypto.1D")); //$NON-NLS-1$
        }
        if (input.length == 0) {
            return null;
        }
        return spiImpl.engineUpdate(input, 0, input.length);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final byte[] update(byte[] input, int inputOffset, int inputLen) {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE) {
            throw new IllegalStateException(
                    Messages.getString("crypto.1C")); //$NON-NLS-1$
        }
        if (input == null) {
            throw new IllegalArgumentException(Messages.getString("crypto.1D")); //$NON-NLS-1$
        }
        if (inputOffset < 0 || inputLen < 0
                || inputLen > input.length 
                || inputOffset > input.length - inputLen) {
            throw new IllegalArgumentException(
                    Messages.getString("crypto.1E")); //$NON-NLS-1$
        }
        if (input.length == 0) {
            return null;
        }
        return spiImpl.engineUpdate(input, inputOffset, inputLen);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final int update(byte[] input, int inputOffset, int inputLen,
            byte[] output) throws ShortBufferException {
        return update(input, inputOffset, inputLen, output, 0);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final int update(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset) throws ShortBufferException {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE) {
            throw new IllegalStateException(
                    Messages.getString("crypto.1C")); //$NON-NLS-1$
        }
        if (input == null) {
            throw new IllegalArgumentException(Messages.getString("crypto.1D")); //$NON-NLS-1$
        }
        if (output == null) {
            throw new IllegalArgumentException(Messages.getString("crypto.1F")); //$NON-NLS-1$
        }
        if (outputOffset < 0) {
            throw new IllegalArgumentException(
                    Messages.getString("crypto.20")); //$NON-NLS-1$
        }
        if (inputOffset < 0 || inputLen < 0
                || inputLen > input.length
                || inputOffset > input.length - inputLen) {
            throw new IllegalArgumentException(
                    Messages.getString("crypto.21")); //$NON-NLS-1$
        }
        if (input.length == 0) {
            return 0;
        }
        return spiImpl.engineUpdate(input, inputOffset, inputLen, output,
                outputOffset);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final int update(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE) {
            throw new IllegalStateException(
                    Messages.getString("crypto.1C")); //$NON-NLS-1$
        }
        if (input == output) {
            throw new IllegalArgumentException(
                    Messages.getString("crypto.22")); //$NON-NLS-1$
        }
        return spiImpl.engineUpdate(input, output);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final byte[] doFinal() throws IllegalBlockSizeException,
            BadPaddingException {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE) {
            throw new IllegalStateException(
                    Messages.getString("crypto.1C")); //$NON-NLS-1$
        }
        return spiImpl.engineDoFinal(null, 0, 0);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final int doFinal(byte[] output, int outputOffset)
            throws IllegalBlockSizeException, ShortBufferException,
            BadPaddingException {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE) {
            throw new IllegalStateException(
                    Messages.getString("crypto.1C")); //$NON-NLS-1$
        }
        if (outputOffset < 0) {
            throw new IllegalArgumentException(
                    Messages.getString("crypto.20")); //$NON-NLS-1$
        }
        return spiImpl.engineDoFinal(null, 0, 0, output, outputOffset);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final byte[] doFinal(byte[] input) throws IllegalBlockSizeException,
            BadPaddingException {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE) {
            throw new IllegalStateException(
                    Messages.getString("crypto.1C")); //$NON-NLS-1$
        }
        return spiImpl.engineDoFinal(input, 0, input.length);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final byte[] doFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE) {
            throw new IllegalStateException(
                    Messages.getString("crypto.1C")); //$NON-NLS-1$
        }
        if (inputOffset < 0 || inputLen < 0
                || inputOffset + inputLen > input.length) {
            throw new IllegalArgumentException(
                    Messages.getString("crypto.1E")); //$NON-NLS-1$
        }
        return spiImpl.engineDoFinal(input, inputOffset, inputLen);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final int doFinal(byte[] input, int inputOffset, int inputLen,
            byte[] output) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
        return doFinal(input, inputOffset, inputLen, output, 0);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final int doFinal(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE) {
            throw new IllegalStateException(
                    Messages.getString("crypto.1C")); //$NON-NLS-1$
        }
        if (inputOffset < 0 || inputLen < 0
                || inputOffset + inputLen > input.length) {
            throw new IllegalArgumentException(
                    Messages.getString("crypto.1E")); //$NON-NLS-1$
        }
        return spiImpl.engineDoFinal(input, inputOffset, inputLen, output,
                outputOffset);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final int doFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE) {
            throw new IllegalStateException(
                    Messages.getString("crypto.1C")); //$NON-NLS-1$
        }
        if (input == output) {
            throw new IllegalArgumentException(
                    Messages.getString("crypto.2E")); //$NON-NLS-1$
        }
        return spiImpl.engineDoFinal(input, output);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final byte[] wrap(Key key) throws IllegalBlockSizeException,
            InvalidKeyException {
        if (mode != WRAP_MODE) {
            throw new IllegalStateException(
                    Messages.getString("crypto.1C")); //$NON-NLS-1$
        }
        return spiImpl.engineWrap(key);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
            int wrappedKeyType) throws InvalidKeyException,
            NoSuchAlgorithmException {
        if (mode != UNWRAP_MODE) {
            throw new IllegalStateException(
                    Messages.getString("crypto.1C")); //$NON-NLS-1$
        }
        return spiImpl.engineUnwrap(wrappedKey, wrappedKeyAlgorithm,
                wrappedKeyType);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final int getMaxAllowedKeyLength(String transformation)
            throws NoSuchAlgorithmException {
        if (transformation == null) {
            throw new NullPointerException();
        }
        checkTransformation(transformation);
        //FIXME jurisdiction policy files
        return Integer.MAX_VALUE;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final AlgorithmParameterSpec getMaxAllowedParameterSpec(
            String transformation) throws NoSuchAlgorithmException {
        if (transformation == null) {
            throw new NullPointerException();
        }
        checkTransformation(transformation);
        //FIXME jurisdiction policy files
        return null;
    }
}
