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
* @author Vera Y. Petrashkova
* @version $Revision$
*/

package javax.crypto;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import org.apache.harmony.crypto.internal.nls.Messages;
import org.apache.harmony.security.fortress.Engine;


/**
 * @com.intel.drl.spec_ref
 * 
 */

public class Mac implements Cloneable {

    //Used to access common engine functionality
    private static final Engine engine = new Engine("Mac"); //$NON-NLS-1$

    // Store used provider
    private final Provider provider;

    // Store used spi implementation
    private final MacSpi spiImpl;

    // Store used algorithm name
    private final String algorithm;

    // Store Mac state (initialized or not initialized)
    private boolean isInitMac;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected Mac(MacSpi macSpi, Provider provider, String algorithm) {
        this.provider = provider;
        this.algorithm = algorithm;
        this.spiImpl = macSpi;
        this.isInitMac = false;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final String getAlgorithm() {
        return algorithm;
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
     * throws NullPointerException if algorithm is null (instead of
     * NoSuchAlgorithmException as in 1.4 release)
     */
    public static final Mac getInstance(String algorithm)
            throws NoSuchAlgorithmException {
        if (algorithm == null) {
            throw new NullPointerException(Messages.getString("crypto.02")); //$NON-NLS-1$
        }
        synchronized (engine) {
            engine.getInstance(algorithm, null);
            return new Mac((MacSpi) engine.spi, engine.provider, algorithm);
        }
    }

    /**
     * @com.intel.drl.spec_ref
     * 
     * throws NullPointerException if algorithm is null (instead of
     * NoSuchAlgorithmException as in 1.4 release)
     */
    public static final Mac getInstance(String algorithm, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        if ((provider == null) || (provider.length() == 0)) {
            throw new IllegalArgumentException(Messages.getString("crypto.03")); //$NON-NLS-1$
        }
        Provider impProvider = Security.getProvider(provider);
        if (impProvider == null) {
            throw new NoSuchProviderException(provider);
        }
        return getInstance(algorithm, impProvider);
    }

    /**
     * @com.intel.drl.spec_ref
     * 
     * throws NullPointerException if algorithm is null (instead of
     * NoSuchAlgorithmException as in 1.4 release)
     */
    public static final Mac getInstance(String algorithm, Provider provider)
            throws NoSuchAlgorithmException {
        if (provider == null) {
            throw new IllegalArgumentException(Messages.getString("crypto.04")); //$NON-NLS-1$
        }
        if (algorithm == null) {
            throw new NullPointerException(Messages.getString("crypto.02")); //$NON-NLS-1$
        }
        synchronized (engine) {
            engine.getInstance(algorithm, provider, null);
            return new Mac((MacSpi) engine.spi, provider, algorithm);
        }
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final int getMacLength() {
        return spiImpl.engineGetMacLength();
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null) {
            throw new InvalidKeyException(Messages.getString("crypto.05")); //$NON-NLS-1$
        }
        spiImpl.engineInit(key, params);
        isInitMac = true;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException(Messages.getString("crypto.05")); //$NON-NLS-1$
        }
        try {
            spiImpl.engineInit(key, null);
            isInitMac = true;
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void update(byte input) throws IllegalStateException {
        if (!isInitMac) {
            throw new IllegalStateException(Messages.getString("crypto.01"));
        }
        spiImpl.engineUpdate(input);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void update(byte[] input, int offset, int len)
            throws IllegalStateException {
        if (!isInitMac) {
            throw new IllegalStateException(Messages.getString("crypto.01"));
        }
        if (input == null) {
            return;
        }
        if ((offset < 0) || (len < 0) || ((offset + len) > input.length)) {
            throw new IllegalArgumentException(Messages.getString("crypto.06")); //$NON-NLS-1$
        }
        spiImpl.engineUpdate(input, offset, len);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void update(byte[] input) throws IllegalStateException {
        if (!isInitMac) {
            throw new IllegalStateException(Messages.getString("crypto.01"));
        }
        if (input != null) {
            spiImpl.engineUpdate(input, 0, input.length);
        }
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void update(ByteBuffer input) {
        if (!isInitMac) {
            throw new IllegalStateException(Messages.getString("crypto.01"));
        }
        if (input != null) {
            spiImpl.engineUpdate(input);
        } else {
            throw new IllegalArgumentException(Messages.getString("crypto.07")); //$NON-NLS-1$
        }
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final byte[] doFinal() throws IllegalStateException {
        if (!isInitMac) {
            throw new IllegalStateException(Messages.getString("crypto.01"));
        }
        return spiImpl.engineDoFinal();
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void doFinal(byte[] output, int outOffset)
            throws ShortBufferException, IllegalStateException {
        if (!isInitMac) {
            throw new IllegalStateException(Messages.getString("crypto.01"));
        }
        if (output == null) {
            throw new ShortBufferException(Messages.getString("crypto.08")); //$NON-NLS-1$
        }
        if ((outOffset < 0) || (outOffset >= output.length)) {
            throw new ShortBufferException(Messages.getString("crypto.09", //$NON-NLS-1$
                    Integer.toString(outOffset)));
        }
        int t = spiImpl.engineGetMacLength();
        if (t > (output.length - outOffset)) {
            throw new ShortBufferException(
                    Messages.getString("crypto.0A", //$NON-NLS-1$
                            Integer.toString(t))); 
        }
        byte[] result = spiImpl.engineDoFinal();
        System.arraycopy(result, 0, output, outOffset, result.length);

    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final byte[] doFinal(byte[] input) throws IllegalStateException {
        if (!isInitMac) {
            throw new IllegalStateException(Messages.getString("crypto.0B")); //$NON-NLS-1$
        }
        if (input != null) {
            spiImpl.engineUpdate(input, 0, input.length);
        }
        return spiImpl.engineDoFinal();
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void reset() {
        spiImpl.engineReset();
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    @Override
    public final Object clone() throws CloneNotSupportedException {
        MacSpi newSpiImpl = (MacSpi)spiImpl.clone(); 
        Mac mac = new Mac(newSpiImpl, this.provider, this.algorithm);
        mac.isInitMac = this.isInitMac; 
        return mac;
    }
}
