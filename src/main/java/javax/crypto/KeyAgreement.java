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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import org.apache.harmony.crypto.internal.nls.Messages;
import org.apache.harmony.security.fortress.Engine;


/**
 * @com.intel.drl.spec_ref
 * 
 */

public class KeyAgreement {

    // Used to access common engine functionality
    private static final Engine engine = new Engine("KeyAgreement"); //$NON-NLS-1$

    // Store SecureRandom
    private static final SecureRandom rndm = new SecureRandom();

    // Store used provider
    private final Provider provider;

    // Store used spi implementation
    private final KeyAgreementSpi spiImpl;

    // Store used algorithm name
    private final String algorithm;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected KeyAgreement(KeyAgreementSpi keyAgreeSpi, Provider provider,
            String algorithm) {
        this.provider = provider;
        this.algorithm = algorithm;
        this.spiImpl = keyAgreeSpi;
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
     */
    public static final KeyAgreement getInstance(String algorithm)
            throws NoSuchAlgorithmException {
        if (algorithm == null) {
            throw new NullPointerException(Messages.getString("crypto.02")); //$NON-NLS-1$
        }
        synchronized (engine) {
            engine.getInstance(algorithm, null);
            return new KeyAgreement((KeyAgreementSpi) engine.spi, engine.provider,
                    algorithm);
        }
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public static final KeyAgreement getInstance(String algorithm,
            String provider) throws NoSuchAlgorithmException,
            NoSuchProviderException {
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
     */
    public static final KeyAgreement getInstance(String algorithm,
            Provider provider) throws NoSuchAlgorithmException {
        if (provider == null) {
            throw new IllegalArgumentException(Messages.getString("crypto.04")); //$NON-NLS-1$
        }
        if (algorithm == null) {
            throw new NullPointerException(Messages.getString("crypto.02")); //$NON-NLS-1$
        }
        synchronized (engine) {
            engine.getInstance(algorithm, provider, null);
            return new KeyAgreement((KeyAgreementSpi) engine.spi, provider,
                    algorithm);
        }
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(Key key) throws InvalidKeyException {
        spiImpl.engineInit(key, rndm);//new SecureRandom());
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(Key key, SecureRandom random)
            throws InvalidKeyException {
        spiImpl.engineInit(key, random);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        spiImpl.engineInit(key, params, rndm);//new SecureRandom());
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final void init(Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        spiImpl.engineInit(key, params, random);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final Key doPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        return spiImpl.engineDoPhase(key, lastPhase);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final byte[] generateSecret() throws IllegalStateException {
        return spiImpl.engineGenerateSecret();
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final int generateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        return spiImpl.engineGenerateSecret(sharedSecret, offset);
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public final SecretKey generateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException,
            InvalidKeyException {
        return spiImpl.engineGenerateSecret(algorithm);
    }

}