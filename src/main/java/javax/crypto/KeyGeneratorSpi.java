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
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @com.intel.drl.spec_ref
 * 
 */
public abstract class KeyGeneratorSpi {
    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public KeyGeneratorSpi() {
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract SecretKey engineGenerateKey();

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract void engineInit(AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidAlgorithmParameterException;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract void engineInit(int keysize, SecureRandom random);

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract void engineInit(SecureRandom random);
}