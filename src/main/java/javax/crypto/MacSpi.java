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

import java.security.Key;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.nio.ByteBuffer;

/**
 * @com.intel.drl.spec_ref
 * 
 */

public abstract class MacSpi {
    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public MacSpi() {
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract int engineGetMacLength();

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract void engineUpdate(byte input);

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract void engineUpdate(byte[] input, int offset, int len);

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected void engineUpdate(ByteBuffer input) {
        if (!input.hasRemaining()) {
            return;
        }
        byte[] bInput;
        if (input.hasArray()) {
            bInput = input.array();
            int offset = input.arrayOffset();
            int position = input.position();
            int limit = input.limit();
            engineUpdate(bInput, offset + position, limit - position);
            input.position(limit);
        } else {
            bInput = new byte[input.limit() - input.position()];
            input.get(bInput);
            engineUpdate(bInput, 0, bInput.length);
        }
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract byte[] engineDoFinal();

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract void engineReset();

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    @Override
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}