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

package javax.crypto.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import org.apache.harmony.crypto.internal.nls.Messages;

/**
 * @com.intel.drl.spec_ref
 */
public class RC2ParameterSpec implements AlgorithmParameterSpec {

    private final int effectiveKeyBits;
    private final byte[] iv;

    /**
     * @com.intel.drl.spec_ref
     */
    public RC2ParameterSpec(int effectiveKeyBits) {
        this.effectiveKeyBits = effectiveKeyBits;
        iv = null;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public RC2ParameterSpec(int effectiveKeyBits, byte[] iv) {
        if (iv == null) {
            throw new IllegalArgumentException(Messages.getString("crypto.31")); //$NON-NLS-1$
        }
        if (iv.length < 8) {
            throw new IllegalArgumentException(Messages.getString("crypto.41")); //$NON-NLS-1$
        }
        this.effectiveKeyBits = effectiveKeyBits;
        this.iv = new byte[8];
        System.arraycopy(iv, 0, this.iv, 0, 8);
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public RC2ParameterSpec(int effectiveKeyBits, byte[] iv, int offset) {
        if (iv == null) {
            throw new IllegalArgumentException(Messages.getString("crypto.31")); //$NON-NLS-1$
        }
        if (iv.length - offset < 8) {
            throw new IllegalArgumentException(Messages.getString("crypto.41")); //$NON-NLS-1$
        }
        this.effectiveKeyBits = effectiveKeyBits;
        this.iv = new byte[8];
        System.arraycopy(iv, offset, this.iv, 0, 8);
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public int getEffectiveKeyBits() {
        return effectiveKeyBits;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public byte[] getIV() {
        if (iv == null) {
            return null;
        }
        byte[] result = new byte[iv.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        return result;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof RC2ParameterSpec)) {
            return false;
        }
        RC2ParameterSpec ps = (RC2ParameterSpec) obj;
        return (effectiveKeyBits == ps.effectiveKeyBits)
            && (Arrays.equals(iv, ps.iv));
    }

    /**
     * @com.intel.drl.spec_ref
     */
    @Override
    public int hashCode() {
        int result = effectiveKeyBits;
        if (iv == null) {
            return result;
        }
        for (byte element : iv) {
            result += element;
        }
        return result;
    }
}

