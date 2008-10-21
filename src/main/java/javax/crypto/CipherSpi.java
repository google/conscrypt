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

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.nio.ByteBuffer;

import org.apache.harmony.crypto.internal.nls.Messages;

/**
 * @com.intel.drl.spec_ref
 * 
 */

public abstract class CipherSpi {

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    public CipherSpi() {
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract void engineSetMode(String mode)
            throws NoSuchAlgorithmException;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract void engineSetPadding(String padding)
            throws NoSuchPaddingException;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract int engineGetBlockSize();

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract int engineGetOutputSize(int inputLen);

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract byte[] engineGetIV();

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract AlgorithmParameters engineGetParameters();

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract void engineInit(int opmode, Key key,
            AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract void engineInit(int opmode, Key key,
            AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract byte[] engineUpdate(byte[] input, int inputOffset,
            int inputLen);

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract int engineUpdate(byte[] input, int inputOffset,
            int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected int engineUpdate(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException {
        if (input == null) {
            throw new NullPointerException(Messages.getString("crypto.0C")); //$NON-NLS-1$
        }
        if (output == null) {
            throw new NullPointerException(Messages.getString("crypto.0D")); //$NON-NLS-1$
        }
        int position = input.position();
        int limit = input.limit();
        if ((limit - position) <= 0) {
            return 0;
        }
        byte[] bInput;
        byte[] bOutput;
        if (input.hasArray()) {
            bInput = input.array();
            int offset = input.arrayOffset();
            bOutput = engineUpdate(bInput, offset + position, limit - position);
            input.position(limit);
        } else {
            bInput = new byte[limit - position];
            input.get(bInput);
            bOutput = engineUpdate(bInput, 0, limit - position);
        }
        if (output.remaining() < bOutput.length) {
            throw new ShortBufferException(Messages.getString("crypto.0E")); //$NON-NLS-1$
        }
        try {
            output.put(bOutput);
        } catch (java.nio.BufferOverflowException e) {
            throw new ShortBufferException(Messages.getString("crypto.0F", e)); //$NON-NLS-1$
        }
        return bOutput.length;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract byte[] engineDoFinal(byte[] input, int inputOffset,
            int inputLen) throws IllegalBlockSizeException, BadPaddingException;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected abstract int engineDoFinal(byte[] input, int inputOffset,
            int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException;

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected int engineDoFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
        if (input == null) {
            throw new NullPointerException(Messages.getString("crypto.0C")); //$NON-NLS-1$
        }
        if (output == null) {
            throw new NullPointerException(Messages.getString("crypto.0D")); //$NON-NLS-1$
        }
        int position = input.position();
        int limit = input.limit();

        if ((limit - position) <= 0) {
            return 0;
        }
        byte[] bInput;
        byte[] bOutput;

        if (input.hasArray()) {
            bInput = input.array();
            int offset = input.arrayOffset();
            bOutput = engineDoFinal(bInput, offset + position, limit - position);
            input.position(limit);
        } else {
            bInput = new byte[limit - position];
            input.get(bInput);
            bOutput = engineDoFinal(bInput, 0, limit - position);
        }
        if (output.remaining() < bOutput.length) {
            throw new ShortBufferException(Messages.getString("crypto.0E")); //$NON-NLS-1$
        }
        try {
            output.put(bOutput);
        } catch (java.nio.BufferOverflowException e) {
            throw new ShortBufferException(Messages.getString("crypto.0F", e)); //$NON-NLS-1$
        }
        return bOutput.length;
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException,
            InvalidKeyException {
        throw new UnsupportedOperationException(
                Messages.getString("crypto.10")); //$NON-NLS-1$
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
            int wrappedKeyType) throws InvalidKeyException,
            NoSuchAlgorithmException {
        throw new UnsupportedOperationException(
                Messages.getString("crypto.11")); //$NON-NLS-1$
    }

    /**
     * @com.intel.drl.spec_ref
     *  
     */
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        throw new UnsupportedOperationException(
                Messages.getString("crypto.12")); //$NON-NLS-1$
    }
}