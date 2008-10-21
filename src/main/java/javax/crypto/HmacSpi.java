/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package javax.crypto;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;


/**
 * Internal class implementing HMAC
 */
class HmacSpi extends MacSpi
{
    protected byte[] engineDoFinal()
    {
        byte[] result = native_compute_sha1_hmac(mKey.getEncoded(), mData.toByteArray());
        engineReset();
        return result;
    }

    protected int engineGetMacLength()
    {
        throw new UnsupportedOperationException("Not implemented");
    }

    protected void engineInit(Key key, AlgorithmParameterSpec params)
                            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        mKey = key;
        mData = null;
    }

    protected void engineReset()
    {
        synchronized (mSync) {
            mData = null;
        }
    }

    protected void engineUpdate(byte input)
    {
        synchronized (mSync) {
            if (mData == null) {
                mData = new ByteArrayOutputStream();
            }
            mData.write(input);
        }
    }

    protected void engineUpdate(byte[] input, int offset, int len)
    {
        synchronized (mSync) {
            if (mData == null) {
                mData = new ByteArrayOutputStream();
            }
            mData.write(input, offset, len);
        }
    }

    private native byte[] native_compute_sha1_hmac(byte[] key, byte[] data);

    private Key mKey;
    private ByteArrayOutputStream mData;
    private Object mSync = new Object();
}

