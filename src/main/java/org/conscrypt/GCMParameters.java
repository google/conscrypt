/*
 * Copyright 2015 The Android Open Source Project
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

package org.conscrypt;

/**
 * GCM parameters used during an ciphering operation with {@link OpenSSLCipher}.
 * This class exists solely for backward compatibility with Android versions
 * that did not have the {@code GCMParameterSpec} class.
 */
public class GCMParameters {
    /** The tag length in bits. */
    public final int tLen;

    /** Actually the nonce value for the GCM operation. */
    public final byte[] iv;

    public GCMParameters(int tLen, byte[] iv) {
        this.tLen = tLen;
        this.iv = iv;
    }

    /**
     * Returns the tag length in bits.
     */
    public int getTLen() {
        return tLen;
    }

    /**
     * Returns a non-cloned version of the IV.
     */
    public byte[] getIV() {
        return iv;
    }
}
