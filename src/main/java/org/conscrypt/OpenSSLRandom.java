/*
 * Copyright (C) 2012 The Android Open Source Project
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

import java.io.Serializable;
import java.security.SecureRandomSpi;

public class OpenSSLRandom extends SecureRandomSpi implements Serializable {
    private static final long serialVersionUID = 8506210602917522860L;

    private boolean mSeeded;

    @Override
    protected void engineSetSeed(byte[] seed) {
        if (seed == null) {
            throw new NullPointerException("seed == null");
        }

        // NOTE: The contract of the SecureRandomSpi does not appear to prohibit self-seeding here
        // (in addition to using the provided seed).
        selfSeedIfNotSeeded();
        NativeCrypto.RAND_seed(seed);
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        selfSeedIfNotSeeded();
        NativeCrypto.RAND_bytes(bytes);
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        selfSeedIfNotSeeded();
        byte[] output = new byte[numBytes];
        NativeCrypto.RAND_bytes(output);
        return output;
    }

    /**
     * Self-seeds this instance from the Linux RNG. Does nothing if this instance has already been
     * seeded.
     */
    private void selfSeedIfNotSeeded() {
        // NOTE: No need to worry about concurrent access to this field because the worst case is
        // that the code below is executed multiple times (by different threads), which may only
        // increase the entropy of the OpenSSL PRNG.
        if (mSeeded) {
            return;
        }

        seedOpenSSLPRNGFromLinuxRNG();
        mSeeded = true;
    }

    /**
     * Obtains a seed from the Linux RNG and mixes it into the OpenSSL PRNG (default RAND engine).
     *
     * <p>NOTE: This modifies the OpenSSL PRNG shared by all instances of OpenSSLRandom and other
     * crypto primitives offered by or built on top of OpenSSL.
     */
    public static void seedOpenSSLPRNGFromLinuxRNG() {
        int seedLengthInBytes = NativeCrypto.RAND_SEED_LENGTH_IN_BYTES;
        int bytesRead = NativeCrypto.RAND_load_file("/dev/urandom", seedLengthInBytes);
        if (bytesRead != seedLengthInBytes) {
            throw new SecurityException("Failed to read sufficient bytes from /dev/urandom."
                    + " Expected: " + seedLengthInBytes + ", actual: " + bytesRead);
        }
    }
}
