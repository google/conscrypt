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

package org.apache.harmony.xnet.provider.jsse;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;

public class OpenSSLDSAParams implements DSAParams {

    private OpenSSLKey key;

    private boolean fetchedParams;

    private BigInteger g;

    private BigInteger p;

    private BigInteger q;

    private BigInteger y;

    private BigInteger x;

    OpenSSLDSAParams(OpenSSLKey key) {
        this.key = key;
    }

    private void ensureReadParams() {
        if (fetchedParams) {
            return;
        }

        byte[][] params = NativeCrypto.get_DSA_params(key.getPkeyContext());
        g = new BigInteger(params[0]);
        p = new BigInteger(params[1]);
        q = new BigInteger(params[2]);
        y = new BigInteger(params[3]);
        x = new BigInteger(params[4]);

        fetchedParams = true;
    }

    @Override
    public BigInteger getG() {
        ensureReadParams();
        return g;
    }

    @Override
    public BigInteger getP() {
        ensureReadParams();
        return p;
    }

    @Override
    public BigInteger getQ() {
        ensureReadParams();
        return q;
    }

    BigInteger getY() {
        ensureReadParams();
        return y;
    }

    BigInteger getX() {
        ensureReadParams();
        return x;
    }
}
