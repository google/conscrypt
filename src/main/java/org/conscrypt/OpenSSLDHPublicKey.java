/*
 * Copyright (C) 2014 The Android Open Source Project
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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

public class OpenSSLDHPublicKey implements DHPublicKey, OpenSSLKeyHolder {
    private static final long serialVersionUID = 6123717708079837723L;

    private transient OpenSSLKey key;

    /** base prime */
    private transient byte[] p;

    /** generator */
    private transient byte[] g;

    /** public key */
    private transient byte[] y;

    private transient final Object mParamsLock = new Object();

    private transient boolean readParams;

    OpenSSLDHPublicKey(OpenSSLKey key) {
        this.key = key;
    }

    @Override
    public OpenSSLKey getOpenSSLKey() {
        return key;
    }

    OpenSSLDHPublicKey(DHPublicKeySpec dsaKeySpec) throws InvalidKeySpecException {
        try {
            key = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_DH(
                    dsaKeySpec.getP().toByteArray(),
                    dsaKeySpec.getG().toByteArray(),
                    dsaKeySpec.getY().toByteArray(),
                    null));
        } catch (Exception e) {
            throw new InvalidKeySpecException(e);
        }
    }

    private void ensureReadParams() {
        synchronized (mParamsLock) {
            if (readParams) {
                return;
            }

            byte[][] params = NativeCrypto.get_DH_params(key.getPkeyContext());

            p = params[0];
            g = params[1];
            y = params[2];

            readParams = true;
        }
    }

    static OpenSSLKey getInstance(DHPublicKey DHPublicKey) throws InvalidKeyException {
        try {
            final DHParameterSpec dhParams = DHPublicKey.getParams();
            return new OpenSSLKey(NativeCrypto.EVP_PKEY_new_DH(
                    dhParams.getP().toByteArray(),
                    dhParams.getG().toByteArray(),
                    DHPublicKey.getY().toByteArray(),
                    null));
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public DHParameterSpec getParams() {
        ensureReadParams();
        return new DHParameterSpec(new BigInteger(p), new BigInteger(g));
    }

    @Override
    public String getAlgorithm() {
        return "DH";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        return NativeCrypto.i2d_PUBKEY(key.getPkeyContext());
    }

    @Override
    public BigInteger getY() {
        ensureReadParams();
        return new BigInteger(y);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (o instanceof OpenSSLDHPublicKey) {
            OpenSSLDHPublicKey other = (OpenSSLDHPublicKey) o;

            /*
             * We can shortcut the true case, but it still may be equivalent but
             * different copies.
             */
            if (key.equals(other.getOpenSSLKey())) {
                return true;
            }
        }

        if (!(o instanceof DHPublicKey)) {
            return false;
        }

        ensureReadParams();

        final DHPublicKey other = (DHPublicKey) o;
        if (!y.equals(other.getY())) {
            return false;
        }

        DHParameterSpec spec = other.getParams();
        return g.equals(spec.getG()) && p.equals(spec.getP());
    }

    @Override
    public int hashCode() {
        ensureReadParams();
        int hash = 1;
        hash = hash * 3 + y.hashCode();
        hash = hash * 7 + p.hashCode();
        hash = hash * 13 + g.hashCode();
        return hash;
    }


    @Override
    public String toString() {
        ensureReadParams();

        final StringBuilder sb = new StringBuilder("OpenSSLDHPublicKey{");
        sb.append("Y=");
        sb.append(new BigInteger(y).toString(16));
        sb.append(',');
        sb.append("P=");
        sb.append(new BigInteger(p).toString(16));
        sb.append(',');
        sb.append("G=");
        sb.append(new BigInteger(g).toString(16));
        sb.append('}');

        return sb.toString();
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject();

        final BigInteger g = (BigInteger) stream.readObject();
        final BigInteger p = (BigInteger) stream.readObject();
        final BigInteger y = (BigInteger) stream.readObject();

        key = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_DH(
                p.toByteArray(),
                g.toByteArray(),
                y.toByteArray(),
                null));
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        stream.defaultWriteObject();

        ensureReadParams();
        stream.writeObject(new BigInteger(g));
        stream.writeObject(new BigInteger(p));
        stream.writeObject(new BigInteger(y));
    }
}
