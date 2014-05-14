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
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;

public class OpenSSLDHPrivateKey implements DHPrivateKey, OpenSSLKeyHolder {
    private static final long serialVersionUID = -7321023036951606638L;

    private transient OpenSSLKey key;

    /** base prime */
    private transient byte[] p;

    /** generator */
    private transient byte[] g;

    /** private key */
    private transient byte[] x;

    private transient Object mParamsLock = new Object();

    private transient boolean readParams;

    OpenSSLDHPrivateKey(OpenSSLKey key) {
        this.key = key;
    }

    @Override
    public OpenSSLKey getOpenSSLKey() {
        return key;
    }

    OpenSSLDHPrivateKey(DHPrivateKeySpec dhKeySpec) throws InvalidKeySpecException {
        try {
            key = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_DH(
                    dhKeySpec.getP().toByteArray(),
                    dhKeySpec.getG().toByteArray(),
                    null,
                    dhKeySpec.getX().toByteArray()));
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
            x = params[3];

            readParams = true;
        }
    }

    static OpenSSLKey getInstance(DHPrivateKey dhPrivateKey) throws InvalidKeyException {
        try {
            DHParameterSpec dhParams = dhPrivateKey.getParams();
            return new OpenSSLKey(NativeCrypto.EVP_PKEY_new_DH(
                    dhParams.getP().toByteArray(),
                    dhParams.getG().toByteArray(),
                    null,
                    dhPrivateKey.getX().toByteArray()));
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public String getAlgorithm() {
        return "DH";
    }

    @Override
    public String getFormat() {
        /*
         * If we're using an OpenSSL ENGINE, there's no guarantee we can export
         * the key. Returning {@code null} tells the caller that there's no
         * encoded format.
         */
        if (key.isEngineBased()) {
            return null;
        }

        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        /*
         * If we're using an OpenSSL ENGINE, there's no guarantee we can export
         * the key. Returning {@code null} tells the caller that there's no
         * encoded format.
         */
        if (key.isEngineBased()) {
            return null;
        }

        return NativeCrypto.i2d_PKCS8_PRIV_KEY_INFO(key.getPkeyContext());
    }

    @Override
    public DHParameterSpec getParams() {
        ensureReadParams();
        return new DHParameterSpec(new BigInteger(p), new BigInteger(g));
    }

    @Override
    public BigInteger getX() {
        if (key.isEngineBased()) {
            throw new UnsupportedOperationException("private key value X cannot be extracted");
        }

        ensureReadParams();
        return new BigInteger(x);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (o instanceof OpenSSLDHPrivateKey) {
            OpenSSLDHPrivateKey other = (OpenSSLDHPrivateKey) o;

            /*
             * We can shortcut the true case, but it still may be equivalent but
             * different copies.
             */
            if (key.equals(other.getOpenSSLKey())) {
                return true;
            }
        }

        if (!(o instanceof DHPrivateKey)) {
            return false;
        }

        ensureReadParams();

        final DHPrivateKey other = (DHPrivateKey) o;
        if (!x.equals(other.getX())) {
            return false;
        }

        DHParameterSpec spec = other.getParams();
        return g.equals(spec.getG()) && p.equals(spec.getP());
    }

    @Override
    public int hashCode() {
        ensureReadParams();
        int hash = 1;
        if (!key.isEngineBased()) {
            hash = hash * 3 + x.hashCode();
        }
        hash = hash * 7 + p.hashCode();
        hash = hash * 13 + g.hashCode();
        return hash;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("OpenSSLDHPrivateKey{");

        if (key.isEngineBased()) {
            sb.append("key=");
            sb.append(key);
            sb.append('}');
            return sb.toString();
        }

        ensureReadParams();
        sb.append("X=");
        sb.append(new BigInteger(x).toString(16));
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
        final BigInteger x = (BigInteger) stream.readObject();

        key = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_DH(
                p.toByteArray(),
                g.toByteArray(),
                null,
                x.toByteArray()));
        mParamsLock = new Object();
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        if (getOpenSSLKey().isEngineBased()) {
            throw new NotSerializableException("engine-based keys can not be serialized");
        }

        stream.defaultWriteObject();

        ensureReadParams();
        stream.writeObject(new BigInteger(g));
        stream.writeObject(new BigInteger(p));
        stream.writeObject(new BigInteger(x));
    }
}
