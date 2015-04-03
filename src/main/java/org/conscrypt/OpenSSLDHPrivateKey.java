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

import java.io.InvalidObjectException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;

@SuppressWarnings("serial") // Uses a serialization proxy
public class OpenSSLDHPrivateKey implements DHPrivateKey, OpenSSLKeyHolder {
    private final OpenSSLKey key;

    /** base prime */
    private byte[] p;

    /** generator */
    private byte[] g;

    /** private key */
    private byte[] x;

    private final Object mParamsLock = new Object();

    private boolean readParams;

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

            byte[][] params = NativeCrypto.get_DH_params(key.getNativeRef());

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

        return NativeCrypto.i2d_PKCS8_PRIV_KEY_INFO(key.getNativeRef());
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

    private void readObject(ObjectInputStream stream) throws InvalidObjectException {
        throw new InvalidObjectException("Proxy required to serialize");
    }

    private Object writeReplace() throws NotSerializableException {
        if (getOpenSSLKey().isEngineBased()) {
            throw new NotSerializableException("engine-based keys can not be serialized");
        }

        return new SerializationProxy(this);
    }

    /**
     * Serialization proxy ensures that the lock used in the parent can be final
     * so it is initialized at all times.
     */
    private static class SerializationProxy implements Serializable {
        private static final long serialVersionUID = -7321023036951606638L;

        private final BigInteger g;
        private final BigInteger p;
        private final BigInteger x;

        public SerializationProxy(OpenSSLDHPrivateKey key) {
            DHParameterSpec spec = key.getParams();

            g = spec.getG();
            p = spec.getP();
            x = key.getX();
        }

        private Object readResolve() {
            return new OpenSSLDHPrivateKey(new OpenSSLKey(NativeCrypto.EVP_PKEY_new_DH(
                    p.toByteArray(), g.toByteArray(), null, x.toByteArray())));
        }
    }
}
