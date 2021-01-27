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

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;

/**
 * An implementation of a {@link java.security.PublicKey} for EC keys based on BoringSSL.
 */
final class OpenSSLECPublicKey implements ECPublicKey, OpenSSLKeyHolder {
    private static final long serialVersionUID = 3215842926808298020L;

    private static final String ALGORITHM = "EC";

    private transient OpenSSLKey key;

    private transient OpenSSLECGroupContext group;

    OpenSSLECPublicKey(OpenSSLECGroupContext group, OpenSSLKey key) {
        this.group = group;
        this.key = key;
    }

    OpenSSLECPublicKey(OpenSSLKey key) {
        this.group = new OpenSSLECGroupContext(new NativeRef.EC_GROUP(
                NativeCrypto.EC_KEY_get1_group(key.getNativeRef())));
        this.key = key;
    }

    OpenSSLECPublicKey(ECPublicKeySpec ecKeySpec) throws InvalidKeySpecException {
        try {
            group = OpenSSLECGroupContext.getInstance(ecKeySpec.getParams());
            OpenSSLECPointContext pubKey = OpenSSLECPointContext.getInstance(group,
                    ecKeySpec.getW());
            key = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_EC_KEY(group.getNativeRef(),
                    pubKey.getNativeRef(), null));
        } catch (Exception e) {
            throw new InvalidKeySpecException(e);
        }
    }

    static OpenSSLKey getInstance(ECPublicKey ecPublicKey) throws InvalidKeyException {
        try {
            OpenSSLECGroupContext group = OpenSSLECGroupContext
                    .getInstance(ecPublicKey.getParams());
            OpenSSLECPointContext pubKey = OpenSSLECPointContext.getInstance(group,
                    ecPublicKey.getW());
            return new OpenSSLKey(NativeCrypto.EVP_PKEY_new_EC_KEY(group.getNativeRef(),
                    pubKey.getNativeRef(), null));
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        return NativeCrypto.EVP_marshal_public_key(key.getNativeRef());
    }

    @Override
    public ECParameterSpec getParams() {
        return group.getECParameterSpec();
    }

    private ECPoint getPublicKey() {
        final OpenSSLECPointContext pubKey = new OpenSSLECPointContext(group,
                new NativeRef.EC_POINT(NativeCrypto.EC_KEY_get_public_key(key.getNativeRef())));

        return pubKey.getECPoint();
    }

    @Override
    public ECPoint getW() {
        return getPublicKey();
    }

    @Override
    public OpenSSLKey getOpenSSLKey() {
        return key;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (o instanceof OpenSSLECPublicKey) {
            OpenSSLECPublicKey other = (OpenSSLECPublicKey) o;
            return key.equals(other.key);
        }

        if (!(o instanceof ECPublicKey)) {
            return false;
        }

        final ECPublicKey other = (ECPublicKey) o;
        if (!getPublicKey().equals(other.getW())) {
            return false;
        }

        final ECParameterSpec spec = getParams();
        final ECParameterSpec otherSpec = other.getParams();

        return spec.getCurve().equals(otherSpec.getCurve())
                && spec.getGenerator().equals(otherSpec.getGenerator())
                && spec.getOrder().equals(otherSpec.getOrder())
                && spec.getCofactor() == otherSpec.getCofactor();
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(NativeCrypto.EVP_marshal_public_key(key.getNativeRef()));
    }

    @Override
    public String toString() {
        return NativeCrypto.EVP_PKEY_print_public(key.getNativeRef());
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject();

        byte[] encoded = (byte[]) stream.readObject();

        try {
            key = new OpenSSLKey(NativeCrypto.EVP_parse_public_key(encoded));
        } catch (ParsingException e) {
            throw new IOException(e);
        }
        group = new OpenSSLECGroupContext(new NativeRef.EC_GROUP(
                NativeCrypto.EC_KEY_get1_group(key.getNativeRef())));
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        if (key.isHardwareBacked()) {
            throw new NotSerializableException("Hardware backed keys cannot be serialized");
        }
        stream.defaultWriteObject();
        stream.writeObject(getEncoded());
    }
}
