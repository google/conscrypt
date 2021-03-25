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
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;

/**
 * An implementation of a {@link PrivateKey} for EC keys based on BoringSSL.
 */
final class OpenSSLECPrivateKey implements ECPrivateKey, OpenSSLKeyHolder {
    private static final long serialVersionUID = -4036633595001083922L;

    private static final String ALGORITHM = "EC";

    private transient OpenSSLKey key;

    private transient OpenSSLECGroupContext group;

    OpenSSLECPrivateKey(OpenSSLECGroupContext group, OpenSSLKey key) {
        this.group = group;
        this.key = key;
    }

    OpenSSLECPrivateKey(OpenSSLKey key) {
        this.group = new OpenSSLECGroupContext(new NativeRef.EC_GROUP(
                NativeCrypto.EC_KEY_get1_group(key.getNativeRef())));
        this.key = key;
    }

    OpenSSLECPrivateKey(ECPrivateKeySpec ecKeySpec) throws InvalidKeySpecException {
        try {
            group = OpenSSLECGroupContext.getInstance(ecKeySpec.getParams());
            final BigInteger privKey = ecKeySpec.getS();
            key = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_EC_KEY(group.getNativeRef(), null,
                    privKey.toByteArray()));
        } catch (Exception e) {
            throw new InvalidKeySpecException(e);
        }
    }

    static OpenSSLKey wrapPlatformKey(ECPrivateKey ecPrivateKey) throws InvalidKeyException {
        OpenSSLECGroupContext group;
        try {
            group = OpenSSLECGroupContext.getInstance(ecPrivateKey.getParams());
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException("Unknown group parameters", e);
        }
        return wrapPlatformKey(ecPrivateKey, group);
    }

    /**
     * Wraps the provided private key for use in the TLS/SSL stack only. Sign/decrypt operations
     * using the key will be delegated to the {@code Signature}/{@code Cipher} implementation of the
     * provider which accepts the key.
     */
    static OpenSSLKey wrapJCAPrivateKeyForTLSStackOnly(PrivateKey privateKey,
            PublicKey publicKey) throws InvalidKeyException {
        ECParameterSpec params = null;
        if (privateKey instanceof ECKey) {
            params = ((ECKey) privateKey).getParams();
        } else if (publicKey instanceof ECKey) {
            params = ((ECKey) publicKey).getParams();
        }
        if (params == null) {
            throw new InvalidKeyException("EC parameters not available. Private: " + privateKey
                    + ", public: " + publicKey);
        }
        return wrapJCAPrivateKeyForTLSStackOnly(privateKey, params);
    }

    /**
     * Wraps the provided private key for use in the TLS/SSL stack only. Sign/decrypt operations
     * using the key will be delegated to the {@code Signature}/{@code Cipher} implementation of the
     * provider which accepts the key.
     */
    static OpenSSLKey wrapJCAPrivateKeyForTLSStackOnly(PrivateKey privateKey,
            ECParameterSpec params) throws InvalidKeyException {
        if (params == null) {
            if (privateKey instanceof ECKey) {
                params = ((ECKey) privateKey).getParams();
            }
        }
        if (params == null) {
            throw new InvalidKeyException("EC parameters not available: " + privateKey);
        }

        OpenSSLECGroupContext group;
        try {
            group = OpenSSLECGroupContext.getInstance(params);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException("Invalid EC parameters: " + params);
        }

        return new OpenSSLKey(
                NativeCrypto.getECPrivateKeyWrapper(privateKey, group.getNativeRef()), true);
    }

    private static OpenSSLKey wrapPlatformKey(ECPrivateKey ecPrivateKey,
            OpenSSLECGroupContext group) throws InvalidKeyException {
        return new OpenSSLKey(NativeCrypto.getECPrivateKeyWrapper(ecPrivateKey,
                group.getNativeRef()), true);
    }

    static OpenSSLKey getInstance(ECPrivateKey ecPrivateKey) throws InvalidKeyException {
        try {
            OpenSSLECGroupContext group = OpenSSLECGroupContext.getInstance(ecPrivateKey
                    .getParams());

            /*
             * If the key is not encodable (PKCS11-like key), then wrap it and
             * use JNI upcalls to satisfy requests.
             */
            if (ecPrivateKey.getFormat() == null) {
                return wrapPlatformKey(ecPrivateKey, group);
            }

            final BigInteger privKey = ecPrivateKey.getS();
            return new OpenSSLKey(NativeCrypto.EVP_PKEY_new_EC_KEY(group.getNativeRef(), null,
                    privKey.toByteArray()));
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
        if (key.isHardwareBacked()) {
            return null;
        }
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        if (key.isHardwareBacked()) {
            return null;
        }
        return NativeCrypto.EVP_marshal_private_key(key.getNativeRef());
    }

    @Override
    public ECParameterSpec getParams() {
        return group.getECParameterSpec();
    }

    @Override
    public BigInteger getS() {
        if (key.isHardwareBacked()) {
            throw new UnsupportedOperationException("Private key value S cannot be extracted");
        }
        return getPrivateKey();
    }

    private BigInteger getPrivateKey() {
        return new BigInteger(NativeCrypto.EC_KEY_get_private_key(key.getNativeRef()));
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

        if (o instanceof OpenSSLECPrivateKey) {
            OpenSSLECPrivateKey other = (OpenSSLECPrivateKey) o;
            return key.equals(other.key);
        }

        if (!(o instanceof ECPrivateKey)) {
            return false;
        }

        final ECPrivateKey other = (ECPrivateKey) o;
        if (!getPrivateKey().equals(other.getS())) {
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
        return Arrays.hashCode(NativeCrypto.EVP_marshal_private_key(key.getNativeRef()));
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("OpenSSLECPrivateKey{");
        sb.append("params={");
        sb.append(NativeCrypto.EVP_PKEY_print_params(key.getNativeRef()));
        sb.append("}}");
        return sb.toString();
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject();

        byte[] encoded = (byte[]) stream.readObject();

        try {
            key = new OpenSSLKey(NativeCrypto.EVP_parse_private_key(encoded));
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
