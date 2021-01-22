package org.conscrypt;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class OpenSSLX25519PublicKey implements OpenSSLX25519Key, PublicKey {
    private static final byte[] X509_PREAMBLE = new byte[] {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
    };

    private static final byte[] X509_PREAMBLE_WITH_NULL = new byte[] {
            0x30, 0x2C, 0x30, 0x07, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x05, 0x00, 0x03, 0x21, 0x00,
    };

    private byte[] uCoordinate;

    public OpenSSLX25519PublicKey(X509EncodedKeySpec keySpec) throws InvalidKeySpecException {
        byte[] encoded = keySpec.getEncoded();
        if (encoded == null || !"X.509".equals(keySpec.getFormat())) {
            throw new InvalidKeySpecException("Encoding must be in X.509 format");
        }

        int preambleLength = matchesPreamble(X509_PREAMBLE, encoded) | matchesPreamble(X509_PREAMBLE_WITH_NULL, encoded);
        if (preambleLength == 0) {
            throw new InvalidKeySpecException("Key size is not correct size");
        }

        uCoordinate = Arrays.copyOfRange(encoded, preambleLength, encoded.length);
    }

    private static int matchesPreamble(byte[] preamble, byte[] encoded) {
        if (encoded.length != (preamble.length + X25519_KEY_SIZE_BYTES)) {
            return 0;
        }
        int cmp = 0;
        for (int i = 0; i < preamble.length; i++) {
            cmp |= encoded[i] ^ preamble[i];
        }
        if (cmp != 0) {
            return 0;
        }
        return preamble.length;
    }

    public OpenSSLX25519PublicKey(byte[] coordinateBytes) {
        uCoordinate = coordinateBytes.clone();
    }

    @Override
    public String getAlgorithm() {
        return "XDH";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        if (uCoordinate == null) {
            throw new IllegalStateException("key is destroyed");
        }

        byte[] encoded = Arrays.copyOf(X509_PREAMBLE, X509_PREAMBLE.length + X25519_KEY_SIZE_BYTES);
        System.arraycopy(uCoordinate, 0, encoded, X509_PREAMBLE.length, uCoordinate.length);
        return encoded;
    }

    @Override
    public byte[] getU() {
        if (uCoordinate == null) {
            throw new IllegalStateException("key is destroyed");
        }

        return uCoordinate.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (uCoordinate == null) {
            throw new IllegalStateException("key is destroyed");
        }

        if (this == o) return true;
        if (!(o instanceof OpenSSLX25519PublicKey)) return false;
        OpenSSLX25519PublicKey that = (OpenSSLX25519PublicKey) o;
        return Arrays.equals(uCoordinate, that.uCoordinate);
    }

    @Override
    public int hashCode() {
        if (uCoordinate == null) {
            throw new IllegalStateException("key is destroyed");
        }

        return Arrays.hashCode(uCoordinate);
    }
}
