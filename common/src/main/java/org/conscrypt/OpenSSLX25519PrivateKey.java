package org.conscrypt;

import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class OpenSSLX25519PrivateKey implements OpenSSLX25519Key, PrivateKey {
    private static final byte[] PKCS8_PREAMBLE = new byte[]{
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
    };

    private static final byte[] PKCS8_PREAMBLE_WITH_NULL = new byte[] {
            0x30, 0x30, 0x02, 0x01, 0x00, 0x30, 0x07, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x05, 0x00, 0x04, 0x22, 0x04, 0x20,
    };

    private byte[] uCoordinate;

    public OpenSSLX25519PrivateKey(PKCS8EncodedKeySpec keySpec) throws InvalidKeySpecException {
        byte[] encoded = keySpec.getEncoded();
        if (encoded == null || !"PKCS#8".equals(keySpec.getFormat())) {
            throw new InvalidKeySpecException("Key must be encoded in PKCS#8 format");
        }

        int preambleLength = matchesPreamble(PKCS8_PREAMBLE, encoded) | matchesPreamble(PKCS8_PREAMBLE_WITH_NULL, encoded);
        if (preambleLength == 0) {
            throw new InvalidKeySpecException("Key size is not correct size");
        }

        uCoordinate = Arrays.copyOfRange(encoded, PKCS8_PREAMBLE.length, encoded.length);
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

    public OpenSSLX25519PrivateKey(byte[] coordinateBytes) {
        uCoordinate = coordinateBytes.clone();
    }

    @Override
    public String getAlgorithm() {
        return "XDH";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        if (uCoordinate == null) {
            throw new IllegalStateException("key is destroyed");
        }

        byte[] encoded = Arrays.copyOf(PKCS8_PREAMBLE, PKCS8_PREAMBLE.length + uCoordinate.length);
        System.arraycopy(uCoordinate, 0, encoded, PKCS8_PREAMBLE.length, uCoordinate.length);
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
    public void destroy() {
        if (uCoordinate != null) {
            Arrays.fill(uCoordinate, (byte) 0);
            uCoordinate = null;
        }
    }

    @Override
    public boolean isDestroyed() {
        return uCoordinate == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OpenSSLX25519PrivateKey)) return false;
        OpenSSLX25519PrivateKey that = (OpenSSLX25519PrivateKey) o;
        return Arrays.equals(uCoordinate, that.uCoordinate);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(uCoordinate);
    }
}