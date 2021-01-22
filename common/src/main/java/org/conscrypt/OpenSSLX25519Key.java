package org.conscrypt;

public interface OpenSSLX25519Key {
    int X25519_KEY_SIZE_BYTES = 32;

    byte[] getU();
}
