package org.conscrypt;

/**
 * A stub utility for bootstrapping the native library. This is included only for building purposes
 * and should be overridden in the platform-specific builds.
 */
class NativeCryptoJni {
    static void init() {
        throw new UnsupportedOperationException();
    }
}
