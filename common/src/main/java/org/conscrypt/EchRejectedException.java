package org.conscrypt;

import javax.net.ssl.SSLHandshakeException;

/**
 * The server rejected the ECH Config List, and might have supplied an ECH
 * Retry Config.
 * 
 * @see NativeCrypto#SSL_get0_ech_retry_configs(long, NativeSsl)
 */
public class EchRejectedException extends SSLHandshakeException {
    private static final long serialVersionUID = 98723498273473923L;

    EchRejectedException(String message) {
        super(message);
    }
}

