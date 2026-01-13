package org.conscrypt;

import java.security.KeyStore;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

/**
 * Shim for Java 7-only google3 builds that does nothing.
 */
public final class TrustManagerFactoryImpl extends TrustManagerFactorySpi  {
    public TrustManagerFactoryImpl() {
        throw new UnsupportedOperationException("Cannot use TrustManagerFactoryImpl on Java 7.");
    }

    protected TrustManager[] engineGetTrustManagers() {
        throw new UnsupportedOperationException("Cannot use TrustManagerFactoryImpl on Java 7.");
    }

    protected void engineInit(KeyStore ks) {
        throw new UnsupportedOperationException("Cannot use TrustManagerFactoryImpl on Java 7.");
    }

    protected void engineInit(ManagerFactoryParameters spec) {
        throw new UnsupportedOperationException("Cannot use TrustManagerFactoryImpl on Java 7.");
    }
}
