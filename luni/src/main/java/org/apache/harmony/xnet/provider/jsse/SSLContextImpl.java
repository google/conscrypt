/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import org.apache.harmony.xnet.provider.jsse.SSLEngineImpl;

// BEGIN android-note
//  Modified heavily during SSLSessionContext refactoring. Added support for
//  persistent session caches.
// END android-note

/**
 * Implementation of SSLContext service provider interface.
 */
public class SSLContextImpl extends SSLContextSpi {

    /**
     * The default SSLContextImpl for use with SSLContext.getInstance("Default").
     * Protected by the DefaultSSLContextImpl.class monitor.
     */
    private static DefaultSSLContextImpl DEFAULT_SSL_CONTEXT_IMPL;

    /** Client session cache. */
    private final ClientSessionContext clientSessionContext;

    /** Server session cache. */
    private final ServerSessionContext serverSessionContext;

    protected SSLParameters sslParameters;

    public SSLContextImpl() {
        clientSessionContext = new ClientSessionContext();
        serverSessionContext = new ServerSessionContext();
    }
    /**
     * Constuctor for the DefaultSSLContextImpl.
     * @param dummy is null, used to distinguish this case from the
     * public SSLContextImpl() constructor.
     */
    protected SSLContextImpl(DefaultSSLContextImpl dummy)
            throws GeneralSecurityException, IOException {
        synchronized (DefaultSSLContextImpl.class) {
            if (DEFAULT_SSL_CONTEXT_IMPL == null) {
                clientSessionContext = new ClientSessionContext();
                serverSessionContext = new ServerSessionContext();
                DEFAULT_SSL_CONTEXT_IMPL = (DefaultSSLContextImpl)this;
            } else {
                clientSessionContext = DEFAULT_SSL_CONTEXT_IMPL.engineGetClientSessionContext();
                serverSessionContext = DEFAULT_SSL_CONTEXT_IMPL.engineGetServerSessionContext();
            }
            sslParameters = new SSLParameters(DEFAULT_SSL_CONTEXT_IMPL.getKeyManagers(),
                                              DEFAULT_SSL_CONTEXT_IMPL.getTrustManagers(),
                                              null,
                                              clientSessionContext,
                                              serverSessionContext);
        }
    }

    /**
     * Initializes this {@code SSLContext} instance. All of the arguments are
     * optional, and the security providers will be searched for the required
     * implementations of the needed algorithms.
     *
     * @param kms the key sources or {@code null}
     * @param tms the trust decision sources or {@code null}
     * @param sr the randomness source or {@code null}
     * @throws KeyManagementException if initializing this instance fails
     */
    @Override
    public void engineInit(KeyManager[] kms, TrustManager[] tms,
            SecureRandom sr) throws KeyManagementException {
        sslParameters = new SSLParameters(kms, tms, sr,
                                          clientSessionContext, serverSessionContext);
    }

    /**
     * @deprecated call setPersistentCache directly on the result of
     * engineGetClientSessionContext() or
     * engineGetServerSessionContext
     */
    public void engineInit(KeyManager[] kms, TrustManager[] tms,
            SecureRandom sr, SSLClientSessionCache clientCache,
            SSLServerSessionCache serverCache) throws KeyManagementException {
        engineInit(kms, tms, sr);
        engineGetClientSessionContext().setPersistentCache(clientCache);
        engineGetServerSessionContext().setPersistentCache(serverCache);
    }

    public SSLSocketFactory engineGetSocketFactory() {
        if (sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initialized.");
        }
        return new OpenSSLSocketFactoryImpl(sslParameters);
    }

    @Override
    public SSLServerSocketFactory engineGetServerSocketFactory() {
        if (sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initialized.");
        }
        return new OpenSSLServerSocketFactoryImpl(sslParameters);
    }

    @Override
    public SSLEngine engineCreateSSLEngine(String host, int port) {
        if (sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initialized.");
        }
        SSLParameters p = (SSLParameters) sslParameters.clone();
        p.setUseClientMode(false);
        return new SSLEngineImpl(host, port, p);
    }

    @Override
    public SSLEngine engineCreateSSLEngine() {
        if (sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initialized.");
        }
        SSLParameters p = (SSLParameters) sslParameters.clone();
        p.setUseClientMode(false);
        return new SSLEngineImpl(p);
    }

    @Override
    public ServerSessionContext engineGetServerSessionContext() {
        return serverSessionContext;
    }

    @Override
    public ClientSessionContext engineGetClientSessionContext() {
        return clientSessionContext;
    }

    @Override
    public javax.net.ssl.SSLParameters engineGetDefaultSSLParameters() {
        return createSSLParameters(false);
    }

    @Override
    public javax.net.ssl.SSLParameters engineGetSupportedSSLParameters() {
        return createSSLParameters(true);
    }

    private SSLParameters createSSLParameters (boolean supported) {
        try {
            SSLSocket s = (SSLSocket) engineGetSocketFactory().createSocket();
            javax.net.ssl.SSLParameters p = new javax.net.ssl.SSLParameters();
            String[] cipherSuites;
            String[] protocols;
            if (supported) {
                cipherSuites = s.getSupportedCipherSuites();
                protocols    = s.getSupportedProtocols();
            } else {
                cipherSuites = s.getEnabledCipherSuites();
                protocols    = s.getEnabledProtocols();
            }
            p.setCipherSuites(cipherSuites);
            p.setProtocols(protocols);
            p.setNeedClientAuth(s.getNeedClientAuth());
            p.setWantClientAuth(s.getWantClientAuth());
            return p;
        } catch (IOException e) {
            /*
             * SSLContext.getDefaultSSLParameters specifies to throw
             * UnsupportedOperationException if there is a problem getting the
             * parameters
             */
            throw new UnsupportedOperationException("Could not access supported SSL parameters");
        }
    }
}
