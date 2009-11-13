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

import org.apache.harmony.xnet.provider.jsse.SSLEngineImpl;
import org.apache.harmony.xnet.provider.jsse.SSLParameters;
// BEGIN android-removed
// import org.apache.harmony.xnet.provider.jsse.SSLServerSocketFactoryImpl;
// END android-removed

import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

// BEGIN android-note
//  Modified heavily during SSLSessionContext refactoring. Added support for
//  persistent session caches.
// END android-note

/**
 * Implementation of SSLContext service provider interface.
 */
public class SSLContextImpl extends SSLContextSpi {

    /** Client session cache. */
    private ClientSessionContext clientSessionContext;

    /** Server session cache. */
    private ServerSessionContext serverSessionContext;

    protected SSLParameters sslParameters;

    public SSLContextImpl() {
        super();
    }

    @Override
    public void engineInit(KeyManager[] kms, TrustManager[] tms,
            SecureRandom sr) throws KeyManagementException {
        engineInit(kms, tms, sr, null, null);
    }

    /**
     * Initializes this {@code SSLContext} instance. All of the arguments are
     * optional, and the security providers will be searched for the required
     * implementations of the needed algorithms.
     *
     * @param kms the key sources or {@code null}
     * @param tms the trust decision sources or {@code null}
     * @param sr the randomness source or {@code null}
     * @param clientCache persistent client session cache or {@code null}
     * @param serverCache persistent server session cache or {@code null}
     * @throws KeyManagementException if initializing this instance fails
     * 
     * @since Android 1.1
     */
    public void engineInit(KeyManager[] kms, TrustManager[] tms,
            SecureRandom sr, SSLClientSessionCache clientCache,
            SSLServerSessionCache serverCache) throws KeyManagementException {
        sslParameters = new SSLParameters(kms, tms, sr,
                clientCache, serverCache);
        clientSessionContext = sslParameters.getClientSessionContext();
        serverSessionContext = sslParameters.getServerSessionContext();
    }

    public SSLSocketFactory engineGetSocketFactory() {
        if (sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initiallized.");
        }
        return new OpenSSLSocketFactoryImpl(sslParameters);
    }

    @Override
    public SSLServerSocketFactory engineGetServerSocketFactory() {
        if (sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initiallized.");
        }
        return new OpenSSLServerSocketFactoryImpl(sslParameters);
    }

    @Override
    public SSLEngine engineCreateSSLEngine(String host, int port) {
        if (sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initiallized.");
        }
        return new SSLEngineImpl(host, port,
                (SSLParameters) sslParameters.clone());
    }

    @Override
    public SSLEngine engineCreateSSLEngine() {
        if (sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initiallized.");
        }
        return new SSLEngineImpl((SSLParameters) sslParameters.clone());
    }

    @Override
    public ServerSessionContext engineGetServerSessionContext() {
        return serverSessionContext;
    }

    @Override
    public ClientSessionContext engineGetClientSessionContext() {
        return clientSessionContext;
    }
}