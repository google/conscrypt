/*
 * Copyright (C) 2007 The Android Open Source Project
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
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;

/**
 * An implementation of {@link javax.net.ssl.SSLSocketFactory} based on BoringSSL.
 *
 * @hide
 */
@Internal
public class OpenSSLSocketFactoryImpl extends javax.net.ssl.SSLSocketFactory {
    private static boolean useEngineSocketByDefault = SSLUtils.USE_ENGINE_SOCKET_BY_DEFAULT;

    private final SSLParametersImpl sslParameters;
    private final IOException instantiationException;
    private boolean useEngineSocket = useEngineSocketByDefault;

    public OpenSSLSocketFactoryImpl() {
        SSLParametersImpl sslParametersLocal = null;
        IOException instantiationExceptionLocal = null;
        try {
            sslParametersLocal = SSLParametersImpl.getDefault();
        } catch (KeyManagementException e) {
            instantiationExceptionLocal = new IOException("Delayed instantiation exception:");
            instantiationExceptionLocal.initCause(e);
        }
        this.sslParameters = sslParametersLocal;
        this.instantiationException = instantiationExceptionLocal;
    }

    public OpenSSLSocketFactoryImpl(SSLParametersImpl sslParameters) {
        this.sslParameters = sslParameters;
        this.instantiationException = null;
    }

    /**
     * Configures the default socket to be created for all instances.
     */
    static void setUseEngineSocketByDefault(boolean useEngineSocket) {
        useEngineSocketByDefault = useEngineSocket;
    }

    /**
     * Configures the socket to be created for this instance. If not called,
     * {@link #useEngineSocketByDefault} will be used.
     */
    public void setUseEngineSocket(boolean useEngineSocket) {
        this.useEngineSocket = useEngineSocket;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return sslParameters.getEnabledCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return NativeCrypto.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        if (instantiationException != null) {
            throw instantiationException;
        }
        return new OpenSSLSocketImpl((SSLParametersImpl) sslParameters.clone());
    }

    @Override
    public Socket createSocket(String hostname, int port) throws IOException, UnknownHostException {
        return new OpenSSLSocketImpl(hostname, port, (SSLParametersImpl) sslParameters.clone());
    }

    @Override
    public Socket createSocket(String hostname, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        return new OpenSSLSocketImpl(hostname,
                                     port,
                                     localHost,
                                     localPort,
                                     (SSLParametersImpl) sslParameters.clone());
    }

    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        return new OpenSSLSocketImpl(address, port, (SSLParametersImpl) sslParameters.clone());
    }

    @Override
    public Socket createSocket(InetAddress address,
                               int port,
                               InetAddress localAddress,
                               int localPort)
            throws IOException {
        return new OpenSSLSocketImpl(address,
                                     port,
                                     localAddress,
                                     localPort,
                                     (SSLParametersImpl) sslParameters.clone());
    }

    @Override
    public Socket createSocket(Socket s, String hostname, int port, boolean autoClose)
            throws IOException {
        boolean socketHasFd = false;
        try {
            // If socket has a file descriptor we can use OpenSSLSocketImplWrapper directly
            // otherwise we need to use the engine.
            socketHasFd = Platform.getFileDescriptor(s) != null;
        } catch (RuntimeException re) {
            // Ignore
        }
        if (socketHasFd && !useEngineSocket) {
            return new OpenSSLSocketImplWrapper(
                    s, hostname, port, autoClose, (SSLParametersImpl) sslParameters.clone());
        } else {
            return new OpenSSLEngineSocketImpl(
                    s, hostname, port, autoClose, (SSLParametersImpl) sslParameters.clone());
        }
    }
}
