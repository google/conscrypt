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
import java.net.ServerSocket;
import javax.net.ServerSocketFactory;
import java.security.KeyManagementException;
import javax.net.ssl.SSLServerSocketFactory;

/**
 * An implementation of {@link SSLServerSocketFactory} using BoringSSL.
 *
 * <p/>This name of this class cannot change in order to maintain backward-compatibility with GMS
 * core {@code ProviderInstallerImpl}
 */
final class OpenSSLServerSocketFactoryImpl extends SSLServerSocketFactory {
    private static boolean useEngineSocketByDefault = SSLUtils.USE_ENGINE_SOCKET_BY_DEFAULT;

    private SSLParametersImpl sslParameters;
    private IOException instantiationException;
    private boolean useEngineSocket = useEngineSocketByDefault;

    OpenSSLServerSocketFactoryImpl() {
        try {
            this.sslParameters = SSLParametersImpl.getDefault();
            this.sslParameters.setUseClientMode(false);
        } catch (KeyManagementException e) {
            instantiationException = new IOException("Delayed instantiation exception:");
            instantiationException.initCause(e);
        }
    }

    OpenSSLServerSocketFactoryImpl(SSLParametersImpl sslParameters) {
        this.sslParameters = (SSLParametersImpl) sslParameters.clone();
        this.sslParameters.setUseClientMode(false);
    }

    /**
     * Configures the default socket type to be created for the default and all new instances.
     */
    static void setUseEngineSocketByDefault(boolean useEngineSocket) {
        useEngineSocketByDefault = useEngineSocket;
        // The default SSLServerSocketFactory may already have been created, so also change its
        // setting.
        ServerSocketFactory defaultFactory = SSLServerSocketFactory.getDefault();
        if (defaultFactory instanceof OpenSSLServerSocketFactoryImpl) {
            ((OpenSSLServerSocketFactoryImpl) defaultFactory).setUseEngineSocket(useEngineSocket);
        }
    }

    /**
     * Configures the socket to be created for this instance. If not called,
     * {@link #useEngineSocketByDefault} will be used.
     */
    void setUseEngineSocket(boolean useEngineSocket) {
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
    public ServerSocket createServerSocket() throws IOException {
        return new ConscryptServerSocket((SSLParametersImpl) sslParameters.clone())
                .setUseEngineSocket(useEngineSocket);
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        return new ConscryptServerSocket(port, (SSLParametersImpl) sslParameters.clone())
                .setUseEngineSocket(useEngineSocket);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        return new ConscryptServerSocket(port, backlog, (SSLParametersImpl) sslParameters.clone())
                .setUseEngineSocket(useEngineSocket);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress iAddress)
            throws IOException {
        return new ConscryptServerSocket(
                port, backlog, iAddress, (SSLParametersImpl) sslParameters.clone())
                .setUseEngineSocket(useEngineSocket);
    }
}
