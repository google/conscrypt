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

import static org.conscrypt.Platform.createEngineSocket;
import static org.conscrypt.Platform.createFileDescriptorSocket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

/**
 * An implementation of {@link SSLSocketFactory} based on BoringSSL.
 *
 * <p/>This name of this class cannot change in order to maintain backward-compatibility with GMS
 * core {@code ProviderInstallerImpl}
 */
final class OpenSSLSocketFactoryImpl extends SSLSocketFactory {
    private static boolean useEngineSocketByDefault = SSLUtils.USE_ENGINE_SOCKET_BY_DEFAULT;

    private final SSLParametersImpl sslParameters;
    private final IOException instantiationException;
    private boolean useEngineSocket = useEngineSocketByDefault;

    OpenSSLSocketFactoryImpl() {
        SSLParametersImpl sslParametersLocal = null;
        IOException instantiationExceptionLocal = null;
        try {
            sslParametersLocal = SSLParametersImpl.getDefault();
        } catch (KeyManagementException e) {
            instantiationExceptionLocal = new IOException("Delayed instantiation exception:", e);
        }
        this.sslParameters = sslParametersLocal;
        this.instantiationException = instantiationExceptionLocal;
    }

    OpenSSLSocketFactoryImpl(SSLParametersImpl sslParameters) {
        this.sslParameters = sslParameters;
        this.instantiationException = null;
    }

    /**
     * Configures the default socket type to be created for the default and all new instances.
     */
    static void setUseEngineSocketByDefault(boolean useEngineSocket) {
        useEngineSocketByDefault = useEngineSocket;
        // The default SSLSocketFactory may already have been created, so also change its setting.
        SocketFactory defaultFactory = SSLSocketFactory.getDefault();
        if (defaultFactory instanceof OpenSSLSocketFactoryImpl) {
            ((OpenSSLSocketFactoryImpl) defaultFactory).setUseEngineSocket(useEngineSocket);
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
    public Socket createSocket() throws IOException {
        if (instantiationException != null) {
            throw instantiationException;
        }
        if (useEngineSocket) {
            return createEngineSocket((SSLParametersImpl) sslParameters.clone());
        } else {
            return createFileDescriptorSocket((SSLParametersImpl) sslParameters.clone());
        }
    }

    @Override
    public Socket createSocket(String hostname, int port) throws IOException, UnknownHostException {
        if (useEngineSocket) {
            return createEngineSocket(
                    hostname, port, (SSLParametersImpl) sslParameters.clone());
        } else {
            return createFileDescriptorSocket(
                    hostname, port, (SSLParametersImpl) sslParameters.clone());
        }
    }

    @Override
    public Socket createSocket(String hostname, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        if (useEngineSocket) {
            return createEngineSocket(hostname, port, localHost,
                    localPort, (SSLParametersImpl) sslParameters.clone());
        } else {
            return createFileDescriptorSocket(hostname, port, localHost,
                    localPort, (SSLParametersImpl) sslParameters.clone());
        }
    }

    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        if (useEngineSocket) {
            return createEngineSocket(
                    address, port, (SSLParametersImpl) sslParameters.clone());
        } else {
            return createFileDescriptorSocket(
                    address, port, (SSLParametersImpl) sslParameters.clone());
        }
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress,
            int localPort) throws IOException {
        if (useEngineSocket) {
            return createEngineSocket(address, port, localAddress,
                    localPort, (SSLParametersImpl) sslParameters.clone());
        } else {
            return createFileDescriptorSocket(address, port, localAddress,
                    localPort, (SSLParametersImpl) sslParameters.clone());
        }
    }

    @Override
    public Socket createSocket(Socket socket, String hostname, int port, boolean autoClose)
            throws IOException {
        Preconditions.checkNotNull(socket, "socket");
        if (!socket.isConnected()) {
            throw new SocketException("Socket is not connected.");
        }

        if (!useEngineSocket && hasFileDescriptor(socket)) {
            return createFileDescriptorSocket(
                    socket, hostname, port, autoClose, (SSLParametersImpl) sslParameters.clone());
        } else {
            return createEngineSocket(
                    socket, hostname, port, autoClose, (SSLParametersImpl) sslParameters.clone());
        }
    }

    private boolean hasFileDescriptor(Socket s) {
        try {
            // If socket has a file descriptor we can use it directly
            // otherwise we need to use the engine.
            Platform.getFileDescriptor(s);
            return true;
        } catch (RuntimeException re) {
            return false;
        }
    }
}
