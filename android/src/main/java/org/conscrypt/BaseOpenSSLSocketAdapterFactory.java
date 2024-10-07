/*
 * Copyright (C) 2015 The Android Open Source Project
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
import javax.net.ssl.SSLSocketFactory;

@Internal
public abstract class BaseOpenSSLSocketAdapterFactory extends SSLSocketFactory {

    private final OpenSSLSocketFactoryImpl delegate;

    protected BaseOpenSSLSocketAdapterFactory(OpenSSLSocketFactoryImpl delegate) {
        this.delegate = delegate;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        return wrap((OpenSSLSocketImpl) delegate.createSocket());
    }

    @Override
    public Socket createSocket(String hostname, int port)
            throws IOException, UnknownHostException {
        return wrap((OpenSSLSocketImpl) delegate.createSocket(hostname, port));
    }

    @Override
    public Socket createSocket(String hostname, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        return wrap(
                (OpenSSLSocketImpl) delegate.createSocket(hostname, port, localHost, localPort));
    }
    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        return wrap((OpenSSLSocketImpl) delegate.createSocket(address, port));
    }

    @Override
    public Socket createSocket(InetAddress address,
                               int port,
                               InetAddress localAddress,
                               int localPort)
            throws IOException {
        return wrap(
                (OpenSSLSocketImpl) delegate.createSocket(address, port, localAddress, localPort));
    }

    @Override
    public Socket createSocket(Socket s, String hostname, int port, boolean autoClose)
            throws IOException {
        return wrap((OpenSSLSocketImpl) delegate.createSocket(s, hostname, port, autoClose));
    }

    /**
     * Wraps the provided unbundled conscrypt SSLSocket into a platform bundled conscrypt
     * SSLSocket.
     */
    protected abstract Socket wrap(OpenSSLSocketImpl sock) throws IOException;
}
