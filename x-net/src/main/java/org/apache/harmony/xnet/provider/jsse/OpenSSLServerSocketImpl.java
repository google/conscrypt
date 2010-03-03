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

package org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

/**
 * OpenSSL-based implementation of server sockets.
 *
 * This class only supports SSLv3 and TLSv1. This should be documented elsewhere
 * later, for example in the package.html or a separate reference document.
 */
public class OpenSSLServerSocketImpl extends javax.net.ssl.SSLServerSocket {
    private final SSLParameters sslParameters;
    private int sslNativePointer;

    protected OpenSSLServerSocketImpl(SSLParameters sslParameters)
        throws IOException {
        super();
        this.sslParameters = sslParameters;
        this.sslNativePointer = NativeCrypto.SSL_new(sslParameters);
    }

    protected OpenSSLServerSocketImpl(int port, SSLParameters sslParameters)
        throws IOException {
        super(port);
        this.sslParameters = sslParameters;
        this.sslNativePointer = NativeCrypto.SSL_new(sslParameters);
    }

    protected OpenSSLServerSocketImpl(int port, int backlog, SSLParameters sslParameters)
        throws IOException {
        super(port, backlog);
        this.sslParameters = sslParameters;
        this.sslNativePointer = NativeCrypto.SSL_new(sslParameters);
    }

    protected OpenSSLServerSocketImpl(int port, int backlog, InetAddress iAddress, SSLParameters sslParameters)
        throws IOException {
        super(port, backlog, iAddress);
        this.sslParameters = sslParameters;
        this.sslNativePointer = NativeCrypto.SSL_new(sslParameters);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return sslParameters.getEnableSessionCreation();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslParameters.setEnableSessionCreation(flag);
    }

    /**
     * The names of the protocols' versions that may be used on this SSL
     * connection.
     * @return an array of protocols names
     */
    @Override
    public String[] getSupportedProtocols() {
        return NativeCrypto.getSupportedProtocols();
    }

    /**
     * The names of the protocols' versions that in use on this SSL connection.
     *
     * @return an array of protocols names
     */
    @Override
    public String[] getEnabledProtocols() {
        return NativeCrypto.getEnabledProtocols(sslNativePointer);
    }

    /**
     * This method enables the protocols' versions listed by
     * getSupportedProtocols().
     *
     * @param protocols names of all the protocols to enable.
     *
     * @throws IllegalArgumentException when one or more of the names in the
     *             array are not supported, or when the array is null.
     */
    @Override
    public void setEnabledProtocols(String[] protocols) {
        NativeCrypto.setEnabledProtocols(sslNativePointer, protocols);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return NativeCrypto.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return NativeCrypto.SSL_get_ciphers(sslNativePointer);
    }

    /**
     * This method enables the cipher suites listed by
     * getSupportedCipherSuites().
     *
     * @param suites the names of all the cipher suites to enable
     * @throws IllegalArgumentException when one or more of the ciphers in array
     *         suites are not supported, or when the array is null.
     */
    @Override
    public void setEnabledCipherSuites(String[] suites) {
        NativeCrypto.setEnabledCipherSuites(sslNativePointer, suites);
    }

    /**
     * See the OpenSSL ssl.h header file for more information.
     */
    static private int SSL_VERIFY_NONE =                 0x00;
    static private int SSL_VERIFY_PEER =                 0x01;
    static private int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
    static private int SSL_VERIFY_CLIENT_ONCE =          0x04;

    /**
     * Calls the SSL_set_verify(...) OpenSSL function with the passed int
     * value.
     */
    private static native void nativesetclientauth(int sslNativePointer, int value);

    private void setClientAuth() {
        int value = SSL_VERIFY_NONE;

        if (sslParameters.getNeedClientAuth()) {
            value |= SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_CLIENT_ONCE;
        } else if (sslParameters.getWantClientAuth()) {
            value |= SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE;
        }

        nativesetclientauth(sslNativePointer, value);
    }

    @Override
    public boolean getWantClientAuth() {
        return sslParameters.getWantClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslParameters.setWantClientAuth(want);
        setClientAuth();
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        sslParameters.setNeedClientAuth(need);
        setClientAuth();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        sslParameters.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return sslParameters.getUseClientMode();
    }

    @Override
    public Socket accept() throws IOException {
        OpenSSLSocketImpl socket = new OpenSSLSocketImpl(sslParameters, null);
        implAccept(socket);
        socket.accept(sslNativePointer);
        return socket;
    }

    /**
     * Unbinds the port if the socket is open.
     */
    @Override
    protected void finalize() throws Throwable {
        if (!isClosed()) close();
    }

    @Override
    public synchronized void close() throws IOException {
        if (sslNativePointer != 0) {
            NativeCrypto.SSL_free(sslNativePointer);
            sslNativePointer = 0;
        }
        super.close();
    }
}
