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
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import javax.net.ssl.SSLException;

/**
 * OpenSSL-based implementation of server sockets.
 *
 * This class only supports SSLv3 and TLSv1. This should be documented elsewhere
 * later, for example in the package.html or a separate reference document.
 */
public class OpenSSLServerSocketImpl extends javax.net.ssl.SSLServerSocket {
    private final SSLParameters sslParameters;
    private String[] enabledProtocols = NativeCrypto.getSupportedProtocols();
    private String[] enabledCipherSuites = NativeCrypto.getDefaultCipherSuites();

    protected OpenSSLServerSocketImpl(SSLParameters sslParameters)
        throws IOException {
        super();
        this.sslParameters = sslParameters;
    }

    protected OpenSSLServerSocketImpl(int port, SSLParameters sslParameters)
        throws IOException {
        super(port);
        this.sslParameters = sslParameters;
    }

    protected OpenSSLServerSocketImpl(int port, int backlog, SSLParameters sslParameters)
        throws IOException {
        super(port, backlog);
        this.sslParameters = sslParameters;
    }

    protected OpenSSLServerSocketImpl(int port,
                                      int backlog,
                                      InetAddress iAddress,
                                      SSLParameters sslParameters)
        throws IOException {
        super(port, backlog, iAddress);
        this.sslParameters = sslParameters;
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
        return enabledProtocols.clone();
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
        enabledProtocols = NativeCrypto.checkEnabledProtocols(protocols);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return NativeCrypto.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return enabledCipherSuites.clone();
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
        enabledCipherSuites = NativeCrypto.checkEnabledCipherSuites(suites);
    }

    @Override
    public boolean getWantClientAuth() {
        return sslParameters.getWantClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslParameters.setWantClientAuth(want);
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        sslParameters.setNeedClientAuth(need);
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
        for (String enabledCipherSuite : enabledCipherSuites) {
            CipherSuite cipherSuite = CipherSuite.getByName(enabledCipherSuite);
            if (cipherSuite == null) {
                continue;
            }
            switch (cipherSuite.keyExchange) {
                case CipherSuite.KeyExchange_DHE_RSA:
                case CipherSuite.KeyExchange_DHE_RSA_EXPORT:
                case CipherSuite.KeyExchange_DH_RSA:
                case CipherSuite.KeyExchange_DH_RSA_EXPORT:
                case CipherSuite.KeyExchange_RSA:
                case CipherSuite.KeyExchange_RSA_EXPORT:
                    String rsaAlias = sslParameters.getKeyManager().chooseServerAlias("RSA",
                                                                                      null,
                                                                                      null);
                    if (rsaAlias == null) {
                        break;
                    }
                    PrivateKey rsa = sslParameters.getKeyManager().getPrivateKey(rsaAlias);
                    if ((rsa == null) || !(rsa instanceof RSAPrivateKey)) {
                        break;
                    }
                    continue;

                case CipherSuite.KeyExchange_DHE_DSS:
                case CipherSuite.KeyExchange_DHE_DSS_EXPORT:
                case CipherSuite.KeyExchange_DH_DSS:
                case CipherSuite.KeyExchange_DH_DSS_EXPORT:
                    String dsaAlias = sslParameters.getKeyManager().chooseServerAlias("DSA",
                                                                                      null,
                                                                                      null);
                    if (dsaAlias == null) {
                        break;
                    }
                    PrivateKey dsa = sslParameters.getKeyManager().getPrivateKey(dsaAlias);
                    if ((dsa == null) || !(dsa instanceof DSAPrivateKey)) {
                        break;
                    }
                    continue;

                case CipherSuite.KeyExchange_DH_anon:
                case CipherSuite.KeyExchange_DH_anon_EXPORT:
                default:
                    continue;
            }
            throw new SSLException("Could not find key store entry to support cipher suite "
                                   + cipherSuite);
        }

        OpenSSLSocketImpl socket = new OpenSSLSocketImpl(sslParameters,
                                                         enabledProtocols.clone(),
                                                         enabledCipherSuites.clone());
        implAccept(socket);
        return socket;
    }
}
