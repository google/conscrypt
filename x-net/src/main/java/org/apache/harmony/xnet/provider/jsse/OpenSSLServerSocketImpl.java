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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.bouncycastle.openssl.PEMWriter;

/**
 * OpenSSL-based implementation of server sockets.
 *  
 * This class only supports SSLv3 and TLSv1. This should be documented elsewhere
 * later, for example in the package.html or a separate reference document.
 */ 
public class OpenSSLServerSocketImpl extends javax.net.ssl.SSLServerSocket {
    private int ssl_ctx;
    private boolean client_mode = true;
    private long ssl_op_no = 0x00000000L;
    private SSLParameters sslParameters;
    private static final String[] supportedProtocols = new String[] {
        "SSLv3",
        "TLSv1"
        };

    private native static void nativeinitstatic();

    static {
        nativeinitstatic();
    }

    private native void nativeinit(String privatekey, String certificate, byte[] seed);

    /**
     * Initialize the SSL server socket and set the certificates for the
     * future handshaking.
     */
    private void init() throws IOException {
        String alias = sslParameters.getKeyManager().chooseServerAlias("RSA", null, null);
        if (alias == null) {
            throw new IOException("No suitable certificates found");
        }

        PrivateKey privateKey = sslParameters.getKeyManager().getPrivateKey(alias);
        X509Certificate[] certificates = sslParameters.getKeyManager().getCertificateChain(alias);

        ByteArrayOutputStream privateKeyOS = new ByteArrayOutputStream();
        PEMWriter privateKeyPEMWriter = new PEMWriter(new OutputStreamWriter(privateKeyOS));
        privateKeyPEMWriter.writeObject(privateKey);
        privateKeyPEMWriter.close();

        ByteArrayOutputStream certificateOS = new ByteArrayOutputStream();
        PEMWriter certificateWriter = new PEMWriter(new OutputStreamWriter(certificateOS));

        for (int i = 0; i < certificates.length; i++) {
            certificateWriter.writeObject(certificates[i]);
        }
        certificateWriter.close();

        nativeinit(privateKeyOS.toString(), certificateOS.toString(),
                sslParameters.getSecureRandomMember() != null ?
                sslParameters.getSecureRandomMember().generateSeed(1024) : null);
    }

    protected OpenSSLServerSocketImpl(SSLParameters sslParameters)
        throws IOException {
        super();
        this.sslParameters = sslParameters;
        init();
    }

    protected OpenSSLServerSocketImpl(int port, SSLParameters sslParameters)
        throws IOException {
        super(port);
        this.sslParameters = sslParameters;
        init();
    }

    protected OpenSSLServerSocketImpl(int port, int backlog, SSLParameters sslParameters)
        throws IOException {
        super(port, backlog);
        this.sslParameters = sslParameters;
        init();
    }

    protected OpenSSLServerSocketImpl(int port, int backlog, InetAddress iAddress, SSLParameters sslParameters)
        throws IOException {
        super(port, backlog, iAddress);
        this.sslParameters = sslParameters;
        init();
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
        return supportedProtocols.clone();
    }

    /**
     * See the OpenSSL ssl.h header file for more information.
     */
    static private long SSL_OP_NO_SSLv3 = 0x02000000L;
    static private long SSL_OP_NO_TLSv1 = 0x04000000L;

    /**
     * The names of the protocols' versions that in use on this SSL connection.
     * 
     * @return an array of protocols names
     */
    @Override
    public String[] getEnabledProtocols() {
        ArrayList<String> array = new ArrayList<String>();

        if ((ssl_op_no & SSL_OP_NO_SSLv3) == 0x00000000L) {
            array.add(supportedProtocols[1]);
        }
        if ((ssl_op_no & SSL_OP_NO_TLSv1) == 0x00000000L) {
            array.add(supportedProtocols[2]);
        }
        return array.toArray(new String[array.size()]);
    }

    private native void nativesetenabledprotocols(long l);

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
        if (protocols == null) {
            throw new IllegalArgumentException("Provided parameter is null");
        }

        ssl_op_no  = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;

        for (int i = 0; i < protocols.length; i++) {
            if (protocols[i].equals("SSLv3"))
                ssl_op_no ^= SSL_OP_NO_SSLv3;
            else if (protocols[i].equals("TLSv1"))
                ssl_op_no ^= SSL_OP_NO_TLSv1;
            else throw new IllegalArgumentException("Protocol " + protocols[i] +
            " is not supported.");
        }

        nativesetenabledprotocols(ssl_op_no);
    }

    /**
     * Gets all available ciphers from the current OpenSSL library.
     * Needed by OpenSSLServerSocketFactory too.
     */
    static native String[] nativegetsupportedciphersuites();

    @Override
    public String[] getSupportedCipherSuites() {
        return nativegetsupportedciphersuites();
    }

    /**
     * Calls native OpenSSL functions to get the enabled ciphers.
     */
    private native String[] nativegetenabledciphersuites();

    @Override
    public String[] getEnabledCipherSuites() {
        return nativegetenabledciphersuites();
    }

    /**
     * Calls the SSL_CTX_set_cipher_list(...) OpenSSL function with the passed
     * char array.
     */
    private native void nativesetenabledciphersuites(String controlString);

    private boolean findSuite(String suite) {
        String[] supportedCipherSuites = nativegetsupportedciphersuites();
        for(int i = 0; i < supportedCipherSuites.length; i++)
            if (supportedCipherSuites[i].equals(suite)) return true;
        throw new IllegalArgumentException("Protocol " + suite +
        " is not supported.");
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
        if (suites == null) {
            throw new IllegalArgumentException("Provided parameter is null");
        }
        String controlString = "";
        for (int i = 0; i < suites.length; i++) {
            findSuite(suites[i]);
            if (i == 0) controlString = suites[i];
            else controlString += ":" + suites[i];
        }
        nativesetenabledciphersuites(controlString);
    }

    /**
     * See the OpenSSL ssl.h header file for more information.
     */
    static private int SSL_VERIFY_NONE =                 0x00;
    static private int SSL_VERIFY_PEER =                 0x01;
    static private int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
    static private int SSL_VERIFY_CLIENT_ONCE =          0x04;

    /**
     * Calls the SSL_CTX_set_verify(...) OpenSSL function with the passed int
     * value.
     */
    private native void nativesetclientauth(int value);

    private void setClientAuth() {
        int value = SSL_VERIFY_NONE;

        if (sslParameters.getNeedClientAuth()) {
            value |= SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_CLIENT_ONCE;
        } else if (sslParameters.getWantClientAuth()) {
            value |= SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE;
        }

        nativesetclientauth(value);
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
        OpenSSLSocketImpl socket = new OpenSSLSocketImpl(sslParameters, ssl_op_no);
        implAccept(socket);
        socket.accept(ssl_ctx, client_mode);

        return socket;
    }

    /**
     * Removes OpenSSL objects from memory.
     */
    private native void nativefree();

    /**
     * Unbinds the port if the socket is open.
     */
    @Override
    protected void finalize() throws Throwable {
        if (!isClosed()) close();
    }

    @Override
    public synchronized void close() throws IOException {
        nativefree();
        super.close();
    }
}
