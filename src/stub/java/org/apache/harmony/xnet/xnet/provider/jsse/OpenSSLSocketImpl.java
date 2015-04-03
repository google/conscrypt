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

package org.apache.harmony.xnet.provider.jsse;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;



/**
 * Implementation of the class OpenSSLSocketImpl based on OpenSSL.
 * <p>
 * Extensions to SSLSocket include:
 * <ul>
 * <li>handshake timeout
 * <li>session tickets
 * <li>Server Name Indication
 * </ul>
 */
public class OpenSSLSocketImpl
        extends javax.net.ssl.SSLSocket
        implements NativeCrypto.SSLHandshakeCallbacks {


    protected OpenSSLSocketImpl(SSLParametersImpl sslParameters) throws IOException {
        throw new RuntimeException("Stub!");
    }

    protected OpenSSLSocketImpl(SSLParametersImpl sslParameters,
                                String[] enabledProtocols,
                                String[] enabledCipherSuites) throws IOException {
        throw new RuntimeException("Stub!");
    }

    protected OpenSSLSocketImpl(String host, int port, SSLParametersImpl sslParameters)
            throws IOException {
        throw new RuntimeException("Stub!");
    }

    protected OpenSSLSocketImpl(InetAddress address, int port, SSLParametersImpl sslParameters)
            throws IOException {
        throw new RuntimeException("Stub!");
    }


    protected OpenSSLSocketImpl(String host, int port,
                                InetAddress clientAddress, int clientPort,
                                SSLParametersImpl sslParameters) throws IOException {
        throw new RuntimeException("Stub!");
    }

    protected OpenSSLSocketImpl(InetAddress address, int port,
                                InetAddress clientAddress, int clientPort,
                                SSLParametersImpl sslParameters) throws IOException {
        throw new RuntimeException("Stub!");
    }

    protected OpenSSLSocketImpl(Socket socket, String host, int port,
            boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        throw new RuntimeException("Stub!");
    }

    @Override public synchronized void startHandshake() throws IOException {
        throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused") // used by NativeCrypto.SSLHandshakeCallbacks / client_cert_cb
    public void clientCertificateRequested(byte[] keyTypeBytes, byte[][] asn1DerEncodedPrincipals)
            throws CertificateEncodingException, SSLException {
        throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused") // used by NativeCrypto.SSLHandshakeCallbacks / info_callback
    public void handshakeCompleted() {
        throw new RuntimeException("Stub!");
    }
    @SuppressWarnings("unused") // used by NativeCrypto.SSLHandshakeCallbacks
    @Override public void verifyCertificateChain(byte[][] bytes, String authMethod)
            throws CertificateException {
        throw new RuntimeException("Stub!");
    }

    @Override public InputStream getInputStream() throws IOException {
        throw new RuntimeException("Stub!");
    }

    @Override public OutputStream getOutputStream() throws IOException {
        throw new RuntimeException("Stub!");
    }
    @Override public SSLSession getSession() {
        throw new RuntimeException("Stub!");
    }

    @Override public void addHandshakeCompletedListener(
            HandshakeCompletedListener listener) {
        throw new RuntimeException("Stub!");
    }

    @Override public void removeHandshakeCompletedListener(
            HandshakeCompletedListener listener) {
        throw new RuntimeException("Stub!");
    }

    @Override public boolean getEnableSessionCreation() {
        throw new RuntimeException("Stub!");
    }

    @Override public void setEnableSessionCreation(boolean flag) {
        throw new RuntimeException("Stub!");
    }

    @Override public String[] getSupportedCipherSuites() {
        throw new RuntimeException("Stub!");
    }

    @Override public String[] getEnabledCipherSuites() {
        throw new RuntimeException("Stub!");
    }

    @Override public void setEnabledCipherSuites(String[] suites) {
        throw new RuntimeException("Stub!");
    }

    @Override public String[] getSupportedProtocols() {
        throw new RuntimeException("Stub!");
    }

    @Override public String[] getEnabledProtocols() {
        throw new RuntimeException("Stub!");
    }

    @Override public void setEnabledProtocols(String[] protocols) {
        throw new RuntimeException("Stub!");
    }
    public void setUseSessionTickets(boolean useSessionTickets) {
        throw new RuntimeException("Stub!");
    }

    public void setHostname(String hostname) {
        throw new RuntimeException("Stub!");
    }

    public void setChannelIdEnabled(boolean enabled) {
        throw new RuntimeException("Stub!");
    }

    public byte[] getChannelId() throws SSLException {
        throw new RuntimeException("Stub!");
    }
    public void setChannelIdPrivateKey(PrivateKey privateKey) {
        throw new RuntimeException("Stub!");
    }

    @Override public boolean getUseClientMode() {
        throw new RuntimeException("Stub!");
    }

    @Override public void setUseClientMode(boolean mode) {
        throw new RuntimeException("Stub!");
    }

    @Override public boolean getWantClientAuth() {
        throw new RuntimeException("Stub!");
    }

    @Override public boolean getNeedClientAuth() {
        throw new RuntimeException("Stub!");
    }

    @Override public void setNeedClientAuth(boolean need) {
        throw new RuntimeException("Stub!");
    }

    @Override public void setWantClientAuth(boolean want) {
        throw new RuntimeException("Stub!");
    }

    @Override public void sendUrgentData(int data) throws IOException {
        throw new RuntimeException("Stub!");
    }

    @Override public void setOOBInline(boolean on) throws SocketException {
        throw new RuntimeException("Stub!");
    }

    @Override public void setSoTimeout(int readTimeoutMilliseconds) throws SocketException {
        throw new RuntimeException("Stub!");
    }

    @Override public int getSoTimeout() throws SocketException {
        throw new RuntimeException("Stub!");
    }

    /**
     * Note write timeouts are not part of the javax.net.ssl.SSLSocket API
     */
    public void setSoWriteTimeout(int writeTimeoutMilliseconds) throws SocketException {
        throw new RuntimeException("Stub!");
    }

    /**
     * Note write timeouts are not part of the javax.net.ssl.SSLSocket API
     */
    public int getSoWriteTimeout() throws SocketException {
        throw new RuntimeException("Stub!");
    }

    /**
     * Set the handshake timeout on this socket.  This timeout is specified in
     * milliseconds and will be used only during the handshake process.
     */
    public void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException {
        throw new RuntimeException("Stub!");
    }

    @Override public void close() throws IOException {
        throw new RuntimeException("Stub!");
    }

    public FileDescriptor getFileDescriptor$() {
        throw new RuntimeException("Stub!");
    }

    /**
     * Returns the protocol agreed upon by client and server, or null if no
     * protocol was agreed upon.
     */
    public byte[] getNpnSelectedProtocol() {
        throw new RuntimeException("Stub!");
    }

    /**
     * Sets the list of protocols this peer is interested in. If null no
     * protocols will be used.
     *
     * @param npnProtocols a non-empty array of protocol names. From
     *     SSL_select_next_proto, "vector of 8-bit, length prefixed byte
     *     strings. The length byte itself is not included in the length. A byte
     *     string of length 0 is invalid. No byte string may be truncated.".
     */
    public void setNpnProtocols(byte[] npnProtocols) {
        throw new RuntimeException("Stub!");
    }
}
