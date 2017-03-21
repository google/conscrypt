/*
 * Copyright 2016 The Android Open Source Project
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

import static javax.net.ssl.SSLEngineResult.Status.OK;

import java.io.EOFException;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;

/**
 * Implements crypto handling by delegating to OpenSSLEngine. Used for socket implementations
 * that are not backed by a real OS socket.
 *
 * @hide
 */
final class OpenSSLEngineSocketImpl extends OpenSSLSocketImplWrapper {
    private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocate(0);

    private final OpenSSLEngineImpl engine;
    private final Socket socket;
    private final OutputStreamWrapper outputStreamWrapper;
    private final InputStreamWrapper inputStreamWrapper;
    private boolean handshakeComplete;

    OpenSSLEngineSocketImpl(Socket socket, String hostname, int port, boolean autoClose,
            SSLParametersImpl sslParameters) throws IOException {
        super(socket, hostname, port, autoClose, sslParameters);
        this.socket = socket;
        engine = new OpenSSLEngineImpl(hostname, port, sslParameters);

        // When the handshake completes, notify any listeners.
        engine.setHandshakeListener(new HandshakeListener() {
            @Override
            public void onHandshakeFinished() {
                if (!handshakeComplete) {
                    handshakeComplete = true;
                    OpenSSLEngineSocketImpl.this.notifyHandshakeCompletedListeners();
                }
            }
        });
        outputStreamWrapper = new OutputStreamWrapper();
        inputStreamWrapper = new InputStreamWrapper();
        engine.setUseClientMode(sslParameters.getUseClientMode());
    }

    @Override
    public void startHandshake() throws IOException {
        // Trigger the handshake
        boolean beginHandshakeCalled = false;
        while (!handshakeComplete) {
            switch (engine.getHandshakeStatus()) {
                case NOT_HANDSHAKING: {
                    if (!beginHandshakeCalled) {
                        beginHandshakeCalled = true;
                        engine.beginHandshake();
                        break;
                    }
                    break;
                }
                case FINISHED: {
                    return;
                }
                case NEED_WRAP: {
                    outputStreamWrapper.write(EMPTY_BUFFER);
                    break;
                }
                case NEED_UNWRAP: {
                    if (inputStreamWrapper.read(EmptyArray.BYTE) == -1) {
                        // Can't complete the handshake due to EOF.
                        throw new EOFException();
                    }
                    break;
                }
                case NEED_TASK: {
                    throw new IllegalStateException("OpenSSLEngineImpl returned NEED_TASK");
                }
                default: { break; }
            }
        }
    }

    @Override
    public void onSSLStateChange(int type, int val) {
        throw new AssertionError("Should be handled by engine");
    }

    @Override
    public void verifyCertificateChain(long[] certRefs, String authMethod)
            throws CertificateException {
        throw new AssertionError("Should be handled by engine");
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return inputStreamWrapper;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return outputStreamWrapper;
    }

    @Override
    public SSLSession getSession() {
        return engine.getSession();
    }

    @Override
    public boolean getEnableSessionCreation() {
        return super.getEnableSessionCreation();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        super.setEnableSessionCreation(flag);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return super.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return super.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        super.setEnabledCipherSuites(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return super.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return super.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        super.setEnabledProtocols(protocols);
    }

    @Override
    public void setUseSessionTickets(boolean useSessionTickets) {
        super.setUseSessionTickets(useSessionTickets);
    }

    @Override
    public void setHostname(String hostname) {
        super.setHostname(hostname);
    }

    @Override
    public void setChannelIdEnabled(boolean enabled) {
        super.setChannelIdEnabled(enabled);
    }

    @Override
    public byte[] getChannelId() throws SSLException {
        return super.getChannelId();
    }

    @Override
    public void setChannelIdPrivateKey(PrivateKey privateKey) {
        super.setChannelIdPrivateKey(privateKey);
    }

    @Override
    public boolean getUseClientMode() {
        return super.getUseClientMode();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        engine.setUseClientMode(mode);
    }

    @Override
    public boolean getWantClientAuth() {
        return super.getWantClientAuth();
    }

    @Override
    public boolean getNeedClientAuth() {
        return super.getNeedClientAuth();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        super.setNeedClientAuth(need);
    }

    @Override
    public void setWantClientAuth(boolean want) {
        super.setWantClientAuth(want);
    }

    @Override
    public void sendUrgentData(int data) throws IOException {
        super.sendUrgentData(data);
    }

    @Override
    public void setOOBInline(boolean on) throws SocketException {
        super.setOOBInline(on);
    }

    @Override
    public void setSoWriteTimeout(int writeTimeoutMilliseconds) throws SocketException {
        throw new UnsupportedOperationException("Not supported");
    }

    @Override
    public int getSoWriteTimeout() throws SocketException {
        return 0;
    }

    @Override
    public void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException {
        throw new UnsupportedOperationException("Not supported");
    }

    @Override
    public synchronized void close() throws IOException {
        // Closing Socket.
        engine.closeInbound();
        engine.closeOutbound();
        socket.close();
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
    }

    @Override
    public SocketChannel getChannel() {
        return super.getChannel();
    }

    @Override
    public FileDescriptor getFileDescriptor$() {
        throw new UnsupportedOperationException("Not supported");
    }

    @Override
    public byte[] getNpnSelectedProtocol() {
        return null;
    }

    @Override
    public byte[] getAlpnSelectedProtocol() {
        return engine.getAlpnSelectedProtocol();
    }

    @Override
    public void setNpnProtocols(byte[] npnProtocols) {
        super.setNpnProtocols(npnProtocols);
    }

    @Override
    public void setAlpnProtocols(byte[] alpnProtocols) {
        super.setAlpnProtocols(alpnProtocols);
    }

    @Override
    public String chooseServerAlias(X509KeyManager keyManager, String keyType) {
        return engine.chooseServerAlias(keyManager, keyType);
    }

    @Override
    public String chooseClientAlias(
            X509KeyManager keyManager, X500Principal[] issuers, String[] keyTypes) {
        return engine.chooseClientAlias(keyManager, issuers, keyTypes);
    }

    @Override
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    public String chooseServerPSKIdentityHint(PSKKeyManager keyManager) {
        return engine.chooseServerPSKIdentityHint(keyManager);
    }

    @Override
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    public String chooseClientPSKIdentity(PSKKeyManager keyManager, String identityHint) {
        return engine.chooseClientPSKIdentity(keyManager, identityHint);
    }

    @Override
    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
    public SecretKey getPSKKey(PSKKeyManager keyManager, String identityHint, String identity) {
        return engine.getPSKKey(keyManager, identityHint, identity);
    }

    /**
     * Wrap bytes written to the underlying socket.
     */
    private final class OutputStreamWrapper extends OutputStream {
        private final Object stateLock = new Object();
        private ByteBuffer target;
        private OutputStream socketOutputStream;
        private SocketChannel socketChannel;

        OutputStreamWrapper() {}

        @Override
        public void write(int b) throws IOException {
            write(new byte[] {(byte) b});
        }

        @Override
        public void write(byte[] b) throws IOException {
            write(ByteBuffer.wrap(b));
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            write(ByteBuffer.wrap(b, off, len));
        }

        private void write(ByteBuffer buffer) throws IOException {
            synchronized (stateLock) {
                try {
                    init();

                    // Need to loop through at least once to enable handshaking where no application
                    // bytes are
                    // processed.
                    int len = buffer.remaining();
                    SSLEngineResult engineResult;
                    do {
                        target.clear();
                        engineResult = engine.wrap(buffer, target);
                        if (engineResult.getStatus() != OK) {
                            throw new SSLException(
                                    "Unexpected engine result " + engineResult.getStatus());
                        }
                        if (target.position() != engineResult.bytesProduced()) {
                            throw new SSLException("Engine bytesProduced "
                                    + engineResult.bytesProduced()
                                    + " does not match bytes written " + target.position());
                        }
                        len -= engineResult.bytesConsumed();
                        if (len != buffer.remaining()) {
                            throw new SSLException(
                                    "Engine did not read the correct number of bytes");
                        }

                        target.flip();

                        // Write the data to the socket.
                        if (socketChannel != null) {
                            // Loop until all of the data is written to the channel. Typically,
                            // SocketChannel writes will return only after all bytes are written,
                            // so we won't really loop here.
                            while (target.hasRemaining()) {
                                socketChannel.write(target);
                            }
                        } else {
                            // Target is a heap buffer.
                            socketOutputStream.write(target.array(), 0, target.limit());
                        }
                    } while (len > 0);
                } catch (IOException e) {
                    e.printStackTrace();
                    throw e;
                } catch (RuntimeException e) {
                    e.printStackTrace();
                    throw e;
                }
            }
        }

        @Override
        public void flush() throws IOException {
            synchronized (stateLock) {
                init();
                socketOutputStream.flush();
            }
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }

        private void init() throws IOException {
            if (socketOutputStream == null) {
                socketOutputStream = socket.getOutputStream();
                socketChannel = socket.getChannel();
                if (socketChannel != null) {
                    // Optimization. Using direct buffers wherever possible to avoid passing
                    // arrays to JNI.
                    target = ByteBuffer.allocateDirect(engine.getSession().getPacketBufferSize());
                } else {
                    target = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
                }
            }
        }
    }

    /**
     * Unwrap bytes read from the underlying socket.
     */
    private final class InputStreamWrapper extends InputStream {
        private final Object stateLock = new Object();
        private final byte[] singleByte = new byte[1];
        private final ByteBuffer fromEngine;
        private ByteBuffer fromSocket;
        private InputStream socketInputStream;
        private SocketChannel socketChannel;

        InputStreamWrapper() {
            fromEngine = ByteBuffer.allocateDirect(engine.getSession().getApplicationBufferSize());
            // Initially fromEngine.remaining() == 0.
            fromEngine.flip();
        }

        @Override
        public int read() throws IOException {
            synchronized (stateLock) {
                // Handle returning of -1 if EOF is reached.
                int count = read(singleByte, 0, 1);
                if (count == -1) {
                    // Handle EOF.
                    return -1;
                }
                if (count != 1) {
                    throw new SSLException("read incorrect number of bytes " + count);
                }
                return (int) singleByte[0];
            }
        }

        @Override
        public int read(byte[] b) throws IOException {
            return read(b, 0, b.length);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            synchronized (stateLock) {
                try {
                    // Make sure the input stream has been created.
                    init();

                    for (;;) {
                        // Serve any remaining data from the engine first.
                        if (fromEngine.remaining() > 0) {
                            int readFromEngine = Math.min(fromEngine.remaining(), len);
                            fromEngine.get(b, off, readFromEngine);
                            return readFromEngine;
                        }

                        // Try to unwrap any data already in the socket buffer.
                        boolean needMoreData = true;
                        if (fromSocket.position() > 0) {
                            // Unwrap the unencrypted bytes into the engine buffer.
                            fromSocket.flip();
                            fromEngine.clear();
                            SSLEngineResult engineResult = engine.unwrap(fromSocket, fromEngine);

                            // Shift any remaining data to the beginning of the buffer so that
                            // we can accommodate the next full packet. After this is called,
                            // limit will be restored to capacity and position will point just
                            // past the end of the data.
                            fromSocket.compact();
                            fromEngine.flip();

                            switch (engineResult.getStatus()) {
                                case BUFFER_UNDERFLOW: {
                                    if (engineResult.bytesProduced() == 0) {
                                        // Need to read more data from the socket.
                                        break;
                                    }
                                    // Also serve the data that was produced.
                                    needMoreData = false;
                                    break;
                                }
                                case OK: {
                                    // We processed the entire packet successfully.
                                    needMoreData = false;
                                    break;
                                }
                                case CLOSED: {
                                    // EOF
                                    return -1;
                                }
                                default: {
                                    // Anything else is an error.
                                    throw new SSLException(
                                            "Unexpected engine result " + engineResult.getStatus());
                                }
                            }

                            if (!needMoreData && engineResult.bytesProduced() == 0) {
                                // Read successfully, but produced no data. Possibly part of a
                                // handshake.
                                return 0;
                            }
                        }

                        // Read more data from the socket.
                        if (needMoreData && readFromSocket() == -1) {
                            // Failed to read the next encrypted packet before reaching EOF.
                            return -1;
                        }

                        // Continue the loop and return the data from the engine buffer.
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    throw e;
                } catch (RuntimeException e) {
                    e.printStackTrace();
                    throw e;
                }
            }
        }

        private void init() throws IOException {
            if (socketInputStream == null) {
                socketInputStream = socket.getInputStream();
                socketChannel = socket.getChannel();
                if (socketChannel != null) {
                    fromSocket =
                            ByteBuffer.allocateDirect(engine.getSession().getPacketBufferSize());
                } else {
                    fromSocket = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
                }
            }
        }

        private int readFromSocket() throws IOException {
            if (socketChannel != null) {
                return socketChannel.read(fromSocket);
            }
            // Read directly to the underlying array and increment the buffer position if
            // appropriate.
            int read = socketInputStream.read(
                    fromSocket.array(), fromSocket.position(), fromSocket.remaining());
            if (read > 0) {
                fromSocket.position(fromSocket.position() + read);
            }
            return read;
        }
    }
}
