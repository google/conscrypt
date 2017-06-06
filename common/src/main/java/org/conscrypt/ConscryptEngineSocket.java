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
import static org.conscrypt.SSLUtils.EngineStates.STATE_CLOSED;
import static org.conscrypt.SSLUtils.EngineStates.STATE_HANDSHAKE_COMPLETED;
import static org.conscrypt.SSLUtils.EngineStates.STATE_HANDSHAKE_STARTED;
import static org.conscrypt.SSLUtils.EngineStates.STATE_NEW;
import static org.conscrypt.SSLUtils.EngineStates.STATE_READY;
import static org.conscrypt.SSLUtils.EngineStates.STATE_READY_HANDSHAKE_CUT_THROUGH;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.PrivateKey;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;

/**
 * Implements crypto handling by delegating to {@link ConscryptEngine}.
 */
final class ConscryptEngineSocket extends OpenSSLSocketImpl
        implements SSLParametersImpl.AliasChooser, SSLParametersImpl.PSKCallbacks {
    private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocate(0);

    private final ConscryptEngine engine;
    private final Object stateLock = new Object();
    private final Object handshakeLock = new Object();

    private SSLOutputStream out;
    private SSLInputStream in;

    // @GuardedBy("stateLock");
    private int state = STATE_NEW;

    ConscryptEngineSocket(SSLParametersImpl sslParameters) throws IOException {
        engine = newEngine(sslParameters, this);
    }

    ConscryptEngineSocket(String hostname, int port, SSLParametersImpl sslParameters)
            throws IOException {
        super(hostname, port);
        engine = newEngine(sslParameters, this);
    }

    ConscryptEngineSocket(InetAddress address, int port, SSLParametersImpl sslParameters)
            throws IOException {
        super(address, port);
        engine = newEngine(sslParameters, this);
    }

    ConscryptEngineSocket(String hostname, int port, InetAddress clientAddress, int clientPort,
            SSLParametersImpl sslParameters) throws IOException {
        super(hostname, port, clientAddress, clientPort);
        engine = newEngine(sslParameters, this);
    }

    ConscryptEngineSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort,
            SSLParametersImpl sslParameters) throws IOException {
        super(address, port, clientAddress, clientPort);
        engine = newEngine(sslParameters, this);
    }

    ConscryptEngineSocket(Socket socket, String hostname, int port, boolean autoClose,
            SSLParametersImpl sslParameters) throws IOException {
        super(socket, hostname, port, autoClose);
        engine = newEngine(sslParameters, this);
    }

    private static ConscryptEngine newEngine(
            SSLParametersImpl sslParameters, final ConscryptEngineSocket socket) {
        ConscryptEngine engine = new ConscryptEngine(sslParameters, socket.peerInfoProvider());

        // When the handshake completes, notify any listeners.
        engine.setHandshakeListener(new HandshakeListener() {
            /**
             * Protected by {@code stateLock}
             */
            @Override
            public void onHandshakeFinished() {
                // Just call the outer class method.
                socket.onHandshakeFinished();
            }
        });

        // Transition the engine state to MODE_SET
        engine.setUseClientMode(sslParameters.getUseClientMode());
        return engine;
    }

    @Override
    public SSLParameters getSSLParameters() {
        return engine.getSSLParameters();
    }

    @Override
    public void setSSLParameters(SSLParameters sslParameters) {
        engine.setSSLParameters(sslParameters);
    }

    @Override
    public void startHandshake() throws IOException {
        checkOpen();

        if (isHandshakeFinished()) {
            // TODO(nmittler): Handle renegotiation.
            return;
        }

        try {
            synchronized (handshakeLock) {
                // Only lock stateLock when we begin the handshake. This is done so that we don't
                // hold the stateLock when we invoke the handshake completion listeners.
                synchronized (stateLock) {
                    // Initialize the handshake if we haven't already.
                    if (state == STATE_NEW) {
                        state = STATE_HANDSHAKE_STARTED;
                        engine.beginHandshake();
                        in = new SSLInputStream();
                        out = new SSLOutputStream();
                    } else {
                        // We've either started the handshake already or have been closed.
                        // Do nothing in both cases.
                        return;
                    }
                }

                boolean finished = false;
                while (!finished) {
                    switch (engine.getHandshakeStatus()) {
                        case NEED_UNWRAP:
                            if (in.readInternal(EmptyArray.BYTE, 0, 0) < 0) {
                                // Can't complete the handshake due to EOF.
                                throw SSLUtils.toSSLHandshakeException(new EOFException());
                            }
                            break;
                        case NEED_WRAP: {
                            out.writeInternal(EMPTY_BUFFER);
                            // Always flush handshake frames immediately.
                            out.flushInternal();
                            break;
                        }
                        case NEED_TASK:
                            // Should never get here, since our engine never provides tasks.
                            throw new IllegalStateException("Engine tasks are unsupported");
                        case NOT_HANDSHAKING:
                        case FINISHED:
                            // Handshake is complete.
                            finished = true;
                            break;
                        default: {
                            throw new IllegalStateException(
                                    "Unknown handshake status: " + engine.getHandshakeStatus());
                        }
                    }
                }
            }
        } catch (SSLException e) {
            close();
            throw e;
        } catch (IOException e) {
            close();
            throw e;
        } catch (Exception e) {
            close();
            // Convert anything else to a handshake exception.
            throw SSLUtils.toSSLHandshakeException(e);
        }
    }

    @Override
    public InputStream getInputStream() throws IOException {
        checkOpen();

        // Block waiting for a handshake without a lock held. It's possible that the socket
        // is closed at this point. If that happens, we'll still return the input stream but
        // all reads on it will throw.
        waitForHandshake();
        return in;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        checkOpen();

        // Block waiting for a handshake without a lock held. It's possible that the socket
        // is closed at this point. If that happens, we'll still return the input stream but
        // all reads on it will throw.
        waitForHandshake();

        return out;
    }

    @Override
    public SSLSession getHandshakeSession() {
        return engine.handshakeSession();
    }

    @Override
    public SSLSession getSession() {
        SSLSession session = engine.getSession();
        if (session == null) {
            boolean handshakeCompleted = false;
            try {
                if (isConnected()) {
                    waitForHandshake();
                    handshakeCompleted = true;
                }
            } catch (IOException e) {
                // Fall through.
            }

            if (!handshakeCompleted) {
                // return an invalid session with
                // invalid cipher suite of "SSL_NULL_WITH_NULL_NULL"
                return SSLNullSession.getNullSession();
            }
            session = engine.getSession();
        }
        return session;
    }

    @Override
    SSLSession getActiveSession() {
        return engine.getSession();
    }

    @Override
    public boolean getEnableSessionCreation() {
        return engine.getEnableSessionCreation();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        engine.setEnableSessionCreation(flag);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return engine.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return engine.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        engine.setEnabledCipherSuites(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return engine.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return engine.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        engine.setEnabledProtocols(protocols);
    }

    /**
     * This method enables Server Name Indication
     *
     * @param hostname the desired SNI hostname, or null to disable
     */
    @Override
    public void setHostname(String hostname) {
        engine.setHostname(hostname);
        super.setHostname(hostname);
    }

    @Override
    public void setUseSessionTickets(boolean useSessionTickets) {
        engine.setUseSessionTickets(useSessionTickets);
    }

    @Override
    public void setChannelIdEnabled(boolean enabled) {
        engine.setChannelIdEnabled(enabled);
    }

    @Override
    public byte[] getChannelId() throws SSLException {
        return engine.getChannelId();
    }

    @Override
    public void setChannelIdPrivateKey(PrivateKey privateKey) {
        engine.setChannelIdPrivateKey(privateKey);
    }

    @Override
    public boolean getUseClientMode() {
        return engine.getUseClientMode();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        engine.setUseClientMode(mode);
    }

    @Override
    public boolean getWantClientAuth() {
        return engine.getWantClientAuth();
    }

    @Override
    public boolean getNeedClientAuth() {
        return engine.getNeedClientAuth();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        engine.setNeedClientAuth(need);
    }

    @Override
    public void setWantClientAuth(boolean want) {
        engine.setWantClientAuth(want);
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void close() throws IOException {
        // TODO: Close SSL sockets using a background thread so they close gracefully.

        synchronized (stateLock) {
            if (state == STATE_CLOSED) {
                // close() has already been called, so do nothing and return.
                return;
            }

            state = STATE_CLOSED;

            stateLock.notifyAll();
        }

        // Close the underlying socket.
        super.close();

        // Close the engine.
        engine.closeInbound();
        engine.closeOutbound();
    }

    @Override
    public byte[] getAlpnSelectedProtocol() {
        return engine.getAlpnSelectedProtocol();
    }

    @Override
    public void setAlpnProtocols(byte[] alpnProtocols) {
        engine.setAlpnProtocols(alpnProtocols);
    }

    @Override
    public void setAlpnProtocols(String[] alpnProtocols) {
        engine.setAlpnProtocols(alpnProtocols);
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

    private boolean isHandshakeFinished() {
        return state >= STATE_READY_HANDSHAKE_CUT_THROUGH;
    }

    private void onHandshakeFinished() {
        boolean notify = false;
        synchronized (stateLock) {
            if (state != STATE_CLOSED) {
                if (state == STATE_HANDSHAKE_STARTED) {
                    state = STATE_READY_HANDSHAKE_CUT_THROUGH;
                } else if (state == STATE_HANDSHAKE_COMPLETED) {
                    state = STATE_READY;
                }

                // Unblock threads that are waiting for our state to transition
                // into STATE_READY or STATE_READY_HANDSHAKE_CUT_THROUGH.
                stateLock.notifyAll();
                notify = true;
            }
        }

        if (notify) {
            notifyHandshakeCompletedListeners();
        }
    }

    /**
     * Waits for the handshake to complete.
     */
    private void waitForHandshake() throws IOException {
        startHandshake();

        synchronized (stateLock) {
            while (state != STATE_READY && state != STATE_READY_HANDSHAKE_CUT_THROUGH
                    && state != STATE_CLOSED) {
                try {
                    stateLock.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted waiting for handshake", e);
                }
            }

            if (state == STATE_CLOSED) {
                throw new SocketException("Socket is closed");
            }
        }
    }

    private OutputStream getUnderlyingOutputStream() throws IOException {
        return super.getOutputStream();
    }

    private InputStream getUnderlyingInputStream() throws IOException {
        return super.getInputStream();
    }

    private SocketChannel getUnderlyingChannel() throws IOException {
        return super.getChannel();
    }

    /**
     * Wrap bytes written to the underlying socket.
     */
    private final class SSLOutputStream extends OutputStream {
        private final Object writeLock = new Object();
        private ByteBuffer target;
        private OutputStream socketOutputStream;
        private SocketChannel socketChannel;

        SSLOutputStream() {}

        @Override
        public void close() throws IOException {
            ConscryptEngineSocket.this.close();
        }

        @Override
        public void write(int b) throws IOException {
            startHandshake();
            synchronized (writeLock) {
                write(new byte[] {(byte) b});
            }
        }

        @Override
        public void write(byte[] b) throws IOException {
            startHandshake();
            synchronized (writeLock) {
                writeInternal(ByteBuffer.wrap(b));
            }
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            startHandshake();
            synchronized (writeLock) {
                writeInternal(ByteBuffer.wrap(b, off, len));
            }
        }

        private void writeInternal(ByteBuffer buffer) throws IOException {
            Platform.blockGuardOnNetwork();
            checkOpen();
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
                    throw new SSLException("Unexpected engine result " + engineResult.getStatus());
                }
                if (target.position() != engineResult.bytesProduced()) {
                    throw new SSLException("Engine bytesProduced " + engineResult.bytesProduced()
                            + " does not match bytes written " + target.position());
                }
                len -= engineResult.bytesConsumed();
                if (len != buffer.remaining()) {
                    throw new SSLException("Engine did not read the correct number of bytes");
                }

                target.flip();

                // Write the data to the socket.
                writeToSocket();
            } while (len > 0);
        }

        @Override
        public void flush() throws IOException {
            startHandshake();
            synchronized (writeLock) {
                flushInternal();
            }
        }

        private void flushInternal() throws IOException {
            checkOpen();
            init();
            socketOutputStream.flush();
        }

        private void init() throws IOException {
            if (socketOutputStream == null) {
                socketOutputStream = getUnderlyingOutputStream();
                socketChannel = getUnderlyingChannel();
                if (socketChannel != null) {
                    // Optimization. Using direct buffers wherever possible to avoid passing
                    // arrays to JNI.
                    target = ByteBuffer.allocateDirect(engine.getSession().getPacketBufferSize());
                } else {
                    target = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
                }
            }
        }

        private void writeToSocket() throws IOException {
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
        }
    }

    /**
     * Unwrap bytes read from the underlying socket.
     */
    private final class SSLInputStream extends InputStream {
        private final Object readLock = new Object();
        private final byte[] singleByte = new byte[1];
        private final ByteBuffer fromEngine;
        private ByteBuffer fromSocket;
        private InputStream socketInputStream;
        private SocketChannel socketChannel;

        SSLInputStream() {
            fromEngine = ByteBuffer.allocateDirect(engine.getSession().getApplicationBufferSize());
            // Initially fromEngine.remaining() == 0.
            fromEngine.flip();
        }

        @Override
        public void close() throws IOException {
            ConscryptEngineSocket.this.close();
        }

        @Override
        public int read() throws IOException {
            startHandshake();
            synchronized (readLock) {
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
            startHandshake();
            synchronized (readLock) {
                return read(b, 0, b.length);
            }
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            startHandshake();
            synchronized (readLock) {
                return readInternal(b, off, len);
            }
        }

        @Override
        public int available() throws IOException {
            startHandshake();
            synchronized (readLock) {
                init();
                return fromEngine.remaining()
                        + (fromSocket.hasRemaining() || socketInputStream.available() > 0 ? 1 : 0);
            }
        }

        private int readInternal(byte[] b, int off, int len) throws IOException {
            Platform.blockGuardOnNetwork();
            checkOpen();

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
                boolean needMoreDataFromSocket = true;

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
                        needMoreDataFromSocket = false;
                        break;
                    }
                    case OK: {
                        // We processed the entire packet successfully.
                        needMoreDataFromSocket = false;
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

                if (!needMoreDataFromSocket && engineResult.bytesProduced() == 0) {
                    // Read successfully, but produced no data. Possibly part of a
                    // handshake.
                    return 0;
                }

                // Read more data from the socket.
                if (needMoreDataFromSocket && readFromSocket() == -1) {
                    // Failed to read the next encrypted packet before reaching EOF.
                    return -1;
                }

                // Continue the loop and return the data from the engine buffer.
            }
        }

        private void init() throws IOException {
            if (socketInputStream == null) {
                socketInputStream = getUnderlyingInputStream();
                socketChannel = getUnderlyingChannel();
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
