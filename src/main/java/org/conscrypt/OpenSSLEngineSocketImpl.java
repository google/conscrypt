package org.conscrypt;

import static javax.net.ssl.SSLEngineResult.Status.OK;

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
import java.util.ArrayList;
import javax.crypto.SecretKey;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;

/**
 * Implements crypto handling by delegating to OpenSSLEngine. Used for socket implementations
 * that are not backed by a real OS socket.
 */
public final class OpenSSLEngineSocketImpl extends OpenSSLSocketImplWrapper {

    private final OpenSSLEngineImpl openSSLEngine;
    private final Socket socket;
    private final OutputStreamWrapper outputStreamWrapper;
    private final InputStreamWrapper inputStreamWrapper;
    private ArrayList<HandshakeCompletedListener> listeners;

    public OpenSSLEngineSocketImpl(Socket socket, String hostname, int port, boolean autoClose,
                                   SSLParametersImpl sslParameters) throws IOException {
        super(socket, hostname, port, autoClose, sslParameters);
        this.socket = socket;
        openSSLEngine = new OpenSSLEngineImpl(hostname, port, sslParameters);
        outputStreamWrapper = new OutputStreamWrapper();
        inputStreamWrapper = new InputStreamWrapper();
        openSSLEngine.setUseClientMode(sslParameters.getUseClientMode());
    }

    @Override
    public void startHandshake() throws IOException {
        // Trigger the handshake
        boolean beginHandshakeCalled = false;
        for (; ; ) {
            switch (openSSLEngine.getHandshakeStatus()) {
                case NOT_HANDSHAKING: {
                    if (!beginHandshakeCalled) {
                        beginHandshakeCalled = true;
                        openSSLEngine.beginHandshake();
                        break;
                    } else {
                        // Notify handshake completion even though handshaking is being skipped.
                        notifyHandshakeCompletedListeners();
                        return;
                    }
                }
                case NEED_WRAP: {
                    outputStreamWrapper.write(new byte[]{});
                    break;
                }
                case NEED_UNWRAP: {
                    inputStreamWrapper.read(new byte[]{});
                    break;
                }
                case NEED_TASK: {
                    openSSLEngine.getDelegatedTask().run();
                    break;
                }
                case FINISHED: {
                    notifyHandshakeCompletedListeners();
                    return;
                }
            }
        }
    }

    @Override
    public void onSSLStateChange(long sslSessionNativePtr, int type, int val) {
        throw new AssertionError("Should be handled by engine");
    }

    @Override
    public void verifyCertificateChain(long sslSessionNativePtr, long[] certRefs, String authMethod)
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
        return openSSLEngine.getSession();
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
        throw new UnsupportedOperationException("Not supported");
    }

    @Override
    public byte[] getChannelId() throws SSLException {
        throw new UnsupportedOperationException("Not supported");
    }

    @Override
    public void setChannelIdPrivateKey(PrivateKey privateKey) {
        throw new UnsupportedOperationException("FIXME");
    }

    @Override
    public boolean getUseClientMode() {
        return super.getUseClientMode();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        openSSLEngine.setUseClientMode(mode);
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
        //throw new UnsupportedOperationException("Not supported");
    }

    @Override
    public void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException {
        throw new UnsupportedOperationException("Not supported");
    }

    @Override
    public synchronized void close() throws IOException {
        openSSLEngine.closeInbound();
        openSSLEngine.closeOutbound();
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
        return openSSLEngine.getNpnSelectedProtocol();
    }

    @Override
    public byte[] getAlpnSelectedProtocol() {
        return openSSLEngine.getAlpnSelectedProtocol();
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
        return openSSLEngine.chooseServerAlias(keyManager, keyType);
    }

    @Override
    public String chooseClientAlias(X509KeyManager keyManager, X500Principal[] issuers,
                                    String[] keyTypes) {
        return openSSLEngine.chooseClientAlias(keyManager, issuers, keyTypes);
    }

    @Override
    public String chooseServerPSKIdentityHint(PSKKeyManager keyManager) {
        return openSSLEngine.chooseServerPSKIdentityHint(keyManager);
    }

    @Override
    public String chooseClientPSKIdentity(PSKKeyManager keyManager, String identityHint) {
        return openSSLEngine.chooseClientPSKIdentity(keyManager, identityHint);
    }

    @Override
    public SecretKey getPSKKey(PSKKeyManager keyManager, String identityHint, String identity) {
        return openSSLEngine.getPSKKey(keyManager, identityHint, identity);
    }

    /**
     * Wrap bytes written to the underlying socket.
     */
    private class OutputStreamWrapper extends OutputStream {

        private final ByteBuffer target;

        public OutputStreamWrapper() {
            target = ByteBuffer.allocate(openSSLEngine.getSession().getPacketBufferSize());
        }

        @Override
        public void write(byte[] b) throws IOException {
            write(b, 0, b.length);
        }

        @Override
        public synchronized void write(byte[] b, int off, int len) throws IOException {
            ByteBuffer wrap = ByteBuffer.wrap(b, off, len);
            // Need to loop through at least once to enable handshaking where no application bytes are
            // processed.
            do {
                SSLEngineResult engineResult = openSSLEngine.wrap(wrap, target);
                len -= engineResult.bytesConsumed();
                socket.getOutputStream().write(target.array(), 0, target.position());
                target.clear();
                if (engineResult.getStatus() != OK) {
                    throw new IllegalStateException("Unexpected engine result " + engineResult.getStatus());
                }
            } while (len > 0);
        }

        @Override
        public void flush() throws IOException {
            socket.getOutputStream().flush();
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[]{(byte) b});
        }
    }

    /**
     * Unwrap bytes read from the underlying socket.
     */
    private class InputStreamWrapper extends InputStream {

        private final byte[] singleByte = new byte[1];
        private final ByteBuffer fromSocket;
        private final ByteBuffer fromEngine;
        private InputStream socketInputStream;

        public InputStreamWrapper() {
            fromSocket = ByteBuffer.allocate(openSSLEngine.getSession().getPacketBufferSize());
            fromEngine = ByteBuffer.allocate(openSSLEngine.getSession().getApplicationBufferSize());
            fromEngine.flip();
        }

        @Override
        public int read(byte[] b) throws IOException {
            return read(b, 0, b.length);
        }

        @Override
        public synchronized int read(byte[] b, int off, int len) throws IOException {
            if (socketInputStream == null) {
                socketInputStream = socket.getInputStream();
            }
            for (; ; ) {
                // Consume bytes we have already passed through the engine and return them immediately
                if (fromEngine.remaining() > 0) {
                    int readFromEngine = Math.min(fromEngine.remaining(), len);
                    fromEngine.get(b, off, readFromEngine);
                    return readFromEngine;
                }
                // Clear the buffer so we can process more bytes through the engine
                fromEngine.clear();

                // Otherwise read more bytes from the socket and process them with the engine

                int read = socketInputStream.read(fromSocket.array(), fromSocket.position(),
                        fromSocket.remaining());
                if (read == -1 && fromSocket.position() == 0) {
                    // No bytes left to process and socket is now unreadable.
                    return -1;
                }
                fromSocket.position(fromSocket.position() + read);
                fromSocket.flip();
                SSLEngineResult engineResult = openSSLEngine.unwrap(fromSocket, fromEngine);
                fromEngine.flip();
                fromSocket.compact();
                if (engineResult.getStatus() == OK) {
                    if (engineResult.bytesProduced() == 0) {
                        return 0;
                    }
                } else {
                    throw new IllegalStateException("Unexpected engine result " + engineResult.getStatus());
                }
            }
        }

        @Override
        public synchronized int read() throws IOException {
            int count = read(singleByte, 0, 1);
            return count != 1 ? count : (int) singleByte[0];
        }
    }
}
