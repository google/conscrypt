/*
 * Copyright (C) 2017 The Android Open Source Project
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
 * limitations under the License
 */

package org.conscrypt;

import static org.conscrypt.TestUtils.getConscryptProvider;
import static org.conscrypt.TestUtils.getJdkProvider;
import static org.conscrypt.TestUtils.getProtocols;
import static org.conscrypt.TestUtils.initSslContext;
import static org.conscrypt.TestUtils.newTextMessage;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import org.conscrypt.java.security.TestKeyStore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.Matchers;
import org.mockito.Mockito;

@RunWith(Parameterized.class)
public class ConscryptEngineTest {
    private static final int MESSAGE_SIZE = 4096;
    private static final int LARGE_MESSAGE_SIZE = 16413;
    private static final String[] CIPHERS = TestUtils.getCommonCipherSuites();
    private static final String RENEGOTIATION_CIPHER = CIPHERS[CIPHERS.length - 1];

    @SuppressWarnings("ImmutableEnumChecker")
    public enum BufferType {
        HEAP_ALLOCATOR(BufferAllocator.unpooled()) {
            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocate(size);
            }
        },
        HEAP_NO_ALLOCATOR(null) {
            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocate(size);
            }
        },
        DIRECT(null) {
            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocateDirect(size);
            }
        };

        abstract ByteBuffer newBuffer(int size);

        BufferType(BufferAllocator allocator) {
            this.allocator = allocator;
        }

        private final BufferAllocator allocator;
    }

    private enum ClientAuth {
        NONE {
            @Override
            void apply(SSLEngine engine) {
                engine.setWantClientAuth(false);
                engine.setNeedClientAuth(false);
            }
        },
        OPTIONAL {
            @Override
            void apply(SSLEngine engine) {
                engine.setWantClientAuth(true);
                engine.setNeedClientAuth(false);
            }
        },
        REQUIRED {
            @Override
            void apply(SSLEngine engine) {
                engine.setWantClientAuth(false);
                engine.setNeedClientAuth(true);
            }
        };

        abstract void apply(SSLEngine engine);
    }

    @Parameters(name = "{0}")
    public static Iterable<BufferType> data() {
        return Arrays.asList(
                BufferType.HEAP_ALLOCATOR, BufferType.HEAP_NO_ALLOCATOR, BufferType.DIRECT);
    }

    @Parameter public BufferType bufferType;

    private SSLEngine clientEngine;
    private SSLEngine serverEngine;

    @Test
    public void closingOutboundBeforeHandshakeShouldCloseAll() throws Exception {
        setupEngines(TestKeyStore.getClient(), TestKeyStore.getServer());
        assertFalse(clientEngine.isInboundDone());
        assertFalse(clientEngine.isOutboundDone());
        assertFalse(serverEngine.isInboundDone());
        assertFalse(serverEngine.isOutboundDone());

        clientEngine.closeOutbound();
        serverEngine.closeOutbound();

        assertTrue(clientEngine.isInboundDone());
        assertTrue(clientEngine.isOutboundDone());
        assertTrue(serverEngine.isInboundDone());
        assertTrue(serverEngine.isOutboundDone());
    }

    @Test
    public void closingOutboundAfterHandshakeShouldOnlyCloseOutbound() throws Exception {
        setupEngines(TestKeyStore.getClient(), TestKeyStore.getServer());
        doHandshake(true);

        assertFalse(clientEngine.isInboundDone());
        assertFalse(clientEngine.isOutboundDone());
        assertFalse(serverEngine.isInboundDone());
        assertFalse(serverEngine.isOutboundDone());

        clientEngine.closeOutbound();
        serverEngine.closeOutbound();

        assertFalse(clientEngine.isInboundDone());
        assertTrue(clientEngine.isOutboundDone());
        assertFalse(serverEngine.isInboundDone());
        assertTrue(serverEngine.isOutboundDone());
    }

    @Test
    public void closingInboundShouldOnlyCloseInbound() throws Exception {
        setupEngines(TestKeyStore.getClient(), TestKeyStore.getServer());
        doHandshake(true);

        assertFalse(clientEngine.isInboundDone());
        assertFalse(clientEngine.isOutboundDone());
        assertFalse(serverEngine.isInboundDone());
        assertFalse(serverEngine.isOutboundDone());

        clientEngine.closeInbound();
        serverEngine.closeInbound();

        assertTrue(clientEngine.isInboundDone());
        assertFalse(clientEngine.isOutboundDone());
        assertTrue(serverEngine.isInboundDone());
        assertFalse(serverEngine.isOutboundDone());
    }

    @Test
    public void mutualAuthWithSameCertsShouldSucceed() throws Exception {
        doMutualAuthHandshake(TestKeyStore.getServer(), TestKeyStore.getServer(), ClientAuth.NONE);
    }

    @Test
    public void mutualAuthWithDifferentCertsShouldSucceed() throws Exception {
        doMutualAuthHandshake(TestKeyStore.getClient(), TestKeyStore.getServer(), ClientAuth.NONE);
    }

    @Test(expected = SSLHandshakeException.class)
    public void mutualAuthWithUntrustedServerShouldFail() throws Exception {
        doMutualAuthHandshake(
                TestKeyStore.getClientCA2(), TestKeyStore.getServer(), ClientAuth.NONE);
    }

    @Test(expected = SSLHandshakeException.class)
    public void mutualAuthWithUntrustedClientShouldFail() throws Exception {
        doMutualAuthHandshake(TestKeyStore.getClient(), TestKeyStore.getClient(), ClientAuth.NONE);
    }

    @Test
    public void optionalClientAuthShouldSucceed() throws Exception {
        doMutualAuthHandshake(
                TestKeyStore.getClient(), TestKeyStore.getServer(), ClientAuth.OPTIONAL);
    }

    @Test(expected = SSLHandshakeException.class)
    public void optionalClientAuthShouldFail() throws Exception {
        doMutualAuthHandshake(
                TestKeyStore.getClient(), TestKeyStore.getClient(), ClientAuth.OPTIONAL);
    }

    @Test
    public void requiredClientAuthShouldSucceed() throws Exception {
        doMutualAuthHandshake(
                TestKeyStore.getServer(), TestKeyStore.getServer(), ClientAuth.REQUIRED);
    }

    @Test(expected = SSLHandshakeException.class)
    public void requiredClientAuthShouldFail() throws Exception {
        doMutualAuthHandshake(
                TestKeyStore.getClient(), TestKeyStore.getClient(), ClientAuth.REQUIRED);
    }

    @Test
    public void exchangeMessages() throws Exception {
        setupEngines(TestKeyStore.getClient(), TestKeyStore.getServer());
        doHandshake(true);

        ByteBuffer message = newMessage(MESSAGE_SIZE);
        byte[] messageBytes = toArray(message);

        // Wrap the original message and create the encrypted data.
        final int numMessages = 100;
        ByteBuffer[] encryptedBuffers = new ByteBuffer[numMessages];
        for (int i = 0; i < numMessages; ++i) {
            List<ByteBuffer> wrapped = wrap(message.duplicate(), clientEngine);
            // Small message, we should only have 1 buffer created.
            assertEquals(1, wrapped.size());
            encryptedBuffers[i] = wrapped.get(0);
        }

        // Unwrap the all of the encrypted messages.
        byte[] actualBytes = unwrap(encryptedBuffers, serverEngine);
        assertEquals(MESSAGE_SIZE * numMessages, actualBytes.length);
        for (int i = 0; i < numMessages; ++i) {
            int offset = i * MESSAGE_SIZE;
            byte[] actualMessageBytes =
                    Arrays.copyOfRange(actualBytes, offset, offset + MESSAGE_SIZE);
            assertArrayEquals(messageBytes, actualMessageBytes);
        }
    }

    @Test
    public void exchangeLargeMessage() throws Exception {
        setupEngines(TestKeyStore.getClient(), TestKeyStore.getServer());
        doHandshake(true);

        ByteBuffer inputBuffer = newMessage(LARGE_MESSAGE_SIZE);
        exchangeMessage(inputBuffer, clientEngine, serverEngine);
    }

    @Test
    public void alpnWithProtocolListShouldSucceed() throws Exception {
        setupEngines(TestKeyStore.getClient(), TestKeyStore.getServer());

        // Configure ALPN protocols
        String[] clientAlpnProtocols = new String[]{"http/1.1", "foo", "spdy/2"};
        String[] serverAlpnProtocols = new String[]{"spdy/2", "foo", "bar"};

        Conscrypt.setApplicationProtocols(clientEngine, clientAlpnProtocols);
        Conscrypt.setApplicationProtocols(serverEngine, serverAlpnProtocols);

        doHandshake(true);
        assertEquals("spdy/2", Conscrypt.getApplicationProtocol(clientEngine));
        assertEquals("spdy/2", Conscrypt.getApplicationProtocol(serverEngine));
    }

    @Test
    public void alpnWithProtocolListShouldFail() throws Exception {
        setupEngines(TestKeyStore.getClient(), TestKeyStore.getServer());

        // Configure ALPN protocols
        String[] clientAlpnProtocols = new String[]{"http/1.1", "foo", "spdy/2"};
        String[] serverAlpnProtocols = new String[]{"h2", "bar", "baz"};

        Conscrypt.setApplicationProtocols(clientEngine, clientAlpnProtocols);
        Conscrypt.setApplicationProtocols(serverEngine, serverAlpnProtocols);

        doHandshake(true);
        assertNull(Conscrypt.getApplicationProtocol(clientEngine));
        assertNull(Conscrypt.getApplicationProtocol(serverEngine));
    }

    @Test
    public void alpnWithServerProtocolSelectorShouldSucceed() throws Exception {
        setupEngines(TestKeyStore.getClient(), TestKeyStore.getServer());

        // Configure client protocols.
        String[] clientAlpnProtocols = new String[]{"http/1.1", "foo", "spdy/2"};
        Conscrypt.setApplicationProtocols(clientEngine, clientAlpnProtocols);

        // Configure server selector
        ApplicationProtocolSelector selector = Mockito.mock(ApplicationProtocolSelector.class);
        when(selector.selectApplicationProtocol(same(serverEngine), Matchers.anyListOf(String.class)))
                .thenReturn("spdy/2");
        Conscrypt.setApplicationProtocolSelector(serverEngine, selector);

        doHandshake(true);
        assertEquals("spdy/2", Conscrypt.getApplicationProtocol(clientEngine));
        assertEquals("spdy/2", Conscrypt.getApplicationProtocol(serverEngine));
    }

    @Test
    public void alpnWithServerProtocolSelectorShouldFail() throws Exception {
        setupEngines(TestKeyStore.getClient(), TestKeyStore.getServer());

        // Configure client protocols.
        String[] clientAlpnProtocols = new String[]{"http/1.1", "foo", "spdy/2"};
        Conscrypt.setApplicationProtocols(clientEngine, clientAlpnProtocols);

        // Configure server selector
        ApplicationProtocolSelector selector = Mockito.mock(ApplicationProtocolSelector.class);
        when(selector.selectApplicationProtocol(same(serverEngine), Matchers.anyListOf(String.class)))
                .thenReturn("h2");
        Conscrypt.setApplicationProtocolSelector(serverEngine, selector);

        doHandshake(true);
        assertNull(Conscrypt.getApplicationProtocol(clientEngine));
        assertNull(Conscrypt.getApplicationProtocol(serverEngine));
    }

    /**
     * BoringSSL server doesn't support renegotiation. BoringSSL clients do not support
     * initiating a renegotiation, only processing a renegotiation initiated by the
     * (non-BoringSSL) server. For this reason we test a server-initiated renegotiation with
     * a Conscrypt client and a JDK server.
     */
    @Test
    public void serverInitiatedRenegotiationShouldSucceed() throws Exception {
        setupClientEngine(getConscryptProvider(), TestKeyStore.getClient());
        setupServerEngine(getJdkProvider(), TestKeyStore.getServer());

        // Perform the initial handshake.
        doHandshake(true);

        // Send a message from client->server.
        exchangeMessage(newMessage(MESSAGE_SIZE), clientEngine, serverEngine);

        // Trigger a renegotiation from the server and send a message back from Server->Client
        serverEngine.setEnabledCipherSuites(new String[] {RENEGOTIATION_CIPHER});
        serverEngine.beginHandshake();
        doHandshake(false);

        exchangeMessage(newMessage(MESSAGE_SIZE), serverEngine, clientEngine);
    }

    @Test
    public void savedSessionWorksAfterClose() throws Exception {
        setupEngines(TestKeyStore.getClient(), TestKeyStore.getServer());
        doHandshake(true);

        SSLSession session = clientEngine.getSession();
        String cipherSuite = session.getCipherSuite();

        clientEngine.closeOutbound();
        clientEngine.closeInbound();

        assertEquals(cipherSuite, session.getCipherSuite());
    }

    private void doMutualAuthHandshake(
            TestKeyStore clientKs, TestKeyStore serverKs, ClientAuth clientAuth) throws Exception {
        setupEngines(clientKs, serverKs);
        clientAuth.apply(serverEngine);
        doHandshake(true);
        assertEquals(HandshakeStatus.NOT_HANDSHAKING, clientEngine.getHandshakeStatus());
        assertEquals(HandshakeStatus.NOT_HANDSHAKING, serverEngine.getHandshakeStatus());
    }

    private void doHandshake(boolean beginHandshake) throws SSLException {
        ByteBuffer clientApplicationBuffer =
                bufferType.newBuffer(clientEngine.getSession().getApplicationBufferSize());
        ByteBuffer clientPacketBuffer =
                bufferType.newBuffer(clientEngine.getSession().getPacketBufferSize());
        ByteBuffer serverApplicationBuffer =
                bufferType.newBuffer(serverEngine.getSession().getApplicationBufferSize());
        ByteBuffer serverPacketBuffer =
                bufferType.newBuffer(serverEngine.getSession().getPacketBufferSize());
        TestUtils.doEngineHandshake(clientEngine, serverEngine, clientApplicationBuffer,
                clientPacketBuffer, serverApplicationBuffer, serverPacketBuffer, beginHandshake);
    }

    private void setupEngines(TestKeyStore clientKeyStore, TestKeyStore serverKeyStore) throws SSLException {
        setupClientEngine(getConscryptProvider(), clientKeyStore);
        setupServerEngine(getConscryptProvider(), serverKeyStore);
    }

    private void setupClientEngine(Provider provider, TestKeyStore clientKeyStore)
            throws SSLException {
        clientEngine = newEngine(provider, clientKeyStore, true);
    }

    private void setupServerEngine(Provider provider, TestKeyStore serverKeyStore)
            throws SSLException {
        serverEngine = newEngine(provider, serverKeyStore, false);
    }

    private SSLEngine newEngine(
            Provider provider, TestKeyStore keyStore, boolean client) {
        SSLContext serverContext = newContext(provider, keyStore);
        SSLEngine engine = serverContext.createSSLEngine();
        engine.setEnabledCipherSuites(CIPHERS);
        engine.setUseClientMode(client);
        if (Conscrypt.isConscrypt(engine)) {
            Conscrypt.setBufferAllocator(engine, bufferType.allocator);
        }
        return engine;
    }

    private void exchangeMessage(ByteBuffer inputBuffer, SSLEngine src, SSLEngine dest)
            throws IOException {
        byte[] messageBytes = toArray(inputBuffer);

        // Encrypt the input message.
        List<ByteBuffer> encryptedBufferList = wrap(inputBuffer, src);

        // Unwrap the all of the encrypted messages.
        ByteBuffer[] encryptedBuffers =
                encryptedBufferList.toArray(new ByteBuffer[encryptedBufferList.size()]);
        byte[] actualBytes = unwrap(encryptedBuffers, dest);
        assertArrayEquals(messageBytes, actualBytes);
    }

    private List<ByteBuffer> wrap(ByteBuffer input, SSLEngine engine) throws SSLException {
        // Encrypt the input message.
        List<ByteBuffer> wrapped = new ArrayList<ByteBuffer>();
        while (input.hasRemaining()) {
            ByteBuffer encryptedBuffer =
                    bufferType.newBuffer(engine.getSession().getPacketBufferSize());
            SSLEngineResult wrapResult = engine.wrap(input, encryptedBuffer);
            assertEquals(SSLEngineResult.Status.OK, wrapResult.getStatus());
            encryptedBuffer.flip();
            wrapped.add(encryptedBuffer);
        }
        return wrapped;
    }

    private byte[] unwrap(ByteBuffer[] encryptedBuffers, SSLEngine engine) throws IOException {
        ByteArrayOutputStream cleartextStream = new ByteArrayOutputStream();
        int decryptedBufferSize = 8192;
        final ByteBuffer encryptedBuffer = combine(encryptedBuffers);
        final ByteBuffer decryptedBuffer = bufferType.newBuffer(decryptedBufferSize);
        while (encryptedBuffer.hasRemaining()) {
            if (!decryptedBuffer.hasRemaining()) {
                decryptedBuffer.clear();
            }
            int prevPos = decryptedBuffer.position();
            SSLEngineResult unwrapResult = engine.unwrap(encryptedBuffer, decryptedBuffer);
            SSLEngineResult.Status status = unwrapResult.getStatus();
            switch (status) {
                case BUFFER_OVERFLOW:
                case OK: {
                    break;
                }
                default: { throw new RuntimeException("Unexpected SSLEngine status: " + status); }
            }
            int newPos = decryptedBuffer.position();
            int bytesProduced = unwrapResult.bytesProduced();
            assertEquals(bytesProduced, newPos - prevPos);

            // Add any generated bytes to the output stream.
            if (bytesProduced > 0 || status == Status.BUFFER_OVERFLOW) {
                byte[] decryptedBytes = new byte[unwrapResult.bytesProduced()];

                // Read the chunk that was just written to the output array.
                int limit = decryptedBuffer.limit();
                decryptedBuffer.limit(newPos);
                decryptedBuffer.position(prevPos);
                decryptedBuffer.get(decryptedBytes);

                // Restore the position and limit.
                decryptedBuffer.limit(limit);

                // Write the decrypted bytes to the stream.
                cleartextStream.write(decryptedBytes);
            }
        }

        return cleartextStream.toByteArray();
    }

    private ByteBuffer combine(ByteBuffer[] buffers) {
        int size = 0;
        for (ByteBuffer buffer : buffers) {
            size += buffer.remaining();
        }
        ByteBuffer combined = bufferType.newBuffer(size);
        for (ByteBuffer buffer : buffers) {
            combined.put(buffer);
        }
        combined.flip();
        return combined;
    }

    private ByteBuffer newMessage(int size) {
        ByteBuffer buffer = bufferType.newBuffer(size);
        buffer.put(newTextMessage(size));
        buffer.flip();
        return buffer;
    }

    private static byte[] toArray(ByteBuffer buffer) {
        int pos = buffer.position();
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        buffer.position(pos);
        return bytes;
    }

    private static SSLContext newContext(Provider provider, TestKeyStore keyStore) {
        try {
            SSLContext ctx = SSLContext.getInstance(getProtocols()[0], provider);
            return initSslContext(ctx, keyStore);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
