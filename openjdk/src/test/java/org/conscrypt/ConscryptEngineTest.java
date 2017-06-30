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

import static org.conscrypt.Conscrypt.Engines.setBufferAllocator;
import static org.conscrypt.TestUtils.PROTOCOL_TLS_V1_2;
import static org.conscrypt.TestUtils.TEST_CIPHER;
import static org.conscrypt.TestUtils.initEngine;
import static org.conscrypt.TestUtils.initSslContext;
import static org.conscrypt.TestUtils.newTextMessage;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
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
import libcore.java.security.TestKeyStore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class ConscryptEngineTest {
    private static final int MESSAGE_SIZE = 4096;

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
    private ByteBuffer clientApplicationBuffer;
    private ByteBuffer clientPacketBuffer;
    private ByteBuffer serverApplicationBuffer;
    private ByteBuffer serverPacketBuffer;

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
        doHandshake();

        ByteBuffer clientCleartextBuffer = bufferType.newBuffer(MESSAGE_SIZE);
        clientCleartextBuffer.put(newTextMessage(MESSAGE_SIZE));
        clientCleartextBuffer.flip();

        // Wrap the original message and create the encrypted data.
        final int numMessages = 100;
        ByteBuffer[] encryptedBuffers = new ByteBuffer[numMessages];
        for (int i = 0; i < numMessages; ++i) {
            clientCleartextBuffer.position(0);
            ByteBuffer out = bufferType.newBuffer(clientEngine.getSession().getPacketBufferSize());
            SSLEngineResult wrapResult = clientEngine.wrap(clientCleartextBuffer, out);
            assertEquals(SSLEngineResult.Status.OK, wrapResult.getStatus());
            out.flip();
            encryptedBuffers[i] = out;
        }

        // Create the expected cleartext message
        clientCleartextBuffer.position(0);
        byte[] expectedMessage = toArray(clientCleartextBuffer);

        // Unwrap the all of the encrypted messages.
        for (int i = 0; i < numMessages; ++i) {
            ByteBuffer out = bufferType.newBuffer(2 * MESSAGE_SIZE);
            SSLEngineResult unwrapResult = Conscrypt.Engines.unwrap(
                    serverEngine, encryptedBuffers, new ByteBuffer[] {out});
            assertEquals(SSLEngineResult.Status.OK, unwrapResult.getStatus());
            assertEquals(MESSAGE_SIZE, unwrapResult.bytesProduced());

            out.flip();
            byte[] actualMessage = toArray(out);
            assertArrayEquals(expectedMessage, actualMessage);
        }
    }

    @Test
    public void exchangeLargeMessage() throws Exception {
        setupEngines(TestKeyStore.getClient(), TestKeyStore.getServer());
        doHandshake();

        // Create the input message.
        final int largeMessageSize = 16413;
        final byte[] message = newTextMessage(largeMessageSize);
        ByteBuffer inputBuffer = bufferType.newBuffer(largeMessageSize);
        inputBuffer.put(message);
        inputBuffer.flip();

        // Encrypt the input message.
        List<ByteBuffer> encryptedBufferList = new ArrayList<ByteBuffer>();
        while (inputBuffer.hasRemaining()) {
            ByteBuffer encryptedBuffer =
                    bufferType.newBuffer(clientEngine.getSession().getPacketBufferSize());
            SSLEngineResult wrapResult = clientEngine.wrap(inputBuffer, encryptedBuffer);
            assertEquals(SSLEngineResult.Status.OK, wrapResult.getStatus());
            encryptedBuffer.flip();
            encryptedBufferList.add(encryptedBuffer);
        }

        // Unwrap the all of the encrypted messages.
        ByteArrayOutputStream cleartextStream = new ByteArrayOutputStream();
        ByteBuffer[] encryptedBuffers =
                encryptedBufferList.toArray(new ByteBuffer[encryptedBufferList.size()]);
        int decryptedBufferSize = 8192;
        final ByteBuffer decryptedBuffer = bufferType.newBuffer(decryptedBufferSize);
        for (ByteBuffer encryptedBuffer : encryptedBuffers) {
            SSLEngineResult.Status status = SSLEngineResult.Status.OK;
            while (encryptedBuffer.hasRemaining() || status.equals(Status.BUFFER_OVERFLOW)) {
                if (!decryptedBuffer.hasRemaining()) {
                    decryptedBuffer.clear();
                }
                int prevPos = decryptedBuffer.position();
                SSLEngineResult unwrapResult = Conscrypt.Engines.unwrap(
                        serverEngine, encryptedBuffers, new ByteBuffer[] {decryptedBuffer});
                status = unwrapResult.getStatus();
                int newPos = decryptedBuffer.position();
                int bytesProduced = unwrapResult.bytesProduced();
                assertEquals(bytesProduced, newPos - prevPos);

                // Add any generated bytes to the output stream.
                if (bytesProduced > 0) {
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
        }
        byte[] actualMessage = cleartextStream.toByteArray();
        assertArrayEquals(message, actualMessage);
    }

    private void doMutualAuthHandshake(
            TestKeyStore clientKs, TestKeyStore serverKs, ClientAuth clientAuth) throws Exception {
        setupEngines(clientKs, serverKs);
        clientAuth.apply(serverEngine);
        doHandshake();
        assertEquals(HandshakeStatus.NOT_HANDSHAKING, clientEngine.getHandshakeStatus());
        assertEquals(HandshakeStatus.NOT_HANDSHAKING, serverEngine.getHandshakeStatus());
    }

    private void doHandshake() throws SSLException {
        TestUtils.doEngineHandshake(clientEngine, serverEngine, clientApplicationBuffer,
                clientPacketBuffer, serverApplicationBuffer, serverPacketBuffer);
    }

    private void setupEngines(TestKeyStore clientKeyStore, TestKeyStore serverKeyStore)
            throws SSLException {
        SSLContext clientContext = initSslContext(newContext(), clientKeyStore);
        SSLContext serverContext = initSslContext(newContext(), serverKeyStore);

        clientEngine = initEngine(clientContext.createSSLEngine(), TEST_CIPHER, true);
        serverEngine = initEngine(serverContext.createSSLEngine(), TEST_CIPHER, false);
        setBufferAllocator(clientEngine, bufferType.allocator);
        setBufferAllocator(serverEngine, bufferType.allocator);

        // Create the application and packet buffers for both endpoints.
        clientApplicationBuffer =
            bufferType.newBuffer(clientEngine.getSession().getApplicationBufferSize());
        serverApplicationBuffer =
            bufferType.newBuffer(serverEngine.getSession().getApplicationBufferSize());
        clientPacketBuffer = bufferType.newBuffer(clientEngine.getSession().getPacketBufferSize());
        serverPacketBuffer = bufferType.newBuffer(serverEngine.getSession().getPacketBufferSize());
    }

    private static byte[] toArray(ByteBuffer buffer) {
        byte[] data = new byte[buffer.remaining()];
        buffer.get(data);
        return data;
    }

    private static SSLContext newContext() {
        try {
            return SSLContext.getInstance(PROTOCOL_TLS_V1_2, new OpenSSLProvider());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
