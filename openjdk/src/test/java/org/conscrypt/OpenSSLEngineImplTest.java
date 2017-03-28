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

import static org.conscrypt.TestUtils.PROTOCOL_TLS_V1_2;
import static org.conscrypt.TestUtils.initEngine;
import static org.conscrypt.TestUtils.initSslContext;
import static org.conscrypt.TestUtils.newTextMessage;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import libcore.java.security.TestKeyStore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class OpenSSLEngineImplTest {
    private static final String CIPHER = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
    private static final int MESSAGE_SIZE = 4096;

    public enum BufferType {
        HEAP {
            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocate(size);
            }
        },
        DIRECT {
            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocateDirect(size);
            }
        };

        abstract ByteBuffer newBuffer(int size);
    }

    private enum ClientAuth {
        NONE {
            @Override
            SSLEngine apply(SSLEngine engine) {
                engine.setWantClientAuth(false);
                engine.setNeedClientAuth(false);
                return engine;
            }
        },
        OPTIONAL {
            @Override
            SSLEngine apply(SSLEngine engine) {
                engine.setWantClientAuth(true);
                engine.setNeedClientAuth(false);
                return engine;
            }
        },
        REQUIRED {
            @Override
            SSLEngine apply(SSLEngine engine) {
                engine.setWantClientAuth(false);
                engine.setNeedClientAuth(true);
                return engine;
            }
        };

        abstract SSLEngine apply(SSLEngine engine);
    }

    @Parameters(name = "{0}")
    public static Iterable<BufferType> data() {
        return Arrays.asList(BufferType.HEAP, BufferType.DIRECT);
    }

    @Parameter
    public BufferType bufferType;

    private SSLEngine clientEngine;
    private SSLEngine serverEngine;

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
        doMutualAuthHandshake(TestKeyStore.getClientCA2(), TestKeyStore.getServer(), ClientAuth.NONE);
    }

    @Test(expected = SSLHandshakeException.class)
    public void mutualAuthWithUntrustedClientShouldFail() throws Exception {
        doMutualAuthHandshake(TestKeyStore.getClient(), TestKeyStore.getClient(), ClientAuth.NONE);
    }

    @Test
    public void optionalClientAuthShouldSucceed() throws Exception {
        doMutualAuthHandshake(TestKeyStore.getClient(), TestKeyStore.getServer(), ClientAuth.OPTIONAL);
    }

    @Test(expected = SSLHandshakeException.class)
    public void optionalClientAuthShouldFail() throws Exception {
        doMutualAuthHandshake(TestKeyStore.getClient(), TestKeyStore.getClient(), ClientAuth.OPTIONAL);
    }

    @Test
    public void requiredClientAuthShouldSucceed() throws Exception {
        doMutualAuthHandshake(TestKeyStore.getServer(), TestKeyStore.getServer(), ClientAuth.REQUIRED);
    }

    @Test(expected = SSLHandshakeException.class)
    public void requiredClientAuthShouldFail() throws Exception {
        doMutualAuthHandshake(TestKeyStore.getClient(), TestKeyStore.getClient(), ClientAuth.REQUIRED);
    }

    @Test
    public void exchangeMessages() throws Exception {
        setupEngines(TestKeyStore.getClient(), TestKeyStore.getServer());
        TestUtils.doEngineHandshake(clientEngine, serverEngine);

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
        ByteBuffer[] cleartextBuffers = new ByteBuffer[numMessages];
        for (int i = 0; i < numMessages; ++i) {
            ByteBuffer out = bufferType.newBuffer(2 * MESSAGE_SIZE);
            cleartextBuffers[i] = out;
            SSLEngineResult unwrapResult = Conscrypt.Engines.unwrap(serverEngine, encryptedBuffers,
                    new ByteBuffer[] {out});
            assertEquals(SSLEngineResult.Status.OK, unwrapResult.getStatus());
            assertEquals(MESSAGE_SIZE, unwrapResult.bytesProduced());

            out.flip();
            byte[] actualMessage = toArray(out);
            assertArrayEquals(expectedMessage, actualMessage);
        }
    }

    private void doMutualAuthHandshake(TestKeyStore clientKs, TestKeyStore serverKs, ClientAuth clientAuth) throws Exception {
        setupEngines(clientKs, serverKs);
        clientAuth.apply(serverEngine);
        TestUtils.doEngineHandshake(clientEngine, serverEngine);
        assertEquals(HandshakeStatus.NOT_HANDSHAKING, clientEngine.getHandshakeStatus());
        assertEquals(HandshakeStatus.NOT_HANDSHAKING, serverEngine.getHandshakeStatus());
    }

    private void setupEngines(TestKeyStore clientKeyStore, TestKeyStore serverKeyStore) throws SSLException {
        SSLContext clientContext = initSslContext(newContext(), clientKeyStore);
        SSLContext serverContext = initSslContext(newContext(), serverKeyStore);

        clientEngine = initEngine(clientContext.createSSLEngine(), CIPHER, true);
        serverEngine = initEngine(serverContext.createSSLEngine(), CIPHER, false);
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
