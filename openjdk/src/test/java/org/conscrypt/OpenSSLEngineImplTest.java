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

import static java.lang.Math.max;
import static org.conscrypt.testing.TestUtil.PROTOCOL_TLS_V1_2;
import static org.conscrypt.testing.TestUtil.initClientSslContext;
import static org.conscrypt.testing.TestUtil.initEngine;
import static org.conscrypt.testing.TestUtil.initServerContext;
import static org.conscrypt.testing.TestUtil.newTextMessage;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngineResult;
import org.conscrypt.testing.TestUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class OpenSSLEngineImplTest {
    private static final String CIPHER = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
    private static final int MESSAGE_SIZE = 4096;
    private static final SSLContext clientContext = initClientSslContext(newContext());
    private static final SSLContext serverContext = initServerContext(newContext());

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

    private BufferType bufferType = BufferType.HEAP;
    private OpenSSLEngineImpl clientEngine;
    private OpenSSLEngineImpl serverEngine;

    private ByteBuffer clientCleartextBuffer;
    private ByteBuffer encryptedBuffer;
    private ByteBuffer serverCleartextBuffer;

    @Before
    public void setup() throws Exception {
        clientEngine = newClientEngine();
        serverEngine = newServerEngine();

        encryptedBuffer = bufferType.newBuffer(clientEngine.getSession().getPacketBufferSize());

        // Generate the message to be sent from the client.
        serverCleartextBuffer = bufferType.newBuffer(
                max(MESSAGE_SIZE, serverEngine.getSession().getApplicationBufferSize()));
        clientCleartextBuffer = bufferType.newBuffer(MESSAGE_SIZE);
        clientCleartextBuffer.put(newTextMessage(MESSAGE_SIZE));
        clientCleartextBuffer.flip();

        // Complete the initial TLS handshake.
        TestUtil.doEngineHandshake(clientEngine, serverEngine);
    }

    @Test
    public void sendMessage() throws Exception {
        // Wrap the original message and create the encrypted data.
        SSLEngineResult wrapResult = clientEngine.wrap(clientCleartextBuffer, encryptedBuffer);
        assertEquals(SSLEngineResult.Status.OK, wrapResult.getStatus());

        // Unwrap the encrypted data and get back the original result.
        encryptedBuffer.flip();
        SSLEngineResult unwrapResult = serverEngine.unwrap(encryptedBuffer, serverCleartextBuffer);
        assertEquals(SSLEngineResult.Status.OK, unwrapResult.getStatus());
        serverCleartextBuffer.flip();

        clientCleartextBuffer.position(0);
        assertArrayEquals(toArray(clientCleartextBuffer), toArray(serverCleartextBuffer));
    }

    @Test
    public void sendManyMessages() throws Exception {
        // Wrap the original message and create the encrypted data.
        int numMessages = 100;
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
            SSLEngineResult unwrapResult =
                    serverEngine.unwrap(encryptedBuffers, new ByteBuffer[] {out});
            assertEquals(SSLEngineResult.Status.OK, unwrapResult.getStatus());
            assertEquals(MESSAGE_SIZE, unwrapResult.bytesProduced());

            out.flip();
            byte[] actualMessage = toArray(out);
            assertArrayEquals(expectedMessage, actualMessage);
        }
    }

    private static OpenSSLEngineImpl newClientEngine() {
        return (OpenSSLEngineImpl) initEngine(clientContext.createSSLEngine(), CIPHER, true);
    }

    private static OpenSSLEngineImpl newServerEngine() {
        return (OpenSSLEngineImpl) initEngine(serverContext.createSSLEngine(), CIPHER, false);
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
