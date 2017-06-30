/*
 * Copyright 2017 The Android Open Source Project
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

/*
 * Copyright 2017 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.conscrypt;

import static java.lang.Math.max;
import static org.conscrypt.TestUtils.PROTOCOL_TLS_V1_2;
import static org.conscrypt.TestUtils.doEngineHandshake;
import static org.conscrypt.TestUtils.initClientSslContext;
import static org.conscrypt.TestUtils.initEngine;
import static org.conscrypt.TestUtils.initServerSslContext;
import static org.conscrypt.TestUtils.newTextMessage;
import static org.junit.Assert.assertEquals;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import java.nio.ByteBuffer;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import libcore.java.security.TestKeyStore;

/**
 * Benchmark comparing performance of various engine implementations to conscrypt.
 */
public final class EngineBenchmark {
    /**
     * Provider for the benchmark configuration
     */
    interface Config {
        SslProvider sslProvider();
        int messageSize();
        String cipher();
    }

    private static final class PooledAllocator extends BufferAllocator {
        private static final ByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
        private static final PooledAllocator instance = new PooledAllocator();

        static PooledAllocator getInstance() {
            return instance;
        }

        @Override
        public AllocatedBuffer allocateDirectBuffer(int capacity) {
            return new ByteBufAdapter(alloc.directBuffer(capacity));
        }

        private static final class ByteBufAdapter extends AllocatedBuffer {
            private final ByteBuf nettyBuffer;
            private final ByteBuffer buffer;

            private ByteBufAdapter(ByteBuf nettyBuffer) {
                this.nettyBuffer = nettyBuffer;
                nettyBuffer.writerIndex(nettyBuffer.capacity());
                this.buffer = nettyBuffer.nioBuffer();
            }

            @Override
            public ByteBuffer nioBuffer() {
                return buffer;
            }

            @Override
            public AllocatedBuffer retain() {
                nettyBuffer.retain();
                return this;
            }

            @Override
            public AllocatedBuffer release() {
                nettyBuffer.release();
                return this;
            }
        }
    }

    @SuppressWarnings({"ImmutableEnumChecker", "unused"})
    public enum SslProvider {
        JDK_HEAP {
            private final SSLContext clientContext = initClientSslContext(newContext());
            private final SSLContext serverContext = initServerSslContext(newContext());

            @Override
            SSLEngine newClientEngine(String cipher) {
                return initEngine(clientContext.createSSLEngine(), cipher, true);
            }

            @Override
            SSLEngine newServerEngine(String cipher) {
                return initEngine(serverContext.createSSLEngine(), cipher, false);
            }

            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocate(size);
            }

            private SSLContext newContext() {
                try {
                    return SSLContext.getInstance(PROTOCOL_TLS_V1_2);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
        },
        JDK_DIRECT {
            private final SSLContext clientContext = initClientSslContext(newContext());
            private final SSLContext serverContext = initServerSslContext(newContext());

            @Override
            SSLEngine newClientEngine(String cipher) {
                return initEngine(clientContext.createSSLEngine(), cipher, true);
            }

            @Override
            SSLEngine newServerEngine(String cipher) {
                return initEngine(serverContext.createSSLEngine(), cipher, false);
            }

            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocateDirect(size);
            }

            private SSLContext newContext() {
                try {
                    return SSLContext.getInstance(PROTOCOL_TLS_V1_2);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
        },
        CONSCRYPT_HEAP_UNPOOLED {
            private final SSLContext clientContext = initClientSslContext(newContext());
            private final SSLContext serverContext = initServerSslContext(newContext());

            @Override
            SSLEngine newClientEngine(String cipher) {
                return initEngine(clientContext.createSSLEngine(), cipher, true);
            }

            @Override
            SSLEngine newServerEngine(String cipher) {
                return initEngine(serverContext.createSSLEngine(), cipher, false);
            }

            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocate(size);
            }

            private SSLContext newContext() {
                try {
                    return SSLContext.getInstance(PROTOCOL_TLS_V1_2, new OpenSSLProvider());
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
        },
        CONSCRYPT_HEAP_POOLED {
            private final SSLContext clientContext = initClientSslContext(newContext());
            private final SSLContext serverContext = initServerSslContext(newContext());

            @Override
            SSLEngine newClientEngine(String cipher) {
                SSLEngine engine = initEngine(clientContext.createSSLEngine(), cipher, true);
                Conscrypt.Engines.setBufferAllocator(engine, PooledAllocator.getInstance());
                return engine;
            }

            @Override
            SSLEngine newServerEngine(String cipher) {
                SSLEngine engine = initEngine(serverContext.createSSLEngine(), cipher, false);
                Conscrypt.Engines.setBufferAllocator(engine, PooledAllocator.getInstance());
                return engine;
            }

            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocate(size);
            }

            private SSLContext newContext() {
                try {
                    return SSLContext.getInstance(PROTOCOL_TLS_V1_2, new OpenSSLProvider());
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
        },
        CONSCRYPT_DIRECT {
            private final SSLContext clientContext = initClientSslContext(newContext());
            private final SSLContext serverContext = initServerSslContext(newContext());

            @Override
            SSLEngine newClientEngine(String cipher) {
                return initEngine(clientContext.createSSLEngine(), cipher, true);
            }

            @Override
            SSLEngine newServerEngine(String cipher) {
                return initEngine(serverContext.createSSLEngine(), cipher, false);
            }

            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocateDirect(size);
            }

            private SSLContext newContext() {
                try {
                    return SSLContext.getInstance(PROTOCOL_TLS_V1_2, new OpenSSLProvider());
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
        },
        NETTY_HEAP {
            private final SslContext clientContext = newNettyClientContext();
            private final SslContext serverContext = newNettyServerContext();

            @Override
            SSLEngine newClientEngine(String cipher) {
                return initEngine(
                    clientContext.newEngine(PooledByteBufAllocator.DEFAULT), cipher, true);
            }

            @Override
            SSLEngine newServerEngine(String cipher) {
                return initEngine(
                    serverContext.newEngine(PooledByteBufAllocator.DEFAULT), cipher, false);
            }

            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocate(size);
            }
        },
        NETTY_DIRECT {
            private final SslContext clientContext = newNettyClientContext();
            private final SslContext serverContext = newNettyServerContext();

            @Override
            SSLEngine newClientEngine(String cipher) {
                return initEngine(
                        clientContext.newEngine(PooledByteBufAllocator.DEFAULT), cipher, true);
            }

            @Override
            SSLEngine newServerEngine(String cipher) {
                return initEngine(
                        serverContext.newEngine(PooledByteBufAllocator.DEFAULT), cipher, false);
            }

            @Override
            ByteBuffer newBuffer(int size) {
                return ByteBuffer.allocateDirect(size);
            }
        };

        abstract SSLEngine newClientEngine(String cipher);
        abstract SSLEngine newServerEngine(String cipher);
        abstract ByteBuffer newBuffer(int size);

        private static SslContext newNettyClientContext() {
            try {
                TestKeyStore server = TestKeyStore.getServer();
                SslContextBuilder ctx =
                        SslContextBuilder.forClient()
                                .sslProvider(io.netty.handler.ssl.SslProvider.OPENSSL)
                                .trustManager((X509Certificate[]) server.getPrivateKey("RSA", "RSA")
                                                      .getCertificateChain());
                return ctx.build();
            } catch (SSLException e) {
                throw new RuntimeException(e);
            }
        }

        private static SslContext newNettyServerContext() {
            try {
                PrivateKeyEntry server = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
                SslContextBuilder ctx =
                        SslContextBuilder
                                .forServer(server.getPrivateKey(),
                                        (X509Certificate[]) server.getCertificateChain())
                                .sslProvider(io.netty.handler.ssl.SslProvider.OPENSSL);
                return ctx.build();
            } catch (SSLException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private final SSLEngine clientEngine;
    private final SSLEngine serverEngine;

    private final ByteBuffer clientCleartextBuffer;
    private final ByteBuffer encryptedBuffer;
    private final ByteBuffer serverCleartextBuffer;
    private final ByteBuffer preEncryptedBuffer;

    EngineBenchmark(Config config) throws Exception {
        final SslProvider provider = config.sslProvider();
        final String cipher = config.cipher();
        final int messageSize = config.messageSize();

        clientEngine = provider.newClientEngine(cipher);
        serverEngine = provider.newServerEngine(cipher);

        final int encryptedBufferSize = clientEngine.getSession().getPacketBufferSize();
        encryptedBuffer = provider.newBuffer(encryptedBufferSize);
        preEncryptedBuffer = provider.newBuffer(encryptedBufferSize);

        // Generate the message to be sent from the client.
        final int cleartextBufferSize = serverEngine.getSession().getApplicationBufferSize();
        serverCleartextBuffer = provider.newBuffer(max(messageSize, cleartextBufferSize));
        clientCleartextBuffer = provider.newBuffer(messageSize);
        clientCleartextBuffer.put(newTextMessage(messageSize));
        clientCleartextBuffer.flip();

        // Complete the initial TLS handshake.
        doEngineHandshake(clientEngine, serverEngine);

        // Populate the pre-encrypted buffer for use with the unwrap benchmark.
        doWrap(clientCleartextBuffer, preEncryptedBuffer);
        doUnwrap(preEncryptedBuffer, serverCleartextBuffer);
    }

    void wrap() throws SSLException {
        // Reset the buffers.
        clientCleartextBuffer.position(0);
        encryptedBuffer.clear();

        // Wrap the original message and create the encrypted data.
        doWrap(clientCleartextBuffer, encryptedBuffer);

        // Lightweight comparison - just make sure the data length is correct.
        assertEquals(preEncryptedBuffer.limit(), encryptedBuffer.limit());
    }

    /**
     * Simple benchmark that sends a single message from client to server.
     */
    void wrapAndUnwrap() throws SSLException {
        // Reset the buffers.
        clientCleartextBuffer.position(0);
        encryptedBuffer.clear();
        serverCleartextBuffer.clear();

        // Wrap the original message and create the encrypted data.
        doWrap(clientCleartextBuffer, encryptedBuffer);

        // Unwrap the encrypted data and get back the original result.
        doUnwrap(encryptedBuffer, serverCleartextBuffer);

        // Lightweight comparison - just make sure the unencrypted data length is correct.
        assertEquals(clientCleartextBuffer.limit(), serverCleartextBuffer.limit());
    }

    private void doWrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        // Wrap the original message and create the encrypted data.
        verifyResult(src, clientEngine.wrap(src, dst));
        dst.flip();
    }

    private void doUnwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        verifyResult(src, serverEngine.unwrap(src, dst));
        dst.flip();
    }

    private void verifyResult(ByteBuffer src, SSLEngineResult result) {
        if (result.getStatus() != SSLEngineResult.Status.OK) {
            throw new RuntimeException("Operation returned unexpected result " + result);
        }
        if (result.bytesConsumed() != src.limit()) {
            throw new RuntimeException(
                    String.format("Operation didn't consume all bytes. Expected %d, consumed %d.",
                            src.limit(), result.bytesConsumed()));
        }
    }

    /**
     * A simple main for profiling.
     */
    public static void main(String[] args) throws Exception {
        EngineBenchmark bm = new EngineBenchmark(new Config() {
            @Override
            public SslProvider sslProvider() {
                return SslProvider.CONSCRYPT_HEAP_POOLED;
            }

            @Override
            public int messageSize() {
                return 512;
            }

            @Override
            public String cipher() {
                return TestUtils.TEST_CIPHER;
            }
        });

        // Just run forever for profiling.
        while (true) {
            bm.wrapAndUnwrap();
        }
    }
}
