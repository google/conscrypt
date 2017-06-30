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
package org.conscrypt;

import static org.conscrypt.TestUtils.PROTOCOL_TLS_V1_2;
import static org.conscrypt.TestUtils.initClientSslContext;
import static org.conscrypt.TestUtils.initEngine;
import static org.conscrypt.TestUtils.initServerSslContext;

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.util.ReferenceCountUtil;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import libcore.java.security.TestKeyStore;

/**
 * Enumeration of various types of engines for use with engine-based benchmarks.
 */
@SuppressWarnings({"ImmutableEnumChecker", "unused"})
public enum EngineType {
    JDK {
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

        private SSLContext newContext() {
            try {
                return SSLContext.getInstance(PROTOCOL_TLS_V1_2);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
    },
    CONSCRYPT_UNPOOLED {
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

        private SSLContext newContext() {
            try {
                return SSLContext.getInstance(PROTOCOL_TLS_V1_2, new OpenSSLProvider());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
    },
    CONSCRYPT_POOLED {
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

        private SSLContext newContext() {
            try {
                return SSLContext.getInstance(PROTOCOL_TLS_V1_2, new OpenSSLProvider());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
    },
    NETTY {
        private final SslContext clientContext =
                newNettyClientContext(io.netty.handler.ssl.SslProvider.OPENSSL);
        private final SslContext serverContext =
                newNettyServerContext(io.netty.handler.ssl.SslProvider.OPENSSL);

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
    },
    NETTY_REF_CNT {
        private final SslContext clientContext =
                newNettyClientContext(io.netty.handler.ssl.SslProvider.OPENSSL_REFCNT);
        private final SslContext serverContext =
                newNettyServerContext(io.netty.handler.ssl.SslProvider.OPENSSL_REFCNT);

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
        void dispose(SSLEngine engine) {
            ReferenceCountUtil.release(engine);
        }
    };

    abstract SSLEngine newClientEngine(String cipher);

    abstract SSLEngine newServerEngine(String cipher);

    void dispose(SSLEngine engine) {}

    private static SslContext newNettyClientContext(io.netty.handler.ssl.SslProvider sslProvider) {
        try {
            TestKeyStore server = TestKeyStore.getServer();
            SslContextBuilder ctx =
                    SslContextBuilder.forClient()
                            .sslProvider(sslProvider)
                            .trustManager((X509Certificate[]) server.getPrivateKey("RSA", "RSA")
                                                  .getCertificateChain());
            return ctx.build();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    private static SslContext newNettyServerContext(io.netty.handler.ssl.SslProvider sslProvider) {
        try {
            PrivateKeyEntry server = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
            SslContextBuilder ctx =
                    SslContextBuilder
                            .forServer(server.getPrivateKey(),
                                    (X509Certificate[]) server.getCertificateChain())
                            .sslProvider(sslProvider);
            return ctx.build();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }
}
