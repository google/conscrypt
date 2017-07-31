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

import static io.netty.handler.ssl.SslProvider.OPENSSL;
import static io.netty.handler.ssl.SslProvider.OPENSSL_REFCNT;
import static org.conscrypt.TestUtils.PROTOCOL_TLS_V1_2;
import static org.conscrypt.TestUtils.initClientSslContext;
import static org.conscrypt.TestUtils.initEngine;
import static org.conscrypt.TestUtils.initServerSslContext;

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolNames;
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
        SSLEngine newClientEngine(String cipher, boolean useAlpn) {
            if (useAlpn) {
                throw new UnsupportedOperationException("ALPN not supported for JDK");
            }
            return initEngine(clientContext.createSSLEngine(), cipher, true);
        }

        @Override
        SSLEngine newServerEngine(String cipher, boolean useAlpn) {
            if (useAlpn) {
                throw new UnsupportedOperationException("ALPN not supported for JDK");
            }
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
        private final SSLContext clientContext = newConscryptClientContext();
        private final SSLContext serverContext = newConscryptServerContext();

        @Override
        SSLEngine newClientEngine(String cipher, boolean useAlpn) {
            SSLEngine engine = initEngine(clientContext.createSSLEngine(), cipher, true);
            if (useAlpn) {
                Conscrypt.Engines.setAlpnProtocols(
                        engine, new String[] {ApplicationProtocolNames.HTTP_2});
            }
            return engine;
        }

        @Override
        SSLEngine newServerEngine(String cipher, boolean useAlpn) {
            SSLEngine engine = initEngine(serverContext.createSSLEngine(), cipher, false);
            if (useAlpn) {
                Conscrypt.Engines.setAlpnProtocols(
                        engine, new String[] {ApplicationProtocolNames.HTTP_2});
            }
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
    CONSCRYPT_POOLED {
        private final SSLContext clientContext = newConscryptClientContext();
        private final SSLContext serverContext = newConscryptServerContext();

        @Override
        SSLEngine newClientEngine(String cipher, boolean useAlpn) {
            SSLEngine engine = initEngine(clientContext.createSSLEngine(), cipher, true);
            Conscrypt.Engines.setBufferAllocator(engine, PooledAllocator.getInstance());
            if (useAlpn) {
                Conscrypt.Engines.setAlpnProtocols(
                        engine, new String[] {ApplicationProtocolNames.HTTP_2});
            }
            return engine;
        }

        @Override
        SSLEngine newServerEngine(String cipher, boolean useAlpn) {
            SSLEngine engine = initEngine(serverContext.createSSLEngine(), cipher, false);
            Conscrypt.Engines.setBufferAllocator(engine, PooledAllocator.getInstance());
            if (useAlpn) {
                Conscrypt.Engines.setAlpnProtocols(
                        engine, new String[] {ApplicationProtocolNames.HTTP_2});
            }
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
        private final SslContext clientContext = newNettyClientContext(OPENSSL, false);
        private final SslContext clientContextAlpn = newNettyClientContext(OPENSSL, true);
        private final SslContext serverContext = newNettyServerContext(OPENSSL, false);
        private final SslContext serverContextAlpn = newNettyServerContext(OPENSSL, true);

        @Override
        SSLEngine newClientEngine(String cipher, boolean useAlpn) {
            return initEngine(
                    clientContext(useAlpn).newEngine(PooledByteBufAllocator.DEFAULT), cipher, true);
        }

        @Override
        SSLEngine newServerEngine(String cipher, boolean useAlpn) {
            return initEngine(serverContext(useAlpn).newEngine(PooledByteBufAllocator.DEFAULT),
                    cipher, false);
        }

        private SslContext clientContext(boolean useAlpn) {
            return useAlpn ? clientContextAlpn : clientContext;
        }

        private SslContext serverContext(boolean useAlpn) {
            return useAlpn ? serverContextAlpn : serverContext;
        }

        @Override
        void dispose(SSLEngine engine) {
            super.dispose(engine);
            ReferenceCountUtil.release(engine);
        }
    },
    NETTY_REF_CNT {
        private final SslContext clientContext = newNettyClientContext(OPENSSL_REFCNT, false);
        private final SslContext clientContextAlpn = newNettyClientContext(OPENSSL_REFCNT, true);
        private final SslContext serverContext = newNettyServerContext(OPENSSL_REFCNT, false);
        private final SslContext serverContextAlpn = newNettyServerContext(OPENSSL_REFCNT, true);

        @Override
        SSLEngine newClientEngine(String cipher, boolean useAlpn) {
            return initEngine(
                    clientContext(useAlpn).newEngine(PooledByteBufAllocator.DEFAULT), cipher, true);
        }

        @Override
        SSLEngine newServerEngine(String cipher, boolean useAlpn) {
            return initEngine(serverContext(useAlpn).newEngine(PooledByteBufAllocator.DEFAULT),
                    cipher, false);
        }

        @Override
        void dispose(SSLEngine engine) {
            super.dispose(engine);
            ReferenceCountUtil.release(engine);
        }

        private SslContext clientContext(boolean useAlpn) {
            return useAlpn ? clientContextAlpn : clientContext;
        }

        private SslContext serverContext(boolean useAlpn) {
            return useAlpn ? serverContextAlpn : serverContext;
        }
    };

    abstract SSLEngine newClientEngine(String cipher, boolean useAlpn);

    abstract SSLEngine newServerEngine(String cipher, boolean useAlpn);

    void dispose(SSLEngine engine) {
        engine.closeOutbound();
    }

    private static SSLContext newConscryptClientContext() {
        return TestUtils.newClientSslContext(TestUtils.getConscryptProvider());
    }

    private static SSLContext newConscryptServerContext() {
        return TestUtils.newServerSslContext(TestUtils.getConscryptProvider());
    }

    private static SslContext newNettyClientContext(
            io.netty.handler.ssl.SslProvider sslProvider, boolean useAlpn) {
        try {
            TestKeyStore server = TestKeyStore.getServer();
            SslContextBuilder ctx =
                    SslContextBuilder.forClient()
                            .sslProvider(sslProvider)
                            .trustManager((X509Certificate[]) server.getPrivateKey("RSA", "RSA")
                                                  .getCertificateChain());
            if (useAlpn) {
                ctx.applicationProtocolConfig(NETTY_ALPN_CONFIG);
            }
            return ctx.build();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    private static SslContext newNettyServerContext(
            io.netty.handler.ssl.SslProvider sslProvider, boolean useAlpn) {
        try {
            PrivateKeyEntry server = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
            SslContextBuilder ctx =
                    SslContextBuilder
                            .forServer(server.getPrivateKey(),
                                    (X509Certificate[]) server.getCertificateChain())
                            .sslProvider(sslProvider);
            if (useAlpn) {
                ctx.applicationProtocolConfig(NETTY_ALPN_CONFIG);
            }
            return ctx.build();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    private static final ApplicationProtocolConfig NETTY_ALPN_CONFIG =
            new ApplicationProtocolConfig(Protocol.ALPN, SelectorFailureBehavior.NO_ADVERTISE,
                    SelectedListenerFailureBehavior.ACCEPT, ApplicationProtocolNames.HTTP_2);
}
