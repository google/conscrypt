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
public enum AndroidEngineType implements EngineType {
    CONSCRYPT_UNPOOLED {
        private final SSLContext clientContext = newConscryptClientContext();
        private final SSLContext serverContext = newConscryptServerContext();

        @Override
        public SSLEngine newClientEngine(String cipher, boolean useAlpn) {
            SSLEngine engine = initEngine(clientContext.createSSLEngine(), cipher, true);
            if (useAlpn) {
                Conscrypt.Engines.setAlpnProtocols(
                        engine, new String[] {"h2"});
            }
            return engine;
        }

        @Override
        public SSLEngine newServerEngine(String cipher, boolean useAlpn) {
            SSLEngine engine = initEngine(serverContext.createSSLEngine(), cipher, false);
            if (useAlpn) {
                Conscrypt.Engines.setAlpnProtocols(
                        engine, new String[] {"h2"});
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

        @Override
        public void dispose(SSLEngine engine) {
            engine.closeOutbound();
        }
    };

    @Override
    public void dispose(SSLEngine engine) {}

    private static SSLContext newConscryptClientContext() {
        return TestUtils.newClientSslContext(TestUtils.getConscryptProvider());
    }

    private static SSLContext newConscryptServerContext() {
        return TestUtils.newServerSslContext(TestUtils.getConscryptProvider());
    }
}
