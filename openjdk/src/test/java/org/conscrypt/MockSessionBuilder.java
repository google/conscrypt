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
 * limitations under the License.
 */
package org.conscrypt;

import static org.conscrypt.TestUtils.UTF_8;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.net.ssl.SSLSession;

/**
 * Utility class for constructing mock sessions.
 */
final class MockSessionBuilder {
    static final String DEFAULT_CIPHER_SUITE = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    static final int DEFAULT_PORT = 443;

    private byte[] id;
    private boolean valid = true;
    private boolean singleUse = false;
    private String host;
    private int port = DEFAULT_PORT;
    private String cipherSuite = DEFAULT_CIPHER_SUITE;
    private byte[] encodedBytes = EmptyArray.BYTE;

    MockSessionBuilder id(byte[] id) {
        this.id = id;
        return this;
    }

    MockSessionBuilder host(String host) {
        this.host = host;
        return this;
    }

    MockSessionBuilder port(int port) {
        this.port = port;
        return this;
    }

    MockSessionBuilder valid(boolean valid) {
        this.valid = valid;
        return this;
    }

    MockSessionBuilder cipherSuite(String cipherSuite) {
        this.cipherSuite = cipherSuite;
        return this;
    }

    MockSessionBuilder encodedBytes(byte[] encodedBytes) {
        this.encodedBytes = encodedBytes;
        return this;
    }

    MockSessionBuilder singleUse(boolean singleUse) {
        this.singleUse = singleUse;
        return this;
    }

    NativeSslSession build() {
        NativeSslSession session = mock(NativeSslSession.class);
        byte[] id = this.id == null ? host.getBytes(UTF_8) : this.id;
        when(session.getId()).thenReturn(id);
        when(session.isValid()).thenReturn(valid);
        when(session.isSingleUse()).thenReturn(singleUse);
        when(session.getProtocol()).thenReturn(TestUtils.getSupportedProtocols()[0]);
        when(session.getPeerHost()).thenReturn(host);
        when(session.getPeerPort()).thenReturn(port);
        when(session.getCipherSuite()).thenReturn(cipherSuite);
        when(session.toBytes()).thenReturn(encodedBytes);
        when(session.toSSLSession()).thenReturn(mock(SSLSession.class));
        return session;
    }
}
