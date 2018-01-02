/*
 * Copyright (C) 2009 The Android Open Source Project
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

package org.conscrypt.javax.net.ssl;

import java.nio.charset.Charset;
import java.security.Principal;
import java.security.cert.Certificate;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

public class FakeSSLSession implements SSLSession {
    private static final Charset UTF_8 = Charset.forName("UTF-8");
    final String host;

    public FakeSSLSession(String host) {
        this.host = host;
    }

    @Override
    public int getApplicationBufferSize() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getCipherSuite() {
        throw new UnsupportedOperationException();
    }

    @Override
    public long getCreationTime() {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] getId() {
        return host.getBytes(UTF_8);
    }

    @Override
    public long getLastAccessedTime() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Certificate[] getLocalCertificates() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Principal getLocalPrincipal() {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getPacketBufferSize() {
        throw new UnsupportedOperationException();
    }

    @Override
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Certificate[] getPeerCertificates() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getPeerHost() {
        return host;
    }

    @Override
    public int getPeerPort() {
        return 443;
    }

    @Override
    public Principal getPeerPrincipal() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getProtocol() {
        throw new UnsupportedOperationException();
    }

    @Override
    public SSLSessionContext getSessionContext() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Object getValue(String name) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getValueNames() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void invalidate() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isValid() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void putValue(String name, Object value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void removeValue(String name) {
        throw new UnsupportedOperationException();
    }
}
