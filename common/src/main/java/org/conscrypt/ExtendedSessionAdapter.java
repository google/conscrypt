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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;

/**
 * This is an adapter that wraps the active session with {@link ExtendedSSLSession}, if running
 * on Java 7+.
 */
final class ExtendedSessionAdapter {
    // TODO: use BoringSSL API to actually fetch the real data
    private static final String[] LOCAL_SUPPORTED_SIGNATURE_ALGORITHMS = new String[] {
            "SHA512withRSA",
            "SHA512withECDSA",
            "SHA384withRSA",
            "SHA384withECDSA",
            "SHA256withRSA",
            "SHA256withECDSA",
            "SHA224withRSA",
            "SHA224withECDSA",
            "SHA1withRSA",
            "SHA1withECDSA",
    };
    // TODO: use BoringSSL API to actually fetch the real data
    private static final String[] PEER_SUPPORTED_SIGNATURE_ALGORITHMS =
            new String[] {"SHA1withRSA", "SHA1withECDSA"};
    private static Class<?> EXTENDED_SSL_SESSION_CLASS = getExtendedSslSessionClass();

    /**
     * Wraps the given session with {@link ExtendedSSLSession}, if running on Java 7+.
     */
    static SSLSession wrap(ActiveSession session) {
        if (EXTENDED_SSL_SESSION_CLASS != null) {
            return new ExtendedWrapper(session);
        }
        return session;
    }

    /**
     * If the given session is a wrapper, returns the delegate session.
     */
    static SSLSession getDelegate(SSLSession session) {
        if (session instanceof ExtendedWrapper) {
            return ((ExtendedWrapper) session).delegate;
        }
        return session;
    }

    private static Class<?> getExtendedSslSessionClass() {
        try {
            return Class.forName("javax.net.ssl.ExtendedSSLSession");
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    static final class ExtendedWrapper extends ExtendedSSLSession {
        private final ActiveSession delegate;

        ExtendedWrapper(ActiveSession delegate) {
            this.delegate = delegate;
        }

        /* @Override */
        @SuppressWarnings("MissingOverride") // For Android backward-compatibility.
        public String[] getLocalSupportedSignatureAlgorithms() {
            return LOCAL_SUPPORTED_SIGNATURE_ALGORITHMS.clone();
        }

        /* @Override */
        @SuppressWarnings("MissingOverride") // For Android backward-compatibility.
        public String[] getPeerSupportedSignatureAlgorithms() {
            return PEER_SUPPORTED_SIGNATURE_ALGORITHMS.clone();
        }

        /* @Override */
        // For Android backward-compatibility.
        @SuppressWarnings({"MissingOverride", "unchecked", "rawtypes"})
        public List getRequestedServerNames() {
            try {
                String requestedServerName = delegate.getRequestedServerName();
                if (requestedServerName == null) {
                    return null;
                }

                Constructor sniHostNameConstructor =
                        Class.forName("javax.net.ssl.SNIHostName").getConstructor(String.class);
                return Collections.singletonList(
                        sniHostNameConstructor.newInstance(requestedServerName));

            } catch (NoSuchMethodException ignore) {
            } catch (InvocationTargetException ignore) {
            } catch (IllegalAccessException ignore) {
            } catch (ClassNotFoundException ignore) {
            } catch (InstantiationException ignore) {
            }
            return null;
        }

        @Override
        public byte[] getId() {
            return delegate.getId();
        }

        @Override
        public SSLSessionContext getSessionContext() {
            return delegate.getSessionContext();
        }

        @Override
        public long getCreationTime() {
            return delegate.getCreationTime();
        }

        @Override
        public long getLastAccessedTime() {
            return delegate.getLastAccessedTime();
        }

        @Override
        public void invalidate() {
            delegate.invalidate();
        }

        @Override
        public boolean isValid() {
            return delegate.isValid();
        }

        @Override
        public void putValue(String name, Object value) {
            delegate.putValue(name, value);
        }

        @Override
        public Object getValue(String name) {
            return delegate.getValue(name);
        }

        @Override
        public void removeValue(String name) {
            delegate.removeValue(name);
        }

        @Override
        public String[] getValueNames() {
            return delegate.getValueNames();
        }

        @Override
        public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
            return delegate.getPeerCertificates();
        }

        @Override
        public Certificate[] getLocalCertificates() {
            return delegate.getLocalCertificates();
        }

        @Override
        public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
            return delegate.getPeerCertificateChain();
        }

        @Override
        public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
            return delegate.getPeerPrincipal();
        }

        @Override
        public Principal getLocalPrincipal() {
            return delegate.getLocalPrincipal();
        }

        @Override
        public String getCipherSuite() {
            return delegate.getCipherSuite();
        }

        @Override
        public String getProtocol() {
            return delegate.getProtocol();
        }

        @Override
        public String getPeerHost() {
            return delegate.getPeerHost();
        }

        @Override
        public int getPeerPort() {
            return delegate.getPeerPort();
        }

        @Override
        public int getPacketBufferSize() {
            return delegate.getPacketBufferSize();
        }

        @Override
        public int getApplicationBufferSize() {
            return delegate.getApplicationBufferSize();
        }
    }
}
