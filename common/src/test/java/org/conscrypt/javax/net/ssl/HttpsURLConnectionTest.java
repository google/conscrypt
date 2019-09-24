/*
 * Copyright (C) 2014 The Android Open Source Project
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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class HttpsURLConnectionTest {
    /**
     * HTTPS URL which cannot be resolved and is thus safe to use in tests where network traffic
     * should be avoided.
     */
    private static final String UNRESOLVABLE_HTTPS_URL = "https:///";

    @Test
    public void testDefaultHostnameVerifierNotNull() {
        assertNotNull(HttpsURLConnection.getDefaultHostnameVerifier());
    }

    @Test
    public void testDefaultHostnameVerifierUsedForNewConnectionsByDefault() throws IOException {
        HostnameVerifier originalHostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
        HttpsURLConnection connection =
                (HttpsURLConnection) new URL(UNRESOLVABLE_HTTPS_URL).openConnection();
        try {
            assertSame(originalHostnameVerifier, connection.getHostnameVerifier());
        } finally {
            connection.disconnect();
        }

        HostnameVerifier anotherVerifier = new FakeHostnameVerifier();
        try {
            HttpsURLConnection.setDefaultHostnameVerifier(anotherVerifier);
            connection = (HttpsURLConnection) new URL(UNRESOLVABLE_HTTPS_URL).openConnection();
            try {
                assertSame(anotherVerifier, connection.getHostnameVerifier());
            } finally {
                connection.disconnect();
            }

            HttpsURLConnection.setDefaultHostnameVerifier(originalHostnameVerifier);
            connection = (HttpsURLConnection) new URL(UNRESOLVABLE_HTTPS_URL).openConnection();
            try {
                assertSame(originalHostnameVerifier, connection.getHostnameVerifier());
            } finally {
                connection.disconnect();
            }
        } finally {
            HttpsURLConnection.setDefaultHostnameVerifier(originalHostnameVerifier);
        }
    }

    @Test
    public void testDefaultSSLSocketFactoryNotNull() {
        assertNotNull(HttpsURLConnection.getDefaultSSLSocketFactory());
    }

    @Test
    public void testDefaultSSLSocketFactoryUsedForNewConnectionsByDefault() throws IOException {
        SSLSocketFactory originalFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
        HttpsURLConnection connection =
                (HttpsURLConnection) new URL(UNRESOLVABLE_HTTPS_URL).openConnection();
        try {
            assertSame(originalFactory, connection.getSSLSocketFactory());
        } finally {
            connection.disconnect();
        }

        SSLSocketFactory anotherFactory = new FakeSSLSocketFactory();
        try {
            HttpsURLConnection.setDefaultSSLSocketFactory(anotherFactory);
            connection = (HttpsURLConnection) new URL(UNRESOLVABLE_HTTPS_URL).openConnection();
            try {
                assertSame(anotherFactory, connection.getSSLSocketFactory());
            } finally {
                connection.disconnect();
            }

            HttpsURLConnection.setDefaultSSLSocketFactory(originalFactory);
            connection = (HttpsURLConnection) new URL(UNRESOLVABLE_HTTPS_URL).openConnection();
            try {
                assertSame(originalFactory, connection.getSSLSocketFactory());
            } finally {
                connection.disconnect();
            }
        } finally {
            HttpsURLConnection.setDefaultSSLSocketFactory(originalFactory);
        }
    }

    private static final class FakeHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    private static final class FakeSSLSocketFactory extends SSLSocketFactory {
        FakeSSLSocketFactory() {}

        @Override
        public String[] getDefaultCipherSuites() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Socket createSocket(
                InetAddress address, int port, InetAddress localAddress, int localPort) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Socket createSocket(InetAddress host, int port) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Socket createSocket(String host, int port) {
            throw new UnsupportedOperationException();
        }
    }
}
