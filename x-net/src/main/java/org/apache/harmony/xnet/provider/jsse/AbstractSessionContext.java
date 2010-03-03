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

package org.apache.harmony.xnet.provider.jsse;

import java.util.*;
import java.util.logging.Level;
import java.io.*;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;
import javax.security.cert.CertificateEncodingException;
import javax.security.cert.CertificateException;

/**
 * Supports SSL session caches.
 */
abstract class AbstractSessionContext implements SSLSessionContext {

    volatile int maximumSize;
    volatile int timeout;

    final SSLParameters parameters;
    final int sslCtxNativePointer;

    /** Identifies OpenSSL sessions. */
    static final int OPEN_SSL = 1;

    /**
     * Constructs a new session context.
     *
     * @param parameters
     * @param maximumSize of cache
     * @param timeout for cache entries
     */
    AbstractSessionContext(SSLParameters parameters, int sslCtxNativePointer,
            int maximumSize, int timeout) {
        this.parameters = parameters;
        this.sslCtxNativePointer = sslCtxNativePointer;
        this.maximumSize = maximumSize;
        this.timeout = timeout;
    }

    /**
     * Returns the collection of sessions ordered by least-recently-used first.
     */
    abstract Iterator<SSLSession> sessionIterator();

    public final Enumeration getIds() {
        final Iterator<SSLSession> iterator = sessionIterator();
        return new Enumeration<byte[]>() {
            public boolean hasMoreElements() {
                return iterator.hasNext();
            }
            public byte[] nextElement() {
                return iterator.next().getId();
            }
        };
    }

    public final int getSessionCacheSize() {
        return maximumSize;
    }

    public final int getSessionTimeout() {
        return timeout;
    }

    /**
     * Makes sure cache size is < maximumSize.
     */
    abstract void trimToSize();

    public final void setSessionCacheSize(int size)
            throws IllegalArgumentException {
        if (size < 0) {
            throw new IllegalArgumentException("size < 0");
        }

        int oldMaximum = maximumSize;
        maximumSize = size;

        // Trim cache to size if necessary.
        if (size < oldMaximum) {
            trimToSize();
        }
    }

    /**
     * Converts the given session to bytes.
     *
     * @return session data as bytes or null if the session can't be converted
     */
    byte[] toBytes(SSLSession session) {
        // TODO: Support SSLSessionImpl, too.
        if (!(session instanceof OpenSSLSessionImpl)) {
            return null;
        }

        OpenSSLSessionImpl sslSession = (OpenSSLSessionImpl) session;
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream daos = new DataOutputStream(baos);

            daos.writeInt(OPEN_SSL); // session type ID

            // Session data.
            byte[] data = sslSession.getEncoded();
            daos.writeInt(data.length);
            daos.write(data);

            // Certificates.
            X509Certificate[] certs = session.getPeerCertificateChain();
            daos.writeInt(certs.length);

            // TODO: Call nativegetpeercertificates()
            for (X509Certificate cert : certs) {
                data = cert.getEncoded();
                daos.writeInt(data.length);
                daos.write(data);
            }

            return baos.toByteArray();
        } catch (IOException e) {
            log(e);
            return null;
        } catch (CertificateEncodingException e) {
            log(e);
            return null;
        }
    }

    /**
     * Creates a session from the given bytes.
     *
     * @return a session or null if the session can't be converted
     */
    SSLSession toSession(byte[] data, String host, int port) {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        DataInputStream dais = new DataInputStream(bais);
        try {
            int type = dais.readInt();
            if (type != OPEN_SSL) {
                log(new AssertionError("Unexpected type ID: " + type));
                return null;
            }

            int length = dais.readInt();
            byte[] sessionData = new byte[length];
            dais.readFully(sessionData);

            int count = dais.readInt();
            X509Certificate[] certs = new X509Certificate[count];
            for (int i = 0; i < count; i++) {
                length = dais.readInt();
                byte[] certData = new byte[length];
                dais.readFully(certData);
                certs[i] = X509Certificate.getInstance(certData);
            }

            return new OpenSSLSessionImpl(sessionData, parameters, host, port,
                    certs, this);
        } catch (IOException e) {
            log(e);
            return null;
        } catch (CertificateException e) {
            log(e);
            return null;
        }
    }

    /**
     * Puts an SSLSession in the AbstractSessionContext cache
     */
    abstract void putSession(SSLSession session);

    static void log(Throwable t) {
        java.util.logging.Logger.global.log(Level.WARNING,
                "Error converting session.", t);
    }

    protected void finalize() throws IOException {
        NativeCrypto.SSL_CTX_free(sslCtxNativePointer);
    }

    /**
     * Byte array wrapper. Implements equals() and hashCode().
     */
    static class ByteArray {

        private final byte[] bytes;

        ByteArray(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }

        @Override
        @SuppressWarnings("EqualsWhichDoesntCheckParameterClass")
        public boolean equals(Object o) {
            ByteArray other = (ByteArray) o;
            return Arrays.equals(bytes, other.bytes);
        }
    }
}
