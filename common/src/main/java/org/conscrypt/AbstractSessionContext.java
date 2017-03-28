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

package org.conscrypt;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

/**
 * Supports SSL session caches.
 */
abstract class AbstractSessionContext implements SSLSessionContext {

    /**
     * Maximum lifetime of a session (in seconds) after which it's considered invalid and should not
     * be used to for new connections.
     */
    private static final int DEFAULT_SESSION_TIMEOUT_SECONDS = 8 * 60 * 60;

    private volatile int maximumSize;
    private volatile int timeout = DEFAULT_SESSION_TIMEOUT_SECONDS;

    final long sslCtxNativePointer = NativeCrypto.SSL_CTX_new();

    /** Identifies OpenSSL sessions. */
    private static final int OPEN_SSL = 1;

    /** Identifies OpenSSL sessions with OCSP stapled data. */
    private static final int OPEN_SSL_WITH_OCSP = 2;

    /** Identifies OpenSSL sessions with TLS SCT data. */
    private static final int OPEN_SSL_WITH_TLS_SCT = 3;

    @SuppressWarnings("serial")
    private final Map<ByteArray, SSLSession> sessions = new LinkedHashMap<ByteArray, SSLSession>() {
        @Override
        protected boolean removeEldestEntry(
                Map.Entry<ByteArray, SSLSession> eldest) {
            boolean remove = maximumSize > 0 && size() > maximumSize;
            if (remove) {
                remove(eldest.getKey());
                sessionRemoved(eldest.getValue());
            }
            return false;
        }
    };

    /**
     * Constructs a new session context.
     *
     * @param maximumSize of cache
     */
    AbstractSessionContext(int maximumSize) {
        this.maximumSize = maximumSize;
    }

    /**
     * Returns the collection of sessions ordered from oldest to newest
     */
    private Iterator<SSLSession> sessionIterator() {
        synchronized (sessions) {
            SSLSession[] array = sessions.values().toArray(
                    new SSLSession[sessions.size()]);
            return Arrays.asList(array).iterator();
        }
    }

    @Override
    public final Enumeration<byte[]> getIds() {
        final Iterator<SSLSession> i = sessionIterator();
        return new Enumeration<byte[]>() {
            private SSLSession next;

            @Override
            public boolean hasMoreElements() {
                if (next != null) {
                    return true;
                }
                while (i.hasNext()) {
                    SSLSession session = i.next();
                    if (session.isValid()) {
                        next = session;
                        return true;
                    }
                }
                next = null;
                return false;
            }

            @Override
            public byte[] nextElement() {
                if (hasMoreElements()) {
                    byte[] id = next.getId();
                    next = null;
                    return id;
                }
                throw new NoSuchElementException();
            }
        };
    }

    @Override
    public final int getSessionCacheSize() {
        return maximumSize;
    }

    @Override
    public final int getSessionTimeout() {
        return timeout;
    }

    /**
     * Makes sure cache size is < maximumSize.
     */
    private void trimToSize() {
        synchronized (sessions) {
            int size = sessions.size();
            if (size > maximumSize) {
                int removals = size - maximumSize;
                Iterator<SSLSession> i = sessions.values().iterator();
                do {
                    SSLSession session = i.next();
                    i.remove();
                    sessionRemoved(session);
                } while (--removals > 0);
            }
        }
    }

    @Override
    public void setSessionTimeout(int seconds)
            throws IllegalArgumentException {
        if (seconds < 0) {
            throw new IllegalArgumentException("seconds < 0");
        }
        timeout = seconds;

        synchronized (sessions) {
            Iterator<SSLSession> i = sessions.values().iterator();
            while (i.hasNext()) {
                SSLSession session = i.next();
                // SSLSession's know their context and consult the
                // timeout as part of their validity condition.
                if (!session.isValid()) {
                    i.remove();
                    sessionRemoved(session);
                }
            }
        }
    }

    /**
     * Called when a session is removed. Used by ClientSessionContext
     * to update its host-and-port based cache.
     */
    protected abstract void sessionRemoved(SSLSession session);

    @Override
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

            daos.writeInt(OPEN_SSL_WITH_TLS_SCT); // session type ID

            // Session data.
            byte[] data = sslSession.getEncoded();
            daos.writeInt(data.length);
            daos.write(data);

            // Certificates.
            Certificate[] certs = session.getPeerCertificates();
            daos.writeInt(certs.length);

            for (Certificate cert : certs) {
                data = cert.getEncoded();
                daos.writeInt(data.length);
                daos.write(data);
            }

            List<byte[]> ocspResponses = sslSession.getStatusResponses();
            daos.writeInt(ocspResponses.size());
            for (byte[] ocspResponse : ocspResponses) {
                daos.writeInt(ocspResponse.length);
                daos.write(ocspResponse);
            }

            byte[] tlsSctData = sslSession.getTlsSctData();
            if (tlsSctData != null) {
                daos.writeInt(tlsSctData.length);
                daos.write(tlsSctData);
            } else {
                daos.writeInt(0);
            }

            // TODO: local certificates?

            return baos.toByteArray();
        } catch (IOException e) {
            System.err.println("Failed to convert saved SSL Session: " + e.getMessage());
            return null;
        } catch (CertificateEncodingException e) {
            log(e);
            return null;
        }
    }

    private static void checkRemaining(ByteBuffer buf, int length) throws IOException {
        if (length < 0) {
            throw new IOException("Length is negative: " + length);
        }
        if (length > buf.remaining()) {
            throw new IOException(
                    "Length of blob is longer than available: " + length + " > " + buf.remaining());
        }
    }

    /**
     * Creates a session from the given bytes.
     *
     * @return a session or null if the session can't be converted
     */
    OpenSSLSessionImpl toSession(byte[] data, String host, int port) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        try {
            int type = buf.getInt();
            if (type != OPEN_SSL && type != OPEN_SSL_WITH_OCSP && type != OPEN_SSL_WITH_TLS_SCT) {
                throw new IOException("Unexpected type ID: " + type);
            }

            int length = buf.getInt();
            checkRemaining(buf, length);

            byte[] sessionData = new byte[length];
            buf.get(sessionData);

            int count = buf.getInt();
            checkRemaining(buf, count);

            X509Certificate[] certs = new X509Certificate[count];
            for (int i = 0; i < count; i++) {
                length = buf.getInt();
                checkRemaining(buf, length);

                byte[] certData = new byte[length];
                buf.get(certData);
                try {
                    certs[i] = OpenSSLX509Certificate.fromX509Der(certData);
                } catch (Exception e) {
                    throw new IOException("Can not read certificate " + i + "/" + count);
                }
            }

            byte[] ocspData = null;
            if (type >= OPEN_SSL_WITH_OCSP) {
                // We only support one OCSP response now, but in the future
                // we may support RFC 6961 which has multiple.
                int countOcspResponses = buf.getInt();
                checkRemaining(buf, countOcspResponses);

                if (countOcspResponses >= 1) {
                    int ocspLength = buf.getInt();
                    checkRemaining(buf, ocspLength);

                    ocspData = new byte[ocspLength];
                    buf.get(ocspData);

                    // Skip the rest of the responses.
                    for (int i = 1; i < countOcspResponses; i++) {
                        ocspLength = buf.getInt();
                        checkRemaining(buf, ocspLength);
                        buf.position(buf.position() + ocspLength);
                    }
                }
            }

            byte[] tlsSctData = null;
            if (type == OPEN_SSL_WITH_TLS_SCT) {
                int tlsSctDataLength = buf.getInt();
                checkRemaining(buf, tlsSctDataLength);

                if (tlsSctDataLength > 0) {
                    tlsSctData = new byte[tlsSctDataLength];
                    buf.get(tlsSctData);
                }
            }

            if (buf.remaining() != 0) {
                log(new AssertionError("Read entire session, but data still remains; rejecting"));
                return null;
            }

            return new OpenSSLSessionImpl(sessionData, host, port, certs, ocspData, tlsSctData,
                    this);
        } catch (IOException e) {
            log(e);
            return null;
        } catch (BufferUnderflowException e) {
            log(e);
            return null;
        }
    }

    SSLSession wrapSSLSessionIfNeeded(SSLSession session) {
        if (session instanceof AbstractOpenSSLSession) {
            return Platform.wrapSSLSession((AbstractOpenSSLSession) session);
        } else {
            return session;
        }
    }

    @Override
    public SSLSession getSession(byte[] sessionId) {
        if (sessionId == null) {
            throw new NullPointerException("sessionId == null");
        }
        ByteArray key = new ByteArray(sessionId);
        SSLSession session;
        synchronized (sessions) {
            session = sessions.get(key);
        }
        if (session != null && session.isValid()) {
            return wrapSSLSessionIfNeeded(session);
        }
        return null;
    }

    void putSession(SSLSession session) {
        byte[] id = session.getId();
        if (id.length == 0) {
            return;
        }
        ByteArray key = new ByteArray(id);
        synchronized (sessions) {
            sessions.put(key, session);
        }
    }

    private static void log(Throwable t) {
        System.out.println("Error inflating SSL session: "
                + (t.getMessage() != null ? t.getMessage() : t.getClass().getName()));
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            NativeCrypto.SSL_CTX_free(sslCtxNativePointer);
        } finally {
            super.finalize();
        }
    }
}
