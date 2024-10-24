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

import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.net.ssl.SSLException;
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

    private volatile long sslCtxNativePointer = NativeCrypto.SSL_CTX_new();

    private final ReadWriteLock lock = new ReentrantReadWriteLock();


    private final Map<ByteArray, NativeSslSession> sessions =
            new LinkedHashMap<ByteArray, NativeSslSession>() {
                @Override
                protected boolean removeEldestEntry(
                        Map.Entry<ByteArray, NativeSslSession> eldest) {
                    // NOTE: does not take into account any session that may have become
                    // invalid.
                    if (maximumSize > 0 && size() > maximumSize) {
                        // Let the subclass know.
                        onBeforeRemoveSession(eldest.getValue());
                        return true;
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
     * This method is provided for API-compatibility only, not intended for use. No guarantees
     * are made WRT performance.
     */
    @Override
    public final Enumeration<byte[]> getIds() {
        // Make a copy of the IDs.
        final Iterator<NativeSslSession> iter;
        synchronized (sessions) {
            iter = Arrays.asList(sessions.values().toArray(new NativeSslSession[0]))
                    .iterator();
        }
        return new Enumeration<byte[]>() {
            private NativeSslSession next;

            @Override
            public boolean hasMoreElements() {
                if (next != null) {
                    return true;
                }
                while (iter.hasNext()) {
                    NativeSslSession session = iter.next();
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

    /**
     * This is provided for API-compatibility only, not intended for use. No guarantees are
     * made WRT performance or the validity of the returned session.
     */
    @Override
    public final SSLSession getSession(byte[] sessionId) {
        if (sessionId == null) {
            throw new NullPointerException("sessionId");
        }
        ByteArray key = new ByteArray(sessionId);
        NativeSslSession session;
        synchronized (sessions) {
            session = sessions.get(key);
        }
        if (session != null && session.isValid()) {
            return session.toSSLSession();
        }
        return null;
    }

    @Override
    public final int getSessionCacheSize() {
        return maximumSize;
    }

    @Override
    public final int getSessionTimeout() {
        return timeout;
    }

    @Override
    public final void setSessionTimeout(int seconds) throws IllegalArgumentException {
        if (seconds < 0) {
            throw new IllegalArgumentException("seconds < 0");
        }

        synchronized (sessions) {
            // Set the timeout on this context.
            timeout = seconds;
            // setSessionTimeout(0) is defined to remove the timeout, but passing 0
            // to SSL_CTX_set_timeout in BoringSSL sets it to the default timeout instead.
            // Pass INT_MAX seconds (68 years), since that's equivalent for practical purposes.
            setTimeout(seconds > 0 ? seconds : Integer.MAX_VALUE);

            Iterator<NativeSslSession> i = sessions.values().iterator();
            while (i.hasNext()) {
                NativeSslSession session = i.next();
                // SSLSession's know their context and consult the
                // timeout as part of their validity condition.
                if (!session.isValid()) {
                    // Let the subclass know.
                    onBeforeRemoveSession(session);
                    i.remove();
                }
            }
        }
    }

    private void setTimeout(int seconds) {
        lock.writeLock().lock();
        try {
            if (isValid()) {
                NativeCrypto.SSL_CTX_set_timeout(sslCtxNativePointer, this, seconds);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public final void setSessionCacheSize(int size) throws IllegalArgumentException {
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

    // isValid() should only be called from code where this.lock is already locked, otherwise the
    // result may be incorrect by the time it is used.
    private boolean isValid() {
        return (sslCtxNativePointer != 0);
    }

    /**
     * Returns a native pointer to a new SSL object in this SSL_CTX.
     */
    long newSsl() throws SSLException {
        lock.readLock().lock();
        try {
            if (isValid()) {
                return NativeCrypto.SSL_new(sslCtxNativePointer, this);
            } else {
                throw new SSLException("Invalid session context");
            }
        } finally {
            lock.readLock().unlock();
        }
    }

    protected void setSesssionIdContext(byte[] bytes) {
        lock.writeLock().lock();
        try {
            if (isValid()) {
                NativeCrypto.SSL_CTX_set_session_id_context(sslCtxNativePointer, this, bytes);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void freeNative() {
        lock.writeLock().lock();
        try {
            if (isValid()) {
                long toFree = sslCtxNativePointer;
                sslCtxNativePointer = 0;
                NativeCrypto.SSL_CTX_free(toFree, this);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    @SuppressWarnings("Finalize")
    protected void finalize() throws Throwable {
        try {
            freeNative();
        } finally {
            super.finalize();
        }
    }

    /**
     * Adds the given session to the cache.
     */
    final void cacheSession(NativeSslSession session) {
        byte[] id = session.getId();
        if (id == null || id.length == 0) {
            return;
        }

        synchronized (sessions) {
            ByteArray key = new ByteArray(id);
            if (sessions.containsKey(key)) {
                removeSession(sessions.get(key));
            }
            // Let the subclass know.
            onBeforeAddSession(session);

            sessions.put(key, session);
        }
    }

    /**
     * Removes the given session from the cache.
     */
    final void removeSession(NativeSslSession session) {
        byte[] id = session.getId();
        if (id == null || id.length == 0) {
            return;
        }

        onBeforeRemoveSession(session);

        ByteArray key = new ByteArray(id);
        synchronized (sessions) {
            sessions.remove(key);
        }
    }

    /**
     * Called for server sessions only. Retrieves the session by its ID. Overridden by
     * {@link ServerSessionContext} to
     */
    final NativeSslSession getSessionFromCache(byte[] sessionId) {
        if (sessionId == null) {
            return null;
        }

        // First, look in the in-memory cache.
        NativeSslSession session;
        synchronized (sessions) {
            session = sessions.get(new ByteArray(sessionId));
        }
        if (session != null && session.isValid()) {
            if (session.isSingleUse()) {
                removeSession(session);
            }
            return session;
        }

        // Look in persistent cache.  We don't currently delete sessions from the persistent
        // cache, so we may find a multi-use (aka TLS 1.2) session after having received and
        // then used up one or more single-use (aka TLS 1.3) sessions.
        return getSessionFromPersistentCache(sessionId);
    }

    /**
     * Called when the given session is about to be added. Used by {@link ClientSessionContext} to
     * update its host-and-port based cache.
     *
     * <p>Visible for extension only, not intended to be called directly.
     */
    abstract void onBeforeAddSession(NativeSslSession session);

    /**
     * Called when a session is about to be removed. Used by {@link ClientSessionContext}
     * to update its host-and-port based cache.
     *
     * <p>Visible for extension only, not intended to be called directly.
     */
    abstract void onBeforeRemoveSession(NativeSslSession session);

    /**
     * Called for server sessions only. Retrieves the session by ID from the persistent cache.
     *
     * <p>Visible for extension only, not intended to be called directly.
     */
    abstract NativeSslSession getSessionFromPersistentCache(byte[] sessionId);

    /**
     * Makes sure cache size is < maximumSize.
     */
    private void trimToSize() {
        synchronized (sessions) {
            int size = sessions.size();
            if (size > maximumSize) {
                int removals = size - maximumSize;
                Iterator<NativeSslSession> i = sessions.values().iterator();
                while (removals-- > 0) {
                    NativeSslSession session = i.next();
                    onBeforeRemoveSession(session);
                    i.remove();
                }
            }
        }
    }
}
