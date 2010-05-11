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

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.net.ssl.SSLSession;

/**
 * Caches server sessions. Indexes by session ID. Users typically look up
 * sessions using the ID provided by an SSL client.
 */
public class ServerSessionContext extends AbstractSessionContext {

    private final Map<ByteArray, SSLSession> sessions
            = new LinkedHashMap<ByteArray, SSLSession>() {
        @Override
        protected boolean removeEldestEntry(
                Map.Entry<ByteArray, SSLSession> eldest) {
            return maximumSize > 0 && size() > maximumSize;
        }
    };

    private SSLServerSessionCache persistentCache;

    public ServerSessionContext() {
        super(100, 0);

        // TODO make sure SSL_CTX does not automaticaly clear sessions we want it to cache
        // SSL_CTX_set_session_cache_mode(sslCtxNativePointer, SSL_SESS_CACHE_NO_AUTO_CLEAR);

        // TODO remove SSL_CTX session cache limit so we can manage it
        // SSL_CTX_sess_set_cache_size(sslCtxNativePointer, 0);

        // TODO override trimToSize and removeEldestEntry to use
        // SSL_CTX_sessions to remove from native cache
    }

    public void setPersistentCache(SSLServerSessionCache persistentCache) {
        this.persistentCache = persistentCache;
    }

    Iterator<SSLSession> sessionIterator() {
        synchronized (sessions) {
            SSLSession[] array = sessions.values().toArray(
                    new SSLSession[sessions.size()]);
            return Arrays.asList(array).iterator();
        }
    }

    void trimToSize() {
        synchronized (sessions) {
            int size = sessions.size();
            if (size > maximumSize) {
                int removals = size - maximumSize;
                Iterator<SSLSession> i = sessions.values().iterator();
                do {
                    i.next();
                    i.remove();
                } while (--removals > 0);
            }
        }
    }

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
                }
            }
        }
    }

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
            return session;
        }

        // Check persistent cache.
        if (persistentCache != null) {
            byte[] data = persistentCache.getSessionData(sessionId);
            if (data != null) {
                session = toSession(data, null, -1);
                if (session != null && session.isValid()) {
                    synchronized (sessions) {
                        sessions.put(key, session);
                    }
                    return session;
                }
            }
        }

        return null;
    }

    @Override
    void putSession(SSLSession session) {
        byte[] id = session.getId();
        if (id.length == 0) {
            return;
        }
        ByteArray key = new ByteArray(id);
        synchronized (sessions) {
            sessions.put(key, session);
        }

        // TODO: In background thread.
        if (persistentCache != null) {
            byte[] data = toBytes(session);
            if (data != null) {
                persistentCache.putSessionData(session, data);
            }
        }
    }
}
