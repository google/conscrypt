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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.Arrays;

import javax.net.ssl.SSLSession;

/**
 * Caches server sessions. Indexes by session ID. Users typically look up
 * sessions using the ID provided by an SSL client.
 */
public class ServerSessionContext extends AbstractSessionContext {

    /*
     * TODO: Expire timed-out sessions more pro-actively.
     */

    private final Map<ByteArray, SSLSession> sessions
            = new LinkedHashMap<ByteArray, SSLSession>() {
        @Override
        protected boolean removeEldestEntry(
                Map.Entry<ByteArray, SSLSession> eldest) {
            return maximumSize > 0 && size() > maximumSize;
        }
    };

    private final SSLServerSessionCache persistentCache;

    public ServerSessionContext(SSLParameters parameters,
            SSLServerSessionCache persistentCache) {
        super(parameters, 100, 0);
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
    }

    public SSLSession getSession(byte[] sessionId) {
        ByteArray key = new ByteArray(sessionId);
        synchronized (sessions) {
            SSLSession session = sessions.get(key);
            if (session != null) {
                return session;
            }
        }

        // Check persistent cache.
        if (persistentCache != null) {
            byte[] data = persistentCache.getSessionData(sessionId);
            if (data != null) {
                SSLSession session = toSession(data, null, -1);
                if (session != null) {
                    synchronized (sessions) {
                        sessions.put(key, session);
                    }
                    return session;
                }
            }
        }

        return null;
    }

    void putSession(SSLSession session) {
        ByteArray key = new ByteArray(session.getId());
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
