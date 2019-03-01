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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;

/**
 * Caches client sessions. Indexes by host and port. Users are typically
 * looking to reuse any session for a given host and port.
 */
@Internal
public final class ClientSessionContext extends AbstractSessionContext {
    /**
     * Sessions indexed by host and port. Protect from concurrent
     * access by holding a lock on sessionsByHostAndPort.
     *
     * Invariant: Each list includes either exactly one multi-use session or one
     * or more single-use sessions.  The types of sessions are never mixed, and adding
     * a session of one kind will remove all sessions of the other kind.
     */
    @SuppressWarnings("serial")
    private final Map<HostAndPort, List<NativeSslSession>> sessionsByHostAndPort = new HashMap<HostAndPort, List<NativeSslSession>>();

    private SSLClientSessionCache persistentCache;

    ClientSessionContext() {
        super(10);
    }

    /**
     * Applications should not use this method. Instead use {@link
     * Conscrypt#setClientSessionCache(SSLContext, SSLClientSessionCache)}.
     */
    public void setPersistentCache(SSLClientSessionCache persistentCache) {
        this.persistentCache = persistentCache;
    }

    /**
     * Gets the suitable session reference from the session cache container.
     */
    synchronized NativeSslSession getCachedSession(String hostName, int port,
            SSLParametersImpl sslParameters) {
        if (hostName == null) {
            return null;
        }

        NativeSslSession session = getSession(hostName, port);
        if (session == null) {
            return null;
        }

        String protocol = session.getProtocol();
        boolean protocolFound = false;
        for (String enabledProtocol : sslParameters.enabledProtocols) {
            if (protocol.equals(enabledProtocol)) {
                protocolFound = true;
                break;
            }
        }
        if (!protocolFound) {
            return null;
        }

        String cipherSuite = session.getCipherSuite();
        boolean cipherSuiteFound = false;
        for (String enabledCipherSuite : sslParameters.getEnabledCipherSuites()) {
            if (cipherSuite.equals(enabledCipherSuite)) {
                cipherSuiteFound = true;
                break;
            }
        }
        if (!cipherSuiteFound) {
            return null;
        }

        if (session.isSingleUse()) {
            removeSession(session);
        }
        return session;
    }

    int size() {
        int size = 0;
        synchronized (sessionsByHostAndPort) {
            for (List<NativeSslSession> sessions : sessionsByHostAndPort.values()) {
                size += sessions.size();
            }
        }
        return size;
    }

    /**
     * Finds a cached session for the given host name and port.
     *
     * @param host of server
     * @param port of server
     * @return cached session or null if none found
     */
    private NativeSslSession getSession(String host, int port) {
        if (host == null) {
            return null;
        }

        HostAndPort key = new HostAndPort(host, port);
        NativeSslSession session = null;
        synchronized (sessionsByHostAndPort) {
            List<NativeSslSession> sessions = sessionsByHostAndPort.get(key);
            if (sessions != null && sessions.size() > 0) {
                session = sessions.get(0);
            }
        }
        if (session != null && session.isValid()) {
            return session;
        }

        // Look in persistent cache.  We don't currently delete sessions from the persistent
        // cache, so we may find a multi-use (aka TLS 1.2) session after having received and
        // then used up one or more single-use (aka TLS 1.3) sessions.
        if (persistentCache != null) {
            byte[] data = persistentCache.getSessionData(host, port);
            if (data != null) {
                session = NativeSslSession.newInstance(this, data, host, port);
                if (session != null && session.isValid()) {
                    putSession(key, session);
                    return session;
                }
            }
        }

        return null;
    }

    private void putSession(HostAndPort key, NativeSslSession session) {
        synchronized (sessionsByHostAndPort) {
            List<NativeSslSession> sessions = sessionsByHostAndPort.get(key);
            if (sessions == null) {
                sessions = new ArrayList<NativeSslSession>();
                sessionsByHostAndPort.put(key, sessions);
            }
            // To maintain the invariant that single- and multi-use sessions aren't
            // mixed, check what the current list contains and remove those sessions if
            // they're of the other type.
            if (sessions.size() > 0 && sessions.get(0).isSingleUse() != session.isSingleUse()) {
                while (!sessions.isEmpty()) {
                    removeSession(sessions.get(0));
                }
                // The last removeSession() call will have removed the list from
                // the map, so put it back.
                sessionsByHostAndPort.put(key, sessions);
            }
            sessions.add(session);
        }
    }

    private void removeSession(HostAndPort key, NativeSslSession session) {
        synchronized (sessionsByHostAndPort) {
            List<NativeSslSession> sessions = sessionsByHostAndPort.get(key);
            if (sessions != null) {
                sessions.remove(session);
                if (sessions.isEmpty()) {
                    sessionsByHostAndPort.remove(key);
                }
            }
        }
    }

    @Override
    void onBeforeAddSession(NativeSslSession session) {
        String host = session.getPeerHost();
        int port = session.getPeerPort();
        if (host == null) {
            return;
        }

        HostAndPort key = new HostAndPort(host, port);
        putSession(key, session);

        // TODO: Do this in a background thread.
        if (persistentCache != null && !session.isSingleUse()) {
            byte[] data = session.toBytes();
            if (data != null) {
                persistentCache.putSessionData(session.toSSLSession(), data);
            }
        }
    }

    @Override
    void onBeforeRemoveSession(NativeSslSession session) {
        String host = session.getPeerHost();
        if (host == null) {
            return;
        }
        int port = session.getPeerPort();
        HostAndPort hostAndPortKey = new HostAndPort(host, port);
        removeSession(hostAndPortKey, session);
    }

    @Override
    NativeSslSession getSessionFromPersistentCache(byte[] sessionId) {
        // Not implemented for clients.
        return null;
    }

    private static final class HostAndPort {
        final String host;
        final int port;

        HostAndPort(String host, int port) {
            this.host = host;
            this.port = port;
        }

        @Override
        public int hashCode() {
            return host.hashCode() * 31 + port;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof HostAndPort)) {
                return false;
            }
            HostAndPort lhs = (HostAndPort) o;
            return host.equals(lhs.host) && port == lhs.port;
        }
    }
}
