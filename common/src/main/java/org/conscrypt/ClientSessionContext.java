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

import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLContext;

/**
 * Caches client sessions. Indexes by host and port. Users are typically
 * looking to reuse any session for a given host and port.
 *
 * @hide
 */
@Internal
public final class ClientSessionContext extends AbstractSessionContext {
    /**
     * Sessions indexed by host and port. Protect from concurrent
     * access by holding a lock on sessionsByHostAndPort.
     */
    @SuppressWarnings("serial")
    private final Map<HostAndPort, NativeSslSession> sessionsByHostAndPort = new HashMap<HostAndPort, NativeSslSession>();

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
    NativeSslSession getCachedSession(String hostName, int port, SSLParametersImpl sslParameters) {
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
        for (String enabledCipherSuite : sslParameters.enabledCipherSuites) {
            if (cipherSuite.equals(enabledCipherSuite)) {
                cipherSuiteFound = true;
                break;
            }
        }
        if (!cipherSuiteFound) {
            return null;
        }

        return session;
    }

    int size() {
        return sessionsByHostAndPort.size();
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
        NativeSslSession session;
        synchronized (sessionsByHostAndPort) {
            session = sessionsByHostAndPort.get(key);
        }
        if (session != null && session.isValid()) {
            return session;
        }

        // Look in persistent cache.
        if (persistentCache != null) {
            byte[] data = persistentCache.getSessionData(host, port);
            if (data != null) {
                session = NativeSslSession.newInstance(this, data, host, port);
                if (session != null && session.isValid()) {
                    synchronized (sessionsByHostAndPort) {
                        sessionsByHostAndPort.put(key, session);
                    }
                    return session;
                }
            }
        }

        return null;
    }

    @Override
    void onBeforeAddSession(NativeSslSession session) {
        String host = session.getPeerHost();
        int port = session.getPeerPort();
        if (host == null) {
            return;
        }

        HostAndPort key = new HostAndPort(host, port);
        synchronized (sessionsByHostAndPort) {
            sessionsByHostAndPort.put(key, session);
        }

        // TODO: Do this in a background thread.
        if (persistentCache != null) {
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
        synchronized (sessionsByHostAndPort) {
            sessionsByHostAndPort.remove(hostAndPortKey);
        }
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
