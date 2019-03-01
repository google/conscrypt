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

import javax.net.ssl.SSLContext;

/**
 * Caches server sessions. Indexes by session ID. Users typically look up
 * sessions using the ID provided by an SSL client.
 */
@Internal
public final class ServerSessionContext extends AbstractSessionContext {
    private SSLServerSessionCache persistentCache;

    ServerSessionContext() {
        super(100);

        // TODO make sure SSL_CTX does not automaticaly clear sessions we want it to cache
        // SSL_CTX_set_session_cache_mode(sslCtxNativePointer, SSL_SESS_CACHE_NO_AUTO_CLEAR);

        // TODO remove SSL_CTX session cache limit so we can manage it
        // SSL_CTX_sess_set_cache_size(sslCtxNativePointer, 0);

        // TODO override trimToSize and removeEldestEntry to use
        // SSL_CTX_sessions to remove from native cache

        // Set a trivial session id context. OpenSSL uses this to make
        // sure you don't reuse sessions externalized with i2d_SSL_SESSION
        // between apps. However our sessions are either in memory or
        // exported to a app's SSLServerSessionCache.
        NativeCrypto.SSL_CTX_set_session_id_context(sslCtxNativePointer, this, new byte[] { ' ' });
    }

    /**
     * Applications should not use this method. Instead use {@link
     * Conscrypt#setServerSessionCache(SSLContext, SSLServerSessionCache)}.
     */
    public void setPersistentCache(SSLServerSessionCache persistentCache) {
        this.persistentCache = persistentCache;
    }

    @Override
    NativeSslSession getSessionFromPersistentCache(byte[] sessionId) {
        if (persistentCache != null) {
            byte[] data = persistentCache.getSessionData(sessionId);
            if (data != null) {
                NativeSslSession session = NativeSslSession.newInstance(this, data, null, -1);
                if (session != null && session.isValid()) {
                    cacheSession(session);
                    return session;
                }
            }
        }

        return null;
    }

    @Override
    void onBeforeAddSession(NativeSslSession session) {
        // TODO: Do this in background thread.
        if (persistentCache != null) {
            byte[] data = session.toBytes();
            if (data != null) {
                persistentCache.putSessionData(session.toSSLSession(), data);
            }
        }
    }

    @Override
    void onBeforeRemoveSession(NativeSslSession session) {
        // Do nothing.
    }
}
