/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/**
 * @author Boris Kuznetsov
 * @version $Revision$
 */
package org.apache.harmony.xnet.provider.jsse;

//BEGIN android-changed
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

/**
 * SSLSessionContext implementation
 * 
 * @see javax.net.ssl.SSLSessionContext
 */
public class SSLSessionContextImpl implements SSLSessionContext {

    private int cacheSize = 20;
    private long timeout = 0;
    private final LinkedHashMap<byte[], SSLSession> sessions =
        new LinkedHashMap<byte[],SSLSession>(cacheSize, 0.75f, true) {
        public boolean removeEldestEntry(Map.Entry eldest) {
            return cacheSize > 0 && this.size() > cacheSize;
        }
    };
    private volatile LinkedHashMap<byte[], SSLSession> clone = new LinkedHashMap<byte[], SSLSession>();

    /**
     * @see javax.net.ssl.SSLSessionContext#getIds()
     */
    public Enumeration<byte[]> getIds() {
        return new Enumeration<byte[]>() {
            Iterator<byte[]> iterator = clone.keySet().iterator();
            public boolean hasMoreElements() {
                return iterator.hasNext();
            }
            public byte[] nextElement() {
                return iterator.next();
            }
        };
    }

    /**
     * @see javax.net.ssl.SSLSessionContext#getSession(byte[] sessionId)
     */
    public SSLSession getSession(byte[] sessionId) {
        synchronized (sessions) {
            return (SSLSession) sessions.get(sessionId);
        }
    }

    /**
     * @see javax.net.ssl.SSLSessionContext#getSessionCacheSize()
     */
    public int getSessionCacheSize() {
        return cacheSize;
    }

    /**
     * @see javax.net.ssl.SSLSessionContext#getSessionTimeout()
     */
    public int getSessionTimeout() {
        return (int) (timeout/1000);
    }

    /**
     * @see javax.net.ssl.SSLSessionContext#setSessionCacheSize(int size)
     */
    public void setSessionCacheSize(int size) throws IllegalArgumentException {
        if (size < 0) {
            throw new IllegalArgumentException("size < 0");
        }
        synchronized (sessions) {
            cacheSize = size;
            Set<byte[]> set = sessions.keySet();
            if (cacheSize > 0 && cacheSize < set.size()) {
                // Resize the cache to the maximum
                Iterator<byte[]> iterator = set.iterator();
                for (int i = 0; iterator.hasNext(); i++) {
                    iterator.next();
                    if (i >= cacheSize) {
                        iterator.remove();
                    }
                }
            }
            clone = (LinkedHashMap<byte[], SSLSession>) sessions.clone();
        }
    }

    /**
     * @see javax.net.ssl.SSLSessionContext#setSessionTimeout(int seconds)
     */
    public void setSessionTimeout(int seconds) throws IllegalArgumentException {
        if (seconds < 0) {
            throw new IllegalArgumentException("seconds < 0");
        }

        synchronized (sessions) {
            timeout = seconds*1000;
            // Check timeouts and remove expired sessions
            SSLSession ses;
            for (Iterator<byte[]> iterator = sessions.keySet().iterator(); iterator.hasNext();) {
                ses = (SSLSession)(sessions.get(iterator.next()));
                if (!ses.isValid()) {
                    iterator.remove();
                }
            }
            clone = (LinkedHashMap<byte[], SSLSession>) sessions.clone();
        }
    }

    /**
     * Adds session to the session cache
     * @param ses
     */
    void putSession(SSLSession ses) {
        synchronized (sessions) {
            sessions.put(ses.getId(), ses);
            clone = (LinkedHashMap<byte[], SSLSession>) sessions.clone();
        }
    }
}
// END android-changed