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
/*
 * Copyright (C) 2008 The Android Open Source Project
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

/**
 * @author Boris Kuznetsov
 * @version $Revision$
 */
package org.apache.harmony.xnet.provider.jsse;

import java.nio.ByteBuffer;
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
    private final LinkedHashMap<ByteBuffer, SSLSession> sessions =
        new LinkedHashMap<ByteBuffer, SSLSession>(cacheSize, 0.75f, true) {
        @Override
        public boolean removeEldestEntry(
                Map.Entry<ByteBuffer, SSLSession> eldest) {
            return cacheSize > 0 && this.size() > cacheSize;
        }
    };
    private volatile LinkedHashMap<ByteBuffer, SSLSession> clone =
            new LinkedHashMap<ByteBuffer, SSLSession>();

    /**
     * @see javax.net.ssl.SSLSessionContext#getIds()
     */
    public Enumeration<byte[]> getIds() {
        return new Enumeration<byte[]>() {
            Iterator<ByteBuffer> iterator = clone.keySet().iterator();
            public boolean hasMoreElements() {
                return iterator.hasNext();
            }
            public byte[] nextElement() {
                return iterator.next().array();
            }
        };
    }

    /**
     * @see javax.net.ssl.SSLSessionContext#getSession(byte[] sessionId)
     */
    public SSLSession getSession(byte[] sessionId) {
        synchronized (sessions) {
            return sessions.get(ByteBuffer.wrap(sessionId));
        }
    }

    /**
     * @see javax.net.ssl.SSLSessionContext#getSessionCacheSize()
     */
    public int getSessionCacheSize() {
        synchronized (sessions) {
            return cacheSize;
        }
    }

    /**
     * @see javax.net.ssl.SSLSessionContext#getSessionTimeout()
     */
    public int getSessionTimeout() {
        synchronized (sessions) {
            return (int) (timeout/1000);
        }
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
            if (cacheSize > 0 && cacheSize < sessions.size()) {
                int removals = sessions.size() - cacheSize;
                Iterator<ByteBuffer> iterator = sessions.keySet().iterator();
                while (removals-- > 0) {
                    iterator.next();
                    iterator.remove();
                }
                clone = (LinkedHashMap<ByteBuffer, SSLSession>)
                        sessions.clone();
            }
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
            Iterator<Map.Entry<ByteBuffer, SSLSession>> iterator =
                    sessions.entrySet().iterator();
            while (iterator.hasNext()) {
                SSLSession session = iterator.next().getValue();
                if (!session.isValid()) {
                    // safe to remove with this special method since it doesn't
                    // make the iterator throw a ConcurrentModificationException
                    iterator.remove();
                }
            }
            clone = (LinkedHashMap<ByteBuffer, SSLSession>) sessions.clone();
        }
    }

    /**
     * Adds session to the session cache
     * @param ses
     */
    void putSession(SSLSession ses) {
        synchronized (sessions) {
            sessions.put(ByteBuffer.wrap(ses.getId()), ses);
            clone = (LinkedHashMap<ByteBuffer, SSLSession>) sessions.clone();
        }
    }
}
