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

package org.conscrypt;

import org.conscrypt.util.EmptyArray;

import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.HashMap;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;

public final class SSLNullSession implements SSLSession, Cloneable {

    /*
     * Holds default instances so class preloading doesn't create an instance of
     * it.
     */
    private static class DefaultHolder {
        public static final SSLNullSession NULL_SESSION = new SSLNullSession();
    }

    private final HashMap<String, Object> values = new HashMap<String, Object>();

    long creationTime;
    long lastAccessedTime;

    public static SSLSession getNullSession() {
        return DefaultHolder.NULL_SESSION;
    }

    public SSLNullSession() {
        creationTime = System.currentTimeMillis();
        lastAccessedTime = creationTime;
    }

    @Override
    public int getApplicationBufferSize() {
        return SSLRecordProtocol.MAX_DATA_LENGTH;
    }

    @Override
    public String getCipherSuite() {
        return "SSL_NULL_WITH_NULL_NULL";
    }

    @Override
    public long getCreationTime() {
        return creationTime;
    }

    @Override
    public byte[] getId() {
        return EmptyArray.BYTE;
    }

    @Override
    public long getLastAccessedTime() {
        return lastAccessedTime;
    }

    @Override
    public Certificate[] getLocalCertificates() {
        return null;
    }

    @Override
    public Principal getLocalPrincipal() {
        return null;
    }

    @Override
    public int getPacketBufferSize() {
        return SSLRecordProtocol.MAX_SSL_PACKET_SIZE;
    }

    @Override
    public javax.security.cert.X509Certificate[] getPeerCertificateChain()
            throws SSLPeerUnverifiedException {
        throw new SSLPeerUnverifiedException("No peer certificate");
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        throw new SSLPeerUnverifiedException("No peer certificate");
    }

    @Override
    public String getPeerHost() {
        return null;
    }

    @Override
    public int getPeerPort() {
        return -1;
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        throw new SSLPeerUnverifiedException("No peer certificate");
    }

    @Override
    public String getProtocol() {
        return "NONE";
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return null;
    }

    @Override
    public Object getValue(String name) {
        if (name == null) {
            throw new IllegalArgumentException("name == null");
        }
        return values.get(name);
    }

    @Override
    public String[] getValueNames() {
        return values.keySet().toArray(new String[values.size()]);
    }

    @Override
    public void invalidate() {
    }

    @Override
    public boolean isValid() {
        return false;
    }

    @Override
    public void putValue(String name, Object value) {
        if (name == null || value == null) {
            throw new IllegalArgumentException("name == null || value == null");
        }
        Object old = values.put(name, value);
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(this, name));
        }
        if (old instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) old).valueUnbound(new SSLSessionBindingEvent(this, name));
        }

    }

    @Override
    public void removeValue(String name) {
        if (name == null) {
            throw new IllegalArgumentException("name == null");
        }
        Object old = values.remove(name);
        if (old instanceof SSLSessionBindingListener) {
            SSLSessionBindingListener listener = (SSLSessionBindingListener) old;
            listener.valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }
}
