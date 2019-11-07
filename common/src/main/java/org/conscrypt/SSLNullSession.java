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

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

/**
 * This is returned in the place of a {@link SSLSession} when no TLS connection could be negotiated,
 * but one was requested from a method that can't throw an exception such as {@link
 * javax.net.ssl.SSLSocket#getSession()} before {@link javax.net.ssl.SSLSocket#startHandshake()} is
 * called.
 */
final class SSLNullSession implements ConscryptSession, Cloneable {
    static final String INVALID_CIPHER = "SSL_NULL_WITH_NULL_NULL";

    /*
     * Holds default instances so class preloading doesn't create an instance of
     * it.
     */
    private static class DefaultHolder {
        static final SSLNullSession NULL_SESSION = new SSLNullSession();
    }

    private long creationTime;
    private long lastAccessedTime;

    static ConscryptSession getNullSession() {
        return DefaultHolder.NULL_SESSION;
    }

    private SSLNullSession() {
        creationTime = System.currentTimeMillis();
        lastAccessedTime = creationTime;
    }

    @Override
    public String getRequestedServerName() {
        return null;
    }

    @Override
    public List<byte[]> getStatusResponses() {
        return Collections.emptyList();
    }

    @Override
    public byte[] getPeerSignedCertificateTimestamp() {
        return EmptyArray.BYTE;
    }

    @Override
    public int getApplicationBufferSize() {
        return NativeConstants.SSL3_RT_MAX_PLAIN_LENGTH;
    }

    @Override
    public String getApplicationProtocol()  {
        return null;
    }

    @Override
    public String getCipherSuite() {
        return INVALID_CIPHER;
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
        return NativeConstants.SSL3_RT_MAX_PACKET_SIZE;
    }

    @Override
    public javax.security.cert.X509Certificate[] getPeerCertificateChain()
            throws SSLPeerUnverifiedException {
        throw new SSLPeerUnverifiedException("No peer certificate");
    }

    @Override
    public X509Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
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
        throw new UnsupportedOperationException(
                "All calls to this method should be intercepted by ExternalSession.");
    }

    @Override
    public String[] getValueNames() {
        throw new UnsupportedOperationException(
                "All calls to this method should be intercepted by ExternalSession.");
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
        throw new UnsupportedOperationException(
                "All calls to this method should be intercepted by ExternalSession.");
    }

    @Override
    public void removeValue(String name) {
        throw new UnsupportedOperationException(
                "All calls to this method should be intercepted by ExternalSession.");
    }
}
