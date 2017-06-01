/*
 * Copyright (C) 2015 The Android Open Source Project
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

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/**
 * This class delegates all calls to an {@code org.conscrypt.AbstractConscryptSocket}.
 * This is to work around code that checks that the socket is an
 * {@code org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl} before
 * calling methods, such as setting SNI. This is only for KitKat.
 *
 * It delegates all public methods in Socket, SSLSocket, and OpenSSLSocket from
 * KK.
 */
public class KitKatPlatformOpenSSLSocketImplAdapter
        extends com.android.org.conscrypt.OpenSSLSocketImpl {
    private final AbstractConscryptSocket delegate;

    public KitKatPlatformOpenSSLSocketImplAdapter(AbstractConscryptSocket delegate)
            throws IOException {
        super(delegate, null, -1, true);
        this.delegate = delegate;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return delegate.getInputStream();
    }

    @Override
    public int getLocalPort() {
        return delegate.getLocalPort();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return delegate.getOutputStream();
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

    @Override
    public FileDescriptor getFileDescriptor$() {
        return delegate.getFileDescriptor$();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        delegate.addHandshakeCompletedListener(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        delegate.removeHandshakeCompletedListener(listener);
    }

    @Override
    public void setUseSessionTickets(boolean useSessionTickets) {
        delegate.setUseSessionTickets(useSessionTickets);
    }

    @Override
    public void setChannelIdEnabled(boolean enabled) {
        delegate.setChannelIdEnabled(enabled);
    }

    @Override
    public byte[] getChannelId() throws SSLException {
        return delegate.getChannelId();
    }

    @Override
    public void setChannelIdPrivateKey(PrivateKey privateKey) {
        delegate.setChannelIdPrivateKey(privateKey);
    }

    @Override
    public byte[] getAlpnSelectedProtocol() {
        return delegate.getAlpnSelectedProtocol();
    }

    @Override
    public void setAlpnProtocols(String[] alpnProtocols) {
        delegate.setAlpnProtocols(alpnProtocols);
    }

    @Override
    public void setAlpnProtocols(byte[] alpnProtocols) {
        delegate.setAlpnProtocols(alpnProtocols);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return delegate.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] strings) {
        delegate.setEnabledCipherSuites(strings);
    }

    @Override
    public String[] getSupportedProtocols() {
        return delegate.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return delegate.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] strings) {
        delegate.setEnabledProtocols(strings);
    }

    @Override
    public SSLSession getSession() {
        return delegate.getSession();
    }

    @Override
    public void startHandshake() throws IOException {
        delegate.startHandshake();
    }

    @Override
    public void setUseClientMode(boolean b) {
        delegate.setUseClientMode(b);
    }

    @Override
    public boolean getUseClientMode() {
        return delegate.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean b) {
        delegate.setNeedClientAuth(b);
    }

    @Override
    public boolean getNeedClientAuth() {
        return delegate.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean b) {
        delegate.setWantClientAuth(b);
    }

    @Override
    public boolean getWantClientAuth() {
        return delegate.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean b) {
        delegate.setEnableSessionCreation(b);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return delegate.getEnableSessionCreation();
    }
}
