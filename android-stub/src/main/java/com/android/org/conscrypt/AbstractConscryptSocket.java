/*
 * Copyright (C) 2017 The Android Open Source Project
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

package com.android.org.conscrypt;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.PrivateKey;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Abstract base class for all Conscrypt sockets that extends the basic {@link SSLSocket} API.
 */
@SuppressWarnings("unused")
abstract class AbstractConscryptSocket extends SSLSocket {
    AbstractConscryptSocket() throws IOException {
    }

    AbstractConscryptSocket(String hostname, int port) throws IOException {
        super(hostname, port);
    }

    AbstractConscryptSocket(InetAddress address, int port) throws IOException {
        super(address, port);
    }

    AbstractConscryptSocket(String hostname, int port, InetAddress clientAddress, int clientPort)
            throws IOException {
        super(hostname, port, clientAddress, clientPort);
    }

    AbstractConscryptSocket(InetAddress address, int port, InetAddress clientAddress,
            int clientPort) throws IOException {
        super(address, port, clientAddress, clientPort);
    }

    AbstractConscryptSocket(Socket socket, String hostname, int port, boolean autoClose)
            throws IOException {
    }

    public String getHostname() {
        return null;
    }

    public void setHostname(String hostname) {
    }

    public String getHostnameOrIP() {
        return null;
    }

    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java 6.
    public abstract SSLSession getHandshakeSession();

    /* @Override */
    public FileDescriptor getFileDescriptor$() {
        return null;
    }

    public void setSoWriteTimeout(int writeTimeoutMilliseconds) throws SocketException {
    }

    public int getSoWriteTimeout() throws SocketException {
        return 0;
    }

    public void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException {
    }

    /**
     * This method enables session ticket support.
     *
     * @param useSessionTickets True to enable session tickets
     */
    public abstract void setUseSessionTickets(boolean useSessionTickets);

    public abstract void setChannelIdEnabled(boolean enabled);

    public abstract byte[] getChannelId() throws SSLException;

    public abstract void setChannelIdPrivateKey(PrivateKey privateKey);

    public byte[] getNpnSelectedProtocol() {
        return null;
    }

    public void setNpnProtocols(byte[] npnProtocols) {}

    public abstract byte[] getAlpnSelectedProtocol();

    public abstract void setAlpnProtocols(String[] alpnProtocols);

    public abstract void setAlpnProtocols(byte[] alpnProtocols);
}
