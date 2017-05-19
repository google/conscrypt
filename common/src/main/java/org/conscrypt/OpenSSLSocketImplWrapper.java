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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;

/**
 * This class wraps the SSL functionality over an existing connected socket.
 */
class OpenSSLSocketImplWrapper extends OpenSSLSocketImpl {

    private Socket socket;

    OpenSSLSocketImplWrapper(Socket socket, String hostname, int port,
            boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        super(socket, hostname, port, autoClose, sslParameters);
        if (!socket.isConnected()) {
            throw new SocketException("Socket is not connected.");
        }
        this.socket = socket;
    }

    @Override
    public void connect(SocketAddress sockaddr, int timeout)
        throws IOException {
        socket.connect(sockaddr, timeout);
    }

    @Override
    public void connect(SocketAddress sockaddr) throws IOException {
        socket.connect(sockaddr);
    }

    @Override
    public void bind(SocketAddress sockaddr) throws IOException {
        socket.bind(sockaddr);
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return socket.getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return socket.getLocalSocketAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return socket.getLocalAddress();
    }

    @Override
    public InetAddress getInetAddress() {
        return socket.getInetAddress();
    }

    @Override
    public String toString() {
        return "SSL socket over " + socket.toString();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        socket.setSoLinger(on, linger);
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        socket.setTcpNoDelay(on);
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        socket.setReuseAddress(on);
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        socket.setKeepAlive(on);
    }

    @Override
    public void setTrafficClass(int tos) throws SocketException {
        socket.setTrafficClass(tos);
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void setSendBufferSize(int size) throws SocketException {
        socket.setSendBufferSize(size);
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void setReceiveBufferSize(int size) throws SocketException {
        socket.setReceiveBufferSize(size);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return socket.getTcpNoDelay();
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        return socket.getReuseAddress();
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return socket.getOOBInline();
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return socket.getKeepAlive();
    }

    @Override
    public int getTrafficClass() throws SocketException {
        return socket.getTrafficClass();
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public int getSoTimeout() throws SocketException {
        return socket.getSoTimeout();
    }

    @Override
    public int getSoLinger() throws SocketException {
        return socket.getSoLinger();
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public int getSendBufferSize() throws SocketException {
        return socket.getSendBufferSize();
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public int getReceiveBufferSize() throws SocketException {
        return socket.getReceiveBufferSize();
    }

    @Override
    public boolean isConnected() {
        return socket.isConnected();
    }

    @Override
    public boolean isClosed() {
        return socket.isClosed();
    }

    @Override
    public boolean isBound() {
        return socket.isBound();
    }

    @Override
    public boolean isOutputShutdown() {
        return socket.isOutputShutdown();
    }

    @Override
    public boolean isInputShutdown() {
        return socket.isInputShutdown();
    }

    @Override
    public int getPort() {
        return socket.getPort();
    }

    @Override
    public int getLocalPort() {
        return socket.getLocalPort();
    }
}
