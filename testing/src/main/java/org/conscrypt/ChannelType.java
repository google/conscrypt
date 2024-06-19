/*
 * Copyright 2017 The Android Open Source Project
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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * The type of socket to be wrapped by the Conscrypt socket.
 */
@SuppressWarnings("unused")
public enum ChannelType {
    NONE {
        @Override
        public SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
                throws IOException {
            return clientMode(factory.createSocket(address, port));
        }

        @Override
        public ServerSocket newServerSocket(SSLServerSocketFactory factory) throws IOException {
            return factory.createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        }

        @Override
        public SSLSocket accept(ServerSocket socket, SSLSocketFactory unused) throws IOException {
            return serverMode(socket.accept());
        }
    },
    NO_CHANNEL {
        @Override
        public SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
                throws IOException {
            Socket wrapped = new Socket(address, port);
            assertNull(wrapped.getChannel());

            return clientMode(factory.createSocket(wrapped, address.getHostName(), port, true));
        }

        @Override
        public ServerSocket newServerSocket(SSLServerSocketFactory unused) throws IOException {
            return ServerSocketFactory.getDefault().createServerSocket(
                    0, 50, InetAddress.getLoopbackAddress());
        }

        @Override
        public SSLSocket accept(ServerSocket serverSocket, SSLSocketFactory factory) throws IOException {
            assertFalse(serverSocket instanceof SSLServerSocket);
            Socket wrapped = serverSocket.accept();
            assertNull(wrapped.getChannel());

            return serverMode(factory.createSocket(
                    wrapped, wrapped.getInetAddress().getHostAddress(), wrapped.getPort(), true));
        }
    },
    CHANNEL {
        @Override
        public SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
                throws IOException {
            Socket wrapped = SocketChannel.open(new InetSocketAddress(address, port)).socket();
            return clientMode(factory.createSocket(wrapped, address.getHostName(), port, true));
        }

        @Override
        public ServerSocket newServerSocket(SSLServerSocketFactory unused) throws IOException {
            return ServerSocketChannel.open()
                    .bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                    .socket();
        }

        @Override
        public SSLSocket accept(ServerSocket serverSocket, SSLSocketFactory factory) throws IOException {
            assertFalse(serverSocket instanceof SSLServerSocket);
            ServerSocketChannel serverChannel = serverSocket.getChannel();

            // Just loop until the accept completes.
            SocketChannel channel;
            do {
                channel = serverChannel.accept();
            } while (channel == null);

            Socket wrapped = channel.socket();
            return serverMode(factory.createSocket(
                    wrapped, wrapped.getInetAddress().getHostAddress(), wrapped.getPort(), true));
        }
    };

    public abstract SSLSocket newClientSocket(SSLSocketFactory factory, InetAddress address, int port)
            throws IOException;
    public abstract ServerSocket newServerSocket(SSLServerSocketFactory factory) throws IOException;
    public abstract SSLSocket accept(ServerSocket socket, SSLSocketFactory factory) throws IOException;

    private static SSLSocket clientMode(Socket socket) {
        SSLSocket sslSocket = (SSLSocket) socket;
        sslSocket.setUseClientMode(true);
        return sslSocket;
    }

    private static SSLSocket serverMode(Socket socket) {
        SSLSocket sslSocket = (SSLSocket) socket;
        sslSocket.setUseClientMode(false);
        return sslSocket;
    }
}
