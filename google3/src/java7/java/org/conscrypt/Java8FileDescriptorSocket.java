package org.conscrypt;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

/**
 * Shim for Java 7-only google3 builds that does nothing.
 */
final class Java8FileDescriptorSocket extends ConscryptFileDescriptorSocket {
    Java8FileDescriptorSocket(SSLParametersImpl sslParameters) throws IOException {
        super(sslParameters);
    }

    Java8FileDescriptorSocket(String hostname, int port, SSLParametersImpl sslParameters)
            throws IOException {
        super(hostname, port, sslParameters);
    }

    Java8FileDescriptorSocket(InetAddress address, int port, SSLParametersImpl sslParameters)
            throws IOException {
        super(address, port, sslParameters);
    }

    Java8FileDescriptorSocket(String hostname, int port, InetAddress clientAddress, int clientPort,
            SSLParametersImpl sslParameters) throws IOException {
        super(hostname, port, clientAddress, clientPort, sslParameters);
    }

    Java8FileDescriptorSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort,
            SSLParametersImpl sslParameters) throws IOException {
        super(address, port, clientAddress, clientPort, sslParameters);
    }

    Java8FileDescriptorSocket(Socket socket, String hostname, int port, boolean autoClose,
            SSLParametersImpl sslParameters) throws IOException {
        super(socket, hostname, port, autoClose, sslParameters);
    }
}
