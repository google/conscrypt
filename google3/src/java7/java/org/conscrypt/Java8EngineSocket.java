package org.conscrypt;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

/**
 * Shim for Java 7-only google3 builds that does nothing.
 */
final class Java8EngineSocket extends ConscryptEngineSocket {
    Java8EngineSocket(SSLParametersImpl sslParameters) throws IOException {
        super(sslParameters);
    }

    Java8EngineSocket(String hostname, int port, SSLParametersImpl sslParameters)
            throws IOException {
        super(hostname, port, sslParameters);
    }

    Java8EngineSocket(InetAddress address, int port, SSLParametersImpl sslParameters)
            throws IOException {
        super(address, port, sslParameters);
    }

    Java8EngineSocket(String hostname, int port, InetAddress clientAddress, int clientPort,
            SSLParametersImpl sslParameters) throws IOException {
        super(hostname, port, clientAddress, clientPort, sslParameters);
    }

    Java8EngineSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort,
            SSLParametersImpl sslParameters) throws IOException {
        super(address, port, clientAddress, clientPort, sslParameters);
    }

    Java8EngineSocket(Socket socket, String hostname, int port, boolean autoClose,
            SSLParametersImpl sslParameters) throws IOException {
        super(socket, hostname, port, autoClose, sslParameters);
    }
}
