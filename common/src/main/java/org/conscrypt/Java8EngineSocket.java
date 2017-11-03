package org.conscrypt;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

/**
 * A version of ConscryptEngineSocket that includes the new Java 9 (and potentially later
 * patches of 8) {@code setHandshakeApplicationProtocolSelector} API (which requires Java 8 for
 * compilation, due to the use of {@link BiFunction}).
 */
final class Java8EngineSocket extends ConscryptEngineSocket {
    private BiFunction<SSLSocket, List<String>, String> selector;

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

    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java < 9.
    public void setHandshakeApplicationProtocolSelector(
            final BiFunction<SSLSocket, List<String>, String> selector) {
        this.selector = selector;
        setApplicationProtocolSelector(toApplicationProtocolSelector(selector));
    }

    /* @Override */
    @SuppressWarnings("MissingOverride") // For compilation with Java < 9.
    public BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return selector;
    }

    private static ApplicationProtocolSelector toApplicationProtocolSelector(
        final BiFunction<SSLSocket, List<String>, String> selector) {
        return selector == null ? null : new ApplicationProtocolSelector() {
            @Override
            public String selectApplicationProtocol(SSLEngine socket, List<String> protocols) {
                throw new UnsupportedOperationException();
            }

            @Override
            public String selectApplicationProtocol(SSLSocket socket, List<String> protocols) {
                return selector.apply(socket, protocols);
            }
        };
    }
}
