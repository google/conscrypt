package org.conscrypt.tlswire;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.conscrypt.tlswire.handshake.ClientHello;
import org.conscrypt.tlswire.handshake.HandshakeMessage;
import org.conscrypt.tlswire.record.TlsProtocols;
import org.conscrypt.tlswire.record.TlsRecord;

public class TlsTester {

    private TlsTester() {}

    public static ClientHello captureTlsHandshakeClientHello(ExecutorService executor,
            SSLSocketFactory sslSocketFactory) throws Exception {
        TlsRecord record = captureTlsHandshakeFirstTlsRecord(executor, sslSocketFactory);
        return parseClientHello(record);
    }

    public static ClientHello parseClientHello(byte[] data) throws Exception {
        return parseClientHello(parseRecord(data));
    }

    private static ClientHello parseClientHello(TlsRecord record) throws Exception {
        assertEquals("TLS record type", TlsProtocols.HANDSHAKE, record.type);
        ByteArrayInputStream fragmentIn = new ByteArrayInputStream(record.fragment);
        HandshakeMessage handshakeMessage = HandshakeMessage.read(new DataInputStream(fragmentIn));
        assertEquals(
                "HandshakeMessage type", HandshakeMessage.TYPE_CLIENT_HELLO, handshakeMessage.type);
        // Assert that the fragment does not contain any more messages
        assertEquals(0, fragmentIn.available());
        return (ClientHello) handshakeMessage;
    }

    public static TlsRecord captureTlsHandshakeFirstTlsRecord(ExecutorService executor,
            SSLSocketFactory sslSocketFactory) throws Exception {
        byte[] firstReceivedChunk = captureTlsHandshakeFirstTransmittedChunkBytes(executor, sslSocketFactory);
        return parseRecord(firstReceivedChunk);
    }

    public static TlsRecord parseRecord(byte[] data) throws Exception {
        ByteArrayInputStream firstReceivedChunkIn = new ByteArrayInputStream(data);
        TlsRecord record = TlsRecord.read(new DataInputStream(firstReceivedChunkIn));
        // Assert that the chunk does not contain any more data
        assertEquals(0, firstReceivedChunkIn.available());
        return record;
    }

    @SuppressWarnings("FutureReturnValueIgnored")
    private static byte[] captureTlsHandshakeFirstTransmittedChunkBytes(
            ExecutorService executor, final SSLSocketFactory sslSocketFactory) throws Exception {
        // Since there's no straightforward way to obtain a ClientHello from SSLSocket, this test
        // does the following:
        // 1. Creates a listening server socket (a plain one rather than a TLS/SSL one).
        // 2. Creates a client SSLSocket, which connects to the server socket and initiates the
        //    TLS/SSL handshake.
        // 3. Makes the server socket accept an incoming connection on the server socket, and reads
        //    the first chunk of data received. This chunk is assumed to be the ClientHello.
        // NOTE: Steps 2 and 3 run concurrently.
        ServerSocket listeningSocket = null;
        // Some Socket operations are not interruptible via Thread.interrupt for some reason. To
        // work around, we unblock these sockets using Socket.close.
        final Socket[] sockets = new Socket[2];
        try {
            // 1. Create the listening server socket.
            listeningSocket = ServerSocketFactory.getDefault().createServerSocket(0);
            final ServerSocket finalListeningSocket = listeningSocket;
            // 2. (in background) Wait for an incoming connection and read its first chunk.
            final Future<byte[]>
                    readFirstReceivedChunkFuture = executor.submit(new Callable<byte[]>() {
                @Override
                public byte[] call() throws Exception {
                    Socket socket = finalListeningSocket.accept();
                    sockets[1] = socket;
                    try {
                        byte[] buffer = new byte[64 * 1024];
                        int bytesRead = socket.getInputStream().read(buffer);
                        if (bytesRead == -1) {
                            throw new EOFException("Failed to read anything");
                        }
                        return Arrays.copyOf(buffer, bytesRead);
                    } finally {
                        closeQuietly(socket);
                    }
                }
            });
            // 3. Create a client socket, connect it to the server socket, and start the TLS/SSL
            //    handshake.
            executor.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    Socket client = new Socket();
                    sockets[0] = client;
                    try {
                        client.connect(finalListeningSocket.getLocalSocketAddress());
                        // Initiate the TLS/SSL handshake which is expected to fail as soon as the
                        // server socket receives a ClientHello.
                        try {
                            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(client,
                                    "localhost.localdomain", finalListeningSocket.getLocalPort(),
                                    true);
                            sslSocket.startHandshake();
                            fail();
                            return null;
                        } catch (IOException expected) {
                            // Ignored.
                        }
                        return null;
                    } finally {
                        closeQuietly(client);
                    }
                }
            });
            // Wait for the ClientHello to arrive
            return readFirstReceivedChunkFuture.get(10, TimeUnit.SECONDS);
        } finally {
            closeQuietly(listeningSocket);
            closeQuietly(sockets[0]);
            closeQuietly(sockets[1]);
        }
    }

    private static void closeQuietly(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // Ignored.
            }
        }
    }

    private static void closeQuietly(ServerSocket serverSocket) {
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
                // Ignored.
            }
        }
    }
}
