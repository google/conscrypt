/*
 * Copyright (C) 2024 The Android Open Source Project
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.net.ssl.PakeClientKeyManagerParameters;
import android.net.ssl.PakeOption;
import android.net.ssl.PakeServerKeyManagerParameters;

import org.conscrypt.Spake2PlusKeyManager;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import tests.util.Pair;

@RunWith(JUnit4.class)
public class SpakeTest {
    private static final byte[] CLIENT_ID = new byte[] {4, 5, 6};
    private static final byte[] SERVER_ID = new byte[] {7, 8, 9};
    private final ThreadGroup threadGroup = new ThreadGroup("SpakeTest");
    private final ExecutorService executor =
            Executors.newCachedThreadPool(t -> new Thread(threadGroup, t));

    private Pair<SSLContext, SSLContext> createContexts(PakeClientKeyManagerParameters clientParams,
            PakeServerKeyManagerParameters serverParams) throws Exception {
        InetAddress hostC = TestUtils.getLoopbackAddress();
        InetAddress hostS = TestUtils.getLoopbackAddress();

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
        tmf.init((ManagerFactoryParameters) null);

        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
        kmfClient.init(clientParams);
        KeyManager[] keyManagersClient = kmfClient.getKeyManagers();
        assertTrue(keyManagersClient.length == 1);
        assertTrue(keyManagersClient[0] instanceof Spake2PlusKeyManager);
        Spake2PlusKeyManager spake2PlusKeyManagerClient =
                (Spake2PlusKeyManager) keyManagersClient[0];
        assertTrue(spake2PlusKeyManagerClient.isClient());
        SSLContext contextClient = SSLContext.getInstance("TlsV1.3");
        contextClient.init(keyManagersClient, tmf.getTrustManagers(), null);

        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
        kmfServer.init(serverParams);
        KeyManager[] keyManagersServer = kmfServer.getKeyManagers();
        assertTrue(keyManagersServer.length == 1);
        assertTrue(keyManagersServer[0] instanceof Spake2PlusKeyManager);
        Spake2PlusKeyManager spakeKeyManagerServer = (Spake2PlusKeyManager) keyManagersServer[0];
        assertFalse(spakeKeyManagerServer.isClient());

        SSLContext contextServer = SSLContext.getInstance("TlsV1.3");
        contextServer.init(keyManagersServer, tmf.getTrustManagers(), null);
        return Pair.of(contextClient, contextServer);
    }

    private SSLContext createClientContext(PakeClientKeyManagerParameters clientParams)
            throws Exception {
        InetAddress hostC = TestUtils.getLoopbackAddress();

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
        tmf.init((ManagerFactoryParameters) null);

        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
        kmfClient.init(clientParams);
        KeyManager[] keyManagersClient = kmfClient.getKeyManagers();
        assertTrue(keyManagersClient.length == 1);
        assertTrue(keyManagersClient[0] instanceof Spake2PlusKeyManager);
        Spake2PlusKeyManager spake2PlusKeyManagerClient =
                (Spake2PlusKeyManager) keyManagersClient[0];
        assertTrue(spake2PlusKeyManagerClient.isClient());
        SSLContext contextClient = SSLContext.getInstance("TlsV1.3");
        contextClient.init(keyManagersClient, tmf.getTrustManagers(), null);
        return contextClient;
    }

    private SSLContext createServerContext(PakeServerKeyManagerParameters serverParams)
            throws Exception {
        InetAddress hostS = TestUtils.getLoopbackAddress();

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
        tmf.init((ManagerFactoryParameters) null);
        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
        kmfServer.init(serverParams);
        KeyManager[] keyManagersServer = kmfServer.getKeyManagers();
        assertTrue(keyManagersServer.length == 1);
        assertTrue(keyManagersServer[0] instanceof Spake2PlusKeyManager);
        Spake2PlusKeyManager spakeKeyManagerServer = (Spake2PlusKeyManager) keyManagersServer[0];
        assertFalse(spakeKeyManagerServer.isClient());

        SSLContext contextServer = SSLContext.getInstance("TlsV1.3");
        contextServer.init(keyManagersServer, tmf.getTrustManagers(), null);
        return contextServer;
    }

    private Pair<SSLSocket, SSLSocket> createSockets(Pair<SSLContext, SSLContext> contexts)
            throws Exception {
        InetAddress hostC = TestUtils.getLoopbackAddress();
        InetAddress hostS = TestUtils.getLoopbackAddress();
        SSLServerSocket serverSocket = (SSLServerSocket) contexts.getSecond()
                                               .getServerSocketFactory()
                                               .createServerSocket();
        serverSocket.bind(new InetSocketAddress(hostS, 0));
        SSLSocket client = (SSLSocket) contexts.getFirst().getSocketFactory().createSocket(
                hostC, serverSocket.getLocalPort());
        SSLSocket server = (SSLSocket) serverSocket.accept();

        assertTrue(client.getUseClientMode());
        return Pair.of(client, server);
    }

    private void connectSockets(Pair<SSLSocket, SSLSocket> sockets) throws Exception {
        SSLSocket client = sockets.getFirst();
        SSLSocket server = sockets.getSecond();
        Future<Void> s = runAsync(() -> {
            server.startHandshake();
            return null;
        });
        client.startHandshake();
        s.get();
    }

    private void sendData(Pair<SSLSocket, SSLSocket> sockets) throws Exception {
        SSLSocket client = sockets.getFirst();
        SSLSocket server = sockets.getSecond();
        byte[] readBytes = new byte[3];
        server.getOutputStream().write(new byte[] {1, 2, 3});
        client.getOutputStream().write(new byte[] {4, 5, 6});
        server.getInputStream().read(readBytes, 0, 3);
        assertArrayEquals(new byte[] {4, 5, 6}, readBytes);
        client.getInputStream().read(readBytes, 0, 3);
        assertArrayEquals(new byte[] {1, 2, 3}, readBytes);
    }

    private void closeSockets(Pair<SSLSocket, SSLSocket> sockets) throws Exception {
        sockets.getFirst().close();
        sockets.getSecond().close();
    }

    @Test
    public void testSpake2PlusPassword() throws Exception {
        byte[] password = new byte[] {1, 2, 3};

        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", password)
                                    .build();

        PakeClientKeyManagerParameters kmfParamsClient =
                new PakeClientKeyManagerParameters.Builder()
                        .setClientId(CLIENT_ID.clone())
                        .setServerId(SERVER_ID.clone())
                        .addOption(option)
                        .build();

        PakeServerKeyManagerParameters kmfParamsServer =
                new PakeServerKeyManagerParameters.Builder()
                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
                        .build();

        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);
        Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);

        connectSockets(sockets);
        sendData(sockets);
        closeSockets(sockets);
    }

    @Test
    public void testSpake2PlusPasswordMultipleConnections() throws Exception {
        byte[] password = new byte[] {1, 2, 3};

        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", password)
                                    .build();

        PakeClientKeyManagerParameters kmfParamsClient =
                new PakeClientKeyManagerParameters.Builder()
                        .setClientId(CLIENT_ID.clone())
                        .setServerId(SERVER_ID.clone())
                        .addOption(option)
                        .build();

        PakeServerKeyManagerParameters kmfParamsServer =
                new PakeServerKeyManagerParameters.Builder()
                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
                        .build();

        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);

        for (int i = 0; i < 10; i++) {
            Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);
            connectSockets(sockets);
            sendData(sockets);
            closeSockets(sockets);
        }
    }

    @Test
    public void testSpake2PlusPasswordHandshakeServerLimit() throws Exception {
        byte[] password = new byte[] {1, 2, 3};
        byte[] password2 = new byte[] {4, 5, 6};

        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", password)
                                    .addMessageComponent("server-handshake-limit", new byte[] {16})
                                    .addMessageComponent("client-handshake-limit", new byte[] {24})
                                    .build();
        PakeOption option2 = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                     .addMessageComponent("password", password2)
                                     .addMessageComponent("server-handshake-limit", new byte[] {16})
                                     .addMessageComponent("client-handshake-limit", new byte[] {24})
                                     .build();

        // Client uses wrong password first
        PakeClientKeyManagerParameters kmfParamsClient =
                new PakeClientKeyManagerParameters.Builder()
                        .setClientId(CLIENT_ID.clone())
                        .setServerId(SERVER_ID.clone())
                        .addOption(option2)
                        .build();

        PakeServerKeyManagerParameters kmfParamsServer =
                new PakeServerKeyManagerParameters.Builder()
                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
                        .build();

        Pair<SSLContext, SSLContext> failingContexts =
                createContexts(kmfParamsClient, kmfParamsServer);

        // Server handshake limit is 16, so it is ok if 15 connections fail.
        for (int i = 0; i < 15; i++) {
            Pair<SSLSocket, SSLSocket> sockets;
            sockets = createSockets(failingContexts);
            assertThrows(SSLHandshakeException.class, () -> connectSockets(sockets));
        }

        // 16th connection should succeed (but requires a new client)
        kmfParamsClient = new PakeClientKeyManagerParameters.Builder()
                                  .setClientId(CLIENT_ID.clone())
                                  .setServerId(SERVER_ID.clone())
                                  .addOption(option)
                                  .build();
        SSLContext workingClientContext = createClientContext(kmfParamsClient);
        Pair<SSLContext, SSLContext> workingContexts =
                Pair.of(workingClientContext, failingContexts.getSecond());
        Pair<SSLSocket, SSLSocket> workingSockets1 = createSockets(workingContexts);
        connectSockets(workingSockets1);
        sendData(workingSockets1);
        closeSockets(workingSockets1);

        // After one more failure, all connections should fail.
        Pair<SSLSocket, SSLSocket> failingSockets = createSockets(failingContexts);
        assertThrows(SSLHandshakeException.class, () -> connectSockets(failingSockets));
        Pair<SSLSocket, SSLSocket> workingSockets2 = createSockets(workingContexts);
        assertThrows(SSLHandshakeException.class, () -> connectSockets(workingSockets2));
    }

    @Test
    public void testSpake2PlusPasswordHandshakeClientLimit() throws Exception {
        byte[] password = new byte[] {1, 2, 3};
        byte[] password2 = new byte[] {4, 5, 6};

        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", password)
                                    .addMessageComponent("server-handshake-limit", new byte[] {24})
                                    .addMessageComponent("client-handshake-limit", new byte[] {16})
                                    .build();
        PakeOption option2 = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                     .addMessageComponent("password", password2)
                                     .addMessageComponent("server-handshake-limit", new byte[] {24})
                                     .addMessageComponent("client-handshake-limit", new byte[] {16})
                                     .build();

        PakeClientKeyManagerParameters kmfParamsClient =
                new PakeClientKeyManagerParameters.Builder()
                        .setClientId(CLIENT_ID.clone())
                        .setServerId(SERVER_ID.clone())
                        .addOption(option)
                        .build();

        // Server uses wrong password first
        PakeServerKeyManagerParameters kmfParamsServer =
                new PakeServerKeyManagerParameters.Builder()
                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option2))
                        .build();

        Pair<SSLContext, SSLContext> failingContexts =
                createContexts(kmfParamsClient, kmfParamsServer);

        // Server handshake limit is 16, so it is ok if 15 connections fail.
        for (int i = 0; i < 15; i++) {
            Pair<SSLSocket, SSLSocket> sockets;
            sockets = createSockets(failingContexts);
            assertThrows(SSLHandshakeException.class, () -> connectSockets(sockets));
        }

        // 16th connection should succeed (but requires a new server)
        kmfParamsServer =
                new PakeServerKeyManagerParameters.Builder()
                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
                        .build();
        SSLContext workingServerContext = createServerContext(kmfParamsServer);
        Pair<SSLContext, SSLContext> workingContexts =
                Pair.of(failingContexts.getFirst(), workingServerContext);
        Pair<SSLSocket, SSLSocket> workingSockets1 = createSockets(workingContexts);
        connectSockets(workingSockets1);
        sendData(workingSockets1);
        closeSockets(workingSockets1);

        // After one more failure, all connections should fail.
        Pair<SSLSocket, SSLSocket> failingSockets = createSockets(failingContexts);
        assertThrows(SSLHandshakeException.class, () -> connectSockets(failingSockets));
        Pair<SSLSocket, SSLSocket> workingSockets2 = createSockets(workingContexts);
        assertThrows(SSLHandshakeException.class, () -> connectSockets(workingSockets2));
    }

    @Test
    public void testSpake2PlusMismatchedPassword() throws Exception {
        byte[] password = new byte[] {1, 2, 3};
        byte[] password2 = new byte[] {4, 5, 6};

        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", password)
                                    .build();
        PakeOption option2 = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                     .addMessageComponent("password", password2)
                                     .build();

        PakeClientKeyManagerParameters kmfParamsClient =
                new PakeClientKeyManagerParameters.Builder()
                        .setClientId(CLIENT_ID.clone())
                        .setServerId(SERVER_ID.clone())
                        .addOption(option)
                        .build();

        PakeServerKeyManagerParameters kmfParamsServer =
                new PakeServerKeyManagerParameters.Builder()
                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option2))
                        .build();

        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);
        Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);

        assertThrows(SSLHandshakeException.class, () -> connectSockets(sockets));
        closeSockets(sockets);
    }

    @Test
    public void testSpake2PlusMismatchedIds() throws Exception {
        byte[] password = new byte[] {1, 2, 3};

        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", password)
                                    .build();
        PakeOption option2 = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                     .addMessageComponent("password", password)
                                     .build();

        // Client ID is different from the one in the server.
        PakeClientKeyManagerParameters kmfParamsClient =
                new PakeClientKeyManagerParameters.Builder()
                        .setClientId(new byte[] {6})
                        .setServerId(SERVER_ID.clone())
                        .addOption(option)
                        .build();

        PakeServerKeyManagerParameters kmfParamsServer =
                new PakeServerKeyManagerParameters.Builder()
                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option2))
                        .build();

        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);
        Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);

        assertThrows(SSLHandshakeException.class, () -> connectSockets(sockets));
        closeSockets(sockets);
    }

    @Test
    public void testSpake2PlusEmptyIds() throws Exception {
        byte[] password = new byte[] {1, 2, 3};

        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", password)
                                    .build();
        PakeOption option2 = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                     .addMessageComponent("password", password)
                                     .build();

        PakeClientKeyManagerParameters kmfParamsClient =
                new PakeClientKeyManagerParameters.Builder()
                        .setClientId(new byte[0])
                        .setServerId(new byte[0])
                        .addOption(option)
                        .build();

        PakeServerKeyManagerParameters kmfParamsServer =
                new PakeServerKeyManagerParameters.Builder()
                        .setOptions(new byte[0], new byte[0], Arrays.asList(option2))
                        .build();

        Pair<SSLContext, SSLContext> contexts = createContexts(kmfParamsClient, kmfParamsServer);
        Pair<SSLSocket, SSLSocket> sockets = createSockets(contexts);

        connectSockets(sockets);
        sendData(sockets);
        closeSockets(sockets);
    }

    @Test
    public void testSpake2PlusAndOthersInvalid() throws Exception {
        byte[] password = new byte[] {1, 2, 3};

        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", password)
                                    .build();

        PakeClientKeyManagerParameters pakeParams = new PakeClientKeyManagerParameters.Builder()
                                                            .setClientId(CLIENT_ID.clone())
                                                            .setServerId(SERVER_ID.clone())
                                                            .addOption(option)
                                                            .build();

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PAKE");
        kmf.init(pakeParams);

        KeyManager[] keyManagers = kmf.getKeyManagers();

        KeyManagerFactory kmf2 =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf2.init(null, null);

        // Add a x509 key manager to the array.
        KeyManager[] keyManagersWithx509 = Arrays.copyOf(keyManagers, keyManagers.length + 1);

        keyManagersWithx509[keyManagers.length] = kmf2.getKeyManagers()[0];

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
        tmf.init((ManagerFactoryParameters) null);
        TrustManager[] trustManagers = tmf.getTrustManagers();

        SSLContext sslContext = SSLContext.getInstance("TlsV1.3");
        // Should throw due to both SPAKE and x509 key managers
        assertThrows(KeyManagementException.class,
                () -> sslContext.init(keyManagersWithx509, trustManagers, null));
    }

    @Test
    public void testSpake2PlusNoTrustOrKeyInvalid() throws Exception {
        byte[] password = new byte[] {1, 2, 3};

        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", password)
                                    .build();

        PakeClientKeyManagerParameters pakeParams = new PakeClientKeyManagerParameters.Builder()
                                                            .setClientId(CLIENT_ID.clone())
                                                            .setServerId(SERVER_ID.clone())
                                                            .addOption(option)
                                                            .build();

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PAKE");
        kmf.init(pakeParams);

        KeyManager[] keyManagers = kmf.getKeyManagers();

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
        tmf.init((ManagerFactoryParameters) null);
        TrustManager[] trustManagers = tmf.getTrustManagers();

        SSLContext sslContext = SSLContext.getInstance("TlsV1.3");
        assertThrows(KeyManagementException.class, () -> sslContext.init(keyManagers, null, null));

        assertThrows(
                KeyManagementException.class, () -> sslContext.init(null, trustManagers, null));
    }

    private <T> Future<T> runAsync(Callable<T> callable) {
        return executor.submit(callable);
    }
}
