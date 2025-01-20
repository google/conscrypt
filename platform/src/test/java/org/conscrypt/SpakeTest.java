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

@RunWith(JUnit4.class)
public class SpakeTest {
    private static final byte[] CLIENT_ID = new byte[] {4, 5, 6};
    private static final byte[] SERVER_ID = new byte[] {7, 8, 9};
    private final ThreadGroup threadGroup = new ThreadGroup("SpakeTest");
    private final ExecutorService executor =
            Executors.newCachedThreadPool(t -> new Thread(threadGroup, t));

    @Test
    public void testSpake2Plus() throws Exception {
        InetAddress hostC = TestUtils.getLoopbackAddress();
        InetAddress hostS = TestUtils.getLoopbackAddress();

        byte[] password = new byte[] {1, 2, 3};

        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", password)
                                    .build();

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PAKE");
        tmf.init((ManagerFactoryParameters) null);

        PakeClientKeyManagerParameters kmfParamsClient =
                new PakeClientKeyManagerParameters.Builder()
                        .setClientId(CLIENT_ID.clone())
                        .setServerId(SERVER_ID.clone())
                        .addOption(option)
                        .build();

        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
        kmfClient.init(kmfParamsClient);
        KeyManager[] keyManagersClient = kmfClient.getKeyManagers();
        assertTrue(keyManagersClient.length == 1);
        assertTrue(keyManagersClient[0] instanceof Spake2PlusKeyManager);
        Spake2PlusKeyManager spake2PlusKeyManagerClient =
                (Spake2PlusKeyManager) keyManagersClient[0];
        assertTrue(spake2PlusKeyManagerClient.isClient());

        SSLContext contextClient = SSLContext.getInstance("TlsV1.3");
        contextClient.init(keyManagersClient, tmf.getTrustManagers(), null);

        PakeServerKeyManagerParameters kmfParamsServer =
                new PakeServerKeyManagerParameters.Builder()
                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
                        .build();

        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
        kmfServer.init(kmfParamsServer);
        KeyManager[] keyManagersServer = kmfServer.getKeyManagers();
        assertTrue(keyManagersServer.length == 1);
        assertTrue(keyManagersServer[0] instanceof Spake2PlusKeyManager);
        Spake2PlusKeyManager spakeKeyManagerServer = (Spake2PlusKeyManager) keyManagersServer[0];
        assertFalse(spakeKeyManagerServer.isClient());

        SSLContext contextServer = SSLContext.getInstance("TlsV1.3");
        contextServer.init(keyManagersServer, tmf.getTrustManagers(), null);

        SSLServerSocket serverSocket =
                (SSLServerSocket) contextServer.getServerSocketFactory().createServerSocket();
        serverSocket.bind(new InetSocketAddress(hostS, 0));
        SSLSocket client = (SSLSocket) contextClient.getSocketFactory().createSocket(
                hostC, serverSocket.getLocalPort());
        SSLSocket server = (SSLSocket) serverSocket.accept();

        assertTrue(client.getUseClientMode());
        Future<Void> s = runAsync(() -> {
            server.startHandshake();
            return null;
        });
        try {
            client.startHandshake();
            s.get();
            fail();
        } catch (SSLHandshakeException e) {
            // Expected
        }
        server.close();
        client.close();
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