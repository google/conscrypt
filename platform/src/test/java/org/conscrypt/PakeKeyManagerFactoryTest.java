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
import static org.junit.Assert.assertThrows;

import android.net.ssl.PakeClientKeyManagerParameters;
import android.net.ssl.PakeOption;
import android.net.ssl.PakeServerKeyManagerParameters;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.KeyStoreException;
import java.util.Arrays;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

@RunWith(JUnit4.class)
public class PakeKeyManagerFactoryTest {
    private static final byte[] PASSWORD = new byte[] {1, 2, 3};
    private static final byte[] CLIENT_ID = new byte[] {2, 3, 4};
    private static final byte[] SERVER_ID = new byte[] {4, 5, 6};

    @Test
    public void pakeKeyManagerFactoryTest() throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PAKE");
        assertThrows(KeyStoreException.class, () -> kmf.init(null, null));
        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", PASSWORD)
                                    .build();

        PakeClientKeyManagerParameters params = new PakeClientKeyManagerParameters.Builder()
                                                        .setClientId(CLIENT_ID.clone())
                                                        .setServerId(SERVER_ID.clone())
                                                        .addOption(option)
                                                        .build();
        kmf.init(params);

        KeyManager[] keyManagers = kmf.getKeyManagers();
        assertEquals(1, keyManagers.length);

        Spake2PlusKeyManager keyManager = (Spake2PlusKeyManager) keyManagers[0];
        assertArrayEquals(PASSWORD, keyManager.getPassword());
        assertArrayEquals(CLIENT_ID, keyManager.getIdProver());
        assertArrayEquals(SERVER_ID, keyManager.getIdVerifier());
    }

    @Test
    public void pakeKeyManagerFactoryTestHanshakeLimitClient() throws Exception {
        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", PASSWORD)
                                    .addMessageComponent("client-handshake-limit", new byte[] {16})
                                    .build();

        // Client
        PakeClientKeyManagerParameters paramsClient = new PakeClientKeyManagerParameters.Builder()
                                                              .setClientId(CLIENT_ID.clone())
                                                              .setServerId(SERVER_ID.clone())
                                                              .addOption(option)
                                                              .build();
        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
        kmfClient.init(paramsClient);

        Spake2PlusKeyManager keyManagerClient =
                (Spake2PlusKeyManager) kmfClient.getKeyManagers()[0];
        assertArrayEquals(PASSWORD, keyManagerClient.getPassword());
        assertArrayEquals(CLIENT_ID, keyManagerClient.getIdProver());
        assertArrayEquals(SERVER_ID, keyManagerClient.getIdVerifier());
        assertEquals(16, keyManagerClient.getHandshakeLimit());

        // Server
        PakeServerKeyManagerParameters paramsServer =
                new PakeServerKeyManagerParameters.Builder()
                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
                        .build();
        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
        kmfServer.init(paramsServer);

        Spake2PlusKeyManager keyManagerServer =
                (Spake2PlusKeyManager) kmfServer.getKeyManagers()[0];
        assertArrayEquals(PASSWORD, keyManagerServer.getPassword());
        assertArrayEquals(CLIENT_ID, keyManagerServer.getIdProver());
        assertArrayEquals(SERVER_ID, keyManagerServer.getIdVerifier());
        assertEquals(1, keyManagerServer.getHandshakeLimit());
    }

    @Test
    public void pakeKeyManagerFactoryTestHanshakeLimitServer() throws Exception {
        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", PASSWORD)
                                    .addMessageComponent("server-handshake-limit", new byte[] {16})
                                    .build();

        // Client
        PakeClientKeyManagerParameters paramsClient = new PakeClientKeyManagerParameters.Builder()
                                                              .setClientId(CLIENT_ID.clone())
                                                              .setServerId(SERVER_ID.clone())
                                                              .addOption(option)
                                                              .build();
        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("PAKE");
        kmfClient.init(paramsClient);

        Spake2PlusKeyManager keyManagerClient =
                (Spake2PlusKeyManager) kmfClient.getKeyManagers()[0];
        assertArrayEquals(PASSWORD, keyManagerClient.getPassword());
        assertArrayEquals(CLIENT_ID, keyManagerClient.getIdProver());
        assertArrayEquals(SERVER_ID, keyManagerClient.getIdVerifier());
        assertEquals(1, keyManagerClient.getHandshakeLimit());

        // Server
        PakeServerKeyManagerParameters paramsServer =
                new PakeServerKeyManagerParameters.Builder()
                        .setOptions(CLIENT_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
                        .build();
        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("PAKE");
        kmfServer.init(paramsServer);

        Spake2PlusKeyManager keyManagerServer =
                (Spake2PlusKeyManager) kmfServer.getKeyManagers()[0];
        assertArrayEquals(PASSWORD, keyManagerServer.getPassword());
        assertArrayEquals(CLIENT_ID, keyManagerServer.getIdProver());
        assertArrayEquals(SERVER_ID, keyManagerServer.getIdVerifier());
        assertEquals(16, keyManagerServer.getHandshakeLimit());
    }
}
