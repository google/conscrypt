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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.KeyStoreException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

@RunWith(JUnit4.class)
public class PakeKeyManagerFactoryTest {
    @Test
    public void pakeKeyManagerFactoryTest() throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PAKE");
        assertThrows(KeyStoreException.class, () -> kmf.init(null, null));
        byte[] password = new byte[] {1, 2, 3};
        byte[] clientId = new byte[] {2, 3, 4};
        byte[] serverId = new byte[] {4, 5, 6};
        PakeOption option =
                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                        .addMessageComponent("password", password)
                        .build();

        PakeClientKeyManagerParameters params =
                new PakeClientKeyManagerParameters.Builder()
                        .setClientId(clientId.clone())
                        .setServerId(serverId.clone())
                        .addOption(option)
                        .build();
        kmf.init(params);

        KeyManager[] keyManagers = kmf.getKeyManagers();
        assertEquals(1, keyManagers.length);

        Spake2PlusKeyManager keyManager = (Spake2PlusKeyManager) keyManagers[0];
        assertArrayEquals(password, keyManager.getPassword());
        assertArrayEquals(clientId, keyManager.getIdProver());
        assertArrayEquals(serverId, keyManager.getIdVerifier());
    }
}
