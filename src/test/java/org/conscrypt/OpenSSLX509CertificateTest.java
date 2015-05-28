/*
 * Copyright 2015 The Android Open Source Project
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.Field;

import junit.framework.TestCase;

public class OpenSSLX509CertificateTest extends TestCase {
    public void testSerialization_NoContextDeserialization() throws Exception {
        // Set correct serialVersionUID
        {
            ObjectStreamClass clDesc = ObjectStreamClass.lookup(OpenSSLX509Certificate.class);
            assertNotNull(clDesc);

            // Set our fake class's serialization UID.
            Field targetUID = ZpenSSLX509Certificate.class.getDeclaredField("serialVersionUID");
            targetUID.setAccessible(true);
            targetUID.set(null, clDesc.getSerialVersionUID());
        }

        final byte[] impostorBytes;
        // Serialization
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(new ZpenSSLX509Certificate(0xA5A5A5A5A5A5A5A5L));
            oos.close();
            impostorBytes = baos.toByteArray();
        }

        // Fix class name
        {
            boolean fixed = false;
            for (int i = 0; i < impostorBytes.length - 4; i++) {
                if (impostorBytes[i] == 'Z' && impostorBytes[i + 1] == 'p'
                        && impostorBytes[i + 2] == 'e' && impostorBytes[i + 3] == 'n') {
                    impostorBytes[i] = 'O';
                    fixed = true;
                    break;
                }
            }
            assertTrue(fixed);
        }

        // Deserialization
        {
            ByteArrayInputStream bais = new ByteArrayInputStream(impostorBytes);
            ObjectInputStream ois = new ObjectInputStream(bais);
            OpenSSLX509Certificate cert = (OpenSSLX509Certificate) ois.readObject();
            ois.close();
            assertEquals(0L, cert.getContext());
        }
    }
}
