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

import static org.conscrypt.TestUtils.openTestFile;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class OpenSSLX509CertificateTest {
  @Test
    public void testSerialization_NoContextDeserialization() throws Exception {
      // TODO(prb): Re-work avoiding reflection for Java 17+
      assumeFalse(TestUtils.isJavaVersion(17));
        // Set correct serialVersionUID
        {
            ObjectStreamClass clDesc = ObjectStreamClass.lookup(OpenSSLX509Certificate.class);
            assertNotNull(clDesc);

            // Set our fake class's serialization UID.
            Field targetUID = ZpenSSLX509Certificate.class.getDeclaredField("serialVersionUID");
            targetUID.setAccessible(true);

            // Mark the field as non-final on JVM that need it.
            try {
                Field modifiersField = null;
                try {
                    modifiersField = Field.class.getDeclaredField("modifiers");
                } catch (NoSuchFieldException e) {
                    try {
                        Method getDeclaredFields0 = Class.class.getDeclaredMethod("getDeclaredFields0", boolean.class);
                        getDeclaredFields0.setAccessible(true);
                        Field[] fields = (Field[]) getDeclaredFields0.invoke(Field.class, false);
                        for (Field field : fields) {
                            if ("modifiers".equals(field.getName())) {
                                modifiersField = field;
                                break;
                            }
                        }
                    } catch (NoSuchMethodException | InvocationTargetException ignored) {
                    }
                }
                if (modifiersField != null) {
                    modifiersField.setAccessible(true);
                    modifiersField.setInt(targetUID, targetUID.getModifiers() & ~Modifier.FINAL);
                }
            } catch (Exception ignored) {
            }

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

    static final String CT_POISON_EXTENSION = "1.3.6.1.4.1.11129.2.4.3";

    private OpenSSLX509Certificate loadTestCertificate(String name)
            throws FileNotFoundException, ParsingException {
        return OpenSSLX509Certificate.fromX509PemInputStream(openTestFile(name));
    }

    @Test
    public void test_deletingCTPoisonExtension() throws Exception {
        /* certPoisoned has an extra poison extension.
         * With the extension, the certificates have different TBS.
         * Without it, the certificates should have the same TBS.
         */
        OpenSSLX509Certificate cert = loadTestCertificate("cert.pem");
        OpenSSLX509Certificate certPoisoned = loadTestCertificate("cert-ct-poisoned.pem");

        assertFalse(Arrays.equals(
                certPoisoned.getTBSCertificate(),
                cert.getTBSCertificate()));

        assertTrue(Arrays.equals(
                certPoisoned.getTBSCertificateWithoutExtension(CT_POISON_EXTENSION),
                cert.getTBSCertificate()));
    }

    @Test
    public void test_deletingExtensionMakesCopy() throws Exception {
        /* Calling getTBSCertificateWithoutExtension should not modify the original certificate.
         * Make sure the extension is still present in the original object.
         */
        OpenSSLX509Certificate certPoisoned = loadTestCertificate("cert-ct-poisoned.pem");
        assertTrue(certPoisoned.getCriticalExtensionOIDs().contains(CT_POISON_EXTENSION));

        certPoisoned.getTBSCertificateWithoutExtension(CT_POISON_EXTENSION);
        assertTrue(certPoisoned.getCriticalExtensionOIDs().contains(CT_POISON_EXTENSION));
    }

    @Test
    public void test_deletingMissingExtension() throws Exception {
        /* getTBSCertificateWithoutExtension should throw on a certificate without the extension.
         */
        OpenSSLX509Certificate cert = loadTestCertificate("cert.pem");
        assertFalse(cert.getCriticalExtensionOIDs().contains(CT_POISON_EXTENSION));

        try {
            cert.getTBSCertificateWithoutExtension(CT_POISON_EXTENSION);
            fail();
        } catch (IllegalArgumentException expected) {
        }
    }
}
