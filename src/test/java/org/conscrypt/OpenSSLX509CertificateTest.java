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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.Field;
import java.util.Arrays;
import junit.framework.TestCase;
import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;

import static org.conscrypt.TestUtils.openTestFile;

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

    static final String CT_POISON_EXTENSION = "1.3.6.1.4.1.11129.2.4.3";

    private OpenSSLX509Certificate loadTestCertificate(String name)
            throws FileNotFoundException, ParsingException {
        return OpenSSLX509Certificate.fromX509PemInputStream(openTestFile(name));
    }

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
                certPoisoned.withDeletedExtension(CT_POISON_EXTENSION).getTBSCertificate(),
                cert.getTBSCertificate()));
    }

    public void test_deletingExtensionMakesCopy() throws Exception {
        /* Calling withDeletedExtension should not modify the original certificate, only make a copy.
         * Make sure the extension is still present in the original object.
         */
        OpenSSLX509Certificate certPoisoned = loadTestCertificate("cert-ct-poisoned.pem");
        assertTrue(certPoisoned.getCriticalExtensionOIDs().contains(CT_POISON_EXTENSION));

        OpenSSLX509Certificate certWithoutExtension = certPoisoned.withDeletedExtension(CT_POISON_EXTENSION);

        assertTrue(certPoisoned.getCriticalExtensionOIDs().contains(CT_POISON_EXTENSION));
        assertFalse(certWithoutExtension.getCriticalExtensionOIDs().contains(CT_POISON_EXTENSION));
    }

    public void test_deletingMissingExtension() throws Exception {
        /* withDeletedExtension should be safe to call on a certificate without the extension, and
         * return an identical copy.
         */
        OpenSSLX509Certificate cert = loadTestCertificate("cert.pem");
        assertFalse(cert.getCriticalExtensionOIDs().contains(CT_POISON_EXTENSION));

        OpenSSLX509Certificate cert2 = cert.withDeletedExtension(CT_POISON_EXTENSION);
        assertEquals(cert, cert2);
    }
}
