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

import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

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
                        Method getDeclaredFields0 =
                                Class.class.getDeclaredMethod("getDeclaredFields0", boolean.class);
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
    public void toString_printsCertificate() throws Exception {
        String expectedToString = "Certificate:\n"
                + "    Data:\n"
                + "        Version: 3 (0x2)\n"
                + "        Serial Number: 7 (0x7)\n"
                + "    Signature Algorithm: sha1WithRSAEncryption\n"
                + "        Issuer: C=GB, O=Certificate Transparency CA, ST=Wales, L=Erw Wen\n"
                + "        Validity\n"
                + "            Not Before: Jun  1 00:00:00 2012 GMT\n"
                + "            Not After : Jun  1 00:00:00 2022 GMT\n"
                + "        Subject: C=GB, O=Certificate Transparency, ST=Wales, L=Erw Wen\n"
                + "        Subject Public Key Info:\n"
                + "            Public Key Algorithm: rsaEncryption\n"
                + "                Public-Key: (1024 bit)\n"
                + "                Modulus:\n"
                + "                    00:be:ef:98:e7:c2:68:77:ae:38:5f:75:32:5a:0c:\n"
                + "                    1d:32:9b:ed:f1:8f:aa:f4:d7:96:bf:04:7e:b7:e1:\n"
                + "                    ce:15:c9:5b:a2:f8:0e:e4:58:bd:7d:b8:6f:8a:4b:\n"
                + "                    25:21:91:a7:9b:d7:00:c3:8e:9c:03:89:b4:5c:d4:\n"
                + "                    dc:9a:12:0a:b2:1e:0c:b4:1c:d0:e7:28:05:a4:10:\n"
                + "                    cd:9c:5b:db:5d:49:27:72:6d:af:17:10:f6:01:87:\n"
                + "                    37:7e:a2:5b:1a:1e:39:ee:d0:b8:81:19:dc:15:4d:\n"
                + "                    c6:8f:7d:a8:e3:0c:af:15:8a:33:e6:c9:50:9f:4a:\n"
                + "                    05:b0:14:09:ff:5d:d8:7e:b5\n"
                + "                Exponent: 65537 (0x10001)\n"
                + "        X509v3 extensions:\n"
                + "            X509v3 Subject Key Identifier:\n"
                + "                20:31:54:1A:F2:5C:05:FF:D8:65:8B:68:43:79:4F:5E:90:36:F7:B4\n"
                + "            X509v3 Authority Key Identifier:\n"
                + "                "
                  + "keyid:5F:9D:88:0D:C8:73:E6:54:D4:F8:0D:D8:E6:B0:C1:24:B4:47:C3:55\n"
                + "                DirName:/C=GB/O=Certificate Transparency CA/ST=Wales/L=Erw Wen\n"
                + "                serial:0\n"
                + "\n"
                + "            X509v3 Basic Constraints:\n"
                + "                CA:FALSE\n"
                + "    Signature Algorithm: sha1WithRSAEncryption\n"
                + "         04:59:00:c8:0d:db:36:35:30:ed:e3:24:8e:e9:f0:ed:85:45:\n"
                + "         e8:05:ca:7e:2c:cd:62:a6:4e:9d:28:a8:02:f7:82:79:93:59:\n"
                + "         6d:6b:ff:f5:b2:5e:3f:3c:48:04:2a:7b:a4:e4:03:c7:f3:bc:\n"
                + "         e0:cc:6d:22:b7:c1:23:ba:b4:20:d9:23:65:1e:58:46:67:ce:\n"
                + "         80:99:94:82:c0:7b:e6:93:cc:fd:83:b1:d2:54:82:ad:ac:a3:\n"
                + "         9d:32:1a:c7:13:79:d6:eb:8f:4f:59:47:51:71:b1:a3:09:e6:\n"
                + "         82:f4:c4:f1:5a:ff:5c:18:2e:cd:a8:32:91:35:c1:96:5a:23:\n"
                + "         77:0e\n";
        OpenSSLX509Certificate cert = loadTestCertificate("cert.pem");
        assertEquals(expectedToString, cert.toString());
    }

    @Test
    public void test_deletingCTPoisonExtension() throws Exception {
        /* certPoisoned has an extra poison extension.
         * With the extension, the certificates have different TBS.
         * Without it, the certificates should have the same TBS.
         */
        OpenSSLX509Certificate cert = loadTestCertificate("cert.pem");
        OpenSSLX509Certificate certPoisoned = loadTestCertificate("cert-ct-poisoned.pem");

        assertFalse(Arrays.equals(certPoisoned.getTBSCertificate(), cert.getTBSCertificate()));

        assertTrue(
                Arrays.equals(certPoisoned.getTBSCertificateWithoutExtension(CT_POISON_EXTENSION),
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
