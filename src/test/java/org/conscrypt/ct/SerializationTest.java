/*
 * Copyright (C) 2015 The Android Open Source Project
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

package org.conscrypt.ct;

import junit.framework.TestCase;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class SerializationTest extends TestCase {
    public void test_decode_SignedCertificateTimestamp() throws Exception {
        byte[] in = new byte[] {
            0x00,                            // version
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // log id
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0x01, 0x02, 0x03, 0x04,          // timestamp
            0x05, 0x06, 0x07, 0x08,
            0x00, 0x00,                      // extensions length
            0x04, 0x03,                      // hash & signature algorithm
            0x00, 0x04,                      // signature length
            0x12, 0x34, 0x56, 0x78           // signature
        };

        SignedCertificateTimestamp sct
            = SignedCertificateTimestamp.decode(in, SignedCertificateTimestamp.Origin.EMBEDDED);

        assertEquals(SignedCertificateTimestamp.Version.V1, sct.getVersion());
        assertEquals(0x0102030405060708L, sct.getTimestamp());
        assertEquals(0, sct.getExtensions().length);
        assertEquals(DigitallySigned.HashAlgorithm.SHA256,
                     sct.getSignature().getHashAlgorithm());
        assertEquals(DigitallySigned.SignatureAlgorithm.ECDSA,
                     sct.getSignature().getSignatureAlgorithm());
        assertTrue(Arrays.equals(new byte[] { 0x12, 0x34, 0x56, 0x78},
                     sct.getSignature().getSignature()));
        assertEquals(SignedCertificateTimestamp.Origin.EMBEDDED, sct.getOrigin());
    }

    public void test_decode_invalid_SignedCertificateTimestamp() throws Exception {
        byte[] sct = new byte[] {
            0x00,                            // version
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // log id
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0x01, 0x02, 0x03, 0x04,          // timestamp
            0x05, 0x06, 0x07, 0x08,
            0x00, 0x00,                      // extensions length
            0x04, 0x03,                      // hash & signature algorithm
            0x00, 0x04,                      // signature length
            0x12, 0x34, 0x56, 0x78           // signature
        };

        // Make sure the original decodes fine
        SignedCertificateTimestamp.decode(sct, SignedCertificateTimestamp.Origin.EMBEDDED);

        // Perform various modification to it, and make sure it throws an exception on decoding
        try {
            byte[] in = sct.clone();
            in[0] = 1; // Modify version field
            SignedCertificateTimestamp.decode(in, SignedCertificateTimestamp.Origin.EMBEDDED);
            fail("SerializationException not thrown on unsupported version");
        } catch (SerializationException e) {}

        try {
            byte[] in = sct.clone();
            in[41] = 1; // Modify extensions lemgth
            SignedCertificateTimestamp.decode(in, SignedCertificateTimestamp.Origin.EMBEDDED);
            fail("SerializationException not thrown on invalid extensions length");
        } catch (SerializationException e) {}
    }

    public void test_decode_DigitallySigned() throws Exception {
        byte[] in = new byte[] {
            0x04, 0x03,            // hash & signature algorithm
            0x00, 0x04,            // signature length
            0x12, 0x34, 0x56, 0x78 // signature
        };

        DigitallySigned dst = DigitallySigned.decode(in);
        assertEquals(DigitallySigned.HashAlgorithm.SHA256, dst.getHashAlgorithm());
        assertEquals(DigitallySigned.SignatureAlgorithm.ECDSA, dst.getSignatureAlgorithm());
        assertEqualByteArrays(new byte[] { 0x12, 0x34, 0x56, 0x78}, dst.getSignature());
    }

    public void test_decode_invalid_DigitallySigned() throws Exception {
        try {
            DigitallySigned.decode(new byte[] {
                0x07, 0x03,            // hash & signature algorithm
                0x00, 0x04,            // signature length
                0x12, 0x34, 0x56, 0x78 // signature
            });
            fail("SerializationException not thrown on invalid hash type");
        } catch (SerializationException e) {}

        try {
            DigitallySigned.decode(new byte[] {
                0x04, 0x04,            // hash & signature algorithm
                0x00, 0x04,            // signature length
                0x12, 0x34, 0x56, 0x78 // signature
            });
            fail("SerializationException not thrown on invalid signature type");
        } catch (SerializationException e) {}

        try {
            DigitallySigned.decode(new byte[] {
                0x07, 0x03,            // hash & signature algorithm
                0x64, 0x35,            // signature length
                0x12, 0x34, 0x56, 0x78 // signature
            });
            fail("SerializationException not thrown on invalid signature length");
        } catch (SerializationException e) {}

        try {
            DigitallySigned.decode(new byte[] {
                0x07, 0x03,            // hash & signature algorithm
            });
            fail("SerializationException not thrown on missing signature");
        } catch (SerializationException e) {}
    }

    public void test_encode_CertificateEntry_X509Certificate() throws Exception {
        // Use a dummy certificate. It doesn't matter, CertificateEntry doesn't care about the contents.
        CertificateEntry entry = CertificateEntry.createForX509Certificate(new byte[] { 0x12, 0x34, 0x56, 0x78 });
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        entry.encode(output);

        assertEqualByteArrays(new byte[] {
            0x00, 0x00,            // entry_type
            0x00, 0x00, 0x04,      // x509_entry length
            0x12, 0x34, 0x56, 0x78 // x509_entry
        }, output.toByteArray());
    }

    public void test_encode_CertificateEntry_PreCertificate() throws Exception {
        // Use a dummy certificate and issuer key hash. It doesn't matter,
        // CertificateEntry doesn't care about the contents.
        CertificateEntry entry = CertificateEntry.createForPrecertificate(new byte[] { 0x12, 0x34, 0x56, 0x78 },
                                                          new byte[32]);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        entry.encode(output);

        assertEqualByteArrays(new byte[] {
            0x00, 0x01,                      // entry_type
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // issuer key hash
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0x00, 0x00, 0x04,                // precert_entry length
            0x12, 0x34, 0x56, 0x78           // precert_entry
        }, output.toByteArray());
    }

    public void test_readDEROctetString() throws Exception {
        byte[] in, expected;

        in = new byte[] {
            0x04, // TAG
            0x06, // length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x05 // data
        };
        expected = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x05 };
        assertEqualByteArrays(expected, Serialization.readDEROctetString(in));

        in = new byte[203];
        in[0] = 0x04; // TAG
        in[1] = (byte)0x81; // long length flag
        in[2] = (byte)200; // length
        in[3] = 0x45; // data, the rest is just zeros

        expected = new byte[200];
        expected[0] = 0x45;
        assertEqualByteArrays(expected, Serialization.readDEROctetString(in));

        try {
            in = new byte[] {
                0x12, // wrong tag
                0x06, // length
                0x01, 0x02, 0x03, 0x04, 0x05, 0x05 // data
            };
            Serialization.readDEROctetString(in);
            fail("SerializationException not thrown on invalid tag.");
        } catch (SerializationException e) {}

        try {
            in = new byte[] {
                0x04, // wrong tag
                0x06, // length
                0x01, 0x02 // data
            };
            Serialization.readDEROctetString(in);
            fail("SerializationException not thrown on invalid length.");
        } catch (SerializationException e) {}
    }

    public static void assertEqualByteArrays(byte[] expected, byte[] actual) {
        assertEquals(Arrays.toString(expected), Arrays.toString(actual));
    }
}

