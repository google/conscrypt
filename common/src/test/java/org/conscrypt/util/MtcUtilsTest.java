/*
 * Copyright 2026 The Android Open Source Project
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

package org.conscrypt.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;

@RunWith(JUnit4.class)
public class MtcUtilsTest {
    // Valid MTC CA certificate (CA ID 32473.1, Subject RDN 1.3.6.1.4.1.44363.47.3=#0D0481FD5901,
    // critical extension 1.3.6.1.4.1.44363.47.4 with minSerial=0x1000000000000,
    // maxSerial=0x5ffffffffffff).
    private static final String VALID_MTC_CA_PEM = "-----BEGIN CERTIFICATE-----\n"
            + "MIIGADCCBe2gAwIBAgIBATAKBggrBgEFBQcGJDAQMQ4wDAYIKwYBBQUHGQEMADAe\n"
            + "Fw0yMDAxMDEwMDAwMDBaFw0zMDEyMzEyMzU5NTlaMBYxFDASBgorBgEEAYLaSy8D\n"
            + "DQSB/VkBMIIFMjALBglghkgBZQMEAxEDggUhAFzN/zgGMsaBJd+nNwxE0mZlxiSI\n"
            + "OIrZwLSScveu9rIIIPfYjTEvKetlhX1W5quTKhFrZqvMzskfSBqUqMuqMCcykhiC\n"
            + "5x5r4GVBvK2GCaP2sTCOM5kJ9hzwCevraUeClJhgDB8dRpYuJox68eNkNnfDsYTN\n"
            + "pfB1HUey8jfDhI9+tGmtHC7apuIEyeYyAMwYobBeCquk4ikCb04KoYQRWkhPSDnN\n"
            + "4XLfY+otOwXy4Ev96V6pK74UrTwHKSzMQPMTF0O8zsVJKgSSNfd1zJp+Tk/CHZDD\n"
            + "2+ZcFMzcU2BdAO0QiMb6O3BOLK5eg1ZFcX/abzQyNcBo3hfuvHlSTsOezgh3u4/x\n"
            + "q4zALLfVTcNQAqY0E6HTSrt+3K7MJhmRwQfr8IsyB+x8nAuesYGrzJbCzDq4Wmfu\n"
            + "R+LCOujNQNT26yBwTIbEUCCRQAz6htYICqmW8jD6hjLnlizUE1lTG2kp/lvtqJj8\n"
            + "AGu654MkUsxVOUAMP1LV3DTHq5RmhZd5oET63yQ/pj+CBzsZx9iJf3ovbNJ7LRGr\n"
            + "nMba9L85KTIjF9vtJKdiQp5Td7gyUlDhKeajvk4VJ6baQa1xuYxa6thcBt18E8Jx\n"
            + "OBvXO8qw+l3jOJnzZdDtnFg3TajfCb1OUZ5cpcEajPtT7IhgbGhKu1B8bcIynUy8\n"
            + "N6Wb99SBdBn8xbaWJOdsq++Yi45VVBdlCL/4psXG6hRoot4V21yUO9xQCQCXYsSI\n"
            + "EQwnUmOkoK82UQ3v0n5Z5K/KZhS6bIWc7zEAp5WU7DBAye8V+rSAoLvxeJE9uvMU\n"
            + "2twQDBVOQAfqVSpskzMZpypMdPPjnBUk0vUaOIih2UuCqLooT/yL54PXO3WHLPj0\n"
            + "G6XKmQ92ksFPyc7skwwnYSh2PDk879/m6i4/8s37i9e6T68O5oQWf7CMShV2z50w\n"
            + "Dkuy34hzHQzCtJ0HWdH73q31etKfIvR11ni7aWVmRGlmU8xXjMATrgJ3w9I8aVY4\n"
            + "M9LG0ykCJYhwZG74zr4WRTr/LEdr97H06D7TZKsBM/jdfHYKLu3VYciHAnwI7iAM\n"
            + "htR3cw9lMGs1NLKdYi12vWdSIiSH//1o6Foa+Yej9j+h4LbNn0orlEZMLBPx+bAf\n"
            + "OzYKIYegyAsxguFvDYDCIhOQ6ZuCD49RyXOKgcfgklFi2d3wiQSyPMAl8nGG1Hun\n"
            + "PdJWVRx4tPx+8/SY8TVcFiTciW/Itdy8uytslOR0h5fB5dQFWxJXaClRzlvOqHXA\n"
            + "bSthBETzCpMDkeRk4qg5MCmrTFepTeshtKC3cwRcPXQo0jys3VrVASLjQehcm7k1\n"
            + "hFXo9TkfBY5hYShjOYoekIuy3wI3dr+SeARSJre2VMxdyd6ZEtQrfaz0pbQaOIr5\n"
            + "CqcM7uyR/lycHlbnwsE2pKPubbFXev836BjfQItaIX2SExK/1rlbXs/rDAidw3Ts\n"
            + "c2XO2Lh8AfG5SPgcJeo3cOQhjhywqECjwcPsTl0CwHDqiW++8wyBGPTyl5niOYPu\n"
            + "VQhAF6wPYUQD8xBywy5QpgvRajWv7LZ0/wztQhkjSiAs453WwRn2WaDlXqAX3xjC\n"
            + "p7UC5NCoB02LCE1xzQa++plEg5uvdMPyFeGRxqmBmU0jUH4PeJyEQJXj0lj2/W+y\n"
            + "YyjbwO51qHyK6AuLyDexkLR2y/H2y+cG4LfRYpI4kmTTItPgzEqSbuhhEKIPZRGR\n"
            + "y5p/8IJvwTDmjQ3H9FwJH9yKBxIoDJIB+9wYkumo/GbvyZ2m1lAVsxI6WqajVzBV\n"
            + "MA4GA1UdDwEB/wQEAwICBDAPBgNVHRMBAf8EBTADAQH/MDIGCisGAQQBgtpLLwQB\n"
            + "Af8EITAfMAsGCWCGSAFlAwQDEQIHAQAAAAAAAAIHBf///////zAKBggrBgEFBQcG\n"
            + "JAMBAA==\n"
            + "-----END CERTIFICATE-----\n";

    private static X509Certificate parseCert(String pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testIsMtcCaCertificateAndExtractCaId() throws Exception {
        X509Certificate caCert = parseCert(VALID_MTC_CA_PEM);
        assertTrue(MtcUtils.isMtcCaCertificate(caCert));
        assertFalse(MtcUtils.hasMtcSignatureAlgorithm(caCert));

        TrustAnchor anchor = new TrustAnchor(caCert, null);
        byte[] expectedCaId = new byte[] {(byte) 0x81, (byte) 0xFD, 0x59, 0x01};
        assertArrayEquals(expectedCaId, MtcUtils.extractCaId(anchor));
        assertEquals("2.16.840.1.101.3.4.3.17", MtcUtils.extractCaSigAlg(anchor));

        byte[] expectedLogId0 = new byte[] {(byte) 0x81, (byte) 0xFD, 0x59, 0x01, 0x00, 0x00};
        assertArrayEquals(expectedLogId0, MtcUtils.getLogId(expectedCaId, 0));
        assertEquals("32473.1.0.0", DerUtils.formatRelativeOid(expectedLogId0));

        byte[] expectedLogId128 =
                new byte[] {(byte) 0x81, (byte) 0xFD, 0x59, 0x01, 0x00, (byte) 0x81, 0x00};
        assertArrayEquals(expectedLogId128, MtcUtils.getLogId(expectedCaId, 128));
        assertEquals("32473.1.0.128", DerUtils.formatRelativeOid(expectedLogId128));
    }

    @Test
    public void testValidateSerialInCaRange() throws Exception {
        X509Certificate caCert = parseCert(VALID_MTC_CA_PEM);
        TrustAnchor anchor = new TrustAnchor(caCert, null);

        // Exact minSerial (0x1000000000000) and maxSerial (0x5ffffffffffff) should succeed
        BigInteger minSerial = BigInteger.ONE.shiftLeft(48);
        BigInteger maxSerial = BigInteger.valueOf(6).shiftLeft(48).subtract(BigInteger.ONE);
        MtcUtils.validateSerialInCaRange(anchor, minSerial);
        MtcUtils.validateSerialInCaRange(anchor, maxSerial);

        // Below minSerial (0x1000000000000 - 1) and above maxSerial (0x6000000000000) must fail
        BigInteger belowMin = minSerial.subtract(BigInteger.ONE);
        BigInteger aboveMax = maxSerial.add(BigInteger.ONE);
        assertThrows(CertificateException.class,
                     () -> MtcUtils.validateSerialInCaRange(anchor, belowMin));
        assertThrows(CertificateException.class,
                     () -> MtcUtils.validateSerialInCaRange(anchor, aboveMax));
    }

    @Test
    public void testFindCaSignature_shortlexOrderingAndUniqueness() throws Exception {
        // cosigner_id for 32473.1 is 4 bytes: 81 fd 59 01
        byte[] cid1 = new byte[] {(byte) 0x81, (byte) 0xFD, 0x59, 0x01};
        // cosigner_id for 32473.2 is 4 bytes: 81 fd 59 02
        byte[] cid2 = new byte[] {(byte) 0x81, (byte) 0xFD, 0x59, 0x02};
        // cosigner_id for 32473.2.3 is 5 bytes: 81 fd 59 02 03
        byte[] cid3 = new byte[] {(byte) 0x81, (byte) 0xFD, 0x59, 0x02, 0x03};

        byte[] sig1 = new byte[] {0x11, 0x22};
        byte[] sig2 = new byte[] {0x33, 0x44};
        byte[] sig3 = new byte[] {0x55, 0x66};

        // Valid shortlex order: cid1 (4B) < cid2 (4B) < cid3 (5B)
        byte[] validSigs =
                packSignatures(new byte[][] {cid1, cid2, cid3}, new byte[][] {sig1, sig2, sig3});
        assertArrayEquals(sig1, MtcUtils.findCaSignature(validSigs, cid1));
        assertArrayEquals(sig2, MtcUtils.findCaSignature(validSigs, cid2));

        // Duplicate cosigner_id after matched entry must still be rejected
        byte[] duplicateAfterMatch =
                packSignatures(new byte[][] {cid1, cid2, cid2}, new byte[][] {sig1, sig2, sig3});
        assertThrows(CertificateException.class,
                     () -> MtcUtils.findCaSignature(duplicateAfterMatch, cid1));

        // Out-of-order cosigner_id (5-byte cid3 before 4-byte cid2) must be rejected
        byte[] outOfOrder =
                packSignatures(new byte[][] {cid1, cid3, cid2}, new byte[][] {sig1, sig3, sig2});
        assertThrows(CertificateException.class, () -> MtcUtils.findCaSignature(outOfOrder, cid1));

        // Empty cosigner_id must be rejected
        byte[] emptyCid = packSignatures(new byte[][] {new byte[0]}, new byte[][] {sig1});
        assertThrows(CertificateException.class, () -> MtcUtils.findCaSignature(emptyCid, cid1));
    }

    @Test
    public void testIsValidSubtree() {
        // Valid full power-of-two subtrees
        assertTrue(MtcUtils.isValidSubtree(0, 8));
        assertTrue(MtcUtils.isValidSubtree(8, 16));
        assertTrue(MtcUtils.isValidSubtree(0, 1L << 48));

        // Valid empty subtree (start == end) and partial subtree (start % 2^n == 0)
        assertTrue(MtcUtils.isValidSubtree(8, 8));
        assertTrue(MtcUtils.isValidSubtree(0, 10));

        // Invalid bounds: start < 0, start > end, end > 2^48, or unaligned [2, 6)
        assertFalse(MtcUtils.isValidSubtree(-1, 8));
        assertFalse(MtcUtils.isValidSubtree(8, 4));
        assertFalse(MtcUtils.isValidSubtree(0, (1L << 48) + 1));
        assertFalse(MtcUtils.isValidSubtree(2, 6));
    }

    private static byte[] packSignatures(byte[][] cids, byte[][] sigs) {
        int total = 0;
        for (int i = 0; i < cids.length; i++) {
            total += 1 + cids[i].length + 2 + sigs[i].length;
        }
        ByteBuffer buf = ByteBuffer.allocate(total);
        for (int i = 0; i < cids.length; i++) {
            buf.put((byte) cids[i].length);
            buf.put(cids[i]);
            buf.putShort((short) sigs[i].length);
            buf.put(sigs[i]);
        }
        return buf.array();
    }
}
