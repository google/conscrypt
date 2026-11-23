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

package org.conscrypt.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.conscrypt.util.DerUtils;
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
    // Valid MTC CA certificate (CA ID 32473.1, Subject RDN 1.3.6.1.5.5.7.25.3=#0D0481FD5901,
    // critical extension 1.3.6.1.5.5.7.1.38 with minSerial=0x1000000000000,
    // maxSerial=0x5ffffffffffff).
    private static final String VALID_MTC_CA_PEM = "-----BEGIN CERTIFICATE-----\n"
            + "MIIF/DCCBemgAwIBAgIBATAKBggrBgEFBQcGJDAQMQ4wDAYIKwYBBQUHGQEMADAe\n"
            + "Fw0yMDAxMDEwMDAwMDBaFw0zMDEyMzEyMzU5NTlaMBQxEjAQBggrBgEFBQcZAw0E\n"
            + "gf1ZATCCBTIwCwYJYIZIAWUDBAMRA4IFIQBczf84BjLGgSXfpzcMRNJmZcYkiDiK\n"
            + "2cC0knL3rvayCCD32I0xLynrZYV9VuarkyoRa2arzM7JH0galKjLqjAnMpIYguce\n"
            + "a+BlQbythgmj9rEwjjOZCfYc8Anr62lHgpSYYAwfHUaWLiaMevHjZDZ3w7GEzaXw\n"
            + "dR1HsvI3w4SPfrRprRwu2qbiBMnmMgDMGKGwXgqrpOIpAm9OCqGEEVpIT0g5zeFy\n"
            + "32PqLTsF8uBL/eleqSu+FK08BykszEDzExdDvM7FSSoEkjX3dcyafk5Pwh2Qw9vm\n"
            + "XBTM3FNgXQDtEIjG+jtwTiyuXoNWRXF/2m80MjXAaN4X7rx5Uk7Dns4Id7uP8auM\n"
            + "wCy31U3DUAKmNBOh00q7ftyuzCYZkcEH6/CLMgfsfJwLnrGBq8yWwsw6uFpn7kfi\n"
            + "wjrozUDU9usgcEyGxFAgkUAM+obWCAqplvIw+oYy55Ys1BNZUxtpKf5b7aiY/ABr\n"
            + "uueDJFLMVTlADD9S1dw0x6uUZoWXeaBE+t8kP6Y/ggc7GcfYiX96L2zSey0Rq5zG\n"
            + "2vS/OSkyIxfb7SSnYkKeU3e4MlJQ4Snmo75OFSem2kGtcbmMWurYXAbdfBPCcTgb\n"
            + "1zvKsPpd4ziZ82XQ7ZxYN02o3wm9TlGeXKXBGoz7U+yIYGxoSrtQfG3CMp1MvDel\n"
            + "m/fUgXQZ/MW2liTnbKvvmIuOVVQXZQi/+KbFxuoUaKLeFdtclDvcUAkAl2LEiBEM\n"
            + "J1JjpKCvNlEN79J+WeSvymYUumyFnO8xAKeVlOwwQMnvFfq0gKC78XiRPbrzFNrc\n"
            + "EAwVTkAH6lUqbJMzGacqTHTz45wVJNL1GjiIodlLgqi6KE/8i+eD1zt1hyz49Bul\n"
            + "ypkPdpLBT8nO7JMMJ2Eodjw5PO/f5uouP/LN+4vXuk+vDuaEFn+wjEoVds+dMA5L\n"
            + "st+Icx0MwrSdB1nR+96t9XrSnyL0ddZ4u2llZkRpZlPMV4zAE64Cd8PSPGlWODPS\n"
            + "xtMpAiWIcGRu+M6+FkU6/yxHa/ex9Og+02SrATP43Xx2Ci7t1WHIhwJ8CO4gDIbU\n"
            + "d3MPZTBrNTSynWItdr1nUiIkh//9aOhaGvmHo/Y/oeC2zZ9KK5RGTCwT8fmwHzs2\n"
            + "CiGHoMgLMYLhbw2AwiITkOmbgg+PUclzioHH4JJRYtnd8IkEsjzAJfJxhtR7pz3S\n"
            + "VlUceLT8fvP0mPE1XBYk3IlvyLXcvLsrbJTkdIeXweXUBVsSV2gpUc5bzqh1wG0r\n"
            + "YQRE8wqTA5HkZOKoOTApq0xXqU3rIbSgt3MEXD10KNI8rN1a1QEi40HoXJu5NYRV\n"
            + "6PU5HwWOYWEoYzmKHpCLst8CN3a/kngEUia3tlTMXcnemRLUK32s9KW0GjiK+Qqn\n"
            + "DO7skf5cnB5W58LBNqSj7m2xV3r/N+gY30CLWiF9khMSv9a5W17P6wwIncN07HNl\n"
            + "zti4fAHxuUj4HCXqN3DkIY4csKhAo8HD7E5dAsBw6olvvvMMgRj08peZ4jmD7lUI\n"
            + "QBesD2FEA/MQcsMuUKYL0Wo1r+y2dP8M7UIZI0ogLOOd1sEZ9lmg5V6gF98Ywqe1\n"
            + "AuTQqAdNiwhNcc0GvvqZRIObr3TD8hXhkcapgZlNI1B+D3ichECV49JY9v1vsmMo\n"
            + "28Dudah8iugLi8g3sZC0dsvx9svnBuC30WKSOJJk0yLT4MxKkm7oYRCiD2URkcua\n"
            + "f/CCb8Ew5o0Nx/RcCR/cigcSKAySAfvcGJLpqPxm78mdptZQFbMSOlqmo1UwUzAO\n"
            + "BgNVHQ8BAf8EBAMCAgQwDwYDVR0TAQH/BAUwAwEB/zAwBggrBgEFBQcBJgEB/wQh\n"
            + "MB8wCwYJYIZIAWUDBAMRAgcBAAAAAAAAAgcF////////MAoGCCsGAQUFBwYkAwEA\n"
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

    @Test
    public void testReadUint24() throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(
                new byte[] {0x00, 0x09, 0x7b, (byte) 0xff, (byte) 0xff, (byte) 0xff});
        assertEquals(0x00097b, MtcUtils.readUint24(buf));
        assertEquals(0xffffff, MtcUtils.readUint24(buf));

        // Buffer with fewer than 3 bytes must throw CertificateException
        ByteBuffer shortBuf = ByteBuffer.wrap(new byte[] {0x01, 0x02});
        assertThrows(CertificateException.class, () -> MtcUtils.readUint24(shortBuf));
    }

    @Test
    public void testValidateExtensions() throws Exception {
        // Empty extensions vector is valid
        MtcUtils.validateExtensions(new byte[0]);

        // Strictly ascending extension_types (1, 2) with empty and 1-byte data are valid
        MtcUtils.validateExtensions(
                new byte[] {0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x42});

        // Duplicate extension_type (1, 1) must be rejected
        assertThrows(CertificateException.class,
                     ()
                             -> MtcUtils.validateExtensions(
                                     new byte[] {0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}));

        // Out-of-order extension_type (2, 1) must be rejected
        assertThrows(CertificateException.class,
                     ()
                             -> MtcUtils.validateExtensions(
                                     new byte[] {0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}));

        // Truncated extension entry must be rejected
        assertThrows(CertificateException.class,
                     () -> MtcUtils.validateExtensions(new byte[] {0x00, 0x01, 0x00, 0x02, 0x42}));
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
