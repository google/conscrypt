/*
 * Copyright (C) 2012 The Android Open Source Project
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

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

@Internal
public final class CertBlacklistImpl implements CertBlacklist {
    private static final Logger logger = Logger.getLogger(CertBlacklistImpl.class.getName());

    private final Set<BigInteger> serialBlacklist;
    private final Set<ByteString> pubkeyBlacklist;

    /**
     * public for testing only.
     */
    public CertBlacklistImpl(Set<BigInteger> serialBlacklist, Set<ByteString> pubkeyBlacklist) {
        this.serialBlacklist = serialBlacklist;
        this.pubkeyBlacklist = pubkeyBlacklist;
    }

    public static CertBlacklist getDefault() {
        String androidData = System.getenv("ANDROID_DATA");
        String blacklistRoot = androidData + "/misc/keychain/";
        String defaultPubkeyBlacklistPath = blacklistRoot + "pubkey_blacklist.txt";
        String defaultSerialBlacklistPath = blacklistRoot + "serial_blacklist.txt";

        Set<ByteString> pubkeyBlacklist = readPublicKeyBlackList(defaultPubkeyBlacklistPath);
        Set<BigInteger> serialBlacklist = readSerialBlackList(defaultSerialBlacklistPath);
        return new CertBlacklistImpl(serialBlacklist, pubkeyBlacklist);
    }

    private static boolean isHex(String value) {
        try {
            new BigInteger(value, 16);
            return true;
        } catch (NumberFormatException e) {
            logger.log(Level.WARNING, "Could not parse hex value " + value, e);
            return false;
        }
    }

    private static boolean isPubkeyHash(String value) {
        if (value.length() != 40) {
            logger.log(Level.WARNING, "Invalid pubkey hash length: " + value.length());
            return false;
        }
        return isHex(value);
    }

    private static String readBlacklist(String path) {
        try {
            return readFileAsString(path);
        } catch (FileNotFoundException ignored) {
        } catch (IOException e) {
            logger.log(Level.WARNING, "Could not read blacklist", e);
        }
        return "";
    }

    // From IoUtils.readFileAsString
    private static String readFileAsString(String path) throws IOException {
        return readFileAsBytes(path).toString("UTF-8");
    }

    // Based on IoUtils.readFileAsBytes
    private static ByteArrayOutputStream readFileAsBytes(String path) throws IOException {
        RandomAccessFile f = null;
        try {
            f = new RandomAccessFile(path, "r");
            ByteArrayOutputStream bytes = new ByteArrayOutputStream((int) f.length());
            byte[] buffer = new byte[8192];
            while (true) {
                int byteCount = f.read(buffer);
                if (byteCount == -1) {
                    return bytes;
                }
                bytes.write(buffer, 0, byteCount);
            }
        } finally {
            closeQuietly(f);
        }
    }

    // Base on IoUtils.closeQuietly
    private static void closeQuietly(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (RuntimeException rethrown) {
                throw rethrown;
            } catch (Exception ignored) {
            }
        }
    }

    private static Set<BigInteger> readSerialBlackList(String path) {

        /* Start out with a base set of known bad values.
         *
         * WARNING: Do not add short serials to this list!
         *
         * Since this currently doesn't compare the serial + issuer, you
         * should only add serials that have enough entropy here. Short
         * serials may inadvertently match a certificate that was issued
         * not in compliance with the Baseline Requirements.
         */
        Set<BigInteger> bl = new HashSet<BigInteger>(Arrays.asList(
            // From http://src.chromium.org/viewvc/chrome/trunk/src/net/base/x509_certificate.cc?revision=78748&view=markup
            // Not a real certificate. For testing only.
            new BigInteger("077a59bcd53459601ca6907267a6dd1c", 16),
            new BigInteger("047ecbe9fca55f7bd09eae36e10cae1e", 16),
            new BigInteger("d8f35f4eb7872b2dab0692e315382fb0", 16),
            new BigInteger("b0b7133ed096f9b56fae91c874bd3ac0", 16),
            new BigInteger("9239d5348f40d1695a745470e1f23f43", 16),
            new BigInteger("e9028b9578e415dc1a710a2b88154447", 16),
            new BigInteger("d7558fdaf5f1105bb213282b707729a3", 16),
            new BigInteger("f5c86af36162f13a64f54f6dc9587c06", 16),
            new BigInteger("392a434f0e07df1f8aa305de34e0c229", 16),
            new BigInteger("3e75ced46b693021218830ae86a82a71", 16)
        ));

        // attempt to augment it with values taken from gservices
        String serialBlacklist = readBlacklist(path);
        if (!serialBlacklist.equals("")) {
            for (String value : serialBlacklist.split(",", -1)) {
                try {
                    bl.add(new BigInteger(value, 16));
                } catch (NumberFormatException e) {
                    logger.log(Level.WARNING, "Tried to blacklist invalid serial number " + value, e);
                }
            }
        }

        // whether that succeeds or fails, send it on its merry way
        return Collections.unmodifiableSet(bl);
    }

    private static Set<ByteString> readPublicKeyBlackList(String path) {

        // start out with a base set of known bad values
        Set<ByteString> bl = new HashSet<ByteString>(toByteStrings(
            // Blacklist test cert for CTS. The cert and key can be found in
            // src/test/resources/blacklist_test_ca.pem and
            // src/test/resources/blacklist_test_ca_key.pem.
            "bae78e6bed65a2bf60ddedde7fd91e825865e93d".getBytes(UTF_8),
            // From http://src.chromium.org/viewvc/chrome/branches/782/src/net/base/x509_certificate.cc?r1=98750&r2=98749&pathrev=98750
            // C=NL, O=DigiNotar, CN=DigiNotar Root CA/emailAddress=info@diginotar.nl
            "410f36363258f30b347d12ce4863e433437806a8".getBytes(UTF_8),
            // Subject: CN=DigiNotar Cyber CA
            // Issuer: CN=GTE CyberTrust Global Root
            "ba3e7bd38cd7e1e6b9cd4c219962e59d7a2f4e37".getBytes(UTF_8),
            // Subject: CN=DigiNotar Services 1024 CA
            // Issuer: CN=Entrust.net
            "e23b8d105f87710a68d9248050ebefc627be4ca6".getBytes(UTF_8),
            // Subject: CN=DigiNotar PKIoverheid CA Organisatie - G2
            // Issuer: CN=Staat der Nederlanden Organisatie CA - G2
            "7b2e16bc39bcd72b456e9f055d1de615b74945db".getBytes(UTF_8),
            // Subject: CN=DigiNotar PKIoverheid CA Overheid en Bedrijven
            // Issuer: CN=Staat der Nederlanden Overheid CA
            "e8f91200c65cee16e039b9f883841661635f81c5".getBytes(UTF_8),
            // From http://src.chromium.org/viewvc/chrome?view=rev&revision=108479
            // Subject: O=Digicert Sdn. Bhd.
            // Issuer: CN=GTE CyberTrust Global Root
            "0129bcd5b448ae8d2496d1c3e19723919088e152".getBytes(UTF_8),
            // Subject: CN=e-islem.kktcmerkezbankasi.org/emailAddress=ileti@kktcmerkezbankasi.org
            // Issuer: CN=T\xC3\x9CRKTRUST Elektronik Sunucu Sertifikas\xC4\xB1 Hizmetleri
            "5f3ab33d55007054bc5e3e5553cd8d8465d77c61".getBytes(UTF_8),
            // Subject: CN=*.EGO.GOV.TR 93
            // Issuer: CN=T\xC3\x9CRKTRUST Elektronik Sunucu Sertifikas\xC4\xB1 Hizmetleri
            "783333c9687df63377efceddd82efa9101913e8e".getBytes(UTF_8),
            // Subject: Subject: C=FR, O=DG Tr\xC3\xA9sor, CN=AC DG Tr\xC3\xA9sor SSL
            // Issuer: C=FR, O=DGTPE, CN=AC DGTPE Signature Authentification
            "3ecf4bbbe46096d514bb539bb913d77aa4ef31bf".getBytes(UTF_8)
        ));

        // attempt to augment it with values taken from gservices
        String pubkeyBlacklist = readBlacklist(path);
        if (!pubkeyBlacklist.equals("")) {
            for (String value : pubkeyBlacklist.split(",", -1)) {
                value = value.trim();
                if (isPubkeyHash(value)) {
                    bl.add(new ByteString(value.getBytes(UTF_8)));
                } else {
                    logger.log(Level.WARNING, "Tried to blacklist invalid pubkey " + value);
                }
            }
        }

        return bl;
    }

    @Override
    public boolean isPublicKeyBlackListed(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA1");
        } catch (GeneralSecurityException e) {
            logger.log(Level.SEVERE, "Unable to get SHA1 MessageDigest", e);
            return false;
        }
        byte[] out = toHex(md.digest(encoded));
        for (ByteString blacklisted : pubkeyBlacklist) {
            if (Arrays.equals(blacklisted.bytes, out)) {
                return true;
            }
        }
        return false;
    }

    private static final byte[] HEX_TABLE = { (byte) '0', (byte) '1', (byte) '2', (byte) '3',
        (byte) '4', (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) 'a',
        (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f'};

    private static byte[] toHex(byte[] in) {
        byte[] out = new byte[in.length * 2];
        int outIndex = 0;
        for (int i = 0; i < in.length; i++) {
            int value = in[i] & 0xff;
            out[outIndex++] = HEX_TABLE[value >> 4];
            out[outIndex++] = HEX_TABLE[value & 0xf];
        }
        return out;
    }

    @Override
    public boolean isSerialNumberBlackListed(BigInteger serial) {
        return serialBlacklist.contains(serial);
    }

    private static List<ByteString> toByteStrings(byte[]... allBytes) {
        List<ByteString> byteStrings = new ArrayList<>(allBytes.length + 1);
        for (byte[] bytes : allBytes) {
            byteStrings.add(new ByteString(bytes));
        }
        return byteStrings;
    }

    private static class ByteString {
        final byte[] bytes;

        public ByteString(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }
            if (!(o instanceof ByteString)) {
                return false;
            }

            ByteString other = (ByteString) o;
            return Arrays.equals(bytes, other.bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }
    }
}
