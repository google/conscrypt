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

import static org.conscrypt.CertBlocklistEntry.Origin;

import static java.nio.charset.StandardCharsets.UTF_8;

import org.conscrypt.Platform;
import org.conscrypt.metrics.StatsLog;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

@Internal
public final class CertBlocklistImpl implements CertBlocklist {
    private static final Logger logger = Logger.getLogger(CertBlocklistImpl.class.getName());
    private static final String DIGEST_SHA1 = "SHA-1";
    private static final String DIGEST_SHA256 = "SHA-256";

    private static class Entry implements CertBlocklistEntry {
        private final Origin origin;
        private final int index;

        public Entry(Origin origin, int index) {
            this.origin = origin;
            this.index = index;
        }

        @Override
        public Origin getOrigin() {
            return origin;
        }

        @Override
        public int getIndex() {
            return index;
        }
    }

    private final Set<BigInteger> serialBlocklist;
    private final Map<ByteArray, Entry> sha1PubkeyBlocklist;
    private final Map<ByteArray, Entry> sha256PubkeyBlocklist;
    private final StatsLog metrics;
    private Map<ByteArray, Optional<Entry>> cache;

    /**
     * Number of entries in the cache. The cache contains public keys which are
     * at most 4096 bits (512 bytes) for RSA. For a cache size of 64, that is
     * at most 512 * 64 = 32,768 bytes.
     */
    private static final int CACHE_SIZE = 64;

    private CertBlocklistImpl(Builder builder) {
        this.cache = Collections.synchronizedMap(new LinkedHashMap<ByteArray, Optional<Entry>>() {
            @Override
            protected boolean removeEldestEntry(
                    Map.Entry<ByteArray, Optional<CertBlocklistImpl.Entry>> eldest) {
                return size() > CACHE_SIZE;
            }
        });
        this.serialBlocklist = builder.serialBlocklist;
        this.sha1PubkeyBlocklist = Collections.unmodifiableMap(builder.sha1PubkeyBlocklist);
        this.sha256PubkeyBlocklist = Collections.unmodifiableMap(builder.sha256PubkeyBlocklist);
        this.metrics = builder.metrics;
    }

    public static class Builder {
        private static String ANDROID_DATA = System.getenv("ANDROID_DATA");
        private static String BLOCKLIST_ROOT = ANDROID_DATA + "/misc/keychain/";
        private static String DEFAULT_PUBKEY_BLOCKLIST_PATH =
                BLOCKLIST_ROOT + "pubkey_blacklist.txt";
        private static String DEFAULT_SERIAL_BLOCKLIST_PATH =
                BLOCKLIST_ROOT + "serial_blacklist.txt";
        private static String DEFAULT_PUBKEY_SHA256_BLOCKLIST_PATH =
                BLOCKLIST_ROOT + "pubkey_sha256_blocklist.txt";

        private Set<BigInteger> serialBlocklist;
        private Map<ByteArray, Entry> sha1PubkeyBlocklist;
        private Map<ByteArray, Entry> sha256PubkeyBlocklist;
        private StatsLog metrics;

        public Builder setMetrics(StatsLog metrics) {
            this.metrics = metrics;
            return this;
        }

        public Builder loadSha1Default() {
            sha1PubkeyBlocklist =
                    readPublicKeyBlockList(DEFAULT_PUBKEY_BLOCKLIST_PATH, DIGEST_SHA1);
            return this;
        }

        public Builder loadSha256Default() {
            sha256PubkeyBlocklist =
                    readPublicKeyBlockList(DEFAULT_PUBKEY_SHA256_BLOCKLIST_PATH, DIGEST_SHA256);
            return this;
        }

        public Builder loadSerialDefault() {
            serialBlocklist = readSerialBlockList(DEFAULT_SERIAL_BLOCKLIST_PATH);
            return this;
        }

        public Builder loadAllDefaults() {
            loadSha1Default();
            loadSha256Default();
            loadSerialDefault();
            return this;
        }

        public CertBlocklistImpl build() {
            if (sha1PubkeyBlocklist == null) {
                sha1PubkeyBlocklist = Collections.emptyMap();
            }
            if (sha256PubkeyBlocklist == null) {
                sha256PubkeyBlocklist = Collections.emptyMap();
            }
            if (serialBlocklist == null) {
                serialBlocklist = Collections.emptySet();
            }
            if (metrics == null) {
                metrics = Platform.getStatsLog();
            }
            return new CertBlocklistImpl(this);
        }
    }

    public static CertBlocklistImpl getDefault() {
        return new Builder().loadAllDefaults().build();
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

    private static boolean isPubkeyHash(String value, int expectedHashLength) {
        if (value.length() != expectedHashLength) {
            logger.log(Level.WARNING, "Invalid pubkey hash length: " + value.length());
            return false;
        }
        return isHex(value);
    }

    private static String readBlocklist(String path) {
        try {
            return readFileAsString(path);
        } catch (FileNotFoundException ignored) {
            // Ignored
        } catch (IOException e) {
            logger.log(Level.WARNING, "Could not read blocklist", e);
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
                // Ignored
            }
        }
    }

    private static Set<BigInteger> readSerialBlockList(String path) {
        /*
         * Deprecated. Serials may inadvertently match a certificate that was
         * issued not in compliance with the Baseline Requirements. Prefer
         * using the certificate public key.
         */
        Set<BigInteger> bl = new HashSet<BigInteger>();
        String serialBlocklist = readBlocklist(path);
        if (!serialBlocklist.equals("")) {
            for (String value : serialBlocklist.split(",", /* limit= */ -1)) {
                try {
                    bl.add(new BigInteger(value, 16));
                } catch (NumberFormatException e) {
                    logger.log(Level.WARNING, "Tried to blacklist invalid serial number " + value,
                               e);
                }
            }
        }

        // whether that succeeds or fails, send it on its merry way
        return Collections.unmodifiableSet(bl);
    }

    // clang-format off
    static final byte[] SHA1_TEST = {
            // Blocklist test cert for CTS. The cert and key can be found in
            // src/test/resources/blocklist_test_ca.pem and
            // src/test/resources/blocklist_test_ca_key.pem.
            // bae78e6bed65a2bf60ddedde7fd91e825865e93d
          (byte) 0xba, (byte) 0xe7, (byte) 0x8e, (byte) 0x6b, (byte) 0xed,
          (byte) 0x65, (byte) 0xa2, (byte) 0xbf, (byte) 0x60, (byte) 0xdd,
          (byte) 0xed, (byte) 0xde, (byte) 0x7f, (byte) 0xd9, (byte) 0x1e,
          (byte) 0x82, (byte) 0x58, (byte) 0x65, (byte) 0xe9, (byte) 0x3d,
    };

    static final byte[] SHA256_TEST = {
            // Blocklist test cert for CTS. The cert and key can be found in
            // src/test/resources/blocklist_test_ca2.pem and
            // src/test/resources/blocklist_test_ca2_key.pem.
            // 809964b15e9bd312993d9984045551f503f2cf8e68f39188921ba30fe623f9fd
          (byte) 0x80, (byte) 0x99, (byte) 0x64, (byte) 0xb1, (byte) 0x5e,
          (byte) 0x9b, (byte) 0xd3, (byte) 0x12, (byte) 0x99, (byte) 0x3d,
          (byte) 0x99, (byte) 0x84, (byte) 0x04, (byte) 0x55, (byte) 0x51,
          (byte) 0xf5, (byte) 0x03, (byte) 0xf2, (byte) 0xcf, (byte) 0x8e,
          (byte) 0x68, (byte) 0xf3, (byte) 0x91, (byte) 0x88, (byte) 0x92,
          (byte) 0x1b, (byte) 0xa3, (byte) 0x0f, (byte) 0xe6, (byte) 0x23,
          (byte) 0xf9, (byte) 0xfd,
    };
    // clang-format on

    private static Map<ByteArray, Entry> readPublicKeyBlockList(String path, String hashType) {
        Map<ByteArray, Entry> bl = new HashMap<ByteArray, Entry>();

        switch (hashType) {
            case DIGEST_SHA1:
                bl.put(new ByteArray(SHA1_TEST), new Entry(Origin.SHA1_TEST, /* index= */ 0));
                break;
            case DIGEST_SHA256:
                bl.put(new ByteArray(SHA256_TEST), new Entry(Origin.SHA256_TEST, /* index= */ 0));
                // Blocklist statically included in Conscrypt. See constants/.
                for (int i = 0; i < StaticBlocklist.PUBLIC_KEYS.length; i++) {
                    bl.put(new ByteArray(StaticBlocklist.PUBLIC_KEYS[i]),
                           new Entry(Origin.SHA256_BUILT_IN, /* index= */ i));
                }
                break;
            default:
                throw new RuntimeException("Unknown hashType: " + hashType
                                           + ". Expected SHA-1 or SHA-256");
        }

        MessageDigest md;
        try {
            md = MessageDigest.getInstance(hashType);
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, "Unable to get " + hashType + " MessageDigest", e);
            return bl;
        }

        // The hashes are encoded with hexadecimal values. There should be
        // twice as many characters as the digest length in bytes.
        int hashLength = md.getDigestLength() * 2;

        // Attempt to augment it with values taken from /data/misc/keychain.
        String pubkeyBlocklist = readBlocklist(path);
        Origin origin = (DIGEST_SHA1.equals(hashType)) ? Origin.SHA1_FILE : Origin.SHA256_FILE;
        if (!pubkeyBlocklist.equals("")) {
            String[] fileBlocklist = pubkeyBlocklist.split(",", /* limit= */ -1);
            for (int i = 0; i < fileBlocklist.length; i++) {
                String value = fileBlocklist[i];
                value = value.trim();
                if (isPubkeyHash(value, hashLength)) {
                    bl.putIfAbsent(new ByteArray(Hex.decodeHex(value)), new Entry(origin, i));
                } else {
                    logger.log(Level.WARNING, "Tried to blocklist invalid pubkey " + value);
                }
            }
        }

        return bl;
    }

    private static Entry isPublicKeyBlockListed(byte[] encodedPublicKey,
                                                Map<ByteArray, Entry> blocklist, String hashType) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(hashType);
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, "Unable to get " + hashType + " MessageDigest", e);
            return null;
        }
        ByteArray out = new ByteArray(md.digest(encodedPublicKey));
        return blocklist.get(out);
    }

    @Override
    public boolean isPublicKeyBlockListed(PublicKey publicKey) {
        byte[] encodedPublicKey = publicKey.getEncoded();
        // cacheKey is a view on encodedPublicKey. Because it is used as a key
        // for a Map, its underlying array (encodedPublicKey) should not be
        // modified.
        ByteArray cacheKey = new ByteArray(encodedPublicKey);
        Optional<Entry> cachedResult = cache.get(cacheKey);
        if (cachedResult != null) {
            if (cachedResult.isPresent()) {
                metrics.reportBlocklistHit(cachedResult.get());
                return true;
            }
            return false;
        }
        if (!sha1PubkeyBlocklist.isEmpty()) {
            Entry entry =
                    isPublicKeyBlockListed(encodedPublicKey, sha1PubkeyBlocklist, DIGEST_SHA1);
            if (entry != null) {
                cache.put(cacheKey, Optional.of(entry));
                metrics.reportBlocklistHit(entry);
                return true;
            }
        }
        if (!sha256PubkeyBlocklist.isEmpty()) {
            Entry entry =
                    isPublicKeyBlockListed(encodedPublicKey, sha256PubkeyBlocklist, DIGEST_SHA256);
            if (entry != null) {
                cache.put(cacheKey, Optional.of(entry));
                metrics.reportBlocklistHit(entry);
                return true;
            }
        }
        cache.put(cacheKey, Optional.empty());
        return false;
    }

    @Override
    public boolean isSerialNumberBlockListed(BigInteger serial) {
        return serialBlocklist.contains(serial);
    }
}
