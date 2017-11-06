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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;
import org.conscrypt.Internal;
import org.conscrypt.InternalUtil;

/**
 * @hide
 */
@Internal
public class CTLogStoreImpl implements CTLogStore {
    private static final Charset US_ASCII = Charset.forName("US-ASCII");

    /**
     * Thrown when parsing of a log file fails.
     */
    public static class InvalidLogFileException extends Exception {
        public InvalidLogFileException() {
        }

        public InvalidLogFileException(String message) {
            super(message);
        }

        public InvalidLogFileException(String message, Throwable cause) {
            super(message, cause);
        }

        public InvalidLogFileException(Throwable cause) {
            super(cause);
        }
    }

    private static final File defaultUserLogDir;
    private static final File defaultSystemLogDir;
    // Lazy loaded by CTLogStoreImpl()
    private static volatile CTLogInfo[] defaultFallbackLogs = null;
    static {
        String ANDROID_DATA = System.getenv("ANDROID_DATA");
        String ANDROID_ROOT = System.getenv("ANDROID_ROOT");
        defaultUserLogDir = new File(ANDROID_DATA + "/misc/keychain/trusted_ct_logs/current/");
        defaultSystemLogDir = new File(ANDROID_ROOT + "/etc/security/ct_known_logs/");
    }

    private File userLogDir;
    private File systemLogDir;
    private CTLogInfo[] fallbackLogs;

    private HashMap<ByteBuffer, CTLogInfo> logCache = new HashMap<>();
    private Set<ByteBuffer> missingLogCache = Collections.synchronizedSet(new HashSet<ByteBuffer>());

    public CTLogStoreImpl() {
        this(defaultUserLogDir,
             defaultSystemLogDir,
             getDefaultFallbackLogs());
    }

    public CTLogStoreImpl(File userLogDir, File systemLogDir, CTLogInfo[] fallbackLogs) {
        this.userLogDir = userLogDir;
        this.systemLogDir = systemLogDir;
        this.fallbackLogs = fallbackLogs;
    }

    @Override
    public CTLogInfo getKnownLog(byte[] logId) {
        ByteBuffer buf = ByteBuffer.wrap(logId);
        CTLogInfo log = logCache.get(buf);
        if (log != null) {
            return log;
        }
        if (missingLogCache.contains(buf)) {
            return null;
        }

        log = findKnownLog(logId);
        if (log != null) {
            logCache.put(buf, log);
        } else {
            missingLogCache.add(buf);
        }

        return log;
    }

    private CTLogInfo findKnownLog(byte[] logId) {
        String filename = hexEncode(logId);
        try {
            return loadLog(new File(userLogDir, filename));
        } catch (InvalidLogFileException e) {
            return null;
        } catch (FileNotFoundException e) {}

        try {
            return loadLog(new File(systemLogDir, filename));
        } catch (InvalidLogFileException e) {
            return null;
        } catch (FileNotFoundException e) {}

        // If the updateable logs dont exist then use the fallback logs.
        if (!userLogDir.exists()) {
            for (CTLogInfo log: fallbackLogs) {
                if (Arrays.equals(logId, log.getID())) {
                    return log;
                }
            }
        }
        return null;
    }

    public static CTLogInfo[] getDefaultFallbackLogs() {
        CTLogInfo[] result = defaultFallbackLogs;
        if (result == null) {
            // single-check idiom
            defaultFallbackLogs = result = createDefaultFallbackLogs();
        }
        return result;
    }

    private static CTLogInfo[] createDefaultFallbackLogs() {
        CTLogInfo[] logs = new CTLogInfo[KnownLogs.LOG_COUNT];
        for (int i = 0; i < KnownLogs.LOG_COUNT; i++) {
            try {
                PublicKey key = InternalUtil.logKeyToPublicKey(KnownLogs.LOG_KEYS[i]);

                logs[i] = new CTLogInfo(key,
                                        KnownLogs.LOG_DESCRIPTIONS[i],
                                        KnownLogs.LOG_URLS[i]);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        defaultFallbackLogs = logs;
        return logs;
    }

    /**
     * Load a CTLogInfo from a file.
     * @throws FileNotFoundException if the file does not exist
     * @throws InvalidLogFileException if the file could not be parsed properly
     * @return a CTLogInfo or null if the file is empty
     */
    public static CTLogInfo loadLog(File file) throws FileNotFoundException,
                                                      InvalidLogFileException {
        return loadLog(new FileInputStream(file));
    }

    /**
     * Load a CTLogInfo from a textual representation. Closes {@code input} upon completion
     * of loading.
     *
     * @throws InvalidLogFileException if the input could not be parsed properly
     * @return a CTLogInfo or null if the input is empty
     */
    public static CTLogInfo loadLog(InputStream input) throws InvalidLogFileException {
        final Scanner scan = new Scanner(input, "UTF-8");
        scan.useDelimiter("\n");

        String description = null;
        String url = null;
        String key = null;
        try {
            // If the scanner can't even read one token then the file must be empty/blank
            if (!scan.hasNext()) {
                return null;
            }

            while (scan.hasNext()) {
                String[] parts = scan.next().split(":", 2);
                if (parts.length < 2) {
                    continue;
                }

                String name = parts[0];
                String value = parts[1];
                switch (name) {
                    case "description":
                        description = value;
                        break;
                    case "url":
                        url = value;
                        break;
                    case "key":
                        key = value;
                        break;
                }
            }
        } finally {
            scan.close();
        }

        if (description == null || url == null || key == null) {
            throw new InvalidLogFileException("Missing one of 'description', 'url' or 'key'");
        }

        PublicKey pubkey;
        try {
            pubkey = InternalUtil.readPublicKeyPem(new ByteArrayInputStream(
                    ("-----BEGIN PUBLIC KEY-----\n" +
                        key + "\n" +
                        "-----END PUBLIC KEY-----").getBytes(US_ASCII)));
        } catch (InvalidKeyException e) {
            throw new InvalidLogFileException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidLogFileException(e);
        }

        return new CTLogInfo(pubkey, description, url);
    }

    private final static char[] HEX_DIGITS = new char[] {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private static String hexEncode(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b: data) {
            sb.append(HEX_DIGITS[(b >> 4) & 0x0f]);
            sb.append(HEX_DIGITS[b & 0x0f]);
        }
        return sb.toString();
    }
}
