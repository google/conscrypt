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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.PublicKey;
import junit.framework.TestCase;
import org.conscrypt.OpenSSLKey;

public class CTLogStoreImplTest extends TestCase {
    private static final String[] LOG_KEYS = new String[] {
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmXg8sUUzwBYaWrRb+V0IopzQ6o3U" +
        "yEJ04r5ZrRXGdpYM8K+hB0pXrGRLI0eeWz+3skXrS0IO83AhA3GpRL6s6w==",

        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErEULmlBnX9L/+AK20hLYzPMFozYx" +
        "pP0Wm1ylqGkPEwuDKn9DSpNSOym49SN77BLGuAXu9twOW/qT+ddIYVBEIw==",

        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP6PGcXmjlyCBz2ZFUuUjrgbZLaEF" +
        "gfLUkt2cEqlSbb4vTuB6WWmgC9h0L6PN6JF0CPcajpBKGlTI15242a8d4g==",

        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER3qB0NADsP1szXxe4EagrD/ryPVh" +
        "Y/azWbKyXcK12zhXnO8WH2U4QROVUMctFXLflIzw0EivdRN9t7UH1Od30w==",

        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY0ww9JqeJvzVtKNTPVb3JZa7s0ZV" +
        "duH3PpshpMS5XVoPRSjSQCph6f3HjUcM3c4N2hpa8OFbrFFy37ttUrgD+A=="
    };
    private static final String[] LOG_FILENAMES = new String[] {
        "df1c2ec11500945247a96168325ddc5c7959e8f7c6d388fc002e0bbd3f74d764",
        "84f8ae3f613b13407a75fa2893b93ab03b18d86c455fe7c241ae020033216446",
        "89baa01a445100009d8f9a238947115b30702275aafee675a7d94b6b09287619",
        "57456bffe268e49a190dce4318456034c2b4958f3c0201bed5a366737d1e74ca",
        "896c898ced4b8e6547fa351266caae4ca304f1c1ec2b623c2ee259c5452147b0"
    };

    private static final CTLogInfo[] LOGS;
    private static final String[] LOGS_SERIALIZED;

    static {
        try {
            int logCount = LOG_KEYS.length;
            LOGS = new CTLogInfo[logCount];
            LOGS_SERIALIZED = new String[logCount];
            for (int i = 0; i < logCount; i++) {
                byte[] pem = ("-----BEGIN PUBLIC KEY-----\n" + LOG_KEYS[i]
                        + "\n-----END PUBLIC KEY-----\n")
                                     .getBytes(US_ASCII);
                ByteArrayInputStream is = new ByteArrayInputStream(pem);
                PublicKey key = OpenSSLKey.fromPublicKeyPemInputStream(is).getPublicKey();
                String description = String.format("Test Log %d", i);
                String url = String.format("log%d.example.com", i);
                LOGS[i] = new CTLogInfo(key, CTLogInfo.STATE_USABLE, description, url);
                LOGS_SERIALIZED[i] = String.format("description:%s\nurl:%s\nkey:%s",
                    description, url, LOG_KEYS[i]);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void test_loadLog() throws Exception {
        CTLogInfo log = CTLogStoreImpl.loadLog(
                new ByteArrayInputStream(LOGS_SERIALIZED[0].getBytes(US_ASCII)));
        assertEquals(LOGS[0], log);

        File testFile = writeFile(LOGS_SERIALIZED[0]);
        log = CTLogStoreImpl.loadLog(testFile);
        assertEquals(LOGS[0], log);

        // Empty log file, used to mask fallback logs
        assertEquals(null, CTLogStoreImpl.loadLog(new ByteArrayInputStream(new byte[0])));
        try {
            CTLogStoreImpl.loadLog(new ByteArrayInputStream("randomgarbage".getBytes(US_ASCII)));
            fail("InvalidLogFileException not thrown");
        } catch (CTLogStoreImpl.InvalidLogFileException e) {}

        try {
            CTLogStoreImpl.loadLog(new File("/nonexistent"));
            fail("FileNotFoundException not thrown");
        } catch (FileNotFoundException e) {}
    }

    public void test_getKnownLog() throws Exception {
        File userDir = createTempDirectory();
        userDir.deleteOnExit();

        CTLogInfo[] extraLogs = new CTLogInfo[] {LOGS[2], LOGS[3]};

        CTLogStore store = new CTLogStoreImpl(userDir, extraLogs);

        /* Add logs 0 and 1 to the user and system directories respectively
         * Log 2 & 3 are part of the extras.
         * Log 4 is not in the store
         */
        File log0File = new File(userDir, LOG_FILENAMES[0]);
        File log4File = new File(userDir, LOG_FILENAMES[4]);

        writeFile(log0File, LOGS_SERIALIZED[0]);

        // Logs 01 are present, log 2 is in the fallback and unused, log 3 is present but masked,
        // log 4 is missing
        assertEquals(LOGS[0], store.getKnownLog(LOGS[0].getID()));
        assertEquals(LOGS[2], store.getKnownLog(LOGS[2].getID()));
        assertEquals(LOGS[3], store.getKnownLog(LOGS[3].getID()));
        assertEquals(null, store.getKnownLog(LOGS[4].getID()));
    }

    /**
     * Create a temporary file and write to it.
     * The file will be deleted on exit.
     * @param contents The data to be written to the file
     * @return A reference to the temporary file
     */
    private File writeFile(String contents) throws IOException {
        File file = File.createTempFile("test", null);
        file.deleteOnExit();
        writeFile(file, contents);
        return file;
    }

    private static void writeFile(File file, String contents) throws FileNotFoundException {
        PrintWriter writer = new PrintWriter(
                new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), UTF_8)),
                false);
        try {
            writer.write(contents);
        } finally {
            writer.close();
        }
    }

    /*
     * This is NOT safe, as another process could create a file between delete() and mkdir()
     * It should be fine for tests though
     */
    private static File createTempDirectory() throws IOException {
        File folder = File.createTempFile("test", "");
        folder.delete();
        folder.mkdir();
        return folder;
    }
}

