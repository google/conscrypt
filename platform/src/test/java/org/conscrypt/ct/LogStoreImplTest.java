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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.PublicKey;
import java.util.Base64;
import junit.framework.TestCase;
import org.conscrypt.OpenSSLKey;

public class LogStoreImplTest extends TestCase {
    public void test_loadLogList() throws Exception {
        // clang-format off
        String content = "" +
"{" +
"  \"version\": \"1.1\"," +
"  \"log_list_timestamp\": \"2024-01-01T11:55:12Z\"," +
"  \"operators\": [" +
"    {" +
"      \"name\": \"Operator 1\"," +
"      \"email\": [\"ct@operator1.com\"]," +
"      \"logs\": [" +
"        {" +
"          \"description\": \"Operator 1 'Test2024' log\"," +
"          \"log_id\": \"7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=\"," +
"          \"key\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA==\"," +
"          \"url\": \"https://operator1.example.com/logs/test2024/\"," +
"          \"mmd\": 86400," +
"          \"state\": {" +
"            \"usable\": {" +
"              \"timestamp\": \"2022-11-01T18:54:00Z\"" +
"            }" +
"          }," +
"          \"temporal_interval\": {" +
"            \"start_inclusive\": \"2024-01-01T00:00:00Z\"," +
"            \"end_exclusive\": \"2025-01-01T00:00:00Z\"" +
"          }" +
"        }," +
"        {" +
"          \"description\": \"Operator 1 'Test2025' log\"," +
"          \"log_id\": \"TnWjJ1yaEMM4W2zU3z9S6x3w4I4bjWnAsfpksWKaOd8=\"," +
"          \"key\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIIKh+WdoqOTblJji4WiH5AltIDUzODyvFKrXCBjw/Rab0/98J4LUh7dOJEY7+66+yCNSICuqRAX+VPnV8R1Fmg==\"," +
"          \"url\": \"https://operator1.example.com/logs/test2025/\"," +
"          \"mmd\": 86400," +
"          \"state\": {" +
"            \"usable\": {" +
"              \"timestamp\": \"2023-11-26T12:00:00Z\"" +
"            }" +
"          }," +
"          \"temporal_interval\": {" +
"            \"start_inclusive\": \"2025-01-01T00:00:00Z\"," +
"            \"end_exclusive\": \"2025-07-01T00:00:00Z\"" +
"          }" +
"        }" +
"      ]" +
"    }," +
"    {" +
"      \"name\": \"Operator 2\"," +
"      \"email\": [\"ct@operator2.com\"]," +
"      \"logs\": [" +
"        {" +
"          \"description\": \"Operator 2 'Test2024' Log\"," +
"          \"log_id\": \"2ra/az+1tiKfm8K7XGvocJFxbLtRhIU0vaQ9MEjX+6s=\"," +
"          \"key\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd7Gbe4/mizX+OpIpLayKjVGKJfyTttegiyk3cR0zyswz6ii5H+Ksw6ld3Ze+9p6UJd02gdHrXSnDK0TxW8oVSA==\"," +
"          \"url\": \"https://operator2.example.com/logs/test2024/\"," +
"          \"mmd\": 86400," +
"          \"state\": {" +
"            \"usable\": {" +
"              \"timestamp\": \"2022-11-30T17:00:00Z\"" +
"            }" +
"          }," +
"          \"temporal_interval\": {" +
"            \"start_inclusive\": \"2024-01-01T00:00:00Z\"," +
"            \"end_exclusive\": \"2025-01-01T00:00:00Z\"" +
"          }" +
"        }" +
"      ]" +
"    }" +
"  ]" +
"}";
        // clang-format on

        File logList = writeFile(content);
        LogStore store = new LogStoreImpl(logList.toPath());

        assertNull("A null logId should return null", store.getKnownLog(null));

        byte[] pem = ("-----BEGIN PUBLIC KEY-----\n"
                + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr"
                + "3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA=="
                + "\n-----END PUBLIC KEY-----\n")
                             .getBytes(US_ASCII);
        ByteArrayInputStream is = new ByteArrayInputStream(pem);

        LogInfo log1 =
                new LogInfo.Builder()
                        .setPublicKey(OpenSSLKey.fromPublicKeyPemInputStream(is).getPublicKey())
                        .setDescription("Operator 1 'Test2024' log")
                        .setUrl("https://operator1.example.com/logs/test2024/")
                        .setState(LogInfo.STATE_USABLE)
                        .setOperator("Operator 1")
                        .build();
        byte[] log1Id = Base64.getDecoder().decode("7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=");
        assertEquals("An existing logId should be returned", log1, store.getKnownLog(log1Id));
    }

    private File writeFile(String content) throws IOException {
        File file = File.createTempFile("test", null);
        file.deleteOnExit();
        try (FileWriter fw = new FileWriter(file)) {
            fw.write(content);
        }
        return file;
    }
}
