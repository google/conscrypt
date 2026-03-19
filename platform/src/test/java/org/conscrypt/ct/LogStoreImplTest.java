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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

import org.conscrypt.OpenSSLKey;
import org.conscrypt.metrics.NoopStatsLog;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.function.Supplier;

@RunWith(JUnit4.class)
public class LogStoreImplTest {
    /** FakeStatsLog captures the events being reported */
    static class FakeStatsLog extends NoopStatsLog {
        public ArrayList<LogStore.State> states = new ArrayList<LogStore.State>();

        @Override
        public void updateCTLogListStatusChanged(LogStore logStore) {
            states.add(logStore.getState());
        }
    }

    Policy alwaysCompliantStorePolicy = new Policy() {
        @Override
        public boolean isLogStoreCompliant(LogStore store) {
            return true;
        }
        @Override
        public PolicyCompliance doesResultConformToPolicy(VerificationResult result,
                                                          X509Certificate leaf) {
            return PolicyCompliance.COMPLY;
        }
    };

    Policy neverCompliantStorePolicy = new Policy() {
        @Override
        public boolean isLogStoreCompliant(LogStore store) {
            return false;
        }
        @Override
        public PolicyCompliance doesResultConformToPolicy(VerificationResult result,
                                                          X509Certificate leaf) {
            return PolicyCompliance.COMPLY;
        }
    };

    /* Time supplier that can be set to any arbitrary time */
    static class TimeSupplier implements Supplier<Long> {
        private long currentTimeInMs;

        TimeSupplier(long currentTimeInMs) {
            this.currentTimeInMs = currentTimeInMs;
        }

        @Override
        public Long get() {
            return currentTimeInMs;
        }

        public void setCurrentTimeInMs(long currentTimeInMs) {
            this.currentTimeInMs = currentTimeInMs;
        }
    }

    private static final long JAN2024 = 1704103200000L;
    private static final long JAN2022 = 1641031200000L;
    // clang-format off
    static final String validLogList = "" +
"{" +
"  \"version\": \"1.1\"," +
"  \"log_list_timestamp\": 1704070861000," +
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
"              \"timestamp\": 1667328840000" +
"            }" +
"          }," +
"          \"temporal_interval\": {" +
"            \"start_inclusive\": 1704070861000," +
"            \"end_exclusive\": 1735693261000" +
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
"              \"timestamp\": 1700960461000" +
"            }" +
"          }," +
"          \"temporal_interval\": {" +
"            \"start_inclusive\": 1735693261000," +
"            \"end_exclusive\": 1751331661000" +
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
"              \"timestamp\": 1669770061000" +
"            }" +
"          }," +
"          \"temporal_interval\": {" +
"            \"start_inclusive\": 1704070861000," +
"            \"end_exclusive\": 1735693261000" +
"          }" +
"        }" +
"      ]," +
"      \"tiled_logs\": [" +
"        {" +
"         \"description\": \"Operator 2 'Test2025' log\"," +
"          \"log_id\": \"DleUvPOuqT4zGyyZB7P3kN+bwj1xMiXdIaklrGHFTiE=\"," +
"          \"key\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB/we6GOO/xwxivy4HhkrYFAAPo6e2nc346Wo2o2U+GvoPWSPJz91s/xrEvA3Bk9kWHUUXVZS5morFEzsgdHqPg==\"," +
"          \"submission_url\": \"https://operator2.example.com/tiled/test2025\"," +
"          \"monitoring_url\": \"https://operator2.exmaple.com/tiled_monitor/test2025\"," +
"          \"mmd\": 86400," +
"          \"state\": {" +
"            \"usable\": {" +
"              \"timestamp\": 1667328840000" +
"            }" +
"          }," +
"          \"temporal_interval\": {" +
"            \"start_inclusive\": 1767225600000," +
"            \"end_exclusive\": 1782864000000" +
"          }" +
"        }" +
"      ]" +
"    }" +
"  ]" +
"}";
    // clang-format on

    Path grandparentDir;
    Path parentDir;
    Path logList;

    @After
    public void tearDown() throws Exception {
        if (logList != null) {
            Files.deleteIfExists(logList);
            Files.deleteIfExists(parentDir);
            Files.deleteIfExists(grandparentDir);
        }
    }

    @Test
    public void loadValidLogList_returnsCompliantState() throws Exception {
        FakeStatsLog metrics = new FakeStatsLog();
        logList = writeLogList(validLogList);
        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
        byte[] pem = ("-----BEGIN PUBLIC KEY-----\n"
                      + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnW"
                      + "TAWUYr"
                      + "3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA=="
                      + "\n-----END PUBLIC KEY-----\n")
                             .getBytes(US_ASCII);
        ByteArrayInputStream is = new ByteArrayInputStream(pem);
        LogInfo log1 =
                new LogInfo.Builder()
                        .setPublicKey(OpenSSLKey.fromPublicKeyPemInputStream(is).getPublicKey())
                        .setType(LogInfo.TYPE_RFC6962)
                        .setState(LogInfo.STATE_USABLE, 1667328840000L)
                        .setOperator("Operator 1")
                        .build();
        byte[] log1Id = Base64.getDecoder().decode("7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=");

        assertNull("A null logId should return null", store.getKnownLog(/* logId= */ null));
        assertEquals("An existing logId should be returned", log1, store.getKnownLog(log1Id));
        assertEquals("One metric update should be emitted", 1, metrics.states.size());
        assertEquals("The metric update for log list state should be compliant",
                     LogStore.State.COMPLIANT, metrics.states.get(0));
    }

    @Test
    public void loadMalformedLogList_returnsMalformedState() throws Exception {
        FakeStatsLog metrics = new FakeStatsLog();
        String content = "}}";
        logList = writeLogList(content);
        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);

        assertEquals("The log state should be malformed", LogStore.State.MALFORMED,
                     store.getState());
        assertEquals("One metric update should be emitted", 1, metrics.states.size());
        assertEquals("The metric update for log list state should be malformed",
                     LogStore.State.MALFORMED, metrics.states.get(0));
    }

    @Test
    public void loadFutureLogList_returnsMalformedState() throws Exception {
        FakeStatsLog metrics = new FakeStatsLog();
        logList = writeLogList(validLogList); // The logs are usable from 2024 onwards.
        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2022);
        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);

        assertEquals("The log state should be malformed", LogStore.State.MALFORMED,
                     store.getState());
        assertEquals("One metric update should be emitted", 1, metrics.states.size());
        assertEquals("The metric update for log list state should be malformed",
                     LogStore.State.MALFORMED, metrics.states.get(0));
    }

    @Test
    public void loadMissingLogList_returnsNotFoundState() throws Exception {
        FakeStatsLog metrics = new FakeStatsLog();
        Path missingLogList = Paths.get("missing_dir", "missing_subdir", "does_not_exist_log_list");
        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
        LogStore store =
                new LogStoreImpl(alwaysCompliantStorePolicy, missingLogList, metrics, fakeTime);

        assertEquals("The log state should be not found", LogStore.State.NOT_FOUND,
                     store.getState());
        assertEquals("One metric update should be emitted", 1, metrics.states.size());
        assertEquals("The metric update for log list state should be not found",
                     LogStore.State.NOT_FOUND, metrics.states.get(0));
    }

    @Test
    public void loadMissingAndThenFoundLogList_logListIsLoaded() throws Exception {
        // Arrange
        FakeStatsLog metrics = new FakeStatsLog();
        // Allocate a temporary file path and delete it. We keep the temporary
        // path so that we can add a valid log list later on.
        logList = writeLogList("");
        Files.deleteIfExists(logList);
        Files.deleteIfExists(parentDir);
        Files.deleteIfExists(grandparentDir);
        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
        assertEquals("The log state should be not found", LogStore.State.NOT_FOUND,
                     store.getState());

        // Act
        Files.createDirectory(grandparentDir);
        Files.createDirectory(parentDir);
        Files.write(logList, validLogList.getBytes());

        // Assert
        // 5min < 10min, we should not check the log list yet.
        fakeTime.setCurrentTimeInMs(JAN2024 + 5L * 60 * 1000);
        assertEquals("The log state should be not found", LogStore.State.NOT_FOUND,
                     store.getState());

        // 12min, the log list should be reloadable.
        fakeTime.setCurrentTimeInMs(JAN2024 + 12L * 60 * 1000);
        assertEquals("The log state should be compliant", LogStore.State.COMPLIANT,
                     store.getState());
    }

    @Test
    public void loadMissingThenTimeTravelBackwardsAndThenFoundLogList_logListIsLoaded()
            throws Exception {
        FakeStatsLog metrics = new FakeStatsLog();
        // Allocate a temporary file path and delete it. We keep the temporary
        // path so that we can add a valid log list later on.
        logList = writeLogList("");
        Files.deleteIfExists(logList);
        Files.deleteIfExists(parentDir);
        Files.deleteIfExists(grandparentDir);
        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024 + 100L * 60 * 1000);
        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
        assertEquals("The log state should be not found", LogStore.State.NOT_FOUND,
                     store.getState());

        Files.createDirectory(grandparentDir);
        Files.createDirectory(parentDir);
        Files.write(logList, validLogList.getBytes());
        // Move back in time.
        fakeTime.setCurrentTimeInMs(JAN2024);

        assertEquals("The log state should be compliant", LogStore.State.COMPLIANT,
                     store.getState());
    }

    @Test
    public void loadExistingAndThenRemovedLogList_logListIsNotFound() throws Exception {
        FakeStatsLog metrics = new FakeStatsLog();
        logList = writeLogList(validLogList);
        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
        assertEquals("The log should be loaded", LogStore.State.COMPLIANT, store.getState());

        Files.delete(logList);
        // 12min, the log list should be reloadable.
        fakeTime.setCurrentTimeInMs(JAN2024 + 12L * 60 * 1000);

        assertEquals("The log should have been refreshed", LogStore.State.NOT_FOUND,
                     store.getState());
    }

    @Test
    public void loadExistingLogListAndThenMoveDirectory_logListIsNotFound() throws Exception {
        FakeStatsLog metrics = new FakeStatsLog();
        logList = writeLogList(validLogList);
        TimeSupplier fakeTime = new TimeSupplier(/* currentTimeInMs= */ JAN2024);
        LogStore store = new LogStoreImpl(alwaysCompliantStorePolicy, logList, metrics, fakeTime);
        assertEquals("The log should be loaded", LogStore.State.COMPLIANT, store.getState());

        Path oldParentDir = parentDir;
        parentDir = grandparentDir.resolve("more_current");
        Files.move(oldParentDir, parentDir);
        logList = parentDir.resolve("log_list.json");
        // 12min, the log list should be reloadable.
        fakeTime.setCurrentTimeInMs(JAN2024 + 12L * 60 * 1000);

        assertEquals("The log should have been refreshed", LogStore.State.NOT_FOUND,
                     store.getState());
    }

    private Path writeLogList(String content) throws IOException {
        grandparentDir = Files.createTempDirectory("v1");
        parentDir = Files.createDirectory(grandparentDir.resolve("current"));
        Path file = Files.createFile(parentDir.resolve("log_list.json"));
        Files.write(file, content.getBytes());
        return file;
    }
}
