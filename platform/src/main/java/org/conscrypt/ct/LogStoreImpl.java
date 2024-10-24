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

import org.conscrypt.ByteArray;
import org.conscrypt.Internal;
import org.conscrypt.OpenSSLKey;
import org.conscrypt.Platform;
import org.conscrypt.metrics.StatsLog;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

@Internal
public class LogStoreImpl implements LogStore {
    private static final Logger logger = Logger.getLogger(LogStoreImpl.class.getName());
    private static final String BASE_PATH = "misc/keychain/ct";
    private static final int COMPAT_VERSION = 1;
    private static final String LOG_LIST_FILENAME = "log_list.json";
    private static final Path DEFAULT_LOG_LIST;

    static {
        String androidData = System.getenv("ANDROID_DATA");
        String compatVersion = String.format("v%d", COMPAT_VERSION);
        DEFAULT_LOG_LIST = Paths.get(androidData, BASE_PATH, compatVersion, LOG_LIST_FILENAME);
    }

    private final Path logList;
    private StatsLog metrics;
    private State state;
    private Policy policy;
    private int majorVersion;
    private int minorVersion;
    private long timestamp;
    private Map<ByteArray, LogInfo> logs;

    public LogStoreImpl() {
        this(DEFAULT_LOG_LIST);
    }

    public LogStoreImpl(Path logList) {
        this(logList, Platform.getStatsLog());
    }

    public LogStoreImpl(Path logList, StatsLog metrics) {
        this.state = State.UNINITIALIZED;
        this.logList = logList;
        this.metrics = metrics;
    }

    @Override
    public State getState() {
        ensureLogListIsLoaded();
        return state;
    }

    @Override
    public long getTimestamp() {
        return timestamp;
    }

    @Override
    public int getMajorVersion() {
        return majorVersion;
    }

    @Override
    public int getMinorVersion() {
        return minorVersion;
    }

    @Override
    public int getCompatVersion() {
        // Currently, there is only one compatibility version supported. If we
        // are loaded or initialized, it means the expected compatibility
        // version was found.
        if (state == State.LOADED || state == State.COMPLIANT || state == State.NON_COMPLIANT) {
            return COMPAT_VERSION;
        }
        return 0;
    }

    @Override
    public int getMinCompatVersionAvailable() {
        return getCompatVersion();
    }

    @Override
    public void setPolicy(Policy policy) {
        this.policy = policy;
    }

    @Override
    public LogInfo getKnownLog(byte[] logId) {
        if (logId == null) {
            return null;
        }
        if (!ensureLogListIsLoaded()) {
            return null;
        }
        ByteArray buf = new ByteArray(logId);
        LogInfo log = logs.get(buf);
        if (log != null) {
            return log;
        }
        return null;
    }

    /* Ensures the log list is loaded.
     * Returns true if the log list is usable.
     */
    private boolean ensureLogListIsLoaded() {
        synchronized (this) {
            State previousState = state;
            if (state == State.UNINITIALIZED) {
                state = loadLogList();
            }
            if (state == State.LOADED && policy != null) {
                state = policy.isLogStoreCompliant(this) ? State.COMPLIANT : State.NON_COMPLIANT;
            }
            if (state != previousState && metrics != null) {
                metrics.updateCTLogListStatusChanged(this);
            }
            return state == State.COMPLIANT;
        }
    }

    private State loadLogList() {
        byte[] content;
        try {
            content = Files.readAllBytes(logList);
        } catch (IOException e) {
            return State.NOT_FOUND;
        }
        if (content == null) {
            return State.NOT_FOUND;
        }
        JSONObject json;
        try {
            json = new JSONObject(new String(content, UTF_8));
        } catch (JSONException e) {
            logger.log(Level.WARNING, "Unable to parse log list", e);
            return State.MALFORMED;
        }
        HashMap<ByteArray, LogInfo> logsMap = new HashMap<>();
        try {
            majorVersion = parseMajorVersion(json.getString("version"));
            minorVersion = parseMinorVersion(json.getString("version"));
            timestamp = parseTimestamp(json.getString("log_list_timestamp"));
            JSONArray operators = json.getJSONArray("operators");
            for (int i = 0; i < operators.length(); i++) {
                JSONObject operator = operators.getJSONObject(i);
                String operatorName = operator.getString("name");
                JSONArray logs = operator.getJSONArray("logs");
                for (int j = 0; j < logs.length(); j++) {
                    JSONObject log = logs.getJSONObject(j);

                    LogInfo.Builder builder =
                            new LogInfo.Builder()
                                    .setDescription(log.getString("description"))
                                    .setPublicKey(parsePubKey(log.getString("key")))
                                    .setUrl(log.getString("url"))
                                    .setOperator(operatorName);

                    JSONObject stateObject = log.optJSONObject("state");
                    if (stateObject != null) {
                        String state = stateObject.keys().next();
                        String stateTimestamp =
                                stateObject.getJSONObject(state).getString("timestamp");
                        builder.setState(parseState(state), parseTimestamp(stateTimestamp));
                    }

                    LogInfo logInfo = builder.build();
                    byte[] logId = Base64.getDecoder().decode(log.getString("log_id"));

                    // The logId computed using the public key should match the log_id field.
                    if (!Arrays.equals(logInfo.getID(), logId)) {
                        throw new IllegalArgumentException("logId does not match publicKey");
                    }

                    logsMap.put(new ByteArray(logId), logInfo);
                }
            }
        } catch (JSONException | IllegalArgumentException e) {
            logger.log(Level.WARNING, "Unable to parse log list", e);
            return State.MALFORMED;
        }
        this.logs = Collections.unmodifiableMap(logsMap);
        return State.LOADED;
    }

    private static int parseMajorVersion(String version) {
        int pos = version.indexOf(".");
        if (pos == -1) {
            pos = version.length();
        }
        try {
            return Integer.parseInt(version.substring(0, pos));
        } catch (IndexOutOfBoundsException | NumberFormatException e) {
            return 0;
        }
    }

    private static int parseMinorVersion(String version) {
        int pos = version.indexOf(".");
        if (pos != -1 && pos < version.length()) {
            try {
                return Integer.parseInt(version.substring(pos + 1, version.length()));
            } catch (IndexOutOfBoundsException | NumberFormatException e) {
                return 0;
            }
        }
        return 0;
    }

    private static int parseState(String state) {
        switch (state) {
            case "pending":
                return LogInfo.STATE_PENDING;
            case "qualified":
                return LogInfo.STATE_QUALIFIED;
            case "usable":
                return LogInfo.STATE_USABLE;
            case "readonly":
                return LogInfo.STATE_READONLY;
            case "retired":
                return LogInfo.STATE_RETIRED;
            case "rejected":
                return LogInfo.STATE_REJECTED;
            default:
                throw new IllegalArgumentException("Unknown log state: " + state);
        }
    }

    // ISO 8601
    private static DateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");

    @SuppressWarnings("JavaUtilDate")
    private static long parseTimestamp(String timestamp) {
        try {
            Date date = dateFormatter.parse(timestamp);
            return date.getTime();
        } catch (ParseException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static PublicKey parsePubKey(String key) {
        byte[] pem = ("-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----")
                             .getBytes(US_ASCII);
        PublicKey pubkey;
        try {
            pubkey = OpenSSLKey.fromPublicKeyPemInputStream(new ByteArrayInputStream(pem))
                             .getPublicKey();
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        return pubkey;
    }
}
