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
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.conscrypt.Internal;
import org.conscrypt.OpenSSLKey;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@Internal
public class CTLogStoreImpl implements CTLogStore {
    private static final Logger logger = Logger.getLogger(CTLogStoreImpl.class.getName());
    public static final String V3_PATH = "/misc/keychain/ct/v3/log_list.json";
    private static final Path defaultLogList;

    static {
        String ANDROID_DATA = System.getenv("ANDROID_DATA");
        defaultLogList = Paths.get(ANDROID_DATA, V3_PATH);
    }

    private enum State {
        UNINITIALIZED,
        LOADED,
        NOT_FOUND,
        MALFORMED,
    }

    private final Path logList;
    private State state;
    private String version;
    private Map<ByteBuffer, CTLogInfo> logs;

    public CTLogStoreImpl() {
        this(defaultLogList);
    }

    public CTLogStoreImpl(Path logList) {
        this.state = State.UNINITIALIZED;
        this.logList = logList;
    }

    @Override
    public CTLogInfo getKnownLog(byte[] logId) {
        if (logId == null) {
            return null;
        }
        if (!ensureLogListIsLoaded()) {
            return null;
        }
        ByteBuffer buf = ByteBuffer.wrap(logId);
        CTLogInfo log = logs.get(buf);
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
            if (state == State.UNINITIALIZED) {
                state = loadLogList();
            }
            return state == State.LOADED;
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
        HashMap<ByteBuffer, CTLogInfo> logsMap = new HashMap<>();
        try {
            version = json.getString("version");
            JSONArray operators = json.getJSONArray("operators");
            for (int i = 0; i < operators.length(); i++) {
                JSONObject operator = operators.getJSONObject(i);
                String operatorName = operator.getString("name");
                JSONArray logs = operator.getJSONArray("logs");
                for (int j = 0; j < logs.length(); j++) {
                    JSONObject log = logs.getJSONObject(j);
                    String description = log.getString("description");
                    byte[] logId = Base64.getDecoder().decode(log.getString("log_id"));
                    PublicKey key = parsePubKey(log.getString("key"));
                    JSONObject stateObject = log.getJSONObject("state");
                    int logState = parseState(stateObject.keys().next());
                    String url = log.getString("url");
                    CTLogInfo logInfo = new CTLogInfo(key, logState, description, url);
                    logsMap.put(ByteBuffer.wrap(logId), logInfo);
                }
            }
        } catch (JSONException | IllegalArgumentException e) {
            logger.log(Level.WARNING, "Unable to parse log list", e);
            return State.MALFORMED;
        }
        this.logs = Collections.unmodifiableMap(logsMap);
        return State.LOADED;
    }

    private static int parseState(String state) {
        switch (state) {
            case "pending":
                return CTLogInfo.STATE_PENDING;
            case "qualified":
                return CTLogInfo.STATE_QUALIFIED;
            case "usable":
                return CTLogInfo.STATE_USABLE;
            case "readonly":
                return CTLogInfo.STATE_READONLY;
            case "retired":
                return CTLogInfo.STATE_RETIRED;
            case "rejected":
                return CTLogInfo.STATE_REJECTED;
            default:
                throw new IllegalArgumentException("Unknown log state: " + state);
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
