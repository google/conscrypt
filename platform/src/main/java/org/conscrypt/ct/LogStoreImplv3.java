/*
 * Copyright (C) 2025 The Android Open Source Project
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

import com.google.flatbuffers.FlatBufferBuilder;

import org.conscrypt.ByteArray;
import org.conscrypt.Internal;
import org.conscrypt.OpenSSLKey;
import org.conscrypt.Platform;
import org.conscrypt.ct.fbs.Log;
import org.conscrypt.ct.fbs.LogList;
import org.conscrypt.ct.fbs.LogState;
import org.conscrypt.ct.fbs.LogType;
import org.conscrypt.metrics.StatsLog;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

@Internal
public class LogStoreImplv3 implements LogStore {
    private static final Logger logger = Logger.getLogger(LogStoreImplv3.class.getName());
    private static final int COMPAT_VERSION = 3;
    private static final Path logListPrefix;
    private static final Path logListSuffix;
    private static final Path logListDeprecatedJsonSuffix;
    private static final long LOG_LIST_CHECK_INTERVAL_IN_MS = 10L * 60 * 1_000; // 10 minutes

    static {
        String androidData = System.getenv("ANDROID_DATA");
        // /data/misc/keychain/ct/v1/current/log_list.json
        logListPrefix = Paths.get(androidData, "misc", "keychain", "ct");
        logListSuffix = Paths.get("current", "log_list.ctfb");
        logListDeprecatedJsonSuffix = Paths.get("current", "log_list.json");
    }

    /** The path to the log list on the filesystem */
    private final Path logPath;

    /** Metrics subsystem. A message is sent there whenever the log state changes */
    private StatsLog metrics;

    /** The current state of this store: UNINITIALIZED, LOADED, COMPLIANT, ... */
    private State state;

    /** The log policy. Used to set the status of this store */
    private Policy policy;

    /** The major version of the log list */
    private int majorVersion;

    /** The minor version of the log list */
    private int minorVersion;

    /** The timestamp of the log list */
    private long timestamp;

    /** The time at which the log list file was last modified */
    private long logListLastModified;

    /** Clock. Faked in testing. */
    private Supplier<Long> clock;

    /** The last time the log list file was checked for modification */
    private long logListLastChecked;

    /** The memory-mapped flat buffer */
    private MappedByteBuffer map;

    /** The flatbuffer root */
    private LogList logList;

    /** Cache of LogInfo already seen */
    private Map<ByteArray, LogInfo> logCache;

    /* We do not have access to InstantSource. Implement a similar pattern using Supplier. */
    static class SystemTimeSupplier implements Supplier<Long> {
        @Override
        public Long get() {
            return System.currentTimeMillis();
        }
    }

    private static Path getPathForCompatVersion(int compatVersion) {
        String version = String.format("v%d", compatVersion);
        if (compatVersion > 2) {
            return logListPrefix.resolve(version).resolve(logListSuffix);
        }
        return logListPrefix.resolve(version).resolve(logListDeprecatedJsonSuffix);
    }

    public LogStoreImplv3(Policy policy) {
        this(policy, getPathForCompatVersion(COMPAT_VERSION), Platform.getStatsLog(),
             new SystemTimeSupplier());
    }

    public LogStoreImplv3(Policy policy, Path logPath, StatsLog metrics, Supplier<Long> clock) {
        this.state = State.UNINITIALIZED;
        this.policy = policy;
        this.logPath = logPath;
        this.metrics = metrics;
        this.clock = clock;
        this.logCache = Collections.synchronizedMap(new HashMap<ByteArray, LogInfo>());
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
        return COMPAT_VERSION;
    }

    @Override
    public int getMinCompatVersionAvailable() {
        for (int i = 1; i < COMPAT_VERSION; i++) {
            if (Files.exists(getPathForCompatVersion(i))) {
                return i;
            }
        }
        return getCompatVersion();
    }

    @Override
    public LogInfo getKnownLog(byte[] logId) throws LogStore.InvalidLogException {
        if (logId == null) {
            return null;
        }
        if (!ensureLogListIsLoaded()) {
            return null;
        }

        ByteArray buf = new ByteArray(logId);
        LogInfo log = logCache.get(buf);
        if (log != null) {
            return log;
        }
        synchronized (this) {
            // Double-check.
            log = logCache.get(buf);
            if (log != null) {
                return log;
            }

            log = cacheLogEntry(logId);
            if (log != null) {
                return log;
            }
        }
        return null;
    }

    /* Ensures the log list is loaded.
     * Returns true if the log list is usable.
     */
    private synchronized boolean ensureLogListIsLoaded() {
        resetLogListIfRequired();
        State previousState = state;
        if (state == State.UNINITIALIZED) {
            state = loadLogList();
        }
        if (state == State.LOADED && policy != null) {
            state = policy.isLogStoreCompliant(this) ? State.COMPLIANT : State.NON_COMPLIANT;
        }
        if (state != previousState) {
            metrics.updateCTLogListStatusChanged(this);
        }
        return state == State.COMPLIANT;
    }

    private synchronized void resetLogListIfRequired() {
        long now = clock.get();
        if (now >= this.logListLastChecked
            && now < this.logListLastChecked + LOG_LIST_CHECK_INTERVAL_IN_MS) {
            return;
        }
        this.logListLastChecked = now;
        try {
            long lastModified = Files.getLastModifiedTime(logPath).toMillis();
            if (this.logListLastModified == lastModified) {
                // The log list has the same last modified timestamp. Keep our
                // current cached value.
                return;
            }
        } catch (IOException e) {
            if (this.logListLastModified == 0) {
                // The log list is not accessible now and it has never been
                // previously, there is nothing to do.
                return;
            }
        }
        this.state = State.UNINITIALIZED;
        this.timestamp = 0;
        this.majorVersion = 0;
        this.minorVersion = 0;
        this.logCache.clear();
    }

    private State loadLogList() {
        FileChannel channel;
        long lastModified;
        try {
            lastModified = Files.getLastModifiedTime(logPath).toMillis();
            channel = FileChannel.open(logPath);
            map = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());
            channel.close();
        } catch (IOException e) {
            return State.NOT_FOUND;
        }
        LogList logList;
        try {
            logList = LogList.getRootAsLogList(map);
        } catch (IndexOutOfBoundsException e) {
            return State.MALFORMED;
        }
        if (logList == null) {
            return State.MALFORMED;
        }
        try {
            this.majorVersion = Math.toIntExact(logList.versionMajor());
            this.minorVersion = Math.toIntExact(logList.versionMinor());
            this.timestamp = logList.timestamp();

            //  Verify that the list timestamp is in the past. This might fail
            //  if there is an issue with the device's clock which can cause
            //  false positives when validating SCTs.
            if (clock.get() < this.timestamp) {
                return State.MALFORMED;
            }

        } catch (ArithmeticException e) {
            logger.log(Level.WARNING, "Unable to parse log list", e);
            return State.MALFORMED;
        }
        this.logList = logList;
        this.logListLastModified = lastModified;
        return State.LOADED;
    }

    private synchronized LogInfo cacheLogEntry(byte[] logId) throws LogStore.InvalidLogException {
        String encodedLogId = Base64.getEncoder().encodeToString(logId);
        Log log = logList.logsByKey(encodedLogId);
        if (log == null) {
            return null;
        }

        try {
            byte[] pubKey = new byte[log.publicKeyLength()];
            log.publicKeyAsByteBuffer().get(pubKey);
            LogInfo.Builder builder =
                    new LogInfo.Builder()
                            .setType(parseType(log.type()))
                            .setOperator(log.operator())
                            .setPublicKey(parsePubKey(pubKey))
                            .setState(parseState(log.state()), log.stateTimestamp());

            LogInfo logInfo = builder.build();

            // The logId computed using the public key should match the log_id field.
            if (!Arrays.equals(logInfo.getID(), logId)) {
                throw new IllegalArgumentException("logId does not match publicKey");
            }

            //  Verify that the log is in a known state now. This might fail if
            //  there is an issue with the device's clock which can cause false
            //  positives when validating SCTs.
            if (logInfo.getStateAt(clock.get()) == LogInfo.STATE_UNKNOWN) {
                throw new IllegalArgumentException("Log current state is "
                                                   + "unknown, logId: " + encodedLogId);
            }

            logCache.put(new ByteArray(logId), logInfo);
            return logInfo;
        } catch (Exception e) {
            // There is something wrong with that log entry. Assume that the log list is corrupted.
            // We throw a InvalidLogException here to fail-open in the CertificateTransparency
            // class.
            logger.log(Level.WARNING, "Unable to parse log entry", e);
            state = State.MALFORMED;
            metrics.updateCTLogListStatusChanged(this);
            throw new LogStore.InvalidLogException(e);
        }
    }

    private static int parseState(byte state) {
        switch (state) {
            case LogState.Pending:
                return LogInfo.STATE_PENDING;
            case LogState.Qualified:
                return LogInfo.STATE_QUALIFIED;
            case LogState.Usable:
                return LogInfo.STATE_USABLE;
            case LogState.Readonly:
                return LogInfo.STATE_READONLY;
            case LogState.Retired:
                return LogInfo.STATE_RETIRED;
            case LogState.Rejected:
                return LogInfo.STATE_REJECTED;
            default:
                throw new IllegalArgumentException("Unknown log state: " + state);
        }
    }

    private static int parseType(byte logType) {
        switch (logType) {
            case LogType.Rfc6962:
                return LogInfo.TYPE_RFC6962;
            case LogType.Static:
                return LogInfo.TYPE_STATIC_CT_API;
            default:
                throw new IllegalArgumentException("Unknown log type: " + logType);
        }
    }

    private static PublicKey parsePubKey(byte[] key) {
        // TODO(tweek): Replace with NativeCrypto.EVP_PKEY_from_subject_public_key_info
        byte[] pem = ("-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(key)
                      + "\n-----END PUBLIC KEY-----")
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
