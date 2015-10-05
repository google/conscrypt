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

import org.conscrypt.NativeCrypto;
import org.conscrypt.OpenSSLKey;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class CTLogStoreImpl implements CTLogStore {
    // Lazy loaded by getKnownLog
    private CTLogInfo[] knownLogs = null;

    @Override
    public CTLogInfo getKnownLog(byte[] logId) {
        if (knownLogs == null) {
            knownLogs = getDefaultKnownLogs();
        }
        for (CTLogInfo log: knownLogs) {
            if (Arrays.equals(logId, log.getID())) {
                return log;
            }
        }
        return null;
    }

    public static CTLogInfo[] getDefaultKnownLogs() {
        CTLogInfo logs[] = new CTLogInfo[KnownLogs.LOG_COUNT];
        for (int i = 0; i < KnownLogs.LOG_COUNT; i++) {
            try {
                PublicKey key = new OpenSSLKey(NativeCrypto.d2i_PUBKEY(KnownLogs.LOG_KEYS[i]))
                                .getPublicKey();

                logs[i] = new CTLogInfo(key,
                                        KnownLogs.LOG_DESCRIPTIONS[i],
                                        KnownLogs.LOG_URLS[i]);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
        return logs;
    }
}
