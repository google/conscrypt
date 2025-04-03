/*
 * Copyright (C) 2024 The Android Open Source Project
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
package org.conscrypt.metrics;

import org.conscrypt.Internal;

/**
 * Mode to metric mapping for metrics instrumentation.
 *
 * Must be in sync with frameworks/base/cmds/statsd/src/atoms.proto
 */
@Internal
public enum MetricsMode {
    NO_MODE(0x0000),
    CBC(0x0001),
    CTR(0x0002),
    ECB(0x0003),
    CFB(0x0004),
    CTS(0x0005),
    GCM(0x0006),
    GCM_SIV(0x0007),
    OFB(0x0008),
    POLY1305(0x0009),
    ;

    final int id;

    public int getId() {
        return this.id;
    }

    public static MetricsMode forName(String name) {
        try {
            return MetricsMode.valueOf(name);
        } catch (IllegalArgumentException e) {
            return MetricsMode.NO_MODE;
        }
    }

    private MetricsMode(int id) {
        this.id = id;
    }
}