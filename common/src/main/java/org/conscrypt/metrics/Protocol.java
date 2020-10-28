/*
 * Copyright (C) 2020 The Android Open Source Project
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
 * Protocols to metric mapping for metrics instrumentation.
 *
 * Must be in sync with frameworks/base/cmds/statsd/src/atoms.proto
 */
@Internal
public enum Protocol {
    UNKNOWN_PROTO(0),
    SSLv3(1),
    TLSv1(2),
    TLSv1_1(3),
    TLSv1_2(4),
    TLSv1_3(5),
    ;

    final byte id;

    public int getId() {
        return this.id;
    }

    public static Protocol forName(String name) {
        switch (name) {
            case "SSLv3":
                return SSLv3;
            case "TLSv1":
                return TLSv1;
            case "TLSv1.1":
                return TLSv1_1;
            case "TLSv1.2":
                return TLSv1_2;
            case "TLSv1.3":
                return TLSv1_3;
            default:
                return UNKNOWN_PROTO;
        }
    }

    private Protocol(int id) {
        this.id = (byte) id;
    }
}