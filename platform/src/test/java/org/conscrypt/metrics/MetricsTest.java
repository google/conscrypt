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

import static org.junit.Assert.assertEquals;

import android.util.StatsEvent;
import java.lang.reflect.Method;
import junit.framework.TestCase;
import org.conscrypt.InternalUtil;
import org.conscrypt.metrics.ReflexiveStatsEvent;
import org.conscrypt.metrics.ReflexiveStatsLog;

public class MetricsTest extends TestCase {
    public static final int TLS_HANDSHAKE_REPORTED = 317;

    // Tests that ReflexiveEvent produces the same event as framework's.
    public void test_reflexiveEvent() throws Exception {
        StatsEvent frameworkStatsEvent = StatsEvent.newBuilder()
                                                 .setAtomId(TLS_HANDSHAKE_REPORTED)
                                                 .writeBoolean(false)
                                                 .writeInt(1) // protocol
                                                 .writeInt(2) // cipher suite
                                                 .writeInt(100) // duration
                                                 .usePooledBuffer()
                                                 .build();

        ReflexiveStatsEvent reflexiveStatsEvent =
                ReflexiveStatsEvent.buildEvent(TLS_HANDSHAKE_REPORTED, false, 1, 2, 100);
        StatsEvent constructedEvent = (StatsEvent) reflexiveStatsEvent.getStatsEvent();

        // TODO(nikitai): Figure out how to use hidden (@hide) getters from StatsEvent
        // to eliminate the use of reflection
        int fid = (Integer) frameworkStatsEvent.getClass()
                          .getMethod("getAtomId")
                          .invoke(frameworkStatsEvent);
        int cid = (Integer) constructedEvent.getClass()
                          .getMethod("getAtomId")
                          .invoke(constructedEvent);
        assertEquals(fid, cid);

        int fnb = (Integer) frameworkStatsEvent.getClass()
                          .getMethod("getNumBytes")
                          .invoke(frameworkStatsEvent);
        int cnb = (Integer) constructedEvent.getClass()
                          .getMethod("getNumBytes")
                          .invoke(constructedEvent);
        assertEquals(fnb, cnb);

        byte[] fbytes = (byte[]) frameworkStatsEvent.getClass()
                                .getMethod("getBytes")
                                .invoke(frameworkStatsEvent);
        byte[] cbytes =
                (byte[]) constructedEvent.getClass().getMethod("getBytes").invoke(constructedEvent);
        for (int i = 0; i < fnb; i++) {
            // skip encoded timestamp (bytes 1-8)
            if (i < 1 || i > 8) {
                assertEquals(fbytes[i], cbytes[i]);
            }
        }
    }
}
