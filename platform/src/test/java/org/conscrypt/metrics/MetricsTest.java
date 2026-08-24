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
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import android.util.StatsEvent;

import org.conscrypt.Platform;
import org.conscrypt.TestUtils;
import org.conscrypt.metrics.OptionalMethod;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MetricsTest {
    public static final int TLS_HANDSHAKE_REPORTED = 317;

    @Test
    public void test_statsLogImpl_isSingleton() {
        TestUtils.assumeStatsLogAvailable();
        StatsLog instance1 = StatsLogImpl.getInstance();
        StatsLog instance2 = StatsLogImpl.getInstance();
        assertSame(instance1, instance2);
    }

    @Test
    public void test_statsLogImpl_threadProcessesQueue() throws Exception {
        TestUtils.assumeStatsLogAvailable();
        StatsLog statsLog = StatsLogImpl.getInstance();
        assertTrue("Expected StatsLogImpl instance", statsLog instanceof StatsLogImpl);
        StatsLogImpl impl = (StatsLogImpl) statsLog;

        java.lang.reflect.Field queueField = StatsLogImpl.class.getDeclaredField("logQueue");
        queueField.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.concurrent.BlockingQueue<Runnable> queue =
                (java.util.concurrent.BlockingQueue<Runnable>) queueField.get(impl);

        // Clear queue to start fresh
        queue.clear();

        // Log something to trigger queue insertion (only applies to SDK > 32)
        impl.countTlsHandshake(true, "TLSv1.3", "TLS_AES_128_GCM_SHA256", 100);

        if (Platform.isSdkGreater(32)) {
            // Verify the background thread processes and empties the queue
            long startTime = System.currentTimeMillis();
            boolean empty = false;
            while (System.currentTimeMillis() - startTime < 2000) { // 2s timeout
                if (queue.isEmpty()) {
                    empty = true;
                    break;
                }
                Thread.sleep(10);
            }
            assertTrue("Queue was not processed (thread might be dead)", empty);
        } else {
            // For SDK <= 32, it writes directly, queue should remain empty
            assertTrue("Queue should be empty for SDK <= 32", queue.isEmpty());
        }
    }

    // Tests that ReflexiveEvent produces the same event as framework's.
    @Test
    public void test_reflexiveEvent() throws Exception {
        TestUtils.assumeStatsLogAvailable();

        StatsEvent frameworkStatsEvent;
        ReflexiveStatsEvent reflexiveStatsEvent;
        if (Platform.isSdkGreater(32)) {
            frameworkStatsEvent = StatsEvent.newBuilder()
                                          .setAtomId(TLS_HANDSHAKE_REPORTED)
                                          .writeBoolean(false)
                                          .writeInt(1) // protocol
                                          .writeInt(2) // cipher suite
                                          .writeInt(100) // duration
                                          .writeInt(3) // source
                                          .writeIntArray(new int[] {0}) // uids
                                          .usePooledBuffer()
                                          .build();
            ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder()
                                                          .setAtomId(TLS_HANDSHAKE_REPORTED)
                                                          .writeBoolean(false)
                                                          .writeInt(1) // protocol
                                                          .writeInt(2) // cipher suite
                                                          .writeInt(100) // duration
                                                          .writeInt(3) // source
                                                          .writeIntArray(new int[] {0}); // uids
            builder.usePooledBuffer();
            reflexiveStatsEvent = builder.build();
        } else {
            frameworkStatsEvent = StatsEvent.newBuilder()
                                          .setAtomId(TLS_HANDSHAKE_REPORTED)
                                          .writeBoolean(false)
                                          .writeInt(1) // protocol
                                          .writeInt(2) // cipher suite
                                          .writeInt(100) // duration
                                          .writeInt(3) // source
                                          .usePooledBuffer()
                                          .build();
            ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder()
                                                          .setAtomId(TLS_HANDSHAKE_REPORTED)
                                                          .writeBoolean(false)
                                                          .writeInt(1) // protocol
                                                          .writeInt(2) // cipher suite
                                                          .writeInt(100) // duration
                                                          .writeInt(3); // source
            builder.usePooledBuffer();
            reflexiveStatsEvent = builder.build();
        }

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
