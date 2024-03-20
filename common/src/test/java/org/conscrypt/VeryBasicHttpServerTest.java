/*
 * Copyright (C) 2023 The Android Open Source Project
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

package org.conscrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for VeryBasicHttpServer.
 * <p>
 * These test VeryBasicHttpServer using plain HTTP connections. They are essentially the same as
 * the ones in HttpsUrlConnectionTest. That way we can differentiate failures due to the
 * HTTP server implementation and failures due to TLS.
 */
@RunWith(JUnit4.class)
public class VeryBasicHttpServerTest {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final VeryBasicHttpServer server = new VeryBasicHttpServer();

    public VeryBasicHttpServerTest() throws IOException {
    }

    @After
    public void after() {
        executor.shutdownNow();
    }

    @Test
    public void failedConnect() throws Exception {
        VeryBasicHttpServer.Op op = server
                .opBuilder()
                .noTls()
                .build();
        Future<Void> future = executor.submit(server.run(op));

        HttpURLConnection connection = server.plainConnection("/file");
        int response = connection.getResponseCode();
        assertEquals(404, response);

        future.get(2000, TimeUnit.MILLISECONDS);
    }

    @Test
    public void successfulConnect() throws Exception {
        VeryBasicHttpServer.Op op = server.opBuilder()
                .content("/file", "Hello\nWorld\n")
                .noTls()
                .build();
        Future<Void> future = executor.submit(server.run(op));

        HttpURLConnection connection = server.plainConnection("/file");
        int response = connection.getResponseCode();
        assertEquals(200, response);

        future.get(2000, TimeUnit.MILLISECONDS);
    }

    @Test
    public void urlReadTimeout() throws Exception {
        TestUtils.assumeEngineSocket();
        VeryBasicHttpServer.Op op = server
                .opBuilder()
                .noTls()
                .postAcceptDelay(5000)
                .closeBeforeRead()
                .build();
        Future<Void> future = executor.submit(server.run(op));

        HttpURLConnection connection = server.plainConnection("/file");
        connection.setConnectTimeout(0);
        connection.setReadTimeout(1000);

        try {
            connection.getInputStream();
            fail("Connection succeeded unexpectedly");
        } catch (SocketException e) {
            if (e.getMessage().contains("reset")) {
                fail("HttpsURLConnection's Read timeout failed, got: " + e.getMessage());
            } else {
                fail("Unexpected SocketException");
            }
        } catch (SocketTimeoutException expected) {
            // Expected
        }

        future.get(6000, TimeUnit.MILLISECONDS);
    }
}
