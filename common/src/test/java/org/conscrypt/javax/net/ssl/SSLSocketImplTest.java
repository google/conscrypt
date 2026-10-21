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

package org.conscrypt.javax.net.ssl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.conscrypt.AllocatedBuffer;
import org.conscrypt.BufferAllocator;
import org.conscrypt.Conscrypt;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

@RunWith(JUnit4.class)
public class SSLSocketImplTest {
    private final ThreadGroup threadGroup = new ThreadGroup("SSLSocketImplTest");
    private final ExecutorService executor =
            Executors.newCachedThreadPool(t -> new Thread(threadGroup, t));

    @After
    public void teardown() throws InterruptedException {
        executor.shutdownNow();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }

    String getGroupName(SSLSocket socket) {
        return Conscrypt.getGroupName(socket);
    }

    private <T> Future<T> runAsync(Callable<T> callable) {
        return executor.submit(callable);
    }

    @Test
    public void setBufferAllocator_afterConnect_fails() throws Exception {
        TestSSLSocketPair pair = TestSSLSocketPair.create();
        BufferAllocator unpooledBufferAllocator = BufferAllocator.unpooled();
        pair.connect();
        assertThrows(IllegalStateException.class,
                     () -> Conscrypt.setBufferAllocator(pair.client, unpooledBufferAllocator));
    }

    // BufferAllocator that counts allocations.
    private static final class SpyBufferAllocator extends BufferAllocator {
        private final BufferAllocator bufferAllocator;
        private int directAllocationCount = 0;
        private int heapAllocationCount = 0;

        SpyBufferAllocator(BufferAllocator bufferAllocator) {
            this.bufferAllocator = bufferAllocator;
        }

        @Override
        public AllocatedBuffer allocateDirectBuffer(int capacity) {
            directAllocationCount++;
            return bufferAllocator.allocateDirectBuffer(capacity);
        }

        @Override
        public AllocatedBuffer allocateHeapBuffer(int capacity) {
            heapAllocationCount++;
            return bufferAllocator.allocateHeapBuffer(capacity);
        }
    }

    @Test
    public void setBufferAllocator_works() throws Exception {
        TestSSLSocketPair pair = TestSSLSocketPair.create();
        SpyBufferAllocator clientBufferAllocator =
                new SpyBufferAllocator(BufferAllocator.unpooled());
        SpyBufferAllocator serverBufferAllocator =
                new SpyBufferAllocator(BufferAllocator.unpooled());
        Conscrypt.setBufferAllocator(pair.client, clientBufferAllocator);
        Conscrypt.setBufferAllocator(pair.server, serverBufferAllocator);
        pair.connect();

        pair.client.getOutputStream().write(new byte[] {1, 2, 3, 4});
        assertEquals(1, pair.server.getInputStream().read());
        assertEquals(3, pair.server.getInputStream().read(new byte[4]));

        pair.server.getOutputStream().write(new byte[] {1, 2, 3, 4});
        assertEquals(1, pair.client.getInputStream().read());
        assertEquals(3, pair.client.getInputStream().read(new byte[4]));

        assertTrue(clientBufferAllocator.directAllocationCount > 0);
        assertTrue(serverBufferAllocator.directAllocationCount > 0);

        // allocateHeapBuffer is currently not called.
        assertEquals(0, clientBufferAllocator.heapAllocationCount);
        assertEquals(0, serverBufferAllocator.heapAllocationCount);
    }

    @Test
    public void socket_setNamedGroups_works() throws Exception {
        TestSSLContext context = TestSSLContext.create();
        final SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                context.host, context.port);
        Conscrypt.setNamedGroups(client, new String[] {"P-384"});

        // For the server, we don't set the named groups. P-384 should be
        // enabled by default.
        final SSLSocket server = (SSLSocket) context.serverSocket.accept();
        Future<Void> s = runAsync(() -> {
            server.startHandshake();
            return null;
        });
        Future<Void> c = runAsync(() -> {
            client.startHandshake();
            return null;
        });
        s.get();
        c.get();
        // This must works even if sslParametersSupportsNamedGroups is false.
        assertEquals("P-384", getGroupName(client));
        assertEquals("P-384", getGroupName(server));
        client.close();
        server.close();
        context.close();
    }

    @Test
    public void socketFactory_setNamedGroups_works() throws Exception {
        TestSSLContext context = TestSSLContext.create();
        SSLSocketFactory clientSocketFactory = context.clientContext.getSocketFactory();
        Conscrypt.setNamedGroups(clientSocketFactory, new String[] {"P-384"});

        final SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                context.host, context.port);

        // For the server, we don't set the named groups. P-384 should be
        // enabled by default.
        final SSLSocket server = (SSLSocket) context.serverSocket.accept();
        Future<Void> s = runAsync(() -> {
            server.startHandshake();
            return null;
        });
        Future<Void> c = runAsync(() -> {
            client.startHandshake();
            return null;
        });
        s.get();
        c.get();
        // This must works even if sslParametersSupportsNamedGroups is false.
        assertEquals("P-384", getGroupName(client));
        assertEquals("P-384", getGroupName(server));
        client.close();
        server.close();
        context.close();
    }
}
