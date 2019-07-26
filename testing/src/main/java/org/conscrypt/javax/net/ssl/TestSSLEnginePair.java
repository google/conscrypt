/*
 * Copyright (C) 2010 The Android Open Source Project
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
import static org.junit.Assert.assertFalse;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/**
 * TestSSLEnginePair is a convenience class for other tests that want
 * a pair of connected and handshaked client and server SSLEngines for
 * testing.
 */
public final class TestSSLEnginePair implements Closeable {
    public final TestSSLContext c;
    public final SSLEngine server;
    public final SSLEngine client;

    private TestSSLEnginePair(TestSSLContext c,
            SSLEngine server,
            SSLEngine client) {
        this.c = c;
        this.server = server;
        this.client = client;
    }

    public static TestSSLEnginePair create() throws IOException {
        return create((Hooks) null);
    }

    public static TestSSLEnginePair create(TestSSLContext c) throws IOException {
        return create(c, null);
    }

    public static TestSSLEnginePair create(Hooks hooks) throws IOException {
        return create(TestSSLContext.create(), hooks);
    }

    public static TestSSLEnginePair create(TestSSLContext c, Hooks hooks) throws IOException {
        return create(c, hooks, null);
    }

    public static TestSSLEnginePair create(TestSSLContext c, Hooks hooks, boolean[] finished)
            throws IOException {
        SSLEngine[] engines = connect(c, hooks, finished);
        return new TestSSLEnginePair(c, engines[0], engines[1]);
    }

    public static SSLEngine[] connect(TestSSLContext c, Hooks hooks) throws IOException {
        return connect(c, hooks, null);
    }

    /**
     * Create a new connected server/client engine pair within a
     * existing SSLContext.
     */
    public static SSLEngine[] connect(final TestSSLContext c,
            Hooks hooks,
            boolean finished[]) throws IOException {
        if (hooks == null) {
            hooks = new Hooks();
        }

        // FINISHED state should be returned only once.
        boolean[] clientFinished = new boolean[1];
        boolean[] serverFinished = new boolean[1];

        SSLSession session = c.clientContext.createSSLEngine().getSession();

        int packetBufferSize = session.getPacketBufferSize();
        ByteBuffer clientToServer = ByteBuffer.allocate(packetBufferSize);
        ByteBuffer serverToClient = ByteBuffer.allocate(packetBufferSize);

        int applicationBufferSize = session.getApplicationBufferSize();
        ByteBuffer scratch = ByteBuffer.allocate(applicationBufferSize);

        SSLEngine client = c.clientContext.createSSLEngine(c.host.getHostName(), c.port);
        SSLEngine server = c.serverContext.createSSLEngine();
        client.setUseClientMode(true);
        server.setUseClientMode(false);
        hooks.beforeBeginHandshake(client, server);
        client.beginHandshake();
        server.beginHandshake();

        while (true) {
            boolean clientDone = client.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING;
            boolean serverDone = server.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING;
            if (clientDone && serverDone) {
                break;
            }

            boolean progress = handshakeStep(client,
                    clientToServer,
                    serverToClient,
                    scratch,
                    clientFinished);
            progress |= handshakeStep(server,
                    serverToClient,
                    clientToServer,
                    scratch,
                    serverFinished);
            if (!progress) {
                break;
            }
        }

        if (finished != null) {
            assertEquals(2, finished.length);
            finished[0] = clientFinished[0];
            finished[1] = serverFinished[0];
        }
        return new SSLEngine[] { server, client };
    }

    public static class Hooks {
        void beforeBeginHandshake(SSLEngine client, SSLEngine server) {}
    }

    @Override
    public void close() throws SSLException {
        close(new SSLEngine[] { client, server });
    }

    public static void close(SSLEngine[] engines) {
        try {
            for (SSLEngine engine : engines) {
                if (engine != null) {
                    engine.closeInbound();
                    engine.closeOutbound();
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean handshakeStep(SSLEngine engine,
            ByteBuffer output,
            ByteBuffer input,
            ByteBuffer scratch,
            boolean[] finished) throws IOException {
        try {
            // make the other side's output into our input
            input.flip();

            HandshakeStatus status = engine.getHandshakeStatus();
            switch (status) {

                case NEED_TASK: {
                    boolean progress = false;
                    while (true) {
                        Runnable runnable = engine.getDelegatedTask();
                        if (runnable == null) {
                            return progress;
                        }
                        runnable.run();
                        progress = true;
                    }
                }

                case NOT_HANDSHAKING:
                    // If we're not handshaking, our peer might still be.  Check if there's
                    // any input for us to consume.
                case NEED_UNWRAP: {
                    // avoid underflow
                    if (input.remaining() == 0) {
                        return false;
                    }
                    int inputPositionBefore = input.position();
                    SSLEngineResult unwrapResult = engine.unwrap(input, scratch);
                    assertEquals(SSLEngineResult.Status.OK, unwrapResult.getStatus());
                    assertEquals(0, scratch.position());
                    assertEquals(0, unwrapResult.bytesProduced());
                    assertEquals(input.position() - inputPositionBefore, unwrapResult.bytesConsumed());
                    assertFinishedOnce(finished, unwrapResult);
                    return true;
                }

                case NEED_WRAP: {
                    // avoid possible overflow
                    if (output.remaining() != output.capacity()) {
                        return false;
                    }
                    ByteBuffer emptyByteBuffer = ByteBuffer.allocate(0);
                    int inputPositionBefore = emptyByteBuffer.position();
                    int outputPositionBefore = output.position();
                    SSLEngineResult wrapResult = engine.wrap(emptyByteBuffer, output);
                    assertEquals(SSLEngineResult.Status.OK, wrapResult.getStatus());
                    assertEquals(0, wrapResult.bytesConsumed());
                    assertEquals(inputPositionBefore, emptyByteBuffer.position());
                    assertEquals(output.position() - outputPositionBefore,
                            wrapResult.bytesProduced());
                    assertFinishedOnce(finished, wrapResult);
                    return true;
                }

                case FINISHED:
                    // only returned by wrap/unrap status, not getHandshakeStatus
                    throw new IllegalStateException("Unexpected HandshakeStatus = " + status);
                default:
                    throw new IllegalStateException("Unknown HandshakeStatus = " + status);
            }
        } finally {
            // shift consumed input, restore to output mode
            input.compact();
        }
    }

    private static void assertFinishedOnce(boolean[] finishedOut, SSLEngineResult result) {
        if (result.getHandshakeStatus() == HandshakeStatus.FINISHED) {
            assertFalse("should only return FINISHED once", finishedOut[0]);
            finishedOut[0] = true;
        }
    }
}
