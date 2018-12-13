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

import java.io.IOException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLSocket;
import org.conscrypt.TestUtils;

/**
 * TestSSLSocketPair is a convenience class for other tests that want
 * a pair of connected and handshaked client and server SSLSockets for
 * testing.
 */
public final class TestSSLSocketPair {
    public final TestSSLContext c;
    public final SSLSocket server;
    public final SSLSocket client;
    private TestSSLSocketPair(TestSSLContext c, SSLSocket server, SSLSocket client) {
        this.c = c;
        this.server = server;
        this.client = client;
    }
    public void close() {
        c.close();
        try {
            server.close();
            client.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public SSLSocket[] sockets() {
        return new SSLSocket[] {server, client};
    }

    public TestSSLSocketPair connect() {
        return connect(null, null);
    }

    /**
     * Create a new connected server/client socket pair within a
     * existing SSLContext. Optionally specify clientCipherSuites to
     * allow forcing new SSLSession to test SSLSessionContext
     * caching. Optionally specify serverCipherSuites for testing
     * cipher suite negotiation.
     */
    public TestSSLSocketPair connect(
            final String[] clientCipherSuites, final String[] serverCipherSuites) {
        try {
            ExecutorService executor = Executors.newFixedThreadPool(2);
            Future<Void> s = executor.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    if (serverCipherSuites != null) {
                        server.setEnabledCipherSuites(serverCipherSuites);
                    }
                    TestUtils.setUseSessionTickets(server, true);
                    server.startHandshake();
                    return null;
                }
            });
            Future<Void> c = executor.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    if (clientCipherSuites != null) {
                        client.setEnabledCipherSuites(clientCipherSuites);
                    }
                    TestUtils.setUseSessionTickets(client, true);
                    client.startHandshake();
                    return null;
                }
            });
            executor.shutdown();
            // catch client and server exceptions separately so we can
            // potentially log both.
            Exception serverException;
            try {
                s.get(30, TimeUnit.SECONDS);
                serverException = null;
            } catch (Exception e) {
                serverException = e;
                e.printStackTrace();
            }
            Exception clientException;
            try {
                c.get(30, TimeUnit.SECONDS);
                clientException = null;
            } catch (Exception e) {
                clientException = e;
                e.printStackTrace();
            }
            if (serverException != null) {
                throw serverException;
            }
            if (clientException != null) {
                throw clientException;
            }
            // Ensure that messages can actually be passed and that any NewSessionTicket messages
            // that come after the handshake have been processed.
            exchangeMessages();
            return this;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private TestSSLSocketPair exchangeMessages() {
        try {
            client.getOutputStream().write('A');
            assertEquals((int) 'A', server.getInputStream().read());
            server.getOutputStream().write('B');
            assertEquals((int) 'B', client.getInputStream().read());
            return this;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static TestSSLSocketPair create() {
        return create(TestSSLContext.create());
    }

    /**
     * based on test_SSLSocket_startHandshake
     */
    public static TestSSLSocketPair create(TestSSLContext context) {
        try {
            SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                    context.host, context.port);
            SSLSocket server = (SSLSocket) context.serverSocket.accept();
            return new TestSSLSocketPair(context, server, client);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
