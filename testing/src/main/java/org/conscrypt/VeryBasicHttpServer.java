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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocket;
import org.conscrypt.javax.net.ssl.TestSSLContext;

/**
 * Very basic http server. Literally just enough to do some HTTP 1.1 in order
 * to test URL connection functionality with the ability to inject faults.
 */
public class VeryBasicHttpServer {
    private final TestSSLContext context = TestSSLContext.create();
    private final ServerSocket tlsSocket = context.serverSocket;
    private final ServerSocket plainSocket = new ServerSocket(0);


    public VeryBasicHttpServer() throws IOException {
    }

    public String getTlsHostname() {
        return context.host.getHostName();
    }

    public int getTlsPort() {
        return tlsSocket.getLocalPort();
    }

    public String getPlainHostname() {
        return plainSocket.getInetAddress().getHostName();
    }

    public int getPlainPort() {
        return plainSocket.getLocalPort();
    }

    public void runInternal(Op op) throws Exception {
        ServerSocket listenSocket = op.useTls() ? tlsSocket : plainSocket;
        Socket connection = listenSocket.accept();
        if (connection instanceof SSLSocket) {
            ((SSLSocket) connection).setUseClientMode(false);
        }
        long delay = op.getPostAcceptDelay();
        if (delay > 0) {
            Thread.sleep(delay);
        }

        if (op.closeBeforeRead()) {
            connection.close();
            return;
        }

        Request request = readRequest(connection);
        process(request, op);
        connection.close();
    }

    public Callable<Void> run(Op op) {
        return () -> {
            runInternal(op);
            return null;
        };
    }

    public Op.Builder opBuilder() {
        return Op.newBuilder();
    }

    void process(Request request, Op op) throws Exception {
        String data = op.content.get(request.path);
        if (data == null) {
            request.sendStatus(404, request.protocol, "Not found: " + request.path);
            request.endHeaders();
        } else {
            request.sendStatus(200, request.protocol, "OK");
            request.sendHeader("Content-type", "text/plain");
            request.sendHeader("Content-Length", data.length());
            request.endHeaders();
            request.sendString(data);
        }
    }

    @SuppressWarnings("StringSplitter") // It's close enough for government work.
    private Request readRequest(Socket socket) throws Exception {
        Request request = new Request();
        request.outputStream = socket.getOutputStream();

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        String line = reader.readLine();
        String[] words = line.split("\\s+");
        checkCondition("Expected 3 words", words.length == 3);
        request.command = words[0];
        request.path = words[1];
        request.protocol = words[2];

        while (true) {
            line = reader.readLine();
            Objects.requireNonNull(line);
            if (line.isEmpty()) {
                break;
            }
            int separator = line.indexOf(": ");
            checkCondition("Parse error", separator > 0);
            String key = line.substring(0, separator);
            String value = line.substring(separator + 2);
            request.headers.put(key, value);
        }
        return request;
    }

    public void checkCondition(String message, boolean condition) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    public HttpsURLConnection tlsConnection(String filePart) throws Exception {
        URL url = new URL("https", getTlsHostname(), getTlsPort(), filePart);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(context.clientContext.getSocketFactory());
        return connection;
    }

    public HttpURLConnection plainConnection(String filePart) throws Exception {
        URL url = new URL("http", getPlainHostname(), getPlainPort(), filePart);
        return (HttpURLConnection) url.openConnection();
    }

    public static class Op {
        private final Map<String, String> content;
        private final long postAcceptDelay;
        private final boolean useTls;
        private final boolean closeBeforeRead;

        Op(Map<String, String> content, long postAcceptDelay,
           boolean useTls, boolean closeBeforeRead) {
            this.content = content;
            this.postAcceptDelay = postAcceptDelay;
            this.useTls = useTls;
            this.closeBeforeRead = closeBeforeRead;
        }

        public long getPostAcceptDelay() {
            return postAcceptDelay;
        }

        public boolean useTls() {
            return useTls;
        }

        public boolean closeBeforeRead() {
            return closeBeforeRead;
        }

        public static class Builder {
            private final Map<String, String> content = new HashMap<>();
            private long postAcceptDelay = 0;
            private boolean useTls = true;
            private boolean closeBeforeRead = false;

            private Builder() {}

            public Builder content(String path, String data) {
                this.content.put(path, data);
                return this;
            }

            public Builder postAcceptDelay(long postAcceptDelay) {
                this.postAcceptDelay = postAcceptDelay;
                return this;
            }

            public Builder noTls() {
                useTls = false;
                return this;
            }

            public Builder closeBeforeRead() {
                this.closeBeforeRead = true;
                return this;
            }

            public Op build() {
                return new Op(content, postAcceptDelay, useTls, closeBeforeRead);
            }
        }
        public static Builder newBuilder() {
            return new Builder();
        }
    }

    private static class Request {
        public String command;
        public String protocol;
        public String path;
        public Map<String, String> headers = new HashMap<>();
        public OutputStream outputStream;

        @Override
        public String toString() {
            return String.format("cmd=%s proto=%s path=%s headers=%s",
                    command, protocol, path, headers.toString());
        }

        public void sendStatus(int result, String proto, String extra) throws Exception {
            String resultString = java.lang.String.format("%s %d %s\r\n", proto, result, extra);
            outputStream.write(resultString.getBytes(StandardCharsets.UTF_8));
        }

        public void sendString (String string) throws Exception {
            outputStream.write(string.getBytes(StandardCharsets.UTF_8));
        }

        public void endHeaders() throws Exception {
            sendString("\r\n");
        }

        public void sendHeader(String key, String value) throws Exception {
            sendString(key + ": " + value + "\r\n");
        }

        public void sendHeader(String key, Integer value) throws Exception {
            sendHeader(key, value.toString());
        }
    }
}