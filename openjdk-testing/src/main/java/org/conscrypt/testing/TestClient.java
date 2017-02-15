/*
 * Copyright 2017 The Android Open Source Project
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

package org.conscrypt.testing;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.net.ssl.SSLSocket;

/**
 * Client-side endpoint. Provides basic services for sending/receiving messages from the client
 * socket.
 */
public final class TestClient {
    private final SSLSocket socket;
    private InputStream input;
    private OutputStream output;

    public TestClient(SSLSocket socket) {
        this.socket = socket;
    }

    public void start() {
        try {
            socket.startHandshake();
            input = socket.getInputStream();
            output = socket.getOutputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void stop() {
        try {
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public int readMessage(byte[] buffer) {
        try {
            int totalBytesRead = 0;
            while (totalBytesRead < buffer.length) {
                int remaining = buffer.length - totalBytesRead;
                int bytesRead = input.read(buffer, totalBytesRead, remaining);
                if (bytesRead == -1) {
                    break;
                }
                totalBytesRead += bytesRead;
            }
            return totalBytesRead;
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    public void sendMessage(byte[] data) {
        try {
            output.write(data);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void flush() {
        try {
            output.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
