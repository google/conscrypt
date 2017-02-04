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

package org.conscrypt.benchmarks;

import java.io.IOException;
import javax.net.ssl.SSLSocket;

/**
 * Client-side endpoint. Provides basic services for sending/receiving messages from the client
 * socket.
 */
final class TestClient {
    private final SSLSocket socket;

    TestClient(SSLSocket socket) {
        this.socket = socket;
    }

    void start() {
        try {
            socket.startHandshake();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    void stop() {
        try {
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    int readMessage(byte[] buffer) {
        try {
            int totalBytesRead = 0;
            while (totalBytesRead < buffer.length) {
                int remaining = buffer.length - totalBytesRead;
                int bytesRead = socket.getInputStream().read(buffer, totalBytesRead, remaining);
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

    void sendMessage(byte[] data) {
        try {
            socket.getOutputStream().write(data);
            socket.getOutputStream().flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
