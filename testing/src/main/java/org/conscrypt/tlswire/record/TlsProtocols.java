/*
 * Copyright (C) 2014 The Android Open Source Project
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
package org.conscrypt.tlswire.record;
/**
 * Protocols that can run over the TLS Record Protocol from TLS 1.2 RFC 5246.
 */
public class TlsProtocols {
    public static final int CHANGE_CIPHER_SPEC = 20;
    public static final int ALERT = 21;
    public static final int HANDSHAKE = 22;
    public static final int APPLICATION_DATA = 23;
    public static final int HEARTBEAT = 24;
    private TlsProtocols() {}
}
