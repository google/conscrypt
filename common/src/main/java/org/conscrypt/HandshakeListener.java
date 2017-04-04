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

package org.conscrypt;

import javax.net.ssl.SSLException;

/**
 * Similar in concept to {@link javax.net.ssl.HandshakeCompletedListener}, but used for listening directly
 * to the engine. Allows the caller to be notified immediately upon completion of the TLS handshake.
 */
public abstract class HandshakeListener {

    /**
     * Called by the engine when the TLS handshake has completed.
     */
    public abstract void onHandshakeFinished() throws SSLException;
}
