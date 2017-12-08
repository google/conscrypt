/*
 * Copyright (C) 2009 The Android Open Source Project
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

import static org.conscrypt.MockSessionBuilder.DEFAULT_PORT;

import java.security.KeyManagementException;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ClientSessionContextTest extends AbstractSessionContextTest<ClientSessionContext> {

    @Override
    ClientSessionContext newContext() {
        return new ClientSessionContext();
    }

    @Override
    NativeSslSession getCachedSession(ClientSessionContext context, NativeSslSession s) {
        return context.getCachedSession(s.getPeerHost(), DEFAULT_PORT,
                getDefaultSSLParameters());
    }

    @Override
    int size(ClientSessionContext context) {
        return context.size();
    }

    private static SSLParametersImpl getDefaultSSLParameters() {
        try {
            return SSLParametersImpl.getDefault();
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }
}
