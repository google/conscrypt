/*
 * Copyright (C) 2017 The Android Open Source Project
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

import java.util.Enumeration;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ServerSessionContextTest extends AbstractSessionContextTest<ServerSessionContext> {

    @Override
    ServerSessionContext newContext() {
        return new ServerSessionContext();
    }

    @Override
    NativeSslSession getCachedSession(ServerSessionContext context, NativeSslSession s) {
        return context.getSessionFromCache(s.getId());
    }

    @Override
    int size(ServerSessionContext context) {
        int count = 0;
        Enumeration<byte[]> ids = context.getIds();
        while (ids.hasMoreElements()) {
            ids.nextElement();
            count++;
        }
        return count;
    }
}
