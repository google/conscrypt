/*
 * Copyright 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or impli$
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.conscrypt;

import java.util.List;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import junit.framework.TestCase;

/**
 * Test for OpenSSLExtendedSessionImpl
 */
public class OpenSSLExtendedSessionImplTest extends TestCase {
  static class MockSSLSession extends OpenSSLSessionImpl {
    MockSSLSession() {
      super(0, null, null, null, null, null, 0, null);
    }

    @Override
    public String getRequestedServerName() {
      return "server.name";
    }
  }

  public void test_getRequestedServerNames() {
    AbstractOpenSSLSession session = new MockSSLSession();
    ExtendedSSLSession extendedSession = new OpenSSLExtendedSessionImpl(session);
    List<SNIServerName> names = extendedSession.getRequestedServerNames();
    assertEquals("server.name", ((SNIHostName) names.get(0)).getAsciiName());
  }
}
