/*
 * Copyright (C) 2013 The Android Open Source Project
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

import junit.framework.TestCase;
import java.util.Arrays;
import java.util.HashSet;

public class SSLParametersImplTest extends TestCase {

  public void testGetClientKeyType() throws Exception {
    // See http://www.ietf.org/assignments/tls-parameters/tls-parameters.xml
    byte b = Byte.MIN_VALUE;
    do {
      String byteString = Byte.toString(b);
      String keyType = SSLParametersImpl.getClientKeyType(b);
      switch (b) {
        case 1:
          assertEquals(byteString, "RSA", keyType);
          break;
        case 3:
          assertEquals(byteString, "DH_RSA", keyType);
          break;
        case 64:
          assertEquals(byteString, "EC", keyType);
          break;
        case 65:
          assertEquals(byteString, "EC_RSA", keyType);
          break;
        case 66:
          assertEquals(byteString, "EC_EC", keyType);
          break;
        default:
          assertNull(byteString, keyType);
      }
      b++;
    } while (b != Byte.MIN_VALUE);
  }

  public void testGetSupportedClientKeyTypes() throws Exception {
      // Create an array with all possible values. Also, duplicate all values.
      byte[] allClientCertificateTypes = new byte[512];
      for (int i = 0; i < allClientCertificateTypes.length; i++) {
          allClientCertificateTypes[i] = (byte) i;
      }
      assertEquals(
              new HashSet<String>(Arrays.asList("RSA", "DH_RSA", "EC", "EC_RSA", "EC_EC")),
              SSLParametersImpl.getSupportedClientKeyTypes(allClientCertificateTypes));
  }
}
