/*
 * Copyright (C) 2019 The Android Open Source Project
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

import java.util.HashMap;
import java.util.Map;

/**
 * Data about OIDs.
 */
final class OidData {

  private OidData() {}

  private static final Map<String, String> OID_TO_NAME_MAP = new HashMap<>();

  static {
    // NOTE: For the time being, we only have X509 signature algorithms here, since we only need
    // them for determining the name of signature algorithms in certs and CRLs.  We can add more in
    // the future if we need them.

    // Signatures

    // RFC 3279
    OID_TO_NAME_MAP.put("1.2.840.113549.1.1.2", "MD2withRSA");
    OID_TO_NAME_MAP.put("1.2.840.113549.1.1.4", "MD5withRSA");
    OID_TO_NAME_MAP.put("1.2.840.113549.1.1.5", "SHA1withRSA");
    OID_TO_NAME_MAP.put("1.2.840.10040.4.3", "SHA1withDSA");
    OID_TO_NAME_MAP.put("1.2.840.10045.4.1", "SHA1withECDSA");

    // RFC 4055
    OID_TO_NAME_MAP.put("1.2.840.113549.1.1.14", "SHA224withRSA");
    OID_TO_NAME_MAP.put("1.2.840.113549.1.1.11", "SHA256withRSA");
    OID_TO_NAME_MAP.put("1.2.840.113549.1.1.12", "SHA384withRSA");
    OID_TO_NAME_MAP.put("1.2.840.113549.1.1.13", "SHA512withRSA");

    // RFC 5758
    OID_TO_NAME_MAP.put("2.16.840.1.101.3.4.3.1", "SHA224withDSA");
    OID_TO_NAME_MAP.put("2.16.840.1.101.3.4.3.2", "SHA256withDSA");
    OID_TO_NAME_MAP.put("1.2.840.10045.4.3.1", "SHA224withECDSA");
    OID_TO_NAME_MAP.put("1.2.840.10045.4.3.2", "SHA256withECDSA");
    OID_TO_NAME_MAP.put("1.2.840.10045.4.3.3", "SHA384withECDSA");
    OID_TO_NAME_MAP.put("1.2.840.10045.4.3.4", "SHA512withECDSA");
  }

  public static String oidToAlgorithmName(String oid) {
    return OID_TO_NAME_MAP.get(oid);
  }
}
