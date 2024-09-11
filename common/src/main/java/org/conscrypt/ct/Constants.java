/*
 * Copyright (C) 2015 The Android Open Source Project
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

package org.conscrypt.ct;

import org.conscrypt.Internal;

@Internal
public class Constants {
    public static final String X509_SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.2";
    public static final String OCSP_SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.5";

    public static final int VERSION_LENGTH = 1;
    public static final int LOGID_LENGTH = 32;
    public static final int TIMESTAMP_LENGTH = 8;
    public static final int EXTENSIONS_LENGTH_BYTES = 2;

    public static final int HASH_ALGORITHM_LENGTH = 1;
    public static final int SIGNATURE_ALGORITHM_LENGTH = 1;
    public static final int SIGNATURE_LENGTH_BYTES = 2;

    public static final int SIGNATURE_TYPE_LENGTH = 1;
    public static final int LOG_ENTRY_TYPE_LENGTH = 2;
    public static final int CERTIFICATE_LENGTH_BYTES = 3;

    public static final int SERIALIZED_SCT_LENGTH_BYTES = 2;
    public static final int SCT_LIST_LENGTH_BYTES = 2;

    public static final int ISSUER_KEY_HASH_LENGTH = 32;
}
