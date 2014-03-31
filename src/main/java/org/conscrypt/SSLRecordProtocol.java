/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.conscrypt;


/**
 * This class contains some SSL constants.
 */
public class SSLRecordProtocol {
    private SSLRecordProtocol() {
    }

    /**
     * Maximum length of allowed plain data fragment as specified by TLS
     * specification.
     */
    static final int MAX_DATA_LENGTH = 16384; // 2^14

    /**
     * Maximum length of allowed compressed data fragment as specified by TLS
     * specification.
     */
    static final int MAX_COMPRESSED_DATA_LENGTH = MAX_DATA_LENGTH + 1024;

    /**
     * Maximum length of allowed ciphered data fragment as specified by TLS
     * specification.
     */
    static final int MAX_CIPHERED_DATA_LENGTH = MAX_COMPRESSED_DATA_LENGTH + 1024;

    /**
     * Maximum length of ssl record. It is counted as: type(1) + version(2) +
     * length(2) + MAX_CIPHERED_DATA_LENGTH
     */
    static final int MAX_SSL_PACKET_SIZE = MAX_CIPHERED_DATA_LENGTH + 5;
}
