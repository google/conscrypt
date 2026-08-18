/*
 * Copyright 2025 The Android Open Source Project
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

import org.conscrypt.Internal;

/**
 * An entry in the blocklist, for the purpose of reporting.
 */
@Internal
public interface CertBlocklistEntry {
    enum Origin { SHA1_TEST, SHA1_BUILT_IN, SHA1_FILE, SHA256_TEST, SHA256_BUILT_IN, SHA256_FILE }

    /**
     * Returns the origin of this entry.
     */
    Origin getOrigin();

    /**
     * Returns the index of this entry in its blocklist.
     */
    int getIndex();
}
