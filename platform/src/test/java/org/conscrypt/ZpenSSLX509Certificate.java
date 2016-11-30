/*
 * Copyright 2015 The Android Open Source Project
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

import java.io.Serializable;

/**
 * This is a fake class to test de-serialization with malicious payloads.
 */
public class ZpenSSLX509Certificate implements Serializable {
    /** This will be set via reflection in the test. */
    private static final long serialVersionUID = 0L;

    public final long mContext;

    ZpenSSLX509Certificate(long ctx) {
        mContext = ctx;
    }
}
