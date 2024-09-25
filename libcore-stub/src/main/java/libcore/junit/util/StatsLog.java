/* GENERATED SOURCE. DO NOT MODIFY. */
/*
 * Copyright (C) 2024 The Android Open Source Project
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
package com.android.org.conscrypt.metrics;

import com.android.org.conscrypt.Internal;
import com.android.org.conscrypt.ct.LogStore;

/**
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public interface StatsLog {
    public void countTlsHandshake(
            boolean success, String protocol, String cipherSuite, long duration);

    public void updateCTLogListStatusChanged(LogStore logStore);
}
