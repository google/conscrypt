/*
 * Copyright (C) 2026 The Android Open Source Project
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

package libcore.net;

@SuppressWarnings({"unused", "DoNotCallSuggester"})
public final class NetworkSecurityPolicy {
    public static final int CERTIFICATE_TRANSPARENCY_REASON_APP_OPT_IN = 1;
    public static final int CERTIFICATE_TRANSPARENCY_REASON_DOMAIN_OPT_IN = 2;
    public static final int CERTIFICATE_TRANSPARENCY_REASON_SDK_TARGET_DEFAULT_ENABLED = 3;

    public static final int DOMAIN_ENCRYPTION_MODE_DISABLED = 1;
    public static final int DOMAIN_ENCRYPTION_MODE_OPPORTUNISTIC = 2;
    public static final int DOMAIN_ENCRYPTION_MODE_ENABLED = 3;
    public static final int DOMAIN_ENCRYPTION_MODE_REQUIRED = 4;

    public static NetworkSecurityPolicy getInstance() {
        throw new RuntimeException("Stub!");
    }

    public boolean isCleartextTrafficPermitted() {
        throw new RuntimeException("Stub!");
    }

    public boolean isCleartextTrafficPermitted(String hostname) {
        throw new RuntimeException("Stub!");
    }

    public boolean isCertificateTransparencyVerificationRequired(String hostname) {
        throw new RuntimeException("Stub!");
    }

    public int getCertificateTransparencyVerificationReason(String hostname) {
        throw new RuntimeException("Stub!");
    }

    public int getDomainEncryptionMode(String hostname) {
        throw new RuntimeException("Stub!");
    }

    public void handleTrustStorageUpdate() {
        throw new RuntimeException("Stub!");
    }
}
