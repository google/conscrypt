/*
 * Copyright (C) 2025 The Android Open Source Project
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

import org.conscrypt.metrics.CertificateTransparencyVerificationReason;

/**
 * ConscryptNetworkSecurityPolicy for the platform (mainline).
 *
 * The Conscrypt-internal interface NetworkSecurityPolicy is ignored when exporting the API.
 */
@SuppressWarnings("HiddenSuperclass")
public class ConscryptNetworkSecurityPolicy implements NetworkSecurityPolicy {
    private final libcore.net.NetworkSecurityPolicy policy;

    public static ConscryptNetworkSecurityPolicy getDefault() {
        return new ConscryptNetworkSecurityPolicy(libcore.net.NetworkSecurityPolicy.getInstance());
    }

    public ConscryptNetworkSecurityPolicy(libcore.net.NetworkSecurityPolicy policy) {
        this.policy = policy;
    }

    @Override
    public boolean isCertificateTransparencyVerificationRequired(String hostname) {
        return policy.isCertificateTransparencyVerificationRequired(hostname);
    }

    @Override
    public CertificateTransparencyVerificationReason getCertificateTransparencyVerificationReason(
            String hostname) {
        if (Platform.isSdkGreater(33)
            && com.android.libcore.Flags.networkSecurityPolicyReasonCtEnabledApi()) {
            CertificateTransparencyVerificationReason reason = plaformCtReasonToConscryptReason(
                    policy.getCertificateTransparencyVerificationReason(hostname));
            if (reason != CertificateTransparencyVerificationReason.UNKNOWN) {
                return reason;
            }
        }
        if (policy.isCertificateTransparencyVerificationRequired("")) {
            return CertificateTransparencyVerificationReason.APP_OPT_IN;
        } else if (policy.isCertificateTransparencyVerificationRequired(hostname)) {
            return CertificateTransparencyVerificationReason.DOMAIN_OPT_IN;
        }
        return CertificateTransparencyVerificationReason.UNKNOWN;
    }

    private static CertificateTransparencyVerificationReason plaformCtReasonToConscryptReason(
            int platformReason) {
        switch (platformReason) {
            case libcore.net.NetworkSecurityPolicy.CERTIFICATE_TRANSPARENCY_REASON_APP_OPT_IN:
                return CertificateTransparencyVerificationReason.APP_OPT_IN;
            case libcore.net.NetworkSecurityPolicy.CERTIFICATE_TRANSPARENCY_REASON_DOMAIN_OPT_IN:
                return CertificateTransparencyVerificationReason.DOMAIN_OPT_IN;
            case libcore.net.NetworkSecurityPolicy
                    .CERTIFICATE_TRANSPARENCY_REASON_SDK_TARGET_DEFAULT_ENABLED:
                return CertificateTransparencyVerificationReason.SDK_TARGET_DEFAULT_ENABLED;
            default:
                return CertificateTransparencyVerificationReason.UNKNOWN;
        }
    }

    @Override
    public DomainEncryptionMode getDomainEncryptionMode(String hostname) {
        // Domain encryption is enabled if it is supported by the platform AND
        // the API is available in libcore.
        if (org.conscrypt.net.flags.Flags.encryptedClientHelloPlatform()
            && com.android.libcore.Flags.networkSecurityPolicyEchApi()) {
            return platformToConscryptEncryptionMode(policy.getDomainEncryptionMode(hostname));
        }
        return DomainEncryptionMode.UNKNOWN;
    }

    private static DomainEncryptionMode platformToConscryptEncryptionMode(int platformMode) {
        switch (platformMode) {
            case libcore.net.NetworkSecurityPolicy.DOMAIN_ENCRYPTION_MODE_DISABLED:
                return DomainEncryptionMode.DISABLED;
            case libcore.net.NetworkSecurityPolicy.DOMAIN_ENCRYPTION_MODE_OPPORTUNISTIC:
                return DomainEncryptionMode.OPPORTUNISTIC;
            case libcore.net.NetworkSecurityPolicy.DOMAIN_ENCRYPTION_MODE_ENABLED:
                return DomainEncryptionMode.ENABLED;
            case libcore.net.NetworkSecurityPolicy.DOMAIN_ENCRYPTION_MODE_REQUIRED:
                return DomainEncryptionMode.REQUIRED;
            default:
                return DomainEncryptionMode.UNKNOWN;
        }
    }
}
