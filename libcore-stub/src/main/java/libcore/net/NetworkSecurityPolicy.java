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

package libcore.net;

/**
 * Network security policy for this process/application.
 *
 * <p>Network stacks/components are expected to honor this policy. Components which can use the
 * Android framework API should be accessing this policy via the framework's
 * {@code android.security.NetworkSecurityPolicy} instead of via this class.
 *
 * <p>The policy currently consists of a single flag: whether cleartext network traffic is
 * permitted. See {@link #isCleartextTrafficPermitted()}.
 */
public abstract class NetworkSecurityPolicy {
    private static volatile NetworkSecurityPolicy instance = new DefaultNetworkSecurityPolicy();

    public static NetworkSecurityPolicy getInstance() {
        return instance;
    }

    public static void setInstance(NetworkSecurityPolicy policy) {
        if (policy == null) {
            throw new NullPointerException("policy == null");
        }
        instance = policy;
    }

    /**
     * Returns {@code true} if cleartext network traffic (e.g. HTTP, FTP, XMPP, IMAP, SMTP --
     * without TLS or STARTTLS) is permitted for all network communications of this process.
     *
     * <p>{@link #isCleartextTrafficPermitted(String)} should be used to determine if cleartext
     * traffic is permitted for a specific host.
     *
     * <p>When cleartext network traffic is not permitted, the platform's components (e.g. HTTP
     * stacks, {@code WebView}, {@code MediaPlayer}) will refuse this process's requests to use
     * cleartext traffic. Third-party libraries are encouraged to do the same.
     *
     * <p>This flag is honored on a best effort basis because it's impossible to prevent all
     * cleartext traffic from an application given the level of access provided to applications on
     * Android. For example, there's no expectation that {@link java.net.Socket} API will honor this
     * flag. Luckily, most network traffic from apps is handled by higher-level network stacks which
     * can be made to honor this flag. Platform-provided network stacks (e.g. HTTP and FTP) honor
     * this flag from day one, and well-established third-party network stacks will eventually
     * honor it.
     */
    public abstract boolean isCleartextTrafficPermitted();

    /**
     * Returns {@code true} if cleartext network traffic (e.g. HTTP, FTP, XMPP, IMAP, SMTP --
     * without TLS or STARTTLS) is permitted for communicating with {@code hostname} for this
     * process.
     *
     * <p>See {@link #isCleartextTrafficPermitted} for more details.
     */
    public abstract boolean isCleartextTrafficPermitted(String hostname);

    /**
     * Returns {@code true} if Certificate Transparency information is required to be presented by
     * the server and verified by the client in TLS connections to {@code hostname}.
     *
     * <p>See RFC6962 section 3.3 for more details.
     */
    public abstract boolean isCertificateTransparencyVerificationRequired(String hostname);

    public static final class DefaultNetworkSecurityPolicy extends NetworkSecurityPolicy {
        @Override
        public boolean isCleartextTrafficPermitted() {
            return true;
        }

        @Override
        public boolean isCleartextTrafficPermitted(String hostname) {
            return isCleartextTrafficPermitted();
        }

        @Override
        public boolean isCertificateTransparencyVerificationRequired(String hostname) {
            return false;
        }
    }
}
