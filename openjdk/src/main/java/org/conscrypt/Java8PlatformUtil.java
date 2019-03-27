/*
 * Copyright 2017 The Android Open Source Project
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

import static javax.net.ssl.StandardConstants.SNI_HOST_NAME;

import java.util.Collections;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/**
 * Utility methods supported on Java 8+.
 */
final class Java8PlatformUtil {
    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        impl.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        impl.setUseCipherSuitesOrder(params.getUseCipherSuitesOrder());
        List<SNIServerName> serverNames = params.getServerNames();

        if (serverNames != null) {
            for (SNIServerName serverName : serverNames) {
                if (serverName.getType() == SNI_HOST_NAME) {
                    socket.setHostname(((SNIHostName) serverName).getAsciiName());
                    break;
                }
            }
        }
    }

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        params.setUseCipherSuitesOrder(impl.getUseCipherSuitesOrder());
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(socket.getHostname())) {
            params.setServerNames(Collections.singletonList(
                    (SNIServerName) new SNIHostName(socket.getHostname())));
        }
    }

    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        impl.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        impl.setUseCipherSuitesOrder(params.getUseCipherSuitesOrder());
        List<SNIServerName> serverNames = params.getServerNames();

        if (serverNames != null) {
            for (SNIServerName serverName : serverNames) {
                if (serverName.getType() == SNI_HOST_NAME) {
                    engine.setHostname(((SNIHostName) serverName).getAsciiName());
                    break;
                }
            }
        }
    }
    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        params.setUseCipherSuitesOrder(impl.getUseCipherSuitesOrder());
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(engine.getHostname())) {
            params.setServerNames(Collections.singletonList(
                    (SNIServerName) new SNIHostName(engine.getHostname())));
        }
    }

    static SSLEngine wrapEngine(ConscryptEngine engine) {
        return new Java8EngineWrapper(engine);
    }

    static SSLEngine unwrapEngine(SSLEngine engine) {
        return Java8EngineWrapper.getDelegate(engine);
    }

    static SSLSession wrapSSLSession(ExternalSession sslSession) {
        return new Java8ExtendedSSLSession(sslSession);
    }

    private Java8PlatformUtil() {}
}
