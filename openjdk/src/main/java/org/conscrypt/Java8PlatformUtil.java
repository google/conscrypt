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

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
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
        setSSLParameters(params, impl);

        String sniHost = getSniHostName(params);
        if (sniHost != null) {
            socket.setHostname(sniHost);
        }
    }

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        getSSLParameters(params, impl);
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(socket.getHostname())) {
            params.setServerNames(Collections.singletonList(
                    (SNIServerName) new SNIHostName(socket.getHostname())));
        }
    }

    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        setSSLParameters(params, impl);

        String sniHost = getSniHostName(params);
        if (sniHost != null) {
            engine.setHostname(sniHost);
        }
    }
    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        getSSLParameters(params, impl);
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(engine.getHostname())) {
            params.setServerNames(Collections.singletonList(
                    (SNIServerName) new SNIHostName(engine.getHostname())));
        }
    }

    private static String getSniHostName(SSLParameters params) {
        List<SNIServerName> serverNames = params.getServerNames();
        if (serverNames != null) {
            for (SNIServerName serverName : serverNames) {
                if (serverName.getType() == SNI_HOST_NAME) {
                    return ((SNIHostName) serverName).getAsciiName();
                }
            }
        }
        return null;
    }

    private static void setSSLParameters(SSLParameters params, SSLParametersImpl impl) {
        impl.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        impl.setUseCipherSuitesOrder(params.getUseCipherSuitesOrder());
        impl.setSNIMatchers(params.getSNIMatchers());
        impl.setAlgorithmConstraints(params.getAlgorithmConstraints());
    }

    private static void getSSLParameters(SSLParameters params, SSLParametersImpl impl) {
        params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        params.setUseCipherSuitesOrder(impl.getUseCipherSuitesOrder());
        params.setSNIMatchers(impl.getSNIMatchers());
        params.setAlgorithmConstraints(impl.getAlgorithmConstraints());
    }

    static boolean serverNamePermitted(SSLParametersImpl parameters, String serverName) {
        Collection<SNIMatcher> sniMatchers = parameters.getSNIMatchers();
        if (sniMatchers == null || sniMatchers.isEmpty()) {
            return true;
        }

        for (SNIMatcher m : sniMatchers) {
            boolean match = m.matches(new SNIHostName(serverName));
            if (match) {
                return true;
            }
        }
        return false;
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
