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

import java.lang.reflect.Method;
import javax.net.ssl.SSLParameters;

/**
 * Utility methods supported on Java 9+.
 */
final class Java9PlatformUtil {
    // TODO(nmittler): Remove reflection once we require Java 9 for building.
    private static final Method SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD;
    private static final Method SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD;

    static {
        Class<?> sslParameters = SSLParameters.class;
        Method getApplicationProtocolsMethod;
        Method setApplicationProtocolsMethod;
        try {
            getApplicationProtocolsMethod = sslParameters.getMethod("getApplicationProtocols");
            setApplicationProtocolsMethod =
                    sslParameters.getMethod("setApplicationProtocols", String[].class);
        } catch (NoSuchMethodException e) {
            getApplicationProtocolsMethod = null;
            setApplicationProtocolsMethod = null;
        }

        SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD = getApplicationProtocolsMethod;
        SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD = setApplicationProtocolsMethod;
    }

    static void setSSLParameters(
            SSLParameters src, SSLParametersImpl dest, AbstractConscryptSocket socket) {
        Java8PlatformUtil.setSSLParameters(src, dest, socket);

        dest.setApplicationProtocols(getApplicationProtocols(src));
    }

    static void getSSLParameters(
            SSLParameters dest, SSLParametersImpl src, AbstractConscryptSocket socket) {
        Java8PlatformUtil.getSSLParameters(dest, src, socket);

        setApplicationProtocols(dest, src.getApplicationProtocols());
    }

    static void setSSLParameters(
            SSLParameters src, SSLParametersImpl dest, ConscryptEngine engine) {
        Java8PlatformUtil.setSSLParameters(src, dest, engine);

        dest.setApplicationProtocols(getApplicationProtocols(src));
    }

    static void getSSLParameters(
            SSLParameters dest, SSLParametersImpl src, ConscryptEngine engine) {
        Java8PlatformUtil.getSSLParameters(dest, src, engine);

        setApplicationProtocols(dest, src.getApplicationProtocols());
    }

    private static String[] getApplicationProtocols(SSLParameters params) {
        if (SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD != null) {
            try {
                return (String[]) SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD.invoke(params);
            } catch (ReflectiveOperationException ignored) {
                // TODO(nmittler): Should we throw here?
            }
        }
        return EmptyArray.STRING;
    }

    private static void setApplicationProtocols(SSLParameters params, String[] protocols) {
        if (SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD != null) {
            try {
                SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD.invoke(params, (Object) protocols);
            } catch (ReflectiveOperationException ignored) {
                // TODO(nmittler): Should we throw here?
            }
        }
    }

    private Java9PlatformUtil() {}
}
