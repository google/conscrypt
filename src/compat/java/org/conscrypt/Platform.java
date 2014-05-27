/*
 * Copyright 2014 The Android Open Source Project
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

import java.io.FileDescriptor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509TrustManager;

/**
 *
 */
public class Platform {
    private static Method m_getCurveName;
    static {
        try {
            m_getCurveName = ECParameterSpec.class.getDeclaredMethod("getCurveName");
            m_getCurveName.setAccessible(true);
        } catch (Exception ignored) {
        }
    }

    public static void setup() {
    }

    public static FileDescriptor getFileDescriptor(Socket s) {
        try {
            Field f_impl = Socket.class.getDeclaredField("impl");
            f_impl.setAccessible(true);
            Object socketImpl = f_impl.get(s);
            Class<?> c_socketImpl = Class.forName("java.net.SocketImpl");
            Field f_fd = c_socketImpl.getDeclaredField("fd");
            f_fd.setAccessible(true);
            return (FileDescriptor) f_fd.get(socketImpl);
        } catch (Exception e) {
            throw new RuntimeException("Can't get FileDescriptor from socket", e);
        }
    }

    public static FileDescriptor getFileDescriptorFromSSLSocket(OpenSSLSocketImpl openSSLSocketImpl) {
        return getFileDescriptor(openSSLSocketImpl);
    }

    public static String getCurveName(ECParameterSpec spec) {
        if (m_getCurveName == null) {
            return null;
        }
        try {
            return (String) m_getCurveName.invoke(spec);
        } catch (Exception e) {
            return null;
        }
    }

    public static void setCurveName(ECParameterSpec spec, String curveName) {
        try {
            Method setCurveName = spec.getClass().getDeclaredMethod("setCurveName", String.class);
            setCurveName.invoke(spec, curveName);
        } catch (Exception ignored) {
        }
    }

    public static void setSocketTimeout(Socket s, long timeoutMillis) {
        // TODO: implement this for unbundled
    }

    public static void setEndpointIdentificationAlgorithm(SSLParameters params,
            String endpointIdentificationAlgorithm) {
        // TODO: implement this for unbundled
    }

    public static String getEndpointIdentificationAlgorithm(SSLParameters params) {
        // TODO: implement this for unbundled
        return null;
    }

    public static void checkClientTrusted(X509TrustManager x509tm, X509Certificate[] chain,
            String authType, Socket socket) throws CertificateException {
        // TODO: use reflection to find whether we have X509ExtendedTrustManager
        /*
        if (x509tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) x509tm;
            x509etm.checkClientTrusted(chain, authType, socket);
        } else {
        */
            x509tm.checkClientTrusted(chain, authType);
        /*
        }
        */
    }

    public static void checkServerTrusted(X509TrustManager x509tm, X509Certificate[] chain,
            String authType, Socket socket) throws CertificateException {
        // TODO: use reflection to find whether we have X509ExtendedTrustManager
        /*
        if (x509tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) x509tm;
            x509etm.checkServerTrusted(chain, authType, socket);
        } else {
        */
            x509tm.checkServerTrusted(chain, authType);
        /*
        }
        */
    }

    public static void checkClientTrusted(X509TrustManager x509tm, X509Certificate[] chain,
            String authType, SSLEngine engine) throws CertificateException {
        // TODO: use reflection to find whether we have X509ExtendedTrustManager
        /*
        if (x509tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) x509tm;
            x509etm.checkClientTrusted(chain, authType, engine);
        } else {
        */
            x509tm.checkClientTrusted(chain, authType);
        /*
        }
        */
    }

    public static void checkServerTrusted(X509TrustManager x509tm, X509Certificate[] chain,
            String authType, SSLEngine engine) throws CertificateException {
        // TODO: use reflection to find whether we have X509ExtendedTrustManager
        /*
        if (x509tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) x509tm;
            x509etm.checkServerTrusted(peerCertChain, authMethod, this);
        } else {
        */
            x509tm.checkServerTrusted(chain, authType);
        /*
        }
        */
    }
}
