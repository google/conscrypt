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
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

/**
 * A stub for platform-specific methods. This is included only for building purposes and should
 * be overridden in the platform-specific builds.
 */
final class Platform {
    private Platform() {}

    static void setup() {
        throw new UnsupportedOperationException();
    }

    static FileDescriptor getFileDescriptor(@SuppressWarnings("unused") Socket s) {
        throw new UnsupportedOperationException();
    }

    static FileDescriptor getFileDescriptorFromSSLSocket(
            @SuppressWarnings("unused") OpenSSLSocketImpl openSSLSocketImpl) {
        throw new UnsupportedOperationException();
    }

    static String getCurveName(@SuppressWarnings("unused") ECParameterSpec spec) {
        throw new UnsupportedOperationException();
    }

    static void setCurveName(@SuppressWarnings("unused") ECParameterSpec spec,
            @SuppressWarnings("unused") String curveName) {
        // This doesn't appear to be needed.
        throw new UnsupportedOperationException();
    }

    static void setSocketWriteTimeout(@SuppressWarnings("unused") Socket s,
            @SuppressWarnings("unused") long timeoutMillis) throws SocketException {
        throw new UnsupportedOperationException();
    }

    static void setSSLParameters(@SuppressWarnings("unused") SSLParameters params,
            @SuppressWarnings("unused") SSLParametersImpl impl,
            @SuppressWarnings("unused") OpenSSLSocketImpl socket) {
        throw new UnsupportedOperationException();
    }

    static void getSSLParameters(@SuppressWarnings("unused") SSLParameters params,
            @SuppressWarnings("unused") SSLParametersImpl impl,
            @SuppressWarnings("unused") OpenSSLSocketImpl socket) {
        throw new UnsupportedOperationException();
    }

    static void checkClientTrusted(@SuppressWarnings("unused") X509TrustManager tm,
            @SuppressWarnings("unused") X509Certificate[] chain,
            @SuppressWarnings("unused") String authType,
            @SuppressWarnings("unused") OpenSSLSocketImpl socket) throws CertificateException {
        throw new UnsupportedOperationException();
    }

    static void checkServerTrusted(@SuppressWarnings("unused") X509TrustManager tm,
            @SuppressWarnings("unused") X509Certificate[] chain,
            @SuppressWarnings("unused") String authType,
            @SuppressWarnings("unused") OpenSSLSocketImpl socket) throws CertificateException {
        throw new UnsupportedOperationException();
    }

    static void checkClientTrusted(@SuppressWarnings("unused") X509TrustManager tm,
            @SuppressWarnings("unused") X509Certificate[] chain,
            @SuppressWarnings("unused") String authType,
            @SuppressWarnings("unused") OpenSSLEngineImpl engine) throws CertificateException {
        throw new UnsupportedOperationException();
    }

    static void checkServerTrusted(@SuppressWarnings("unused") X509TrustManager tm,
            @SuppressWarnings("unused") X509Certificate[] chain,
            @SuppressWarnings("unused") String authType,
            @SuppressWarnings("unused") OpenSSLEngineImpl engine) throws CertificateException {
        throw new UnsupportedOperationException();
    }

    /**
     * Wraps an old AndroidOpenSSL key instance. This is not needed on RI.
     */
    static OpenSSLKey wrapRsaKey(@SuppressWarnings("unused") PrivateKey javaKey) {
        throw new UnsupportedOperationException();
    }

    /**
     * Logs to the system EventLog system.
     */
    static void logEvent(@SuppressWarnings("unused") String message) {
        throw new UnsupportedOperationException();
    }

    /**
     * Returns true if the supplied hostname is an literal IP address.
     */
    static boolean isLiteralIpAddress(@SuppressWarnings("unused") String hostname) {
        throw new UnsupportedOperationException();
    }

    /**
     * Currently we don't wrap anything from the RI.
     */
    static SSLSocketFactory wrapSocketFactoryIfNeeded(
            @SuppressWarnings("unused") OpenSSLSocketFactoryImpl factory) {
        throw new UnsupportedOperationException();
    }

    /**
     * Convert from platform's GCMParameterSpec to our internal version.
     */
    static GCMParameters fromGCMParameterSpec(
            @SuppressWarnings("unused") AlgorithmParameterSpec params) {
        throw new UnsupportedOperationException();
    }

    /**
     * Creates a platform version of {@code GCMParameterSpec}.
     */
    static AlgorithmParameterSpec toGCMParameterSpec(
            @SuppressWarnings("unused") int tagLenInBits, @SuppressWarnings("unused") byte[] iv) {
        throw new UnsupportedOperationException();
    }

    /*
     * CloseGuard functions.
     */

    static Object closeGuardGet() {
        throw new UnsupportedOperationException();
    }

    static void closeGuardOpen(@SuppressWarnings("unused") Object guardObj,
            @SuppressWarnings("unused") String message) {
        throw new UnsupportedOperationException();
    }

    static void closeGuardClose(@SuppressWarnings("unused") Object guardObj) {
        throw new UnsupportedOperationException();
    }

    static void closeGuardWarnIfOpen(@SuppressWarnings("unused") Object guardObj) {
        throw new UnsupportedOperationException();
    }

    /*
     * BlockGuard functions.
     */

    static void blockGuardOnNetwork() {
        throw new UnsupportedOperationException();
    }

    /**
     * OID to Algorithm Name mapping.
     */
    static String oidToAlgorithmName(@SuppressWarnings("unused") String oid) {
        throw new UnsupportedOperationException();
    }

    /*
     * Pre-Java-8 backward compatibility.
     */

    static SSLSession wrapSSLSession(
            @SuppressWarnings("unused") AbstractOpenSSLSession sslSession) {
        throw new UnsupportedOperationException();
    }

    static SSLSession unwrapSSLSession(@SuppressWarnings("unused") SSLSession sslSession) {
        throw new UnsupportedOperationException();
    }

    /*
     * Pre-Java-7 backward compatibility.
     */

    static String getHostStringFromInetSocketAddress(
            @SuppressWarnings("unused") InetSocketAddress addr) {
        throw new UnsupportedOperationException();
    }

    /**
     * Check if SCT verification is required for a given hostname.
     *
     * SCT Verification is enabled using {@code Security} properties.
     * The "conscrypt.ct.enable" property must be true, as well as a per domain property.
     * The reverse notation of the domain name, prefixed with "conscrypt.ct.enforce."
     * is used as the property name.
     * Basic globbing is also supported.
     *
     * For example, for the domain foo.bar.com, the following properties will be
     * looked up, in order of precedence.
     * - conscrypt.ct.enforce.com.bar.foo
     * - conscrypt.ct.enforce.com.bar.*
     * - conscrypt.ct.enforce.com.*
     * - conscrypt.ct.enforce.*
     */
    static boolean isCTVerificationRequired(@SuppressWarnings("unused") String hostname) {
        throw new UnsupportedOperationException();
    }
}
