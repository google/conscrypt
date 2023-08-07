/*
 * Copyright 2023 The Android Open Source Project
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

/*
 * Copyright 2013 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.conscrypt;

import org.conscrypt.ct.CTLogStore;
import org.conscrypt.ct.CTPolicy;

import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.AlgorithmParameters;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

final class Platform {
    private Platform() {}

    static void setup() {
        throw new RuntimeException("Stub!");
    }

    static File createTempFile(String prefix, String suffix, File directory) {
        throw new RuntimeException("Stub!");
    }

    static String getDefaultProviderName() {
	throw new RuntimeException("Stub!");
    }

    static boolean provideTrustManagerByDefault() {
	throw new RuntimeException("Stub!");
    }

    static boolean canExecuteExecutable(File file) throws IOException {
	throw new RuntimeException("Stub!");
    }

    static FileDescriptor getFileDescriptor(Socket s) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static FileDescriptor getFileDescriptorFromSSLSocket(AbstractConscryptSocket socket) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static String getCurveName(ECParameterSpec spec) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void setCurveName(@SuppressWarnings("unused") ECParameterSpec spec,
            @SuppressWarnings("unused") String curveName) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void setSocketWriteTimeout(@SuppressWarnings("unused") Socket s,
            @SuppressWarnings("unused") long timeoutMillis) throws SocketException {
	throw new RuntimeException("Stub!");
    }

    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
	throw new RuntimeException("Stub!");
    }

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
	throw new RuntimeException("Stub!");
    }

    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
	throw new RuntimeException("Stub!");
    }

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void setEndpointIdentificationAlgorithm(
            SSLParameters params, String endpointIdentificationAlgorithm) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static String getEndpointIdentificationAlgorithm(SSLParameters params) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            AbstractConscryptSocket socket) throws CertificateException {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            AbstractConscryptSocket socket) throws CertificateException {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            ConscryptEngine engine) throws CertificateException {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            ConscryptEngine engine) throws CertificateException {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static OpenSSLKey wrapRsaKey(@SuppressWarnings("unused") PrivateKey javaKey) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void logEvent(@SuppressWarnings("unused") String message) {
        throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static boolean isSniEnabledByDefault() {
	throw new RuntimeException("Stub!");
    }

    static SSLEngine wrapEngine(ConscryptEngine engine) {
	throw new RuntimeException("Stub!");
    }

    static SSLEngine unwrapEngine(SSLEngine engine) {
	throw new RuntimeException("Stub!");
    }

    static ConscryptEngineSocket createEngineSocket(SSLParametersImpl sslParameters)
            throws IOException {
	throw new RuntimeException("Stub!");
    }

    static ConscryptEngineSocket createEngineSocket(String hostname, int port,
            SSLParametersImpl sslParameters) throws IOException {
	throw new RuntimeException("Stub!");
    }

    static ConscryptEngineSocket createEngineSocket(InetAddress address, int port,
            SSLParametersImpl sslParameters) throws IOException {
	throw new RuntimeException("Stub!");
    }

    static ConscryptEngineSocket createEngineSocket(String hostname, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
	throw new RuntimeException("Stub!");
    }

    static ConscryptEngineSocket createEngineSocket(InetAddress address, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
	throw new RuntimeException("Stub!");
    }

    static ConscryptEngineSocket createEngineSocket(Socket socket, String hostname, int port,
            boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
	throw new RuntimeException("Stub!");
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(SSLParametersImpl sslParameters)
            throws IOException {
	throw new RuntimeException("Stub!");
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(String hostname, int port,
            SSLParametersImpl sslParameters) throws IOException {
	throw new RuntimeException("Stub!");
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(InetAddress address, int port,
            SSLParametersImpl sslParameters) throws IOException {
	throw new RuntimeException("Stub!");
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(String hostname, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
	throw new RuntimeException("Stub!");
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(InetAddress address, int port,
            InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters)
            throws IOException {
	throw new RuntimeException("Stub!");
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(Socket socket, String hostname,
            int port, boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static SSLSocketFactory wrapSocketFactoryIfNeeded(OpenSSLSocketFactoryImpl factory) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static GCMParameters fromGCMParameterSpec(AlgorithmParameterSpec params) {
	throw new RuntimeException("Stub!");
    }

    static AlgorithmParameterSpec fromGCMParameters(AlgorithmParameters params) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static AlgorithmParameterSpec toGCMParameterSpec(int tagLenInBits, byte[] iv) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static Object closeGuardGet() {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void closeGuardOpen(@SuppressWarnings("unused") Object guardObj,
            @SuppressWarnings("unused") String message) {
        throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void closeGuardClose(@SuppressWarnings("unused") Object guardObj) {
        throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void closeGuardWarnIfOpen(@SuppressWarnings("unused") Object guardObj) {
        throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void blockGuardOnNetwork() {
        throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static String oidToAlgorithmName(String oid) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static SSLSession wrapSSLSession(ExternalSession sslSession) {
	throw new RuntimeException("Stub!");
    }

    public static String getOriginalHostNameFromInetAddress(InetAddress addr) {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static String getHostStringFromInetSocketAddress(InetSocketAddress addr) {
	throw new RuntimeException("Stub!");
    }

    static boolean supportsX509ExtendedTrustManager() {
	throw new RuntimeException("Stub!");
    }

    static boolean isCTVerificationRequired(String hostname) {
	throw new RuntimeException("Stub!");
    }

    static boolean supportsConscryptCertStore() {
	throw new RuntimeException("Stub!");
    }

    static KeyStore getDefaultCertKeyStore() throws KeyStoreException {
	throw new RuntimeException("Stub!");
    }

    static ConscryptCertStore newDefaultCertStore() {
	throw new RuntimeException("Stub!");
    }

    static CertBlocklist newDefaultBlocklist() {
	throw new RuntimeException("Stub!");
    }

    static CTLogStore newDefaultLogStore() {
	throw new RuntimeException("Stub!");
    }

    static CTPolicy newDefaultPolicy(CTLogStore logStore) {
	throw new RuntimeException("Stub!");
    }

    static boolean serverNamePermitted(SSLParametersImpl parameters, String serverName) {
	throw new RuntimeException("Stub!");
    }

  @SuppressWarnings("unused")
    public static ConscryptHostnameVerifier getDefaultHostnameVerifier() {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static long getMillisSinceBoot() {
	throw new RuntimeException("Stub!");
    }

    @SuppressWarnings("unused")
    static void countTlsHandshake(
            boolean success, String protocol, String cipherSuite, long duration) {
        throw new RuntimeException("Stub!");
    }

    public static boolean isJavaxCertificateSupported() {
	throw new RuntimeException("Stub!");
    }
}
