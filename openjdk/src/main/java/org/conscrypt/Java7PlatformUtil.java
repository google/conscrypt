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

import static java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.attribute.PosixFilePermission;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.Set;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Utility methods supported on Java 7+.
 */
final class Java7PlatformUtil {
    static String getHostStringFromInetSocketAddress(InetSocketAddress addr) {
        return addr.getHostString();
    }

    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            AbstractConscryptSocket socket) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkClientTrusted(chain, authType, socket);
        } else {
            tm.checkClientTrusted(chain, authType);
        }
    }

    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            AbstractConscryptSocket socket) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkServerTrusted(chain, authType, socket);
        } else {
            tm.checkServerTrusted(chain, authType);
        }
    }

    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            ConscryptEngine engine) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkClientTrusted(chain, authType, engine);
        } else {
            tm.checkClientTrusted(chain, authType);
        }
    }

    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType,
            ConscryptEngine engine) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) tm;
            x509etm.checkServerTrusted(chain, authType, engine);
        } else {
            tm.checkServerTrusted(chain, authType);
        }
    }

    static void setSSLParameters(SSLParameters params, SSLParametersImpl impl) {
        impl.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
    }

    static void getSSLParameters(SSLParameters params, SSLParametersImpl impl) {
        params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
    }

    static void addSuppressed(Throwable t, Throwable suppressed) {
        t.addSuppressed(suppressed);
    }

    static boolean canExecuteExecutable(File file) throws IOException {
        // If we can already execute, there is nothing to do.
        if (file.canExecute()) {
            return true;
        }

        // On volumes, with noexec set, even files with the executable POSIX permissions will
        // fail to execute. The File#canExecute() method honors this behavior, probaby via
        // parsing the noexec flag when initializing the UnixFileStore, though the flag is not
        // exposed via a public API.  To find out if library is being loaded off a volume with
        // noexec, confirm or add executalbe permissions, then check File#canExecute().

        // Note: We use FQCN to not break when used in java6
        Set<PosixFilePermission> existingFilePermissions =
                java.nio.file.Files.getPosixFilePermissions(file.toPath());
        Set<java.nio.file.attribute.PosixFilePermission> executePermissions =
                EnumSet.of(OWNER_EXECUTE, GROUP_EXECUTE, OTHERS_EXECUTE);
        if (existingFilePermissions.containsAll(executePermissions)) {
            return false;
        }

        Set<java.nio.file.attribute.PosixFilePermission> newPermissions =
                EnumSet.copyOf(existingFilePermissions);
        newPermissions.addAll(executePermissions);
        java.nio.file.Files.setPosixFilePermissions(file.toPath(), newPermissions);
        return file.canExecute();
    }

    static SSLSession wrapSSLSession(ConscryptSession sslSession) {
        return new Java7ExtendedSSLSession(sslSession);
    }

    private Java7PlatformUtil() {}
}
