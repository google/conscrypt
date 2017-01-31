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

package org.conscrypt.benchmarks;

import com.google.common.base.Charsets;
import com.google.common.io.BaseEncoding;
import com.google.common.io.CharStreams;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;
import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility methods to support testing.
 */
final class Util {
    private static final Pattern KEY_PATTERN =
            Pattern.compile("-+BEGIN\\s+.*PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+" + // Header
                            "([a-z0-9+/=\\r\\n]+)" + // Base64 text
                            "-+END\\s+.*PRIVATE\\s+KEY[^-]*-+", // Footer
                    Pattern.CASE_INSENSITIVE);

    private Util() {}

    /**
     * Load a file from the resources folder.
     *
     * @param name  name of a file in src/main/resources/certs.
     */
    static File loadCert(String name) {
        try {
            InputStream in = Util.class.getResourceAsStream("/certs/" + name);
            File tmpFile = File.createTempFile(name, "");
            tmpFile.deleteOnExit();

            BufferedWriter writer = new BufferedWriter(new FileWriter(tmpFile));
            try {
                int b;
                while ((b = in.read()) != -1) {
                    writer.write(b);
                }
            } finally {
                writer.close();
            }

            return tmpFile;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Initializes the given client-side {@code context} with an appropriate trust manager based on
     * the
     * {@code certChainFile} as its only root certificate.
     */
    static SSLContext initClientSslContext(SSLContext context, File certChainFile) {
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new BufferedInputStream(new FileInputStream(certChainFile)));
            X500Principal principal = cert.getSubjectX500Principal();
            ks.setCertificateEntry(principal.getName("RFC2253"), cert);

            // Set up trust manager factory to use our key store.
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(ks);
            context.init(null, trustManagerFactory.getTrustManagers(), null);
            return context;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Initializes the given server-side {@code context} with the
     */
    static SSLContext initServerContext(SSLContext context, File certChainFile, File keyFile) {
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);

            // Read the cert.
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new BufferedInputStream(new FileInputStream(certChainFile)));

            // Read the private key.
            byte[] keyData = readPrivateKey(keyFile);
            KeySpec keySpec = new PKCS8EncodedKeySpec(keyData);
            PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(keySpec);

            ks.setKeyEntry("key", key, new char[0], new Certificate[] {cert});
            KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, new char[0]);

            // Set up trust manager factory to use our key store.
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(ks);
            context.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            return context;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] readPrivateKey(File file) throws KeyException {
        String content = readPemFileContent(file);

        Matcher m = KEY_PATTERN.matcher(content);
        if (!m.find()) {
            throw new KeyException("could not find a PKCS #8 private key in input stream"
                    + " (see http://netty.io/wiki/sslcontextbuilder-and-private-key.html for more information)");
        }

        String data = m.group(1).replace("\n", "");
        return BaseEncoding.base64().decode(data);
    }

    private static String readPemFileContent(File file) {
        InputStream in = null;
        Reader reader = null;
        try {
            in = new FileInputStream(file);
            reader = new InputStreamReader(in, Charsets.US_ASCII);
            return CharStreams.toString(reader);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
                if (reader != null) {
                    reader.close();
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
