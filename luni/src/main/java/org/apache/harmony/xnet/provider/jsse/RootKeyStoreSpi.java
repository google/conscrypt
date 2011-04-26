/*
 * Copyright (C) 2011 The Android Open Source Project
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

package org.apache.harmony.xnet.provider.jsse;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.PublicKey;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import javax.security.auth.x500.X500Principal;
import libcore.io.IoUtils;

/**
 * A Root Certificate Authority (CA) store for Android
 *
 * This KeyStoreSpi provides a read-only view of the
 * TrustedCertificateEntry objects found in the
 * $ANDROID_ROOT/etc/security/cacerts/ directory. The alias names used
 * correspond to filenames in that directory, which themselves are
 * named based on the OpenSSL X509_NAME_hash_old function.  The
 * property that the filenames are based on a hash of the subject name
 * allows operations such as engineGetCertificateAlias to be
 * implemented efficiently without scanning the entire store.
 *
 * In addition to the KeyStoreSpi, RootKeyStoreSpi also provides the
 * additional public methods {@link #isTrustAnchor isTrustAnchor} and
 * {@link #findIssuer findIssuer} which allow efficient lookup
 * operations for CAs again based on the file naming convention.
 */
public final class RootKeyStoreSpi extends KeyStoreSpi {

    private static final File CA_CERTS_DIR
            = new File(System.getenv("ANDROID_ROOT") + "/etc/security/cacerts");

    private static final CertificateFactory CERT_FACTORY;
    static {
        try {
            CERT_FACTORY = CertificateFactory.getInstance("X509");
        } catch (CertificateException e) {
            throw new AssertionError(e);
        }
    }

    public RootKeyStoreSpi() {
        if (!CA_CERTS_DIR.isDirectory()) {
            throw new IllegalStateException(CA_CERTS_DIR + " is not a directory");
        }
    }

    @Override public Key engineGetKey(String alias, char[] password) {
        if (alias == null) {
            throw new NullPointerException("alias == null");
        }
        return null;
    }

    @Override public Certificate[] engineGetCertificateChain(String alias) {
        if (alias == null) {
            throw new NullPointerException("alias == null");
        }
        return null;
    }

    @Override public Certificate engineGetCertificate(String alias) {
        if (alias == null) {
            throw new NullPointerException("alias == null");
        }
        return getCertificate(new File(CA_CERTS_DIR, alias));
    }

    private static X509Certificate getCertificate(File file) {
        if (!file.isFile()) {
            return null;
        }
        InputStream is = null;
        try {
            is = new BufferedInputStream(new FileInputStream(file));
            return (X509Certificate) CERT_FACTORY.generateCertificate(is);
        } catch (IOException e) {
            return null;
        } catch (CertificateException e) {
            throw new AssertionError(e);
        } finally {
            IoUtils.closeQuietly(is);
        }
    }

    @Override public Date engineGetCreationDate(String alias) {
        if (alias == null) {
            throw new NullPointerException("alias == null");
        }
        File file = new File(CA_CERTS_DIR, alias);
        if (!file.isFile()) {
            return null;
        }
        long time = file.lastModified();
        if (time == 0) {
            return null;
        }
        return new Date(time);
    }

    @Override public void engineSetKeyEntry(
            String alias, Key key, char[] password, Certificate[] chain) {
        throw new UnsupportedOperationException();
    }

    @Override public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
        throw new UnsupportedOperationException();
    }

    @Override public void engineSetCertificateEntry(String alias, Certificate cert) {
        if (alias == null) {
            throw new NullPointerException("alias == null");
        }
        throw new UnsupportedOperationException();
    }

    @Override public void engineDeleteEntry(String alias) {
        throw new UnsupportedOperationException();
    }

    @Override public Enumeration<String> engineAliases() {
        return Collections.enumeration(Arrays.asList(CA_CERTS_DIR.list()));
    }

    @Override public boolean engineContainsAlias(String alias) {
        if (alias == null) {
            throw new NullPointerException("alias == null");
        }
        return new File(CA_CERTS_DIR, alias).isFile();
    }

    @Override public int engineSize() {
        return CA_CERTS_DIR.list().length;
    }

    @Override public boolean engineIsKeyEntry(String alias) {
        if (alias == null) {
            throw new NullPointerException("alias == null");
        }
        return false;
    }

    @Override public boolean engineIsCertificateEntry(String alias) {
        return engineContainsAlias(alias);
    }

    @Override public String engineGetCertificateAlias(Certificate c) {
        if (c == null || !(c instanceof X509Certificate)) {
            return null;
        }
        final X509Certificate x = (X509Certificate) c;
        // compare X509Certificate.getEncoded values
        CertSelector selector = new CertSelector() {
            public boolean match(Certificate cert) {
                return cert.equals(x);
            }
            public Object clone() {
                throw new UnsupportedOperationException();
            }
        };
        return findCert(x.getSubjectX500Principal(), selector, String.class);
    }

    /**
     * This non-{@code KeyStoreSpi} public interface is used by {@code
     * TrustManagerImpl} to locate a CA certificate with the same
     * public key as the provided {@code X509Certificate}. We match on
     * public key and not the certificate itself since a CA may be
     * reissued with the same PublicKey but different signature (for
     * example when switching signature from md2WithRSAEncryption to
     * SHA1withRSA)
     */
    public static final boolean isTrustAnchor(final X509Certificate x) {
        // compare X509Certificate.getPublicKey values
        CertSelector selector = new CertSelector() {
            public boolean match(Certificate c) {
                X509Certificate ca = (X509Certificate)c;
                PublicKey caPublic = ca.getPublicKey();
                PublicKey certPublic = x.getPublicKey();
                return caPublic != null && certPublic != null && caPublic.equals(certPublic);
            }
            public Object clone() {
                throw new UnsupportedOperationException();
            }
        };
        return findCert(x.getSubjectX500Principal(), selector, Boolean.class);
    }

    /**
     * This non-{@code KeyStoreSpi} public interface is used by {@code
     * TrustManagerImpl} to locate the CA certificate that signed the
     * provided {@code X509Certificate}.
     */
    public static final X509Certificate findIssuer(final X509Certificate x) {
        // match on verified issuer of Certificate
        CertSelector selector = new CertSelector() {
            public boolean match(Certificate c) {
                X509Certificate ca = (X509Certificate)c;
                try {
                    x.verify(ca.getPublicKey());
                    return true;
                } catch (Exception e) {
                    return false;
                }
            }
            public Object clone() {
                throw new UnsupportedOperationException();
            }
        };
        return findCert(x.getIssuerX500Principal(), selector, X509Certificate.class);
    }

    private static <T> T findCert(
            X500Principal subject, CertSelector selector, Class<T> desiredReturnType) {

        int intHash = NativeCrypto.X509_NAME_hash_old(subject);
        String strHash = IntegralToString.intToHexString(intHash, false, 8);

        for (int index = 0; true; index++) {
            String alias = strHash + "." + index;
            File file = new File(CA_CERTS_DIR, alias);
            if (!file.isFile()) {
                // could not find a match, no file exists, bail
                if (desiredReturnType == Boolean.class) {
                    return (T) Boolean.FALSE;
                }
                return null;
            }
            X509Certificate cert = getCertificate(file);
            if (selector.match(cert)) {
                if (desiredReturnType == X509Certificate.class) {
                    return (T) cert;
                }
                if (desiredReturnType == Boolean.class) {
                    return (T) Boolean.TRUE;
                }
                if (desiredReturnType == String.class) {
                    return (T) alias;
                }
                throw new AssertionError();
            }
        }
    }

    @Override public void engineStore(OutputStream stream, char[] password) {
        throw new UnsupportedOperationException();
    }

    @Override public void engineLoad(InputStream stream, char[] password) {
        if (stream != null) {
            throw new UnsupportedOperationException();
        }
    }
}
