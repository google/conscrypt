/*
 * Copyright (C) 2008 The Android Open Source Project
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.bouncycastle.openssl.PEMWriter;

/**
 * Provides the Java side of our JNI glue for OpenSSL. Currently only hashing
 * and verifying are covered. Is expected to grow over time. Also needs to move
 * into libcore/openssl at some point.
 */
public class NativeCrypto {

    // --- OpenSSL library initialization --------------------------------------
    static {
        clinit();
    }

    private native static void clinit();

    // --- DSA/RSA public/private key handling functions -----------------------

    public static native int EVP_PKEY_new_DSA(byte[] p, byte[] q, byte[] g, byte[] priv_key, byte[] pub_key);

    public static native int EVP_PKEY_new_RSA(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q);

    public static native void EVP_PKEY_free(int pkey);

    // --- General context handling functions (despite the names) --------------

    public static native int EVP_new();

    public static native void EVP_free(int ctx);

    // --- Digest handling functions -------------------------------------------

    public static native void EVP_DigestInit(int ctx, String algorithm);

    public static native void EVP_DigestUpdate(int ctx, byte[] buffer, int offset, int length);

    public static native int EVP_DigestFinal(int ctx, byte[] hash, int offset);

    public static native int EVP_DigestSize(int ctx);

    public static native int EVP_DigestBlockSize(int ctx);

    // --- Signature handling functions ----------------------------------------

    public static native void EVP_VerifyInit(int ctx, String algorithm);

    public static native void EVP_VerifyUpdate(int ctx, byte[] buffer, int offset, int length);

    public static native int EVP_VerifyFinal(int ctx, byte[] signature, int offset, int length, int key);

    // --- SSL handling --------------------------------------------------------

    private static final String SUPPORTED_PROTOCOL_SSLV3 = "SSLv3";
    private static final String SUPPORTED_PROTOCOL_TLSV1 = "TLSv1";

    // SSL mode
    public static long SSL_MODE_HANDSHAKE_CUTTHROUGH = 0x00000040L;

    // SSL options
    public static long SSL_OP_NO_SSLv3 = 0x02000000L;
    public static long SSL_OP_NO_TLSv1 = 0x04000000L;

    public static native int SSL_CTX_new();

    public static native String[] SSL_CTX_get_ciphers(int ssl_ctx);

    public static String[] getDefaultCipherSuites() {
        int ssl_ctx = SSL_CTX_new();
        String[] supportedCiphers = SSL_CTX_get_ciphers(ssl_ctx);
        SSL_CTX_free(ssl_ctx);
        return supportedCiphers;
    }

    public static String[] getSupportedCipherSuites() {
        // TODO really return full cipher list
        return getDefaultCipherSuites();
    }

    public static native void SSL_CTX_free(int ssl_ctx);

    public static native int SSL_new(int ssl_ctx, String privatekey, String certificate, byte[] seed) throws IOException;

    /**
     * Initialize the SSL socket and set the certificates for the
     * future handshaking.
     */
    public static int SSL_new(SSLParameters sslParameters) throws IOException {
        boolean client = sslParameters.getUseClientMode();

        final int ssl_ctx = (client) ?
            sslParameters.getClientSessionContext().sslCtxNativePointer :
            sslParameters.getServerSessionContext().sslCtxNativePointer;

        // TODO support more than RSA certificates?  non-openssl
        // SSLEngine implementation did these callbacks during
        // handshake after selecting cipher suite, not before
        // handshake. Should do the same via SSL_CTX_set_client_cert_cb
        final String alias = (client) ?
            sslParameters.getKeyManager().chooseClientAlias(new String[] { "RSA" }, null, null) :
            sslParameters.getKeyManager().chooseServerAlias("RSA", null, null);

        final String privateKeyString;
        final String certificateString;
        if (alias == null) {
            privateKeyString = null;
            certificateString = null;
        } else {
            PrivateKey privateKey = sslParameters.getKeyManager().getPrivateKey(alias);
            X509Certificate[] certificates = sslParameters.getKeyManager().getCertificateChain(alias);

            ByteArrayOutputStream privateKeyOS = new ByteArrayOutputStream();
            PEMWriter privateKeyPEMWriter = new PEMWriter(new OutputStreamWriter(privateKeyOS));
            privateKeyPEMWriter.writeObject(privateKey);
            privateKeyPEMWriter.close();
            privateKeyString = privateKeyOS.toString();

            ByteArrayOutputStream certificateOS = new ByteArrayOutputStream();
            PEMWriter certificateWriter = new PEMWriter(new OutputStreamWriter(certificateOS));

            for (X509Certificate certificate : certificates) {
                certificateWriter.writeObject(certificate);
            }
            certificateWriter.close();
            certificateString = certificateOS.toString();
        }

        final byte[] seed = (sslParameters.getSecureRandomMember() != null) ?
            sslParameters.getSecureRandomMember().generateSeed(1024) :
            null;

        return SSL_new(ssl_ctx,
                       privateKeyString,
                       certificateString,
                       seed);
    }


    public static native long SSL_get_mode(int ssl);

    public static native long SSL_set_mode(int ssl, long mode);

    public static native long SSL_clear_mode(int ssl, long mode);

    public static native long SSL_get_options(int ssl);

    public static native long SSL_set_options(int ssl, long options);

    public static native long SSL_clear_options(int ssl, long options);

    public static String[] getSupportedProtocols() {
        return new String[] { SUPPORTED_PROTOCOL_SSLV3, SUPPORTED_PROTOCOL_TLSV1 };
    }

    public static String[] getEnabledProtocols(int ssl) {
        long options = SSL_get_options(ssl);
        ArrayList<String> array = new ArrayList<String>();
        if ((options & NativeCrypto.SSL_OP_NO_SSLv3) == 0) {
            array.add(SUPPORTED_PROTOCOL_SSLV3);
        }
        if ((options & NativeCrypto.SSL_OP_NO_TLSv1) == 0) {
            array.add(SUPPORTED_PROTOCOL_TLSV1);
        }
        return array.toArray(new String[array.size()]);
    }

    public static void setEnabledProtocols(int ssl, String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("protocols == null");
        }

        // openssl uses negative logic letting you disable protocols.
        // so first, assume we need to set all (disable all ) and clear none (enable none).
        // in the loop, selectively move bits from set to clear (from disable to enable)
        long optionsToSet = (SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
        long optionsToClear = 0;
        for (int i = 0; i < protocols.length; i++) {
            String protocol = protocols[i];
            if (protocol == null) {
                throw new IllegalArgumentException("protocols[" + i + "] == null");
            }
            if (protocol.equals(SUPPORTED_PROTOCOL_SSLV3)) {
                optionsToSet &= ~SSL_OP_NO_SSLv3;
                optionsToClear |= SSL_OP_NO_SSLv3;
            } else if (protocol.equals(SUPPORTED_PROTOCOL_TLSV1)) {
                optionsToSet &= ~SSL_OP_NO_TLSv1;
                optionsToClear |= SSL_OP_NO_TLSv1;
            } else {
                throw new IllegalArgumentException("Protocol " + protocol +
                                                   " is not supported");
            }
        }

        SSL_set_options(ssl, optionsToSet);
        SSL_clear_options(ssl, optionsToClear);
    }

    public static String[] checkEnabledProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("protocols parameter is null");
        }
        for (int i = 0; i < protocols.length; i++) {
            String protocol = protocols[i];
            if (protocol == null) {
                throw new IllegalArgumentException("protocols[" + i + "] == null");
            }
            if ((!protocol.equals(SUPPORTED_PROTOCOL_SSLV3))
                && (!protocol.equals(SUPPORTED_PROTOCOL_TLSV1))) {
                throw new IllegalArgumentException("Protocol " + protocol +
                                                   " is not supported");
            }
        }
        return protocols;
    }

    public static native String[] SSL_get_ciphers(int ssl);

    public static native void SSL_set_cipher_list(int ssl, String ciphers);

    public static void setEnabledCipherSuites(int ssl, String[] cipherSuites) {
        checkEnabledCipherSuites(cipherSuites);
        String controlString = "";
        for (int i = 0; i < cipherSuites.length; i++) {
            String cipherSuite = cipherSuites[i];
            if (i == 0) {
                controlString = cipherSuite;
            } else {
                controlString += ":" + cipherSuite;
            }
        }
        SSL_set_cipher_list(ssl, controlString);
    }

    public static String[] checkEnabledCipherSuites(String[] cipherSuites) {
        if (cipherSuites == null) {
            throw new IllegalArgumentException("cipherSuites == null");
        }
        // makes sure all suites are valid, throwing on error
        String[] supportedCipherSuites = getSupportedCipherSuites();
        for (int i = 0; i < cipherSuites.length; i++) {
            String cipherSuite = cipherSuites[i];
            if (cipherSuite == null) {
                throw new IllegalArgumentException("cipherSuites[" + i + "] == null");
            }
            findSuite(supportedCipherSuites, cipherSuite);
        }
        return cipherSuites;
    }

    private static void findSuite(String[] supportedCipherSuites, String suite) {
        for (String supportedCipherSuite : supportedCipherSuites) {
            if (supportedCipherSuite.equals(suite)) {
                return;
            }
        }
        throw new IllegalArgumentException("Protocol " + suite + " is not supported.");
    }

    /*
     * See the OpenSSL ssl.h header file for more information.
     */
    public static final int SSL_VERIFY_NONE =                 0x00;
    public static final int SSL_VERIFY_PEER =                 0x01;
    public static final int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
    public static final int SSL_VERIFY_CLIENT_ONCE =          0x04;

    public static native void SSL_set_verify(int sslNativePointer, int mode) throws IOException;

    public static native void SSL_set_session(int sslNativePointer, int sslSessionNativePointer) throws IOException;

    public static native void SSL_set_session_creation_enabled(int sslNativePointer, boolean creationEnabled) throws IOException;

    /**
     * Returns the sslSessionNativePointer of the negotiated session
     */
    public static native int SSL_do_handshake(int sslNativePointer, Socket sock,
                                              CertificateChainVerifier ccv, HandshakeCompletedCallback hcc,
                                              int timeout, boolean client_mode) throws IOException, CertificateException;

    public static native byte[][] SSL_get_certificate(int sslNativePointer);

    public static native void SSL_free(int sslNativePointer);

    public interface CertificateChainVerifier {
        /**
         * Verify that we trust the certificate chain is trusted.
         *
         * @param bytes An array of certficates in PEM encode bytes
         * @param authMethod auth algorithm name
         *
         * @throws CertificateException if the certificate is untrusted
         */
        public void verifyCertificateChain(byte[][] bytes, String authMethod) throws CertificateException;
    }

    public interface HandshakeCompletedCallback {
        /**
         * Called when SSL handshake is completed. Note that this can
         * be after SSL_do_handshake returns when handshake cutthrough
         * is enabled.
         */
        public void handshakeCompleted();
    }
}
