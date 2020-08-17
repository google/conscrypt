/*
 * Copyright (C) 2016 The Android Open Source Project
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
 * Copyright 2016 The Netty Project
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

import static java.lang.Math.min;
import static org.conscrypt.NativeConstants.SSL3_RT_ALERT;
import static org.conscrypt.NativeConstants.SSL3_RT_APPLICATION_DATA;
import static org.conscrypt.NativeConstants.SSL3_RT_CHANGE_CIPHER_SPEC;
import static org.conscrypt.NativeConstants.SSL3_RT_HANDSHAKE;
import static org.conscrypt.NativeConstants.SSL3_RT_HEADER_LENGTH;
import static org.conscrypt.NativeConstants.SSL3_RT_MAX_PACKET_SIZE;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.cert.CertificateException;

/**
 * Utility methods for SSL packet processing. Copied from the Netty project.
 * <p>
 * This is a public class to allow testing to occur on Android via CTS.
 */
final class SSLUtils {
    static final boolean USE_ENGINE_SOCKET_BY_DEFAULT = Boolean.parseBoolean(
            System.getProperty("org.conscrypt.useEngineSocketByDefault", "true"));
    private static final int MAX_PROTOCOL_LENGTH = 255;

    private static final Charset US_ASCII = Charset.forName("US-ASCII");

    // TODO(nathanmittler): Should these be in NativeConstants?
    enum SessionType {
        /**
         * Identifies OpenSSL sessions.
         */
        OPEN_SSL(1),

        /**
         * Identifies OpenSSL sessions with OCSP stapled data.
         */
        OPEN_SSL_WITH_OCSP(2),

        /**
         * Identifies OpenSSL sessions with TLS SCT data.
         */
        OPEN_SSL_WITH_TLS_SCT(3);

        SessionType(int value) {
            this.value = value;
        }

        static boolean isSupportedType(int type) {
            return type == OPEN_SSL.value || type == OPEN_SSL_WITH_OCSP.value
                    || type == OPEN_SSL_WITH_TLS_SCT.value;
        }

        final int value;
    }

    /**
     * States for SSL engines.
     */
    static final class EngineStates {
        private EngineStates() {}

        /**
         * The engine is constructed, but the initial handshake hasn't been started
         */
        static final int STATE_NEW = 0;

        /**
         * The client/server mode of the engine has been set.
         */
        static final int STATE_MODE_SET = 1;

        /**
         * The handshake has been started
         */
        static final int STATE_HANDSHAKE_STARTED = 2;

        /**
         * Listeners of the handshake have been notified of completion but the handshake call
         * hasn't returned.
         */
        static final int STATE_HANDSHAKE_COMPLETED = 3;

        /**
         * The handshake call returned but the listeners have not yet been notified. This is expected
         * behaviour in cut-through mode, where SSL_do_handshake returns before the handshake is
         * complete. We can now start writing data to the socket.
         */
        static final int STATE_READY_HANDSHAKE_CUT_THROUGH = 4;

        /**
         * The handshake call has returned and the listeners have been notified. Ready to begin
         * writing data.
         */
        static final int STATE_READY = 5;

        /**
         * The inbound direction of the engine has been closed.
         */
        static final int STATE_CLOSED_INBOUND = 6;

        /**
         * The outbound direction of the engine has been closed.
         */
        static final int STATE_CLOSED_OUTBOUND = 7;

        /**
         * The engine has been closed.
         */
        static final int STATE_CLOSED = 8;
    }

    /**
     * This is the maximum overhead when encrypting plaintext as defined by
     * <a href="https://www.ietf.org/rfc/rfc5246.txt">rfc5264</a>,
     * <a href="https://www.ietf.org/rfc/rfc5289.txt">rfc5289</a>, and the BoringSSL
     * implementation itself.
     *
     * Please note that we use a padding of 16 here as BoringSSL uses PKCS#5 which uses 16 bytes
     * while the spec itself allow up to 255 bytes. 16 bytes is the max for PKCS#5 (which handles it
     * the same way as PKCS#7) as we use a block size of 16. See <a
     * href="https://tools.ietf.org/html/rfc5652#section-6.3">rfc5652#section-6.3</a>.
     *
     * 16 (IV) + 48 (MAC) + 1 (Padding_length field) + 15 (Padding)
     * + 1 (ContentType in TLSCiphertext) + 2 (ProtocolVersion) + 2 (Length)
     * + 1 (ContentType in TLSInnerPlaintext)
     */
    private static final int MAX_ENCRYPTION_OVERHEAD_LENGTH = 15 + 48 + 1 + 16 + 1 + 2 + 2 + 1;

    private static final int MAX_ENCRYPTION_OVERHEAD_DIFF =
            Integer.MAX_VALUE - MAX_ENCRYPTION_OVERHEAD_LENGTH;

    /** Key type: RSA certificate. */
    private static final String KEY_TYPE_RSA = "RSA";

    /** Key type: Elliptic Curve certificate. */
    private static final String KEY_TYPE_EC = "EC";

    static X509Certificate[] decodeX509CertificateChain(byte[][] certChain)
            throws java.security.cert.CertificateException {
        CertificateFactory certificateFactory = getCertificateFactory();
        int numCerts = certChain.length;
        X509Certificate[] decodedCerts = new X509Certificate[numCerts];
        for (int i = 0; i < numCerts; i++) {
            decodedCerts[i] = decodeX509Certificate(certificateFactory, certChain[i]);
        }
        return decodedCerts;
    }

    private static CertificateFactory getCertificateFactory() {
        try {
            return CertificateFactory.getInstance("X.509");
        } catch (java.security.cert.CertificateException e) {
            return null;
        }
    }

    private static X509Certificate decodeX509Certificate(CertificateFactory certificateFactory,
            byte[] bytes) throws java.security.cert.CertificateException {
        if (certificateFactory != null) {
            return (X509Certificate) certificateFactory.generateCertificate(
                    new ByteArrayInputStream(bytes));
        }
        return OpenSSLX509Certificate.fromX509Der(bytes);
    }

    /**
     * Returns key type constant suitable for calling X509KeyManager.chooseServerAlias or
     * X509ExtendedKeyManager.chooseEngineServerAlias. Returns {@code null} for key exchanges that
     * do not use X.509 for server authentication.
     */
    static String getServerX509KeyType(long sslCipherNative) {
        String kx_name = NativeCrypto.SSL_CIPHER_get_kx_name(sslCipherNative);
        if (kx_name.equals("RSA") || kx_name.equals("DHE_RSA") || kx_name.equals("ECDHE_RSA")) {
            return KEY_TYPE_RSA;
        } else if (kx_name.equals("ECDHE_ECDSA")) {
            return KEY_TYPE_EC;
        } else {
            return null;
        }
    }

    /**
     * Similar to getServerKeyType, but returns value given TLS
     * ClientCertificateType byte values from a CertificateRequest
     * message for use with X509KeyManager.chooseClientAlias or
     * X509ExtendedKeyManager.chooseEngineClientAlias.
     * <p>
     * Visible for testing.
     */
    static String getClientKeyType(byte clientCertificateType) {
        // See also
        // https://www.ietf.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-2
        switch (clientCertificateType) {
            case NativeConstants.TLS_CT_RSA_SIGN:
                return KEY_TYPE_RSA; // RFC rsa_sign
            case NativeConstants.TLS_CT_ECDSA_SIGN:
                return KEY_TYPE_EC; // RFC ecdsa_sign
            default:
                return null;
        }
    }

    static String getClientKeyTypeFromSignatureAlg(int signatureAlg) {
        // See also
        // https://www.ietf.org/assignments/tls-parameters/tls-parameters.xml#tls-signaturescheme
        switch (NativeCrypto.SSL_get_signature_algorithm_key_type(signatureAlg)) {
            case NativeConstants.EVP_PKEY_RSA:
                return KEY_TYPE_RSA;
            case NativeConstants.EVP_PKEY_EC:
                return KEY_TYPE_EC;
            default:
                return null;
        }
    }

    /**
     * Gets the supported key types for client certificates based on the
     * {@code ClientCertificateType} values provided by the server.
     *
     * @param clientCertificateTypes
     *         {@code ClientCertificateType} values provided by the server.
     *         See https://www.ietf.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-2.
     * @param signatureAlgs
     *         {@code SignatureScheme} values provided by the server.
     *         See https://www.ietf.org/assignments/tls-parameters/tls-parameters.xml#tls-signaturescheme
     * @return supported key types that can be used in {@code X509KeyManager.chooseClientAlias} and
     * {@code X509ExtendedKeyManager.chooseEngineClientAlias}.  If the inputs imply a preference
     * order, the returned set will have an iteration order that respects that preference order,
     * otherwise it will be in an arbitrary order.
     *
     * Visible for testing.
     */
    static Set<String> getSupportedClientKeyTypes(byte[] clientCertificateTypes,
            int[] signatureAlgs) {
        Set<String> fromClientCerts = new HashSet<String>(clientCertificateTypes.length);
        for (byte keyTypeCode : clientCertificateTypes) {
            String keyType = SSLUtils.getClientKeyType(keyTypeCode);
            if (keyType == null) {
                // Unsupported client key type -- ignore
                continue;
            }
            fromClientCerts.add(keyType);
        }
        // Signature algorithms are listed in preference order
        Set<String> fromSigAlgs = new LinkedHashSet<String>(signatureAlgs.length);
        for (int signatureAlg : signatureAlgs) {
            String keyType = SSLUtils.getClientKeyTypeFromSignatureAlg(signatureAlg);
            if (keyType == null) {
                // Unsupported client key type -- ignore
                continue;
            }
            fromSigAlgs.add(keyType);
        }
        // If both are specified, the key needs to meet both sets of requirements.  Otherwise,
        // just meet the set of requirements that were specified.  See RFC 5246, section 7.4.4.
        // (In TLS 1.3, certificate_types is no longer used and is never present.)
        if (clientCertificateTypes.length > 0 && signatureAlgs.length > 0) {
            fromSigAlgs.retainAll(fromClientCerts);
            return fromSigAlgs;
        } else if (signatureAlgs.length > 0) {
            return fromSigAlgs;
        } else {
            return fromClientCerts;
        }
    }

    static byte[][] encodeSubjectX509Principals(X509Certificate[] certificates)
            throws CertificateEncodingException {
        byte[][] principalBytes = new byte[certificates.length][];
        for (int i = 0; i < certificates.length; i++) {
            principalBytes[i] = certificates[i].getSubjectX500Principal().getEncoded();
        }
        return principalBytes;
    }

    /**
     * Converts the peer certificates into a cert chain.
     */
    static javax.security.cert.X509Certificate[] toCertificateChain(X509Certificate[] certificates)
            throws SSLPeerUnverifiedException {
        try {
            javax.security.cert.X509Certificate[] chain =
                    new javax.security.cert.X509Certificate[certificates.length];

            for (int i = 0; i < certificates.length; i++) {
                byte[] encoded = certificates[i].getEncoded();
                chain[i] = javax.security.cert.X509Certificate.getInstance(encoded);
            }
            return chain;
        } catch (CertificateEncodingException e) {
            SSLPeerUnverifiedException exception = new SSLPeerUnverifiedException(e.getMessage());
            exception.initCause(exception);
            throw exception;
        } catch (CertificateException e) {
            SSLPeerUnverifiedException exception = new SSLPeerUnverifiedException(e.getMessage());
            exception.initCause(exception);
            throw exception;
        }
    }

    /**
     * Calculates the minimum bytes required in the encrypted output buffer for the given number of
     * plaintext source bytes.
     */
    static int calculateOutNetBufSize(int pendingBytes) {
        return min(SSL3_RT_MAX_PACKET_SIZE,
                MAX_ENCRYPTION_OVERHEAD_LENGTH + min(MAX_ENCRYPTION_OVERHEAD_DIFF, pendingBytes));
    }

    /**
     * Wraps the given exception if it's not already a {@link SSLHandshakeException}.
     */
    static SSLHandshakeException toSSLHandshakeException(Throwable e) {
        if (e instanceof SSLHandshakeException) {
            return (SSLHandshakeException) e;
        }

        return (SSLHandshakeException) new SSLHandshakeException(e.getMessage()).initCause(e);
    }

    /**
     * Wraps the given exception if it's not already a {@link SSLException}.
     */
    static SSLException toSSLException(Throwable e) {
        if (e instanceof SSLException) {
            return (SSLException) e;
        }
        return new SSLException(e);
    }

    static String toProtocolString(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        return new String(bytes, US_ASCII);
    }

    static byte[] toProtocolBytes(String protocol) {
        if (protocol == null) {
            return null;
        }
        return protocol.getBytes(US_ASCII);
    }

    /**
     * Decodes the given list of protocols into {@link String}s.
     * @param protocols the encoded protocol list
     * @return the decoded protocols or {@link EmptyArray#BYTE} if {@code protocols} is
     * empty.
     * @throws NullPointerException if protocols is {@code null}.
     */
    static String[] decodeProtocols(byte[] protocols) {
        if (protocols.length == 0) {
            return EmptyArray.STRING;
        }

        int numProtocols = 0;
        for (int i = 0; i < protocols.length;) {
            int protocolLength = protocols[i];
            if (protocolLength < 0 || protocolLength > protocols.length - i) {
                throw new IllegalArgumentException(
                    "Protocol has invalid length (" + protocolLength + " at position " + i
                        + "): " + (protocols.length < 50
                        ? Arrays.toString(protocols) : protocols.length + " byte array"));
            }

            numProtocols++;
            i += 1 + protocolLength;
        }

        String[] decoded = new String[numProtocols];
        for (int i = 0, d = 0; i < protocols.length;) {
            int protocolLength = protocols[i];
            decoded[d++] = protocolLength > 0
                    ? new String(protocols, i + 1, protocolLength, US_ASCII)
                    : "";
            i += 1 + protocolLength;
        }

        return decoded;
    }

    /**
     * Encodes a list of protocols into the wire-format (length-prefixed 8-bit strings).
     * Requires that all strings be encoded with US-ASCII.
     *
     * @param protocols the list of protocols to be encoded
     * @return the encoded form of the protocol list.
     * @throws IllegalArgumentException if protocols is {@code null}, or if any element is
     * {@code null} or an empty string.
     */
    static byte[] encodeProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("protocols array must be non-null");
        }

        if (protocols.length == 0) {
            return EmptyArray.BYTE;
        }

        // Calculate the encoded length.
        int length = 0;
        for (int i = 0; i < protocols.length; ++i) {
            String protocol = protocols[i];
            if (protocol == null) {
                throw new IllegalArgumentException("protocol[" + i + "] is null");
            }
            int protocolLength = protocols[i].length();

            // Verify that the length is valid here, so that we don't attempt to allocate an array
            // below if the threshold is violated.
            if (protocolLength == 0 || protocolLength > MAX_PROTOCOL_LENGTH) {
                throw new IllegalArgumentException(
                    "protocol[" + i + "] has invalid length: " + protocolLength);
            }

            // Include a 1-byte prefix for each protocol.
            length += 1 + protocolLength;
        }

        byte[] data = new byte[length];
        for (int dataIndex = 0, i = 0; i < protocols.length; ++i) {
            String protocol = protocols[i];
            int protocolLength = protocol.length();

            // Add the length prefix.
            data[dataIndex++] = (byte) protocolLength;
            for (int ci = 0; ci < protocolLength; ++ci) {
                char c = protocol.charAt(ci);
                if (c > Byte.MAX_VALUE) {
                    // Enforce US-ASCII
                    throw new IllegalArgumentException("Protocol contains invalid character: "
                        + c + "(protocol=" + protocol + ")");
                }
                data[dataIndex++] = (byte) c;
            }
        }
        return data;
    }

    /**
     * Return how much bytes can be read out of the encrypted data. Be aware that this method will
     * not increase the readerIndex of the given {@link ByteBuffer}.
     *
     * @param buffers The {@link ByteBuffer}s to read from. Be aware that they must have at least
     * {@link org.conscrypt.NativeConstants#SSL3_RT_HEADER_LENGTH} bytes to read, otherwise it will
     * throw an {@link IllegalArgumentException}.
     * @return length The length of the encrypted packet that is included in the buffer. This will
     * return {@code -1} if the given {@link ByteBuffer} is not encrypted at all.
     * @throws IllegalArgumentException Is thrown if the given {@link ByteBuffer} has not at least
     * {@link org.conscrypt.NativeConstants#SSL3_RT_HEADER_LENGTH} bytes to read.
     */
    static int getEncryptedPacketLength(ByteBuffer[] buffers, int offset) {
        ByteBuffer buffer = buffers[offset];

        // Check if everything we need is in one ByteBuffer. If so we can make use of the fast-path.
        if (buffer.remaining() >= SSL3_RT_HEADER_LENGTH) {
            return getEncryptedPacketLength(buffer);
        }

        // We need to copy 5 bytes into a temporary buffer so we can parse out the packet length
        // easily.
        ByteBuffer tmp = ByteBuffer.allocate(SSL3_RT_HEADER_LENGTH);
        do {
            buffer = buffers[offset++];
            int pos = buffer.position();
            int limit = buffer.limit();
            if (buffer.remaining() > tmp.remaining()) {
                buffer.limit(pos + tmp.remaining());
            }
            try {
                tmp.put(buffer);
            } finally {
                // Restore the original indices.
                buffer.limit(limit);
                buffer.position(pos);
            }
        } while (tmp.hasRemaining());

        // Done, flip the buffer so we can read from it.
        tmp.flip();
        return getEncryptedPacketLength(tmp);
    }

    private static int getEncryptedPacketLength(ByteBuffer buffer) {
        int pos = buffer.position();
        // SSLv3 or TLS - Check ContentType
        switch (unsignedByte(buffer.get(pos))) {
            case SSL3_RT_CHANGE_CIPHER_SPEC:
            case SSL3_RT_ALERT:
            case SSL3_RT_HANDSHAKE:
            case SSL3_RT_APPLICATION_DATA:
                break;
            default:
                // SSLv2 or bad data
                return -1;
        }

        // SSLv3 or TLS - Check ProtocolVersion
        int majorVersion = unsignedByte(buffer.get(pos + 1));
        if (majorVersion != 3) {
            // Neither SSLv3 or TLSv1 (i.e. SSLv2 or bad data)
            return -1;
        }

        // SSLv3 or TLS
        int packetLength = unsignedShort(buffer.getShort(pos + 3)) + SSL3_RT_HEADER_LENGTH;
        if (packetLength <= SSL3_RT_HEADER_LENGTH) {
            // Neither SSLv3 or TLSv1 (i.e. SSLv2 or bad data)
            return -1;
        }
        return packetLength;
    }

    private static short unsignedByte(byte b) {
        return (short) (b & 0xFF);
    }

    private static int unsignedShort(short s) {
        return s & 0xFFFF;
    }

    static String[] concat(String[]... arrays) {
        int resultLength = 0;
        for (String[] array : arrays) {
            resultLength += array.length;
        }
        String[] result = new String[resultLength];
        int resultOffset = 0;
        for (String[] array : arrays) {
            System.arraycopy(array, 0, result, resultOffset, array.length);
            resultOffset += array.length;
        }
        return result;
    }

    private SSLUtils() {}
}
