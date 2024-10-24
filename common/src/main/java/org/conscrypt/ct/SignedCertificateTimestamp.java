/*
 * Copyright (C) 2015 The Android Open Source Project
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

package org.conscrypt.ct;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import org.conscrypt.Internal;

/**
 * SignedCertificateTimestamp structure, as defined by RFC6962 Section 3.2.
 */
@Internal
public class SignedCertificateTimestamp {
    public enum Version {
            V1(0)
        ;

        private final int value;

        Version(int value) {
            this.value = value;
        }

        int value() {
            return value;
        }
    }

    public enum SignatureType {
        CERTIFICATE_TIMESTAMP(0),
        TREE_HASH(1)
        ;
        private final int value;

        SignatureType(int value) {
            this.value = value;
        }

        int value() {
            return value;
        }
    }

    public enum Origin {
        EMBEDDED,
        TLS_EXTENSION,
        OCSP_RESPONSE
    }

    private final Version version;
    private final byte[] logId;
    private final long timestamp;
    private final byte[] extensions;
    private final DigitallySigned signature;

    // origin is implied from the SCT's source and is not encoded in it,
    // and affects the verification process.
    private final Origin origin;

    public SignedCertificateTimestamp(Version version, byte[] logId,
                                      long timestamp, byte[] extensions,
                                      DigitallySigned signature, Origin origin) {
        this.version = version;
        this.logId = logId;
        this.timestamp = timestamp;
        this.extensions = extensions;
        this.signature = signature;
        this.origin = origin;
    }

    public Version getVersion() {
        return version;
    }
    public byte[] getLogID() {
        return logId;
    }
    public long getTimestamp() {
        return timestamp;
    }
    public byte[] getExtensions() {
        return extensions;
    }
    public DigitallySigned getSignature() {
        return signature;
    }
    public Origin getOrigin() {
        return origin;
    }

    /**
     * Decode a TLS encoded SignedCertificateTimestamp structure.
     */
    public static SignedCertificateTimestamp decode(InputStream input, Origin origin)
            throws SerializationException {
        int version = Serialization.readNumber(input, Constants.VERSION_LENGTH);
        if (version != Version.V1.value()) {
            throw new SerializationException("Unsupported SCT version " + version);
        }

        return new SignedCertificateTimestamp(Version.V1,
                Serialization.readFixedBytes(input, Constants.LOGID_LENGTH),
                Serialization.readLong(input, Constants.TIMESTAMP_LENGTH),
                Serialization.readVariableBytes(input, Constants.EXTENSIONS_LENGTH_BYTES),
                DigitallySigned.decode(input), origin);
    }

    /**
     * Decode a TLS encoded SignedCertificateTimestamp structure.
     */
    public static SignedCertificateTimestamp decode(byte[] input, Origin origin)
            throws SerializationException {
        return decode(new ByteArrayInputStream(input), origin);
    }

    /**
     * TLS encode the signed part of the SCT, as described by RFC6962 section 3.2.
     */
    public void encodeTBS(OutputStream output, CertificateEntry certEntry)
            throws SerializationException {
        Serialization.writeNumber(output, version.value(), Constants.VERSION_LENGTH);
        Serialization.writeNumber(output, SignatureType.CERTIFICATE_TIMESTAMP.value(),
                Constants.SIGNATURE_TYPE_LENGTH);
        Serialization.writeNumber(output, timestamp, Constants.TIMESTAMP_LENGTH);
        certEntry.encode(output);
        Serialization.writeVariableBytes(output, extensions, Constants.EXTENSIONS_LENGTH_BYTES);
    }

    /**
     * TLS encode the signed part of the SCT, as described by RFC6962 section 3.2.
     */
    public byte[] encodeTBS(CertificateEntry certEntry)
            throws SerializationException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        encodeTBS(output, certEntry);
        return output.toByteArray();
    }
}

